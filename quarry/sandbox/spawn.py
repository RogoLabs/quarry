"""Tier 1 spawn wrapper: the only way a scanner is ever started.

Seat 5, P0 steps 4 and 7. Three rules encoded here, each learned from running real
tools under the profile:

  * list-form argv, never a shell — target content must never be word-split;
  * ``env -i`` with a fixed allowlist, so no credential is inherited;
  * stdout/stderr to *files on the run volume*, not pipes — the volume quota bounds
    output size for free, nothing streams target-controlled escape sequences into the
    operator's terminal, and a crashed orchestrator loses no results.

Two operational facts that are not obvious: the profile must supply a writable HOME
and cache (Syft degrades without one), and cwd must be inside RUNDIR (Syft exits with
"could not get current working directory: operation not permitted" otherwise).
"""
from __future__ import annotations

import os
import shlex
import signal
import subprocess
from dataclasses import dataclass
from pathlib import Path

PROFILE = Path(__file__).with_name("quarry-tier1.sb")
CLONE_PROFILE = Path(__file__).with_name("quarry-clone.sb")
# Layer 3 only: loopback allowed so a local probe can reach a running target,
# egress still denied. The one capability difference from PROFILE. See validate.py.
TARGET_PROFILE = Path(__file__).with_name("quarry-target.sb")


def rules_dir() -> Path:
    """Rule packs. Read-only, ours, and outside the target's control — so the profile
    allowlists it exactly like TOOLSDIR. A target-supplied rule file never reaches
    here: those are quarantined at ingest (D14)."""
    if p := os.environ.get("QUARRY_RULES"):
        return Path(p).expanduser().resolve()
    return (Path.home() / "Library" / "Application Support" / "Quarry" / "rules").resolve()


def db_dir() -> Path:
    """Vulnerability databases (Trivy, OSV, Grype). Fetched by `quarry db sync`
    OUTSIDE the sandbox — that is the one deliberate network step — then read-only
    inside it. Trivy cannot run with --skip-db-update on a first run, and OSV-Scanner
    has no offline database until one is downloaded; both are provisioning steps, not
    flags (Seat 5's measurement)."""
    if p := os.environ.get("QUARRY_DBS"):
        return Path(p).expanduser().resolve()
    return (Path.home() / "Library" / "Application Support" / "Quarry" / "vulndb").resolve()


def tools_dir() -> Path:
    """The one directory under /Users the profile will let a sandboxed tool read.

    Python-packaged scanners (bandit, checkov) live in a virtualenv, and a venv under
    /Users is unexecutable under the profile's blanket deny. Rather than widen the deny
    or scatter allow rules, we name exactly one directory and put our tools in it.
    Everything outside /Users (Homebrew, /usr) is already readable.
    """
    if p := os.environ.get("QUARRY_TOOLS"):
        return Path(p).expanduser().resolve()
    return (Path(__file__).resolve().parents[2] / ".venv").resolve()

# Everything a scanner is allowed to see of the environment. Nothing else is inherited.
BASE_ENV = {
    # tools_dir()/bin is appended at build time; see tier1_argv.
    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    # Stop tools that phone home from doing so; the profile denies it anyway, but a
    # denied call still costs a timeout.
    "SYFT_CHECK_FOR_APP_UPDATE": "false",
    "GRYPE_CHECK_FOR_APP_UPDATE": "false",
    "CHECKPOINT_DISABLE": "1",
    "DO_NOT_TRACK": "1",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_SYSTEM": "/dev/null",
}

# Cache/DB locations, resolved at spawn time so the sandboxed tool looks in the one
# directory the profile allows it to read.
DB_ENV = {
    "TRIVY_CACHE_DIR": "trivy",
    "GRYPE_DB_CACHE_DIR": "grype",
    "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": "osv",
}


class SandboxError(RuntimeError):
    pass


# The logs live on the run volume, which every sandboxed child can write. So a child
# can plant `logs/<tool>.stdout -> ~/.zshrc` and wait for the UNSANDBOXED parent to
# open it. MEASURED: the old `Path.open("wb")` followed that link and truncated the
# host file. Every parent-side open of a log therefore refuses symlinks, and on macOS
# O_NOFOLLOW_ANY refuses them in every path component, not just the last, which also
# covers a child that swaps `logs/` itself for a link to a host directory. The two
# flags cannot be combined (measured: EINVAL), so it is one or the other.
_NOFOLLOW = getattr(os, "O_NOFOLLOW_ANY", 0) or os.O_NOFOLLOW


def _create_log(path: Path) -> int:
    """Create `path` fresh for writing, never through a symlink. Whatever is there is
    unlinked first (unlink removes a link, not its target), then O_EXCL guarantees the
    file we write is one we just created. A child re-planting in between makes the
    open fail, which is the right outcome."""
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    except OSError as e:
        raise SandboxError(f"cannot clear log {path.name}: {e}") from e
    try:
        return os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
                       | _NOFOLLOW, 0o644)
    except OSError as e:
        raise SandboxError(f"refusing to create log {path.name}: {e}") from e


def read_log(path: Path, cap: int = 64 * 1024 * 1024) -> bytes:
    """Read a log the sandbox could have tampered with, capped, never through a
    symlink. A child can replace the file after it exits; the parent must not then
    read a host file in its place."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | _NOFOLLOW)
    except OSError as e:
        raise SandboxError(f"refusing to read log {path.name}: {e}") from e
    with os.fdopen(fd, "rb") as fh:
        return fh.read(cap)


@dataclass
class ToolResult:
    argv: list[str]
    returncode: int
    stdout_path: Path
    stderr_path: Path
    duration_s: float

    def stdout_bytes(self, cap: int = 64 * 1024 * 1024) -> bytes:
        """Read captured stdout, capped. The cap is a second line of defence behind
        the volume quota — see taint.ingest_bytes for the sanitising boundary."""
        return read_log(self.stdout_path, cap)

    def stderr_bytes(self, cap: int = 64 * 1024 * 1024) -> bytes:
        return read_log(self.stderr_path, cap)


def tier1_argv(rundir: Path, argv: list[str], *, cwd: Path | None = None,
               env: dict[str, str] | None = None, profile: Path | None = None) -> list[str]:
    """Build the full sandbox-exec command line. Exposed for tests and for logging."""
    profile = profile or PROFILE
    if not profile.exists():                      # pragma: no cover - packaging error
        raise SandboxError(f"profile missing: {profile}")
    if not argv:
        raise SandboxError("empty argv")

    rundir = rundir.resolve()
    home = Path.home()
    tools = tools_dir()
    rules = rules_dir()
    dbs = db_dir()
    full_env = dict(BASE_ENV)
    full_env.update({
        "HOME": str(rundir / "home"),
        "TMPDIR": str(rundir / "cache"),
        "XDG_CACHE_HOME": str(rundir / "cache"),
        "XDG_CONFIG_HOME": str(rundir / "home" / ".config"),
    })
    full_env["PATH"] = f"{tools / 'bin'}:{BASE_ENV['PATH']}"
    for var, sub in DB_ENV.items():
        full_env[var] = str(dbs / sub)
    if env:
        for k, v in env.items():
            if k.lower() in ("path",):           # callers do not get to widen PATH
                raise SandboxError(f"refusing caller-supplied {k}")
            full_env[k] = v

    env_argv = ["/usr/bin/env", "-i"] + [f"{k}={v}" for k, v in sorted(full_env.items())]
    return [
        "/usr/bin/sandbox-exec",
        "-D", f"RUNDIR={rundir}",
        "-D", f"HOSTHOME={home}",
        "-D", f"TOOLSDIR={tools}",
        "-D", f"RULESDIR={rules}",
        "-D", f"DBDIR={dbs}",
        "-f", str(profile),
        *env_argv,
        *argv,
    ]


def tier1(rundir: Path, argv: list[str], *, name: str, cwd: Path | None = None,
          env: dict[str, str] | None = None, timeout: int = 1800,
          profile: Path | None = None) -> ToolResult:
    """Run one tool under Tier 1 containment. Never raises on tool failure — a
    non-zero exit is data, and the caller records it in the manifest."""
    import time

    rundir = rundir.resolve()
    out_dir = rundir / "out"
    log_dir = rundir / "logs"
    # A previous child may have replaced logs/ with a symlink. Drop the link and make
    # the real directory; _create_log's O_NOFOLLOW_ANY catches a re-plant after this.
    if log_dir.is_symlink():
        log_dir.unlink()
    # opengrep hard-fails if $HOME/.config is absent, so create it rather than
    # letting every scan lose one tool to a missing directory.
    for d in (out_dir, log_dir, rundir / "home", rundir / "home" / ".config",
              rundir / "cache"):
        d.mkdir(parents=True, exist_ok=True)

    # cwd must be inside RUNDIR or the profile denies getcwd().
    work = (cwd or out_dir).resolve()
    if not (work == rundir or str(work).startswith(str(rundir) + os.sep)):
        raise SandboxError(f"cwd {work} is outside the run volume {rundir}")

    stdout_path = log_dir / f"{name}.stdout"
    stderr_path = log_dir / f"{name}.stderr"
    full = tier1_argv(rundir, argv, cwd=work, env=env, profile=profile)
    with os.fdopen(_create_log(log_dir / f"{name}.argv"), "w") as fh:
        fh.write(shlex.join(full) + "\n")

    started = time.monotonic()
    with os.fdopen(_create_log(stdout_path), "wb") as so, \
         os.fdopen(_create_log(stderr_path), "wb") as se:
        # Own session, so the tool is a process-group leader and the group is ours to
        # kill. subprocess.run's timeout kills only the direct child, so a tool's
        # worker processes outlived it and kept running against the volume we were
        # about to detach. The group is killed while the leader is still unreaped, so
        # its pgid cannot have been recycled to an unrelated process. A worker that
        # calls setsid() itself escapes this; the profile's signal rule still keeps it
        # inside the sandbox.
        proc = subprocess.Popen(full, stdout=so, stderr=se, cwd=work,
                                start_new_session=True)
        try:
            rc = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            rc = -9
            _killpg(proc.pid)
            proc.wait()
            se.write(b"\n[quarry] timeout\n")
    return ToolResult(full, rc, stdout_path, stderr_path, time.monotonic() - started)


def _killpg(pgid: int) -> None:
    try:
        os.killpg(pgid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
