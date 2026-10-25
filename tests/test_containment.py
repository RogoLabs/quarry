"""The P0 acceptance test.

Seat 5, round 2, step 5: "This test is the deliverable, not the profile — a profile
with no test is a comment."

A hostile fixture repo is planted with the two attacks that actually fire, then ingest
and a representative Layer 1 tool are run against it. The assertions are the invariant:

  * the symlink to a private key is recorded and gone;
  * the loader-capable config is quarantined and never loaded;
  * no sandboxed process can read a credential, write to $HOME, or reach the network;
  * nothing escaped the run volume.

These tests mount a real APFS sparse image and run real sandbox-exec, so they are slow
(~10 s) and macOS-only. That is deliberate: a mocked containment test proves nothing.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quarry.ingest.clone import quarantine_configs, scrub_symlinks   # noqa: E402
from quarry.ingest.volume import RunVolume                   # noqa: E402
from quarry.sandbox import (                                 # noqa: E402
    CLONE_PROFILE, PROFILE, TARGET_PROFILE, SandboxError, tier1, tier1_argv)
from quarry.sandbox.spawn import tools_dir                   # noqa: E402

pytestmark = pytest.mark.skipif(sys.platform != "darwin", reason="sandbox-exec is macOS-only")

# Per process, not a constant: the mount point is /private/tmp/quarry/run-<id>, and two
# suites sharing one id mount on top of each other and detach each other's volume.
RUN_ID = 900_000 + os.getpid() % 90_000
HOME = Path.home()

# Every profile, for the denials that must hold under all three.
EVERY_PROFILE = pytest.mark.parametrize(
    "profile", [PROFILE, CLONE_PROFILE, TARGET_PROFILE], ids=["tier1", "clone", "target"])


@pytest.fixture(scope="module")
def volume(tmp_path_factory):
    # The image lives in a pytest temp dir, never under the operator's real data root.
    images = tmp_path_factory.mktemp("runs")
    vol = RunVolume.create(RUN_ID, images, size_gb=1)
    try:
        yield vol
    finally:
        vol.release()


@pytest.fixture(scope="module")
def hostile(volume):
    """A repo that tries the two attacks worth testing."""
    src = volume.src
    (src / "app").mkdir(parents=True, exist_ok=True)
    (src / "app" / "main.py").write_text("import os\nprint(os.getenv('HOME'))\n")

    # Attack 1: exfiltrate a private key by making a scanner read it for us.
    os.symlink(str(HOME / ".ssh" / "id_ed25519"), src / "evil.pem")
    os.symlink("/etc/passwd", src / "app" / "passwd.conf")

    # Attack 2: reconfigure the scanner that is about to analyse us.
    (src / ".checkov.yaml").write_text(
        "external-checks-dir:\n  - ./.evil-checks\ncompact: true\n")
    (src / ".semgrep.yml").write_text("rules: []\n")
    (src / ".trivyignore").write_text("CVE-2024-0001\nCVE-2024-0002\n")
    return src


def test_symlinks_are_recorded_then_destroyed(volume, hostile):
    found = scrub_symlinks(hostile)
    kinds = {e.original_path: e.detail for e in found if e.kind == "symlink"}

    assert "evil.pem" in kinds, "the private-key symlink was not recorded"
    assert ".ssh/id_ed25519" in kinds["evil.pem"]
    assert "app/passwd.conf" in kinds

    assert not (hostile / "evil.pem").is_symlink()
    assert not (hostile / "evil.pem").exists()
    assert not (hostile / "app" / "passwd.conf").exists()
    # scrubbing must not eat real files
    assert (hostile / "app" / "main.py").exists()


def test_loader_config_is_quarantined_not_deleted(volume, hostile):
    found = quarantine_configs(hostile, volume.quarantine)
    by_path = {e.original_path: e for e in found}

    assert by_path[".checkov.yaml"].kind == "loader-config"
    assert by_path[".semgrep.yml"].kind == "loader-config"
    assert by_path[".trivyignore"].kind == "suppression"

    # gone from the tree a scanner will walk...
    assert not (hostile / ".checkov.yaml").exists()
    assert not (hostile / ".trivyignore").exists()
    # ...but preserved as evidence (D8: nothing is ever deleted)
    assert (volume.quarantine / ".checkov.yaml").exists()
    assert "external-checks-dir" in (volume.quarantine / ".checkov.yaml").read_text()
    assert by_path[".checkov.yaml"].sha256 and len(by_path[".checkov.yaml"].sha256) == 64
    # suppressions are counted, never obeyed
    assert by_path[".trivyignore"].detail == "2 entries"


@pytest.mark.parametrize("label,argv", [
    ("ssh-key",   ["/bin/cat", str(HOME / ".ssh" / "id_ed25519")]),
    ("gh-token",  ["/bin/cat", str(HOME / ".config" / "gh" / "hosts.yml")]),
    ("aws-creds", ["/bin/cat", str(HOME / ".aws" / "credentials")]),
])
def test_credentials_are_unreachable(volume, label, argv):
    r = tier1(volume.mount, argv, name=f"cred-{label}")
    assert r.returncode != 0, f"sandboxed process read {label}"
    combined = r.stdout_bytes(4096) + r.stderr_bytes()
    assert b"PRIVATE KEY" not in combined
    assert b"oauth_token" not in combined


@pytest.mark.parametrize("label,argv", [
    ("credential-helper", ["/usr/local/bin/docker-credential-desktop", "list"]),
    ("docker config",     ["/bin/cat", str(HOME / ".docker" / "config.json")]),
    ("docker socket",     ["/bin/ls", str(HOME / ".docker" / "run" / "docker.sock")]),
])
def test_docker_desktop_credentials_are_unreachable(volume, label, argv):
    """Installing Docker Desktop puts `docker-credential-desktop` at /usr/local/bin —
    OUTSIDE /Users, so the profile's blanket deny does not cover the binary itself.
    It stays harmless only because the config and socket it needs are both under
    /Users and denied. That is a load-bearing coincidence, so assert it rather than
    rely on it: a scanner that could run the helper could read every registry
    credential on the machine."""
    if not Path(argv[0]).exists():
        pytest.skip(f"{argv[0]} not installed")
    r = tier1(volume.mount, argv, name=f"docker-{label}")
    assert r.returncode != 0, f"sandboxed process reached docker {label}"
    combined = r.stdout_bytes(4096) + r.stderr_bytes()
    assert b"credsStore" not in combined and b"auths" not in combined


def test_network_egress_is_denied(volume):
    r = tier1(volume.mount, ["/usr/bin/curl", "-sS", "-m", "8", "-o", "/dev/null",
                             "-w", "HTTP:%{http_code}", "https://api.github.com"],
              name="egress")
    assert r.returncode != 0
    assert b"HTTP:000" in r.stdout_bytes(64)


def test_host_writes_are_denied(volume):
    probe = HOME / ".quarry-acceptance-probe"
    probe.unlink(missing_ok=True)
    r = tier1(volume.mount, ["/usr/bin/touch", str(probe)], name="hostwrite")
    assert r.returncode != 0
    assert not probe.exists(), "a sandboxed process wrote to $HOME"


def test_run_volume_is_writable(volume):
    r = tier1(volume.mount, ["/usr/bin/touch", str(volume.mount / "out" / "ok")],
              name="volwrite")
    assert r.returncode == 0
    assert (volume.mount / "out" / "ok").exists()


def test_no_credential_env_is_inherited(volume):
    """env -i plus a fixed allowlist: a scanner sees no token even if the orchestrator has one."""
    os.environ["ANTHROPIC_API_KEY"] = "sk-ant-canary-value"
    try:
        r = tier1(volume.mount, ["/usr/bin/env"], name="envdump")
        dump = r.stdout_bytes(65536).decode("utf-8", "replace")
    finally:
        os.environ.pop("ANTHROPIC_API_KEY", None)
    assert "sk-ant-canary-value" not in dump
    assert "ANTHROPIC_API_KEY" not in dump
    assert "GITHUB_TOKEN" not in dump
    lines = dump.splitlines()
    home = [ln for ln in lines if ln.startswith("HOME=")]
    assert home == [f"HOME={volume.mount}/home"], f"unexpected HOME: {home}"
    # nothing outside the declared allowlist leaks in
    assert {ln.split("=", 1)[0] for ln in lines} <= {
        "PATH", "LANG", "LC_ALL", "HOME", "TMPDIR", "XDG_CACHE_HOME", "XDG_CONFIG_HOME",
        "SYFT_CHECK_FOR_APP_UPDATE", "GRYPE_CHECK_FOR_APP_UPDATE", "CHECKPOINT_DISABLE",
        "DO_NOT_TRACK", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
        # database locations, pointed at the read-only DBDIR the profile allows
        "TRIVY_CACHE_DIR", "GRYPE_DB_CACHE_DIR", "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY",
    }


def test_cwd_outside_the_volume_is_refused(volume):
    with pytest.raises(SandboxError):
        tier1(volume.mount, ["/bin/echo", "hi"], name="badcwd", cwd=Path("/tmp"))


def test_caller_cannot_widen_path(volume):
    with pytest.raises(SandboxError):
        tier1_argv(volume.mount, ["/bin/echo"], env={"PATH": "/evil"})


# ------------------------------------------------------------------ per-user services
#
# The profiles used to be `(allow default)` with ONE mach service denied. MEASURED under
# that profile: `pbpaste` returned the operator's clipboard, `launchctl print gui/<uid>`
# listed the operator's launchd domain, and `defaults write` created a plist in
# ~/Library/Preferences through cfprefsd, a host write the file rules never saw.

@EVERY_PROFILE
def test_clipboard_is_unreachable(volume, profile):
    r = tier1(volume.mount, ["/usr/bin/pbpaste"], name=f"pbpaste-{profile.stem}",
              profile=profile)
    # An empty clipboard also prints nothing, but exits 0; a denied lookup exits 1.
    assert r.returncode != 0, "pbpaste reached the pasteboard server"
    assert r.stdout_bytes() == b""


@EVERY_PROFILE
def test_launchd_user_domain_is_unreachable(volume, profile):
    r = tier1(volume.mount, ["/bin/launchctl", "print", f"gui/{os.getuid()}"],
              name=f"launchctl-{profile.stem}", profile=profile)
    assert r.returncode != 0
    assert b"type = login" not in r.stdout_bytes(65536)


@EVERY_PROFILE
def test_preferences_cannot_be_written(volume, profile):
    domain = "net.rogolabs.quarry.containment-probe"
    plist = HOME / "Library" / "Preferences" / f"{domain}.plist"
    try:
        r = tier1(volume.mount, ["/usr/bin/defaults", "write", domain, "k", "v"],
                  name=f"prefs-{profile.stem}", profile=profile)
        assert r.returncode != 0
        assert not plist.exists(), "a sandboxed process wrote a host preference file"
    finally:
        subprocess.run(["/usr/bin/defaults", "delete", domain], capture_output=True)
        plist.unlink(missing_ok=True)


# ------------------------------------------------------------------ host reads outside /Users

@pytest.fixture
def sibling_secret():
    """A file in a sibling /private/tmp dir: where other runs' volumes, the ssh-agent
    socket and launchd's per-user sockets live."""
    d = Path(tempfile.mkdtemp(prefix="quarry-sibling-", dir="/private/tmp"))
    f = d / "secret.txt"
    f.write_text("SIBLING-SECRET\n")
    try:
        yield f
    finally:
        f.unlink(missing_ok=True)
        d.rmdir()


@EVERY_PROFILE
def test_sibling_tmp_is_unreadable(volume, profile, sibling_secret):
    r = tier1(volume.mount, ["/bin/cat", str(sibling_secret)],
              name=f"sibling-{profile.stem}", profile=profile)
    assert r.returncode != 0
    assert b"SIBLING-SECRET" not in r.stdout_bytes(4096)


@EVERY_PROFILE
def test_per_user_temp_is_unreadable(volume, profile, tmp_path):
    """pytest's tmp_path is under /private/var/folders, the per-user temp and cache
    root, which is exactly what this rule covers."""
    secret = tmp_path / "secret.txt"
    secret.write_text("FOLDERS-SECRET\n")
    if not str(secret.resolve()).startswith("/private/var/folders/"):
        pytest.skip(f"tmp_path is not under /private/var/folders: {secret}")
    r = tier1(volume.mount, ["/bin/cat", str(secret)], name=f"folders-{profile.stem}",
              profile=profile)
    assert r.returncode != 0
    assert b"FOLDERS-SECRET" not in r.stdout_bytes(4096)


@EVERY_PROFILE
def test_other_volumes_are_unreadable(volume, profile):
    r = tier1(volume.mount, ["/bin/ls", "/Volumes"], name=f"volumes-{profile.stem}",
              profile=profile)
    assert r.returncode != 0


# ------------------------------------------------------------------ processes

@EVERY_PROFILE
def test_cannot_signal_outside_the_sandbox(volume, profile):
    victim = subprocess.Popen(["/bin/sleep", "30"])
    try:
        r = tier1(volume.mount, ["/bin/kill", "-0", str(victim.pid)],
                  name=f"signal-{profile.stem}", profile=profile)
        assert r.returncode != 0, "a sandboxed process could signal an operator process"
        assert victim.poll() is None
    finally:
        victim.kill()
        victim.wait()


@pytest.mark.parametrize("profile", [PROFILE, CLONE_PROFILE], ids=["tier1", "clone"])
def test_target_bytes_are_never_executed(volume, profile):
    """Scanners read the target; they never run it. (The target profile exists to run
    it, so it is the one profile without this rule.)"""
    script = volume.src / f"payload-{profile.stem}.sh"
    script.write_text("#!/bin/sh\necho PAYLOAD-RAN\n")
    script.chmod(0o755)
    try:
        r = tier1(volume.mount, [str(script)], name=f"exec-{profile.stem}",
                  profile=profile)
        assert r.returncode != 0
        assert b"PAYLOAD-RAN" not in r.stdout_bytes(4096)
    finally:
        script.unlink(missing_ok=True)


def test_timeout_kills_the_whole_process_group(volume):
    """subprocess.run's timeout killed only the direct child; a tool's workers kept
    running. The worker here would live 60 s if the group were not killed."""
    pidfile = volume.mount / "out" / "worker.pid"
    pidfile.unlink(missing_ok=True)
    r = tier1(volume.mount,
              ["/bin/sh", "-c", f"/bin/sleep 60 & echo $! > {pidfile}; wait"],
              name="timeout-group", timeout=2)
    assert r.returncode == -9
    worker = int(pidfile.read_text())
    deadline = time.monotonic() + 5
    alive = True
    while alive and time.monotonic() < deadline:
        try:
            os.kill(worker, 0)
            time.sleep(0.1)
        except ProcessLookupError:
            alive = False
    if alive:
        os.kill(worker, 9)
    assert not alive, "a worker process outlived its tool's timeout"


# ------------------------------------------------------------------ our tools still run

def _venv_bin(name: str) -> Path:
    p = tools_dir() / "bin" / name
    if not p.exists():
        pytest.skip(f"{p} not present (set QUARRY_TOOLS to the venv)")
    return p


def test_venv_python_still_runs(volume):
    r = tier1(volume.mount, [str(_venv_bin("python")), "-c", "print('venv-ok')"],
              name="venv-python")
    assert r.returncode == 0, r.stderr_bytes(4096)
    assert r.stdout_bytes(64).strip() == b"venv-ok"


def test_bandit_still_scans_under_the_profile(volume):
    """The positive control for the deny-by-default mach rule: a real scanner, through
    its real adapter, still produces findings with no system service allowed."""
    _venv_bin("bandit")
    from quarry.scanners.tools import Bandit
    (volume.src / "bandit_fixture").mkdir(parents=True, exist_ok=True)
    (volume.src / "bandit_fixture" / "shell.py").write_text(
        "import subprocess\nsubprocess.call('ls ' + input(), shell=True)\n")
    out = Bandit().run(volume.mount, volume.src / "bandit_fixture", timeout=300)
    assert out.ok, out.error or out.skipped
    assert any(rec.path == "shell.py" for rec in out.records), out.records


# ------------------------------------------------------------------ the parent's own log I/O
#
# logs/ is on the run volume, so every sandboxed child can write it. The parent that
# writes and reads those logs is NOT sandboxed. MEASURED before the fix: a child
# planted `logs/<next>.stdout -> <host file>` and the parent's next spawn truncated and
# overwrote the host file.

@pytest.fixture
def victim(tmp_path):
    v = tmp_path / "victim.txt"
    v.write_text("ORIGINAL\n")
    return v


def test_planted_log_symlink_does_not_clobber_a_host_file(volume, victim):
    logs = volume.mount / "logs"
    # The attacker is a sandboxed child: it can create symlinks on the volume.
    plant = "; ".join(f"/bin/ln -sf {victim} {logs}/clobber.{ext}"
                      for ext in ("stdout", "stderr", "argv"))
    r = tier1(volume.mount, ["/bin/sh", "-c", plant], name="planter")
    assert r.returncode == 0, r.stderr_bytes(4096)
    assert (logs / "clobber.stdout").is_symlink()

    r = tier1(volume.mount, ["/bin/echo", "OVERWRITTEN"], name="clobber")
    assert victim.read_text() == "ORIGINAL\n", "the parent wrote through a planted symlink"
    assert not r.stdout_path.is_symlink()
    assert r.stdout_bytes() == b"OVERWRITTEN\n"


def test_swapped_log_is_not_read_through(volume, victim):
    """After it exits, a child can replace its own log with a symlink. Reading it back
    must refuse, not return the host file."""
    log = volume.mount / "logs" / "swap.stdout"
    r = tier1(volume.mount, ["/bin/sh", "-c", f"/bin/rm {log}; /bin/ln -s {victim} {log}"],
              name="swap")
    assert r.stdout_path.is_symlink()
    with pytest.raises(SandboxError):
        r.stdout_bytes()


def test_swapped_logs_directory_is_not_written_through(volume, tmp_path):
    """The directory, not just the file: a child replaces logs/ with a link to a host
    directory. The next spawn must not create files there."""
    hostdir = tmp_path / "hostdir"
    hostdir.mkdir()
    logs = volume.mount / "logs"
    stash = volume.mount / "logs.moved"
    r = tier1(volume.mount, ["/bin/sh", "-c",
                             f"/bin/mv {logs} {stash}; /bin/ln -s {hostdir} {logs}"],
              name="dirswap")
    try:
        assert logs.is_symlink()
        tier1(volume.mount, ["/bin/echo", "hi"], name="after-dirswap")
        assert list(hostdir.iterdir()) == [], "the parent wrote logs into a host directory"
        assert logs.is_dir() and not logs.is_symlink()
    finally:
        if logs.is_symlink():
            logs.unlink()
        if stash.exists():
            for f in stash.iterdir():
                f.unlink()
            stash.rmdir()
        logs.mkdir(exist_ok=True)
