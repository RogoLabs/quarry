"""Hardened clone, symlink scrub, and config quarantine.

Seat 5 P0 step 3 + Seat 1's D14 ruling. Three separable jobs:

1. **Clone with every git feature that executes or redirects turned off.** Anonymous
   HTTPS with an empty credential helper removes the operator's token from ingest
   entirely — a public clone never needed it, and `gh repo clone` must not be used
   for exactly this reason.

2. **Record then destroy every symlink.** This is the exfiltration vector: a target
   ships `evil.pem -> ~/.ssh/id_ed25519`, a secrets scanner follows it, and the key
   lands in a database row and then in a model prompt. Every "safe" parser stage.
   The sandbox denies the read, so this is defence in depth — but the sandbox is a
   deny-list, and this is not.

3. **Quarantine target-supplied scanner config, never delete it.** Every one of these
   files auto-discovers from cwd, so a target can reconfigure the scanner that is
   analysing it. Two classes, per Seat 1:
     * *loader-capable* (`.checkov.yaml` with `external-checks-dir`, `.semgrep.yml`,
       `.bandit`): quarantined and never loaded.
     * *suppression* (`.trivyignore`, `.semgrepignore`, `.gitleaksignore`): parsed for
       metadata, never obeyed — we scan as if absent, then rank by suppression
       posture. Reason strings never reach a model; that is the cheapest
       verdict-suppression attack available to a hostile repo.
"""
from __future__ import annotations

import hashlib
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from ..sandbox import CLONE_PROFILE, tier1

# Files a target can drop to reconfigure or re-point a scanner. Quarantined.
LOADER_CONFIG = (
    ".checkov.yaml", ".checkov.yml", ".semgrep.yml", ".semgrep.yaml", ".semgrepconfig.yml",
    ".opengrep.yml", ".opengrep.yaml", ".trivy.yaml", ".trivy.yml",
    ".gitleaks.toml", "osv-scanner.toml", ".grype.yaml", ".grype.yml",
    ".bandit", "bandit.yaml", "bandit.yml", ".njsscan", ".syft.yaml", ".syft.yml",
    "zizmor.yml", "zizmor.yaml",
)
# Files that only suppress. Parsed for metadata, never obeyed.
SUPPRESSION_CONFIG = (
    ".trivyignore", ".semgrepignore", ".gitleaksignore", ".grype-ignore.yaml",
    ".checkov.baseline", ".secrets.baseline",
)
# Directories we never walk when scrubbing.
SKIP_DIRS = {".git"}


@dataclass
class QuarantineEntry:
    original_path: str
    kind: str          # loader-config | suppression | symlink
    detail: str = ""
    sha256: str | None = None


@dataclass
class CloneResult:
    src: Path
    git_sha: str | None
    quarantined: list[QuarantineEntry] = field(default_factory=list)
    returncode: int = 0
    stderr_tail: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and self.git_sha is not None


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _https_url(target: str) -> str:
    """owner/repo or a full URL -> an anonymous https URL. Never ssh, never gh."""
    t = target.strip()
    if t.startswith(("https://", "http://")):
        return t
    if t.startswith("git@github.com:"):
        t = t.split(":", 1)[1]
    return f"https://github.com/{t.removesuffix('.git')}.git"


def scrub_symlinks(src: Path) -> list[QuarantineEntry]:
    """Record every symlink, then remove it. Returns what was found."""
    found: list[QuarantineEntry] = []
    for root, dirs, files in os.walk(src, followlinks=False):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in list(dirs) + files:
            p = Path(root) / name
            if not p.is_symlink():
                continue
            try:
                target = os.readlink(p)
            except OSError:
                target = "<unreadable>"
            found.append(QuarantineEntry(
                original_path=str(p.relative_to(src)), kind="symlink", detail=target))
            # A symlinked *directory* needs unlink, not rmtree.
            p.unlink(missing_ok=True)
            if name in dirs:
                dirs.remove(name)
    return found


def quarantine_configs(src: Path, quarantine: Path) -> list[QuarantineEntry]:
    """Move every target-supplied scanner config aside. Never delete — it is evidence,
    and D8 says nothing is ever deleted."""
    found: list[QuarantineEntry] = []
    wanted = {n.lower(): "loader-config" for n in LOADER_CONFIG}
    wanted.update({n.lower(): "suppression" for n in SUPPRESSION_CONFIG})

    for root, dirs, files in os.walk(src, followlinks=False):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            kind = wanted.get(name.lower())
            if kind is None:
                continue
            p = Path(root) / name
            rel = p.relative_to(src)
            digest = _sha256(p)
            dest = quarantine / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(p), str(dest))
            detail = ""
            if kind == "suppression":
                # Parsed for posture metadata only. Never obeyed, never shown to a model.
                try:
                    detail = f"{len(dest.read_text(errors='replace').splitlines())} entries"
                except OSError:
                    detail = "unreadable"
            found.append(QuarantineEntry(str(rel), kind, detail, digest))
    return found


def clone_target(target: str, rundir: Path, *, depth: int = 1,
                 timeout: int = 900) -> CloneResult:
    """Clone `target` into <rundir>/src under the clone profile, then scrub."""
    src = rundir / "src"
    quarantine = rundir / "quarantine"
    quarantine.mkdir(parents=True, exist_ok=True)
    if src.exists() and any(src.iterdir()):
        raise RuntimeError(f"{src} is not empty")
    src.mkdir(parents=True, exist_ok=True)

    argv = [
        "/usr/bin/git",
        "-c", "core.hooksPath=/dev/null",     # no post-checkout / no filters
        "-c", "protocol.file.allow=never",    # no local-path submodule tricks
        "-c", "credential.helper=",           # empty: never consult the keychain
        "-c", "core.symlinks=true",           # create them so scrub can record them
        "clone", "--depth", str(depth),
        "--no-recurse-submodules", "--no-tags", "--quiet",
        _https_url(target), str(src),
    ]
    res = tier1(rundir, argv, name="clone", cwd=rundir / "out", timeout=timeout,
                profile=CLONE_PROFILE,
                env={"GIT_LFS_SKIP_SMUDGE": "1", "GIT_TERMINAL_PROMPT": "0",
                     "GIT_ASKPASS": "/usr/bin/true"})
    # Never Path.read_text: git ran sandboxed and could have swapped its own log for
    # a symlink to a host file. stderr_bytes() refuses to follow one.
    stderr_tail = res.stderr_bytes().decode("utf-8", "replace")[-500:]
    if res.returncode != 0:
        return CloneResult(src, None, [], res.returncode, stderr_tail)

    sha = None
    head = tier1(rundir, ["/usr/bin/git", "-C", str(src), "rev-parse", "HEAD"],
                 name="clone-sha", cwd=rundir / "out", timeout=60, profile=CLONE_PROFILE)
    if head.returncode == 0:
        sha = head.stdout_bytes(128).decode().strip() or None

    entries = scrub_symlinks(src)
    entries += quarantine_configs(src, quarantine)
    return CloneResult(src, sha, entries, 0, stderr_tail)
