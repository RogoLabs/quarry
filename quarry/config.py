"""Paths and the startup refusal check.

Seat 5, P0 step 1: the data root is never under ~/Documents or ~/Desktop, and we
refuse to start on a file-provider-synced or network-mounted volume. SQLite WAL on
an iCloud-synced directory corrupts silently, and it corrupts months after someone
enables sync for an unrelated reason.
"""
from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

APP = "Quarry"

# Sync daemons stamp these; presence of any means the directory is not ours alone.
_SYNC_XATTRS = ("com.apple.fileprovider", "com.apple.cloud")
# Filesystems that must never host the DB or a run volume.
_BAD_FS = ("smbfs", "nfs", "afpfs", "webdav", "osxfuse", "macfuse")


class UnsafeDataRoot(RuntimeError):
    """Raised at startup rather than corrupting a database later."""


@dataclass(frozen=True)
class Paths:
    root: Path

    @property
    def db(self) -> Path:
        return self.root / "quarry.db"

    @property
    def runs(self) -> Path:
        """Sparse images, one per run."""
        return self.root / "runs"

    @property
    def blobs(self) -> Path:
        """Content-addressed evidence windows (PLAN D15)."""
        return self.root / "blobs"

    @property
    def sock(self) -> Path:
        return self.root / "run"

    def ensure(self) -> "Paths":
        for p in (self.root, self.runs, self.blobs, self.sock):
            p.mkdir(parents=True, exist_ok=True)
        self.sock.chmod(0o700)
        return self


def default_root() -> Path:
    if env := os.environ.get("QUARRY_HOME"):
        return Path(env).expanduser().resolve()
    return Path.home() / "Library" / "Application Support" / APP


def _xattrs(path: Path) -> list[str]:
    """Extended attributes on `path`. os.listxattr is Linux-only, so shell out."""
    try:
        out = subprocess.run(["/usr/bin/xattr", str(path)], capture_output=True,
                             text=True, timeout=5, check=False)
    except (OSError, subprocess.SubprocessError):
        return []
    return [line.strip() for line in out.stdout.splitlines() if line.strip()]


def _filesystem(path: Path) -> str:
    """Mount type for `path`. Empty string if it cannot be determined.

    `stat -f %T` reports the *file* type on macOS, not the filesystem, so parse
    mount(8) and take the longest matching mount point.
    """
    try:
        mounts = subprocess.run(["/sbin/mount"], capture_output=True, text=True,
                                timeout=5, check=False).stdout
    except (OSError, subprocess.SubprocessError):
        return ""
    target = str(path)
    best, best_type = "", ""
    for line in mounts.splitlines():
        # "/dev/disk3s5 on /System/Volumes/Data (apfs, local, journaled)"
        if " on " not in line or "(" not in line:
            continue
        point = line.split(" on ", 1)[1].rsplit(" (", 1)[0]
        fstype = line.rsplit("(", 1)[1].split(",", 1)[0].strip()
        if (target == point or target.startswith(point.rstrip("/") + "/")) \
                and len(point) >= len(best):
            best, best_type = point, fstype
    return best_type


def check_root(root: Path) -> None:
    """Refuse, with a reason, rather than degrade quietly."""
    home = Path.home()
    for forbidden in ("Documents", "Desktop", "Downloads"):
        if root == home / forbidden or (home / forbidden) in root.parents:
            raise UnsafeDataRoot(
                f"data root {root} is under ~/{forbidden}, which is commonly cloud-synced. "
                f"Set QUARRY_HOME to a local path."
            )

    probe = root if root.exists() else root.parent
    for attr in _xattrs(probe):
        if any(attr.startswith(p) for p in _SYNC_XATTRS):
            raise UnsafeDataRoot(
                f"{probe} carries the sync attribute {attr!r}. A file-provider daemon "
                f"rewriting SQLite WAL underneath us corrupts the database. Move the data root."
            )

    fs = _filesystem(probe)
    if fs and fs.lower() in _BAD_FS:
        raise UnsafeDataRoot(
            f"{probe} is on a {fs} mount. SQLite WAL requires local storage. Move the data root."
        )


def paths(root: Path | None = None) -> Paths:
    r = (root or default_root()).expanduser().resolve()
    check_root(r)
    return Paths(r).ensure()
