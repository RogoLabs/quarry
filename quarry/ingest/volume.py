"""Per-run APFS sparse image.

One mechanism, four problems (Seat 5, P0 step 2):
  * a hard disk quota, so an archive bomb fills 20 GB of sparse image and stops
    rather than filling the boot volume;
  * case sensitivity, so `README.md` and `readme.md` are distinct as they are on the
    Linux CI the target was written for;
  * a stable `subpath` for the sandbox profile to anchor on;
  * retention as a single `rm`.

Measured: creating a 1 GB image costs ~9 MB on disk, and `dd` of 1.2 GB into it stops
at 999 MB in 0.57 s with host free space unchanged.
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

MOUNT_BASE = Path("/private/tmp/quarry")
SUBDIRS = ("src", "home", "home/.config", "cache", "out", "quarantine", "logs")
# Per hdiutil detach attempt, in seconds. Generous on purpose; it only has to be finite.
DETACH_TIMEOUT = 60


class VolumeError(RuntimeError):
    pass


def _run(argv: list[str], timeout: int = 120) -> subprocess.CompletedProcess:
    p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    if p.returncode != 0:
        raise VolumeError(f"{argv[0]} failed ({p.returncode}): {p.stderr.strip() or p.stdout.strip()}")
    return p


@dataclass
class RunVolume:
    run_id: int
    image: Path
    mount: Path

    @classmethod
    def create(cls, run_id: int, images_dir: Path, size_gb: int = 20) -> "RunVolume":
        images_dir.mkdir(parents=True, exist_ok=True)
        image = images_dir / f"{run_id}.sparseimage"
        mount = MOUNT_BASE / f"run-{run_id}"
        if image.exists():
            raise VolumeError(f"image already exists: {image}")
        _run(["/usr/bin/hdiutil", "create", "-size", f"{size_gb}g",
              "-fs", "Case-sensitive APFS", "-type", "SPARSE",
              "-volname", f"quarry-{run_id}", "-quiet", str(image)])
        mount.mkdir(parents=True, exist_ok=True)
        _run(["/usr/bin/hdiutil", "attach", "-nobrowse", "-owners", "off",
              "-mountpoint", str(mount), str(image)])
        for d in SUBDIRS:
            (mount / d).mkdir(parents=True, exist_ok=True)
        return cls(run_id, image, mount)

    @classmethod
    def attach_existing(cls, run_id: int, images_dir: Path) -> "RunVolume":
        image = images_dir / f"{run_id}.sparseimage"
        mount = MOUNT_BASE / f"run-{run_id}"
        if not image.exists():
            raise VolumeError(f"no image for run {run_id}")
        if not mount.is_mount():
            mount.mkdir(parents=True, exist_ok=True)
            _run(["/usr/bin/hdiutil", "attach", "-nobrowse", "-owners", "off",
                  "-mountpoint", str(mount), str(image)])
        return cls(run_id, image, mount)

    @property
    def src(self) -> Path:
        return self.mount / "src"

    @property
    def quarantine(self) -> Path:
        return self.mount / "quarantine"

    def detach(self, timeout: int = DETACH_TIMEOUT) -> None:
        if self.mount.is_mount():
            # hdiutil occasionally needs a moment after a tool exits. A plain detach
            # can also hang while something holds the volume open, and with no bound it
            # would hang the orchestrator with it. So each attempt is bounded, and a
            # hang is treated like a refusal: escalate to -force.
            for force in (False, True):
                argv = ["/usr/bin/hdiutil", "detach", str(self.mount), "-quiet"]
                if force:
                    argv.append("-force")
                try:
                    p = subprocess.run(argv, capture_output=True, text=True,
                                       timeout=timeout, check=False)
                except subprocess.TimeoutExpired:
                    continue
                if p.returncode == 0:
                    break

    def release(self) -> None:
        """Detach and delete. Evidence lives in blobs, not here (D15)."""
        self.detach()
        self.image.unlink(missing_ok=True)

    def __enter__(self) -> "RunVolume":
        return self

    def __exit__(self, *exc) -> None:
        self.detach()
