"""Vulnerability-database provisioning.

The one place Quarry deliberately reaches the network for tool data. It runs
*outside* the sandbox — a scanner may never fetch its own database, because a tool
that can reach the network during a scan can also exfiltrate the target. Every fetch
is written to the egress ledger so "completely local" stays an auditable claim rather
than a slogan.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from . import db
from .sandbox.spawn import BASE_ENV, db_dir


@dataclass
class SyncResult:
    name: str
    ok: bool
    seconds: float
    detail: str = ""


# Where each fetch actually goes, for the egress ledger. A label such as "trivy
# vulnerability database" made the ledger unauditable: it named no host. Trivy pulls
# the trivy-db OCI artifact from its default repositories in priority order
# (trivy 0.76.0 `--db-repository` default); grype reads its v6 listing and archive
# from grype.anchore.io; osv-scanner downloads one zip per ecosystem from the OSV
# bucket. Registry blob redirects are not enumerated here.
HOSTS = {
    "trivy": ("mirror.gcr.io", "ghcr.io"),
    "grype": ("grype.anchore.io",),
    "osv-scanner": ("osv-vulnerabilities.storage.googleapis.com",),
}

# The only variables a sync inherits from the operator's environment: proxy and CA
# settings, without which a fetch behind a corporate proxy cannot work. Everything
# else (tokens, cloud credentials, tool config) stays out.
_PASS_ENV = ("HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy",
             "no_proxy", "SSL_CERT_FILE", "SSL_CERT_DIR")


def _env(root: Path, extra: dict[str, str]) -> dict[str, str]:
    """A minimal environment. HOME and the XDG dirs point at an empty directory so a
    tool cannot pick up the operator's own config (~/.grype.yaml, a docker login)."""
    home = root / "_home"
    (home / ".config").mkdir(parents=True, exist_ok=True)
    (home / "tmp").mkdir(parents=True, exist_ok=True)
    env = {"PATH": BASE_ENV["PATH"], "LANG": "C.UTF-8", "HOME": str(home),
           "TMPDIR": str(home / "tmp"), "XDG_CACHE_HOME": str(home / ".cache"),
           "XDG_CONFIG_HOME": str(home / ".config"),
           "GRYPE_CHECK_FOR_APP_UPDATE": "false", "DO_NOT_TRACK": "1"}
    env.update({k: os.environ[k] for k in _PASS_ENV if k in os.environ})
    env.update(extra)
    return env


def _sync(name: str, argv: list[str], env: dict[str, str], timeout: int) -> SyncResult:
    import time
    exe = shutil.which(argv[0])
    if not exe:
        return SyncResult(name, False, 0.0, f"{argv[0]} not installed")
    started = time.monotonic()
    try:
        p = subprocess.run([exe, *argv[1:]], capture_output=True, text=True,
                           env=env, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return SyncResult(name, False, time.monotonic() - started,
                          f"timed out after {timeout}s")
    except OSError as e:
        return SyncResult(name, False, time.monotonic() - started, f"could not run: {e}")
    dur = time.monotonic() - started
    # osv-scanner exits 1 when it finds vulnerabilities in the seed, which is success.
    if p.returncode not in (0,) and not (name == "osv-scanner" and p.returncode == 1):
        return SyncResult(name, False, dur,
                          (p.stderr or p.stdout).strip().splitlines()[-1][:200] if (p.stderr or p.stdout) else "failed")
    return SyncResult(name, True, dur)


# OSV downloads databases per ecosystem, and only for ecosystems where it actually
# resolves a package. A manifest with zero packages (or, for npm, one with no resolved
# URL) registers no ecosystem, so its database is never fetched and the first real
# target in that language fails the scan with "no offline version of the OSV database is
# available" (exit 127). MEASURED: empty package-lock.json/Gemfile.lock/composer.lock
# seeds left npm, RubyGems and Packagist undownloaded while PyPI/Go/crates.io (which had
# a real entry) worked. Each seed therefore pins one real, long-lived package so every
# ecosystem's DB is pulled. The seeds live as data files, not as string literals here,
# so the npm `resolved` registry URL they must carry is not a URL in the Python source
# (test_no_paid_models greps *.py for outbound hosts); it is inert fixture data that
# osv-scanner reads to identify a package, never a host anything contacts.
SEEDS_DIR = Path(__file__).resolve().parent / "vulndb_seeds"


def _osv_seed(root: Path) -> Path:
    seed = root / "_seed"
    seed.mkdir(parents=True, exist_ok=True)
    for f in SEEDS_DIR.iterdir():
        if f.is_file():
            (seed / f.name).write_bytes(f.read_bytes())
    return seed


def sync_all(con: sqlite3.Connection | None = None, *, timeout: int = 900) -> list[SyncResult]:
    """Fetch the databases the scanners read: Trivy's and OSV's. Grype's is no longer
    fetched (decision A, 2026-11-05): no adapter reads it, it is the same sca-db class
    as OSV and Trivy so sca-merge would fold its findings into theirs, and it was the
    largest disk cost (3,358 MB on 2026-11-02) and one more network step. A copy
    already on disk is left alone and shown by `db status` as unused."""
    root = db_dir()
    root.mkdir(parents=True, exist_ok=True)
    # Trivy consults the docker credential helper even for a filesystem DB pull. This
    # started as a workaround for Docker Desktop being absent, but it stays now that it
    # is installed, and for a better reason: pulling a public vulnerability database
    # needs no registry credential, so it should not be able to read one. Least
    # privilege, not a bug workaround.
    empty_docker = root / "_docker"
    empty_docker.mkdir(parents=True, exist_ok=True)
    (empty_docker / "config.json").write_text("{}\n")

    results = [
        _sync("trivy", ["trivy", "fs", "--download-db-only", "--quiet"],
              _env(root, {"TRIVY_CACHE_DIR": str(root / "trivy"),
                          "DOCKER_CONFIG": str(empty_docker)}), timeout),
        _sync("osv-scanner", ["osv-scanner", "scan", "source", "--recursive",
                              "--download-offline-databases", "--offline-vulnerabilities",
                              str(_osv_seed(root))],
              _env(root, {"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": str(root / "osv")}),
              timeout),
    ]
    if con is not None:
        for r in results:
            if r.detail.endswith("not installed"):
                continue                      # nothing ran, nothing left the machine
            for host in HOSTS[r.name]:
                db.egress(con, None, "db-sync", host,
                          note=f"{r.name} database: " + ("ok" if r.ok else r.detail))
    return results


def status() -> dict[str, str]:
    root = db_dir()
    out: dict[str, str] = {}
    for name in ("trivy", "grype", "osv"):
        d = root / name
        if not d.exists():
            out[name] = "absent"
            continue
        total = sum(f.stat().st_size for f in d.rglob("*") if f.is_file())
        out[name] = f"{total / 1e6:.0f} MB"
        if name == "grype":
            out[name] += f" (not synced or read since decision A; safe to delete {d})"
    return out


# ------------------------------------------------------------------ age

#: A database older than this is called out on the run page and in `doctor`. Trivy's
#: own NextUpdate is 24 hours after UpdatedAt; a week is the point where a scan's
#: "nothing found" stops being worth much, not a precise threshold.
STALE_DAYS = 7
#: Which database each scanner reads. Grype has a database but no adapter (decision A).
DB_OF_TOOL = {"trivy": "trivy", "osv-scanner": "osv"}
_GRYPE_BUILT = re.compile(r"_(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)_")


def _parse_ts(text: str) -> datetime | None:
    """ISO-8601 with any number of fractional digits (Trivy writes nanoseconds)."""
    m = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:?\d{2})?$",
                 text.strip())
    if not m:
        return None
    frac = (m[2] or "")[:7]
    tz = "+00:00" if m[3] in (None, "Z") else m[3]
    try:
        return datetime.fromisoformat(f"{m[1]}{frac}{tz}")
    except ValueError:
        return None


def built_at(name: str, root: Path | None = None) -> tuple[datetime | None, str]:
    """When a database's data was built, and what that is read from. Each tool records
    it differently, so the basis travels with the time."""
    import json
    root = root or db_dir()
    if name == "trivy":
        p = root / "trivy" / "db" / "metadata.json"
        try:
            return _parse_ts(json.loads(p.read_text()).get("UpdatedAt", "")), \
                "metadata.json UpdatedAt"
        except (OSError, ValueError, AttributeError):
            return None, "metadata.json missing"
    if name == "grype":
        p = root / "grype" / "6" / "import.json"
        try:
            m = _GRYPE_BUILT.search(json.loads(p.read_text()).get("source", ""))
        except (OSError, ValueError, AttributeError):
            return None, "import.json missing"
        return (_parse_ts(m[1]) if m else None), "archive build time in import.json"
    if name == "osv":
        # OSV publishes per-ecosystem zips continuously, so the download time is close
        # to the data's age. The oldest ecosystem is the one that matters.
        zips = list((root / "osv").rglob("all.zip"))
        if not zips:
            return None, "no ecosystem zips"
        oldest = min(z.stat().st_mtime for z in zips)
        return datetime.fromtimestamp(oldest, timezone.utc), \
            f"oldest of {len(zips)} ecosystem zip download times"
    raise ValueError(f"unknown database {name!r}")


def ages(now: datetime | None = None, root: Path | None = None) -> dict[str, dict]:
    now = now or datetime.now(timezone.utc)
    out = {}
    for name in ("trivy", "grype", "osv"):
        when, basis = built_at(name, root)
        out[name] = {"built": when.isoformat() if when else None, "basis": basis,
                     "age_days": round((now - when).total_seconds() / 86400, 1)
                     if when else None}
    return out


def stale_warnings(by_db: dict[str, dict], tools: list[str]) -> dict[str, list[str]]:
    """Health messages for the scanners in `tools`, keyed by tool, empty when fresh."""
    out: dict[str, list[str]] = {}
    for tool in tools:
        name = DB_OF_TOOL.get(tool)
        if name is None:
            continue
        a = by_db.get(name) or {}
        if a.get("age_days") is None:
            out[tool] = [f"{name} database build time unknown ({a.get('basis', '?')}); "
                         f"run `quarry db sync`"]
        elif a["age_days"] > STALE_DAYS:
            out[tool] = [f"{name} database is {a['age_days']:.0f} days old at scan time "
                         f"(over {STALE_DAYS}); its clean results may be stale. Run "
                         f"`quarry db sync` and re-scan"]
        else:
            out[tool] = []
    return out
