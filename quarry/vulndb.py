"""Vulnerability-database provisioning.

The one place Quarry deliberately reaches the network for tool data. It runs
*outside* the sandbox — a scanner may never fetch its own database, because a tool
that can reach the network during a scan can also exfiltrate the target. Every fetch
is written to the egress ledger so "completely local" stays an auditable claim rather
than a slogan.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sqlite3
from dataclasses import dataclass
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


# OSV downloads databases per ecosystem, and only for ecosystems it actually sees.
# A seed tree with one empty manifest per ecosystem makes the sync deterministic
# instead of "whatever the last repo happened to use".
OSV_SEED_MANIFESTS = {
    "requirements.txt": "requests==2.0.0\n",
    "package-lock.json": '{"name":"seed","lockfileVersion":3,"packages":{}}\n',
    "go.mod": "module seed\n\ngo 1.21\n",
    "Gemfile.lock": "GEM\n  specs:\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n",
    "Cargo.lock": 'version = 3\n\n[[package]]\nname = "seed"\nversion = "0.1.0"\n',
    "composer.lock": '{"packages":[],"packages-dev":[]}\n',
}


def _osv_seed(root: Path) -> Path:
    seed = root / "_seed"
    seed.mkdir(parents=True, exist_ok=True)
    for name, body in OSV_SEED_MANIFESTS.items():
        (seed / name).write_text(body)
    return seed


def sync_all(con: sqlite3.Connection | None = None, *, timeout: int = 900) -> list[SyncResult]:
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
        _sync("grype", ["grype", "db", "update"],
              _env(root, {"GRYPE_DB_CACHE_DIR": str(root / "grype")}), timeout),
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
    return out
