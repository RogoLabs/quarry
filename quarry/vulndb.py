"""Vulnerability-database provisioning.

The one place Quarry deliberately reaches the network for tool data. It runs
*outside* the sandbox — a scanner may never fetch its own database, because a tool
that can reach the network during a scan can also exfiltrate the target. Every fetch
is written to the egress ledger so "completely local" stays an auditable claim rather
than a slogan.

It also reads what was fetched: the advisory draft's prior-advisory check searches the
downloaded OSV zips on disk and never fetches.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sqlite3
import zipfile
from dataclasses import dataclass, field
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


def _osv_zips(root: Path) -> dict[str, Path]:
    """The offline OSV databases on disk, by ecosystem. osv-scanner lays them out as
    `<cache>/<subdir>/<Ecosystem>/all.zip`; the directory name is the ecosystem."""
    return {z.parent.name: z for z in sorted((root / "osv").rglob("all.zip"))}


# ------------------------------------------------------------------ prior advisories

# An OSV record is a few KB; one past this is not a record this lookup should inflate.
_OSV_MEMBER_CAP = 4 * 1024 * 1024


@dataclass(frozen=True)
class PriorAdvisory:
    """One local OSV record that names the package or the repository."""
    id: str
    aliases: tuple[str, ...]
    cwes: tuple[str, ...]
    summary: str
    modified: str
    ecosystem: str
    basis: str                    # one of BASES, strongest first


# Why a record was matched, strongest first. A reference URL under the repository is the
# weakest, and one record can sit in several ecosystems' zips. MEASURED on the live copy
# before de-duplication: Django's 3 reference-URL matches were all one jQuery advisory
# (GHSA-6c3j-c64m-qhgq) in the Packagist, RubyGems and npm zips. Its PyPI copy names
# django as an affected package, so it is now kept once, as a package-name match.
BASES = ("package name", "affected repository", "reference URL")


@dataclass
class PriorCheck:
    """What a local prior-advisory lookup did, so the draft can say what was searched as
    well as what was found. `checked` False means nothing was searched, with `reason`."""
    checked: bool
    reason: str = ""
    ecosystems: tuple[str, ...] = ()       # the local OSV copies read
    entries_read: int = 0
    downloaded: str | None = None          # oldest ecosystem zip download date
    package: str = ""
    package_ecosystem: str = ""            # "" when the name was not searched
    repo: str = ""                         # normalised repository key, "" when not searched
    matches: list[PriorAdvisory] = field(default_factory=list)


def _pypi_name(name: str) -> str:
    """PEP 503 normalisation: PyPI treats runs of -, _ and . as one separator."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _same_package(ecosystem: str, a: str, b: str) -> bool:
    if ecosystem == "PyPI":
        return _pypi_name(a) == _pypi_name(b)
    return a.lower() == b.lower()


def repo_key(url: str) -> str:
    """`host/owner/repo`, lower-case, from any spelling of a repository URL (scheme,
    `git@host:` form, trailing `.git` or slash, query or fragment). "" when the URL has
    fewer than three parts, so a bare host can never match every advisory on it."""
    s = (url or "").strip().lower()
    s = re.sub(r"^[a-z][a-z0-9+.-]*://", "", s)
    s = re.sub(r"^[^@/]+@([^:/]+):", r"\1/", s)       # git@github.com:owner/repo
    s = re.sub(r"^[^@/]+@", "", s)
    s = s.removeprefix("www.").split("#")[0].split("?")[0]
    s = s.rstrip("/").removesuffix(".git").rstrip("/")
    return s if s.count("/") >= 2 else ""


def _names_repo(url: str, key: str) -> bool:
    k = repo_key(url)
    if not k:
        return False
    return k == key or k.startswith(key + "/")


def local_prior_advisories(ecosystem: str, package: str, repo_url: str,
                           root: Path | None = None) -> PriorCheck:
    """Search the offline OSV databases `quarry db sync` already downloaded for records
    that name this package (exact, in its own ecosystem) or this repository (a GIT
    range or a reference URL under it, in any ecosystem on disk). Reads local zips
    only; nothing here touches the network, which is why a missing database is a
    reported gap and not a fetch.

    A record is matched by package name only in the guessed ecosystem, since the same
    name in another registry is another project. The repository name a run carries is
    not always the published package name, so the repository URL is the stronger key.
    A miss does not show the issue is new: the copy is a snapshot and OSV is not every
    advisory source.

    MEASURED 2026-11-05 on the live OSV copy (six ecosystems, 283,287 records, downloaded
    2026-10-28): 3.2 to 3.4 s per lookup over five targets. npm alone is 230,903 records
    (388 MB unpacked). A byte pre-filter means only records that mention the name or the
    repository are parsed. django matched 339 records, all by package name; the three
    targets Quarry has run (vulnerability-lookup, ML-Gateway, cve-services) matched none."""
    root = root or db_dir()
    zips = _osv_zips(root)
    if not zips:
        return PriorCheck(False, "no local OSV database; quarry db sync downloads one")
    key = repo_key(repo_url)
    name = (package or "").strip()
    by_name = ecosystem if (name and ecosystem in zips) else ""
    if not key and not by_name:
        return PriorCheck(False, f"no local OSV database for {ecosystem} and no "
                                 f"repository URL to search by")
    when, _ = built_at("osv", root)
    check = PriorCheck(True, ecosystems=tuple(zips), package=name,
                       package_ecosystem=by_name, repo=key,
                       downloaded=when.date().isoformat() if when else None)
    # The pre-filter looks for the name as a JSON string; PyPI spellings differ in their
    # separators, so any run of -, _ or . stands for one.
    parts = [re.escape(p) for p in re.split(r"[-_.]+", name.lower()) if p]
    pat = "[-_.]+".join(parts) if ecosystem == "PyPI" else re.escape(name.lower())
    name_re = re.compile(('"' + pat + '"').encode()) if by_name else None
    key_b = key.encode()
    found: dict[str, PriorAdvisory] = {}
    for eco, path in zips.items():
        try:
            zf = zipfile.ZipFile(path)
        except (OSError, zipfile.BadZipFile):
            continue
        with zf:
            for info in zf.infolist():
                if info.is_dir() or info.file_size > _OSV_MEMBER_CAP:
                    continue
                raw = zf.read(info)
                check.entries_read += 1
                low = raw.lower()
                hit_name = bool(name_re and eco == by_name and name_re.search(low))
                hit_repo = bool(key_b and key_b in low)
                if not (hit_name or hit_repo):
                    continue
                try:
                    rec = json.loads(raw)
                except ValueError:
                    continue
                if not isinstance(rec, dict):
                    continue
                basis = _osv_basis(rec, eco, by_name, name, key)
                if not basis:
                    continue
                adv = _prior(rec, eco, basis)
                old = found.get(adv.id)
                if old is None or BASES.index(basis) < BASES.index(old.basis):
                    found[adv.id] = adv
    check.matches = list(found.values())
    return check


def _osv_basis(rec: dict, eco: str, by_name: str, name: str, key: str) -> str:
    """Why this record is about the target, re-checked on the parsed record (the byte
    pre-filter only says the string occurs somewhere), or "" when it is not."""
    affected = [a for a in rec.get("affected") or [] if isinstance(a, dict)]
    if eco == by_name:
        for a in affected:
            pkg = a.get("package") or {}
            if (isinstance(pkg, dict) and pkg.get("ecosystem") == eco
                    and isinstance(pkg.get("name"), str)
                    and _same_package(eco, pkg["name"], name)):
                return "package name"
    if key:
        repos = [r.get("repo") for a in affected for r in a.get("ranges") or []
                 if isinstance(r, dict)]
        if any(isinstance(u, str) and _names_repo(u, key) for u in repos):
            return "affected repository"
        refs = [r.get("url") for r in rec.get("references") or [] if isinstance(r, dict)]
        if any(isinstance(u, str) and _names_repo(u, key) for u in refs):
            return "reference URL"
    return ""


def _prior(rec: dict, eco: str, basis: str) -> PriorAdvisory:
    from .cwe import normalise
    ds = rec.get("database_specific") or {}
    cwes = ds.get("cwe_ids") if isinstance(ds, dict) else None
    return PriorAdvisory(
        id=str(rec.get("id") or "?"),
        aliases=tuple(str(a) for a in rec.get("aliases") or [] if isinstance(a, str)),
        cwes=tuple(c for c in (normalise(x) for x in cwes or [] if isinstance(x, str)) if c),
        summary=str(rec.get("summary") or ""), modified=str(rec.get("modified") or ""),
        ecosystem=eco, basis=basis)


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
