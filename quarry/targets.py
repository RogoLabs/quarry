"""Target selection (D2, P1a).

The panel's Adversarial Economist argued this is the highest-ROI item in the whole
plan, and the evidence is hard to dismiss: the predecessor hunted OWASP Nettacker,
DefectDojo, IntelOwl and CVE Project infrastructure — repositories with years of
professional attention — and found almost nothing. That is the correct answer for
those targets. The bottleneck was never the harness.

**What is scored, and what is deliberately not.** Score = attack surface + blast
radius + maintainer responsiveness. Audit maturity — Scorecard, `SECURITY.md`, a
CodeQL workflow — is recorded as a *covariate* and never scored, because selecting
targets on "has no security tooling" begs the exact question the calibration run
exists to answer, and would guarantee the free-stack arm wins.

**Trust.** Everything here is third-party metadata: descriptions, topics and names are
attacker-controlled strings. They cross the taint boundary before they are stored,
and they are never treated as a path or a command.
"""
from __future__ import annotations

import json
import math
import subprocess
from dataclasses import dataclass, field
from typing import Any

from . import taint

# Languages weighted by how much of their typical surface is attacker-reachable
# parsing, not by how "unsafe" the language is in the abstract.
LANG_SURFACE = {
    "C": 10, "C++": 10, "Objective-C": 7,
    "PHP": 9, "Python": 8, "Ruby": 8, "JavaScript": 8, "TypeScript": 7,
    "Java": 7, "Go": 6, "C#": 6, "Rust": 4, "Kotlin": 6, "Scala": 5,
    "Perl": 7, "Lua": 6, "Elixir": 5, "Shell": 4,
}

# Topic and description signals for "this thing parses input somebody else controls".
SURFACE_TERMS = {
    "server": 6, "daemon": 6, "proxy": 6, "gateway": 6, "broker": 5,
    "api": 5, "rest": 4, "graphql": 5, "grpc": 4, "websocket": 5,
    "parser": 7, "decoder": 6, "deserial": 7, "codec": 5, "protocol": 5,
    "upload": 6, "file-sharing": 6, "storage": 4,
    "auth": 7, "oauth": 7, "sso": 7, "jwt": 6, "session": 5, "rbac": 6,
    "framework": 4, "cms": 6, "webapp": 5, "dashboard": 4, "admin": 5,
    "webhook": 5, "ingest": 5, "importer": 5, "crawler": 4, "scraper": 4,
    "sandbox": 6, "plugin": 5, "template": 5, "database": 4, "orm": 4,
}
NEGATIVE_TERMS = {
    "awesome": -12, "list": -6, "curated": -8, "cheatsheet": -8, "tutorial": -6,
    "documentation": -6, "docs": -4, "blog": -6, "dotfiles": -8, "resume": -8,
    "boilerplate": -4, "example": -4, "demo": -4, "book": -6, "course": -6,
    "wordlist": -10, "seclist": -10, "payloads": -8, "dataset": -6, "papers": -6,
    "collection": -6, "resources": -6, "roadmap": -6, "interview": -8,
}


@dataclass
class TargetScore:
    slug: str
    score: float = 0.0
    surface: float = 0.0
    blast_radius: float = 0.0
    responsiveness: float = 0.0
    language: str | None = None
    stars: int = 0
    pushed_at: str | None = None
    archived: bool = False
    license_spdx: str | None = None
    covariates: dict[str, Any] = field(default_factory=dict)
    reasons: list[str] = field(default_factory=list)
    #: {destination: {requests, bytes_in}} — every host this scoring pass touched.
    hosts_contacted: dict[str, dict[str, int]] = field(default_factory=dict)
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.error


# ---------------------------------------------------------------- fetchers

def _gh(path: str, timeout: int = 20,
        ledger: dict[str, dict[str, int]] | None = None) -> dict[str, Any] | None:
    """Public metadata via the authenticated gh CLI. Read-only, and the response is
    treated as untrusted data. Recorded in `ledger` — see `_http_json`."""
    try:
        p = subprocess.run(["gh", "api", path], capture_output=True, text=True,
                           timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError):
        _record(ledger, "api.github.com", 0)
        return None
    _record(ledger, "api.github.com", len(p.stdout.encode("utf-8", "replace")))
    if p.returncode != 0:
        return None
    try:
        return json.loads(p.stdout)
    except ValueError:
        return None


def _http_json(url: str, timeout: int = 15,
               ledger: dict[str, dict[str, int]] | None = None) -> dict[str, Any] | None:
    """A public JSON endpoint, recorded.

    `ledger` accumulates {destination: {requests, bytes_in}} so the caller can write
    `egress` rows. Scoring reached two hosts that never appeared in the ledger, which
    meant `quarry doctor` under-reported the product's own network destinations —
    and "completely local" is only worth saying if the ledger can prove it.
    """
    host = ""
    try:
        from urllib.parse import urlsplit
        host = urlsplit(url).netloc
    except ValueError:
        host = "unparseable-url"
    try:
        # -q first: ignore ~/.curlrc, which could add headers, a proxy or an upload
        # to a request the ledger thinks it understands.
        p = subprocess.run(["curl", "-q", "-sS", "--max-time", str(timeout), url],
                           capture_output=True, text=True, timeout=timeout + 5, check=False)
    except (OSError, subprocess.SubprocessError):
        _record(ledger, host, 0)
        return None
    _record(ledger, host, len(p.stdout.encode("utf-8", "replace")))
    if p.returncode != 0 or not p.stdout.strip():
        return None
    try:
        return json.loads(p.stdout)
    except ValueError:
        return None


def _record(ledger: dict[str, dict[str, int]] | None, host: str, nbytes: int) -> None:
    """A request that failed still left the machine, so it is still recorded."""
    if ledger is None or not host:
        return
    slot = ledger.setdefault(host, {"requests": 0, "bytes_in": 0})
    slot["requests"] += 1
    slot["bytes_in"] += nbytes


def log_egress(con, ts: "TargetScore") -> None:
    """Write one ledger row per destination a scoring pass contacted.

    Called even when the score failed: the requests happened either way.
    """
    from . import db as _db
    for host, m in sorted(ts.hosts_contacted.items()):
        _db.egress(con, None, "targets-score", host, bytes_out=0,
                   bytes_in=m["bytes_in"],
                   note=f"{m['requests']} request(s) scoring {ts.slug} — "
                        "public metadata, no credential, read-only")


# ---------------------------------------------------------------- scoring

def _log_points(value: float | None, cap: float, scale: float) -> float:
    if not value or value <= 0:
        return 0.0
    return min(cap, scale * math.log10(1 + value))


def _days_since(iso: str | None) -> float | None:
    if not iso:
        return None
    from datetime import datetime, timezone
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return None
    return (datetime.now(timezone.utc) - dt).days


def score_target(slug: str, *, now_days: float | None = None) -> TargetScore:
    """Fetch and score one `owner/repo`."""
    ts = TargetScore(slug=slug)
    repo = _gh(f"repos/{slug}", ledger=ts.hosts_contacted)
    if repo is None:
        ts.error = "metadata unavailable (private, missing, or rate-limited)"
        return ts

    ts.language = taint.scrub_text(repo.get("language"), 40) or None
    ts.stars = int(repo.get("stargazers_count") or 0)
    ts.pushed_at = taint.scrub_text(repo.get("pushed_at"), 40) or None
    ts.archived = bool(repo.get("archived"))
    ts.license_spdx = ((repo.get("license") or {}).get("spdx_id") or None)

    topics = [taint.scrub_text(t, 60).lower() for t in (repo.get("topics") or [])]
    desc = taint.scrub_text(repo.get("description"), 400).lower()
    haystack = " ".join(topics) + " " + desc + " " + slug.lower()

    # ---- surface -------------------------------------------------------
    surface = float(LANG_SURFACE.get(ts.language or "", 3))
    ts.reasons.append(f"language {ts.language or 'unknown'} (+{surface:.0f})")

    matched = []
    for term, pts in SURFACE_TERMS.items():
        if term in haystack:
            surface += pts
            matched.append(term)
    if matched:
        ts.reasons.append(f"surface terms {', '.join(sorted(matched)[:6])} "
                          f"(+{sum(SURFACE_TERMS[m] for m in matched)})")
    penalties = [t for t in NEGATIVE_TERMS if t in haystack]
    if penalties:
        pen = sum(NEGATIVE_TERMS[t] for t in penalties)
        surface += pen
        ts.reasons.append(f"non-code signals {', '.join(sorted(penalties)[:4])} ({pen})")

    kb = int(repo.get("size") or 0)
    size_pts = _log_points(kb, 8, 2.0)
    surface += size_pts
    ts.surface = max(0.0, min(40.0, surface))

    # ---- blast radius --------------------------------------------------
    eco = _http_json(f"https://repos.ecosyste.ms/api/v1/hosts/GitHub/repositories/"
                     f"{slug.replace('/', '%2F')}", ledger=ts.hosts_contacted)
    dependents = 0
    if eco:
        dependents = int(eco.get("dependent_repos_count") or 0) + \
                     int(eco.get("dependent_packages_count") or 0)
    blast = _log_points(dependents, 20, 6.0) + _log_points(ts.stars, 10, 2.6)
    if dependents:
        ts.reasons.append(f"{dependents} dependents (+{_log_points(dependents, 20, 6.0):.0f})")
    ts.reasons.append(f"{ts.stars} stars (+{_log_points(ts.stars, 10, 2.6):.0f})")
    ts.blast_radius = min(30.0, blast)

    # ---- responsiveness ------------------------------------------------
    days = now_days if now_days is not None else _days_since(ts.pushed_at)
    resp = 0.0
    if days is not None:
        if days <= 30:
            resp += 14
        elif days <= 90:
            resp += 10
        elif days <= 365:
            resp += 5
        ts.reasons.append(f"last push {days:.0f}d ago (+{resp:.0f})")
    committers = int(((eco or {}).get("commit_stats") or {}).get("total_committers") or 0)
    resp += _log_points(committers, 10, 5.0)
    if committers:
        ts.reasons.append(f"{committers} committers (+{_log_points(committers, 10, 5.0):.0f})")
    open_issues = int(repo.get("open_issues_count") or 0)
    if ts.stars > 100 and open_issues / max(ts.stars, 1) > 0.25:
        resp -= 5
        ts.reasons.append("high open-issue ratio (-5)")
    ts.responsiveness = max(0.0, min(30.0, resp))

    # ---- covariates: recorded, never scored ----------------------------
    sc = _http_json(f"https://api.securityscorecards.dev/projects/github.com/{slug}",
                    ledger=ts.hosts_contacted)
    ts.covariates = {
        "openssf_scorecard": (sc or {}).get("score"),
        "has_security_md": bool(_gh(f"repos/{slug}/contents/SECURITY.md",
                                    ledger=ts.hosts_contacted)),
        "has_codeql_workflow": _has_codeql(slug, ledger=ts.hosts_contacted),
        "archived": ts.archived,
        "license_osi_known": bool(ts.license_spdx and ts.license_spdx != "NOASSERTION"),
    }

    # Surface GATES; it does not merely add.
    #
    # An additive model scored `danielmiessler/SecLists` at 45 and
    # `sindresorhus/awesome` at 34 — a wordlist and a link directory outranking real
    # applications, purely on stars and commit recency. Reach and maintainer activity
    # are multipliers on how much a vulnerability would matter; they cannot conjure
    # one into existence. A repository with no attacker-reachable code has nothing to
    # find no matter how many projects depend on it, so surface=0 must be an absolute
    # veto rather than a small deduction.
    reach = 1.0 + 0.7 * (ts.blast_radius / 30.0) + 0.5 * (ts.responsiveness / 30.0)
    ts.score = round(ts.surface * reach, 1)
    ts.reasons.append(f"score = surface {ts.surface:.0f} × reach {reach:.2f} "
                      f"(blast {ts.blast_radius:.0f}/30, resp {ts.responsiveness:.0f}/30)")
    if ts.archived:
        ts.score = 0.0
        ts.reasons.append("archived — not a viable disclosure target, score zeroed")
    return ts


def _has_codeql(slug: str, ledger: dict[str, dict[str, int]] | None = None) -> bool:
    listing = _gh(f"repos/{slug}/contents/.github/workflows", ledger=ledger)
    if not isinstance(listing, list):
        return False
    return any("codeql" in taint.scrub_text(f.get("name"), 100).lower()
               for f in listing if isinstance(f, dict))


# ---------------------------------------------------------------- persistence

def save(con, ts: TargetScore, stratum: str | None = None) -> None:
    con.execute("""
        INSERT INTO targets (slug,score,surface,blast_radius,responsiveness,language,
                             stars,pushed_at,archived,license_spdx,covariates,reasons,
                             stratum,scored_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,datetime('now'))
        ON CONFLICT(slug) DO UPDATE SET
          score=excluded.score, surface=excluded.surface,
          blast_radius=excluded.blast_radius, responsiveness=excluded.responsiveness,
          language=excluded.language, stars=excluded.stars, pushed_at=excluded.pushed_at,
          archived=excluded.archived, license_spdx=excluded.license_spdx,
          covariates=excluded.covariates, reasons=excluded.reasons,
          stratum=COALESCE(excluded.stratum, targets.stratum),
          scored_at=datetime('now')""",
        (ts.slug, ts.score, ts.surface, ts.blast_radius, ts.responsiveness,
         ts.language, ts.stars, ts.pushed_at, int(ts.archived), ts.license_spdx,
         json.dumps(ts.covariates, sort_keys=True), json.dumps(ts.reasons), stratum))


def ranked(con, limit: int = 50, stratum: str | None = None) -> list[dict[str, Any]]:
    sql = "SELECT * FROM targets WHERE archived=0"
    args: list[Any] = []
    if stratum:
        sql += " AND stratum=?"
        args.append(stratum)
    sql += " ORDER BY score DESC LIMIT ?"
    args.append(limit)
    return [dict(r) for r in con.execute(sql, args)]
