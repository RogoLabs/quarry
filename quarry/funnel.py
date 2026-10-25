"""The funnel: twelve ordered stages between Layer 1 and anything that costs money.

Seat 1's canonical order, adopted verbatim, because order changes the answer:
dedup must precede any cap or the cap is spent on duplicates; quote-verify must
precede dedup or a hallucinated finding becomes a cluster's representative and drags
real ones down with it; corroboration is meaningless before clustering because you
cannot count agreement until you have decided what "the same finding" is.

Two rules hold throughout:

* **Nothing is ever deleted.** Every stage writes a `funnel_events` row. Suppression
  is a reversible, attributed event, and `live_occurrences` is the only place the
  semantics live.
* **`defer` is not `kill`.** A rate limiter running out is not evidence of anything.
  Conflating the two destroys the only number that matters.

Every stage is deterministic and free. `deterministic=False` marks the ones whose
suppression carries real recall risk, so the UI can flag them (Seat 4).
"""
from __future__ import annotations

import json
import re
import sqlite3
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from . import db
from .taint import PLACEHOLDER_SECRETS, PLACEHOLDER_SHAS, redact_secret

# ---------------------------------------------------------------- path classes

TEST_PAT = re.compile(
    r"(^|/)(tests?|unittests?|testing|spec|specs|__tests__|e2e|fixtures?|testdata|"
    r"test_data|conftest\.py)(/|$)|(^|/)test_[^/]*$|[^/]*_test\.(py|go|js|ts|rb|java)$"
    r"|[^/]*\.(test|spec)\.(js|jsx|ts|tsx)$", re.I)

VENDOR_PAT = re.compile(
    r"(^|/)(node_modules|vendor|third_party|thirdparty|bower_components|\.venv|venv|"
    r"site-packages|dist-packages|Pods|Godeps|external|deps)(/|$)", re.I)

GENERATED_PAT = re.compile(
    r"\.(min\.js|min\.css|bundle\.js|pb\.go|pb2\.py|generated\.go)$"
    r"|(^|/)(migrations|__generated__|_generated|gen)(/|$)"
    r"|\.(lock|sum)$|(^|/)(package-lock\.json|yarn\.lock|poetry\.lock|Gemfile\.lock)$", re.I)

# Seat 3's reportability test, made deterministic. A path signalling local
# development, combined with a value that is self-evidently not a live credential.
DEVPATH_PAT = re.compile(
    r"(^|/)(deploy|deployment|examples?|samples?|docs?|demo|dev|local|"
    r"\.devcontainer|contrib|hack)(/|$)"
    r"|(^|/)docker-compose[^/]*\.ya?ml$|(^|/)compose[^/]*\.ya?ml$"
    r"|(^|/)\.env\.(example|sample|template|dist)$"
    r"|(^|/)scripts/local(/|$)", re.I)


# ---------------------------------------------------------------- independence
# Seat 1: "corroboration boost when N tools agree" mostly measures shared rule
# ancestry. njsscan IS semgrep. OSV-Scanner, Trivy, Grype and npm-audit are one
# database queried four times. Checkov and Trivy misconfig share CIS lineage. And
# opengrep ships gitleaks' own rules under `generic.secrets.gitleaks.*` — which this
# corpus actually contains, so the degenerate case is not hypothetical.
#
# Agreement is only evidence across independence classes, never within one.

def independence_class(tool: str, rule_id: str) -> str:
    r = (rule_id or "").lower()
    if tool in ("osv-scanner", "grype", "npm-audit", "cargo-audit"):
        return "sca-db"
    if tool == "trivy":
        return "policy" if r.startswith(("avd-", "ds", "ksv")) else "sca-db"
    if tool in ("gitleaks", "trufflehog") or "secrets.gitleaks" in r or "generic.secrets" in r:
        return "secrets"
    if tool in ("checkov", "kics", "tfsec"):
        return "policy"
    if tool in ("opengrep", "semgrep", "njsscan"):
        # Many semgrep python rules were ported from Bandit's checks, so those
        # specific agreements carry roughly zero bits.
        is_py = r.startswith("python.") or ".python." in r
        return "python-ast" if is_py and _bandit_ported(r) else "semgrep"
    if tool == "bandit":
        return "python-ast"
    return f"solo:{tool}"


_BANDIT_PORTED = ("subprocess", "shell-true", "yaml-load", "pickle", "marshal",
                  "md5", "sha1", "assert", "eval-detected", "exec-detected",
                  "insecure-hash", "random")


def _bandit_ported(rule_id: str) -> bool:
    return any(k in rule_id for k in _BANDIT_PORTED)


# ---------------------------------------------------------------- result

@dataclass
class StageResult:
    stage: str
    killed: int = 0
    deferred: int = 0
    merged: int = 0
    boosted: int = 0
    passed: int = 0
    remaining: int = 0           # alive after this stage — clustering must not reduce it
    heuristic: bool = False      # UI flags these as RECALL RISK

    @property
    def touched(self) -> int:
        return self.killed + self.deferred + self.merged + self.boosted


@dataclass
class FunnelResult:
    run_id: int
    started_with: int = 0
    stages: list[StageResult] = field(default_factory=list)
    survivors: int = 0

    def by_stage(self) -> dict[str, StageResult]:
        return {s.stage: s for s in self.stages}


# ---------------------------------------------------------------- the pipeline

class FunnelAlreadyRan(RuntimeError):
    """The funnel has already written its ledger for this run."""


def run(con: sqlite3.Connection, run_id: int, *, src: Path | None = None,
        budget_top_k: int | None = None) -> FunnelResult:
    """Execute every stage in Seat 1's canonical order.

    Once per run. A second pass appended a second set of score deltas (doubling
    occurrence_rank) and a second set of kills, which land after any operator
    resurrect and so silently undo it. Nothing is deleted, so there is no honest way
    to replay over an existing ledger; scan into a new run instead."""
    prior = con.execute(
        "SELECT COUNT(*) n FROM funnel_events WHERE run_id=? AND actor='system' "
        "AND stage != 'operator'", (run_id,)).fetchone()["n"]
    if prior:
        raise FunnelAlreadyRan(
            f"run {run_id} has already been through the funnel ({prior} ledger events). "
            f"Re-running would double every score and re-kill findings an operator "
            f"resurrected. Scan the target into a new run to funnel it again.")
    res = FunnelResult(run_id)
    rows = _load(con, run_id)
    res.started_with = len(rows)

    for stage_fn in (
        _quote_verify,
        _symbol_containment,
        _path_class_filter,
        _local_dev_fixture,
        _exact_dedup,
        _sca_merge,
        _cross_tool_cluster,
        _rejected_carry_forward,
        _rule_precision_prior,
        _independence_corroboration,
        _novelty_rank,
    ):
        alive = [r for r in rows if r["_alive"]]
        with db.tx(con):
            sr = stage_fn(con, run_id, alive, src)
        sr.remaining = sum(1 for r in rows if r["_alive"])
        res.stages.append(sr)

    if budget_top_k is not None:
        alive = [r for r in rows if r["_alive"]]
        with db.tx(con):
            sr = _budget_top_k(con, run_id, alive, budget_top_k)
        sr.remaining = sum(1 for r in rows if r["_alive"])
        res.stages.append(sr)

    res.survivors = sum(1 for r in rows if r["_alive"])
    _persist_summary(con, run_id, res)
    return res


def _persist_summary(con: sqlite3.Connection, run_id: int, res: "FunnelResult") -> None:
    """Write the stage list into the run manifest.

    A stage that suppressed nothing writes no ledger rows, so it would silently vanish
    from the funnel table — and a stage you cannot see is a stage you cannot audit.
    The manifest is the reproducibility record, so the stage list belongs there.
    """
    import json as _json
    row = con.execute("SELECT manifest FROM runs WHERE id=?", (run_id,)).fetchone()
    try:
        manifest = _json.loads(row["manifest"]) if row and row["manifest"] else {}
    except (ValueError, TypeError):
        manifest = {}
    manifest["funnel"] = {
        "started_with": res.started_with,
        "survivors": res.survivors,
        "stages": [{"stage": s.stage, "kill": s.killed, "defer": s.deferred,
                    "merge": s.merged, "boost": s.boosted, "pass": s.passed,
                    "remaining": s.remaining, "heuristic": s.heuristic}
                   for s in res.stages],
    }
    con.execute("UPDATE runs SET manifest=? WHERE id=?",
                (_json.dumps(manifest, sort_keys=True), run_id))


def _load(con: sqlite3.Connection, run_id: int) -> list[dict[str, Any]]:
    rows = [dict(r) for r in con.execute(
        """SELECT o.id, o.finding_id, o.producer_id, o.path, o.start_line, o.message,
                  o.severity, o.secret_prefix, o.secret_sha, o.redacted, o.blob_sha,
                  o.fingerprint, o.raw_result,
                  p.tool, p.rule_id, p.n_occurrences, p.n_adjudicated, p.n_confirmed,
                  p.enabled, b.start_line AS blob_start, b.end_line AS blob_end
           FROM occurrences o
           JOIN producers p ON p.id = o.producer_id
           LEFT JOIN evidence_blobs b ON b.sha = o.blob_sha
           WHERE o.run_id = ?
           ORDER BY o.id""", (run_id,))]
    for r in rows:
        r["_alive"] = True
        r["_score"] = 0.0
    return rows


def _kill(con, run_id, row, stage, reason, *, deterministic=True):
    row["_alive"] = False
    db.funnel(con, run_id, occurrence_id=row["id"], stage=stage, action="kill",
              reason=reason, deterministic=deterministic)


def _defer(con, run_id, row, stage, reason):
    """A rate limiter, not evidence. The finding stays true; we just are not paying
    for it this run."""
    row["_alive"] = False
    db.funnel(con, run_id, occurrence_id=row["id"], stage=stage, action="defer",
              reason=reason, deterministic=True)


def _boost(con, run_id, row, stage, reason, delta):
    row["_score"] += delta
    db.funnel(con, run_id, occurrence_id=row["id"], stage=stage, action="boost",
              reason=reason, deterministic=True, score_delta=delta)


# -- 1 -------------------------------------------------------------------------
def _quote_verify(con, run_id, rows, src) -> StageResult:
    """Does the cited location still exist? Deterministic tools rarely lie about
    this, but a stale volume or a bad path mapping does — and catching it here is
    free, where catching it at adjudication costs ~$0.50 (the measured
    false-premise class was 30% of all rejections)."""
    sr = StageResult("quote-verify")
    for r in rows:
        if r["blob_sha"] is None and r["start_line"]:
            _kill(con, run_id, r, sr.stage,
                  f"no evidence window could be captured at {r['path']}:{r['start_line']}")
            sr.killed += 1
        else:
            sr.passed += 1
    return sr


# -- 2 -------------------------------------------------------------------------
def _symbol_containment(con, run_id, rows, src) -> StageResult:
    """A finding whose line falls outside the window we captured is mislocated."""
    sr = StageResult("symbol-containment")
    for r in rows:
        ln, lo, hi = r["start_line"], r["blob_start"], r["blob_end"]
        if ln and lo and hi and not (lo <= ln <= hi):
            _kill(con, run_id, r, sr.stage,
                  f"line {ln} outside captured symbol window {lo}-{hi}")
            sr.killed += 1
        else:
            sr.passed += 1
    return sr


# -- 3 -------------------------------------------------------------------------
def _path_class_filter(con, run_id, rows, src) -> StageResult:
    """Test, vendored, and generated paths. Heuristic — flagged as recall risk,
    because DefectDojo's `unittests/` is exactly the directory a previous run's skip
    list missed, and it cost ten paid adjudications.

    **Tool-aware, and this is not a refinement — it is load-bearing.** A lockfile is
    "generated" to a SAST engine and is the *canonical and only* location for an SCA
    finding. The first run of this stage killed 107 findings on `poetry.lock`, which
    was 100% of the dependency-vulnerability output from both OSV-Scanner and Trivy.
    A path filter that is not tool-aware silently deletes an entire detector class,
    and the run still reports success. Hence: the `sca-db` class is exempt from the
    generated-path rule, and vendored trees stay excluded for everyone because a
    vulnerable dependency vendored into `node_modules/` is the dependency finding
    already reported from the manifest.
    """
    sr = StageResult("path-class", heuristic=True)
    for r in rows:
        p = r["path"]
        is_sca = independence_class(r["tool"], r["rule_id"]) == "sca-db"
        rules = [(VENDOR_PAT, "vendored"), (TEST_PAT, "test")]
        if not is_sca:
            rules.insert(1, (GENERATED_PAT, "generated"))
        for pat, label in rules:
            if pat.search(p):
                _kill(con, run_id, r, sr.stage, f"{label} path: {p}", deterministic=False)
                sr.killed += 1
                break
        else:
            sr.passed += 1
    return sr


# -- 4 -------------------------------------------------------------------------
def _local_dev_fixture(con, run_id, rows, src) -> StageResult:
    """Seat 3's reportability test.

    All three must hold to suppress: a development/example path, a secret-class
    finding, and a value that is self-evidently not a live credential. A credential
    that authenticates to a database the same file started ninety seconds ago is not
    a leaked credential, and this rule alone removes two of the four "confirmed"
    findings in the predecessor's corpus.

    Heuristic, so flagged as recall risk: the path half is a guess about intent, and
    a real key committed under deploy/ is exactly the finding worth reporting. The
    value half is therefore strict (see _looks_placeholder).
    """
    sr = StageResult("local-dev-fixture", heuristic=True)
    for r in rows:
        is_secret = r["redacted"] or independence_class(r["tool"], r["rule_id"]) == "secrets"
        if not is_secret:
            sr.passed += 1
            continue
        dev_path = bool(DEVPATH_PAT.search(r["path"]))
        if dev_path and _looks_placeholder(r):
            _kill(con, run_id, r, sr.stage,
                  f"development-path fixture credential in {r['path']} "
                  f"(value is a known placeholder, not a live credential)",
                  deterministic=False)
            sr.killed += 1
        else:
            sr.passed += 1
    return sr


def _looks_placeholder(row: dict[str, Any]) -> bool:
    """We store secrets as prefix + hash (D16), so the full value is unavailable by
    design. Kill only on proof: the stored hash is a known placeholder's hash, or the
    whole value is its four-character prefix and that prefix is a placeholder.

    This used to match an anchored pattern against the 4-character prefix (so
    "password" could never match) and then fall back to killing any "generic"
    detector, which suppressed every generic secret under deploy/ or docs/."""
    sha = row.get("secret_sha")
    if not sha:
        return False
    if sha in PLACEHOLDER_SHAS:
        return True
    prefix = row.get("secret_prefix") or ""
    return (prefix.lower() in PLACEHOLDER_SECRETS
            and redact_secret(prefix).sha256 == sha)


# -- 5 -------------------------------------------------------------------------
def _exact_dedup(con, run_id, rows, src) -> StageResult:
    """Identical (finding_id, line) from the same producer. Merge, never kill —
    the duplicate is real, it is just not a second finding."""
    sr = StageResult("exact-dedup")
    seen: dict[tuple, int] = {}
    for r in rows:
        key = (r["finding_id"], r["producer_id"], r["start_line"])
        if key in seen:
            r["_alive"] = False
            db.funnel(con, run_id, occurrence_id=r["id"], stage=sr.stage, action="merge",
                      reason=f"identical to occurrence {seen[key]}", deterministic=True,
                      merged_into=seen[key])
            sr.merged += 1
        else:
            seen[key] = r["id"]
            sr.passed += 1
    return sr


# -- 6 -------------------------------------------------------------------------
def _sca_merge(con, run_id, rows, src) -> StageResult:
    """Four tools consuming GHSA/OSV are one database queried four times.

    Merging needs aliases, not rule ids: OSV reports `PYSEC-2026-2094` where Trivy
    reports `CVE-2026-22815`, and those are the same advisory for the same package.
    Without alias resolution this stage silently finds nothing and every dependency
    vulnerability is counted twice — which then feeds a corroboration boost, so the
    duplicate is not merely noise, it actively outranks a genuine single-source
    finding.
    """
    sr = StageResult("sca-merge")
    seen: dict[tuple, int] = {}
    for r in rows:
        if independence_class(r["tool"], r["rule_id"]) != "sca-db":
            sr.passed += 1
            continue
        key = (_advisory_key(r), _package_key(r))
        if key in seen:
            r["_alive"] = False
            db.funnel(con, run_id, occurrence_id=r["id"], stage=sr.stage, action="merge",
                      reason=f"same advisory+package as occurrence {seen[key]} "
                             f"({key[0]} / {key[1]}) — one OSV/GHSA database queried twice",
                      deterministic=True, merged_into=seen[key])
            sr.merged += 1
        else:
            seen[key] = r["id"]
            sr.passed += 1
    return sr


_CVE = re.compile(r"CVE-\d{4}-\d+", re.I)
_GHSA = re.compile(r"GHSA-[\w-]+", re.I)
_PKG_TRIVY = re.compile(r"^Package:\s*(\S+)", re.I | re.M)


def _advisory_key(row: dict[str, Any]) -> str:
    """Canonical advisory id, preferring CVE, then GHSA, then the raw id.
    Aliases come from the tool's own record — OSV publishes them; Trivy's id is
    already a CVE."""
    candidates = [row.get("rule_id") or ""]
    try:
        raw = json.loads(row.get("raw_result") or "{}")
    except (ValueError, TypeError):
        raw = {}
    aliases = raw.get("aliases")
    if isinstance(aliases, list):
        candidates += [a for a in aliases if isinstance(a, str)]
    blob = " ".join(candidates)
    if m := _CVE.search(blob):
        return m.group(0).upper()
    if m := _GHSA.search(blob):
        return m.group(0).upper()
    return (row.get("rule_id") or "").upper()


def _package_key(row: dict[str, Any]) -> str:
    """Package name, from either message shape.
    OSV:   "aiohttp 3.13.3: PYSEC-..."      Trivy: "Package: aiohttp\nInstalled..."
    """
    msg = row.get("message") or ""
    if m := _PKG_TRIVY.search(msg):
        return m.group(1).strip().lower()
    try:
        pkg = (json.loads(row.get("raw_result") or "{}").get("package") or {}).get("name")
    except (ValueError, TypeError, AttributeError):
        pkg = None
    if pkg:
        return str(pkg).strip().lower()
    return msg.split(":", 1)[0].split(" ")[0].strip().lower()[:80]


# -- 7 -------------------------------------------------------------------------
def _cross_tool_cluster(con, run_id, rows, src) -> StageResult:
    """Assign issue_id: same file, overlapping lines, compatible class. A membership
    table, never a merge-and-delete — every member keeps its own row and its own
    provenance."""
    sr = StageResult("cross-tool-cluster")
    buckets: dict[tuple, list[dict]] = defaultdict(list)
    for r in rows:
        # A finding with no line (SCA on a lockfile) has no position to overlap. As
        # line 0 it fell into the 1-9 bucket and clustered with any SAST hit there.
        if not r["start_line"]:
            sr.passed += 1
            continue
        buckets[(r["path"], r["start_line"] // 10)].append(r)

    for (path, decade), members in buckets.items():
        classes = {independence_class(m["tool"], m["rule_id"]) for m in members}
        if len(members) < 2 or len(classes) < 2:
            sr.passed += len(members)
            continue
        issue_id = f"{run_id}:{path}:{decade}"
        con.execute("INSERT OR IGNORE INTO issues (id,target,title,created_run) "
                    "SELECT ?,?,?,? ",
                    (issue_id, path, f"{len(members)} findings at {path}", run_id))
        for m in members:
            con.execute("UPDATE findings SET issue_id=? WHERE id=?", (issue_id, m["finding_id"]))
            con.execute("INSERT OR IGNORE INTO issue_members (issue_id,finding_id,run_id) "
                        "VALUES (?,?,?)", (issue_id, m["finding_id"], run_id))
            m["_issue"] = issue_id
            m["_classes"] = classes
            # `pass`, not `merge`: clustering assigns identity, it never suppresses.
            # It still writes an event, because a stage that leaves no trace cannot be
            # audited and, in the UI, cannot be shown to have run at all.
            db.funnel(con, run_id, occurrence_id=m["id"], stage=sr.stage, action="pass",
                      reason=f"clustered into {issue_id} with "
                             f"{len(members) - 1} other finding(s) from "
                             f"{len(classes)} detector class(es)",
                      deterministic=True)
        sr.boosted += len(members)   # clustered, not suppressed
    return sr


# -- 8 -------------------------------------------------------------------------
def _rejected_carry_forward(con, run_id, rows, src) -> StageResult:
    """A verdict from a previous run keys on finding_id, which is line-number-free.
    Without this, a re-scan re-pays to re-reject everything it already rejected."""
    sr = StageResult("rejected-carry-forward")
    # The latest verdict per finding, selected explicitly. `GROUP BY ... HAVING MAX(id)`
    # leaned on SQLite's bare-column rule, which nothing guarantees for a HAVING.
    prior = {r["finding_id"]: r["verdict"] for r in con.execute(
        """SELECT v.finding_id, v.verdict FROM verdicts v
           JOIN (SELECT finding_id, MAX(id) AS id FROM verdicts
                 WHERE run_id != ? GROUP BY finding_id) latest ON latest.id = v.id""",
        (run_id,))}
    for r in rows:
        v = prior.get(r["finding_id"])
        if v == "rejected":
            _kill(con, run_id, r, sr.stage,
                  "adjudicated `rejected` in an earlier run; symbol content unchanged")
            sr.killed += 1
        elif v == "confirmed":
            _boost(con, run_id, r, sr.stage, "confirmed in an earlier run", 50.0)
            sr.boosted += 1
        else:
            sr.passed += 1
    return sr


# -- 9 -------------------------------------------------------------------------
def _rule_precision_prior(con, run_id, rows, src) -> StageResult:
    """The cross-repo precision ledger, used as a prior. A producer with a measured
    record earns or loses rank; an unmeasured one is worth *investigating*, because
    a cheap measurement is itself valuable (Seat 4's cheapest-information-first)."""
    sr = StageResult("rule-precision-prior")
    for r in rows:
        adj, conf, n = r["n_adjudicated"] or 0, r["n_confirmed"] or 0, r["n_occurrences"] or 0
        if not r["enabled"]:
            _kill(con, run_id, r, sr.stage, "producer dismissed by the operator",
                  deterministic=True)
            sr.killed += 1
            continue
        if adj >= 5:
            rate = conf / adj
            delta = 40.0 * rate - 10.0
            _boost(con, run_id, r, sr.stage,
                   f"producer measured {conf}/{adj} confirmed", delta)
        elif n < 5:
            _boost(con, run_id, r, sr.stage,
                   f"producer unmeasured and cheap to measure (n={n})", 6.0)
        else:
            _boost(con, run_id, r, sr.stage, f"producer unmeasured (n={n})", 2.0)
        sr.boosted += 1
    return sr


# -- 10 ------------------------------------------------------------------------
def _independence_corroboration(con, run_id, rows, src) -> StageResult:
    """Agreement weighted by independence, and **boost only**.

    It may never demote an N=1 finding. The findings that justify building this at
    all — a missing authz decorator, a cross-file taint chain — have corroboration
    N=1 by construction, because exactly one component can see them.
    """
    sr = StageResult("independence-corroboration")
    for r in rows:
        classes = r.get("_classes")
        if not classes or len(classes) < 2:
            sr.passed += 1
            continue
        own = independence_class(r["tool"], r["rule_id"])
        others = classes - {own}
        delta = 8.0 * len(others)
        _boost(con, run_id, r, sr.stage,
               f"corroborated by {len(others)} independent detector class(es): "
               f"{', '.join(sorted(others))}", delta)
        sr.boosted += 1
    return sr


# -- 11 ------------------------------------------------------------------------
def _novelty_rank(con, run_id, rows, src) -> StageResult:
    """A finding nobody has seen before outranks the fiftieth instance of a rule
    that fires everywhere. This is the counterweight to corroboration."""
    sr = StageResult("novelty-rank")
    per_producer: dict[str, int] = defaultdict(int)
    for r in rows:
        per_producer[r["producer_id"]] += 1
    for r in rows:
        n = per_producer[r["producer_id"]]
        delta = 12.0 if n == 1 else (6.0 if n <= 3 else (0.0 if n <= 20 else -6.0))
        if delta:
            _boost(con, run_id, r, sr.stage,
                   f"producer fired {n}x in this run", delta)
            sr.boosted += 1
        else:
            sr.passed += 1
    return sr


# -- 12 ------------------------------------------------------------------------
def _budget_top_k(con, run_id, rows, k: int) -> StageResult:
    """A rate limiter. Everything below the cut is **deferred, never killed** — it is
    still true, we are just not paying for it this run."""
    sr = StageResult("budget-top-k")
    ranked = sorted(rows, key=lambda r: -r["_score"])
    for r in ranked[k:]:
        _defer(con, run_id, r, sr.stage,
               f"below the top-{k} budget cut at score {r['_score']:.0f}")
        sr.deferred += 1
    sr.passed = min(k, len(ranked))
    return sr
