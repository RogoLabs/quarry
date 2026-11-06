"""The funnel: thirteen ordered stages between Layer 1 and anything that costs money.

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

from . import db, dismissals
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
    health: dict[str, list[str]] = field(default_factory=dict)

    def by_stage(self) -> dict[str, StageResult]:
        return {s.stage: s for s in self.stages}


# ---------------------------------------------------------------- the pipeline

def run(con: sqlite3.Connection, run_id: int, *, src: Path | None = None,
        budget_top_k: int | None = None) -> FunnelResult:
    """Execute every stage in Seat 1's canonical order over the run's *fresh*
    occurrences: those no funnel stage has written an event for yet.

    Per occurrence, not per run. It used to refuse a second pass, because replaying
    over the ledger doubled every score and re-killed findings an operator had
    resurrected. But a re-scan and Layer 2 both add occurrences after the funnel ran,
    and those were never funnelled at all: 1,717 of 2,779 on run 1, all live. Now
    each occurrence goes through once. Already-funnelled live occurrences are context
    (`prior`): a fresh duplicate merges into them, a fresh hit can cluster with them,
    and they count toward novelty, but no stage writes an event for them again.

    Deep-review occurrences wait while their research run is still going, and are
    deferred at the Layer 2 gate while their cross-family refutation is pending. A
    later pass revives a deferred one once its refutation is in (`_revive_layer2`)."""
    res = FunnelResult(run_id)
    rows = _load(con, run_id)
    with db.tx(con):
        _revive_layer2(con, run_id, rows)
    entered = [r for r in rows if r["_fresh"] and r["_alive"]]
    res.started_with = len(entered)

    for stage_fn in STAGES:
        fresh = [r for r in rows if r["_alive"] and r["_fresh"]]
        prior = [r for r in rows if r["_alive"] and not r["_fresh"]]
        with db.tx(con):
            sr = stage_fn(con, run_id, fresh, src, prior)
        sr.remaining = sum(1 for r in rows if r["_alive"] and r["_fresh"])
        res.stages.append(sr)

    if budget_top_k is not None:
        fresh = [r for r in rows if r["_alive"] and r["_fresh"]]
        with db.tx(con):
            sr = _budget_top_k(con, run_id, fresh, budget_top_k)
        sr.remaining = sum(1 for r in rows if r["_alive"] and r["_fresh"])
        res.stages.append(sr)

    res.survivors = sum(1 for r in rows if r["_alive"] and r["_fresh"])
    with db.tx(con):
        _persist_summary(con, run_id, res)
        res.health = funnel_health(entered)
        db.set_health(con, run_id, "funnel", res.health)
    return res


def funnel_health(entered: list[dict[str, Any]]) -> dict[str, list[str]]:
    """A tool with output that lost every occurrence to deterministic kills. That is
    what Checkov's broken paths looked like (21 of 21 killed by quote-verify) and the
    run still reported success. Merges do not count: a duplicate is not a loss."""
    by_tool: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in entered:
        by_tool[r["tool"]].append(r)
    out: dict[str, list[str]] = {}
    for tool, rs in by_tool.items():
        if all(r.get("_det_kill") for r in rs):
            stages = sorted({r["_det_kill"] for r in rs})
            out[tool] = [f"all {len(rs)} new occurrence(s) killed by deterministic "
                         f"stage(s) {', '.join(stages)}; check the tool's output"]
        else:
            out[tool] = []
    return out


def _persist_summary(con: sqlite3.Connection, run_id: int, res: "FunnelResult") -> None:
    """Write the stage list into the run manifest.

    A stage that suppressed nothing writes no ledger rows, so it would silently vanish
    from the funnel table — and a stage you cannot see is a stage you cannot audit.
    The manifest is the reproducibility record, so the stage list belongs there.

    Each pass is appended to `passes`; `stages` holds the order and the recall-risk
    flag. Counts are not stored here: the run page reads them from the ledger, which
    is what each cell links to.
    """
    import json as _json
    row = con.execute("SELECT manifest FROM runs WHERE id=?", (run_id,)).fetchone()
    try:
        manifest = _json.loads(row["manifest"]) if row and row["manifest"] else {}
    except (ValueError, TypeError):
        manifest = {}
    old = manifest.get("funnel") if isinstance(manifest.get("funnel"), dict) else {}
    passes = list(old.get("passes") or [])
    if not passes and old.get("stages"):
        # A run funnelled before passes were recorded: keep its one pass.
        passes.append({"started_with": old.get("started_with"),
                       "survivors": old.get("survivors")})
    passes.append({"started_with": res.started_with, "survivors": res.survivors})
    manifest["funnel"] = {
        "passes": passes,
        "stages": [{"stage": s.stage, "heuristic": s.heuristic} for s in res.stages],
    }
    con.execute("UPDATE runs SET manifest=? WHERE id=?",
                (_json.dumps(manifest, sort_keys=True), run_id))


def _research_in_progress(con: sqlite3.Connection, run_id: int) -> set[int]:
    """Research runs whose worker is verifiably still working. Read through the same
    liveness rule as the dashboard, never from the status column alone: run 1's deep
    review still said `running` five days after its last heartbeat, with its pid gone,
    and trusting that would hold its 1,708 candidates out of the funnel forever. A
    resume the dashboard has claimed and is starting counts too: its worker is about
    to add to the same candidates."""
    from .web.queries import live_status        # the reader-side rule, one copy of it
    return {r["id"] for r in con.execute("SELECT * FROM research_runs WHERE run_id=?",
                                         (run_id,))
            if live_status(dict(r))[0] in ("running", "unverified", "starting")}


def _load(con: sqlite3.Connection, run_id: int) -> list[dict[str, Any]]:
    """Every occurrence of the run. `_alive` mirrors `live_occurrences`, so an operator
    dismissal holds; `_fresh` marks the ones no funnel stage has seen."""
    rows = [dict(r) for r in con.execute(
        """SELECT o.id, o.finding_id, o.producer_id, o.path, o.start_line, o.message,
                  o.severity, o.secret_prefix, o.secret_sha, o.redacted, o.blob_sha,
                  o.fingerprint, o.raw_result,
                  p.tool, p.rule_id, p.n_occurrences, p.n_adjudicated, p.n_confirmed,
                  p.enabled, b.start_line AS blob_start, b.end_line AS blob_end,
                  rf.id AS rf_id, rf.research_id, rf.quote_verified, rf.n_survived,
                  rf.n_refuted, rf.refutations, rf.refuter_errors, rf.n_unsupported,
                  EXISTS (SELECT 1 FROM live_occurrences l WHERE l.id = o.id) AS live,
                  NOT EXISTS (SELECT 1 FROM funnel_events f WHERE f.occurrence_id = o.id
                                AND f.stage != 'operator') AS unseen
           FROM occurrences o
           JOIN producers p ON p.id = o.producer_id
           LEFT JOIN evidence_blobs b ON b.sha = o.blob_sha
           LEFT JOIN research_findings rf ON rf.occurrence_id = o.id
           WHERE o.run_id = ?
           ORDER BY o.id""", (run_id,))]
    busy = _research_in_progress(con, run_id)
    for r in rows:
        r["_busy"] = r["research_id"] in busy
        r["_alive"] = bool(r["live"])
        r["_fresh"] = bool(r["unseen"]) and not r["_busy"]
        r["_score"] = 0.0
    return rows


def _layer2_decided(r: dict[str, Any]) -> bool:
    return (not r["quote_verified"] or bool(r["n_survived"]) or bool(r["n_refuted"])
            or bool(r.get("n_unsupported")))


def _revive_layer2(con, run_id: int, rows: list[dict[str, Any]]) -> None:
    """A deep candidate deferred at the Layer 2 gate because no cross-family refuter
    had answered comes back once one has (`quarry deep --resume` finishes the refute
    pass). Only when that defer is still its latest event, so an operator's later
    dismissal stands."""
    deferred = {r["occurrence_id"] for r in con.execute(
        """SELECT f.occurrence_id FROM funnel_events f
           WHERE f.run_id = ? AND f.stage = 'layer2-gate' AND f.action = 'defer'
             AND f.id = (SELECT MAX(g.id) FROM funnel_events g
                         WHERE g.occurrence_id = f.occurrence_id)""", (run_id,))}
    for r in rows:
        if r["id"] in deferred and r["rf_id"] is not None and _layer2_decided(r) \
                and not r["_busy"]:
            db.funnel(con, run_id, occurrence_id=r["id"], stage="layer2-gate",
                      action="resurrect", deterministic=True,
                      reason="cross-family refutation completed; re-entering the funnel")
            r["_alive"] = r["_fresh"] = True


def _kill(con, run_id, row, stage, reason, *, deterministic=True):
    row["_alive"] = False
    if deterministic:
        row["_det_kill"] = stage
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
def _quote_verify(con, run_id, rows, src, prior=()) -> StageResult:
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


# -- 1b ------------------------------------------------------------------------
def _layer2_gate(con, run_id, rows, src, prior=()) -> StageResult:
    """Deep-review candidates pass only on the bar the Layer 2 digest uses: the quote
    verified against the source, and a model of another family defended the claim
    after being told to refute it. They used to skip the funnel entirely and land in
    triage as 1,708 live rows, refuted ones included.

    A quote that is not in the source is a deterministic kill. Refutation by every
    cross-family model that answered is a model's judgement, so it is flagged as
    recall risk; since decision F only a refutation whose quoted evidence is on the
    claim's path counts. A claim every refuter tried to refute without such evidence
    passes as "not rebutted" (`ensemble.KEPT_SQL`). No answer yet is a defer, not
    evidence, and is revived later."""
    sr = StageResult("layer2-gate", heuristic=True)
    for r in rows:
        if r["tool"] != "deep" or r["rf_id"] is None:
            sr.passed += 1
        elif not r["quote_verified"]:
            _kill(con, run_id, r, sr.stage,
                  "the model's quoted code was not found in the source")
            sr.killed += 1
        elif r["n_survived"]:
            sr.passed += 1
        elif r["n_refuted"]:
            _kill(con, run_id, r, sr.stage,
                  f"refuted by all {r['n_refuted']} cross-family model(s) that answered",
                  deterministic=False)
            sr.killed += 1
        elif r.get("n_unsupported"):
            # Decision F: no answering refuter rebutted the claim. Each either said
            # `refuted` without quoting a guard on the claim's path, even when asked
            # again, or said `uncertain`. That is not a rejection, so the claim goes to a
            # human, as a Layer 3 probe that could not decide does. The event says why,
            # since a plain pass would look like a defence.
            db.funnel(con, run_id, occurrence_id=r["id"], stage=sr.stage, action="pass",
                      reason=f"not rebutted: {r['n_unsupported']} cross-family "
                             f"answer(s) were uncertain or refuted without evidence on "
                             f"the claim's path",
                      deterministic=False)
            sr.passed += 1
        elif (r["refutations"] or "[]") == "[]":
            _defer(con, run_id, r, sr.stage,
                   "awaiting cross-family refutation: no refuter has answered yet")
            sr.deferred += 1
        else:
            # Measured on runs 1 and 2: 14 candidates, every refuter errored or had its
            # verdict discarded. `quarry deep --resume` asks a model whose only record
            # is an error again (item 5), and _revive_layer2 brings the finding back
            # once a usable verdict lands.
            _defer(con, run_id, r, sr.stage,
                   f"no usable cross-family verdict: {r['refuter_errors'] or 0} refuter "
                   f"error(s) and no valid refutation or defence")
            sr.deferred += 1
    return sr


# -- 2 -------------------------------------------------------------------------
def _symbol_containment(con, run_id, rows, src, prior=()) -> StageResult:
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
def _path_class_filter(con, run_id, rows, src, prior=()) -> StageResult:
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

    The `secrets` class is exempt from the test-path rule for the same reason. A key
    committed under `tests/` is as leaked as one under `src/`, and run 1 killed 38
    Gitleaks hits here by path alone. local-dev-fixture decides them on the value.

    It is exempt from the generated-path rule too (decision 2026-11-05). A lockfile is
    where a private registry token lands: npm writes `resolved` URLs with credentials
    into package-lock.json, and a built bundle carries the keys its build embedded.
    Generated or not, the token is committed. Once Gitleaks stopped skipping lockfiles
    (item 23), this rule would have killed exactly those hits. Vendored trees still
    apply: a secret under node_modules/ is far more often a third-party fixture.
    """
    sr = StageResult("path-class", heuristic=True)
    for r in rows:
        p = r["path"]
        cls = independence_class(r["tool"], r["rule_id"])
        rules = [(VENDOR_PAT, "vendored")]
        if cls not in ("sca-db", "secrets"):
            rules.append((GENERATED_PAT, "generated"))
        if cls != "secrets":
            rules.append((TEST_PAT, "test"))
        for pat, label in rules:
            if pat.search(p):
                _kill(con, run_id, r, sr.stage, f"{label} path: {p}", deterministic=False)
                sr.killed += 1
                break
        else:
            sr.passed += 1
    return sr


# -- 4 -------------------------------------------------------------------------
def _local_dev_fixture(con, run_id, rows, src, prior=()) -> StageResult:
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
        # Test paths count as development paths here: path-class leaves secrets in
        # them to this stage, which kills only on a known placeholder value.
        dev_path = bool(DEVPATH_PAT.search(r["path"]) or TEST_PAT.search(r["path"]))
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
def _exact_dedup(con, run_id, rows, src, prior=()) -> StageResult:
    """Identical (finding_id, line) from the same producer. Merge, never kill —
    the duplicate is real, it is just not a second finding. A fresh duplicate of an
    already-funnelled occurrence merges into it."""
    sr = StageResult("exact-dedup")
    seen: dict[tuple, int] = {(r["finding_id"], r["producer_id"], r["start_line"]): r["id"]
                              for r in reversed(prior)}
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
def _sca_merge(con, run_id, rows, src, prior=()) -> StageResult:
    """Four tools consuming GHSA/OSV are one database queried four times.

    Merging needs aliases, not rule ids: OSV reports `PYSEC-2026-2094` where Trivy
    reports `CVE-2026-22815`, and those are the same advisory for the same package.
    Without alias resolution this stage silently finds nothing and every dependency
    vulnerability is counted twice — which then feeds a corroboration boost, so the
    duplicate is not merely noise, it actively outranks a genuine single-source
    finding.
    """
    sr = StageResult("sca-merge")
    seen: dict[tuple, int] = {(_advisory_key(r), _package_key(r)): r["id"]
                              for r in reversed(prior)
                              if independence_class(r["tool"], r["rule_id"]) == "sca-db"}
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
def _cross_tool_cluster(con, run_id, rows, src, prior=()) -> StageResult:
    """Assign issue_id: same file, overlapping lines, compatible class. A membership
    table, never a merge-and-delete — every member keeps its own row and its own
    provenance. Already-funnelled occurrences are members too, so a fresh hit can
    cluster with one; only the fresh members get an event."""
    sr = StageResult("cross-tool-cluster")
    fresh = {r["id"] for r in rows}
    by_path: dict[str, list[dict]] = defaultdict(list)
    for r in (*prior, *rows):
        # A finding with no line (SCA on a lockfile) has no position to overlap. As
        # line 0 it fell into the 1-9 bucket and clustered with any SAST hit there.
        if not r["start_line"]:
            sr.passed += r["id"] in fresh
            continue
        by_path[r["path"]].append(r)
    target = (con.execute("SELECT target FROM runs WHERE id=?", (run_id,)).fetchone()
              or [""])[0]

    for path, members in _line_groups(by_path):
        classes = {independence_class(m["tool"], m["rule_id"]) for m in members}
        new = [m for m in members if m["id"] in fresh]
        if len(members) < 2 or len(classes) < 2 or not new:
            sr.passed += len(new)
            continue
        issue_id = _issue_id(con, run_id, path, members)
        # issues.target is the repository, as on every other table. It was written with
        # the file path.
        con.execute("INSERT INTO issues (id,target,title,created_run) VALUES (?,?,?,?) "
                    "ON CONFLICT(id) DO UPDATE SET title=excluded.title",
                    (issue_id, target, f"{len(members)} findings at {path}", run_id))
        for m in members:
            con.execute("UPDATE findings SET issue_id=? WHERE id=?", (issue_id, m["finding_id"]))
            con.execute("INSERT OR IGNORE INTO issue_members (issue_id,finding_id,run_id) "
                        "VALUES (?,?,?)", (issue_id, m["finding_id"], run_id))
            m["_issue"] = issue_id
            m["_classes"] = classes
        for m in new:
            # `pass`, not `merge`: clustering assigns identity, it never suppresses.
            # It still writes an event, because a stage that leaves no trace cannot be
            # audited and, in the UI, cannot be shown to have run at all.
            db.funnel(con, run_id, occurrence_id=m["id"], stage=sr.stage, action="pass",
                      reason=f"clustered into {issue_id} with "
                             f"{len(members) - 1} other finding(s) from "
                             f"{len(classes)} detector class(es)",
                      deterministic=True)
        # Counted as passed, matching the events above. It was counted as boosted, so
        # the funnel table showed "boost 3" over a set of zero boost events.
        sr.passed += len(new)
    return sr


CLUSTER_SPAN = 10


def _line_groups(by_path: dict[str, list[dict]]):
    """Per file, findings whose lines fall within CLUSTER_SPAN of the group's first
    line. Bucketing by `line // 10` put lines 9 and 10 in different buckets, so two
    tools flagging adjacent lines never clustered."""
    for path, rs in by_path.items():
        rs = sorted(rs, key=lambda r: (r["start_line"], r["id"]))
        group: list[dict] = []
        for r in rs:
            if group and r["start_line"] - group[0]["start_line"] > CLUSTER_SPAN:
                yield path, group
                group = []
            group.append(r)
        if group:
            yield path, group


def _issue_id(con, run_id: int, path: str, members: list[dict]) -> str:
    """Reuse the issue an earlier pass gave any member in this run, so a fresh hit that
    lands above an existing cluster joins it rather than opening a second one."""
    ids = [m["finding_id"] for m in members]
    marks = ",".join("?" * len(ids))
    have = con.execute(
        f"SELECT MIN(issue_id) FROM findings WHERE id IN ({marks}) AND issue_id LIKE ?",
        (*ids, f"{run_id}:%")).fetchone()[0]
    return have or f"{run_id}:{path}:{members[0]['start_line']}"


# -- 8 -------------------------------------------------------------------------
def _rejected_carry_forward(con, run_id, rows, src, prior=()) -> StageResult:
    """A verdict from a previous run keys on finding_id, which is line-number-free.
    Without this, a re-scan re-pays to re-reject everything it already rejected."""
    sr = StageResult("rejected-carry-forward")
    # The latest verdict per finding, selected explicitly. `GROUP BY ... HAVING MAX(id)`
    # leaned on SQLite's bare-column rule, which nothing guarantees for a HAVING.
    prior = {r["finding_id"]: r for r in con.execute(
        """SELECT v.finding_id, v.run_id, v.verdict, v.seat, v.reason, v.rationale
           FROM verdicts v
           JOIN (SELECT finding_id, MAX(id) AS id FROM verdicts
                 WHERE run_id != ? GROUP BY finding_id) latest ON latest.id = v.id""",
        (run_id,))}
    for r in rows:
        p = prior.get(r["finding_id"])
        v = p["verdict"] if p else None
        if v == "rejected" and _controlled_rejection(p):
            if why := _still_applies(p, r):
                _kill(con, run_id, r, sr.stage, why)
                sr.killed += 1
            else:
                sr.passed += 1               # reopened: the probe or the code moved
        elif v == "confirmed":
            _boost(con, run_id, r, sr.stage, "confirmed in an earlier run", 50.0)
            sr.boosted += 1
        else:
            sr.passed += 1
    return sr


def _still_applies(v, row) -> str:
    """The reopen condition (IMPROVEMENT-PLAN item 18). A rejection is carried forward
    only while what it was measured against is unchanged: the same probe source, and
    the same evidence window around the flagged line. finding_id alone keys on the
    flagged line(s), so a changed handler around an unchanged line, or a fixed probe,
    used to keep the old kill forever. Returns the kill reason, or "" to reopen. A
    rejection written before probes recorded their identity reopens."""
    import json as _json
    try:
        probe = (_json.loads(v["rationale"] or "{}") or {}).get("probe") or {}
    except (ValueError, TypeError, AttributeError):
        return ""
    if not probe.get("source_sha") or not probe.get("evidence_blob"):
        return ""
    if probe["evidence_blob"] != row["blob_sha"]:
        return ""
    from .dynamic.lenses import CATALOGUE
    from .dynamic.validate import probe_source_sha
    lens = next((ln for ln in CATALOGUE if ln.key == probe.get("id")), None)
    if lens is None or probe_source_sha(lens) != probe["source_sha"]:
        return ""
    where = f" against {probe.get('method')} {probe.get('route')}" if probe.get("route") else ""
    return (f"rejected in run {v['run_id']} by probe {probe['id']}{where}; probe source "
            f"and evidence window unchanged")


def _controlled_rejection(v) -> bool:
    """A kill that outlives its run needs the strongest rejection Layer 3 makes: a
    deterministic probe whose handled request behaved like a recorded control. A
    statistical miss, or a rejection written before probes recorded controls, stays a
    verdict on its own run and is not carried forward."""
    import json as _json
    if v["seat"] != "dynamic" or v["reason"] != "deterministic":
        return False
    try:
        ev = _json.loads(v["rationale"] or "{}")
    except (ValueError, TypeError):
        return False
    return (isinstance(ev, dict) and bool(ev.get("baseline"))
            and ev.get("differs_from_baseline") is False and ev.get("handled") is True)


# -- 9 -------------------------------------------------------------------------
def _rule_precision_prior(con, run_id, rows, src, prior=()) -> StageResult:
    """The cross-repo precision ledger, used as a prior. A producer with a measured
    record earns or loses rank; an unmeasured one is worth *investigating*, because
    a cheap measurement is itself valuable (Seat 4's cheapest-information-first)."""
    sr = StageResult(dismissals.FUNNEL_STAGE)
    # A repo dismissal is keyed on the target, so it holds for every run of it, not
    # just the run it was made from (see quarry/dismissals.py).
    run = con.execute("SELECT target FROM runs WHERE id=?", (run_id,)).fetchone()
    repo_off = dismissals.repo_dismissals(con, run["target"]) if run else {}
    for r in rows:
        adj, conf, n = r["n_adjudicated"] or 0, r["n_confirmed"] or 0, r["n_occurrences"] or 0
        why = (dismissals.FUNNEL_CORPUS if not r["enabled"] else
               dismissals.FUNNEL_REPO if r["producer_id"] in repo_off else None)
        if why:
            _kill(con, run_id, r, sr.stage, why, deterministic=True)
            # The operator's decision, not the tool losing its output: it must not
            # trip the "every occurrence killed" health check.
            r.pop("_det_kill", None)
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
def _independence_corroboration(con, run_id, rows, src, prior=()) -> StageResult:
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
def _novelty_rank(con, run_id, rows, src, prior=()) -> StageResult:
    """A finding nobody has seen before outranks the fiftieth instance of a rule
    that fires everywhere. This is the counterweight to corroboration. The count
    includes the run's already-funnelled live occurrences."""
    sr = StageResult("novelty-rank")
    per_producer: dict[str, int] = defaultdict(int)
    for r in (*prior, *rows):
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


#: Seat 1's canonical order, plus the Layer 2 gate right after quote-verify: a deep
#: candidate must clear its own bar before it can be deduplicated or clustered.
STAGES = (
    _quote_verify,
    _layer2_gate,
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
)


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
