"""Candidate selection, the probe/runtime contracts, and verdict adjudication.

This module holds the parts of Layer 3 that do not themselves execute a target: which
findings are worth validating, the interfaces a target-runtime and a probe-lens must
satisfy, and how a probe's measured evidence maps to a verdict. The executing pieces
(standing a target up under quarry-target.sb, and the concrete probe lenses) plug in
through the registries here; until a runtime and a matching lens exist for a target,
`plan_validation` reports a candidate as un-probed rather than guessing a verdict.

A reproduction alone is not a confirmation. A probe that saw a 200, a reflected marker
or an error string has measured one response; it has not shown that the response is the
finding and not how the route always behaves. A confirmed verdict becomes an advisory a
human may send to a maintainer, so the bar is a measured difference: the evidence must
carry the control request's result (`baseline`) and say that the probe's effect departs
from it (`differs_from_baseline is True`). A reproduction without that comparison is
recorded as needs-review with the reason "no baseline comparison recorded", and the
disclosure step never drafts a needs-review finding. The probes populate the baseline
fields one at a time; until a probe does, its reproductions wait for a human.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Protocol

from .. import db

# CWE classes whose findings a running-target probe can actually decide: the effect is
# observable from a loopback client (a response, a timing separation, a reflected
# marker, an error that proves reachability). A finding outside this set is left to the
# read-only layers; Layer 3 does not pretend to confirm what it cannot observe.
DYNAMICALLY_TESTABLE = frozenset({
    "CWE-287",   # improper authentication
    "CWE-862",   # missing authorization
    "CWE-863",   # incorrect authorization
    "CWE-639",   # authorization bypass through user-controlled key (IDOR)
    "CWE-307",   # improper restriction of excessive auth attempts (rate limiting)
    "CWE-208",   # observable timing discrepancy
    "CWE-89",    # SQL injection
    "CWE-79",    # reflected cross-site scripting
    "CWE-22",    # path traversal
    "CWE-918",   # SSRF
    "CWE-77",    # command injection
    "CWE-400",   # uncontrolled resource consumption
})


@dataclass(frozen=True)
class Candidate:
    """A live finding selected for dynamic validation. Line-number-free identity, so a
    verdict written here carries forward across runs (see taint.finding_id)."""
    finding_id: str
    occurrence_id: int
    target: str
    path: str
    start_line: int | None
    producer_id: str
    cwe: str | None
    message: str


@dataclass(frozen=True)
class ProbeEvidence:
    """What a probe measured against the running target. `reproduced` and the baseline
    comparison decide the verdict; the rest is what a maintainer replays and inspects."""
    reproduced: bool
    summary: str
    request: str = ""            # the exact probe sent, for replay (no secrets)
    observed: str = ""           # the measured effect (status, timing delta, marker)
    determinism: str = "unknown"  # "deterministic" | "statistical" | "unknown"
    artifact_sha: str | None = None  # evidence blob, captured through the taint boundary
    baseline: str = ""           # the control's result: same route, benign input / creds
    differs_from_baseline: bool | None = None  # True only when measured against baseline

    @property
    def has_baseline_comparison(self) -> bool:
        return bool(self.baseline) and self.differs_from_baseline is True


# The reason a reproduction without a control comparison is held back from "confirmed".
NO_BASELINE = "no baseline comparison recorded"


class TargetRuntime(Protocol):
    """Stands one target up under quarry-target.sb and exposes a loopback base URL.

    Implementations detect how a target boots (a declared run command, a Dockerfile, a
    compose file) and are responsible for doing it inside the run volume with egress
    denied. `detect` returns None when it does not know how to run this target, with
    the reason recorded by the caller, never a guess."""

    def detect(self, src: Path) -> "RuntimeSpec | None": ...
    def start(self, spec: "RuntimeSpec", rundir: Path) -> "RunningTarget": ...


@dataclass(frozen=True)
class RuntimeSpec:
    kind: str                    # "command" | "compose" | "dockerfile"
    detail: str
    base_url: str = ""


@dataclass
class RunningTarget:
    base_url: str                # reachable only from inside `network`
    stop: Callable[[], None]
    network: str = ""            # the isolated docker network a probe joins to reach it
    service: str = ""
    port: int = 0


# Probe lenses and their selection live in lenses.py, keyed to the repo profile. The
# runtime registry stays here because candidate selection and the plan need it.
_RUNTIMES: list[TargetRuntime] = []


def register_runtime(rt: TargetRuntime) -> None:
    _RUNTIMES.append(rt)


def _cwe_of(row: dict[str, Any]) -> str | None:
    cwe = row.get("cwe")
    if cwe and str(cwe).upper().startswith("CWE-"):
        return str(cwe).upper()
    return None


def select_candidates(con: sqlite3.Connection, run_id: int, *,
                      limit: int = 50) -> list[Candidate]:
    """Live findings worth probing, best first.

    Only occurrences that survive the funnel (live_occurrences) are eligible, and only
    those whose producer's CWE is in DYNAMICALLY_TESTABLE. Ordered by the producer's
    cross-repo precision (n_confirmed / n_adjudicated), so the probe budget goes to the
    rules that have earned it, then by occurrence id for stability."""
    rows = con.execute(
        """SELECT o.id AS occurrence_id, o.finding_id, o.path, o.start_line,
                  o.message, o.producer_id, f.target, p.cwe,
                  CASE WHEN p.n_adjudicated > 0
                       THEN CAST(p.n_confirmed AS REAL) / p.n_adjudicated ELSE 0 END AS precision
             FROM live_occurrences o
             JOIN findings  f ON f.id = o.finding_id
             JOIN producers p ON p.id = o.producer_id
            WHERE o.run_id = ?
            ORDER BY precision DESC, o.id ASC""",
        (run_id,)).fetchall()
    out: list[Candidate] = []
    for r in rows:
        row = dict(r)
        cwe = _cwe_of(row)
        if cwe not in DYNAMICALLY_TESTABLE:
            continue
        out.append(Candidate(
            finding_id=row["finding_id"], occurrence_id=row["occurrence_id"],
            target=row["target"], path=row["path"], start_line=row["start_line"],
            producer_id=row["producer_id"], cwe=cwe, message=row["message"] or ""))
        if len(out) >= limit:
            break
    return out


def adjudicate(evidence: ProbeEvidence) -> str:
    """Map measured evidence to a verdict value. A probe that reproduced the finding and
    recorded a baseline it differs from is a confirmation; a probe that ran and did not
    reproduce is a rejection; everything else, a reproduction with no baseline included,
    stays needs-review. Layer 3 never confirms without both."""
    return adjudicate_with_reason(evidence)[0]


def adjudicate_with_reason(evidence: ProbeEvidence) -> tuple[str, str]:
    """The verdict and the reason stored beside it: the determinism of the signal, or
    NO_BASELINE when a reproduction was held back for want of a control comparison."""
    if evidence.reproduced:
        if evidence.has_baseline_comparison:
            return "confirmed", evidence.determinism
        return "needs-review", NO_BASELINE
    if evidence.determinism in ("deterministic", "statistical"):
        return "rejected", evidence.determinism
    return "needs-review", evidence.determinism


@dataclass
class ValidationPlan:
    """What Layer 3 would do for a run, without executing anything: the profile that
    drives selection, the candidates, which probe lenses the codebase selected (and the
    evidence that selected them), which it skipped (and why), and whether a runtime can
    boot the target. This is the dynamic, per-codebase plan the CLI shows first."""
    run_id: int
    artifact_kind: str = "unknown"
    profile_summary: str = ""
    candidates: list[Candidate] = field(default_factory=list)
    routed: int = 0              # candidates whose file maps to a discovered route
    routes_found: int = 0        # total routes discovered in the target
    runnable: bool = False
    runtime_reason: str = ""
    selected: list[tuple[str, int, str]] = field(default_factory=list)   # (lens, n, why)
    skipped: list[tuple[str, str]] = field(default_factory=list)         # (lens, why_not)


def plan_validation(con: sqlite3.Connection, run_id: int, src: Path, *,
                    limit: int = 50) -> ValidationPlan:
    """Dry run: profile the codebase, select candidates, and let the profile choose which
    probe lenses apply. Writes nothing. Honest about the gap between what survived the
    funnel and what can actually be probed on this target."""
    from ..research.profile import profile_repo
    from .lenses import select_probe_lenses
    from .routes import build_route_map

    cands = select_candidates(con, run_id, limit=limit)
    prof = profile_repo(src)
    selected_raw, skipped = select_probe_lenses(prof, cands)
    rmap = build_route_map(src)
    routed = sum(1 for c in cands if rmap.for_finding(c.path))

    spec = None
    for rt in _RUNTIMES:
        spec = rt.detect(src)
        if spec is not None:
            break
    reason = (f"runtime: {spec.kind} ({spec.detail})" if spec is not None
              else "no registered runtime can boot this target yet")
    return ValidationPlan(
        run_id=run_id, artifact_kind=prof.artifact_kind, profile_summary=prof.summary(),
        candidates=cands, routed=routed, routes_found=len(rmap.routes),
        runnable=spec is not None, runtime_reason=reason,
        selected=[(lens.key, len(matching), why) for lens, matching, why in selected_raw],
        skipped=skipped)


@dataclass
class ValidationResult:
    """The outcome of a validation run: counts and the per-finding verdicts, so the CLI
    and the dashboard can show what Layer 3 confirmed, killed, or left for review."""
    run_id: int
    confirmed: int = 0
    rejected: int = 0
    needs_review: int = 0
    verdicts: list[tuple[str, str, str]] = field(default_factory=list)  # finding, lens, verdict


def run_validation(con: sqlite3.Connection, run_id: int, rundir: Path, runtime, *,
                   limit: int = 50, enrich: bool = True) -> ValidationResult:
    """The end-to-end loop: profile the target, select candidates and the probe lenses the
    codebase supports, stand the target up under containment, probe each candidate against
    its routes, and record a verdict. Every target is torn down even on error."""
    from ..research.profile import profile_repo
    from .lenses import select_probe_lenses
    from .routes import build_route_map, fetch_openapi_routes

    rundir = Path(rundir)
    src = rundir / "src"
    res = ValidationResult(run_id)
    cands = select_candidates(con, run_id, limit=limit)
    prof = profile_repo(src)
    selected, _ = select_probe_lenses(prof, cands)
    if not selected:
        return res
    spec = runtime.detect(src)
    if spec is None:
        return res

    rmap = build_route_map(src)
    running = runtime.start(spec, rundir)
    try:
        def exec_fn(argv):
            return runtime.probe_exec(running, argv)
        if enrich:
            try:
                rmap.add_all(fetch_openapi_routes(exec_fn, running.base_url))
            except Exception:                       # enrichment is best-effort
                pass
        for lens, matching, _why in selected:
            for cand in matching:
                routes = rmap.for_finding(cand.path)
                evidence = lens.probe(running, cand, routes, exec_fn)
                with db.tx(con):
                    record_verdict(con, cand, run_id, evidence, model=lens.key)
                v = adjudicate(evidence)
                res.verdicts.append((cand.finding_id, lens.key, v))
                res.confirmed += v == "confirmed"
                res.rejected += v == "rejected"
                res.needs_review += v == "needs-review"
    finally:
        running.stop()
    return res


def record_verdict(con: sqlite3.Connection, candidate: Candidate, run_id: int,
                   evidence: ProbeEvidence, *, model: str = "probe") -> int:
    """Write the adjudication for one probed candidate. executed_score is non-zero only
    when a probe actually ran, which is the ledger's whole point, and is 100 only for a
    confirmation: a reproduction held back for want of a baseline scores as a probe that
    ran and did not decide. The full evidence, baseline included, is stored as JSON in
    `rationale` so a disclosure report is reproducible from the DB."""
    import json
    v, reason = adjudicate_with_reason(evidence)
    executed = 100 if v == "confirmed" else (
        50 if v == "rejected" or evidence.reproduced else 0)
    rationale = json.dumps({
        "summary": evidence.summary, "request": evidence.request,
        "observed": evidence.observed, "determinism": evidence.determinism,
        "baseline": evidence.baseline,
        "differs_from_baseline": evidence.differs_from_baseline,
    }, sort_keys=True)
    return db.verdict(
        con, candidate.finding_id, run_id, verdict=v, seat="dynamic", model=model,
        cwe=candidate.cwe, executed_score=executed, evidence_score=0,
        reason=reason, rationale=rationale)
