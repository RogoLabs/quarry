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

A non-reproduction is not a rejection either, and the bar is the same. A rejected
verdict kills the finding in every later run (funnel stage rejected-carry-forward), so
it needs as much proof as a confirmation: the probe's requests were answered by a
handler (`handled`, so not 404, 405 or nothing) and the attack input behaved like a
recorded control (`baseline` set, `differs_from_baseline is False`). Without that it is
needs-review with the reason "no control comparison recorded". Before this, a login
route that answered 404 to both timing identifiers was rejected, and stayed rejected.
"""
from __future__ import annotations

import dataclasses

import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Protocol

from .. import db
from ..cwe import normalise as normalise_cwe, probe_class

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

# Deep-review lenses a probe class covers, and the CWE that selects that class. A deep
# finding's producer is its lens, with no CWE, so until this map none of them reached
# Layer 3: on run 3 every deep-review finding was left out of `quarry validate`. A lens
# is a kind of question, not a CWE, so a probe that does not reproduce the model's
# claim cannot reject it (`INFERRED_CWE`); a confirmation on the finding's own handler
# still counts, and its verdict records where the CWE came from. The injection lens is
# not mapped: it spans XSS, SQL, command injection and SSRF, and which check to send
# would be a guess.
DEEP_LENS_CWE = {
    "broken-authz-idor": "CWE-639",
    "multi-tenancy-isolation": "CWE-863",
    "filesystem-and-path": "CWE-22",
}


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
    # Where `cwe` came from when the producer has none: "deep lens <key>". Empty for a
    # scanner's own CWE. A candidate with one is never rejected (`final_verdict`).
    cwe_from: str = ""


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
    differs_from_baseline: bool | None = None  # True/False only when measured against baseline
    handled: bool | None = None  # True only when a handler answered (not 404/405/nothing)
    # What a reproduction looks like next to the control. "differs" for almost every
    # probe: the finding's effect is something the control lacks (a SQL error the plain
    # value did not raise, a cross-user delete the anonymous control was refused). "same"
    # for a finding that is the absence of a defence: a missing rate limit reproduces
    # when every request of a bounded burst is answered exactly like a lone request, and
    # the defence shows as a difference (a 429). Stored in the rationale, so the
    # disclosure step reads a "same" confirmation the right way round.
    reproduces_when: str = "differs"
    # False when the probe could not exercise the finding at all: no route in its file to
    # address, no check for its class, nothing measured. The verdict is then `untested`,
    # which asks nothing of a person, rather than needs-review, which does.
    exercised: bool = True

    @property
    def _supporting(self) -> bool:
        """The value of differs_from_baseline that supports the finding."""
        return self.reproduces_when != "same"

    @property
    def has_baseline_comparison(self) -> bool:
        return bool(self.baseline) and self.differs_from_baseline is self._supporting

    @property
    def has_negative_control(self) -> bool:
        """The attack input was handled and behaved like the control did (for a "same"
        probe: the defence appeared, which the lone control request did not need)."""
        return (bool(self.baseline) and self.differs_from_baseline is (not self._supporting)
                and self.handled is True)


# The reason a reproduction without a control comparison is held back from "confirmed".
NO_BASELINE = "no baseline comparison recorded"
# The reason a non-reproduction without a handled control is held back from "rejected".
NO_CONTROL = "no control comparison recorded"
# The reason a confirmation is held back when replaying it did not give the same result.
DID_NOT_REPLAY = "did not replay"
# The reason stored beside an `untested` verdict; the evidence summary says which gap.
UNTESTED = "the probe could not exercise the finding"
# The reason a rejection is held back when the candidate's CWE was inferred from a lens.
INFERRED_CWE = "CWE inferred from a deep-review lens, so not reproducing it rejects nothing"


class TargetRuntime(Protocol):
    """Stands one target up and exposes a base URL that probes can reach.

    Implementations detect how a target boots (a declared run command, a Dockerfile, a
    compose file) and are responsible for doing it with egress denied. The Docker
    runtime does not run under quarry-target.sb; it contains a target through the
    compose document it writes (runtime_docker.harden_compose). `detect` returns None
    when it does not know how to run this target, with the reason recorded by the
    caller, never a guess."""

    def detect(self, src: Path) -> "RuntimeSpec | None": ...
    def start(self, spec: "RuntimeSpec", rundir: Path) -> "RunningTarget": ...


@dataclass(frozen=True)
class RuntimeSpec:
    kind: str                    # "command" | "compose" | "dockerfile"
    detail: str
    base_url: str = ""
    # Parameter-free GET routes from the clone's own route map. Readiness requires one
    # of them to answer as the app would (IMPROVEMENT-PLAN item 16).
    ready_paths: tuple[str, ...] = ()


def readiness_paths(rmap, limit: int = 6) -> tuple[str, ...]:
    """Routes that can show the running service is this target: GET, no path parameter
    to guess, no wildcard. Committed-spec routes first (they describe the deployed
    API, prefix included), then static ones, shortest first so `/` and `/api/health`
    style routes lead. Pure: reads the route map, sends nothing."""
    order = {"openapi": 0, "static": 1}
    seen: set[str] = set()
    picks: list[tuple[int, int, str]] = []
    for r in rmap.routes.values():
        p = r.path
        if r.method != "GET" or r.params or any(c in p for c in "{}<>:*"):
            continue
        if not p.startswith("/") or p in seen:
            continue
        seen.add(p)
        picks.append((order.get(r.source, 2), len(p), p))
    return tuple(p for _, _, p in sorted(picks)[:limit])


@dataclass
class RunningTarget:
    base_url: str                # reachable only from inside `network`
    stop: Callable[[], None]
    network: str = ""            # the isolated docker network a probe joins to reach it
    service: str = ""
    port: int = 0
    # Real values for named path parameters, so a probe addresses a record that exists
    # instead of the placeholder `1`. Keyed by parameter name (vulnerability_id, uid).
    # Empty means every parameter falls back to `1`, the old behaviour.
    param_values: dict[str, str] = field(default_factory=dict)
    # Test credentials a seed recipe created with the target's own commands, by name
    # (e.g. {"admin_api_key": "..."}). In memory only, for authenticated probes; never
    # stored or rendered. Empty unless a recipe ran.
    credentials: dict[str, str] = field(default_factory=dict)
    # How to reach the target's own service containers for operator setup steps. Set by
    # the Docker runtime; a sidecar probe does not need them.
    project: str = ""
    compose_file: str = ""
    # The per-user resources a seed recipe declared for the cross-user authz probe
    # (seed.CrossUser): which test account owns what, and how the target's own API
    # creates, reads and deletes it. None unless a recipe that declares them ran.
    cross_user: Any = None


# Probe lenses and their selection live in lenses.py, keyed to the repo profile. The
# runtime registry stays here because candidate selection and the plan need it.
_RUNTIMES: list[TargetRuntime] = []


def register_runtime(rt: TargetRuntime) -> None:
    _RUNTIMES.append(rt)


def _cwe_of(row: dict[str, Any]) -> str | None:
    # Normalised on read as well as at ingest, so producers stored in the long form
    # before ingest normalised them are still selected.
    return normalise_cwe(row.get("cwe"))


def _deep_quote_line(con: sqlite3.Connection, src: Path, occurrence_id: int,
                     path: str) -> int | None:
    """The 1-based line a deep finding's quote starts on in `path`, or None.

    Read through quote verification's path checks (`grounding._read`). A same-named
    file standing in for a missing path gives no line, since a route matches the
    finding by its own path. In Python, a quote on a decorator belongs to the def it
    decorates (`intent._past_decorators`), which is where a handler's lines start."""
    import json as _json
    from ..research import grounding, intent
    row = con.execute("SELECT raw_result FROM occurrences WHERE id=?",
                      (occurrence_id,)).fetchone()
    try:
        quote = str((_json.loads(row["raw_result"] or "{}") if row else {}).get("quote")
                    or "")
    except ValueError:
        return None
    got = grounding._read(src, path) if quote.strip() else None
    if not got or got[0] != path:
        return None
    lines = got[1]
    idx = intent.quote_line(lines, quote)
    if idx is None:
        return None
    if path.endswith(".py"):
        idx = intent._past_decorators(lines, idx)
    return idx + 1


def _interleave(cands: list[Candidate]) -> list[Candidate]:
    """Probe classes take turns, each keeping its own order, so one plentiful class
    cannot fill the budget before another class gets a probe."""
    queues: dict[str, list[Candidate]] = {}
    for c in cands:
        queues.setdefault(probe_class(c.cwe) or "", []).append(c)
    out: list[Candidate] = []
    while any(queues.values()):
        for q in queues.values():
            if q:
                out.append(q.pop(0))
    return out


def select_candidates(con: sqlite3.Connection, run_id: int, *, limit: int = 50,
                      routed: Callable[[str], Any] | None = None,
                      src: Path | None = None) -> list[Candidate]:
    """Live findings worth probing, best first.

    Only occurrences that survive the funnel (live_occurrences) are eligible, and only
    those whose producer's CWE is in DYNAMICALLY_TESTABLE. Dependency findings
    (the funnel's `sca-db` class) are left out: they sit on a lockfile, which has no
    route, and both verdicts in the operator's DB were probes against poetry.lock that
    could not run. Ordered by the producer's
    cross-repo precision (n_confirmed / n_adjudicated), so the probe budget goes to the
    rules that have earned it, then by occurrence id for stability. One occurrence per
    (finding, file) is kept: routes are looked up per file, so a second one in the same
    file would repeat the same probe.

    `routed` (the static route map's for_finding) puts findings in a file that serves a
    route ahead of the rest, since a probe needs a route to address, and lets the probe
    classes take turns inside each group. On the 2026-11-06 test run 38 of VulnLookup's
    50 slots went to findings in files with no route (selection by occurrence id, every
    rule's precision still 0), while 65 of its 448 eligible findings had one.

    A deep-review finding takes its CWE from `DEEP_LENS_CWE`. The model rarely gives a
    line, and a probe decides only on the handler enclosing the finding's line, so with
    `src` the line is recovered from the finding's verified quote (`_quote_line`)."""
    rows = con.execute(
        """SELECT o.id AS occurrence_id, o.finding_id, o.path, o.start_line,
                  o.message, o.producer_id, f.target, p.cwe, p.tool, p.rule_id,
                  CASE WHEN p.n_adjudicated > 0
                       THEN CAST(p.n_confirmed AS REAL) / p.n_adjudicated ELSE 0 END AS precision
             FROM live_occurrences o
             JOIN findings  f ON f.id = o.finding_id
             JOIN producers p ON p.id = o.producer_id
            WHERE o.run_id = ?
            ORDER BY precision DESC, o.id ASC""",
        (run_id,)).fetchall()
    from ..funnel import independence_class
    out: list[Candidate] = []
    seen: set[tuple[str, str]] = set()
    for r in rows:
        row = dict(r)
        if independence_class(row["tool"], row["rule_id"]) == "sca-db":
            continue
        cwe, cwe_from = _cwe_of(row), ""
        if cwe is None and row["tool"] == "deep" and row["rule_id"] in DEEP_LENS_CWE:
            cwe, cwe_from = DEEP_LENS_CWE[row["rule_id"]], f"deep lens {row['rule_id']}"
        if probe_class(cwe) not in DYNAMICALLY_TESTABLE:
            continue
        if (row["finding_id"], row["path"]) in seen:
            continue
        seen.add((row["finding_id"], row["path"]))
        line = row["start_line"]
        if cwe_from and not line and src is not None:
            line = _deep_quote_line(con, src, row["occurrence_id"], row["path"])
        out.append(Candidate(
            finding_id=row["finding_id"], occurrence_id=row["occurrence_id"],
            target=row["target"], path=row["path"], start_line=line,
            producer_id=row["producer_id"], cwe=cwe, message=row["message"] or "",
            cwe_from=cwe_from))
        if routed is None and len(out) >= limit:
            break
    if routed is None:
        return out
    has = [bool(routed(c.path)) for c in out]
    first = _interleave([c for c, h in zip(out, has) if h])
    rest = _interleave([c for c, h in zip(out, has) if not h])
    return (first + rest)[:limit]


def final_verdict(evidence: ProbeEvidence, replay: dict | None = None, *,
                  may_reject: bool = True) -> tuple[str, str]:
    """adjudicate_with_reason, then the replay rule: a confirmation whose replay did not
    hold is needs-review with DID_NOT_REPLAY. No replay record leaves the verdict as
    measured once (IMPROVEMENT-PLAN item 17); the advisory then says it was not
    replayed. `may_reject` False holds a rejection back as INFERRED_CWE: the probe
    measured a class the finding was only assumed to be in."""
    v, reason = adjudicate_with_reason(evidence)
    if v == "confirmed" and replay is not None and not replay.get("held"):
        return "needs-review", DID_NOT_REPLAY
    if v == "rejected" and not may_reject:
        return "needs-review", INFERRED_CWE
    return v, reason


def replay_confirmation(probe_once: Callable[[], ProbeEvidence], *, times: int = 3,
                        restart: Callable[[], object] | None = None) -> dict:
    """Run the whole probe again, attack request and control together, `times` times in
    the running instance, then once more after `restart()` if one is given.

    IMPROVEMENT-PLAN item 17 and the book it came from: the one request that showed an
    effect is run again under the same conditions, after a reset, before it counts.
    A single disagreeing replay holds the confirmation back. A restart that fails also
    holds it back: the effect was not shown to survive one. Every replay is kept, as
    verdict, status line and whether the control still differed, so the advisory can
    say exactly how often it held."""
    runs: list[dict] = []

    def once(after_restart: bool) -> None:
        ev = probe_once()
        runs.append({"verdict": adjudicate_with_reason(ev)[0],
                     "reproduced": bool(ev.reproduced),
                     # The comparison held in the direction this probe reads: a
                     # rate-limit burst reproduces by answering the SAME as its lone
                     # baseline (reproduces_when "same"), so "differed" would undercount.
                     "control_differed": ev.has_baseline_comparison,
                     "observed": (ev.observed or "")[:200],
                     "after_restart": after_restart})
    for _ in range(times):
        once(False)
    after: bool | None = None
    note = ""
    if restart is not None:
        try:
            restart()
            once(True)
            after = runs[-1]["verdict"] == "confirmed"
        except Exception as e:                       # noqa: BLE001 - recorded, not raised
            after = False
            note = f"restart failed: {type(e).__name__}: {e}"[:300]
    held = all(r["verdict"] == "confirmed" for r in runs) and after is not False
    out = {"attempts": len(runs), "reproduced": sum(r["reproduced"] for r in runs),
           "control_held": sum(r["control_differed"] for r in runs),
           "after_restart": after, "held": held, "runs": runs}
    if note:
        out["note"] = note
    return out


def probe_identity(lens, evidence: ProbeEvidence) -> dict:
    """What a verdict was measured with, so a later run can tell whether it still
    applies (IMPROVEMENT-PLAN item 18): the lens, the sha256 of the module that holds
    its probe body (any change to the probes reopens the verdict; conservative on
    purpose), and the method and path of the first request the probe sent."""
    method, path = _request_line(evidence.request)
    return {"id": getattr(lens, "key", "?"), "source_sha": probe_source_sha(lens),
            "method": method, "route": path}


def probe_source_sha(lens) -> str:
    """sha256 of the source module of a lens's probe body, or "" when unavailable."""
    import hashlib
    import inspect
    fn = getattr(lens, "run", None)
    try:
        mod = inspect.getmodule(fn) if fn is not None else None
        text = inspect.getsource(mod) if mod is not None else ""
    except (OSError, TypeError):
        return ""
    return hashlib.sha256(text.encode()).hexdigest() if text else ""


_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")


def _request_line(request: str) -> tuple[str, str]:
    """(method, path) of the first request in a probe's replay string, query dropped.
    Probe strings look like `GET <base_url>/api/x?q=1  (no Authorization header)`
    or `GET <a>  vs  GET <b>`."""
    from urllib.parse import urlsplit
    parts = (request or "").split()
    if len(parts) < 2 or parts[0] not in _METHODS:
        return "", ""
    url = parts[1]
    path = urlsplit(url).path if "://" in url else url.split("?", 1)[0]
    return parts[0], path or "/"


def adjudicate(evidence: ProbeEvidence) -> str:
    """Map measured evidence to a verdict value. A probe that reproduced the finding and
    recorded a baseline it differs from is a confirmation; a probe whose handled request
    behaved like a recorded control is a rejection; everything else stays needs-review.
    Layer 3 neither confirms nor rejects without a control."""
    return adjudicate_with_reason(evidence)[0]


def adjudicate_with_reason(evidence: ProbeEvidence) -> tuple[str, str]:
    """The verdict and the reason stored beside it: the determinism of the signal, or
    NO_BASELINE / NO_CONTROL when a measured result was held back for want of a control,
    or UNTESTED when the probe could not exercise the finding at all."""
    if not evidence.exercised:
        return "untested", UNTESTED
    if evidence.reproduced:
        if evidence.has_baseline_comparison:
            return "confirmed", evidence.determinism
        return "needs-review", NO_BASELINE
    if evidence.determinism in ("deterministic", "statistical"):
        if evidence.has_negative_control:
            return "rejected", evidence.determinism
        return "needs-review", NO_CONTROL
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

    rmap = build_route_map(src)
    cands = select_candidates(con, run_id, limit=limit, routed=rmap.for_finding,
                              src=src)
    prof = profile_repo(src)
    selected_raw, skipped = select_probe_lenses(prof, cands)
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
    untested: int = 0
    verdicts: list[tuple[str, str, str]] = field(default_factory=list)  # finding, lens, verdict
    #: How the run ended, as the Runs page shows it: "probed", or why nothing was.
    outcome: str = ""
    candidates: int = 0


def _record_provisioning(con: sqlite3.Connection, run_id: int, runtime) -> None:
    """Put what provisioning did on the run: the facts in the manifest, and the ones that
    weaken containment or change how the target booted as run-page warnings. A runtime
    that keeps no such record (a test double) writes nothing."""
    prov = getattr(runtime, "provisioning", None)
    if not prov:
        return
    ready = prov.get("readiness")
    db.update_manifest(con, run_id,
                       lambda m: m.setdefault("validate", {}).update(
                           provisioning={k: v for k, v in prov.items() if k != "readiness"},
                           **({"readiness": ready} if ready else {})))
    netted = prov.get("build_network", "none") != "none"
    sample = prov.get("dotenv") or ""
    # Item 2: pulls and ADD fetches go through the daemon and BuildKit, outside the
    # build's network: none. Each host goes on the egress ledger; a pull may have been
    # served from the local image cache, which the daemon does not report.
    hosts: dict[str, int] = {}
    for f in prov.get("remote_fetches") or []:
        hosts[f.get("host") or "?"] = hosts.get(f.get("host") or "?", 0) + 1
    for host, n in sorted(hosts.items()):
        db.egress(con, run_id, "validate-provision", host,
                  note=f"{n} image or ADD fetch(es) by the docker daemon or BuildKit; "
                       f"may have been local cache hits")
    db.set_health(con, run_id, "validate", {
        "readiness": ([f"readiness route {ready.get('request')} answered the same as a "
                       f"random path ({ready.get('status')}); it shows something is "
                       f"serving, not that it is this target"]
                      if ready and ready.get("discriminates") is False else []),
        "build-network": ["Dockerfile RUN steps had network access while the target "
                          "was built (--build-network)"] if netted else [],
        "env": ([f"no .env in the clone; interpolated from {sample}"]
                if sample and Path(sample).name != ".env" else [])
               + list(prov.get("env_files") or [])
               + ([f"set by the operator with --env: {', '.join(prov['env_overrides'])}"]
                  if prov.get("env_overrides") else []),
    })


def _record_served_spec(con: sqlite3.Connection, run_id: int,
                        committed: list, served) -> None:
    """Put the served-versus-committed OpenAPI comparison beside the readiness evidence
    (`manifest.validate.readiness.served_spec`), and warn on the run page when the two
    describe different APIs. Extra evidence that the probes reached this target, never a
    requirement: a target that serves no spec, or a clone that commits none, records
    `matches: null` and no warning."""
    from .routes import compare_served_spec
    cmp = compare_served_spec(committed, served)
    db.update_manifest(con, run_id, lambda m: m.setdefault("validate", {}).setdefault(
        "readiness", {}).update(served_spec=cmp))
    warn = []
    if cmp.get("matches") is False:
        warn.append(f"the OpenAPI document the target served at {cmp['served']} shares "
                    f"{cmp['shared_ops']} of its {cmp['served_ops']} operations with the "
                    f"{cmp['committed_ops']} in the committed {cmp['compared_with']}, "
                    "under half of the smaller document's: the probes may have reached a "
                    "different application, or the committed spec is stale")
    db.set_health(con, run_id, "validate", {"served-spec": warn})


def _record_conditions(con: sqlite3.Connection, run_id: int, running, seed) -> None:
    """Put on the run what an advisory's Conditions section reads back: the seed recipe
    asked for and the service the probes addressed. `seed` is written as None when no
    recipe was asked for, so a draft can tell "not seeded" from "not recorded". Names
    only: a recipe's captured keys and generated password stay on the RunningTarget, in
    memory, and never reach the manifest."""
    db.update_manifest(con, run_id, lambda m: m.setdefault("validate", {}).update(
        seed=getattr(seed, "name", None) or None,
        service=getattr(running, "service", "") or None))


def run_validation(con: sqlite3.Connection, run_id: int, rundir: Path, runtime, *,
                   limit: int = 50, enrich: bool = True, seed=None) -> ValidationResult:
    """The end-to-end loop: profile the target, select candidates and the probe lenses the
    codebase supports, stand the target up under containment, optionally seed it to a
    testable state with the target's own commands, probe each candidate against its routes,
    and record a verdict. Every target is torn down even on error.

    The attempt itself goes on the run, start and end (`db.stage_started`), so the
    Runs page can say "not run", "running" or how it ended, including the exits that
    write no verdict: no candidates, no probe for them, nothing to boot, an error."""
    db.stage_started(con, run_id, "validate")
    try:
        res = _run_validation(con, run_id, rundir, runtime, limit=limit, enrich=enrich,
                              seed=seed)
    except Exception as e:
        db.stage_ended(con, run_id, "validate", "error",
                       note=f"{type(e).__name__}: {e}"[:300])
        raise
    db.stage_ended(con, run_id, "validate", res.outcome or "probed",
                   candidates=res.candidates, verdicts=len(res.verdicts),
                   confirmed=res.confirmed)
    return res


def _run_validation(con: sqlite3.Connection, run_id: int, rundir: Path, runtime, *,
                    limit: int, enrich: bool, seed) -> ValidationResult:
    from ..research.profile import profile_repo
    from .lenses import select_probe_lenses
    from .routes import (build_route_map, committed_specs, crawl_routes,
                         fetch_openapi_doc, routes_from_openapi)
    from .seed import run_seed

    rundir = Path(rundir)
    src = rundir / "src"
    res = ValidationResult(run_id)
    rmap = build_route_map(src)
    cands = select_candidates(con, run_id, limit=limit, routed=rmap.for_finding,
                              src=src)
    res.candidates = len(cands)
    if not cands:
        res.outcome = "no candidates"
        return res
    prof = profile_repo(src)
    selected, _ = select_probe_lenses(prof, cands)
    if not selected:
        res.outcome = "no probe fits these findings"
        return res
    spec = runtime.detect(src)
    if spec is None:
        res.outcome = "nothing to boot"
        return res
    res.outcome = "probed"

    spec = dataclasses.replace(spec, ready_paths=readiness_paths(rmap))
    try:
        running = runtime.start(spec, rundir)
    except Exception as e:
        # A target that cannot be stood up under containment is a recorded gap, not a
        # silent zero: the run page shows it beside the scanner warnings.
        with db.tx(con):
            _record_provisioning(con, run_id, runtime)
            db.set_health(con, run_id, "validate",
                          {"runtime": [f"{spec.kind}: {type(e).__name__}: {e}"[:600]]})
        raise
    with db.tx(con):
        _record_provisioning(con, run_id, runtime)
        _record_conditions(con, run_id, running, seed)
        db.set_health(con, run_id, "validate", {"runtime": []})
    try:
        def exec_fn(argv):
            return runtime.probe_exec(running, argv)
        if seed is not None:
            # Run the target's own setup commands in the contained instance, then carry
            # what they established onto `running` for the probes. A seed failure is a
            # recorded gap, never a stopped validation.
            sr = run_seed(runtime, running, seed)
            running.param_values = {**running.param_values, **sr.param_values}
            running.credentials = {**running.credentials, **sr.credentials}
            running.cross_user = getattr(sr, "cross_user", None) or running.cross_user
            with db.tx(con):
                db.set_health(con, run_id, "validate",
                              {"seed": sr.notes or []})
        prov = getattr(runtime, "provisioning", None) or {}
        conditions = {
            "seed": getattr(seed, "name", None) if seed is not None else None,
            "env_keys": sorted(prov.get("env_overrides") or []),
            "readiness": (prov.get("readiness") or {}).get("request"),
            "build_network": prov.get("build_network"),
        }
        if enrich:
            # Best-effort, and both read-only: a served OpenAPI document, then a bounded
            # GET-only crawl. Neither knows a handler file, so each only adds to a static
            # route it matches by (method, path); with mount prefixes resolved, that
            # match now happens for routers mounted under a prefix.
            served = None
            try:
                served = fetch_openapi_doc(exec_fn, running.base_url)
                if served is not None:
                    rmap.add_all(routes_from_openapi(served[1]))
            except Exception:                       # enrichment is best-effort
                pass
            try:
                rmap.add_all(crawl_routes(exec_fn, running.base_url))
            except Exception:                       # enrichment is best-effort
                pass
            with db.tx(con):
                _record_served_spec(con, run_id, committed_specs(src), served)
        for lens, matching, _why in selected:
            for cand in matching:
                routes = rmap.for_finding(cand.path)
                evidence = lens.probe(running, cand, routes, exec_fn)
                replay = None
                if adjudicate(evidence) == "confirmed":
                    # Item 17: no confirmation on one observation. The same probe runs
                    # again in place, then after the target service restarts.
                    restart = getattr(runtime, "restart", None)
                    replay = replay_confirmation(
                        lambda: lens.probe(running, cand, routes, exec_fn),
                        restart=(lambda: restart(running, spec.ready_paths))
                        if restart else None)
                with db.tx(con):
                    record_verdict(con, cand, run_id, evidence, model=lens.key,
                                   replay=replay, probe=probe_identity(lens, evidence),
                                   conditions=conditions)
                v = final_verdict(evidence, replay,
                                  may_reject=not cand.cwe_from)[0]
                res.verdicts.append((cand.finding_id, lens.key, v))
                res.confirmed += v == "confirmed"
                res.rejected += v == "rejected"
                res.needs_review += v == "needs-review"
                res.untested += v == "untested"
    finally:
        running.stop()
        # The precision ledger is derived from verdicts, so refresh it here rather than
        # leave it stale until the next scan. In `finally` so a run that errors part way
        # still counts the verdicts it did write.
        if res.verdicts:
            with db.tx(con):
                db.bump_producer_counts(con)
    return res


def record_verdict(con: sqlite3.Connection, candidate: Candidate, run_id: int,
                   evidence: ProbeEvidence, *, model: str = "probe",
                   replay: dict | None = None, probe: dict | None = None,
                   conditions: dict | None = None) -> int:
    """Write the adjudication for one probed candidate. executed_score is non-zero only
    when a probe actually ran, which is the ledger's whole point, and is 100 only for a
    confirmation: a reproduction held back for want of a baseline scores as a probe that
    ran and did not decide. The full evidence, baseline included, is stored as JSON in
    `rationale` so a disclosure report is reproducible from the DB."""
    import json
    v, reason = final_verdict(evidence, replay, may_reject=not candidate.cwe_from)
    executed = 100 if v == "confirmed" else (
        50 if v == "rejected" or evidence.reproduced else 0)
    body = {
        "summary": evidence.summary, "request": evidence.request,
        "observed": evidence.observed, "determinism": evidence.determinism,
        "baseline": evidence.baseline,
        "differs_from_baseline": evidence.differs_from_baseline,
        "handled": evidence.handled,
        "reproduces_when": evidence.reproduces_when,
    }
    if candidate.cwe_from:
        body["cwe_from"] = candidate.cwe_from
    if probe is not None:
        # The evidence window the finding was flagged in. A later run carries this
        # verdict forward only while the window, not just the flagged line, is the same.
        row = con.execute("SELECT blob_sha FROM occurrences WHERE id=?",
                          (candidate.occurrence_id,)).fetchone()
        body["probe"] = {**probe, "evidence_blob": row["blob_sha"] if row else None}
    if replay is not None:
        body["replay"] = replay
    if conditions is not None:
        body["conditions"] = conditions
    rationale = json.dumps(body, sort_keys=True)
    return db.verdict(
        con, candidate.finding_id, run_id, verdict=v, seat="dynamic", model=model,
        cwe=candidate.cwe, executed_score=executed, evidence_score=0,
        reason=reason, rationale=rationale)
