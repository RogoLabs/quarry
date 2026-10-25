"""Probe lenses and their selection, driven by the repo profile.

Which bug class to probe is not a constant; it is a function of what the target is,
exactly as Layer 2's reading lenses are chosen by `research.ensemble.select_lenses`
from `research.profile`. A probe lens runs only when three things coincide:

  1. the artifact is runnable (a service): you can only probe what you can stand up,
     so a library, CLI or data repo is left to the read-only layers, honestly;
  2. the profile shows the capability the bug class lives in (routes for authz, an
     auth path for a timing oracle, a SQL/shell/template sink for injection); and
  3. a finding survived the funnel whose CWE this lens can actually confirm.

`select_probe_lenses` reports both halves, like the profiler: what will run and the
evidence that selected it, and what will not and why. No lens is hardcoded as "first".

Safety invariant for every probe body: non-destructive. A probe observes, it does not
mutate or delete target data, and it does not try to take the target down. Confirmation
is a measured, replayable observation a maintainer can reproduce, not an exploit.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .validate import Candidate, ProbeEvidence, RunningTarget
from .probes import (probe_broken_authz, probe_missing_rate_limit,
                     probe_auth_timing_oracle, probe_injection_observable,
                     probe_path_traversal_ssrf)

# A bound probe_exec: run argv in a sidecar on the target's isolated network -> (rc, out).
ExecFn = Callable[[list[str]], tuple[int, str]]
# A probe body: (running target, candidate, routes in the finding's file, exec_fn).
ProbeFn = Callable[[RunningTarget, Candidate, list, ExecFn], ProbeEvidence]


@dataclass(frozen=True)
class ProbeLens:
    key: str
    cwes: frozenset[str]              # CWE classes this lens can confirm
    requires: tuple[str, ...]        # capabilities; any one at >= min_hits qualifies
    rationale: str
    min_hits: int = 1
    kinds: tuple[str, ...] = ("service",)      # must be runnable to probe
    frameworks: tuple[str, ...] = ()
    # Execution. Default is an honest "not wired yet" that can only ever yield
    # needs-review, never a confirmation. Concrete bodies replace this per lens.
    run: ProbeFn | None = None

    def profile_applies(self, prof) -> tuple[bool, str]:
        """Capability/kind/framework gate, independent of any single finding."""
        if self.kinds and prof.artifact_kind not in self.kinds:
            return False, f"artifact is {prof.artifact_kind}, probe needs {'/'.join(self.kinds)}"
        if self.frameworks and not any(f in prof.frameworks for f in self.frameworks):
            return False, f"no {'/'.join(self.frameworks)} detected"
        for cap in self.requires:
            n = prof.capabilities.get(cap, 0)
            if n >= self.min_hits:
                return True, f"{cap}={n} (e.g. {prof.evidence.get(cap, '?')})"
        return False, f"no {'/'.join(self.requires)} at >={self.min_hits} hits"

    def probe(self, running: RunningTarget, candidate: Candidate,
              routes: list, exec_fn: ExecFn) -> ProbeEvidence:
        if self.run is None:
            return ProbeEvidence(
                reproduced=False, determinism="unknown",
                summary=f"{self.key}: probe body not wired yet; left for review")
        return self.run(running, candidate, routes, exec_fn)


# The catalogue, in priority order. Priority is confirmability x signal x how cleanly
# the probe stays non-destructive. See docs/LAYER3-PLAN.md for the reasoning.
CATALOGUE: tuple[ProbeLens, ...] = (
    ProbeLens(
        key="broken-authz-idor",
        cwes=frozenset({"CWE-862", "CWE-863", "CWE-639"}),
        requires=("http_routes",), min_hits=3,
        rationale="Highest signal and the cleanest non-destructive confirmation: reach "
                  "an object or action with the intended identity, then without it (or "
                  "with another's), and compare. Deterministic, idempotent, read-only.",
        run=probe_broken_authz),
    ProbeLens(
        key="missing-rate-limit",
        cwes=frozenset({"CWE-307", "CWE-400"}),
        requires=("authn", "http_routes"), min_hits=1,
        rationale="A small bounded burst against an auth or expensive endpoint, observing "
                  "the absence of throttling (no 429, no backoff). Near-deterministic and "
                  "a common gap in self-hosted APIs.",
        run=probe_missing_rate_limit),
    ProbeLens(
        key="auth-timing-oracle",
        cwes=frozenset({"CWE-208"}),
        requires=("authn",), min_hits=1,
        rationale="A measurable response-time separation that "
                  "leaks whether an account exists. Statistical rather than deterministic "
                  "(many samples, distribution separation), so it sits below the clean "
                  "boolean classes.",
        run=probe_auth_timing_oracle),
    ProbeLens(
        key="injection-observable",
        cwes=frozenset({"CWE-89", "CWE-77", "CWE-79"}),
        requires=("raw_sql", "subprocess", "template_render"), min_hits=1,
        rationale="Confirmed only through a strictly benign, observable signal (a unique "
                  "reflected marker, or a bounded boolean/time-based response) that never "
                  "modifies or destroys data. Gated carefully for that reason.",
        run=probe_injection_observable),
    ProbeLens(
        key="path-traversal-ssrf",
        cwes=frozenset({"CWE-22", "CWE-918"}),
        requires=("filesystem", "http_routes"), min_hits=1,
        rationale="A caller-supplied path or URL that reaches a resource the author did "
                  "not intend, observed read-only. SSRF is confirmed against the isolated "
                  "network only, so it can never reach a real internal service.",
        run=probe_path_traversal_ssrf),
)


def select_probe_lenses(prof, candidates: list[Candidate]):
    """-> (selected, skipped).

    selected: list of (lens, [candidates it applies to], why) in catalogue priority.
    skipped:  list of (lens.key, why_not), so a lens that did not run is information,
              not silence, exactly like the profiler's lens selection."""
    selected: list[tuple[ProbeLens, list[Candidate], str]] = []
    skipped: list[tuple[str, str]] = []
    for lens in CATALOGUE:
        ok, why = lens.profile_applies(prof)
        if not ok:
            skipped.append((lens.key, why))
            continue
        matching = [c for c in candidates if c.cwe in lens.cwes]
        if not matching:
            skipped.append((lens.key, "profile supports it, but no surviving finding "
                                      f"with a CWE in {sorted(lens.cwes)}"))
            continue
        selected.append((lens, matching, why))
    return selected, skipped
