"""The missing-rate-limit and auth-timing-oracle probe bodies, driven hermetically with
a fake exec_fn so their decision logic is pinned without a running target.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quarry.dynamic.validate import Candidate, RunningTarget, adjudicate      # noqa: E402
from quarry.dynamic.routes import Route                                       # noqa: E402
from quarry.dynamic.probes import (                                           # noqa: E402
    probe_missing_rate_limit, probe_auth_timing_oracle)

CAND = Candidate("f1", 1, "o/r", "app/auth.py", 5, "prod", "CWE-307", "no rate limit")
# A reproduction is held at needs-review until the probe records a baseline comparison
# (validate.NO_BASELINE). When a probe fills `baseline` and `differs_from_baseline`,
# its reproductions here go back to asserting "confirmed".
HELD = "needs-review"
RUNNING = RunningTarget(base_url="http://web:8080", stop=lambda: None, network="net")
LOGIN = [Route("GET", "/login", "app/auth.py", "static")]


def _codes(sequence):
    """Fake exec_fn for status probes: yield the given codes in order, then the last."""
    it = iter(sequence)
    last = {"v": sequence[-1]}
    def run(argv):
        try:
            last["v"] = next(it)
        except StopIteration:
            pass
        return 0, last["v"]
    return run


def test_rate_limit_confirmed_when_no_throttling():
    ev = probe_missing_rate_limit(RUNNING, CAND, LOGIN, _codes(["200"] * 30), burst=30)
    assert ev.reproduced is True and adjudicate(ev) == HELD
    assert "no throttling" in ev.summary


def test_rate_limit_rejected_when_429_appears():
    ev = probe_missing_rate_limit(RUNNING, CAND, LOGIN,
                                  _codes(["200", "200", "429", "429"]), burst=30)
    assert ev.reproduced is False and ev.determinism == "deterministic"
    assert adjudicate(ev) == "rejected" and "429" in ev.observed


def test_rate_limit_needs_review_when_only_wrong_method():
    # GET on a POST-only login yields 405s: not a meaningful rate-limit test.
    ev = probe_missing_rate_limit(RUNNING, CAND, LOGIN, _codes(["405"] * 30), burst=30)
    assert ev.reproduced is False and ev.determinism == "unknown"
    assert adjudicate(ev) == "needs-review"


def test_rate_limit_needs_review_without_routes():
    ev = probe_missing_rate_limit(RUNNING, CAND, [], _codes(["200"]), burst=5)
    assert adjudicate(ev) == "needs-review"


def _timings(present_ms, absent_ms):
    """Fake exec_fn for timing probes: return seconds keyed by the username in the URL."""
    def run(argv):
        url = argv[-1]
        ms = present_ms if "username=admin" in url else absent_ms
        return 0, f"{ms / 1000:.6f}"
    return run


def test_timing_oracle_confirmed_on_clear_separation():
    ev = probe_auth_timing_oracle(RUNNING, CAND, LOGIN, _timings(60.0, 5.0), samples=15)
    assert ev.reproduced is True and ev.determinism == "statistical"
    assert adjudicate(ev) == HELD and "separates" in ev.summary


def test_timing_oracle_rejected_when_no_separation():
    ev = probe_auth_timing_oracle(RUNNING, CAND, LOGIN, _timings(20.0, 20.0), samples=15)
    assert ev.reproduced is False and ev.determinism == "statistical"
    assert adjudicate(ev) == "rejected"


def test_timing_oracle_needs_review_without_auth_route():
    # a route with no auth-like name is not a timing target.
    ev = probe_auth_timing_oracle(RUNNING, CAND, [Route("GET", "/items", "app/auth.py")],
                                  _timings(60.0, 5.0))
    assert adjudicate(ev) == "needs-review"
