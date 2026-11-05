"""The missing-rate-limit and auth-timing-oracle probe bodies, driven hermetically with
a fake curl so their decision logic is pinned without a running target.

The rate-limit probe's baseline is a lone request; its probe a bounded burst sent in one
curl run. Its finding is a missing defence, so it reproduces on sameness: every request
of the burst answered like the lone one. A throttle (429, 503, Retry-After) or a
RateLimit-Remaining that counts down is a limit that exists, and rejects.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quarry.dynamic.validate import (                                         # noqa: E402
    Candidate, RunningTarget, adjudicate, adjudicate_with_reason)
from quarry.dynamic.routes import Route                                       # noqa: E402
from quarry.dynamic.probes import (                                           # noqa: E402
    probe_missing_rate_limit, probe_auth_timing_oracle)
from fakecurl import Reply, curl                                              # noqa: E402

CAND = Candidate("f1", 1, "o/r", "app/auth.py", 5, "prod", "CWE-307", "no rate limit")
RUNNING = RunningTarget(base_url="http://web:8080", stop=lambda: None, network="net")
# The finding's own handler: the static span encloses line 5.
LOGIN = [Route("GET", "/login", "app/auth.py", "static", line=3, end_line=9)]


def _limited(codes, headers=None):
    """A target that answers the nth request with codes[n] (the last code repeats), and
    the headers headers[n] when given. Request 0 is the lone baseline."""
    seen = {"n": 0}

    def handle(req):
        n = seen["n"]
        seen["n"] += 1
        code = codes[min(n, len(codes) - 1)]
        hdrs = (headers[min(n, len(headers) - 1)] if headers else {})
        return Reply(code, "denied", "application/json", 0.004, hdrs)
    return curl(handle)


def test_rate_limit_confirmed_when_the_burst_is_answered_like_the_lone_request():
    fake = _limited([401])
    ev = probe_missing_rate_limit(RUNNING, CAND, LOGIN, fake, burst=20)
    assert ev.reproduced is True and ev.determinism == "statistical"
    assert ev.reproduces_when == "same" and ev.differs_from_baseline is False
    assert adjudicate(ev) == "confirmed"
    assert "lone GET /login -> HTTP 401" in ev.baseline and "401x20" in ev.observed
    assert "not excluded" in ev.summary                 # the bound is stated
    assert len(fake.requests) == 21                     # 1 lone + 20, never more


def test_the_burst_is_one_curl_run_not_one_sidecar_per_request():
    calls = []
    inner = _limited([200])

    def counting(argv):
        calls.append(argv)
        return inner(argv)
    probe_missing_rate_limit(RUNNING, CAND, LOGIN, counting, burst=20)
    assert len(calls) == 2                              # the lone request, then the burst
    assert calls[1].count("http://web:8080/login") == 20


def test_a_429_in_the_burst_rejects():
    fake = _limited([401, 401, 401, 429])
    ev = probe_missing_rate_limit(RUNNING, CAND, LOGIN, fake, burst=20)
    assert ev.reproduced is False and ev.determinism == "deterministic"
    assert ev.handled is True and ev.differs_from_baseline is True
    assert adjudicate(ev) == "rejected"
    assert "request 3 of the burst answered 429" in ev.summary


def test_a_counting_down_ratelimit_header_rejects_without_hitting_the_limit():
    hdrs = [{}] + [{"X-RateLimit-Remaining": str(99 - i)} for i in range(20)]
    fake = _limited([200], headers=hdrs)
    ev = probe_missing_rate_limit(RUNNING, CAND, LOGIN, fake, burst=20)
    assert adjudicate(ev) == "rejected" and "counted down from 99 to 80" in ev.summary


@pytest.mark.parametrize("code", [404, 405])
def test_rate_limit_is_not_decided_when_no_handler_answered(code):
    # GET on a POST-only login yields 405s: the burst would time the router.
    fake = _limited([code])
    ev = probe_missing_rate_limit(RUNNING, CAND, LOGIN, fake, burst=20)
    assert ev.handled is False and adjudicate(ev) == "needs-review"
    assert len(fake.requests) == 1                      # no burst sent


def test_mixed_statuses_are_inconclusive():
    fake = _limited([401, 401, 500, 401])
    ev = probe_missing_rate_limit(RUNNING, CAND, LOGIN, fake, burst=20)
    assert adjudicate(ev) == "needs-review" and "inconclusive" in ev.summary


def test_a_sibling_route_is_measured_but_not_decided():
    sibling = [Route("GET", "/login", "app/auth.py", "static", line=30, end_line=40)]
    ev = probe_missing_rate_limit(RUNNING, CAND, sibling, _limited([401]), burst=20)
    assert ev.reproduced is True and adjudicate(ev) == "needs-review"
    assert "held for review" in ev.summary


def test_cwe_400_is_not_a_request_rate_question():
    # Mostly ReDoS: a 429 says nothing about per-request cost, so nothing is sent.
    cand = Candidate("f1", 1, "o/r", "app/auth.py", 5, "prod", "CWE-1333", "regex")
    fake = _limited([200])
    ev = probe_missing_rate_limit(RUNNING, cand, LOGIN, fake, burst=20)
    assert adjudicate(ev) == "needs-review" and fake.requests == []


def test_a_login_post_is_burst_with_a_bogus_credential_and_register_never():
    login = [Route("POST", "/api/user/login", "app/auth.py", "static", line=3, end_line=9)]
    fake = _limited([401])
    ev = probe_missing_rate_limit(RUNNING, CAND, login, fake, burst=5)
    assert adjudicate(ev) == "confirmed"
    assert all(r.method == "POST" and "quarry-no-such-user" in r.data
               for r in fake.requests)
    register = [Route("POST", "/api/user/register", "app/auth.py", "static",
                      line=3, end_line=9)]
    fake = _limited([201])
    ev = probe_missing_rate_limit(RUNNING, CAND, register, fake, burst=5)
    assert adjudicate(ev) == "needs-review" and fake.requests == []


def test_rate_limit_needs_review_without_routes():
    fake = _limited([200])
    ev = probe_missing_rate_limit(RUNNING, CAND, [], fake, burst=5)
    assert adjudicate(ev) == "needs-review" and fake.requests == []


def _timings(present_ms, absent_ms, code="200"):
    """Fake exec_fn for timing probes: `<status> <seconds>` keyed by the username."""
    def run(argv):
        url = argv[-1]
        ms = present_ms if "username=admin" in url else absent_ms
        return 0, f"{code} {ms / 1000:.6f}"
    return run


def test_timing_oracle_confirmed_on_clear_separation():
    ev = probe_auth_timing_oracle(RUNNING, CAND, LOGIN, _timings(60.0, 5.0), samples=15)
    assert ev.reproduced is True and ev.determinism == "statistical"
    # A separation is recorded without a baseline comparison, so it waits for a human.
    assert adjudicate(ev) == "needs-review" and "separates" in ev.summary


def test_timing_oracle_rejected_when_no_separation():
    ev = probe_auth_timing_oracle(RUNNING, CAND, LOGIN, _timings(20.0, 20.0), samples=15)
    assert ev.reproduced is False and ev.determinism == "statistical"
    assert adjudicate(ev) == "rejected"            # the absent identifier is the control
    assert "absent identifier" in ev.baseline and ev.handled is True


def test_timing_oracle_does_not_reject_on_a_sibling_route():
    # The auth-like route is in the finding's file, but its handler does not enclose the
    # finding's line; equal timing there says nothing about the flagged code.
    sibling = [Route("GET", "/login", "app/auth.py", "static", line=30, end_line=40)]
    ev = probe_auth_timing_oracle(RUNNING, CAND, sibling, _timings(20.0, 20.0), samples=15)
    assert ev.handled is True and ev.differs_from_baseline is None
    assert adjudicate_with_reason(ev)[0] == "needs-review"


@pytest.mark.parametrize("code", ["404", "405"])
def test_timing_oracle_is_not_rejected_when_no_handler_answered(code):
    """Both identifiers 404: equal medians time the router, not the auth check. This
    was a rejection, and rejected-carry-forward then killed the finding in every run."""
    ev = probe_auth_timing_oracle(RUNNING, CAND, LOGIN, _timings(20.0, 20.0, code),
                                  samples=15)
    assert ev.handled is False and adjudicate(ev) == "needs-review"
    assert code in ev.summary


def test_timing_oracle_needs_review_without_auth_route():
    # a route with no auth-like name is not a timing target.
    ev = probe_auth_timing_oracle(RUNNING, CAND, [Route("GET", "/items", "app/auth.py")],
                                  _timings(60.0, 5.0))
    assert adjudicate(ev) == "needs-review"
