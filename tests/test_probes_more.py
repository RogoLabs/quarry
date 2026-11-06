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
    NO_CONTROL, Candidate, RunningTarget, adjudicate, adjudicate_with_reason)
from quarry.dynamic.routes import Route                                       # noqa: E402
from quarry.dynamic.seed import CrossUser                                     # noqa: E402
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


# ------------------------------------------------------------------ timing oracle
# A present identifier against two absent ones shaped like it; the two absent ones are
# the A/A control. The thresholds (10 ms floor, 3x the A/A difference, 2x the spread)
# are in probes.py beside _TIMING_FLOOR.

TIMING = Candidate("f2", 2, "o/r", "app/auth.py", 5, "prod", "CWE-208", "timing")
# A run whose seed created quarry_user and read its key back, so that login exists.
SEEDED = RunningTarget(base_url="http://web:8080", stop=lambda: None, network="net",
                       credentials={"user_api_key": "k" * 24},
                       cross_user=CrossUser(header="X-API-KEY",
                                            accounts={"user_api_key": "quarry_user"}))
# The finding's own handler, with the identifier parameter declared.
LOGIN_ID = [Route("GET", "/login", "app/auth.py", "openapi+static", query=("username",),
                  line=3, end_line=9)]


def _clock(present_ms, absent_ms, *, present=("quarry_user", "admin"), code=200,
           present_code=None, absent2_ms=None, jitter_ms=0.0):
    """A /login that answers a present identifier in present_ms and any other in
    absent_ms. The second absent identifier of each probe gets absent2_ms when given (an
    A/A difference). Each identifier's own samples alternate +jitter, -jitter, so every
    class has the same median and a spread of about jitter_ms. The first request of each
    curl run is the probe's warm-up; it is answered and not counted."""
    seen: list[str] = []
    count: dict[str, int] = {}
    state = {"first": False}

    def handle(req):
        who = req.query.get("username", "")
        if state.pop("first", False):
            return Reply(code, "", "application/json", 0.001)
        count[who] = count.get(who, 0) + 1
        j = jitter_ms if count[who] % 2 else -jitter_ms
        if who in present:
            return Reply(present_code or code, "", "application/json",
                         (present_ms + j) / 1000)
        if who not in seen:
            seen.append(who)
        ms = absent2_ms if absent2_ms is not None and seen.index(who) % 2 else absent_ms
        return Reply(code, "", "application/json", (ms + j) / 1000)
    inner = curl(handle)

    def run(argv):
        state["first"] = True
        return inner(argv)
    run.requests = inner.requests
    return run


def test_timing_confirms_against_the_a_a_control():
    ev = probe_auth_timing_oracle(SEEDED, TIMING, LOGIN_ID, _clock(60.0, 5.0))
    assert ev.reproduced is True and ev.determinism == "statistical"
    assert ev.differs_from_baseline is True and ev.handled is True
    assert adjudicate_with_reason(ev) == ("confirmed", "statistical")
    assert "two absent identifiers" in ev.baseline and "A/A difference 0.0 ms" in ev.baseline
    assert "`quarry_user` (account quarry_user, created by the seed recipe" in ev.observed
    assert "separates a present identifier from two absent ones by 55.0 ms" in ev.summary


def test_a_separation_also_confirms_with_a_guessed_identifier():
    """A separation shows the guessed identifier exists and the handler read it."""
    ev = probe_auth_timing_oracle(RUNNING, TIMING, LOGIN, _clock(60.0, 5.0))
    assert adjudicate(ev) == "confirmed" and "`admin` (guessed)" in ev.observed


def test_no_confirmation_when_the_absent_identifiers_differ_as_much():
    """55 ms and 20 ms from the two absent identifiers, which differ by 35 ms between
    themselves: the separation is not three times the A/A difference."""
    ev = probe_auth_timing_oracle(SEEDED, TIMING, LOGIN_ID,
                                  _clock(60.0, 5.0, absent2_ms=40.0))
    assert ev.reproduced is False and adjudicate(ev) == "needs-review"
    assert "A/A difference 35.0 ms" in ev.summary


def test_timing_rejects_with_a_known_identifier_on_a_declared_parameter():
    ev = probe_auth_timing_oracle(SEEDED, TIMING, LOGIN_ID, _clock(20.0, 20.0, jitter_ms=1))
    assert ev.reproduced is False and ev.differs_from_baseline is False
    assert ev.handled is True and adjudicate_with_reason(ev) == ("rejected", "statistical")
    assert "A separation of 10.0 ms or more is excluded" in ev.summary
    assert "A/A difference" in ev.baseline


def test_timing_does_not_reject_without_an_identifier_known_to_exist():
    """REGRESSION. `admin` may not exist, and then both sides are absent."""
    ev = probe_auth_timing_oracle(RUNNING, TIMING, LOGIN_ID,
                                  _clock(20.0, 20.0, present=("admin",)))
    assert adjudicate_with_reason(ev) == ("needs-review", NO_CONTROL)
    assert "a guess that may not exist" in ev.summary


def test_timing_does_not_reject_on_a_guessed_parameter():
    ev = probe_auth_timing_oracle(SEEDED, TIMING, LOGIN, _clock(20.0, 20.0))
    assert adjudicate_with_reason(ev) == ("needs-review", NO_CONTROL)
    assert "`username` is a guessed parameter" in ev.summary


def test_timing_too_noisy_to_exclude_the_floor_does_not_reject():
    """Equal medians, but an 8 ms spread could hide a 10 ms separation."""
    ev = probe_auth_timing_oracle(SEEDED, TIMING, LOGIN_ID, _clock(20.0, 20.0, jitter_ms=8))
    assert adjudicate(ev) == "needs-review" and "too noisy to exclude 10.0 ms" in ev.summary


def test_a_status_that_splits_the_identifiers_is_held_for_review():
    ev = probe_auth_timing_oracle(SEEDED, TIMING, LOGIN_ID,
                                  _clock(20.0, 20.0, code=400, present_code=401))
    assert adjudicate(ev) == "needs-review" and "different statuses" in ev.summary


def test_timing_samples_are_interleaved_in_a_few_curl_runs():
    fake = _clock(20.0, 20.0)
    calls = []

    def counting(argv):
        calls.append(argv)
        return fake(argv)
    probe_auth_timing_oracle(SEEDED, TIMING, LOGIN_ID, counting, samples=15)
    assert len(calls) == 3 and len(fake.requests) == 48     # 3 x (1 warm-up + 5 x 3)
    who = [r.query["username"] for r in fake.requests]
    assert who[0] == "quarry_user"                            # the warm-up
    p, a, b = who[1:4]
    assert p == "quarry_user" and len({p, a, b}) == 3 and len(a) == len(p)
    assert who[4:7] == [a, b, p] and who[7:10] == [b, p, a]  # the order rotates
    assert {who.count(x) for x in (a, b)} == {15} and who.count(p) == 18
    assert all("%{time_starttransfer}" in " ".join(c) for c in calls)


def test_timing_oracle_does_not_reject_on_a_sibling_route():
    # The auth-like route is in the finding's file, but its handler does not enclose the
    # finding's line; equal timing there says nothing about the flagged code.
    sibling = [Route("GET", "/login", "app/auth.py", "static", query=("username",),
                     line=30, end_line=40)]
    ev = probe_auth_timing_oracle(SEEDED, TIMING, sibling, _clock(20.0, 20.0))
    assert ev.handled is True and ev.differs_from_baseline is None
    assert adjudicate_with_reason(ev)[0] == "needs-review"


@pytest.mark.parametrize("code", [404, 405])
def test_timing_oracle_is_not_rejected_when_no_handler_answered(code):
    """Both identifiers 404: equal medians time the router, not the auth check. This
    was a rejection, and rejected-carry-forward then killed the finding in every run."""
    ev = probe_auth_timing_oracle(SEEDED, TIMING, LOGIN_ID, _clock(20.0, 20.0, code=code))
    assert ev.handled is False and adjudicate(ev) == "needs-review"
    assert str(code) in ev.summary


def test_timing_oracle_needs_review_without_auth_route():
    # a route with no auth-like name is not a timing target.
    ev = probe_auth_timing_oracle(SEEDED, TIMING, [Route("GET", "/items", "app/auth.py")],
                                  _clock(60.0, 5.0))
    assert adjudicate(ev) == "needs-review"
