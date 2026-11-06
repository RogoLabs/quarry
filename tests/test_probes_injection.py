"""The injection-observable and path-traversal/SSRF probe bodies, driven hermetically
with a fake curl. Each check is benign and read-only; the fake handler stands in for the
target so the decision logic, and each class's control, is pinned without a daemon.

Every class records a control on the same parameter. Confirmations need the effect to be
absent from the control; rejections need the finding's own route, a parameter the
handler is known to read, and a safe handling the control shows was reached.
"""
from __future__ import annotations

import html
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quarry.dynamic.validate import (                                         # noqa: E402
    Candidate, RunningTarget, adjudicate, adjudicate_with_reason, NO_BASELINE)
from quarry.dynamic.routes import Route                                       # noqa: E402
from quarry.dynamic.probes import (                                           # noqa: E402
    probe_injection_observable, probe_path_traversal_ssrf)
from fakecurl import Reply, curl                                              # noqa: E402

RUNNING = RunningTarget(base_url="http://web:8080", stop=lambda: None, network="net")
# The finding's own route: a path param, and a handler span enclosing line 5.
ROUTE = [Route("GET", "/items/{id}", "app/api.py", "static", params=("id",),
               line=3, end_line=9)]
SIBLING = [Route("GET", "/items/{id}", "app/api.py", "static", params=("id",),
                 line=30, end_line=40)]
NOPARAM = [Route("GET", "/search", "app/api.py", "static", line=3, end_line=9)]


def _cand(cwe):
    return Candidate("f1", 1, "o/r", "app/api.py", 5, "prod", cwe, "msg")


def _value(req) -> str:
    """The injected value, as the server decoded it: the path tail or the query value."""
    if req.path.startswith("/items/"):
        return req.path[len("/items/"):]
    return next(iter(req.query.values()), "")


def _echo(transform, ctype="text/html; charset=utf-8"):
    return curl(lambda req: Reply(200, "<html><p>" + transform(_value(req)) + "</p></html>",
                                  ctype))


# ---- XSS (CWE-79) ----

def test_xss_confirmed_on_unencoded_reflection_against_a_benign_control():
    fake = _echo(lambda v: v)
    ev = probe_injection_observable(RUNNING, _cand("CWE-79"), ROUTE, fake)
    assert ev.reproduced is True and adjudicate(ev) == "confirmed"
    assert "benign token reflected as text" in ev.baseline
    assert len(fake.requests) == 2                      # one control, one marker


def test_xss_rejected_when_the_reflection_point_encodes_markup_and_quotes():
    fake = _echo(lambda v: html.escape(v, quote=True))
    ev = probe_injection_observable(RUNNING, _cand("CWE-79"), ROUTE, fake)
    assert ev.reproduced is False and ev.handled is True
    assert ev.differs_from_baseline is False and adjudicate(ev) == "rejected"


def test_xss_held_when_brackets_are_encoded_but_quotes_are_not():
    fake = _echo(lambda v: v.replace("<", "&lt;").replace(">", "&gt;"))
    ev = probe_injection_observable(RUNNING, _cand("CWE-79"), ROUTE, fake)
    assert adjudicate(ev) == "needs-review" and "attribute" in ev.summary


def test_xss_raw_markup_in_json_is_not_a_confirmation():
    fake = _echo(lambda v: v, ctype="application/json")
    ev = probe_injection_observable(RUNNING, _cand("CWE-79"), ROUTE, fake)
    assert adjudicate(ev) == "needs-review" and "application/json" in ev.summary


def test_xss_unreflected_control_decides_nothing():
    fake = curl(lambda req: Reply(200, "<html>static page</html>"))
    ev = probe_injection_observable(RUNNING, _cand("CWE-79"), ROUTE, fake)
    assert adjudicate(ev) == "needs-review" and "benign token" in ev.summary


def test_xss_a_guessed_parameter_cannot_reject():
    # No declared parameter: the probe guesses `q`. A handler that escapes `q` may still
    # render another parameter raw, so the escaped `q` does not reject.
    fake = _echo(lambda v: html.escape(v, quote=True))
    ev = probe_injection_observable(RUNNING, _cand("CWE-79"), NOPARAM, fake)
    assert "q" in fake.requests[0].query
    assert adjudicate(ev) == "needs-review"


def test_xss_a_declared_query_parameter_is_used_and_can_reject():
    route = [Route("GET", "/search", "app/api.py", "static", query=("term",),
                   line=3, end_line=9)]
    fake = _echo(lambda v: html.escape(v, quote=True))
    ev = probe_injection_observable(RUNNING, _cand("CWE-79"), route, fake)
    assert set(fake.requests[0].query) == {"term"} and adjudicate(ev) == "rejected"


def test_xss_on_a_sibling_route_is_held():
    ev = probe_injection_observable(RUNNING, _cand("CWE-79"), SIBLING, _echo(lambda v: v))
    assert ev.reproduced is True and adjudicate(ev) == "needs-review"
    assert "held for review" in ev.summary


# ---- SQLi (CWE-89) ----

def test_sqli_confirmed_on_error_differential():
    fake = curl(lambda req: (200, "OperationalError: unrecognized token" if
                             _value(req).endswith("'") else "ok"))
    ev = probe_injection_observable(RUNNING, _cand("CWE-89"), ROUTE, fake)
    # The plain-value request is the control, so this one confirms.
    assert ev.reproduced is True and adjudicate(ev) == "confirmed"
    assert ev.baseline.startswith("GET ") and ev.differs_from_baseline is True


def test_sqli_held_when_the_control_returned_nothing():
    fake = curl(lambda req: (200, "OperationalError: unrecognized token" if
                             _value(req).endswith("'") else ""))
    ev = probe_injection_observable(RUNNING, _cand("CWE-89"), ROUTE, fake)
    assert ev.reproduced is True
    assert adjudicate_with_reason(ev) == ("needs-review", NO_BASELINE)


def test_sqli_needs_review_without_error():
    # no error on a quote is not positive proof of parameterisation (blind SQLi exists).
    ev = probe_injection_observable(RUNNING, _cand("CWE-89"), ROUTE, curl(lambda r: (200, "ok")))
    assert ev.reproduced is False and adjudicate(ev) == "needs-review"


def _typed_id(req):
    """A handler whose id is a typed integer: anything else is refused as input."""
    v = _value(req)
    return (200, "item") if v.isdigit() else (422, "id must be an integer")


def test_sqli_rejected_when_every_declared_parameter_refuses_metacharacters():
    fake = curl(_typed_id)
    ev = probe_injection_observable(RUNNING, _cand("CWE-89"), ROUTE, fake)
    assert ev.reproduced is False and ev.handled is True
    assert ev.differs_from_baseline is False
    assert adjudicate_with_reason(ev) == ("rejected", "deterministic")
    assert "HTTP 200" in ev.baseline and "422" in ev.observed
    assert "body, a header or a cookie was not tested" in ev.summary
    sent = [_value(r) for r in fake.requests]
    assert sent == ["1", "1'", '1"', "1)", "1 AND 1=2"]        # never a tautology
    assert not any("OR" in v.upper().split() for v in sent)


def test_sqli_is_not_rejected_when_one_declared_parameter_accepts_metacharacters():
    route = [Route("GET", "/items/{id}", "app/api.py", "static", params=("id",),
                   query=("sort",), line=3, end_line=9)]

    def handler(req):
        if not req.path[len("/items/"):].isdigit():
            return 422, "id must be an integer"
        return 200, "items"                       # `sort` takes anything, silently
    ev = probe_injection_observable(RUNNING, _cand("CWE-89"), route, curl(handler))
    assert adjudicate(ev) == "needs-review"
    assert "not refused, or not decidable: `sort`" in ev.summary


def test_sqli_is_not_rejected_on_a_guessed_parameter_or_a_sibling():
    noparam = curl(lambda req: (200, "ok") if req.query.get("q", "1") == "1"
                   else (400, "bad q"))
    ev = probe_injection_observable(RUNNING, _cand("CWE-89"), NOPARAM, noparam)
    assert adjudicate(ev) == "needs-review"                 # `q` was a guess
    ev = probe_injection_observable(RUNNING, _cand("CWE-89"), SIBLING, curl(_typed_id))
    assert adjudicate(ev) == "needs-review"                 # not the finding's handler


def test_sqli_is_not_rejected_when_the_control_was_refused_or_unrouted():
    refused = curl(lambda req: (403, "forbidden"))
    assert adjudicate(probe_injection_observable(RUNNING, _cand("CWE-89"), ROUTE,
                                                 refused)) == "needs-review"
    unrouted = curl(lambda req: (404, "no route") if not _value(req).isdigit()
                    else (404, "no such item"))
    assert adjudicate(probe_injection_observable(RUNNING, _cand("CWE-89"), ROUTE,
                                                 unrouted)) == "needs-review"


def test_a_sql_error_behind_a_refusal_status_is_not_a_clean_refusal():
    """The quote is refused cleanly, but `1)` comes back 400 with a SQL error: the
    value reached a statement, so the 400 is not validation."""
    def handler(req):
        v = _value(req)
        if v == "1":
            return 200, "item"
        if v == "1)":
            return 400, "sqlite3.OperationalError: near \")\": syntax error"
        return 422, "invalid id"
    ev = probe_injection_observable(RUNNING, _cand("CWE-89"), ROUTE, curl(handler))
    assert adjudicate(ev) == "needs-review"


# ---- command injection (CWE-77, and CWE-78 folded onto it) ----

_ARITH = re.compile(r"\$\(\((\d+)\*(\d+)\)\)")


def _shell(req):
    """A handler that runs its input through a shell: arithmetic is evaluated."""
    v = _value(req)
    m = _ARITH.search(v)
    return Reply(200, f"ping: {int(m[1]) * int(m[2])}" if m else f"ping: {v}")


def test_command_injection_confirmed_on_computed_output():
    ev = probe_injection_observable(RUNNING, _cand("CWE-78"), ROUTE, curl(_shell))
    assert ev.reproduced is True and adjudicate(ev) == "confirmed"
    assert "not in the input" in ev.summary and "control GET" in ev.baseline


def test_command_injection_a_reflected_payload_is_not_output():
    # The payload text comes back verbatim; its product never does. Not a confirmation.
    fake = curl(lambda req: Reply(200, "you sent: " + _value(req)))
    ev = probe_injection_observable(RUNNING, _cand("CWE-77"), ROUTE, fake)
    assert ev.reproduced is False and adjudicate(ev) == "needs-review"


def test_command_injection_confirmed_on_a_replayed_delay():
    fake = curl(lambda req: Reply(200, "ok", secs=2.3 if "sleep 2" in _value(req) else 0.02))
    ev = probe_injection_observable(RUNNING, _cand("CWE-77"), ROUTE, fake)
    assert ev.reproduced is True and ev.determinism == "statistical"
    assert adjudicate(ev) == "confirmed" and "replay" in ev.summary


def test_command_injection_rejected_on_an_explicit_refusal():
    fake = curl(lambda req: (400, "invalid host") if re.search(r"[;|$()]", _value(req))
                else (200, "pong"))
    ev = probe_injection_observable(RUNNING, _cand("CWE-77"), ROUTE, fake)
    assert ev.reproduced is False and adjudicate(ev) == "rejected"
    assert "refused all 6" in ev.summary


def test_command_injection_silence_does_not_reject():
    ev = probe_injection_observable(RUNNING, _cand("CWE-77"), ROUTE,
                                    curl(lambda r: (200, "pong")))
    assert adjudicate(ev) == "needs-review" and "does not reject" in ev.summary


# ---- path traversal (CWE-22) ----

_PASSWD = "root:x:0:0:root:/root:/bin/bash\n"


def test_traversal_confirmed_on_passwd_signature_with_the_path_left_as_is():
    # A `<path:p>` route: only the raw `../` sequence, sent --path-as-is, reaches it.
    def handle(req):
        if req.path_as_is and "etc/passwd" in req.raw_path:
            return Reply(200, _PASSWD, "text/plain")
        return Reply(404, "no such file", "text/plain")
    fake = curl(handle)
    ev = probe_path_traversal_ssrf(RUNNING, _cand("CWE-22"), ROUTE, fake)
    assert ev.reproduced is True and adjudicate(ev) == "confirmed"
    assert "--path-as-is" in ev.request


def test_traversal_rejected_on_an_explicit_refusal():
    def handle(req):
        v = _value(req)
        if ".." in v or v.startswith("/"):
            return Reply(400, "invalid path", "text/plain")
        return Reply(404, "no such file", "text/plain")
    ev = probe_path_traversal_ssrf(RUNNING, _cand("CWE-22"), ROUTE, curl(handle))
    assert ev.reproduced is False and adjudicate(ev) == "rejected"


def test_traversal_404s_everywhere_do_not_reject():
    # A router 404 and a handler's "no such file" look alike.
    ev = probe_path_traversal_ssrf(RUNNING, _cand("CWE-22"), ROUTE,
                                   curl(lambda r: (404, "not found")))
    assert ev.reproduced is False and adjudicate(ev) == "needs-review"


# ---- SSRF (CWE-918) ----

FETCH = [Route("GET", "/fetch", "app/api.py", "static", query=("url",), line=3, end_line=9)]
ROOT = "<html><title>Acme internal dashboard</title><body>build 7f3c2a, 14 widgets " \
       "online, cluster eu-west-2b, owner team-orion</body></html>"


def test_ssrf_confirmed_when_the_server_returns_its_own_internal_page():
    def handle(req):
        if req.path == "/":
            return Reply(200, ROOT)
        url = req.query.get("url", "")
        if url == "http://web:8080/":
            return Reply(200, "<pre>" + ROOT + "</pre>")
        return Reply(400, "<p>not a URL</p>")
    ev = probe_path_traversal_ssrf(RUNNING, _cand("CWE-918"), FETCH, curl(handle))
    assert ev.reproduced is True and adjudicate(ev) == "confirmed"
    assert "internal network" in ev.summary


def test_ssrf_confirmed_on_server_side_fetch_error():
    def handle(req):
        if "quarry-ssrf-sentinel.invalid" in req.query.get("url", ""):
            return Reply(502, "Error: getaddrinfo ENOTFOUND quarry-ssrf-sentinel.invalid")
        return Reply(200, "ok")
    ev = probe_path_traversal_ssrf(RUNNING, _cand("CWE-918"), FETCH, curl(handle))
    assert ev.reproduced is True and adjudicate(ev) == "confirmed"


def test_ssrf_rejected_when_internal_addresses_are_refused():
    # The mitigation for a URL-fetching feature: external URLs are fetched (the sentinel
    # fails to resolve), the target's own address is refused.
    def handle(req):
        url = req.query.get("url", "")
        if url.startswith("http://web:8080"):
            return Reply(403, "internal addresses are not allowed")
        if "sentinel" in url:
            return Reply(502, "could not resolve quarry-ssrf-sentinel.invalid")
        return Reply(200, "nothing to fetch")
    ev = probe_path_traversal_ssrf(RUNNING, _cand("CWE-918"), FETCH, curl(handle))
    assert ev.reproduced is False and adjudicate(ev) == "rejected"
    assert "blocks internal targets" in ev.summary


def test_injection_needs_review_without_routes():
    ev = probe_injection_observable(RUNNING, _cand("CWE-79"), [], curl(lambda r: (200, "")))
    assert adjudicate(ev) == "needs-review"
