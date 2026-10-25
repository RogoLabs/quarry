"""The injection-observable and path-traversal/SSRF probe bodies, driven hermetically
with a fake exec_fn. Each check is benign and read-only; the fake stands in for the
target's responses so the decision logic is pinned without a daemon.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quarry.dynamic.validate import Candidate, RunningTarget, adjudicate      # noqa: E402
from quarry.dynamic.routes import Route                                       # noqa: E402
from quarry.dynamic.probes import (                                           # noqa: E402
    probe_injection_observable, probe_path_traversal_ssrf)

# A reproduction is held at needs-review until the probe records a baseline comparison
# (validate.NO_BASELINE). When a probe fills `baseline` and `differs_from_baseline`,
# its reproductions here go back to asserting "confirmed".
HELD = "needs-review"
RUNNING = RunningTarget(base_url="http://web:8080", stop=lambda: None, network="net")
# a route with a path param so payloads land in the path
ROUTE = [Route("GET", "/items/{id}", "app/api.py", "static", params=("id",))]


def _cand(cwe):
    return Candidate("f1", 1, "o/r", "app/api.py", 5, "prod", cwe, "msg")


def _body_fn(responder):
    def run(argv):
        return 0, responder(argv[-1])
    return run


# ---- XSS (CWE-79) ----

def test_xss_confirmed_on_unencoded_reflection():
    # echo the raw payload back (the part after /items/)
    def resp(url):
        return "<html>" + url.split("/items/", 1)[-1] + "</html>"
    ev = probe_injection_observable(RUNNING, _cand("CWE-79"), ROUTE, _body_fn(resp))
    assert ev.reproduced is True and adjudicate(ev) == HELD


def test_xss_rejected_when_encoded():
    def resp(url):
        raw = url.split("/items/", 1)[-1]
        return "<html>" + raw.replace("<", "&lt;").replace(">", "&gt;") + "</html>"
    ev = probe_injection_observable(RUNNING, _cand("CWE-79"), ROUTE, _body_fn(resp))
    assert ev.reproduced is False and ev.determinism == "deterministic"
    assert adjudicate(ev) == "rejected"


# ---- SQLi (CWE-89) ----

def test_sqli_confirmed_on_error_differential():
    def resp(url):
        tail = url.split("/items/", 1)[-1]
        return "OperationalError: unrecognized token near \"'\"" if tail.endswith("'") else "ok"
    ev = probe_injection_observable(RUNNING, _cand("CWE-89"), ROUTE, _body_fn(resp))
    assert ev.reproduced is True and adjudicate(ev) == HELD


def test_sqli_needs_review_without_error():
    # no error on a quote is not positive proof of parameterisation (blind SQLi exists).
    ev = probe_injection_observable(RUNNING, _cand("CWE-89"), ROUTE, _body_fn(lambda u: "ok"))
    assert ev.reproduced is False and adjudicate(ev) == "needs-review"


# ---- command injection (CWE-77) ----

def test_command_injection_confirmed_on_id_output():
    def resp(url):
        return "uid=0(root) gid=0(root)" if "id" in url.split("/items/", 1)[-1] else "x"
    ev = probe_injection_observable(RUNNING, _cand("CWE-77"), ROUTE, _body_fn(resp))
    assert ev.reproduced is True and adjudicate(ev) == HELD


# ---- path traversal (CWE-22) ----

def test_traversal_confirmed_on_passwd_signature():
    def resp(url):
        return "root:x:0:0:root:/root:/bin/bash\n" if "passwd" in url else "not found"
    ev = probe_path_traversal_ssrf(RUNNING, _cand("CWE-22"), ROUTE, _body_fn(resp))
    assert ev.reproduced is True and adjudicate(ev) == HELD
    assert "escapes" in ev.summary


def test_traversal_needs_review_when_no_leak():
    # no passwd leak is not proof of containment (other files, encodings, blind variants).
    ev = probe_path_traversal_ssrf(RUNNING, _cand("CWE-22"), ROUTE,
                                   _body_fn(lambda u: "404 not found"))
    assert ev.reproduced is False and adjudicate(ev) == "needs-review"


# ---- SSRF (CWE-918) ----

def test_ssrf_confirmed_on_server_side_fetch_error():
    def resp(url):
        if "quarry-ssrf-sentinel.invalid" in url:
            return "Error: getaddrinfo ENOTFOUND quarry-ssrf-sentinel.invalid"
        return "ok"
    ev = probe_path_traversal_ssrf(RUNNING, _cand("CWE-918"),
                                   [Route("GET", "/fetch", "app/api.py", "static", params=("url",))],
                                   _body_fn(resp))
    assert ev.reproduced is True and adjudicate(ev) == HELD


def test_injection_needs_review_without_routes():
    ev = probe_injection_observable(RUNNING, _cand("CWE-79"), [], _body_fn(lambda u: ""))
    assert adjudicate(ev) == "needs-review"
