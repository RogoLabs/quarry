"""The anonymous authz probe body and the runtime route sources.

Hermetic tests drive the probe and the OpenAPI/crawl parsers with a fake curl, so the
decision logic is pinned without Docker. A docker-gated test then stands a real target up
on the isolated network and shows the probe confirms a declared-protected route whose
check fails open, and holds the two cases it cannot decide.

The anonymous probe's control is an invalid credential (a working check refuses it) and
its baseline a valid seeded credential (whose body the anonymous response must match).
It never rejects: an anonymous refusal is authentication, not authorization.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quarry.dynamic.validate import (                                         # noqa: E402
    Candidate, RunningTarget, adjudicate, adjudicate_with_reason, NO_BASELINE)
from quarry.dynamic.routes import (                                           # noqa: E402
    Route, routes_from_openapi, fetch_openapi_routes, crawl_routes)
from quarry.dynamic.probes import probe_broken_authz                          # noqa: E402
from quarry.dynamic import runtime_docker as rt                               # noqa: E402
from fakecurl import Reply, curl                                              # noqa: E402

CAND = Candidate("f1", 1, "o/r", "app/api.py", 5, "prod", "CWE-862", "missing authz")
RUNNING = RunningTarget(base_url="http://web:8080", stop=lambda: None, network="net")
KEYED = RunningTarget(base_url="http://web:8080", stop=lambda: None, network="net",
                      credentials={"user_api_key": "k-user-0123456789"})

OPENAPI = {"openapi": "3.0.0",
           "components": {"securitySchemes": {"key": {"type": "apiKey", "in": "header",
                                                      "name": "X-API-KEY"}}},
           "paths": {
               "/secret": {"get": {"security": [{"key": []}]}},
               "/protected/{id}": {"get": {"security": [{"key": []}],
                                           "parameters": [{"name": "id", "in": "path"}]}},
               "/health": {"get": {}},
           }}


def _own(routes, line=5, path="app/api.py"):
    """The routes as the static pass would leave them after the merge: in the finding's
    file, with a handler span that encloses its line."""
    from dataclasses import replace
    return [replace(r, handler_file=path, line=line - 1, end_line=line + 1) for r in routes]


def test_routes_from_openapi():
    routes = {(r.method, r.path): r for r in routes_from_openapi(OPENAPI)}
    assert routes[("GET", "/secret")].auth_required is True
    assert routes[("GET", "/secret")].auth_scope == "operation"
    assert routes[("GET", "/secret")].auth_header == "X-API-KEY"
    assert routes[("GET", "/protected/{id}")].params == ("id",)
    assert routes[("GET", "/health")].auth_required is False


def _server(served: dict):
    """A target whose routes answer by credential: served[path] = {"none": code,
    "invalid": code, "valid": code}, with a fixed body per credential class."""
    def handle(req):
        key = req.headers.get("x-api-key")
        who = "none" if key is None else ("valid" if key.startswith("k-") else "invalid")
        codes = served.get(req.path)
        if codes is None:
            return 404, "nope"
        code = codes.get(who, 404)
        body = codes.get(f"{who}_body", "SECRET RECORD 42" if code == 200 else "denied")
        return Reply(code, body, "application/json")
    return curl(handle)


def test_confirms_a_check_that_fails_open_on_a_missing_credential():
    # The VulnLookup auth_func shape, wrong: a present key is checked, an absent one is
    # waved through. The invalid key's 401 is the control the anonymous 200 departs from.
    routes = _own(routes_from_openapi(OPENAPI))
    fake = _server({"/secret": {"none": 200, "invalid": 401, "valid": 200}})
    ev = probe_broken_authz(KEYED, CAND, routes, fake)
    assert ev.reproduced is True and ev.differs_from_baseline is True
    assert adjudicate(ev) == "confirmed"
    assert "invalid credential" in ev.baseline and "401" in ev.baseline
    assert "<user_api_key>" in ev.baseline and "k-user" not in ev.baseline   # no secret
    assert "byte for byte" in ev.summary


def test_holds_when_an_invalid_credential_is_served_too():
    # No refusal anywhere: the route checks nothing, or the spec is stale. Either way there
    # is no control to compare against.
    routes = _own(routes_from_openapi(OPENAPI))
    fake = _server({"/secret": {"none": 200, "invalid": 200, "valid": 200}})
    ev = probe_broken_authz(RUNNING, CAND, routes, fake)
    assert ev.reproduced is True
    assert adjudicate_with_reason(ev) == ("needs-review", NO_BASELINE)


def test_holds_when_anonymous_gets_a_different_body_than_a_valid_key():
    routes = _own(routes_from_openapi(OPENAPI))
    fake = _server({"/secret": {"none": 200, "none_body": "public teaser",
                                "invalid": 401, "valid": 200}})
    ev = probe_broken_authz(KEYED, CAND, routes, fake)
    assert ev.reproduced is True and adjudicate(ev) == "needs-review"
    assert "public view" in ev.summary


def test_a_denial_is_never_a_rejection():
    # Anonymous 401/403 says nothing about IDOR, which is cross-principal by definition.
    routes = _own(routes_from_openapi(OPENAPI))
    fake = _server({"/secret": {"none": 401}, "/protected/1": {"none": 403}})
    ev = probe_broken_authz(RUNNING, CAND, routes, fake)
    assert ev.reproduced is False and ev.determinism == "deterministic"
    assert adjudicate(ev) == "needs-review" and "cross-user" in ev.summary


def test_a_spec_wide_requirement_is_not_declared_protection():
    # VulnLookup's swagger.json: `security: [{apikey: []}]` at the top, nothing per
    # operation, so the public read API inherits it. Not "this route is protected".
    doc = {"swagger": "2.0", "security": [{"apikey": []}],
           "securityDefinitions": {"apikey": {"type": "apiKey", "in": "header",
                                              "name": "X-API-KEY"}},
           "paths": {"/secret": {"get": {}}}}
    routes = _own(routes_from_openapi(doc))
    assert routes[0].auth_required is True and routes[0].auth_scope == "global"
    fake = _server({"/secret": {"none": 200, "invalid": 401, "valid": 200}})
    ev = probe_broken_authz(RUNNING, CAND, routes, fake)
    assert ev.reproduced is False and adjudicate(ev) == "needs-review"
    assert "spec-wide" in ev.summary and fake.requests == []      # nothing was sent


def test_a_sibling_route_is_measured_but_not_decided():
    # The route is declared protected and fails open, but its handler does not enclose
    # the finding's line: a different finding, held for a human.
    routes = _own(routes_from_openapi(OPENAPI), line=40)
    fake = _server({"/secret": {"none": 200, "invalid": 401, "valid": 200}})
    ev = probe_broken_authz(KEYED, CAND, routes, fake)
    assert ev.reproduced is True and ev.differs_from_baseline is None
    assert adjudicate(ev) == "needs-review" and "held for review" in ev.summary


def test_probe_needs_review_without_a_security_signal():
    # static-only routes carry no auth flag, so the probe cannot decide.
    routes = [Route("GET", "/secret", "app/api.py", "static", line=4, end_line=6)]
    ev = probe_broken_authz(RUNNING, CAND, routes, _server({"/secret": {"none": 200}}))
    assert ev.reproduced is False and ev.determinism == "unknown"
    assert adjudicate(ev) == "needs-review"


def test_crawl_is_bounded_and_get_only():
    pages = {"/": "<a href='/a'>a</a><a href='/b'>b</a>",
             "/a": "<a href='/c'>c</a>", "/b": "", "/c": ""}
    def run(argv):
        url = argv[-1]
        path = "/" + url.split("http://web:8080", 1)[-1].lstrip("/")
        return (0, pages.get(path, "")) if path in pages else (0, "")
    routes = crawl_routes(run, "http://web:8080", max_fetch=3)
    assert all(r.method == "GET" and r.source == "crawl" for r in routes)
    assert len(routes) <= 3                          # bound respected


# ------------------------------------------------------------------ live (docker)

docker = pytest.mark.skipif(not rt.docker_available(), reason="docker daemon not available")

APP = (
    "from http.server import BaseHTTPRequestHandler, HTTPServer\n"
    "import json\n"
    "SPEC = {'openapi':'3.0.0',\n"
    " 'components':{'securitySchemes':{'k':{'type':'apiKey','in':'header','name':'X-API-KEY'}}},\n"
    " 'paths':{'/secret':{'get':{'security':[{'k':[]}]}},\n"
    "          '/failopen':{'get':{'security':[{'k':[]}]}},\n"
    "          '/protected':{'get':{'security':[{'k':[]}]}}}}\n"
    "class H(BaseHTTPRequestHandler):\n"
    "    def do_GET(self):\n"
    "        key = self.headers.get('X-API-KEY')\n"
    "        if self.path=='/openapi.json': return self.s(200, json.dumps(SPEC))\n"
    "        if self.path=='/secret': return self.s(200, 'TOP SECRET')\n"   # checks nothing
    "        if self.path=='/failopen':\n"                                     # the bug
    "            if key is not None and key != 'good': return self.s(401, 'bad key')\n"
    "            return self.s(200, 'TOP SECRET')\n"
    "        if self.path=='/protected':\n"
    "            return self.s(200,'ok') if key == 'good' else self.s(403,'no')\n"
    "        return self.s(404,'nope')\n"
    "    def s(self, code, body):\n"
    "        self.send_response(code); self.end_headers(); self.wfile.write(body.encode())\n"
    "    def log_message(self,*a): pass\n"
    "HTTPServer(('0.0.0.0',8080), H).serve_forever()\n"
)


@docker
def test_authz_probe_decides_against_a_live_target(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text(APP)
    (src / "docker-compose.yml").write_text(
        "services:\n"
        "  web:\n"
        "    image: python:3.13-alpine\n"
        "    command: ['python','/app/app.py']\n"
        "    volumes: ['./:/app']\n"
        "    ports: ['18081:8080']\n")
    runtime = rt.DockerRuntime(health_timeout=90)
    running = runtime.start(runtime.detect(src), tmp_path)
    running.credentials = {"user_api_key": "good"}
    try:
        exec_fn = lambda argv: runtime.probe_exec(running, argv)
        routes = _own(fetch_openapi_routes(exec_fn, running.base_url))
        assert {r.path for r in routes} == {"/secret", "/failopen", "/protected"}
        by = {r.path: [r] for r in routes}

        # Fails open on a missing key: invalid key 401, no key 200, same body as a valid
        # key -> confirmed.
        ev = probe_broken_authz(running, CAND, by["/failopen"], exec_fn)
        assert adjudicate(ev) == "confirmed", ev
        assert "401" in ev.baseline and ev.differs_from_baseline is True

        # Checks nothing at all: no refusal to compare against -> held.
        ev = probe_broken_authz(running, CAND, by["/secret"], exec_fn)
        assert ev.reproduced is True and adjudicate(ev) == "needs-review", ev.summary

        # Refuses anonymous: authentication works; not a rejection of an authz finding.
        ev = probe_broken_authz(running, CAND, by["/protected"], exec_fn)
        assert ev.reproduced is False and adjudicate(ev) == "needs-review", ev.summary
    finally:
        running.stop()
