"""The authz probe body and the runtime route sources.

Hermetic tests drive the probe and the OpenAPI/crawl parsers with a fake exec_fn, so the
decision logic is pinned without Docker. A docker-gated test then stands a real target up
on the isolated network and shows the probe confirms a declared-protected route that is
reachable unauthenticated, and kills one that is properly denied.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quarry.dynamic.validate import Candidate, RunningTarget, adjudicate      # noqa: E402
from quarry.dynamic.routes import (                                           # noqa: E402
    Route, routes_from_openapi, fetch_openapi_routes, crawl_routes)
from quarry.dynamic.probes import probe_broken_authz                          # noqa: E402
from quarry.dynamic import runtime_docker as rt                               # noqa: E402

CAND = Candidate("f1", 1, "o/r", "app/api.py", 5, "prod", "CWE-862", "missing authz")
# A reproduction is held at needs-review until the probe records a baseline comparison
# (validate.NO_BASELINE). When a probe fills `baseline` and `differs_from_baseline`,
# its reproductions here go back to asserting "confirmed".
HELD = "needs-review"
RUNNING = RunningTarget(base_url="http://web:8080", stop=lambda: None, network="net")

OPENAPI = {"openapi": "3.0.0", "paths": {
    "/secret": {"get": {"security": [{"bearer": []}]}},
    "/protected/{id}": {"get": {"security": [{"bearer": []}],
                                "parameters": [{"name": "id", "in": "path"}]}},
    "/health": {"get": {}},
}}


def test_routes_from_openapi():
    routes = {(r.method, r.path): r for r in routes_from_openapi(OPENAPI)}
    assert routes[("GET", "/secret")].auth_required is True
    assert routes[("GET", "/protected/{id}")].params == ("id",)
    assert routes[("GET", "/health")].auth_required is False


def _status_exec(mapping):
    """Fake exec_fn: for a status probe (-w) return the mapped code by URL suffix."""
    def run(argv):
        url = argv[-1]
        if "-w" in argv:
            for suffix, code in mapping.items():
                if url.endswith(suffix):
                    return 0, code
            return 0, "404"
        return 0, ""
    return run


def test_probe_confirms_unauthenticated_reach():
    routes = routes_from_openapi(OPENAPI)
    ev = probe_broken_authz(RUNNING, CAND, routes, _status_exec({"/secret": "200"}))
    assert ev.reproduced is True and ev.determinism == "deterministic"
    assert "no credentials" in ev.summary and adjudicate(ev) == HELD


def test_probe_kills_when_properly_denied():
    routes = routes_from_openapi(OPENAPI)
    ev = probe_broken_authz(RUNNING, CAND, routes,
                            _status_exec({"/secret": "401", "/protected/1": "403"}))
    assert ev.reproduced is False and ev.determinism == "deterministic"
    assert adjudicate(ev) == "rejected"


def test_probe_needs_review_without_a_security_signal():
    # static-only routes carry no auth flag, so the probe cannot decide.
    routes = [Route("GET", "/secret", "app/api.py", "static")]
    ev = probe_broken_authz(RUNNING, CAND, routes, _status_exec({"/secret": "200"}))
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
    "SPEC = {'openapi':'3.0.0','paths':{"
    "'/secret':{'get':{'security':[{'b':[]}]}},"
    "'/protected':{'get':{'security':[{'b':[]}]}}}}\n"
    "class H(BaseHTTPRequestHandler):\n"
    "    def do_GET(self):\n"
    "        if self.path=='/openapi.json': return self.s(200, json.dumps(SPEC))\n"
    "        if self.path=='/secret': return self.s(200, 'TOP SECRET')\n"  # the bug
    "        if self.path=='/protected':\n"
    "            return self.s(200,'ok') if self.headers.get('Authorization') else self.s(403,'no')\n"
    "        return self.s(404,'nope')\n"
    "    def s(self, code, body):\n"
    "        self.send_response(code); self.end_headers(); self.wfile.write(body.encode())\n"
    "    def log_message(self,*a): pass\n"
    "HTTPServer(('0.0.0.0',8080), H).serve_forever()\n"
)


@docker
def test_authz_probe_confirms_and_kills_against_a_live_target(tmp_path):
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
    try:
        exec_fn = lambda argv: runtime.probe_exec(running, argv)
        routes = fetch_openapi_routes(exec_fn, running.base_url)
        assert {r.path for r in routes} == {"/secret", "/protected"}

        # /secret is declared protected but served open -> reproduced (held, no baseline).
        secret = [r for r in routes if r.path == "/secret"]
        ev = probe_broken_authz(running, CAND, secret, exec_fn)
        assert ev.reproduced is True and adjudicate(ev) == HELD, ev.summary

        # /protected denies without a token -> killed, with evidence.
        protected = [r for r in routes if r.path == "/protected"]
        ev = probe_broken_authz(running, CAND, protected, exec_fn)
        assert ev.reproduced is False and adjudicate(ev) == "rejected", ev.summary
    finally:
        running.stop()
