"""Every probe class and its control against one live target, through the real sidecar.

The hermetic tests pin the decisions with a fake curl. This one checks what the fake
cannot: that the argv each probe builds means to the real curl what the probe expects
(`-g`, `--path-as-is`, the `%header{}` write-out, twenty URLs with an `-o` each in one
run), and that real servers answer the way the controls assume. The target is a small
threaded http.server on the isolated internal network, with a vulnerable and a safe
handler per class. The probes run through DockerRuntime.probe_exec exactly as in
`quarry validate`; nothing here reaches beyond that network. Docker-gated.
"""
from __future__ import annotations

import dataclasses

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quarry.dynamic import runtime_docker as rt                               # noqa: E402
from quarry.dynamic.probes import (                                           # noqa: E402
    probe_auth_timing_oracle, probe_cross_user, probe_injection_observable,
    probe_missing_rate_limit, probe_path_traversal_ssrf)
from quarry.dynamic.routes import Route                                       # noqa: E402
from quarry.dynamic.seed import CrossUser, OwnedResource                      # noqa: E402
from quarry.dynamic.validate import Candidate, adjudicate                     # noqa: E402

docker = pytest.mark.skipif(not rt.docker_available(), reason="docker daemon not available")

APP = r'''
import html, json, os, re, sqlite3, subprocess, time, urllib.parse, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

os.makedirs("/srv/files", exist_ok=True)
open("/srv/files/readme.txt", "w").write("hello")
KEYS = {"k-owner-0000000000001": "owner", "k-other-0000000000002": "other"}
STORE, HITS = {}, {"n": 0}
ROOT = ("<html><title>Fixture internal console</title><body>node 4f9a1c, seven queues, "
        "region test-1, owner team-quarry-fixture, build 2026.11.05</body></html>")


class H(BaseHTTPRequestHandler):
    def send(self, code, body, ctype="text/html; charset=utf-8", headers=()):
        b = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass

    def parts(self):
        u = urllib.parse.urlsplit(self.path)
        return u.path, dict(urllib.parse.parse_qsl(u.query))

    def fetch(self, url):
        try:
            return self.send(200, urllib.request.urlopen(url, timeout=3).read().decode(),
                             "text/plain")
        except ValueError:
            return self.send(400, "not a URL", "text/plain")
        except Exception as e:
            return self.send(502, f"fetch failed for {url}: {e}", "text/plain")

    def do_GET(self):
        raw, q = self.parts()
        path = urllib.parse.unquote(raw)
        if path == "/":
            return self.send(200, ROOT)
        if path == "/echo":                                   # reflected XSS
            return self.send(200, "<p>" + q.get("term", "") + "</p>")
        if path == "/safe":
            return self.send(200, "<p>" + html.escape(q.get("term", ""), quote=True) + "</p>")
        if path == "/ping":                                   # command injection
            out = subprocess.run("echo pinging " + q.get("host", ""), shell=True,
                                 capture_output=True, text=True, timeout=5).stdout
            return self.send(200, out, "text/plain")
        if path == "/ping_safe":
            host = q.get("host", "")
            if not re.fullmatch(r"[A-Za-z0-9.-]+", host):
                return self.send(400, "invalid host", "text/plain")
            return self.send(200, "pinging " + host, "text/plain")
        if path.startswith("/files/"):                        # traversal
            try:
                return self.send(200, open(os.path.join("/srv/files", path[7:])).read(),
                                 "text/plain")
            except OSError:
                return self.send(404, "no such file", "text/plain")
        if path.startswith("/files_safe/"):
            name = path[len("/files_safe/"):]
            if ".." in name or name.startswith("/"):
                return self.send(400, "invalid path", "text/plain")
            try:
                return self.send(200, open(os.path.join("/srv/files", name)).read(),
                                 "text/plain")
            except OSError:
                return self.send(404, "no such file", "text/plain")
        if path == "/fetch":                                  # SSRF
            return self.fetch(q.get("url", ""))
        if path == "/fetch_safe":
            host = urllib.parse.urlsplit(q.get("url", "")).hostname or ""
            if host in ("web", "localhost") or host.startswith("127."):
                return self.send(403, "internal addresses are not allowed", "text/plain")
            return self.fetch(q.get("url", ""))
        if path == "/login":                                  # no rate limit
            return self.send(401, '{"error": "bad credentials"}', "application/json")
        if path in ("/item", "/item_typed"):                  # SQL injection
            v = q.get("id", "")
            if path == "/item_typed" and not v.isdigit():
                return self.send(422, "id must be an integer", "text/plain")
            con = sqlite3.connect(":memory:")
            con.execute("CREATE TABLE t (id INTEGER, name TEXT)")
            con.execute("INSERT INTO t VALUES (1, 'one')")
            try:
                rows = (con.execute("SELECT name FROM t WHERE id = " + v).fetchall()
                        if path == "/item" else
                        con.execute("SELECT name FROM t WHERE id = ?", (int(v),)).fetchall())
            except sqlite3.Error as e:
                return self.send(500, f"sqlite3.{type(e).__name__}: {e}", "text/plain")
            return self.send(200, json.dumps(rows), "application/json")
        if path == "/whoami":                                 # account timing oracle
            if q.get("username") == "quarry_user":
                time.sleep(0.08)               # a hash compared only for a real account
            return self.send(401, '{"error": "bad credentials"}', "application/json")
        if path == "/whoami_flat":
            return self.send(401, '{"error": "bad credentials"}', "application/json")
        if path == "/login_limited":
            HITS["n"] += 1
            if HITS["n"] > 5:
                return self.send(429, "slow down", "application/json", [("Retry-After", "60")])
            return self.send(401, '{"error": "bad credentials"}', "application/json")
        if path.startswith("/api/"):
            return self.api("GET", path)
        return self.send(404, "nope", "text/plain")

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.api("POST", urllib.parse.unquote(self.parts()[0]),
                        self.rfile.read(n).decode())

    def do_DELETE(self):
        return self.api("DELETE", urllib.parse.unquote(self.parts()[0]))

    def api(self, method, path, body=None):
        m = re.fullmatch(r"/api/(sighting|bundle)/([^/]*)", path)
        if not m:
            return self.send(404, "{}", "application/json")
        kind, rid = m[1], m[2]
        who = KEYS.get(self.headers.get("X-API-KEY", ""))
        delete_any = kind == "bundle"                         # the cross-user bug
        if method == "POST" and rid == "":
            if who is None:
                return self.send(401, "{}", "application/json")
            doc = json.loads(body)
            rec = STORE.get(doc["uuid"])
            if rec is None:
                STORE[doc["uuid"]] = {"owner": who, **doc}
                return self.send(201, json.dumps(doc), "application/json")
            if who != rec["owner"]:
                return self.send(403, "{}", "application/json")
            rec.update(doc)
            return self.send(201, json.dumps(rec), "application/json")
        rec = STORE.get(rid)
        if method == "GET":
            if rec is None:
                return self.send(404, "{}", "application/json")
            return self.send(200, json.dumps(rec, sort_keys=True), "application/json")
        if method == "DELETE":
            if who is None:
                return self.send(401, "{}", "application/json")
            if rec is None:
                return self.send(404, "{}", "application/json")
            if who != rec["owner"] and not delete_any:
                return self.send(403, "{}", "application/json")
            del STORE[rid]
            return self.send(200, "{}", "application/json")
        return self.send(405, "{}", "application/json")


ThreadingHTTPServer(("0.0.0.0", 8080), H).serve_forever()
'''


def _cand(cwe):
    return Candidate("f1", 1, "o/r", "app.py", 5, "prod", cwe, "msg")


def _route(method, path, **kw):
    """The finding's own handler: the span encloses line 5 of app.py."""
    return [Route(method, path, "app.py", "static", line=1, end_line=999, **kw)]


@pytest.fixture(scope="module")
def target(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("live")
    src = tmp / "src"
    src.mkdir()
    (src / "app.py").write_text(APP)
    (src / "docker-compose.yml").write_text(
        "services:\n"
        "  web:\n"
        "    image: python:3.13-alpine\n"
        "    command: ['python','/app/app.py']\n"
        "    volumes: ['./:/app']\n"
        "    ports: ['18082:8080']\n")
    runtime = rt.DockerRuntime(health_timeout=90)
    # Readiness needs a route the app serves (IMPROVEMENT-PLAN item 16).
    running = runtime.start(dataclasses.replace(runtime.detect(src), ready_paths=("/",)),
                            tmp)
    try:
        yield running, (lambda argv: runtime.probe_exec(running, argv))
    finally:
        running.stop()


@docker
@pytest.mark.parametrize("path, cwe, verdict", [
    ("/echo", "CWE-79", "confirmed"), ("/safe", "CWE-79", "rejected"),
    ("/ping", "CWE-78", "confirmed"), ("/ping_safe", "CWE-78", "rejected"),
    ("/item", "CWE-89", "confirmed"), ("/item_typed", "CWE-89", "rejected"),
])
def test_injection_controls_decide_against_a_live_target(target, path, cwe, verdict):
    running, exec_fn = target
    query = {"CWE-79": ("term",), "CWE-89": ("id",)}.get(cwe, ("host",))
    ev = probe_injection_observable(running, _cand(cwe), _route("GET", path, query=query),
                                    exec_fn)
    assert adjudicate(ev) == verdict, ev


@docker
@pytest.mark.parametrize("path, cwe, verdict", [
    ("/files/<path:name>", "CWE-22", "confirmed"),
    ("/files_safe/<path:name>", "CWE-22", "rejected"),
    ("/fetch", "CWE-918", "confirmed"), ("/fetch_safe", "CWE-918", "rejected"),
])
def test_traversal_and_ssrf_controls_decide_against_a_live_target(target, path, cwe, verdict):
    running, exec_fn = target
    query = ("url",) if cwe == "CWE-918" else ()
    ev = probe_path_traversal_ssrf(running, _cand(cwe), _route("GET", path, query=query),
                                   exec_fn)
    assert adjudicate(ev) == verdict, ev


@docker
@pytest.mark.parametrize("path, verdict", [("/login", "confirmed"),
                                           ("/login_limited", "rejected")])
def test_rate_limit_decides_against_a_live_target(target, path, verdict):
    running, exec_fn = target
    ev = probe_missing_rate_limit(running, _cand("CWE-307"), _route("GET", path), exec_fn)
    assert adjudicate(ev) == verdict, ev


@docker
def test_timing_decides_against_a_live_target(target):
    """The real curl's time_pretransfer and time_starttransfer, over the sidecar. An
    80 ms delay for the one existing account confirms. The flat handler must never
    confirm; it rejects when the measured spread is small enough to have seen 10 ms,
    and is held for review when this machine's load makes it noisier than that."""
    running, exec_fn = target
    seeded = dataclasses.replace(running, param_values={"username": "quarry_user"})
    ev = probe_auth_timing_oracle(seeded, _cand("CWE-208"),
                                  _route("GET", "/whoami", query=("username",)), exec_fn)
    assert adjudicate(ev) == "confirmed", ev
    ev = probe_auth_timing_oracle(seeded, _cand("CWE-208"),
                                  _route("GET", "/whoami_flat", query=("username",)),
                                  exec_fn)
    verdict = adjudicate(ev)
    assert verdict == "rejected" or (verdict == "needs-review"
                                     and "too noisy" in ev.summary), ev


@docker
@pytest.mark.parametrize("kind, verdict", [("sighting", "rejected"), ("bundle", "confirmed")])
def test_cross_user_decides_against_a_live_target(target, kind, verdict):
    running, exec_fn = target
    running.credentials = {"owner_key": "k-owner-0000000000001",
                           "other_key": "k-other-0000000000002"}
    running.cross_user = CrossUser(
        header="X-API-KEY", accounts={"owner_key": "owner", "other_key": "other"},
        resources=(OwnedResource(name=kind, collection=f"/api/{kind}/",
                                 item=f"/api/{kind}/{{id}}",
                                 body='{"uuid": "{id}", "name": "canary {marker}"}',
                                 owner="owner_key", other="other_key"),))
    ev = probe_cross_user(running, _cand("CWE-639"),
                          _route("DELETE", f"/api/{kind}/<id>"), exec_fn)
    assert adjudicate(ev) == verdict, ev
    # Both canaries are gone: the owner's GET of either answers 404.
    for rid in {seg.split()[0].rsplit("/", 1)[-1] for seg in ev.request.split("; ")
                if seg.startswith("DELETE")}:
        rc, out = exec_fn(["-s", "-o", "/dev/null", "-w", "%{http_code}",
                           running.base_url + f"/api/{kind}/{rid}"])
        assert out.strip() == "404"
