"""Probes must send their path exactly as written (IMPROVEMENT-PLAN P4: curl path
normalisation, `--path-as-is`).

curl removes dot segments from a URL's path before it sends it (RFC 3986 section 5.2.4)
unless it is given `--path-as-is`. The traversal probe's first payload,
`/files/../../../../../../etc/passwd`, went out as `GET /etc/passwd`: the request never
reached the route under test, and the probe recorded a request it did not send.
MEASURED with curl 8.7.1 against a loopback listener, and in the sidecar image
(curlimages/curl:8.11.1, `-w %{url_effective}` with `--network none`): without the flag
the effective URL is `/etc/passwd`, with it the path is kept. Percent-encoded dots and
`....//` are not rewritten either way.

The live test here runs the host's curl against a listener on 127.0.0.1 and reads the
request line the server received. Nothing leaves the machine.
"""
from __future__ import annotations

import shutil
import socket
import subprocess
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quarry.dynamic import lenses                                      # noqa: E402
from quarry.dynamic.probes import probe_path_traversal_ssrf            # noqa: E402
from quarry.dynamic.routes import Route                                # noqa: E402
from quarry.dynamic.validate import Candidate, RunningTarget           # noqa: E402

# Each handler spans the finding's line 3, so every probe decides on its own route
# (since the probe-controls merge, a probe only decides on a route whose handler holds
# the finding's line), and the users route declares per-operation security.
ROUTES = [
    Route("GET", "/api/users/{uid}", "app.py", "openapi", auth_required=True,
          params=("uid",), auth_scope="operation", line=1, end_line=10),
    Route("GET", "/login", "app.py", "static", query=("q",), line=1, end_line=10),
    Route("GET", "/files/<name>", "app.py", "static", params=("name",), line=1,
          end_line=10),
]
# Lens and CWE pairs that send nothing by design: a request rate says nothing about
# CWE-400 (ReDoS and the like), so the rate-limit probe leaves it unprobed.
SILENT = {("missing-rate-limit", "CWE-400")}
CASES = [(lens, cwe) for lens in lenses.CATALOGUE for cwe in sorted(lens.cwes)]
PASSWD = "root:x:0:0:root:/root:/bin/sh\n"


@pytest.mark.parametrize("lens, cwe", CASES,
                         ids=[f"{lens.key}-{cwe}" for lens, cwe in CASES])
def test_every_probe_request_keeps_its_path_as_written(lens, cwe):
    seen: list[list[str]] = []

    def exec_fn(argv):
        seen.append(argv)
        if "-w" in argv:
            fmt = argv[argv.index("-w") + 1]
            return 0, "200 0.010000" if "time_total" in fmt else "200"
        return 0, "ok"

    running = RunningTarget("http://web:8080", stop=lambda: None, network="net")
    lens.probe(running, Candidate("f", 1, "o/r", "app.py", 3, "p", cwe, "m"), ROUTES,
               exec_fn)
    if (lens.key, cwe) in SILENT:
        assert not seen
        return
    assert seen, f"{lens.key} sent nothing"
    assert all("--path-as-is" in argv for argv in seen), \
        [a for a in seen if "--path-as-is" not in a][:1]


@pytest.fixture
def server():
    """A loopback HTTP listener that records each request line and, like a handler
    that joins the raw path onto a directory, serves a passwd-shaped body only when a
    `..` segment survives to it under /files/."""
    lines: list[str] = []
    stop = threading.Event()
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(16)
    srv.settimeout(0.2)

    def serve():
        while not stop.is_set():
            try:
                c, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            c.settimeout(10)
            with c:
                data = b""
                while b"\r\n\r\n" not in data:
                    chunk = c.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                line = data.split(b"\r\n", 1)[0].decode("latin-1")
                lines.append(line)
                target = line.split(" ")[1] if line.count(" ") >= 2 else ""
                ok = target.startswith("/files/../")
                body = PASSWD if ok else "not found"
                status = "200 OK" if ok else "404 Not Found"
                c.sendall(f"HTTP/1.1 {status}\r\nContent-Length: {len(body)}\r\n"
                          f"Connection: close\r\n\r\n{body}".encode())

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.getsockname()[1]}", lines
    stop.set()
    t.join(timeout=5)
    srv.close()


@pytest.mark.skipif(not shutil.which("curl"), reason="curl not installed")
def test_a_traversal_probe_reaches_the_server_unnormalised(server):
    base, lines = server

    def exec_fn(argv):
        r = subprocess.run(["curl", *argv], capture_output=True, text=True, timeout=20)
        return r.returncode, r.stdout

    running = RunningTarget(base, stop=lambda: None, network="")
    ev = probe_path_traversal_ssrf(
        running, Candidate("f", 1, "o/r", "app.py", 3, "p", "CWE-22", "m"),
        [Route("GET", "/files/<name>", "app.py", "static", params=("name",), line=1,
               end_line=10)], exec_fn)

    # Since the probe-controls merge a benign control request goes first, so the
    # traversal is looked for among the lines, not at the front.
    assert lines, "the listener saw no request"
    raw = [ln for ln in lines
           if ln.startswith("GET /files/../") and ln.endswith("/etc/passwd HTTP/1.1")]
    assert raw, lines                              # dot segments arrived as written
    assert "GET /etc/passwd HTTP/1.1" not in lines
    assert ev.reproduced is True                   # the handler was reached and read it
    assert raw[0].split(" ")[1] in ev.request      # the record names what was sent
