"""The end-to-end Layer 3 loop, hermetic: profile a target, select the probe lens the
codebase supports, merge static and OpenAPI routes, probe, and write a verdict. A fake
runtime stands in for Docker so the whole orchestration is pinned without a daemon.
"""
from __future__ import annotations

import json
import sys
from dataclasses import replace
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quarry import db                                              # noqa: E402
from quarry.dynamic import lenses, probes                          # noqa: E402
from quarry.dynamic.validate import (                              # noqa: E402
    NO_BASELINE, RuntimeSpec, RunningTarget, run_validation)

SPEC = {"openapi": "3.0.0", "paths": {
    "/secret": {"get": {"security": [{"b": []}]}},
    "/health": {"get": {}},
}}


class FakeRuntime:
    """Detects a compose target, 'starts' it, and answers probes from a status map."""
    def __init__(self, status):
        self.status = status
        self.stopped = False

    def detect(self, src):
        return RuntimeSpec("compose", "docker-compose.yml", base_url="http://web:8080")

    def start(self, spec, rundir):
        return RunningTarget("http://web:8080", stop=self._stop, network="net")

    def _stop(self):
        self.stopped = True

    def probe_exec(self, running, argv):
        url = argv[-1]
        if "-w" in argv:                                  # status probe
            for suffix, code in self.status.items():
                if url.endswith(suffix):
                    return 0, code
            return 0, "404"
        if url.endswith("/openapi.json"):                 # spec fetch
            return 0, json.dumps(SPEC)
        return 0, ""


@pytest.fixture
def scanned(tmp_path):
    # A target that profiles as a service with a route in app.py, and a live CWE-862
    # finding in that file.
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text(
        "@app.get('/secret')\n"
        "def secret(): ...\n"
        "@app.get('/health')\n"
        "def health(): ...\n"
        "@app.get('/users')\n"
        "def users(): ...\n"
        "@app.post('/users')\n"
        "def make_user(): ...\n")
    (src / "docker-compose.yml").write_text("services:\n  web:\n    image: x\n")
    p = tmp_path / "quarry.db"
    db.init(p)
    con = db.connect(p)
    with db.tx(con):
        con.execute("INSERT INTO runs (id, target, clone_url) VALUES (1,'o/r','https://x')")
        con.execute("""INSERT INTO producers (id,tool,rule_id,cwe,n_adjudicated,n_confirmed)
                       VALUES ('t:authz','opengrep','authz','CWE-862',3,2)""")
        con.execute("""INSERT INTO findings (id,target,path,producer_id,first_seen_run,last_seen_run)
                       VALUES ('f-secret','o/r','app.py','t:authz',1,1)""")
        con.execute("""INSERT INTO occurrences (id,run_id,finding_id,producer_id,path,start_line,message)
                       VALUES (10,1,'f-secret','t:authz','app.py',2,'missing authz')""")
    return con, tmp_path


def test_holds_an_open_protected_route_without_a_baseline(scanned):
    # The authz probe reproduces (declared protected, served open) but does not yet record
    # a baseline comparison, so the verdict waits for a human instead of being confirmed.
    con, rundir = scanned
    runtime = FakeRuntime({"/secret": "200"})          # declared protected, served open
    res = run_validation(con, 1, rundir, runtime)
    assert (res.confirmed, res.rejected, res.needs_review) == (0, 0, 1)
    assert res.verdicts == [("f-secret", "broken-authz-idor", "needs-review")]
    assert runtime.stopped is True                      # target always torn down
    row = dict(con.execute("SELECT * FROM verdicts WHERE finding_id='f-secret'").fetchone())
    assert row["verdict"] == "needs-review" and row["reason"] == NO_BASELINE


def test_confirms_an_open_protected_route_with_a_baseline(scanned, monkeypatch):
    # Stand in for the authz probe once it records its control request: same body, plus
    # the baseline it measured against. Only then does the loop confirm.
    con, rundir = scanned

    def with_baseline(running, cand, routes, exec_fn):
        ev = probes.probe_broken_authz(running, cand, routes, exec_fn)
        return replace(ev, baseline="GET /health -> 200 (unprotected sibling)",
                       differs_from_baseline=True)
    catalogue = tuple(replace(lens, run=with_baseline) if lens.key == "broken-authz-idor"
                      else lens for lens in lenses.CATALOGUE)
    monkeypatch.setattr(lenses, "CATALOGUE", catalogue)
    runtime = FakeRuntime({"/secret": "200"})
    res = run_validation(con, 1, rundir, runtime)
    assert (res.confirmed, res.rejected, res.needs_review) == (1, 0, 0)
    assert res.verdicts == [("f-secret", "broken-authz-idor", "confirmed")]
    row = dict(con.execute("SELECT * FROM verdicts WHERE finding_id='f-secret'").fetchone())
    assert row["verdict"] == "confirmed" and row["executed_score"] == 100


def test_kills_a_properly_protected_route_end_to_end(scanned):
    con, rundir = scanned
    runtime = FakeRuntime({"/secret": "403"})          # declared protected, enforced
    res = run_validation(con, 1, rundir, runtime)
    assert (res.confirmed, res.rejected, res.needs_review) == (0, 1, 0)
    row = dict(con.execute("SELECT * FROM verdicts WHERE finding_id='f-secret'").fetchone())
    assert row["verdict"] == "rejected" and row["executed_score"] == 50
