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
    NO_BASELINE, NO_CONTROL, RuntimeSpec, RunningTarget, run_validation)

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


def test_holds_a_denied_route_without_a_control(scanned):
    # Anonymous denial was a rejection, which carried forward and killed the finding in
    # every later run. The authz probe records no control, so it is held instead.
    con, rundir = scanned
    runtime = FakeRuntime({"/secret": "403"})          # declared protected, enforced
    res = run_validation(con, 1, rundir, runtime)
    assert (res.confirmed, res.rejected, res.needs_review) == (0, 0, 1)
    row = dict(con.execute("SELECT * FROM verdicts WHERE finding_id='f-secret'").fetchone())
    assert row["verdict"] == "needs-review" and row["reason"] == NO_CONTROL


def _with_control(monkeypatch):
    """Stand in for the authz probe once it records a control: a denial measured
    against an unprotected sibling that the same anonymous client could reach."""
    def controlled(running, cand, routes, exec_fn):
        ev = probes.probe_broken_authz(running, cand, routes, exec_fn)
        return replace(ev, handled=True, differs_from_baseline=False,
                       baseline="GET /health -> 200 (unprotected sibling)")
    catalogue = tuple(replace(lens, run=controlled) if lens.key == "broken-authz-idor"
                      else lens for lens in lenses.CATALOGUE)
    monkeypatch.setattr(lenses, "CATALOGUE", catalogue)


def test_kills_a_denied_route_measured_against_a_control(scanned, monkeypatch):
    con, rundir = scanned
    _with_control(monkeypatch)
    res = run_validation(con, 1, rundir, FakeRuntime({"/secret": "403"}))
    assert (res.confirmed, res.rejected, res.needs_review) == (0, 1, 0)
    row = dict(con.execute("SELECT * FROM verdicts WHERE finding_id='f-secret'").fetchone())
    assert row["verdict"] == "rejected" and row["executed_score"] == 50


def _ledger(con):
    r = con.execute("SELECT n_adjudicated, n_confirmed FROM producers WHERE id='t:authz'")
    return tuple(r.fetchone())


@pytest.mark.parametrize("served, controlled, ledger", [
    ("200", False, (0, 0)),     # needs-review: no baseline, so nothing adjudicated
    ("403", False, (0, 0)),     # needs-review: no control
    ("403", True, (1, 0)),      # rejected against a control
])
def test_validation_refreshes_the_precision_ledger(scanned, monkeypatch,
                                                   served, controlled, ledger):
    # The fixture seeds (3, 2). Validation recomputes from verdicts, and only confirmed
    # and rejected count: a needs-review used to read as an adjudicated non-confirmation,
    # so five unanswered probes banded a producer known-bad.
    con, rundir = scanned
    if controlled:
        _with_control(monkeypatch)
    run_validation(con, 1, rundir, FakeRuntime({"/secret": served}))
    assert _ledger(con) == ledger


def test_a_target_that_will_not_come_up_is_recorded_on_the_run(scanned):
    # A refused compose file or a build that needed the network used to surface only as
    # a traceback. It is a health warning on the run now, and a later good run clears it.
    con, rundir = scanned

    class Refusing(FakeRuntime):
        def start(self, spec, rundir):
            raise RuntimeError("top-level include is not supported")

    with pytest.raises(RuntimeError):
        run_validation(con, 1, rundir, Refusing({}))
    health = db.read_manifest(con, 1)["health"]["validate"]
    assert health == {"runtime": ["compose: RuntimeError: top-level include is not supported"]}

    run_validation(con, 1, rundir, FakeRuntime({"/secret": "200"}))
    assert db.read_manifest(con, 1)["health"]["validate"] == {}


def test_provisioning_choices_are_recorded_on_the_run(scanned):
    con, rundir = scanned

    class Provisioned(FakeRuntime):
        provisioning = {"build_network": "default", "dotenv": ".env.sample",
                        "env_files": ["service 'web': env_file .env is missing; "
                                      "used .env.sample"],
                        "env_overrides": ["INSTANCE_UUID"]}

    run_validation(con, 1, rundir, Provisioned({"/secret": "200"}))
    m = db.read_manifest(con, 1)
    assert m["validate"]["provisioning"]["build_network"] == "default"
    health = m["health"]["validate"]
    assert "--build-network" in health["build-network"][0]
    assert health["env"][0] == "no .env in the clone; interpolated from .env.sample"
    assert "env_file .env is missing" in health["env"][1]
    assert health["env"][2] == "set by the operator with --env: INSTANCE_UUID"

    class Offline(FakeRuntime):
        provisioning = {"build_network": "none", "dotenv": ".env", "env_files": []}

    run_validation(con, 1, rundir, Offline({"/secret": "200"}))
    assert db.read_manifest(con, 1)["health"]["validate"] == {}


def _candidate_ids(con):
    from quarry.dynamic.validate import select_candidates
    return [c.finding_id for c in select_candidates(con, 1)]


def _add_finding(con, fid, tool, rule, cwe, path, line=2):
    with db.tx(con):
        pid = db.upsert_producer(con, tool, rule, cwe=cwe)
        con.execute("INSERT INTO findings (id,target,path,producer_id,first_seen_run,"
                    "last_seen_run) VALUES (?,?,?,?,1,1)", (fid, "o/r", path, pid))
        con.execute("INSERT INTO occurrences (run_id,finding_id,producer_id,path,"
                    "start_line,message) VALUES (1,?,?,?,?,'m')", (fid, pid, path, line))


def test_a_long_form_cwe_is_selected_and_stored_short(scanned):
    """IMPROVEMENT-PLAN item 10. Opengrep tags read 'CWE-22: Improper Limitation...',
    which never equalled 'CWE-22', so no Opengrep finding reached Layer 3."""
    con, _ = scanned
    _add_finding(con, "f-trav", "opengrep", "path-join",
                 "CWE-22: Improper Limitation of a Pathname to a Restricted Directory",
                 "app.py")
    assert "f-trav" in _candidate_ids(con)
    assert con.execute("SELECT cwe FROM producers WHERE id='opengrep:path-join'"
                       ).fetchone()[0] == "CWE-22"
    # A producer stored in the long form by an older build is still selected.
    con.execute("UPDATE producers SET cwe='CWE-22: Improper Limitation' "
                "WHERE id='opengrep:path-join'")
    from quarry.dynamic.validate import select_candidates
    trav = [c for c in select_candidates(con, 1) if c.finding_id == "f-trav"]
    assert [c.cwe for c in trav] == ["CWE-22"]          # what the verdict will carry


def test_cwe_78_reaches_the_command_injection_probe(scanned):
    from quarry.cwe import probe_class
    from quarry.dynamic.lenses import CATALOGUE
    con, _ = scanned
    _add_finding(con, "f-cmd", "bandit", "B602", "CWE-78", "app.py")
    cands = [c for c in __import__("quarry.dynamic.validate", fromlist=["x"])
             .select_candidates(con, 1) if c.finding_id == "f-cmd"]
    assert cands and cands[0].cwe == "CWE-78"            # stored as the scanner said
    assert any(probe_class(cands[0].cwe) in lens.cwes for lens in CATALOGUE)


def test_dependency_findings_are_not_probe_candidates(scanned):
    """IMPROVEMENT-PLAN item 11. Both verdicts in the DB were probes against
    poetry.lock: no route, nothing decided, two of the 50-candidate budget spent."""
    con, _ = scanned
    _add_finding(con, "f-osv", "osv-scanner", "GHSA-xxxx", "CWE-22", "poetry.lock", 0)
    _add_finding(con, "f-trivy", "trivy", "CVE-2024-1", "CWE-400", "poetry.lock", 0)
    ids = _candidate_ids(con)
    assert "f-osv" not in ids and "f-trivy" not in ids
    assert "f-secret" in ids
