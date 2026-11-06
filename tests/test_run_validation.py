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
from fakecurl import Reply, curl                                   # noqa: E402

SPEC = {"openapi": "3.0.0", "paths": {
    "/secret": {"get": {"security": [{"b": []}]}},
    "/health": {"get": {}},
}}


class FakeRuntime:
    """Detects a compose target, 'starts' it, and answers probes from a status map."""
    def __init__(self, status):
        self.status = status
        self.stopped = False
        self.http = curl(self.handle)

    def detect(self, src):
        return RuntimeSpec("compose", "docker-compose.yml", base_url="http://web:8080")

    def start(self, spec, rundir):
        return RunningTarget("http://web:8080", stop=self._stop, network="net")

    def _stop(self):
        self.stopped = True

    def handle(self, req):
        if req.path == "/openapi.json":                   # spec fetch
            return Reply(200, json.dumps(SPEC), "application/json")
        for suffix, code in self.status.items():
            if req.path.endswith(suffix):
                return Reply(int(code), "record", "application/json")
        return Reply(404, "", "text/plain")

    def probe_exec(self, running, argv):
        if "-w" not in argv:                              # the fetch/crawl helpers
            url = argv[-1]
            return 0, json.dumps(SPEC) if url.endswith("/openapi.json") else ""
        return self.http(argv)


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


def test_seeding_runs_the_targets_commands_and_carries_inputs_to_probes(scanned):
    con, rundir = scanned
    from quarry.dynamic.seed import SeedRecipe, SeedStep

    class Seeding(FakeRuntime):
        def __init__(self, status):
            super().__init__(status)
            self.seeded = []
            self.running = None

        def start(self, spec, rundir):
            self.running = RunningTarget("http://web:8080", stop=self._stop, network="net",
                                         project="p", compose_file="/x/compose.yml")
            return self.running

        def service_exec(self, running, argv, *, service="", timeout=900):
            self.seeded.append(argv)
            if "getkey" in argv:
                return 0, "APIKEY=abcdef0123456789\n"
            return 0, "ok"

    recipe = SeedRecipe(name="t", param_values={"vulnerability_id": "CVE-2021-44228"},
                        steps=(SeedStep(argv=("mkadmin", "--password", "{password}")),
                               SeedStep(argv=("getkey",), capture=r"APIKEY=(\w+)",
                                        capture_as="admin_api_key")))
    rt = Seeding({"/secret": "401"})
    run_validation(con, 1, rundir, rt, seed=recipe)
    assert ["mkadmin", "--password"] == rt.seeded[0][:2]
    assert "{password}" not in rt.seeded[0]                      # generated, not literal
    assert rt.running.param_values["vulnerability_id"] == "CVE-2021-44228"
    assert rt.running.credentials["admin_api_key"] == "abcdef0123456789"
    seed_notes = db.read_manifest(con, 1)["health"]["validate"]["seed"]
    assert any("captured admin_api_key" in n for n in seed_notes)


def test_seed_recipe_and_service_are_recorded_for_the_advisory(scanned):
    # The advisory's Conditions section reads these back. A run with no recipe records
    # None, so a draft can say "not seeded" rather than "not recorded".
    con, rundir = scanned
    from quarry.dynamic.seed import SeedRecipe, SeedStep

    class Seeding(FakeRuntime):
        def start(self, spec, rundir):
            return RunningTarget("http://web:8080", stop=self._stop, network="net",
                                 service="web", port=8080)

        def service_exec(self, running, argv, *, service="", timeout=900):
            self.argv = argv
            return 0, "APIKEY=abcdef0123456789\n"

    rt = Seeding({"/secret": "401"})
    recipe = SeedRecipe(name="t", steps=(SeedStep(
        argv=("mkadmin", "--password", "{password}"), capture=r"APIKEY=(\w+)",
        capture_as="admin_api_key"),))
    run_validation(con, 1, rundir, rt, seed=recipe)
    m = db.read_manifest(con, 1)
    assert m["validate"]["seed"] == "t" and m["validate"]["service"] == "web"
    # names only: neither the captured key nor the generated password is on the run
    dumped = json.dumps(m)
    assert "abcdef0123456789" not in dumped and rt.argv[2] not in dumped

    run_validation(con, 1, rundir, FakeRuntime({"/secret": "401"}))
    m = db.read_manifest(con, 1)
    assert m["validate"]["seed"] is None and m["validate"]["service"] is None


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


# --- IMPROVEMENT-PLAN items 16 to 18: readiness routes, replay, probe identity -----

def _confirming(monkeypatch, verdicts=None):
    """The authz probe with a baseline, so it confirms. `verdicts` scripts later calls:
    True keeps confirming, False loses the baseline difference (a replay that
    disagrees). Returns the call counter."""
    calls = {"n": 0}

    def probe(running, cand, routes, exec_fn):
        calls["n"] += 1
        ev = probes.probe_broken_authz(running, cand, routes, exec_fn)
        keep = True if verdicts is None else verdicts[min(calls["n"], len(verdicts)) - 1]
        return replace(ev, baseline="GET /health -> 200 (unprotected sibling)",
                       differs_from_baseline=keep)
    monkeypatch.setattr(lenses, "CATALOGUE", tuple(
        replace(lens, run=probe) if lens.key == "broken-authz-idor" else lens
        for lens in lenses.CATALOGUE))
    return calls


class Restartable(FakeRuntime):
    provisioning = {"build_network": "none", "env_overrides": ["INSTANCE_UUID"],
                    "readiness": {"request": "GET /health", "status": 200}}

    def __init__(self, status, fail=False):
        super().__init__(status)
        self.restarts, self.fail, self.spec = 0, fail, None

    def start(self, spec, rundir):
        self.spec = spec
        return super().start(spec, rundir)

    def restart(self, running, ready_paths=()):
        self.restarts += 1
        if self.fail:
            raise RuntimeError("compose restart failed")
        return {"basis": "known-route"}


def test_a_confirmation_is_replayed_in_place_and_after_a_restart(scanned, monkeypatch):
    con, rundir = scanned
    calls = _confirming(monkeypatch)
    runtime = Restartable({"/secret": "200"})
    res = run_validation(con, 1, rundir, runtime)
    assert res.verdicts == [("f-secret", "broken-authz-idor", "confirmed")]
    assert calls["n"] == 5 and runtime.restarts == 1    # 1 + 3 in place + 1 after restart
    row = con.execute("SELECT rationale FROM verdicts WHERE finding_id='f-secret'").fetchone()
    ev = json.loads(row["rationale"])
    assert {k: ev["replay"][k] for k in ("attempts", "reproduced", "control_held",
                                         "after_restart", "held")} == \
        {"attempts": 4, "reproduced": 4, "control_held": 4, "after_restart": True,
         "held": True}
    assert ev["probe"]["id"] == "broken-authz-idor" and len(ev["probe"]["source_sha"]) == 64
    assert ev["probe"]["method"] == "GET" and ev["probe"]["route"] == "/secret"
    assert "evidence_blob" in ev["probe"]
    assert ev["conditions"] == {"seed": None, "env_keys": ["INSTANCE_UUID"],
                                "readiness": "GET /health", "build_network": "none"}
    # Readiness was handed the clone's parameter-free GET routes (item 16).
    assert set(runtime.spec.ready_paths) == {"/secret", "/health", "/users"}


def test_a_confirmation_that_does_not_replay_is_held(scanned, monkeypatch):
    con, rundir = scanned
    _confirming(monkeypatch, verdicts=[True, True, False, True, True])
    res = run_validation(con, 1, rundir, Restartable({"/secret": "200"}))
    assert res.verdicts == [("f-secret", "broken-authz-idor", "needs-review")]
    row = dict(con.execute("SELECT * FROM verdicts WHERE finding_id='f-secret'").fetchone())
    assert row["reason"] == "did not replay" and row["executed_score"] == 50
    assert json.loads(row["rationale"])["replay"]["reproduced"] == 4
    assert json.loads(row["rationale"])["replay"]["control_held"] == 3


def test_a_restart_that_fails_holds_the_confirmation(scanned, monkeypatch):
    con, rundir = scanned
    _confirming(monkeypatch)
    res = run_validation(con, 1, rundir, Restartable({"/secret": "200"}, fail=True))
    assert res.verdicts == [("f-secret", "broken-authz-idor", "needs-review")]
    ev = json.loads(con.execute("SELECT rationale FROM verdicts").fetchone()["rationale"])
    assert ev["replay"]["after_restart"] is False and ev["replay"]["held"] is False
    assert "restart failed: RuntimeError" in ev["replay"]["note"]


def test_only_confirmations_are_replayed(scanned, monkeypatch):
    con, rundir = scanned
    _with_control(monkeypatch)
    runtime = Restartable({"/secret": "403"})
    res = run_validation(con, 1, rundir, runtime)
    assert res.verdicts == [("f-secret", "broken-authz-idor", "rejected")]
    assert runtime.restarts == 0
    ev = json.loads(con.execute("SELECT rationale FROM verdicts").fetchone()["rationale"])
    assert "replay" not in ev and ev["probe"]["id"] == "broken-authz-idor"


# ------------------------------------------------------------------ cross-user, end to end

SIGHTING_PY = (
    "ns = Namespace('sighting')\n"
    "@ns.route('/<uuid:sighting_uuid>')\n"
    "class SightingItem(Resource):\n"
    "    def get(self, sighting_uuid):\n"
    "        return {}\n"
    "\n"
    "    @auth_func\n"
    "    def delete(self, sighting_uuid):\n"
    "        obj = Sighting.query.get(sighting_uuid)  # the flagged line\n"
    "        return {}, 200\n"
    "@ns.route('/')\n"
    "class Sightings(Resource):\n"
    "    def post(self):\n"
    "        return {}, 201\n")


@pytest.mark.parametrize("delete_any, verdict", [(False, "rejected"), (True, "confirmed")])
def test_a_seeded_cross_user_run_decides_on_the_findings_own_handler(tmp_path, delete_any,
                                                                     verdict):
    """Seed three accounts with the target's own commands, then let the authz lens test
    the flagged DELETE handler as another account. The verdict names the canaries it
    made and no key, and the precision ledger counts it."""
    from test_probes_cross_user import VL, CREDS, SPEC as XU
    from quarry.dynamic.seed import SeedRecipe, SeedStep

    src = tmp_path / "src"
    (src / "website" / "api").mkdir(parents=True)
    (src / "website" / "api" / "__init__.py").write_text(
        "bp = Blueprint('apiv1', __name__, url_prefix='/api')\n"
        "def setup():\n"
        "    api = Api(bp)\n"
        "    from website.api import sighting\n"
        "    api.add_namespace(sighting.ns, path='/sighting')\n")
    (src / "website" / "api" / "sighting.py").write_text(SIGHTING_PY)
    (src / "website" / "app.py").write_text(            # enough routes to profile a service
        "@app.get('/health')\ndef h(): ...\n@app.get('/v')\ndef v(): ...\n"
        "@app.post('/x')\ndef x(): ...\n")
    (src / "docker-compose.yml").write_text("services:\n  web:\n    image: x\n")
    flagged = SIGHTING_PY.splitlines().index(
        "        obj = Sighting.query.get(sighting_uuid)  # the flagged line") + 1
    p = tmp_path / "quarry.db"
    db.init(p)
    con = db.connect(p)
    with db.tx(con):
        con.execute("INSERT INTO runs (id, target, clone_url) VALUES (1,'o/r','https://x')")
        con.execute("""INSERT INTO producers (id,tool,rule_id,cwe,n_adjudicated,n_confirmed)
                       VALUES ('t:idor','opengrep','idor','CWE-639',0,0)""")
        con.execute("""INSERT INTO findings (id,target,path,producer_id,first_seen_run,
                       last_seen_run) VALUES ('f-idor','o/r','website/api/sighting.py',
                       't:idor',1,1)""")
        con.execute("""INSERT INTO occurrences (id,run_id,finding_id,producer_id,path,
                       start_line,message) VALUES (10,1,'f-idor','t:idor',
                       'website/api/sighting.py',?,'idor')""", (flagged,))

    vl = VL(delete_any=delete_any)

    class Seeded(FakeRuntime):
        def start(self, spec, rundir):
            return RunningTarget("http://web:10001", stop=self._stop, network="net",
                                 project="p", compose_file="/x/compose.yml")

        def service_exec(self, running, argv, *, service="", timeout=900):
            return 0, CREDS.get(argv[-1], "ok")       # `getkey <name>` prints the key

        def probe_exec(self, running, argv):
            return vl.fake(argv) if "-w" in argv else (0, "")

    recipe = SeedRecipe(
        name="t", param_values={"vulnerability_id": "CVE-2021-44228"}, cross_user=XU,
        steps=tuple(SeedStep(argv=("getkey", k), capture=r"(\S{16,})", capture_as=k)
                    for k in CREDS))
    res = run_validation(con, 1, tmp_path, Seeded({}), seed=recipe)
    assert res.verdicts == [("f-idor", "broken-authz-idor", verdict)]
    row = dict(con.execute("SELECT * FROM verdicts WHERE finding_id='f-idor'").fetchone())
    stored = json.loads(row["rationale"])
    assert row["verdict"] == verdict and row["reason"] == "deterministic"
    assert "contained throwaway instance" in stored["summary"]
    assert stored["reproduces_when"] == "differs"
    assert not any(k in row["rationale"] for k in CREDS.values())    # no key stored
    assert vl.records == {}                                          # canaries cleaned up
    assert tuple(con.execute("SELECT n_adjudicated FROM producers WHERE id='t:idor'")
                 .fetchone()) == (1,)


def test_a_sameness_confirmation_counts_its_control_as_held():
    """A rate-limit probe confirms when a burst is answered the SAME as a lone request
    (reproduces_when "same", differs_from_baseline False). Counting replays on
    `differs_from_baseline is True` reported its control as never holding."""
    from quarry.dynamic.validate import ProbeEvidence, replay_confirmation
    ev = ProbeEvidence(reproduced=True, summary="20 requests, no throttle",
                       determinism="deterministic", baseline="GET /login -> 401 (lone)",
                       differs_from_baseline=False, handled=True,
                       reproduces_when="same")
    assert ev.has_baseline_comparison
    out = replay_confirmation(lambda: ev, times=3)
    assert (out["reproduced"], out["control_held"], out["held"]) == (3, 3, True)


# ------------------------------------------------- item 16: served spec beside readiness

OTHER_APP = {"openapi": "3.0.0", "paths": {"/metrics": {"get": {}}, "/admin": {"get": {}},
                                           "/queue": {"post": {}}}}


@pytest.mark.parametrize("committed, matches, warns", [
    (SPEC, True, False),                    # the clone's spec is what the target serves
    (OTHER_APP, False, True),               # a different API answered on the port
    (None, None, False),                    # nothing committed: recorded, not a failure
], ids=["same", "different", "none-committed"])
def test_the_served_spec_is_compared_with_the_committed_one(scanned, committed, matches,
                                                             warns):
    con, rundir = scanned
    if committed is not None:
        (rundir / "src" / "docs").mkdir()
        (rundir / "src" / "docs" / "openapi.json").write_text(json.dumps(committed))
    res = run_validation(con, 1, rundir, FakeRuntime({"/secret": "401"}))
    assert res.verdicts                                  # it never blocked probing
    m = db.read_manifest(con, 1)
    got = m["validate"]["readiness"]["served_spec"]
    assert got["matches"] is matches and got["served"] == "/openapi.json"
    assert got["served_ops"] == 2
    warning = m.get("health", {}).get("validate", {}).get("served-spec")
    assert bool(warning) is warns
    if warns:
        assert "shares 0 of its 2 operations with the 3 in the committed " \
               "docs/openapi.json" in warning[0]
    if matches:
        assert got["identical"] is True and got["compared_with"] == "docs/openapi.json"


def test_a_target_that_serves_no_spec_is_recorded_and_a_rerun_clears_the_warning(scanned):
    con, rundir = scanned
    (rundir / "src" / "openapi.json").write_text(json.dumps(OTHER_APP))
    run_validation(con, 1, rundir, FakeRuntime({"/secret": "401"}))
    assert db.read_manifest(con, 1)["health"]["validate"]["served-spec"]

    class Silent(FakeRuntime):
        def probe_exec(self, running, argv):
            return (0, "") if "-w" not in argv else self.http(argv)
    run_validation(con, 1, rundir, Silent({"/secret": "401"}))
    m = db.read_manifest(con, 1)
    got = m["validate"]["readiness"]["served_spec"]
    assert got["served"] is None and got["matches"] is None
    assert got["committed"] == ["openapi.json"]
    assert "served-spec" not in m["health"]["validate"]


# ------------------------------------------------------------------ timing, end to end

TIMING_APP = (
    "import bcrypt\n"
    "@app.get('/login')\n"
    "def login():\n"
    "    user = User.find(request.args.get('username'))  # the flagged line\n"
    "    return {}\n"
    "@app.get('/health')\n"
    "def health(): ...\n")


@pytest.fixture
def timing_run(tmp_path):
    """A service with an auth capability and a live CWE-208 finding inside GET /login."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text(TIMING_APP)
    (src / "docker-compose.yml").write_text("services:\n  web:\n    image: x\n")
    p = tmp_path / "quarry.db"
    db.init(p)
    con = db.connect(p)
    with db.tx(con):
        con.execute("INSERT INTO runs (id, target, clone_url) VALUES (1,'o/r','https://x')")
        con.execute("""INSERT INTO producers (id,tool,rule_id,cwe) VALUES
                       ('t:timing','opengrep','timing','CWE-208')""")
        con.execute("""INSERT INTO findings (id,target,path,producer_id,first_seen_run,
                       last_seen_run) VALUES ('f-timing','o/r','app.py','t:timing',1,1)""")
        con.execute("""INSERT INTO occurrences (id,run_id,finding_id,producer_id,path,
                       start_line,message) VALUES (10,1,'f-timing','t:timing','app.py',4,
                       'timing')""")
    return con, tmp_path


class TimingTarget(Restartable):
    """GET /login answers `admin` in 60 ms and anything else in 5 ms, until `flat_after`
    login requests have been answered; after that every identifier takes 20 ms."""
    def __init__(self, flat_after=None):
        super().__init__({})
        self.flat_after, self.logins = flat_after, 0

    def handle(self, req):
        if req.path != "/login":
            return Reply(404, "", "text/plain")
        self.logins += 1
        if self.flat_after is not None and self.logins > self.flat_after:
            return Reply(401, "", "application/json", 0.020)
        slow = req.query.get("username") == "admin"
        return Reply(401, "", "application/json", 0.060 if slow else 0.005)


def test_a_timing_confirmation_is_replayed_like_the_others(timing_run):
    con, rundir = timing_run
    target = TimingTarget()
    res = run_validation(con, 1, rundir, target)
    assert res.verdicts == [("f-timing", "auth-timing-oracle", "confirmed")]
    assert target.restarts == 1 and target.logins == 5 * 48   # first + 3 + 1 after restart
    row = dict(con.execute("SELECT * FROM verdicts WHERE finding_id='f-timing'").fetchone())
    assert row["reason"] == "statistical"
    ev = json.loads(row["rationale"])
    assert {k: ev["replay"][k] for k in ("attempts", "reproduced", "control_held",
                                         "after_restart", "held")} == \
        {"attempts": 4, "reproduced": 4, "control_held": 4, "after_restart": True,
         "held": True}
    assert ev["probe"]["route"] == "/login" and ev["differs_from_baseline"] is True
    assert "two absent identifiers" in ev["baseline"]


def test_a_timing_separation_that_does_not_replay_is_held(timing_run):
    con, rundir = timing_run
    res = run_validation(con, 1, rundir, TimingTarget(flat_after=48))
    assert res.verdicts == [("f-timing", "auth-timing-oracle", "needs-review")]
    row = dict(con.execute("SELECT * FROM verdicts WHERE finding_id='f-timing'").fetchone())
    assert row["reason"] == "did not replay"
    assert json.loads(row["rationale"])["replay"]["reproduced"] == 0
