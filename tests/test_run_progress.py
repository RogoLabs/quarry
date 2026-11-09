"""One status for a run, read from every stage (queries.run_progress).

2026-11-09: the Runs list showed run 3 as `done`, with 0 verdicts and 0 drafts, while
its deep review had a day of refuting left. `done` was `runs.status`, which only
ingest writes, three seconds into the run. And 0 was what the page showed for a
stage that had never run, the same as for one that ran and found nothing, because
validate recorded nothing unless a target booted and report recorded only its digest.

Now validate and report put each attempt on the run, start and end
(`db.stage_started`), and the list, the run page and `quarry runs` / `quarry status`
all show the first thing the run is doing or waiting on.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from quarry import db                                             # noqa: E402
from quarry.dynamic.validate import run_validation                # noqa: E402
from quarry.web import queries as q                               # noqa: E402
from test_run_validation import FakeRuntime, scanned              # noqa: E402,F401
from test_web import _spawn_sleeper, _utc_now, seeded, worker     # noqa: E402,F401


def _last(con, stage, rid=1):
    return db.read_manifest(con, rid)[stage]["last"]


def _progress(con, rid=1):
    return q.run_progress(con, q.run_summary(con, rid))


def _row(html: str, rid: int = 1) -> str:
    """The Runs list's <tr> for run `rid`, after its id cell: target is [0], status [3],
    verdicts [6], drafts [7]."""
    return html.split(f'<a href="/runs/{rid}">{rid}</a>', 1)[1].split("</tr>", 1)[0]


def _cells(row: str) -> list[str]:
    import html
    import re
    return [" ".join(html.unescape(re.sub(r"<[^>]+>", " ", c)).split())
            for c in re.findall(r"<t[dh][^>]*>(.*?)</t[dh]>", row, re.S)]


# ------------------------------------------------- validate and report record themselves

def test_validate_records_its_start_and_how_it_ended(scanned):
    con, rundir = scanned
    assert "validate" not in db.read_manifest(con, 1)
    run_validation(con, 1, rundir, FakeRuntime({"/secret": "200"}))
    last = _last(con, "validate")
    assert last["outcome"] == "probed" and last["pid"] is None
    assert last["started_at"] and last["ended_at"] >= last["started_at"]
    assert (last["candidates"], last["verdicts"], last["confirmed"]) == (1, 1, 0)


def test_validate_records_the_exits_that_write_no_verdict(scanned):
    con, rundir = scanned

    class NoTarget(FakeRuntime):
        def detect(self, src):
            return None

    class Refusing(FakeRuntime):
        def start(self, spec, rundir):
            raise RuntimeError("top-level include is not supported")

    res = run_validation(con, 1, rundir, NoTarget({}))
    assert res.outcome == "nothing to boot" and res.verdicts == []
    assert _last(con, "validate")["outcome"] == "nothing to boot"

    with pytest.raises(RuntimeError):
        run_validation(con, 1, rundir, Refusing({}))
    last = _last(con, "validate")
    assert last["outcome"] == "error" and last["ended_at"]
    assert last["note"] == "RuntimeError: top-level include is not supported"

    with db.tx(con):
        con.execute("DELETE FROM occurrences")
    res = run_validation(con, 1, rundir, FakeRuntime({}))
    assert (res.outcome, res.candidates) == ("no candidates", 0)
    assert _last(con, "validate")["outcome"] == "no candidates"


def test_quarry_report_records_its_start_and_end(seeded, monkeypatch, tmp_path):
    from typer.testing import CliRunner
    from quarry import cli, disclosure, ingest
    _, con = seeded
    monkeypatch.setattr(ingest.RunVolume, "attach_existing",
                        classmethod(lambda cls, *a, **k: type("V", (), {"src": tmp_path})()))
    monkeypatch.setattr(disclosure, "draft_reports", lambda *a, **k: [])
    monkeypatch.setattr(disclosure, "draft_research_digest", lambda *a, **k: None)
    r = CliRunner().invoke(cli.app, ["report", "1"], env={"COLUMNS": "200"})
    assert r.exit_code == 0, r.output
    last = _last(con, "report")
    assert (last["outcome"], last["drafts"], last["digest"]) == ("nothing to report", 0, False)

    def boom(*a, **k):
        raise OSError("disk full")
    monkeypatch.setattr(disclosure, "draft_reports", boom)
    r = CliRunner().invoke(cli.app, ["report", "1"], env={"COLUMNS": "200"})
    assert r.exit_code != 0
    assert _last(con, "report")["outcome"] == "error"
    assert _last(con, "report")["note"] == "OSError: disk full"


# ------------------------------------------------------------------ the Runs list

def test_a_funnelled_run_waits_for_validate_and_says_not_run(seeded):
    """The seeded run is ingested, scanned and funnelled, and nothing more."""
    client, con = seeded
    assert con.execute("SELECT status FROM runs WHERE id=1").fetchone()[0] == "done"
    p = _progress(con)
    assert (p["state"], p["label"], p["stage"]) == ("waiting", "next: validate", "Validate")
    cells = _cells(_row(client.get("/runs").text))
    assert cells[3] == "waiting next: validate"
    assert cells[6:8] == ["not run", "not run"]          # verdicts, drafts
    page = client.get("/runs/1").text
    assert "next: validate" in page
    assert "validate has not run on this run" in page and "report has not run on this run" in page


def test_a_deep_review_at_work_makes_the_run_running(seeded, worker):
    client, con = seeded
    con.execute("INSERT INTO research_runs (id,run_id,status,models,lenses,profile,pid,"
                "heartbeat) VALUES (1,1,'running','[\"a:1b\",\"c:2d\"]','[]','{}',?,?)",
                (worker.pid, _utc_now()))
    con.execute("INSERT INTO research_units (research_id,subsystem,weight,lens,model,"
                "phase,status) VALUES (1,'src',1.0,'x','a:1b','hunt','done')")
    con.execute("INSERT INTO research_findings (research_id,subsystem,lens,model,family,"
                "title,file,quote,quote_verified,refutations) "
                "VALUES (1,'src','x','a:1b','a','t','f.py','q',1,'[]')")
    con.commit()
    p = _progress(con)
    assert p == {"state": "running", "label": "deep review: refuting, 1 answer owed",
                 "href": "/research/1", "stage": "Deep review"}
    cells = _cells(_row(client.get("/runs").text))
    assert cells[3] == "running deep review: refuting, 1 answer owed"
    assert "done" not in cells[3]


def test_a_stopped_review_with_every_unit_hunted_names_the_answers_owed(seeded):
    """It read "1 of 1 units", which looked finished, while the refute pass owed work."""
    _, con = seeded
    con.execute("INSERT INTO research_runs (id,run_id,status,models,lenses,profile) "
                "VALUES (1,1,'stopped','[\"a:1b\",\"c:2d\"]','[]','{}')")
    con.execute("INSERT INTO research_units (research_id,subsystem,weight,lens,model,"
                "phase,status) VALUES (1,'src',1.0,'x','a:1b','hunt','done')")
    con.execute("INSERT INTO research_findings (research_id,subsystem,lens,model,family,"
                "title,file,quote,quote_verified,refutations) "
                "VALUES (1,'src','x','a:1b','a','t','f.py','q',1,'[]')")
    con.commit()
    assert q.deep_state(con, 1)["phase"] == "all 1 units hunted, 1 answer owed"
    p = _progress(con)
    assert (p["state"], p["href"]) == ("stopped", "/research/1")
    assert p["label"] == "deep review stopped, all 1 units hunted, 1 answer owed"


def test_validate_running_then_dead(seeded):
    """A start with no end reads as running while its process is `quarry validate 1`,
    and as died once that process is gone."""
    client, con = seeded
    proc = _spawn_sleeper("quarry.cli", "validate", "1")
    try:
        with db.tx(con):
            db.update_manifest(con, 1, lambda m: m.setdefault("validate", {}).update(
                last={"started_at": _utc_now(), "ended_at": None, "pid": proc.pid,
                      "outcome": "running"}))
        assert q.stage_state(con, 1, "validate")["status"] == "running"
        p = _progress(con)
        assert (p["state"], p["label"]) == ("running", "validate: probing")
        assert _cells(_row(client.get("/runs").text))[6] == "running"
    finally:
        proc.kill()
        proc.wait()
    s = q.stage_state(con, 1, "validate")
    assert s["status"] == "died" and "never finished" in s["note"]
    p = _progress(con)
    assert (p["state"], p["label"]) == ("failed", "validate stopped before it finished; "
                                                  "run it again")


def test_a_pid_that_is_something_else_is_not_a_running_validate(seeded):
    _, con = seeded
    proc = _spawn_sleeper("quarry.cli", "validate", "2")       # another run's validate
    try:
        with db.tx(con):
            db.update_manifest(con, 1, lambda m: m.setdefault("validate", {}).update(
                last={"started_at": _utc_now(), "ended_at": None, "pid": proc.pid}))
        assert q.stage_state(con, 1, "validate")["status"] == "died"
    finally:
        proc.kill()
        proc.wait()


def test_validate_that_had_nothing_to_probe_shows_zero_and_why(seeded):
    client, con = seeded
    db.stage_started(con, 1, "validate")
    db.stage_ended(con, 1, "validate", "no candidates", candidates=0, verdicts=0, confirmed=0)
    cells = _cells(_row(client.get("/runs").text))
    assert cells[6] == "0 no candidates"
    v = [st for st in q.pipeline(con, q.run_summary(con, 1)) if st["name"] == "Validate"][0]
    assert (v["n"], v["unit"]) == (0, "verdicts, 0 confirmed; no candidates")
    # validate has run, nothing is confirmed and there is no deep review: nothing owed
    assert _progress(con) == {"state": "done", "label": "every stage has run",
                              "href": "/runs/1#terminal", "stage": "Report"}
    assert _cells(_row(client.get("/runs").text))[3] == "done every stage has run"


def test_a_failed_validate_says_why(seeded):
    _, con = seeded
    db.stage_started(con, 1, "validate")
    db.stage_ended(con, 1, "validate", "error",
                   note="DockerError: Cannot connect to the Docker daemon")
    p = _progress(con)
    assert p["state"] == "failed"
    assert p["label"] == "validate failed: DockerError: Cannot connect to the Docker daemon"


def test_done_needs_a_draft_for_each_confirmed_verdict(seeded, tmp_path):
    _, con = seeded
    fid = con.execute("SELECT finding_id FROM occurrences WHERE run_id=1 LIMIT 1"
                      ).fetchone()[0]
    with db.tx(con):
        vid = db.verdict(con, fid, 1, verdict="confirmed", model="idor")
    # A verdict from before attempts were recorded still counts as validate having run.
    assert q.stage_state(con, 1, "validate")["status"] == "done"
    p = _progress(con)
    assert (p["state"], p["label"]) == ("waiting", "next: report, 1 confirmed verdict "
                                                   "with no draft")
    with db.tx(con):
        db.advisory(con, 1, fid, str(tmp_path / "adv.md"), "ab" * 32, verdict_id=vid)
    assert _progress(con)["state"] == "done"


def test_a_finished_deep_review_waits_for_its_digest(seeded):
    _, con = seeded
    con.execute("INSERT INTO research_runs (id,run_id,status,models,lenses,profile) "
                "VALUES (1,1,'done','[\"a:1b\"]','[]','{}')")
    con.commit()
    db.stage_started(con, 1, "validate")
    db.stage_ended(con, 1, "validate", "nothing to boot", candidates=3, verdicts=0,
                   confirmed=0)
    p = _progress(con)
    assert (p["state"], p["label"]) == ("waiting", "next: report, for the deep review's digest")
    db.stage_started(con, 1, "report")
    db.stage_ended(con, 1, "report", "nothing to report", drafts=0, digest=False)
    assert _progress(con)["state"] == "done"


def test_an_ingest_failure_wins(seeded):
    _, con = seeded
    con.execute("UPDATE runs SET status='failed' WHERE id=1")
    con.commit()
    p = _progress(con)
    assert (p["state"], p["label"]) == ("failed", "ingest failed")


# --------------------------------------------------------------------- the terminal

def test_quarry_status_and_runs_say_the_same_thing(seeded):
    from typer.testing import CliRunner
    from quarry import cli
    r = CliRunner().invoke(cli.app, ["status", "1"])
    assert r.exit_code == 0, r.output
    lines = r.output.splitlines()
    for want in ("run.status: waiting", "run.progress: next: validate", "run.ingest: done"):
        assert want in lines, want
    doc = json.loads(CliRunner().invoke(cli.app, ["status", "1", "--json"]).output)
    assert (doc["run"]["status"], doc["run"]["ingest"]) == ("waiting", "done")

    r = CliRunner().invoke(cli.app, ["runs"], env={"COLUMNS": "200"})
    assert r.exit_code == 0, r.output
    row = next(ln for ln in r.output.splitlines() if "o/r" in ln)
    assert "waiting" in row and "next: validate" in row
