"""A deep review that stops says so, and a refute pass left unfinished is work left.

Three ways a run's record went wrong, all seen on run 3 between 2026-11-07 and 11-09:

- SIGTERM, from the dashboard's Stop, ended the worker without a word to the database,
  so the row kept `running` and the dead pid and read as `died`, a crash. Ctrl-C did
  the same. `quarry deep` now turns SIGTERM into KeyboardInterrupt, `runner.execute`
  records `stopped`, and `db.tx` rolls back on it rather than leaving a transaction
  open that swallowed that write.
- A night whose deadline cut the refute pass short, with every unit hunted, finished
  `done`. The review read as finished with answers owed, and the nightly job, which
  resumed only for units, never asked them.
- The dashboard offered Resume only when units were left, so a stopped refute pass
  had no button.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import textwrap
import time
from datetime import datetime, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from quarry import db                                             # noqa: E402
from quarry.cli import _term_as_interrupt                         # noqa: E402
from quarry.research import ensemble as E, runner                 # noqa: E402
from quarry.web import queries as q                               # noqa: E402
from test_deep_intent import _planned                             # noqa: E402
from test_web import seeded                                       # noqa: E402,F401

HUNTER = "qwen3.6:27b"            # the finding's author; devstral, another family, owes


def _row(con, rid):
    return dict(con.execute("SELECT * FROM research_runs WHERE id=?", (rid,)).fetchone())


def _hunted(tmp_path, monkeypatch, *, subsystem=None):
    """A planned run whose hunt marks every unit done and leaves one quote-verified
    finding by HUNTER, so the refute pass owes devstral's answer on it."""
    con, rid, src, _ = _planned(tmp_path, ["broken-authz-idor"])
    sub = subsystem or con.execute("SELECT subsystem FROM research_units "
                                   "WHERE research_id=? LIMIT 1", (rid,)).fetchone()[0]

    def hunt(con, rid, *, until, **k):
        con.execute("UPDATE research_units SET status='done' WHERE research_id=?", (rid,))
        if not con.execute("SELECT 1 FROM research_findings WHERE research_id=?",
                           (rid,)).fetchone():
            con.execute(
                "INSERT INTO research_findings (research_id,subsystem,lens,model,family,"
                "title,file,quote,quote_verified,refutations) "
                "VALUES (?,?,'broken-authz-idor',?,?,'t','routes/index.js','q',1,'[]')",
                (rid, sub, HUNTER, E.family(HUNTER)))
    monkeypatch.setattr(runner, "_hunt", hunt)
    monkeypatch.setattr(E, "model_provenance", lambda models: {})
    return con, rid, src


def _answers(monkeypatch, on_call=None):
    def fake_call(model, prompt, schema, *, num_ctx=0, num_predict=0):
        if on_call:
            on_call()
        return json.dumps({"verdict": "survives", "reason": "could not kill it"}), {}
    monkeypatch.setattr(E, "call", fake_call)


# ------------------------------------------------------- owed answers are work left

def test_a_deadline_that_cuts_the_refute_pass_short_leaves_the_run_stopped(
        tmp_path, monkeypatch):
    con, rid, src = _hunted(tmp_path, monkeypatch)
    _answers(monkeypatch)
    stats = runner.execute(con, rid, src, deadline=datetime.now() - timedelta(seconds=1),
                           progress=lambda *_: None)
    assert con.execute("SELECT COUNT(*) FROM research_units WHERE research_id=? "
                       "AND status!='done'", (rid,)).fetchone()[0] == 0
    assert stats["owed"] == 1
    assert _row(con, rid)["status"] == "stopped", "every unit hunted is not done"


def test_a_refute_pass_that_answers_everything_finishes_done(tmp_path, monkeypatch):
    con, rid, src = _hunted(tmp_path, monkeypatch)
    _answers(monkeypatch)
    stats = runner.execute(con, rid, src, progress=lambda *_: None)
    assert stats["owed"] == 0
    assert _row(con, rid)["status"] == "done"


def test_no_refute_owes_nothing(tmp_path, monkeypatch):
    con, rid, src = _hunted(tmp_path, monkeypatch)
    runner.execute(con, rid, src, refute=False, progress=lambda *_: None)
    assert _row(con, rid)["status"] == "done", "--no-refute asked for no answers"


def test_a_finding_the_pack_cannot_render_does_not_hold_the_run_open(tmp_path,
                                                                     monkeypatch):
    """The refute pass cannot ask about a subsystem the pack no longer has, so counting
    it would leave the run `stopped` for good and the nightly job resuming it nightly."""
    con, rid, src = _hunted(tmp_path, monkeypatch, subsystem="gone/after/a/repack")
    _answers(monkeypatch)
    stats = runner.execute(con, rid, src, progress=lambda *_: None)
    assert stats["owed"] == 0
    assert _row(con, rid)["status"] == "done"


# ------------------------------------------------------------- a stop is a stop

def test_sigterm_during_the_refute_pass_records_stopped(tmp_path, monkeypatch):
    con, rid, src = _hunted(tmp_path, monkeypatch)
    before = signal.getsignal(signal.SIGTERM)

    def term_self():
        # Only with the handler in place: the default action would end pytest itself.
        assert signal.getsignal(signal.SIGTERM) not in (signal.SIG_DFL, signal.SIG_IGN)
        os.kill(os.getpid(), signal.SIGTERM)
        time.sleep(1)                   # the handler raises before this returns
    _answers(monkeypatch, on_call=term_self)
    with pytest.raises(KeyboardInterrupt), _term_as_interrupt():
        runner.execute(con, rid, src, progress=lambda *_: None)
    row = _row(con, rid)
    assert row["status"] == "stopped" and row["pid"] is None and row["finished_at"]
    assert q.live_status(row)[0] == "stopped", "it read as died"
    assert not con.in_transaction
    assert signal.getsignal(signal.SIGTERM) is before, "the old handler is back"


def test_sigterm_to_a_worker_process_records_stopped(tmp_path):
    """The same across processes, the way the dashboard's Stop and the nightly script
    send it: a worker blocked in a model call, signalled from outside."""
    ready = tmp_path / "ready"
    script = textwrap.dedent(f"""
        import json, sys, time
        sys.path[:0] = [{str(Path(__file__).resolve().parents[1])!r},
                        {str(Path(__file__).resolve().parent)!r}]
        from pathlib import Path
        from quarry.cli import _term_as_interrupt
        from quarry.research import ensemble as E, runner
        from test_deep_intent import _planned
        con, rid, src, _ = _planned(Path({str(tmp_path)!r}), ["broken-authz-idor"])
        E.model_provenance = lambda models: {{}}
        def call(*a, **k):
            Path({str(ready)!r}).write_text(str(rid))
            time.sleep(60)
        E.call = call
        try:
            with _term_as_interrupt():
                runner.execute(con, rid, src, progress=lambda *_: None)
        except KeyboardInterrupt:
            sys.exit(130)
    """)
    proc = subprocess.Popen([sys.executable, "-c", script])
    try:
        for _ in range(300):
            if ready.exists() or proc.poll() is not None:
                break
            time.sleep(0.1)
        assert ready.exists(), "the worker never reached a model call"
        proc.send_signal(signal.SIGTERM)
        assert proc.wait(timeout=20) == 130
    finally:
        if proc.poll() is None:
            proc.kill()
    con = db.connect(tmp_path / "t.db")
    row = _row(con, int(ready.read_text()))
    assert row["status"] == "stopped" and row["pid"] is None


def test_quarry_deep_says_it_stopped_and_exits_130(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from typer.testing import CliRunner

    from quarry import cli
    from quarry.ingest import RunVolume
    monkeypatch.setenv("QUARRY_HOME", str(tmp_path / "home"))
    monkeypatch.setattr(RunVolume, "attach_existing",
                        classmethod(lambda cls, run_id, d: SimpleNamespace(src=tmp_path)))
    monkeypatch.setattr(runner, "hold", lambda *a, **k: None)

    def interrupted(*a, **k):
        raise KeyboardInterrupt
    monkeypatch.setattr(runner, "execute", interrupted)
    r = CliRunner().invoke(cli.app, ["deep", "3", "--resume", "1"], env={"COLUMNS": "200"})
    assert r.exit_code == 130
    assert "research run 1 is recorded as stopped" in r.output
    assert "quarry deep 3 --resume 1 continues it" in r.output
    assert "funnel pass" not in r.output, "nothing after the review ran"


def test_tx_rolls_back_on_an_interrupt(tmp_path):
    con = db.init(tmp_path / "t.db")
    con.execute("INSERT INTO runs (id,target,clone_url,status) VALUES (1,'o/r','x','done')")
    with pytest.raises(KeyboardInterrupt):
        with db.tx(con):
            con.execute("UPDATE runs SET status='failed' WHERE id=1")
            raise KeyboardInterrupt
    assert not con.in_transaction, "the transaction stayed open"
    assert con.execute("SELECT status FROM runs WHERE id=1").fetchone()[0] == "done"


# ------------------------------------------------------------ the dashboard's Resume

def _stopped_review(con, refutations):
    con.execute("INSERT INTO research_runs (id,run_id,status,models,lenses,profile) "
                "VALUES (1,1,'stopped','[\"a:1b\",\"c:2d\"]','[]','{}')")
    con.execute("INSERT INTO research_units (research_id,subsystem,weight,lens,model,"
                "phase,status) VALUES (1,'src',1.0,'x','a:1b','hunt','done')")
    con.execute("INSERT INTO research_findings (research_id,subsystem,lens,model,family,"
                "title,file,quote,quote_verified,refutations) "
                "VALUES (1,'src','x','a:1b','a','t','f.py','q',1,?)",
                (json.dumps(refutations),))
    con.commit()


def test_a_stopped_refute_pass_offers_resume(seeded):
    client, con = seeded
    _stopped_review(con, [])
    row = q.research_runs(con, rid=1)[0]
    assert row["resumable"] and row["owed"] == 1
    page = client.get("/research/1").text
    assert "/research/1/resume" in page
    assert "All 1 units ran; the refute pass still" in page
    assert "owes 1 answer." in page
    assert "0 of 1 units never ran" not in page


def test_a_stopped_review_with_nothing_owed_offers_no_resume(seeded):
    client, con = seeded
    _stopped_review(con, [{"model": "c:2d", "verdict": "survives", "reason": "r"}])
    row = q.research_runs(con, rid=1)[0]
    assert not row["resumable"] and row["owed"] == 0
    assert "/research/1/resume" not in client.get("/research/1").text
