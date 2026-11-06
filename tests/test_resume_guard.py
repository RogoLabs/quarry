"""IMPROVEMENT-PLAN item 26: two workers must not resume the same deep review.

`quarry deep --resume` started on a research run without asking whether a worker
already held it, so the 21:00 launchd job and a review resumed by hand could work the
same units side by side. `runner.hold` now checks with the dashboard's own liveness
rules and claims the run in the same transaction.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from quarry.research import runner                       # noqa: E402
from quarry.web import queries as q                      # noqa: E402
from test_web import (_post, _utc_now, bystander, seeded,  # noqa: E402,F401
                      worker)
from test_web_dashboard import _row, _stopped_research   # noqa: E402


def _set(con, **cols):
    sets = ", ".join(f"{k}=?" for k in cols)
    con.execute(f"UPDATE research_runs SET {sets} WHERE id=1", tuple(cols.values()))
    con.commit()


# ------------------------------------------------------------ the status rule

@pytest.mark.parametrize("status", q.LIVE_STATUSES)
def test_a_held_run_is_refused_and_left_alone(seeded, monkeypatch, status):
    _, con = seeded
    _stopped_research(con)
    monkeypatch.setattr(q, "live_status", lambda row: (status, "reason"))
    with pytest.raises(runner.ResumeRefused, match=f"is {status} \\(reason\\)"):
        runner.hold(con, 1, 1)
    assert _row(con)["status"] == "stopped" and _row(con)["pid"] is None


@pytest.mark.parametrize("status", ["stopped", "done", "failed", "died", "stalled",
                                    "unknown"])
def test_a_run_nobody_holds_is_taken(seeded, monkeypatch, status):
    _, con = seeded
    _stopped_research(con)
    monkeypatch.setattr(q, "live_status", lambda row: (status, "reason"))
    runner.hold(con, 1, 1)
    row = _row(con)
    assert row["status"] == "running" and row["pid"] == os.getpid()


# ------------------------------------------------------- real processes, real ps

def test_a_live_worker_blocks_a_resume(seeded, worker):
    _, con = seeded
    _stopped_research(con)
    _set(con, status="running", pid=worker.pid, heartbeat=_utc_now())
    with pytest.raises(runner.ResumeRefused, match=f"running \\(pid {worker.pid} alive\\)"):
        runner.hold(con, 1, 1)
    assert _row(con)["pid"] == worker.pid, "the live worker keeps the run"


def test_a_dead_worker_does_not_block(seeded):
    """A worker killed mid-run never writes `stopped`; its gone pid reads as died."""
    _, con = seeded
    _stopped_research(con)
    _set(con, status="running", pid=999_999_999, heartbeat=_utc_now())
    runner.hold(con, 1, 1)
    assert _row(con)["pid"] == os.getpid()


def test_a_recycled_pid_does_not_block(seeded, bystander):
    _, con = seeded
    _stopped_research(con)
    _set(con, status="running", pid=bystander.pid, heartbeat=_utc_now())
    runner.hold(con, 1, 1)
    assert _row(con)["pid"] == os.getpid()


def test_the_second_of_two_resumes_is_refused(seeded, worker):
    """The first resume claims the run; a second one then reads it as running. The
    first claimant here is this test process, which `ps` does not show as a worker, so
    the worker fixture (started earlier, like the real one) stands in for it."""
    _, con = seeded
    _stopped_research(con)
    runner.hold(con, 1, 1)
    _set(con, pid=worker.pid)
    with pytest.raises(runner.ResumeRefused, match="is running"):
        runner.hold(con, 1, 1)


# ----------------------------------------------------------- the dashboard claim

def test_only_the_dashboards_worker_fills_its_claim(seeded):
    _, con = seeded
    _stopped_research(con)
    _set(con, status=q.RESUMING, pid=None, heartbeat=_utc_now())
    with pytest.raises(runner.ResumeRefused, match="is starting"):
        runner.hold(con, 1, 1)
    runner.hold(con, 1, 1, dashboard_claim=True)
    row = _row(con)
    assert row["status"] == "running" and row["pid"] == os.getpid()


def test_the_marker_does_not_take_a_claim_another_worker_is_filling(seeded, worker):
    """The dashboard recorded a different worker's pid: that one fills the claim."""
    _, con = seeded
    _stopped_research(con)
    _set(con, status=q.RESUMING, pid=worker.pid, heartbeat=_utc_now())
    with pytest.raises(runner.ResumeRefused, match="is starting"):
        runner.hold(con, 1, 1, dashboard_claim=True)


def test_the_dashboard_marks_the_worker_it_spawns(seeded, monkeypatch, worker):
    import subprocess
    client, con = seeded
    _stopped_research(con)
    real, seen = subprocess.Popen, []

    def popen(argv, *a, **k):
        if "quarry.cli" not in argv:
            return real(argv, *a, **k)
        seen.append(k.get("env") or {})
        return worker
    monkeypatch.setattr(subprocess, "Popen", popen)
    assert _post(client, "/research/1/resume").status_code == 303
    assert seen[0][q.RESUME_CLAIM_ENV] == "1"
    assert seen[0].get("PATH") == os.environ.get("PATH"), \
        "the marker is added to the environment, not a replacement for it"


# --------------------------------------------------------------- the wrong run

def test_a_research_run_of_another_ingest_run_is_refused(seeded):
    """`deep 5 --resume 1` would check run 1's units against run 5's source tree."""
    _, con = seeded
    _stopped_research(con)
    with pytest.raises(runner.ResumeRefused, match="belongs to run 1, not run 5"):
        runner.hold(con, 1, 5)
    assert _row(con)["status"] == "stopped"


def test_a_missing_research_run_is_refused(seeded):
    _, con = seeded
    with pytest.raises(runner.ResumeRefused, match="no research run 9"):
        runner.hold(con, 9, 1)


# ------------------------------------------------------------------- the CLI

class _Reached(Exception):
    pass


def _cli(monkeypatch, *argv, env=None):
    from typer.testing import CliRunner
    from quarry import cli
    from quarry.ingest import RunVolume
    monkeypatch.setattr(RunVolume, "attach_existing", classmethod(
        lambda cls, run_id, images_dir: SimpleNamespace(src=Path("/nonexistent"))))

    def execute(*a, **k):
        raise _Reached
    monkeypatch.setattr(runner, "execute", execute)
    return CliRunner().invoke(cli.app, list(argv), env={"COLUMNS": "200", **(env or {})})


def test_the_cli_refuses_before_any_work(seeded, monkeypatch, worker):
    _, con = seeded
    _stopped_research(con)
    _set(con, status="running", pid=worker.pid, heartbeat=_utc_now())
    r = _cli(monkeypatch, "deep", "1", "--resume", "1")
    assert r.exit_code == 1, r.output
    assert "refusing to resume" in r.output and f"pid {worker.pid}" in r.output
    assert not isinstance(r.exception, _Reached), "the review started anyway"


def test_the_cli_takes_a_free_run_and_reads_the_dashboards_marker(seeded, monkeypatch):
    _, con = seeded
    _stopped_research(con)
    _set(con, status=q.RESUMING, pid=None, heartbeat=_utc_now())
    r = _cli(monkeypatch, "deep", "1", "--resume", "1")
    assert r.exit_code == 1 and "is starting" in r.output
    r = _cli(monkeypatch, "deep", "1", "--resume", "1", env={q.RESUME_CLAIM_ENV: "1"})
    assert isinstance(r.exception, _Reached), r.output
    assert _row(con)["status"] == "running"


# ----------------------------------------------- two real processes, one database

#: Run in two child processes by the race test. Each poses as a worker to `ps` (its
#: command line ends `quarry.cli deep 1`, which a script path ignores), opens its own
#: connection to the test database, and then, round after round, waits on the round's
#: barrier file and calls `runner.hold` the moment it appears. It stays alive between
#: rounds: a claimant that exited would read as `died`, and the other process would
#: then rightly take the run, which is not the race being tested.
_RACER = r"""
import json, os, sys, time
from pathlib import Path
sys.path.insert(0, os.environ["RACE_ROOT"])
import quarry
from quarry import db
from quarry.research import runner

d, me = Path(os.environ["RACE_DIR"]), os.environ["RACE_NAME"]
rounds, give_up = int(os.environ["RACE_ROUNDS"]), time.time() + 120


def wait_for(p):
    while not p.exists():
        if (d / "stop").exists():          # the test ended early, having failed
            sys.exit(0)
        if time.time() > give_up:
            sys.exit(f"{me}: gave up waiting for {p.name}")


def put(name, text):                       # whole or absent, never half written
    (d / f"{name}.tmp").write_text(text)
    os.replace(d / f"{name}.tmp", d / name)


con = db.connect(Path(os.environ["RACE_DB"]))
put(f"ready-{me}", quarry.__file__)
for i in range(rounds):
    wait_for(d / f"go-{i}")
    t0 = time.time()
    try:
        runner.hold(con, 1, 1)
        out = {"claimed": True, "why": ""}
    except runner.ResumeRefused as e:
        out = {"claimed": False, "why": str(e)}
    out.update(t0=t0, t1=time.time(), pid=os.getpid())
    put(f"result-{i}-{me}.json", json.dumps(out))
wait_for(d / "stop")
"""

RACE_ROUNDS = 30


def test_two_processes_resuming_at_once_get_one_claim(seeded, tmp_path):
    """P3 item 7 and item 26: the claim is one `BEGIN IMMEDIATE` transaction, so two
    resumes started at the same moment are serialised and the second reads the first
    as running. The tests above take one claim after the other; here two real
    processes on one SQLite file call `runner.hold` together, released by one barrier
    file, for RACE_ROUNDS rounds. Every round must end with exactly one claim, held by
    the process the database names, and the other refused because that process holds
    the run."""
    import json
    import subprocess
    import time
    from quarry import config
    _, con = seeded
    _stopped_research(con)
    root = Path(__file__).resolve().parents[1]
    script = tmp_path / "racer.py"
    script.write_text(_RACER)
    gate = tmp_path / "gate"
    gate.mkdir()
    env = {**os.environ, "RACE_ROOT": str(root), "RACE_DIR": str(gate),
           "RACE_DB": str(config.paths().db), "RACE_ROUNDS": str(RACE_ROUNDS)}
    env.pop(q.RESUME_CLAIM_ENV, None)
    procs = {name: subprocess.Popen(
                 [sys.executable, str(script), "quarry.cli", "deep", "1"],
                 env={**env, "RACE_NAME": name}, stderr=subprocess.PIPE, text=True)
             for name in ("a", "b")}

    def wait_for(paths, what):
        deadline = time.time() + 60
        while not all(p.exists() for p in paths):
            dead = {n: p.poll() for n, p in procs.items() if p.poll() is not None}
            if dead or time.time() > deadline:
                errs = {n: procs[n].stderr.read() for n in dead}
                pytest.fail(f"waiting for {what}: exited {dead}, stderr {errs}")
            time.sleep(0.002)

    overlapped = 0
    try:
        wait_for([gate / "ready-a", gate / "ready-b"], "both racers to start")
        for n in ("a", "b"):
            # A script's own directory comes first on sys.path, so this proves the
            # racers run this checkout's quarry, not an installed copy.
            assert Path((gate / f"ready-{n}").read_text()).is_relative_to(root)
        for i in range(RACE_ROUNDS):
            con.execute("UPDATE research_runs SET status='stopped', pid=NULL, host=NULL, "
                        "heartbeat=NULL WHERE id=1")
            (gate / f"go-{i}").touch()
            wait_for([gate / f"result-{i}-a.json", gate / f"result-{i}-b.json"],
                     f"round {i}")
            res = {n: json.loads((gate / f"result-{i}-{n}.json").read_text())
                   for n in ("a", "b")}
            claimed = [n for n, r in res.items() if r["claimed"]]
            assert len(claimed) == 1, f"round {i}: {res}"
            won, lost = res[claimed[0]], res[({"a", "b"} - set(claimed)).pop()]
            assert _row(con)["pid"] == won["pid"] == procs[claimed[0]].pid, (i, res)
            assert _row(con)["status"] == "running"
            assert f"pid {won['pid']}" in lost["why"], (i, res)
            assert "is running" in lost["why"] or "is unverified" in lost["why"], (i, res)
            # Both were inside hold() at once: the loser entered before the winner
            # left, so its wait was on the lock, not on the order of the barrier.
            overlapped += lost["t0"] < won["t1"]
    finally:
        (gate / "stop").touch()
        for p in procs.values():
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()
    assert all(p.returncode == 0 for p in procs.values()), \
        {n: p.stderr.read() for n, p in procs.items()}
    # Without overlap this would only re-run the sequential test above. The barrier
    # releases both within a poll of each other; demand that it did so in most rounds.
    assert overlapped >= RACE_ROUNDS // 2, f"{overlapped} of {RACE_ROUNDS} rounds overlapped"
