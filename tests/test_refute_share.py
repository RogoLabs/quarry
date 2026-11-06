"""IMPROVEMENT-PLAN item 28: refutation gets a share of every deadline-bound night.

The refute pass used to run only after the hunt loop, and the hunt loop ran to the
deadline while units remained, so research 4 (run 7) hunted 125 of 1,551 units on its
first night and refuted none of its 162 findings.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from quarry.research import ensemble as E, runner          # noqa: E402
from test_deep_intent import _planned                       # noqa: E402


def _record(monkeypatch):
    calls: list[tuple[str, datetime | None]] = []
    monkeypatch.setattr(runner, "_hunt",
                        lambda con, rid, *, until, **k: calls.append(("hunt", until)))
    monkeypatch.setattr(runner, "_refute_pass",
                        lambda con, rid, src, subs, models, until, progress, **k:
                        calls.append(("refute", until)) or {})
    monkeypatch.setattr(E, "model_provenance", lambda models: {})
    return calls


def test_a_night_refutes_first_hunts_to_its_share_then_refutes_again(tmp_path, monkeypatch):
    con, rid, src, _ = _planned(tmp_path, ["broken-authz-idor"])
    calls = _record(monkeypatch)
    deadline = datetime.now() + timedelta(hours=10)
    runner.execute(con, rid, src, deadline=deadline, progress=lambda *_: None)
    assert [k for k, _ in calls] == ["refute", "hunt", "refute", "hunt"]
    cutoff = calls[1][1]
    share = (deadline - cutoff).total_seconds() / (10 * 3600)
    assert abs(share - runner.REFUTE_SHARE) < 0.01
    assert calls[0][1] == calls[2][1] == calls[3][1] == deadline


def test_without_a_deadline_the_order_is_unchanged(tmp_path, monkeypatch):
    con, rid, src, _ = _planned(tmp_path, ["broken-authz-idor"])
    calls = _record(monkeypatch)
    runner.execute(con, rid, src, progress=lambda *_: None)
    assert calls == [("hunt", None), ("refute", None)]


def test_no_refute_means_no_share(tmp_path, monkeypatch):
    con, rid, src, _ = _planned(tmp_path, ["broken-authz-idor"])
    calls = _record(monkeypatch)
    deadline = datetime.now() + timedelta(hours=1)
    runner.execute(con, rid, src, deadline=deadline, refute=False, progress=lambda *_: None)
    assert calls == [("hunt", deadline)], "the whole night hunts, and nothing refutes"


def test_a_unit_that_fails_is_not_retried_the_same_night(tmp_path, monkeypatch):
    """The second hunt of a night must not re-run units that errored in the first."""
    con, rid, src, _ = _planned(tmp_path, ["broken-authz-idor"])
    hunts: list[str] = []

    def fake_call(model, prompt, schema, *, num_ctx=0, num_predict=0):
        if "YOUR LENS" in prompt:
            hunts.append(model)
            raise RuntimeError("done_reason=length")
        return json.dumps({"verdict": "survives", "reason": "r"}), {}
    monkeypatch.setattr(E, "call", fake_call)
    monkeypatch.setattr(E, "model_provenance", lambda models: {})
    units = con.execute("SELECT COUNT(*) FROM research_units WHERE research_id=?",
                        (rid,)).fetchone()[0]
    stats = runner.execute(con, rid, src, deadline=datetime.now() + timedelta(hours=1),
                           progress=lambda *_: None)
    assert len(hunts) == units, "each unit was asked once"
    assert stats["errors"] == units and stats["skipped_deadline"] == 0
