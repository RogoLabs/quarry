"""The refute pass asks only what can change an outcome, and says how far it has got.

On 2026-11-07 a VulnLookup day run sat in its refute pass for hours. Its log printed
"granite4.2:30b: refuting 737 finding(s)" and nothing after, the dashboard's unit count
stood still at 724, and it looked hung. It was answering about one finding a minute,
and 411 of the 497 answers granite still owed were on findings whose quote did not
verify, which the funnel's Layer 2 gate kills without reading a refutation.

No model and no network: E.call is monkeypatched.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quarry import db                                        # noqa: E402
from quarry.research import ensemble as E                    # noqa: E402
from quarry.research import runner                           # noqa: E402
from quarry.web import queries as q                          # noqa: E402

MODELS = ["qwen3.6:27b", "devstral:24b", "granite4.2:30b"]   # three distinct families


class _Sub:
    def render(self, tag: str = "") -> str:
        return "===== REPOSITORY =====\nconst x = 1\n"


@pytest.fixture
def con(tmp_path):
    c = db.init(tmp_path / "t.db")
    c.execute("INSERT INTO runs (id,target,clone_url,status) VALUES (1,'o/r','x','done')")
    c.execute("INSERT INTO research_runs (id,run_id,status,models) VALUES (1,1,'running',?)",
              (json.dumps(MODELS),))
    return c


def _add(con, fid: int, model: str, *, verified: int = 1, refutations: str = "[]") -> None:
    con.execute(
        """INSERT INTO research_findings
           (id, research_id, subsystem, lens, model, family, title, file, quote,
            quote_verified, severity, reasoning, attacker_control, self_critique,
            refutations)
           VALUES (?,1,'core','injection',?,?,?,'a.js','const x = 1',?,
                   'high','r','a','w',?)""",
        (fid, model, E.family(model), f"finding {fid}", verified, refutations))


def _survives(monkeypatch) -> list[str]:
    seen: list[str] = []

    def fake_call(model, prompt, schema, *, num_ctx=0, num_predict=0):
        seen.append(model)
        return json.dumps({"verdict": "survives", "reason": "could not kill it"}), {}

    monkeypatch.setattr(E, "call", fake_call)
    return seen


def test_a_finding_whose_quote_did_not_verify_is_not_refuted(con, monkeypatch):
    _add(con, 1, "qwen3.6:27b", verified=1)
    _add(con, 2, "qwen3.6:27b", verified=0)
    seen = _survives(monkeypatch)

    runner._refute_pass(con, 1, Path("/x"), {"core": _Sub()}, MODELS, None, lambda *_: None)

    assert sorted(seen) == ["devstral:24b", "granite4.2:30b"]     # finding 1 only
    refs = {r["id"]: r["refutations"] for r in
            con.execute("SELECT id, refutations FROM research_findings")}
    assert refs[2] == "[]"
    assert len(json.loads(refs[1])) == 2


def test_the_pass_reports_progress_every_25_answers(con, monkeypatch):
    for fid in range(1, 61):
        _add(con, fid, "qwen3.6:27b")
    _survives(monkeypatch)
    lines: list[str] = []

    runner._refute_pass(con, 1, Path("/x"), {"core": _Sub()}, MODELS, None, lines.append)

    for m in ("devstral:24b", "granite4.2:30b"):
        ticks = [x.strip() for x in lines if x.strip().startswith(f"{m}: ")
                 and "answered" in x]
        assert [t.split(",")[0] for t in ticks] == [f"{m}: 25/60 answered",
                                                     f"{m}: 50/60 answered"], lines


def test_refute_status_counts_what_each_refuter_answered_and_owes(con):
    err = json.dumps([{"model": "granite4.2:30b", "verdict": "error", "reason": "timeout"}])
    done = json.dumps([{"model": "devstral:24b", "verdict": "refuted", "reason": "x"}])
    _add(con, 1, "qwen3.6:27b", refutations=done)      # devstral answered, granite owes
    _add(con, 2, "qwen3.6:27b", refutations=err)       # an error is not an answer
    _add(con, 3, "devstral:24b")                       # devstral never refutes its own
    _add(con, 4, "qwen3.6:27b", verified=0, refutations=done)   # never asked: unverified

    got = {x["model"]: (x["answered"], x["owed"]) for x in q.refute_status(con, 1, MODELS)}

    assert got["devstral:24b"] == (1, 1)               # findings 1 and 2
    assert got["granite4.2:30b"] == (0, 3)             # findings 1, 2 and 3
    assert got["qwen3.6:27b"] == (0, 1)                # finding 3
