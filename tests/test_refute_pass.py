"""The cross-family refute pass, which gates what a deep run reports.

Two properties, each a defect that reached a live run before it was caught:

  * the pass refuted finding-by-finding, calling the two other-family models in turn,
    so Ollama evicted and reloaded a 30B model on nearly every call. On cve-services
    that crawled at minutes per finding and would have taken days. The pass must group
    its calls by refuter model so each one loads once.
  * a refuter must only ever be a model of a DIFFERENT family, and a finding already
    answered by a model must not be asked again, so an interrupted pass resumes at the
    (finding, model) pair instead of re-refuting.

No model and no network: E.call is monkeypatched to record the order it is called in.
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

MODELS = ["qwen3.6:27b", "devstral:24b", "granite4.2:30b"]   # three distinct families


class _Sub:
    """A subsystem stand-in: the refute pass only needs render() for the prompt."""
    def render(self, tag: str = "") -> str:
        return "===== REPOSITORY =====\nconst x = 1\n"


@pytest.fixture
def con(tmp_path):
    c = db.init(tmp_path / "t.db")
    c.execute("INSERT INTO runs (id,target,clone_url,status) VALUES (1,'o/r','x','done')")
    c.execute("INSERT INTO research_runs (id,run_id,status,models) VALUES (1,1,'running',?)",
              (json.dumps(MODELS),))
    return c


def _add(con, fid: int, model: str) -> None:
    """A finding authored by `model`; its family is recorded exactly as the producer
    records it, so the cross-family filter is tested against real family names."""
    con.execute(
        """INSERT INTO research_findings
           (id, research_id, subsystem, lens, model, family, title, file, quote,
            quote_verified, severity, reasoning, attacker_control, self_critique)
           VALUES (?,1,'core','injection',?,?,?,'a.js','const x = 1',1,
                   'high','r','a','w')""",
        (fid, model, E.family(model), f"finding {fid}"))


def _record_calls(monkeypatch) -> list[str]:
    """Replace the model call with one that records the model and returns `survives`."""
    seen: list[str] = []

    def fake_call(model, prompt, schema, *, num_ctx=0, num_predict=0):
        seen.append(model)
        return json.dumps({"verdict": "survives", "reason": "could not kill it"}), {}

    monkeypatch.setattr(E, "call", fake_call)
    return seen


def test_refute_pass_groups_calls_by_model_not_by_finding(con, monkeypatch):
    # two findings from each of the three families: each is refuted by the two OTHER models.
    for fid, m in enumerate([m for m in MODELS for _ in range(2)]):
        _add(con, fid + 1, m)
    seen = _record_calls(monkeypatch)

    runner._refute_pass(con, 1, Path("/x"), {"core": _Sub()}, MODELS, None, lambda *_: None)

    # 6 findings x 2 cross-family refuters each.
    assert len(seen) == 12
    # The point of the fix: each model's calls are contiguous, so a 30B model loads once.
    # Finding-by-finding ordering would switch models ~11 times here; grouped is 2.
    switches = sum(1 for a, b in zip(seen, seen[1:]) if a != b)
    assert switches == len(set(seen)) - 1 == 2, seen


def test_refuters_are_cross_family_only(con, monkeypatch):
    for fid, m in enumerate(MODELS):
        _add(con, fid + 1, m)
    _record_calls(monkeypatch)

    runner._refute_pass(con, 1, Path("/x"), {"core": _Sub()}, MODELS, None, lambda *_: None)

    for r in con.execute("SELECT family, refutations FROM research_findings"):
        refuters = {x["model"] for x in json.loads(r["refutations"])}
        same_family = {m for m in MODELS if E.family(m) == r["family"]}
        assert refuters == set(MODELS) - same_family
        assert not (refuters & same_family)      # never refuted by its own family


def test_refute_pass_resumes_and_does_not_re_ask(con, monkeypatch):
    _add(con, 1, "qwen3.6:27b")
    # devstral has already answered this finding; the pass must not ask it again.
    con.execute("UPDATE research_findings SET refutations=? WHERE id=1",
                (json.dumps([{"model": "devstral:24b", "verdict": "refuted",
                              "reason": "already done"}]),))
    seen = _record_calls(monkeypatch)

    runner._refute_pass(con, 1, Path("/x"), {"core": _Sub()}, MODELS, None, lambda *_: None)

    # only the missing cross-family refuter (granite) runs; devstral is not re-asked.
    assert seen == ["granite4.2:30b"]
    refs = json.loads(con.execute("SELECT refutations FROM research_findings WHERE id=1")
                      .fetchone()["refutations"])
    assert {x["model"] for x in refs} == {"devstral:24b", "granite4.2:30b"}


def test_second_full_pass_is_a_no_op(con, monkeypatch):
    _add(con, 1, "qwen3.6:27b")
    _record_calls(monkeypatch)
    runner._refute_pass(con, 1, Path("/x"), {"core": _Sub()}, MODELS, None, lambda *_: None)

    seen = _record_calls(monkeypatch)          # fresh recorder
    runner._refute_pass(con, 1, Path("/x"), {"core": _Sub()}, MODELS, None, lambda *_: None)
    assert seen == []                          # everything already refuted


def test_a_refuter_that_errored_is_asked_again_on_resume(con, monkeypatch):
    """IMPROVEMENT-PLAN item 5. 14 candidates on runs 1 and 2 had every refuter error;
    the pass treated an error record as an answer and never asked again, so they sat
    deferred at the Layer 2 gate for good."""
    _add(con, 1, "qwen3.6:27b")
    con.execute("UPDATE research_findings SET refutations=?, refuter_errors=1 WHERE id=1",
                (json.dumps([{"model": "devstral:24b", "verdict": "error",
                              "reason": "timed out"},
                             {"model": "granite4.2:30b", "verdict": "refuted",
                              "reason": "guarded upstream"}]),))
    seen = _record_calls(monkeypatch)

    runner._refute_pass(con, 1, Path("/x"), {"core": _Sub()}, MODELS, None, lambda *_: None)

    assert seen == ["devstral:24b"]                # granite answered; only devstral retried
    row = con.execute("SELECT * FROM research_findings WHERE id=1").fetchone()
    recs = json.loads(row["refutations"])
    dev = [x for x in recs if x["model"] == "devstral:24b"]
    assert len(dev) == 1 and dev[0]["verdict"] == "survives"
    assert dev[0]["earlier_errors"] == ["timed out"]
    assert (row["n_survived"], row["n_refuted"], row["refuter_errors"]) == (1, 1, 0)


def test_an_error_record_counts_as_a_refuter_error_not_a_vote():
    f = E.Finding(lens="authz", model="qwen3.6:27b", title="t", file="a.js", quote="q",
                  severity="high", reasoning="r", attacker_control="a",
                  why_it_might_be_wrong="w", quote_verified=True,
                  refutations=[{"model": "devstral:24b", "verdict": "error", "reason": "x"},
                               {"model": "granite4.2:30b", "verdict": "error", "reason": "y"}])
    assert (f.refuted, f.survived, f.refuter_errors) == (0, 0, 2)
