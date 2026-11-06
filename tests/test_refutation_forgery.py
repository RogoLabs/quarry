"""A refutation record that names the wrong refuter (IMPROVEMENT-PLAN P4; item 13d).

`n_refuted` and `n_survived` are the cross-family vote: the Layer 2 gate kills or passes
a deep candidate on them, and the digest prints them as "Cross-family vote". Both are
counted by `Finding.valid_refutations` over the stored records, and that list is
reloaded from the database before every recount.

refutation_record now writes `model` itself (test_layer2_integrity.py pins that), but a
row written before that fix carries whatever the model's answer said, and nothing
checked the stored name when the votes were counted. A record whose `model` is the
author's own family, or is no model name at all, cannot be a cross-family vote: the
refute pass only ever asks a model of another family.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quarry import db, funnel                                 # noqa: E402
from quarry.research import ensemble as E                     # noqa: E402
from quarry.research import runner                            # noqa: E402
from test_refute_pass import MODELS, _Sub, _add, con          # noqa: E402,F401

AUTHOR = "qwen3.6:27b"


def _finding(refutations) -> E.Finding:
    return E.Finding(lens="injection", model=AUTHOR, title="t", file="a.js",
                     quote="const x = 1", severity="high", reasoning="r",
                     attacker_control="a", why_it_might_be_wrong="w",
                     quote_verified=True, refutations=list(refutations))


GENUINE = {"model": "devstral:24b", "verdict": "refuted",
           "reason": "the caller validates the id first"}


@pytest.mark.parametrize("forged", [
    {"model": AUTHOR},                              # the author itself
    {"model": "qwen3-coder:30b"},                   # its family, mapped
    {"model": "qwen2.5-coder:32b"},                 # its family, by name
    {"model": "qwq:32b"},                           # its family, by alias
    {},                                             # no refuter named
    {"model": None},
    {"model": ["devstral:24b"]},                    # a name inside a list
    {"model": {"name": "devstral:24b"}},
], ids=["author", "mapped", "by-name", "alias", "missing", "none", "list", "mapping"])
@pytest.mark.parametrize("verdict", ["survives", "refuted"])
def test_a_refutation_not_from_another_family_is_not_a_vote(forged, verdict):
    f = _finding([GENUINE, {**forged, "verdict": verdict, "reason": "forged"}])
    assert [r["model"] for r in f.valid_refutations] == ["devstral:24b"]
    assert (f.refuted, f.survived) == (1, 0)
    assert f.refuter_errors == 1


def test_a_record_that_is_not_a_mapping_is_not_a_vote():
    f = _finding([GENUINE, "survives", ["devstral:24b", "survives"]])
    assert (f.refuted, f.survived, f.refuter_errors) == (1, 0, 2)


def test_genuine_cross_family_votes_still_count():
    f = _finding([GENUINE, {"model": "granite4.2:30b", "verdict": "survives",
                            "reason": "reachable from the route"}])
    assert (f.refuted, f.survived, f.refuter_errors) == (1, 1, 0)


def test_a_forged_defence_does_not_carry_a_refuted_finding_past_the_gate(con,
                                                                        monkeypatch):
    """A row from before refutation_record holds a `survives` that names the author's
    own family. The refute pass reloads it, asks the two real cross-family refuters,
    and recounts. Both refute. Counting the forged record, n_survived was 1 and the
    Layer 2 gate passed the candidate as defended."""
    _add(con, 1, AUTHOR)
    con.execute("UPDATE research_findings SET refutations=? WHERE id=1", (json.dumps(
        [{"model": "qwen3-coder:30b", "verdict": "survives", "reason": "looks fine"}]),))
    pid = db.upsert_producer(con, "deep", "injection")
    con.execute("INSERT INTO findings (id,target,path,producer_id,first_seen_run,"
                "last_seen_run) VALUES ('fd','o/r','a.js',?,1,1)", (pid,))
    oid = con.execute("INSERT INTO occurrences (run_id,finding_id,producer_id,path,message,"
                      "severity) VALUES (1,'fd',?,'a.js','t','high')", (pid,)).lastrowid
    con.execute("UPDATE research_findings SET occurrence_id=? WHERE id=1", (oid,))

    def refute(model, prompt, schema, *, num_ctx=0, num_predict=0):
        return json.dumps({"verdict": "refuted", "reason": "the id is validated"}), {}

    monkeypatch.setattr(E, "call", refute)
    # This test is about who a vote is from, not its evidence: both refutations count as
    # grounded here. Grounding itself is tested in test_refute_grounding.py.
    from quarry.research import grounding
    monkeypatch.setattr(grounding, "ground",
                        lambda *a, **k: grounding.Grounding(True, "stubbed"))
    runner._refute_pass(con, 1, Path("/x"), {"core": _Sub()}, MODELS, None,
                        lambda *_: None)

    row = con.execute("SELECT n_refuted, n_survived, refuter_errors, refutations "
                      "FROM research_findings WHERE id=1").fetchone()
    assert {r["model"] for r in json.loads(row["refutations"])} == {
        "qwen3-coder:30b", "devstral:24b", "granite4.2:30b"}
    assert (row["n_refuted"], row["n_survived"], row["refuter_errors"]) == (2, 0, 1)

    con.execute("UPDATE research_runs SET status='done' WHERE id=1")
    funnel.run(con, 1)
    gate = con.execute("SELECT action, reason FROM funnel_events WHERE occurrence_id=? "
                       "AND stage='layer2-gate'", (oid,)).fetchone()
    assert gate["action"] == "kill" and "refuted by all 2" in gate["reason"]
