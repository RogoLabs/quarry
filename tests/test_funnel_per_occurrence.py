"""The per-occurrence funnel (IMPROVEMENT-PLAN P4; item 5).

Each occurrence goes through the funnel once. Occurrences that arrive after a pass (a
re-scan, deep review) are funnelled by the next pass on their own, and the ones already
funnelled are context for them, never funnelled again. test_funnel.py pins a two-pass
case and the Layer 2 gate. These run several passes with arrivals between them and
check the ledger afterwards: which pass wrote each event, that no stage acts on an
occurrence twice, what a fresh row may take from a funnelled one (a merge target, a
cluster, a novelty count) and what it may not (a new event on the old row, a merge into
a dead one).
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quarry import db, funnel                                    # noqa: E402
from test_funnel import _deep, _events, add, con                 # noqa: E402,F401


def _ledger(c) -> dict[int, list[tuple[int, str, str]]]:
    """Every non-operator event, per occurrence, as (event id, stage, action)."""
    out: dict[int, list] = defaultdict(list)
    for r in c.execute("SELECT id, occurrence_id, stage, action FROM funnel_events "
                       "WHERE stage != 'operator' ORDER BY id"):
        out[r["occurrence_id"]].append((r["id"], r["stage"], r["action"]))
    return out


def _live(c) -> set[int]:
    return {r["id"] for r in c.execute("SELECT id FROM live_occurrences")}


def _score(c, oid) -> float:
    return c.execute("SELECT score FROM occurrence_rank WHERE occurrence_id=?",
                     (oid,)).fetchone()["score"]


def test_each_occurrence_is_funnelled_once_across_passes(con):
    """Four passes, with occurrences arriving before each of the first three. An
    occurrence's events are all written by the pass it entered (a deep candidate that
    was deferred and then revived is the one documented exception), no stage acts on
    an occurrence twice, and a pass with nothing fresh writes nothing."""
    entered: dict[int, int] = {}                # occurrence id -> pass it entered
    after: list[dict] = []                      # ledger after each pass

    def run(n: int, *oids: int) -> funnel.FunnelResult:
        for o in oids:
            entered[o] = n
        res = funnel.run(con, 1)
        after.append(_ledger(con))
        return res

    a_sast = add(con, "bandit", "B113", "src/net.py", 42)
    a_test = add(con, "bandit", "B101", "tests/test_a.py", 5)
    a_sca = add(con, "osv-scanner", "GHSA-x", "poetry.lock", 10)
    r1 = run(1, a_sast, a_test, a_sca)

    b_dup = add(con, "bandit", "B113", "src/net.py", 42)            # same as a_sast
    b_cluster = add(con, "opengrep", "javascript.express.xss", "src/net.py", 44)
    b_novel = add(con, "bandit", "B113", "src/other.py", 7)          # producer's 2nd
    b_deep, _ = _deep(con)                                           # no refuter yet
    r2 = run(2, b_dup, b_cluster, b_novel, b_deep)

    c_new = add(con, "bandit", "B105", "src/new.py", 3)
    c_dead_dup = add(con, "bandit", "B101", "tests/test_a.py", 5)   # same as a_test
    con.execute("UPDATE research_findings SET n_survived=1 WHERE occurrence_id=?",
                (b_deep,))
    r3 = run(3, c_new, c_dead_dup)
    r4 = run(4)

    assert [r.started_with for r in (r1, r2, r3, r4)] == [3, 4, 3, 0]
    assert after[3] == after[2], "a pass with nothing fresh wrote events"
    passes = json.loads(con.execute("SELECT manifest FROM runs WHERE id=1")
                        .fetchone()[0])["funnel"]["passes"]
    assert len(passes) == 4

    final = after[-1]
    assert set(final) == set(entered)
    for oid, n in entered.items():
        assert final[oid], f"occurrence {oid} entered pass {n} and left no event"
        # Nothing written for it before the pass it entered, nothing after.
        if n > 1:
            assert oid not in after[n - 2], f"occurrence {oid} funnelled before it arrived"
        if oid != b_deep:
            assert after[n - 1][oid] == final[oid], f"occurrence {oid} funnelled again"
    # The exception: deferred in pass 2 for want of a refuter, revived in pass 3 once
    # one answered, and left alone after that.
    assert [(s, a) for _, s, a in after[1][b_deep]] == [("layer2-gate", "defer")]
    assert after[2][b_deep][:1] == after[1][b_deep]
    assert after[3][b_deep] == after[2][b_deep]
    for oid, events in final.items():
        stages = [s for _, s, _ in events]
        repeated = {s for s in stages if stages.count(s) > 1}
        if oid == b_deep:
            assert [(s, a) for _, s, a in events if s == "layer2-gate"] == [
                ("layer2-gate", "defer"), ("layer2-gate", "resurrect")]
            repeated -= {"layer2-gate"}
        assert not repeated, (oid, repeated)

    # What the fresh rows took from the funnelled ones.
    merge = con.execute("SELECT merged_into FROM funnel_events WHERE occurrence_id=? "
                        "AND stage='exact-dedup'", (b_dup,)).fetchone()
    assert merge["merged_into"] == a_sast
    assert ("cross-tool-cluster", "pass") in _events(con, b_cluster)
    assert ("independence-corroboration", "boost") in _events(con, b_cluster)
    assert not [e for e in _events(con, a_sast) if e[0] == "independence-corroboration"]
    issue = {r["issue_id"] for r in con.execute(
        "SELECT f.issue_id FROM findings f JOIN occurrences o ON o.finding_id=f.id "
        "WHERE o.id IN (?,?)", (a_sast, b_cluster))}
    assert len(issue) == 1 and None not in issue
    novelty = {o: con.execute("SELECT score_delta FROM funnel_events WHERE "
                              "occurrence_id=? AND stage='novelty-rank'", (o,)).fetchone()
               for o in (a_sast, b_novel)}
    assert novelty[a_sast]["score_delta"] == 12.0      # first of its producer, pass 1
    assert novelty[b_novel]["score_delta"] == 6.0      # counted a_sast, did not touch it
    # A duplicate of a killed occurrence is not merged into the dead row; it is
    # funnelled on its own (and its test path kills it on its own).
    assert _events(con, c_dead_dup) == [("path-class", "kill")]
    assert ("rule-precision-prior", "boost") in _events(con, b_deep)
    assert {a_sast, b_cluster, b_novel, c_new, b_deep, a_sca} <= _live(con)


def test_a_late_hit_clusters_with_a_funnelled_one_without_rescoring_it(con):
    old = add(con, "bandit", "B307", "src/app.py", 10)
    funnel.run(con, 1)
    before, score = _events(con, old), _score(con, old)

    new = add(con, "opengrep", "javascript.express.xss", "src/app.py", 12)
    funnel.run(con, 1)

    assert _events(con, old) == before and _score(con, old) == score
    assert ("cross-tool-cluster", "pass") in _events(con, new)
    issues = {r["issue_id"] for r in con.execute(
        "SELECT issue_id FROM findings WHERE id IN (SELECT finding_id FROM occurrences)")}
    assert len(issues) == 1 and None not in issues
    members = con.execute("SELECT COUNT(*) FROM issue_members").fetchone()[0]
    assert members == 2


def test_an_operator_resurrection_holds_through_a_pass_with_fresh_rows(con):
    """test_funnel.py covers a second pass with nothing fresh. With fresh rows in it,
    the resurrected row is still context, not fresh: its path-class kill is not written
    again over the operator's resurrect. A fresh duplicate of it is decided on its own,
    and path-class (stage 3) reaches it before exact-dedup (stage 5) would merge it."""
    oid = add(con, "bandit", "B101", "tests/test_x.py", 5)
    funnel.run(con, 1)
    db.funnel(con, 1, occurrence_id=oid, stage="operator", action="resurrect",
              reason="production code", deterministic=False, actor="jerry")
    before = _events(con, oid)

    dup = add(con, "bandit", "B101", "tests/test_x.py", 5)
    other = add(con, "bandit", "B113", "src/net.py", 42)
    res = funnel.run(con, 1)

    assert res.started_with == 2
    assert _events(con, oid) == before
    assert oid in _live(con) and other in _live(con)
    assert _events(con, dup) == [("path-class", "kill")] and dup not in _live(con)


def test_a_late_duplicate_of_a_dead_occurrence_is_funnelled_on_its_own(con):
    """A row killed for having no evidence window is not a merge target. The same
    finding arriving later with a window goes through the funnel on its own evidence."""
    dead = add(con, "checkov", "CKV_DOCKER_2", "docker/Dockerfile", 1, blob=False)
    funnel.run(con, 1)
    assert _events(con, dead) == [("quote-verify", "kill")]

    again = add(con, "checkov", "CKV_DOCKER_2", "docker/Dockerfile", 1, blob=True)
    funnel.run(con, 1)

    assert _events(con, dead) == [("quote-verify", "kill")]
    assert not [e for e in _events(con, again) if e[1] in ("kill", "merge", "defer")]
    assert again in _live(con) and dead not in _live(con)
