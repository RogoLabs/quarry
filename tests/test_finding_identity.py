"""finding_id: line-number-free, but not file-wide.

Keyed on the whole file's hash, every same-rule finding in a file shared one id, so a
rejected verdict carried forward onto real siblings, and any byte change in the file
reset every verdict in it. These pin the replacement: rule + path + the flagged
line(s) with whitespace stripped.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quarry import db, funnel, taint                # noqa: E402
from test_funnel import add, con                    # noqa: E402,F401


def _fid(root: Path, line: int, end: int | None = None) -> str:
    ev = taint.extract_evidence(root, Path("a.py"), line, end_line=end)
    return taint.finding_id("o/r", "a.py", "bandit:B307", ev.match_sha)


def test_same_rule_siblings_in_one_file_get_distinct_ids(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\neval(a)\ny = 2\neval(b)\n")
    assert _fid(tmp_path, 2) != _fid(tmp_path, 4)


def test_id_survives_moves_reindent_and_unrelated_edits(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\neval(a)\n")
    before = _fid(tmp_path, 2)
    # three lines inserted above, the flagged line re-indented, a byte changed elsewhere
    (tmp_path / "a.py").write_text("# new\n# new\nx = 2\nif True:\n    eval( a )\n")
    assert _fid(tmp_path, 5) == before
    # but a changed token is a different finding
    (tmp_path / "a.py").write_text("x = 1\neval(b)\n")
    assert _fid(tmp_path, 2) != before


def test_multi_line_match_keys_on_every_flagged_line(tmp_path):
    (tmp_path / "a.py").write_text("call(\n  a,\n)\ncall(\n  b,\n)\n")
    assert _fid(tmp_path, 1, 3) != _fid(tmp_path, 4, 6)


def test_lineless_findings_key_on_their_message():
    a = taint.finding_id("o/r", "poetry.lock", "osv-scanner:GHSA-1", None, fallback="aiohttp 3.1: x")
    b = taint.finding_id("o/r", "poetry.lock", "osv-scanner:GHSA-1", None, fallback="yarl 1.0: x")
    assert a != b


def test_rejected_verdict_does_not_kill_a_sibling(con):
    """REGRESSION. With a file-wide id, rejecting one eval() rejected all of them."""
    rejected = add(con, "bandit", "B307", "src/a.py", 10)
    sibling = add(con, "bandit", "B307", "src/a.py", 20)
    con.execute("INSERT INTO runs (id,target,clone_url,status) VALUES (0,'o/r','x','done')")
    fid = con.execute("SELECT finding_id FROM occurrences WHERE id=?",
                      (rejected,)).fetchone()["finding_id"]
    db.verdict(con, fid, 0, verdict="rejected")
    funnel.run(con, 1)
    alive = {r["id"] for r in con.execute("SELECT id FROM live_occurrences")}
    assert rejected not in alive and sibling in alive


def test_carry_forward_uses_the_latest_verdict(con):
    oid = add(con, "bandit", "B307", "src/a.py", 10)
    con.execute("INSERT INTO runs (id,target,clone_url,status) VALUES (0,'o/r','x','done')")
    fid = con.execute("SELECT finding_id FROM occurrences WHERE id=?",
                      (oid,)).fetchone()["finding_id"]
    db.verdict(con, fid, 0, verdict="rejected")
    db.verdict(con, fid, 0, verdict="confirmed")
    funnel.run(con, 1)
    assert oid in {r["id"] for r in con.execute("SELECT id FROM live_occurrences")}
    assert con.execute("SELECT 1 FROM funnel_events WHERE occurrence_id=? AND "
                       "stage='rejected-carry-forward' AND action='boost'",
                       (oid,)).fetchone()


def test_persist_gives_same_rule_siblings_their_own_findings(tmp_path):
    """Through the real writer: two B307 hits in one file are two findings."""
    from quarry import orchestrator
    from quarry.scanners.base import Record
    (tmp_path / "a.py").write_text("x = 1\neval(a)\ny = 2\neval(b)\n")
    c = db.init(tmp_path / "t.db")
    c.execute("INSERT INTO runs (id,target,clone_url,status) VALUES (1,'o/r','x','done')")
    recs = [Record(tool="bandit", rule_id="B307", path="a.py", start_line=n) for n in (2, 4)]
    summary = orchestrator.ScanSummary(1)
    orchestrator._persist(c, 1, "o/r", None, tmp_path, "bandit", recs, summary)
    assert c.execute("SELECT COUNT(DISTINCT finding_id) n FROM occurrences").fetchone()["n"] == 2
