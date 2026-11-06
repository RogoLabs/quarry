"""The precision ledger counts a finding's latest verdict, not every verdict it ever had.

On 2026-11-06 a faulty SSRF check confirmed sixteen VulnLookup findings and put their
two rules at 10 of 10 and 6 of 6. The ledger orders every later validate run by that
precision, and it counted any confirmation ever written, so a re-run that held the
findings could not take it back. The advisory drafts and the dashboard already read the
latest verdict per run, finding, seat and model.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quarry import db                                   # noqa: E402


@pytest.fixture
def con(tmp_path):
    p = tmp_path / "quarry.db"
    db.init(p)
    c = db.connect(p)
    with db.tx(c):
        c.execute("INSERT INTO runs (id, target, clone_url) VALUES (1,'o/r','https://x')")
        c.execute("INSERT INTO runs (id, target, clone_url) VALUES (2,'o/r','https://x')")
        c.execute("""INSERT INTO producers (id, tool, rule_id, cwe)
                     VALUES ('p:ssrf','opengrep','ssrf','CWE-918')""")
        for fid in ("f1", "f2"):
            c.execute("""INSERT INTO findings (id,target,path,producer_id,first_seen_run,
                                               last_seen_run)
                         VALUES (?,'o/r','a.py','p:ssrf',1,2)""", (fid,))
    return c


def _verdict(con, fid, run, verdict, model="path-traversal-ssrf"):
    with db.tx(con):
        con.execute("""INSERT INTO verdicts (finding_id, run_id, seat, model, verdict)
                       VALUES (?,?,'dynamic',?,?)""", (fid, run, model, verdict))


def _ledger(con):
    with db.tx(con):
        db.bump_producer_counts(con)
    return tuple(con.execute("SELECT n_adjudicated, n_confirmed FROM producers "
                             "WHERE id='p:ssrf'").fetchone())


def test_a_rerun_that_holds_a_finding_withdraws_its_confirmation(con):
    _verdict(con, "f1", 1, "confirmed")
    _verdict(con, "f2", 1, "confirmed")
    assert _ledger(con) == (2, 2)
    _verdict(con, "f1", 1, "needs-review")
    assert _ledger(con) == (1, 1)
    _verdict(con, "f2", 1, "rejected")
    assert _ledger(con) == (1, 0)


def test_a_confirmation_in_another_run_still_counts(con):
    """Latest per run: a later run of other code does not erase what an earlier run
    showed, the same reading the dashboard gives."""
    _verdict(con, "f1", 1, "confirmed")
    _verdict(con, "f1", 2, "needs-review")
    assert _ledger(con) == (1, 1)
