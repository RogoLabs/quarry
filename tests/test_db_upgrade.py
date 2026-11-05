"""An existing database from an older build must open, not fail with "no such table".

cli.py and web/app.py only ran migrations when the database file was new, so a
database created before a migration landed never received it.
"""
from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quarry import db                                # noqa: E402
from quarry.migrations import MIGRATIONS              # noqa: E402


def _tables(con: sqlite3.Connection) -> set[str]:
    return {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def test_connect_migrates_a_database_at_an_old_version(tmp_path):
    p = tmp_path / "old.db"
    old = db.init(p)
    # Roll it back to what a v4 build left behind: no targets, no research tables.
    old.executescript("""
        DROP TABLE deep_verdicts;
        DROP TABLE research_findings; DROP TABLE research_units;
        DROP TABLE research_runs; DROP TABLE targets;
        PRAGMA user_version = 4;
    """)
    old.close()

    con = db.connect(p)
    assert {"targets", "research_runs", "research_units", "research_findings"} <= _tables(con)
    assert con.execute("PRAGMA user_version").fetchone()[0] == len(MIGRATIONS)
    cols = {r[1] for r in con.execute("PRAGMA table_info(research_runs)")}
    assert {"pid", "host", "heartbeat"} <= cols
    assert "deep_verdicts" in _tables(con)
    cols = {r[1] for r in con.execute("PRAGMA table_info(research_findings)")}
    assert {"symbol", "prior_verdict_id", "prior_match"} <= cols


def test_v9_keeps_existing_deep_findings_and_adds_verdicts(tmp_path):
    """A v8 database with run 1's findings in it: v9 adds the verdict table and three
    NULL columns, and touches no existing row."""
    p = tmp_path / "v8.db"
    old = db.init(p)
    old.executescript("""
        DROP TABLE deep_verdicts;
        DROP INDEX IF EXISTS idx_rfind_lens_file;
        ALTER TABLE research_findings DROP COLUMN prior_match;
        ALTER TABLE research_findings DROP COLUMN prior_verdict_id;
        ALTER TABLE research_findings DROP COLUMN symbol;
        PRAGMA user_version = 8;
    """)
    old.execute("INSERT INTO runs (id,target,clone_url,status) VALUES (1,'o/r','x','done')")
    old.execute("INSERT INTO research_runs (id,run_id) VALUES (1,1)")
    old.execute("INSERT INTO research_findings (id,research_id,subsystem,lens,model,family,"
                "title,quote_verified,n_survived) VALUES (7,1,'s','broken-authz-idor',"
                "'devstral:24b','mistral','t',1,1)")
    old.close()

    con = db.connect(p)
    assert con.execute("PRAGMA user_version").fetchone()[0] == len(MIGRATIONS) >= 9
    row = con.execute("SELECT * FROM research_findings WHERE id=7").fetchone()
    assert row["title"] == "t" and row["n_survived"] == 1
    assert row["symbol"] is None and row["prior_verdict_id"] is None
    con.execute("INSERT INTO deep_verdicts (research_finding_id, verdict, note) "
                "VALUES (7, 'intended', 'deliberate')")
    assert con.execute("SELECT created_at FROM deep_verdicts").fetchone()[0]


def test_fresh_and_upgraded_databases_agree_on_v9(tmp_path):
    """schema.sql does not repeat migration DDL, so both paths must end the same."""
    fresh = db.init(tmp_path / "fresh.db")
    raw = sqlite3.connect(tmp_path / "v0.db")
    raw.executescript(db.SCHEMA.read_text())
    raw.close()
    upgraded = db.connect(tmp_path / "v0.db")

    def cols(con, table):
        return [tuple(r)[1:] for r in con.execute(f"PRAGMA table_info({table})")]

    for table in ("deep_verdicts", "research_findings"):
        assert cols(fresh, table) == cols(upgraded, table), table


def test_connect_migrates_a_schema_only_database(tmp_path):
    """user_version 0: the schema script ran, no migration ever did."""
    p = tmp_path / "v0.db"
    raw = sqlite3.connect(p)
    raw.executescript(db.SCHEMA.read_text())
    raw.close()

    con = db.connect(p)
    assert "issue_members" in _tables(con)
    cols = {r[1] for r in con.execute("PRAGMA table_info(funnel_events)")}
    assert "score_delta" in cols
    con.execute("SELECT COUNT(*) FROM live_occurrences").fetchone()   # view repaired by v4


def test_connect_is_idempotent_on_a_current_database(tmp_path):
    p = tmp_path / "cur.db"
    db.init(p).close()
    for _ in range(2):
        con = db.connect(p)
        assert con.execute("PRAGMA user_version").fetchone()[0] == len(MIGRATIONS)
        con.close()
