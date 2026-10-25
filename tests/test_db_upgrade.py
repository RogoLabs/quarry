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
