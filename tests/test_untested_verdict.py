"""`untested`: a probe that could not exercise the finding is not waiting on a person.

On run 3 (2026-11-10) 706 of 800 verdicts were a probe with no route in the finding's
file, no route declared protected, no check for the class, or nothing measured, and every
one was labelled needs-review, so the review queue read 800 where 94 had anything to
judge. Those now write `untested` (`ProbeEvidence.exercised`), which the schema accepts
from migration _v12, and the CLI and dashboard count apart.
"""
from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from quarry import db                                              # noqa: E402
from quarry.dynamic.validate import (                              # noqa: E402
    UNTESTED, ProbeEvidence, adjudicate_with_reason, run_validation)
from quarry.migrations import MIGRATIONS                           # noqa: E402
from quarry.web import queries as q                                # noqa: E402
from test_run_validation import FakeRuntime, scanned               # noqa: E402,F401
from test_web import seeded                                        # noqa: E402,F401
from test_web_pipeline import _finding, _verdict                   # noqa: E402

OLD_CHECK = "CHECK (verdict IN ('confirmed','needs-review','rejected'))"


def _old_database(path: Path) -> None:
    """A database as v11 left it: the verdicts CHECK without `untested`, two verdicts,
    and an advisory pointing at one of them."""
    con = db.init(path)
    sql = con.execute("SELECT sql FROM sqlite_master WHERE name='verdicts'").fetchone()[0]
    start, end = sql.index("CHECK (verdict IN"), sql.index("'untested')),") + len("'untested'))")
    old = sql[:start] + OLD_CHECK + sql[end:]
    con.execute("PRAGMA foreign_keys = OFF")
    con.executescript(f"""
        DROP TABLE verdicts;
        {old};
        CREATE INDEX IF NOT EXISTS idx_verdict_finding ON verdicts(finding_id);
        INSERT INTO runs (id, target, clone_url) VALUES (1, 'o/r', 'https://x');
        INSERT INTO producers (id, tool, rule_id) VALUES ('t:r', 't', 'r');
        INSERT INTO findings (id, target, path, producer_id, first_seen_run, last_seen_run)
            VALUES ('f1', 'o/r', 'a.py', 't:r', 1, 1);
        INSERT INTO verdicts (id, finding_id, run_id, model, verdict, rationale)
            VALUES (7, 'f1', 1, 'probe', 'confirmed', '{{"summary": "s"}}'),
                   (9, 'f1', 1, 'probe', 'needs-review', NULL);
        INSERT INTO advisories (run_id, finding_id, verdict_id, path, sha256)
            VALUES (1, 'f1', 7, 'a.md', 'abc');
        PRAGMA user_version = 11;
    """)
    con.close()


def test_v12_rebuilds_the_check_and_keeps_every_row_and_reference(tmp_path):
    path = tmp_path / "old.db"
    _old_database(path)
    with pytest_raises_check(path):
        pass
    con = db.connect(path)                      # upgrades on open
    assert con.execute("PRAGMA user_version").fetchone()[0] == len(MIGRATIONS)
    sql = con.execute("SELECT sql FROM sqlite_master WHERE name='verdicts'").fetchone()[0]
    assert "'untested'" in sql
    rows = [tuple(r) for r in con.execute("SELECT id, verdict, rationale FROM verdicts "
                                          "ORDER BY id")]
    assert rows == [(7, "confirmed", '{"summary": "s"}'), (9, "needs-review", None)]
    assert con.execute("PRAGMA foreign_key_check").fetchall() == []
    adv = con.execute("SELECT sql FROM sqlite_master WHERE name='advisories'").fetchone()[0]
    assert "REFERENCES verdicts(id)" in adv and "verdicts_v12" not in adv
    assert con.execute("SELECT verdict_id FROM advisories").fetchone()[0] == 7
    assert con.execute("SELECT 1 FROM sqlite_master WHERE name='idx_verdict_finding'"
                       ).fetchone()
    assert con.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    with db.tx(con):
        db.verdict(con, "f1", 1, verdict="untested", reason=UNTESTED)
    # Every view still parses after the swap (v4 exists because a rebuild broke one).
    for (name,) in con.execute("SELECT name FROM sqlite_master WHERE type='view'"):
        con.execute(f"SELECT * FROM {name} LIMIT 1").fetchall()


class pytest_raises_check:
    """Before the upgrade, the old CHECK refuses `untested`."""
    def __init__(self, path):
        self.path = path

    def __enter__(self):
        raw = sqlite3.connect(self.path)
        try:
            raw.execute("INSERT INTO verdicts (finding_id, run_id, model, verdict) "
                        "VALUES ('f1', 1, 'probe', 'untested')")
        except sqlite3.IntegrityError:
            return self
        finally:
            raw.close()
        raise AssertionError("the v11 table accepted 'untested'")

    def __exit__(self, *exc):
        return False


def test_a_new_database_has_it_from_the_schema(tmp_path):
    con = db.init(tmp_path / "new.db")
    with db.tx(con):
        con.execute("INSERT INTO runs (id, target, clone_url) VALUES (1, 'o/r', 'x')")
        con.execute("INSERT INTO producers (id, tool, rule_id) VALUES ('t:r', 't', 'r')")
        con.execute("INSERT INTO findings (id, target, path, producer_id, first_seen_run, "
                    "last_seen_run) VALUES ('f1', 'o/r', 'a.py', 't:r', 1, 1)")
        db.verdict(con, "f1", 1, verdict="untested")


def test_evidence_that_was_not_exercised_is_untested():
    ev = ProbeEvidence(reproduced=False, summary="no GET route", exercised=False)
    assert adjudicate_with_reason(ev) == ("untested", UNTESTED)
    measured = ProbeEvidence(reproduced=False, summary="no reflection")
    assert adjudicate_with_reason(measured)[0] == "needs-review"


def test_a_finding_with_no_route_in_its_file_is_untested(scanned):
    """The scanned target's only routes are in app.py; a finding elsewhere has nothing
    for the probe to address."""
    con, rundir = scanned
    with db.tx(con):
        con.execute("INSERT INTO findings (id,target,path,producer_id,first_seen_run,"
                    "last_seen_run) VALUES ('f-lib','o/r','lib.py','t:authz',1,1)")
        con.execute("INSERT INTO occurrences (run_id,finding_id,producer_id,path,"
                    "start_line,message) VALUES (1,'f-lib','t:authz','lib.py',3,'m')")
    res = run_validation(con, 1, rundir, FakeRuntime({"/secret": "200"}))
    assert res.untested == 1 and ("f-lib", "broken-authz-idor", "untested") in res.verdicts
    row = dict(con.execute("SELECT * FROM verdicts WHERE finding_id='f-lib'").fetchone())
    assert (row["verdict"], row["reason"], row["executed_score"]) == ("untested",
                                                                      UNTESTED, 0)


def test_the_dashboard_counts_untested_apart(seeded):
    client, con = seeded
    fid, _ = _finding(con, "mod0")
    other, _ = _finding(con, "mod1")
    _verdict(con, fid, "needs-review")
    _verdict(con, other, "untested")
    assert q.verdict_counts(con, 1)["untested"] == 1
    runs = client.get("/runs").text
    row = runs.split('<a href="/runs/1">1</a>', 1)[1].split("</tr>", 1)[0]
    assert '/runs/1/validation">1</a>' in row, "the count leaves untested out"
    assert "1 untested" in row
    page = client.get("/runs/1").text
    assert "/runs/1/validation?state=untested" in page
    listed = client.get("/runs/1/validation?state=untested").text
    assert '<span class="pill inert">untested</span>' in listed
    card = next(c for c in q.pipeline(con, q.run_summary(con, 1)) if c["name"] == "Validate")
    assert card["n"] == 1 and "1 untested" in card["unit"]
