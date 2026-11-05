"""Every write the dashboard makes, in one place.

There are only two kinds. Operator dispositions append ledger rows (and, for a
corpus-wide dismissal, flip `producers.enabled`): nothing is ever deleted (D8), and a
dismissal is undone by a later row, never by removing the first. Research-run claims
update the run's status, pid and heartbeat columns so that a resume is held by one
worker at a time.

Routes decide whether a write is allowed (the run exists, the claim is free) and
call these to make it. The SQL moved here from app.py unchanged; the reasons for each
rule are on the routes in routes/triage.py and routes/research.py.
"""
from __future__ import annotations

import sqlite3
from typing import Any

from .. import db, dismissals
from . import queries as q


def dismiss_producer(con: sqlite3.Connection, run_id: int, producer_id: str,
                     scope: str, note: str) -> None:
    """Dismiss a producer for this run's target (`repo`) or everywhere (`corpus`).

    One producer-level ledger row records the decision and its scope, and an
    operator kill holds out each of the producer's live occurrences in this run. A
    corpus-wide dismissal also disables the producer. `note` is already scrubbed."""
    with db.tx(con):
        if scope == "corpus":
            con.execute("UPDATE producers SET enabled=0, dismissed_at=datetime('now'), "
                        "dismissed_note=? WHERE id=?",
                        (note or dismissals.DEFAULT_NOTE, producer_id))
        db.funnel(con, run_id, producer_id=producer_id, stage="operator",
                  action="kill", deterministic=False, actor="operator",
                  reason=dismissals.reason(
                      dismissals.CORPUS_PREFIX if scope == "corpus"
                      else dismissals.REPO_PREFIX, note))
        ids = [r["id"] for r in con.execute(
            "SELECT id FROM live_occurrences WHERE run_id=? AND producer_id=?",
            (run_id, producer_id))]
        for oid in ids:
            db.funnel(con, run_id, occurrence_id=oid, producer_id=producer_id,
                      stage="operator", action="kill", deterministic=False,
                      actor="operator",
                      reason=note or (f"producer dismissed {'corpus-wide' if scope == 'corpus' else 'for this repo'}"))


def restore_producer(con: sqlite3.Connection, run_id: int, producer_id: str,
                     target: str) -> None:
    """Undo a dismissal from this run, and only that (see routes.triage.restore)."""
    with db.tx(con):
        if q.corpus_dismissal_run(con, producer_id) == run_id:
            con.execute("UPDATE producers SET enabled=1, dismissed_at=NULL, "
                        "dismissed_note=NULL WHERE id=?", (producer_id,))
            db.funnel(con, run_id, producer_id=producer_id, stage="operator",
                      action="resurrect", deterministic=False, actor="operator",
                      reason=dismissals.CORPUS_WITHDRAWN)
        if dismissals.repo_dismissal(con, producer_id, target) is not None:
            db.funnel(con, run_id, producer_id=producer_id, stage="operator",
                      action="resurrect", deterministic=False, actor="operator",
                      reason=dismissals.REPO_WITHDRAWN)
        for oid in q.restorable_occurrences(con, run_id, producer_id):
            db.funnel(con, run_id, occurrence_id=oid, producer_id=producer_id,
                      stage="operator", action="resurrect", deterministic=False,
                      actor="operator", reason="operator dismissal withdrawn")


def claim_research_run(con: sqlite3.Connection, rid: int) -> None:
    """Mark a research run as being resumed, before its worker exists.

    Call it inside the same transaction that found the run resumable: the check and
    the claim are one step, or two requests can both pass the check."""
    con.execute("UPDATE research_runs SET status=?, pid=NULL, "
                "heartbeat=datetime('now') WHERE id=?", (q.RESUMING, rid))


def release_research_claim(con: sqlite3.Connection, rid: int,
                           prior: dict[str, Any]) -> None:
    """Put back what the claim overwrote, after a spawn that failed. Only while the
    claim is still unfilled: a worker that got as far as claiming the run stands."""
    with db.tx(con):
        con.execute("UPDATE research_runs SET status=?, pid=?, heartbeat=? "
                    "WHERE id=? AND status=? AND pid IS NULL",
                    (prior["status"], prior["pid"], prior["heartbeat"], rid,
                     q.RESUMING))


def record_worker_pid(con: sqlite3.Connection, rid: int, pid: int) -> None:
    """Fill a claim with the spawned worker's pid. Only while the claim is still ours
    and unfilled: a worker that has already claimed the run wrote its own."""
    with db.tx(con):
        con.execute("UPDATE research_runs SET pid=? WHERE id=? AND status=? "
                    "AND pid IS NULL", (pid, rid, q.RESUMING))
