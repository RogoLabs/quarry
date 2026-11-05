"""Operator dismissals: what each one is keyed on, and how the ledger records it.

A dismissal is a ledger event, never a DELETE and never a hidden flag (D8). There are
two scopes, and each writes one producer-level operator row (`occurrence_id` NULL,
which the schema reserves for exactly this) plus an operator kill for each of the
producer's live occurrences in the run it was made from:

* **repo**: this producer, for this target (`owner/repo`). The target is the run's.
  It used to kill only that run's occurrences, so the next scan of the same
  repository brought the producer straight back; now every later funnel pass on any
  run of the target honours it.
* **corpus**: the producer is disabled (`producers.enabled = 0`) for every target.

The funnel honours both at `rule-precision-prior`, killing a fresh occurrence with
one of FUNNEL_REASONS. Those kills are the dismissal's doing, not evidence, so a
restore undoes them along with the operator's own.

This module only reads. The reasons are matched by prefix because the operator's
note follows it: `producer dismissed for this repo: style, not security`.
"""
from __future__ import annotations

import sqlite3
from typing import Any

REPO_PREFIX = "producer dismissed for this repo"
CORPUS_PREFIX = "producer disabled corpus-wide"
REPO_WITHDRAWN = "repo dismissal withdrawn"
CORPUS_WITHDRAWN = "corpus-wide dismissal withdrawn"

#: The funnel stage that applies dismissals to fresh occurrences, and its reasons.
FUNNEL_STAGE = "rule-precision-prior"
FUNNEL_CORPUS = "producer dismissed by the operator"
FUNNEL_REPO = "producer dismissed for this repo by the operator"
FUNNEL_REASONS = (FUNNEL_CORPUS, FUNNEL_REPO)

DEFAULT_NOTE = "operator dismissal"


def reason(prefix: str, note: str) -> str:
    return f"{prefix}: {note or DEFAULT_NOTE}"


def note_of(text: str | None, prefix: str) -> str:
    """The operator's note back out of a ledger reason."""
    text = text or ""
    head = prefix + ": "
    return text[len(head):] if text.startswith(head) else text


#: Producer-level operator rows of one scope: the dismissals and their withdrawals.
_SCOPE = """fe.occurrence_id IS NULL AND fe.actor = 'operator' AND fe.stage = 'operator'
            AND (fe.reason = ? OR substr(fe.reason, 1, ?) = ?)"""


def _scope_args(scope: str) -> tuple[Any, ...]:
    prefix, withdrawn = ((REPO_PREFIX, REPO_WITHDRAWN) if scope == "repo"
                         else (CORPUS_PREFIX, CORPUS_WITHDRAWN))
    return (withdrawn, len(prefix), prefix)


def latest_corpus_event(con: sqlite3.Connection, producer_id: str) -> sqlite3.Row | None:
    """The newest corpus-scope operator row for a producer, of either action."""
    return con.execute(
        f"""SELECT fe.run_id, fe.action, fe.reason, fe.created_at FROM funnel_events fe
            WHERE fe.producer_id = ? AND {_SCOPE} ORDER BY fe.id DESC LIMIT 1""",
        (producer_id, *_scope_args("corpus"))).fetchone()


def repo_dismissals(con: sqlite3.Connection, target: str) -> dict[str, dict[str, Any]]:
    """Every repo dismissal in force for `target`: producer id -> where and why.

    In force means the producer's newest repo-scope row, across every run of the
    target, is a kill rather than a withdrawal."""
    latest: dict[str, sqlite3.Row] = {}
    for r in con.execute(
            f"""SELECT fe.producer_id, fe.run_id, fe.action, fe.reason, fe.created_at
                FROM funnel_events fe JOIN runs r ON r.id = fe.run_id
                WHERE r.target = ? AND {_SCOPE} ORDER BY fe.id""",
            (target, *_scope_args("repo"))):
        latest[r["producer_id"]] = r
    return {pid: {"run_id": r["run_id"], "note": note_of(r["reason"], REPO_PREFIX),
                  "created_at": r["created_at"]}
            for pid, r in latest.items() if r["action"] == "kill"}


def repo_dismissal(con: sqlite3.Connection, producer_id: str,
                   target: str) -> dict[str, Any] | None:
    """The repo dismissal in force for one producer on one target, or None."""
    return repo_dismissals(con, target).get(producer_id)
