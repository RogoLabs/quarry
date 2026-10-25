"""SQLite access. One writer process owns the database; workers never open it.

Seat 5, P0 step 7. Workers write their output to files on the run volume; the
orchestrator ingests those through the taint boundary and is the only thing that
touches SQLite. That keeps WAL contention at zero and means a crashed scanner cannot
leave a half-written row.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

SCHEMA = Path(__file__).with_name("schema.sql")


def connect(path: Path, *, readonly: bool = False) -> sqlite3.Connection:
    uri = f"file:{path}?mode=ro" if readonly else f"file:{path}"
    con = sqlite3.connect(uri, uri=True, timeout=30, isolation_level=None)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    if not readonly:
        con.execute("PRAGMA journal_mode = WAL")
        con.execute("PRAGMA synchronous = NORMAL")
        con.execute("PRAGMA busy_timeout = 30000")
        _upgrade(con)
    return con


def _upgrade(con: sqlite3.Connection) -> None:
    """Bring any database this process opens for writing up to the current schema.

    Callers used to migrate only when the file was new, so a database created by an
    older build failed later with "no such table". Gated on user_version, so a current
    database costs one PRAGMA. The schema script is all IF NOT EXISTS and runs first,
    because the migrations assume its tables exist."""
    from .migrations import MIGRATIONS, migrate
    if con.execute("PRAGMA user_version").fetchone()[0] >= len(MIGRATIONS):
        return
    con.executescript(SCHEMA.read_text())
    migrate(con)


def init(path: Path) -> sqlite3.Connection:
    from .migrations import migrate
    con = connect(path)
    con.executescript(SCHEMA.read_text())
    migrate(con)
    return con


@contextmanager
def tx(con: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    con.execute("BEGIN IMMEDIATE")
    try:
        yield con
    except Exception:
        con.execute("ROLLBACK")
        raise
    con.execute("COMMIT")


# ------------------------------------------------------------------ runs

def start_run(con: sqlite3.Connection, target: str, clone_url: str,
              manifest: dict[str, Any] | None = None) -> int:
    cur = con.execute(
        "INSERT INTO runs (target, clone_url, manifest) VALUES (?,?,?)",
        (target, clone_url, json.dumps(manifest or {}, sort_keys=True)))
    return int(cur.lastrowid)


def finish_run(con: sqlite3.Connection, run_id: int, status: str = "done",
               **fields: Any) -> None:
    sets = ["finished_at = datetime('now')", "status = ?"]
    args: list[Any] = [status]
    for k, v in fields.items():
        sets.append(f"{k} = ?")
        args.append(json.dumps(v, sort_keys=True) if k == "manifest" else v)
    args.append(run_id)
    con.execute(f"UPDATE runs SET {', '.join(sets)} WHERE id = ?", args)


# ------------------------------------------------------------------ producers

def upsert_producer(con: sqlite3.Connection, tool: str, rule_id: str, **meta: Any) -> str:
    pid = f"{tool}:{rule_id}"
    con.execute(
        """INSERT INTO producers (id, tool, rule_id, name, cwe, default_severity, help_uri)
           VALUES (?,?,?,?,?,?,?)
           ON CONFLICT(id) DO UPDATE SET
             name             = COALESCE(excluded.name, producers.name),
             cwe              = COALESCE(excluded.cwe, producers.cwe),
             default_severity = COALESCE(excluded.default_severity, producers.default_severity),
             help_uri         = COALESCE(excluded.help_uri, producers.help_uri)""",
        (pid, tool, rule_id, meta.get("name"), meta.get("cwe"),
         meta.get("default_severity"), meta.get("help_uri")))
    return pid


def bump_producer_counts(con: sqlite3.Connection) -> None:
    """Recompute the cross-repo precision ledger. Cheap enough to run after each ingest,
    and being derived rather than incremented means it cannot drift."""
    con.execute("""
        UPDATE producers SET
          n_occurrences = COALESCE((SELECT COUNT(*) FROM occurrences o
                                    WHERE o.producer_id = producers.id), 0),
          n_adjudicated = COALESCE((SELECT COUNT(DISTINCT v.finding_id) FROM verdicts v
                                    JOIN findings f ON f.id = v.finding_id
                                    WHERE f.producer_id = producers.id), 0),
          n_confirmed   = COALESCE((SELECT COUNT(DISTINCT v.finding_id) FROM verdicts v
                                    JOIN findings f ON f.id = v.finding_id
                                    WHERE f.producer_id = producers.id
                                      AND v.verdict = 'confirmed'), 0)
    """)


# ------------------------------------------------------------------ funnel ledger

# Seat 1's action set. `defer` (a rate limiter ran out) and `kill` (evidence says no)
# are different actions with different colours in the UI, because conflating "this is
# not a vulnerability" with "we ran out of money" destroys the only number that matters.
ACTIONS = ("pass", "kill", "defer", "merge", "boost", "resurrect")


def funnel(con: sqlite3.Connection, run_id: int, *, stage: str, action: str,
           reason: str, deterministic: bool, occurrence_id: int | None = None,
           producer_id: str | None = None, actor: str = "system",
           score_delta: float = 0.0, merged_into: int | None = None) -> None:
    """The only way anything is ever suppressed. There is no DELETE and no flag."""
    if action not in ACTIONS:
        raise ValueError(f"bad action {action!r}; expected one of {sorted(ACTIONS)}")
    con.execute(
        """INSERT INTO funnel_events
             (run_id, occurrence_id, producer_id, stage, action, deterministic,
              reason, score_delta, merged_into, actor)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (run_id, occurrence_id, producer_id, stage, action, int(deterministic),
         reason, score_delta, merged_into, actor))


def funnel_summary(con: sqlite3.Connection, run_id: int) -> list[dict[str, Any]]:
    """Per-stage counts for /runs/:id. Every number here must link to its killed set,
    which is why occurrence_id is recorded on every event."""
    rows = con.execute(
        """SELECT stage, action, deterministic, COUNT(*) AS n
           FROM funnel_events WHERE run_id = ?
           GROUP BY stage, action, deterministic
           ORDER BY n DESC""", (run_id,)).fetchall()
    return [dict(r) for r in rows]


# ------------------------------------------------------------------ adjudication

VERDICTS = ("confirmed", "needs-review", "rejected")


def verdict(con: sqlite3.Connection, finding_id: str, run_id: int, *,
            verdict: str, seat: str = "dynamic", model: str = "probe",
            effort: str | None = None, reason: str | None = None,
            adjusted_severity: str | None = None, cvss_vector: str | None = None,
            cwe: str | None = None, evidence_score: int = 0, executed_score: int = 0,
            rationale: str | None = None, cost_usd: float = 0.0) -> int:
    """Record one adjudication of a finding. Layer 3 writes these with a high
    executed_score when a probe confirmed the finding against a running target, and
    a rejected verdict when the probe ran and the finding did not reproduce. A verdict
    carries forward across runs on finding_id, which is line-number-free (see taint)."""
    if verdict not in VERDICTS:
        raise ValueError(f"bad verdict {verdict!r}; expected one of {sorted(VERDICTS)}")
    cur = con.execute(
        """INSERT INTO verdicts
             (finding_id, run_id, seat, model, effort, verdict, reason,
              adjusted_severity, cvss_vector, cwe, evidence_score, executed_score,
              rationale, cost_usd)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (finding_id, run_id, seat, model, effort, verdict, reason,
         adjusted_severity, cvss_vector, cwe, evidence_score, executed_score,
         rationale, cost_usd))
    return int(cur.lastrowid)


def advisory(con: sqlite3.Connection, run_id: int, finding_id: str, path: str,
             sha256: str, verdict_id: int | None = None) -> int:
    """Record one advisory draft written to disk (migration _v8). The file is the
    artifact; this row lets the dashboard list it and detect later edits by hash."""
    cur = con.execute(
        """INSERT INTO advisories (run_id, finding_id, verdict_id, path, sha256)
           VALUES (?,?,?,?,?)""",
        (run_id, finding_id, verdict_id, str(path), sha256))
    return int(cur.lastrowid)


# ------------------------------------------------------------------ egress ledger

def egress(con: sqlite3.Connection, run_id: int | None, stage: str, destination: str,
           bytes_out: int = 0, bytes_in: int = 0, note: str = "") -> None:
    con.execute(
        """INSERT INTO egress (run_id, stage, destination, bytes_out, bytes_in, note)
           VALUES (?,?,?,?,?,?)""",
        (run_id, stage, destination, bytes_out, bytes_in, note))
