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
from typing import Any, Callable, Iterator

from .cwe import normalise as normalise_cwe

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
    except BaseException:
        # BaseException, not Exception: a KeyboardInterrupt (Ctrl-C, or the SIGTERM
        # `quarry deep` turns into one) left the transaction open, and every write
        # after it, the run's own `stopped`, went down with it when the process exited.
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


def read_manifest(con: sqlite3.Connection, run_id: int) -> dict[str, Any]:
    row = con.execute("SELECT manifest FROM runs WHERE id=?", (run_id,)).fetchone()
    try:
        m = json.loads(row["manifest"]) if row and row["manifest"] else {}
    except (ValueError, TypeError):
        m = {}
    return m if isinstance(m, dict) else {}


def update_manifest(con: sqlite3.Connection, run_id: int,
                    change: "Callable[[dict[str, Any]], None]") -> dict[str, Any]:
    """Read, change in place, write back. The manifest is one JSON document, so every
    writer goes through here rather than overwriting another writer's keys."""
    m = read_manifest(con, run_id)
    change(m)
    con.execute("UPDATE runs SET manifest=? WHERE id=?",
                (json.dumps(m, sort_keys=True, default=str), run_id))
    return m


#: The stages that record their own start and end on the run (`stage_started`).
#: Ingest has `runs.status`, scan its per-tool records, the funnel its ledger and the
#: deep review its own table; these two left nothing when they found nothing.
RECORDED_STAGES = ("validate", "report")


def _utc_stamp() -> str:
    """The same shape as SQLite's datetime('now'), which the dashboard's `local` reads."""
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _stage_record(m: dict[str, Any], stage: str) -> dict[str, Any]:
    d = m.get(stage)
    if not isinstance(d, dict):
        d = m[stage] = {}
    return d


def stage_started(con: sqlite3.Connection, run_id: int, stage: str) -> None:
    """Put on the run that `stage` started, and which process is doing it.

    The Runs page said `done` with 0 verdicts and 0 drafts for a run validate had
    never touched, because validate recorded nothing unless a target booted and
    report recorded only its digest: "not run" and "ran, found nothing" looked the
    same. `manifest[stage]["last"]` now holds the latest attempt, from start to end,
    and a start with no end and no live process reads as died."""
    import os
    assert stage in RECORDED_STAGES, stage
    rec = {"started_at": _utc_stamp(), "ended_at": None, "pid": os.getpid(),
           "outcome": "running"}
    with tx(con):
        update_manifest(con, run_id, lambda m: _stage_record(m, stage).update(last=rec))


def stage_ended(con: sqlite3.Connection, run_id: int, stage: str, outcome: str,
                **facts: Any) -> None:
    """Close the record `stage_started` opened: how it ended, and what it produced.
    `outcome` is a short phrase the dashboard shows as is ("probed", "no candidates",
    "error"); `facts` are counts and a `note`."""
    assert stage in RECORDED_STAGES, stage

    def change(m: dict[str, Any]) -> None:
        d = _stage_record(m, stage)
        last = d.get("last") if isinstance(d.get("last"), dict) else {}
        last.update(ended_at=_utc_stamp(), pid=None, outcome=outcome, **facts)
        d["last"] = last
    with tx(con):
        update_manifest(con, run_id, change)


def set_health(con: sqlite3.Connection, run_id: int, source: str,
               by_tool: dict[str, list[str]]) -> None:
    """Replace the health warnings `source` holds for each tool in `by_tool`. A tool
    with an empty list is cleared, so a re-run that fixed it stops warning."""
    def change(m: dict[str, Any]) -> None:
        h = m.setdefault("health", {}).setdefault(source, {})
        for tool, msgs in by_tool.items():
            if msgs:
                h[tool] = msgs
            else:
                h.pop(tool, None)
    update_manifest(con, run_id, change)


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
        (pid, tool, rule_id, meta.get("name"), normalise_cwe(meta.get("cwe")),
         meta.get("default_severity"), meta.get("help_uri")))
    return pid


def bump_producer_counts(con: sqlite3.Connection) -> None:
    """Recompute the cross-repo precision ledger. Cheap enough to run after each ingest,
    and being derived rather than incremented means it cannot drift.

    Only confirmed and rejected count as adjudicated. A needs-review verdict means the
    probe got no signal; counting it made a producer probed five times with no answer
    read as 0 of 5 confirmed, which ranks it down and bands it known-bad.

    Only the latest verdict per run, finding, seat and model counts, the rule the
    dashboard (queries.LATEST_VERDICTS) and the advisory drafts already use, so a
    re-run of validate that holds or rejects a finding withdraws its confirmation here
    too. It once counted any confirmation ever written: sixteen from a faulty SSRF check
    on 2026-11-06 put two rules at 10 of 10 and 6 of 6, and no re-run could undo that."""
    latest = """(SELECT v.finding_id, v.verdict FROM verdicts v
                   JOIN (SELECT MAX(id) AS id FROM verdicts
                          GROUP BY run_id, finding_id, seat, model) l ON l.id = v.id)"""
    con.execute(f"""
        UPDATE producers SET
          n_occurrences = COALESCE((SELECT COUNT(*) FROM occurrences o
                                    WHERE o.producer_id = producers.id), 0),
          n_adjudicated = COALESCE((SELECT COUNT(DISTINCT v.finding_id) FROM {latest} v
                                    JOIN findings f ON f.id = v.finding_id
                                    WHERE f.producer_id = producers.id
                                      AND v.verdict IN ('confirmed', 'rejected')), 0),
          n_confirmed   = COALESCE((SELECT COUNT(DISTINCT v.finding_id) FROM {latest} v
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
