"""Read models for the UI.

Seat 4's ruling, round 2: **the P1 triage unit is the RULE, not the finding.** At ~458
verdict-less findings per repo a 60-second per-finding decision is the wrong operation,
because the decision does not vary within a rule. The operator's job is "which
producers do I ever want to hear from again."

Sorting is by band, then by cheapest-information-first — never by severity. The
predecessor's data is unambiguous on that: claimed severity `critical` 0/11, `high` 3%,
`medium` 0/26. It predicts nothing.
"""
from __future__ import annotations

import datetime as _dt
import gzip
import json
import sqlite3
from dataclasses import dataclass, field
from typing import Any

BANDS = ("known-good", "unmeasured", "known-bad")


@dataclass
class ProducerGroup:
    producer_id: str
    tool: str
    rule_id: str
    band: str
    n_live: int
    n_total: int
    n_adjudicated: int
    n_confirmed: int
    corroborated: int          # how many of its live findings sit in a cross-tool cluster
    top_score: float
    cwe: str | None
    sample: list[dict[str, Any]] = field(default_factory=list)

    @property
    def precision(self) -> str:
        if not self.n_adjudicated:
            return "—"
        return f"{100 * self.n_confirmed / self.n_adjudicated:.0f}%"


def _band(n_adjudicated: int, n_confirmed: int, n_total: int) -> str:
    if n_confirmed > 0:
        return "known-good"
    if n_adjudicated >= 5 or n_total >= 5:
        return "known-bad" if n_adjudicated >= 5 else "unmeasured"
    return "unmeasured"


def producer_groups(con: sqlite3.Connection, run_id: int,
                    verdict: str | None = None) -> list[ProducerGroup]:
    """Live findings, grouped by producer, banded and ordered for triage.

    `verdict` narrows to occurrences whose finding's latest verdict in this run is in
    that state (see FINDING_HAS_VERDICT); an unknown state yields no groups."""
    if verdict is not None and verdict not in VERDICT_STATES:
        return []
    extra, args = ("", (run_id,)) if not verdict else (
        " AND " + FINDING_HAS_VERDICT, (run_id, run_id, verdict))
    rows = con.execute("""
        SELECT p.id, p.tool, p.rule_id, p.cwe,
               p.n_occurrences, p.n_adjudicated, p.n_confirmed,
               COUNT(o.id)                AS n_live,
               MAX(COALESCE(rk.score,0))  AS top_score,
               SUM(CASE WHEN f.issue_id IS NOT NULL THEN 1 ELSE 0 END) AS corroborated
        FROM live_occurrences o
        JOIN producers p       ON p.id = o.producer_id
        JOIN findings  f       ON f.id = o.finding_id
        LEFT JOIN occurrence_rank rk ON rk.occurrence_id = o.id
        WHERE o.run_id = ?""" + extra + """
        GROUP BY p.id
    """, args).fetchall()

    groups: list[ProducerGroup] = []
    for r in rows:
        band = _band(r["n_adjudicated"] or 0, r["n_confirmed"] or 0, r["n_live"])
        groups.append(ProducerGroup(
            producer_id=r["id"], tool=r["tool"], rule_id=r["rule_id"], band=band,
            n_live=r["n_live"], n_total=r["n_occurrences"] or 0,
            n_adjudicated=r["n_adjudicated"] or 0, n_confirmed=r["n_confirmed"] or 0,
            corroborated=r["corroborated"] or 0, top_score=r["top_score"] or 0.0,
            cwe=r["cwe"]))

    # Cheapest-information-first inside the unmeasured band: a rule that fired 3 times
    # is a cheaper measurement than one that fired 61, and corroboration is the one
    # signal available before any adjudication exists.
    def key(g: ProducerGroup):
        return (BANDS.index(g.band),
                -g.corroborated,
                g.n_live if g.band == "unmeasured" else -g.n_live,
                -g.top_score)

    return sorted(groups, key=key)


def occurrences_for(con: sqlite3.Connection, run_id: int, producer_id: str,
                    limit: int = 200, verdict: str | None = None) -> list[dict[str, Any]]:
    if verdict is not None and verdict not in VERDICT_STATES:
        return []
    extra, args = ("", ()) if not verdict else (" AND " + FINDING_HAS_VERDICT,
                                                (run_id, verdict))
    return [dict(r) for r in con.execute("""
        SELECT o.id, o.path, o.start_line, o.message, o.severity, o.blob_sha,
               o.redacted, o.secret_prefix, f.issue_id,
               COALESCE(rk.score, 0) AS score
        FROM live_occurrences o
        JOIN findings f ON f.id = o.finding_id
        LEFT JOIN occurrence_rank rk ON rk.occurrence_id = o.id
        WHERE o.run_id = ? AND o.producer_id = ?""" + extra + """
        ORDER BY rk.score DESC, o.path, o.start_line
        LIMIT ?""", (run_id, producer_id, *args, limit))]


def occurrences_total(con: sqlite3.Connection, run_id: int, producer_id: str,
                      verdict: str | None = None) -> int:
    """How many live occurrences this producer actually has.

    `occurrences_for` caps at 200. The column header showed that capped count beside
    an uncapped total in the adjacent column, so a producer with 920 live findings
    read as "200" next to "920" with nothing saying which was which.
    """
    if verdict is not None and verdict not in VERDICT_STATES:
        return 0
    extra, args = ("", ()) if not verdict else (" AND " + FINDING_HAS_VERDICT,
                                                (run_id, verdict))
    return con.execute(
        "SELECT COUNT(*) c FROM live_occurrences o WHERE o.run_id=? AND o.producer_id=?"
        + extra, (run_id, producer_id, *args)).fetchone()["c"]


def occurrence(con: sqlite3.Connection, oid: int) -> dict[str, Any] | None:
    r = con.execute("""
        SELECT o.*, p.tool, p.rule_id, p.cwe, p.help_uri, f.issue_id,
               COALESCE(rk.score,0) AS score
        FROM occurrences o
        JOIN producers p ON p.id = o.producer_id
        JOIN findings  f ON f.id = o.finding_id
        LEFT JOIN occurrence_rank rk ON rk.occurrence_id = o.id
        WHERE o.id = ?""", (oid,)).fetchone()
    return dict(r) if r else None


def evidence(con: sqlite3.Connection, blob_sha: str | None) -> dict[str, Any] | None:
    """Source from the content-addressed blob, never from the clone (D15). The pane
    keeps working after the volume is released, including for killed findings."""
    if not blob_sha:
        return None
    r = con.execute("SELECT * FROM evidence_blobs WHERE sha=?", (blob_sha,)).fetchone()
    if not r:
        return None
    try:
        text = gzip.decompress(r["body"]).decode("utf-8", "replace")
    except (OSError, EOFError):
        return None
    return {"path": r["path"], "start_line": r["start_line"],
            "end_line": r["end_line"], "lines": text.split("\n"),
            "file_sha256": r["file_sha256"]}


def provenance(con: sqlite3.Connection, oid: int) -> list[dict[str, Any]]:
    """Every ledger event for one finding. This is what makes the rank auditable."""
    return [dict(r) for r in con.execute(
        "SELECT stage,action,deterministic,reason,score_delta,merged_into,actor,created_at "
        "FROM funnel_events WHERE occurrence_id=? ORDER BY id", (oid,))]


def funnel_stages(con: sqlite3.Connection, run_id: int) -> list[dict[str, Any]]:
    """Per-stage counts for /runs/:id. Every number here links to its own set —
    that is a build constraint, not a nicety (Seat 4).

    Read from the run manifest when it is present, so stages that suppressed nothing
    still appear with zeroes rather than disappearing.
    """
    import json as _json
    row = con.execute("SELECT manifest FROM runs WHERE id=?", (run_id,)).fetchone()
    if row and row["manifest"]:
        try:
            f = _json.loads(row["manifest"]).get("funnel")
        except (ValueError, TypeError):
            f = None
        if f and f.get("stages"):
            return f["stages"]

    order = con.execute("""
        SELECT stage, MIN(id) AS first_id FROM funnel_events
        WHERE run_id=? GROUP BY stage ORDER BY first_id""", (run_id,)).fetchall()
    out = []
    for row in order:
        stage = row["stage"]
        counts = {r["action"]: r["n"] for r in con.execute(
            "SELECT action, COUNT(*) n FROM funnel_events WHERE run_id=? AND stage=? "
            "AND occurrence_id IS NOT NULL GROUP BY action", (run_id, stage))}
        heuristic = con.execute(
            "SELECT MIN(deterministic) d FROM funnel_events WHERE run_id=? AND stage=?",
            (run_id, stage)).fetchone()["d"] == 0
        out.append({"stage": stage, "heuristic": heuristic,
                    "kill": counts.get("kill", 0), "defer": counts.get("defer", 0),
                    "merge": counts.get("merge", 0), "boost": counts.get("boost", 0)})
    return out


#: Actions a funnel stage can take. `boost` is not a suppression — it raises a score —
#: but it is exactly as much of an audit target as a kill, and it was previously excluded
#: from this query while `run.html` linked it anyway. Two of eleven stages therefore
#: rendered "Suppressed at X — 0 shown" over an empty table, directly beneath the heading
#: promising that every number is a link to its set.
FUNNEL_ACTIONS = ("kill", "defer", "merge", "boost")

#: What the page should call each action's set. A boost was never "suppressed".
ACTION_NOUN = {"kill": "Killed", "defer": "Deferred", "merge": "Merged",
               "boost": "Boosted"}


def suppressed(con: sqlite3.Connection, run_id: int, stage: str | None = None,
               action: str | None = None, limit: int = 300) -> list[dict[str, Any]]:
    """The set behind one funnel number.

    `action` scopes to a single column so every cell in the funnel table links to its own
    set rather than to the union of three of them. Passing an unknown action yields
    nothing rather than silently widening to all four.
    """
    if action is not None and action not in FUNNEL_ACTIONS:
        return []
    wanted = (action,) if action else FUNNEL_ACTIONS
    sql = f"""SELECT fe.id, fe.stage, fe.action, fe.reason, fe.deterministic,
                     fe.score_delta,
                     o.id AS occurrence_id, o.path, o.start_line, o.blob_sha,
                     p.id AS producer_id
              FROM funnel_events fe
              JOIN occurrences o ON o.id = fe.occurrence_id
              JOIN producers  p ON p.id = o.producer_id
              WHERE fe.run_id = ?
                AND fe.action IN ({','.join('?' * len(wanted))})"""
    args: list[Any] = [run_id, *wanted]
    if stage:
        sql += " AND fe.stage = ?"
        args.append(stage)
    sql += " ORDER BY fe.id LIMIT ?"
    args.append(limit)
    return [dict(r) for r in con.execute(sql, args)]


def suppressed_total(con: sqlite3.Connection, run_id: int, stage: str | None = None,
                     action: str | None = None) -> int:
    """How many rows `suppressed()` would return without its LIMIT.

    A truncated tail presented as a complete record is the same defect as an
    unauditable funnel, one order of magnitude smaller.
    """
    if action is not None and action not in FUNNEL_ACTIONS:
        return 0
    wanted = (action,) if action else FUNNEL_ACTIONS
    # Producer-level rows (occurrence_id NULL, written by a corpus-wide dismissal) have
    # no occurrence for `suppressed()` to join, so counting them here would claim rows
    # the table can never show.
    sql = ("SELECT COUNT(*) c FROM funnel_events WHERE run_id = ? "
           "AND occurrence_id IS NOT NULL "
           f"AND action IN ({','.join('?' * len(wanted))})")
    args: list[Any] = [run_id, *wanted]
    if stage:
        sql += " AND stage = ?"
        args.append(stage)
    return con.execute(sql, args).fetchone()["c"]


#: What `live_occurrences` treats as suppression. `boost` is auditable but leaves an
#: occurrence live, so it is not here.
SUPPRESSING = ("kill", "defer", "merge")


def not_live(con: sqlite3.Connection, run_id: int, limit: int = 300) -> list[dict[str, Any]]:
    """Every occurrence of a run that is not live, each with the event that holds it.

    This is the set the run page's "suppressed" card counts (total minus live), across
    all stages. It mirrors `live_occurrences` exactly: an occurrence is out when a
    kill, defer or merge postdates its last resurrect, and the row shown is the latest
    such event. The card used to link to `?stage=&action=kill`, which rendered nothing
    at all, and would have omitted defers and merges if it had rendered.
    """
    sql = f"""SELECT fe.id, fe.stage, fe.action, fe.reason, fe.deterministic,
                     fe.score_delta,
                     o.id AS occurrence_id, o.path, o.start_line, o.blob_sha,
                     o.producer_id
              FROM occurrences o
              JOIN funnel_events fe ON fe.id = (
                  SELECT MAX(f.id) FROM funnel_events f
                  WHERE f.occurrence_id = o.id
                    AND f.action IN ({','.join('?' * len(SUPPRESSING))}))
              WHERE o.run_id = ?
                AND o.id NOT IN (SELECT id FROM live_occurrences WHERE run_id = ?)
              ORDER BY fe.id LIMIT ?"""
    return [dict(r) for r in con.execute(sql, (*SUPPRESSING, run_id, run_id, limit))]


# ------------------------------------------------------- operator dispositions

def corpus_dismissal_run(con: sqlite3.Connection, producer_id: str) -> int | None:
    """The run whose corpus-wide dismissal is the reason this producer is disabled.

    None when the producer is enabled, or when its disable cannot be traced to a
    dismissal: the latest producer-level operator event must be a kill whose reason
    carries the producer's current dismissal note. Anything else (a disable written by
    another path, or a later re-disable) is not this dismissal's to undo.
    """
    p = con.execute("SELECT enabled, dismissed_note FROM producers WHERE id=?",
                    (producer_id,)).fetchone()
    if p is None or p["enabled"]:
        return None
    e = con.execute(
        """SELECT run_id, action, reason FROM funnel_events
           WHERE producer_id = ? AND occurrence_id IS NULL
             AND actor = 'operator' AND stage = 'operator'
           ORDER BY id DESC LIMIT 1""", (producer_id,)).fetchone()
    if e is None or e["action"] != "kill":
        return None
    if e["reason"] != f"producer disabled corpus-wide: {p['dismissed_note']}":
        return None
    return e["run_id"]


def operator_killed(con: sqlite3.Connection, run_id: int, producer_id: str) -> list[int]:
    """Occurrences in this run that are out ONLY because the operator dismissed them.

    Excludes anything the deterministic funnel also suppressed (a test path, a merged
    duplicate), and anything already live again, so a restore is idempotent.
    """
    return [r["id"] for r in con.execute(
        """SELECT o.id FROM occurrences o
           WHERE o.run_id = ? AND o.producer_id = ?
             AND o.id NOT IN (SELECT id FROM live_occurrences WHERE run_id = ?)
             AND EXISTS (SELECT 1 FROM funnel_events e
                         WHERE e.occurrence_id = o.id AND e.actor = 'operator'
                           AND e.action = 'kill')
             AND NOT EXISTS (SELECT 1 FROM funnel_events e
                             WHERE e.occurrence_id = o.id
                               AND e.actor != 'operator'
                               AND e.action IN ('kill','defer','merge'))""",
        (run_id, producer_id, run_id))]


def restorable(con: sqlite3.Connection, run_id: int, producer_id: str) -> bool:
    """Would `POST /producers/{id}/restore` with this run change anything?"""
    return bool(operator_killed(con, run_id, producer_id)) \
        or corpus_dismissal_run(con, producer_id) == run_id


def run_summary(con: sqlite3.Connection, run_id: int) -> dict[str, Any] | None:
    r = con.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
    if not r:
        return None
    d = dict(r)
    d["total"] = con.execute("SELECT COUNT(*) c FROM occurrences WHERE run_id=?",
                             (run_id,)).fetchone()["c"]
    d["live"] = con.execute("SELECT COUNT(*) c FROM live_occurrences WHERE run_id=?",
                            (run_id,)).fetchone()["c"]
    d["producers"] = con.execute(
        "SELECT COUNT(DISTINCT producer_id) c FROM live_occurrences WHERE run_id=?",
        (run_id,)).fetchone()["c"]
    return d


def all_runs(con: sqlite3.Connection) -> list[dict[str, Any]]:
    return [dict(r) for r in con.execute(f"""
        SELECT r.*,
               (SELECT COUNT(*) FROM occurrences o WHERE o.run_id=r.id) AS total,
               (SELECT COUNT(*) FROM live_occurrences o WHERE o.run_id=r.id) AS live,
               (SELECT COUNT(*) FROM ({LATEST_VERDICTS}) lv
                 WHERE lv.run_id=r.id) AS n_verdicts,
               (SELECT COUNT(*) FROM ({LATEST_VERDICTS}) lv
                 WHERE lv.run_id=r.id AND lv.verdict='confirmed') AS n_confirmed,
               (SELECT COUNT(*) FROM advisories a WHERE a.run_id=r.id) AS n_advisories
        FROM runs r ORDER BY r.id DESC""")]


# ---------------------------------------------------------------- deep mode

def _pid_alive(pid: int | None) -> bool:
    """Is that process still *running*?

    `kill -0` is the cheap check and it is not sufficient: a process that has exited
    but not yet been reaped stays a zombie, keeps its PID table entry, and answers
    `kill -0` successfully. MEASURED — research run 3's worker died at 15:56 and the
    dashboard still read "running · pid 80566 alive" twenty-five minutes later, with
    `ps` showing `STAT Z` and `<defunct>` and no model loaded in ollama.

    That is the same defect 5e7e14a set out to close one layer up. The heartbeat rule
    below does eventually catch it, but STALL_SECONDS is twenty-five minutes, so a
    detached worker's death was invisible for that whole window on the one screen whose
    job is to report it.

    So: `kill -0` first because it is free, then confirm the process is not a zombie.
    """
    if not pid:
        return False
    import os
    import subprocess
    try:
        os.kill(int(pid), 0)
    except (OSError, ValueError, TypeError):
        return False
    # It exists. Whether it is still a process rather than a corpse needs its state.
    try:
        out = subprocess.run(["ps", "-o", "stat=", "-p", str(int(pid))],
                             capture_output=True, text=True, timeout=5, check=False)
    except (OSError, subprocess.SubprocessError, ValueError, TypeError):
        return True          # cannot tell; the heartbeat rule is the backstop
    state = out.stdout.strip()
    if not state:
        return False         # vanished between the two calls
    return not state.startswith("Z")


STALL_SECONDS = 25 * 60          # longer than the slowest observed unit (~7 min) by 3x


def _ago(seconds: float) -> str:
    if seconds < 90:
        return f"{int(seconds)}s"
    if seconds < 5400:
        return f"{int(seconds // 60)}m"
    return f"{seconds / 3600:.1f}h"


#: Statuses only the worker writes, and only on its way out. Never second-guessed, and
#: never signalled.
TERMINAL_STATUSES = ("done", "stopped", "failed")

#: Slack between a process's start (ps reports whole seconds) and the heartbeat it
#: writes when it claims the run.
_START_SLACK = 2.0


def _ps(pid: int | None) -> dict[str, Any] | None:
    """Start time (epoch seconds) and argv tokens for `pid`, or None if unknowable.

    `lstart` is printed in local time in a fixed C-locale layout, so `LC_ALL=C` keeps
    it parseable regardless of the operator's locale. `-ww` stops BSD ps truncating
    the command line to the terminal width.
    """
    import os
    import subprocess
    import time
    try:
        out = subprocess.run(["ps", "-ww", "-o", "lstart=", "-o", "command=",
                              "-p", str(int(pid))],
                             capture_output=True, text=True, timeout=5, check=False,
                             env={**os.environ, "LC_ALL": "C"})
    except (OSError, subprocess.SubprocessError, ValueError, TypeError):
        return None
    parts = out.stdout.split()
    if len(parts) < 6:
        return None
    try:
        start = time.mktime(time.strptime(" ".join(parts[:5]), "%a %b %d %H:%M:%S %Y"))
    except ValueError:
        return None
    return {"start": start, "argv": parts[5:]}


def _utc_epoch(ts: str | None) -> float | None:
    if not ts:
        return None
    try:
        return _dt.datetime.fromisoformat(str(ts)).replace(
            tzinfo=_dt.timezone.utc).timestamp()
    except ValueError:
        return None


def worker_identity(row: dict[str, Any]) -> tuple[bool | None, str]:
    """Is `row['pid']` still this research run's worker? -> (verdict, why).

    True only when both hold:

    * **argv**: the process is `quarry deep <run_id> ...` (via `-m quarry.cli` or the
      console script), for this run's ingest id when the row carries one.
    * **start time**: the process started no later than the run's last heartbeat. The
      worker writes `heartbeat` when it claims the run (runner._claim) and refreshes it
      as it works, so the real worker always started before its own heartbeat. A
      process that received the pid after the worker died necessarily started after
      the last heartbeat that worker wrote.

    Both facts come from columns the runner already writes, so no schema change was
    needed. False means the pid now belongs to something else; None means it could
    not be checked (no heartbeat, or `ps` gave nothing usable). Callers that send a
    signal treat None as no.
    """
    pid = row.get("pid")
    info = _ps(pid)
    if info is None:
        return None, "process details unavailable"
    argv = info["argv"]
    is_quarry = any(t == "quarry.cli" or t == "quarry" or t.endswith("/quarry")
                    for t in argv)
    if not is_quarry or "deep" not in argv:
        return False, f"pid {pid} now belongs to another program"
    run_id = row.get("run_id")
    if run_id is not None:
        i = argv.index("deep")
        if i + 1 >= len(argv) or argv[i + 1] != str(run_id):
            return False, f"pid {pid} is a deep review of a different run"
    hb = _utc_epoch(row.get("heartbeat"))
    if hb is None:
        return None, "no heartbeat recorded to check the process start against"
    if info["start"] > hb + _START_SLACK:
        return False, f"pid {pid} started after this run's last heartbeat (pid reused)"
    return True, ""


def live_status(row: dict[str, Any]) -> tuple[str, str]:
    """-> (status, explanation). Computed by the reader, never trusted from the writer.

    A status column only the worker writes cannot report the worker dying: the first
    deep run showed `running` indefinitely after its process was killed. So the reader
    checks the pid and the heartbeat and states what is actually true.

    A live pid is not enough either: pids are recycled, so the process holding it is
    checked against the run (`worker_identity`). A recycled pid reads as `died`; one
    that cannot be checked reads as `unverified`, which is neither offered a Stop nor
    a Resume.
    """
    stored = row.get("status") or "unknown"
    if stored in TERMINAL_STATUSES:
        return stored, ""
    pid, hb = row.get("pid"), row.get("heartbeat")
    alive = _pid_alive(pid)
    gone = f"pid {pid} is gone"
    if alive:
        ok, why = worker_identity(row)
        if ok:
            return "running", f"pid {pid} alive"
        if ok is None:
            return "unverified", f"pid {pid} is alive but not verified as the worker: {why}"
        alive, gone = False, why
    age = None
    if hb:
        try:
            # SQLite's datetime('now') is UTC. Comparing it against a naive local
            # datetime.now() reports a negative age in any non-UTC zone; it read
            # "-300m ago" on a UTC-5 machine.
            stamp = _dt.datetime.fromisoformat(hb).replace(tzinfo=_dt.timezone.utc)
            age = max(0.0, (_dt.datetime.now(_dt.timezone.utc) - stamp).total_seconds())
        except ValueError:
            age = None
    if pid and not alive:
        return "died", (gone
                        + (f", last activity {_ago(age)} ago" if age is not None else ""))
    if age is not None and age > STALL_SECONDS:
        return "stalled", f"no activity for {_ago(age)}"
    return "unknown", "no pid recorded (started before liveness tracking)"


def research_runs(con: sqlite3.Connection, run_id: int | None = None,
                  rid: int | None = None) -> list[dict[str, Any]]:
    """Deep-review runs, newest first.

    `run_id` filters by the *ingest* run; `rid` filters to one *research* run. The `rid`
    filter exists because `research_detail` needs exactly one row: each row here costs
    five correlated subqueries plus a `live_status()` call, and `live_status` issues an
    `os.kill(pid, 0)` syscall. Rendering one run used to compute all of them, which a
    polling progress fragment would then multiply by the poll rate and the tab count.
    """
    sql = """SELECT rr.*, r.target, r.git_sha,
                    (SELECT COUNT(*) FROM research_units u WHERE u.research_id=rr.id) AS units,
                    (SELECT COUNT(*) FROM research_units u WHERE u.research_id=rr.id
                       AND u.status='done') AS done,
                    (SELECT COUNT(*) FROM research_units u WHERE u.research_id=rr.id
                       AND u.status='error') AS errored,
                    (SELECT COALESCE(SUM(u.seconds),0) FROM research_units u
                       WHERE u.research_id=rr.id) AS seconds,
                    (SELECT COUNT(*) FROM research_findings f WHERE f.research_id=rr.id) AS findings
             FROM research_runs rr JOIN runs r ON r.id = rr.run_id"""
    args: list[Any] = []
    where = []
    if run_id:
        where.append("rr.run_id = ?")
        args.append(run_id)
    if rid:
        where.append("rr.id = ?")
        args.append(rid)
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY rr.id DESC"
    out = []
    for r in con.execute(sql, args):
        d = dict(r)
        d["status"], d["status_why"] = live_status(d)
        d["resumable"] = d["status"] in ("died", "stalled", "stopped", "unknown") \
            and d["done"] + d["errored"] < d["units"]
        out.append(d)
    return out


UNITS_SHOWN = 25
FINDINGS_SHOWN = 60


def research_detail(con: sqlite3.Connection, rid: int) -> dict[str, Any] | None:
    rows = research_runs(con, rid=rid)
    head = rows[0] if rows else None
    if not head:
        return None
    head["n_findings"] = head["findings"]      # the aggregate count from research_runs
    head["profile"] = json.loads(head.get("profile") or "{}")
    head["models"] = json.loads(head.get("models") or "[]")
    head["lenses"] = json.loads(head.get("lenses") or "[]")
    head["by_lens"] = [dict(r) for r in con.execute(
        """SELECT lens,
                  COUNT(*) AS units,
                  SUM(status='done') AS done,
                  SUM(n_findings)    AS findings,
                  ROUND(SUM(seconds)/60.0,1) AS minutes
           FROM research_units WHERE research_id=? GROUP BY lens
           ORDER BY findings DESC, lens""", (rid,))]
    head["by_model"] = [dict(r) for r in con.execute(
        """SELECT model,
                  SUM(status='done') AS done,
                  SUM(n_findings)    AS findings,
                  ROUND(SUM(seconds)/60.0,1) AS minutes
           FROM research_units WHERE research_id=? GROUP BY model
           ORDER BY findings DESC""", (rid,))]
    # In-flight units sort FIRST. The previous order put 'error' then 'done' then
    # everything else, so a unit that was actually running appeared last — the opposite
    # of what someone watching an eight-hour run wants to see.
    #
    # Both lists are capped, and the caps are published so the templates can say
    # "25 of 340" instead of presenting a truncated tail as the whole set. The
    # denominators are `head["units"]` and `head["n_findings"]`.
    head["units_shown_max"] = UNITS_SHOWN
    head["findings_shown_max"] = FINDINGS_SHOWN
    head["running"] = [dict(r) for r in con.execute(
        """SELECT subsystem, lens, model, status, seconds, n_findings, error
           FROM research_units WHERE research_id=?
           ORDER BY CASE status WHEN 'running' THEN 0 WHEN 'error' THEN 1
                                WHEN 'pending' THEN 2 ELSE 3 END,
                    updated_at DESC LIMIT ?""", (rid, UNITS_SHOWN))]
    head["findings"] = [dict(r) for r in con.execute(
        """SELECT * FROM research_findings WHERE research_id=?
           ORDER BY quote_verified DESC, n_survived DESC, n_refuted ASC, id
           LIMIT ?""", (rid, FINDINGS_SHOWN))]
    for f in head["findings"]:
        try:
            f["refutations"] = json.loads(f.get("refutations") or "[]")
        except ValueError:
            f["refutations"] = []
    return head


def ingested_runs(con: sqlite3.Connection) -> list[dict[str, Any]]:
    """Runs that can be deep-reviewed: ingest completed and the volume still exists."""
    return [dict(r) for r in con.execute(
        """SELECT id, target, git_sha, volume_path FROM runs
           WHERE status='done' AND volume_path IS NOT NULL ORDER BY id DESC""")]


# ------------------------------------------------------------------ egress ledger

def egress_ledger(con: sqlite3.Connection, run_id: int | None = None) -> dict[str, Any]:
    """The egress ledger, with its totals.

    `bytes_out` is the number that answers the product's central claim and it was stored
    from the first migration and never rendered. A figure that can change is information;
    a badge that is green in every possible state is decoration.

    `run_id` scopes to one run *and* the global rows (`run_id IS NULL`, e.g. `db sync`),
    because those are real egress that happened on this machine — but every row carries
    `scope` so the page can say which is which. The previous per-run table mixed them
    with no such column, so attribution was wrong on the containment screen.
    """
    sql = """SELECT e.id, e.run_id, e.stage, e.destination, e.bytes_out, e.bytes_in,
                    e.note, e.created_at, r.target
             FROM egress e LEFT JOIN runs r ON r.id = e.run_id"""
    args: list[Any] = []
    if run_id is not None:
        sql += " WHERE e.run_id = ? OR e.run_id IS NULL"
        args.append(run_id)
    sql += " ORDER BY e.id DESC"
    rows = []
    for r in con.execute(sql, args):
        d = dict(r)
        d["scope"] = "global" if d["run_id"] is None else f"run {d['run_id']}"
        rows.append(d)
    return {"rows": rows, **egress_totals(con)}


def egress_totals(con: sqlite3.Connection) -> dict[str, int]:
    """All-time ledger totals, without the rows. The header counter on every page needs
    only these two numbers and used to load the whole ledger to get them."""
    tot = con.execute(
        "SELECT COALESCE(SUM(bytes_out),0) o, COALESCE(SUM(bytes_in),0) i, "
        "COUNT(*) n, COUNT(DISTINCT destination) d FROM egress").fetchone()
    return {"bytes_out": tot["o"], "bytes_in": tot["i"],
            "n_events": tot["n"], "n_destinations": tot["d"]}


def human_bytes(n: int | None) -> str:
    """Byte counts for the header counter. Exact at zero, because zero is the claim."""
    n = int(n or 0)
    if n == 0:
        return "0 B"
    for unit, div in (("GB", 1 << 30), ("MB", 1 << 20), ("kB", 1 << 10)):
        if n >= div:
            return f"{n / div:.1f} {unit}"
    return f"{n} B"


# ------------------------------------------------------- clocks, reconciled

def local(ts: str | None, *, with_date: bool = True) -> str:
    """A stored timestamp, rendered in the operator's own timezone.

    The database speaks two clocks and the UI used to render both side by side:
    `started_at`, `heartbeat`, `created_at` and `updated_at` come from SQLite's
    `datetime('now')`, which is **UTC**; `research_runs.deadline` comes from Python's
    `datetime.now()` in `cli.py`, which is **naive local**. Enforcement is consistent
    (the runner compares local to local), so this was only ever a display defect — but
    it was a five-hour one, and the reader had no way to know which column was which.

    Everything the page shows now goes through here, so one clock is on screen.
    Naive-local values are detected by the `T` separator `datetime.isoformat()` writes
    and passed through unconverted; SQLite's space-separated UTC is converted.
    """
    if not ts:
        return "—"
    text = str(ts)
    fmt = "%Y-%m-%d %H:%M" if with_date else "%H:%M"
    try:
        if "T" in text:                      # isoformat() — already local, naive
            dt = _dt.datetime.fromisoformat(text)
            return dt.strftime(fmt)
        dt = _dt.datetime.strptime(text[:19], "%Y-%m-%d %H:%M:%S")
        dt = dt.replace(tzinfo=_dt.timezone.utc).astimezone()
        return dt.strftime(fmt)
    except (ValueError, TypeError):
        return text


def until(deadline: str | None) -> str:
    """How much of a long run's budget is left, from the clock that enforces it.

    `runner.py` skips remaining units once `datetime.now() >= deadline`, so this reads
    the same naive-local value the same way rather than reconciling against the UTC
    rows around it. The operator's actual decision is "let it finish or stop it", which
    needs a duration, not a timestamp.
    """
    if not deadline:
        return "no deadline"
    try:
        dt = _dt.datetime.fromisoformat(str(deadline))
    except (ValueError, TypeError):
        return str(deadline)
    secs = (dt - _dt.datetime.now()).total_seconds()
    if secs <= 0:
        return "deadline passed"
    h, m = divmod(int(secs // 60), 60)
    return f"{h}h {m:02d}m left" if h else f"{m}m left"


def elapsed(started_at: str | None) -> str:
    """Wall time since a run started. UTC in, duration out."""
    if not started_at:
        return "—"
    try:
        dt = _dt.datetime.strptime(str(started_at)[:19], "%Y-%m-%d %H:%M:%S")
        dt = dt.replace(tzinfo=_dt.timezone.utc)
    except (ValueError, TypeError):
        return "—"
    secs = (_dt.datetime.now(_dt.timezone.utc) - dt).total_seconds()
    if secs < 0:
        return "—"
    h, m = divmod(int(secs // 60), 60)
    return f"{h}h {m:02d}m" if h else f"{m}m"


# ------------------------------------------------------------------ verdicts
#
# `verdicts` is append-only: validate writes a new row every time it probes, so the
# current state of anything is its LATEST row. The unit everywhere below is one
# (run, finding, seat, model) slot: for the dynamic seat `model` holds the lens key,
# so a finding probed by two lenses has two slots and two verdicts. Counts on screen
# are counts of slots, and the pages say so.

VERDICT_STATES = ("confirmed", "needs-review", "rejected")

#: The latest verdict in each (run, finding, seat, model) slot.
LATEST_VERDICTS = """
    SELECT v.* FROM verdicts v
    JOIN (SELECT MAX(id) AS id FROM verdicts
          GROUP BY run_id, finding_id, seat, model) latest ON latest.id = v.id"""

#: The rationale keys validate.record_verdict writes, in display order.
RATIONALE_KEYS = ("summary", "request", "observed", "baseline", "differs_from_baseline",
                  "determinism")


def _rationale(text: str | None) -> tuple[dict[str, Any] | None, str | None]:
    """-> (parsed fields, raw text). The raw text is returned when it is not a JSON
    object, so a hand-written or older rationale is still shown rather than hidden."""
    if not text:
        return None, None
    try:
        obj = json.loads(text)
    except ValueError:
        return None, text
    if not isinstance(obj, dict):
        return None, text
    return obj, None


def _decorate_verdict(d: dict[str, Any]) -> dict[str, Any]:
    d["fields"], d["raw_rationale"] = _rationale(d.get("rationale"))
    d["summary"] = (d["fields"] or {}).get("summary")
    return d


def verdicts_for_finding(con: sqlite3.Connection,
                         finding_id: str | None) -> list[dict[str, Any]]:
    """The latest verdict per seat and lens for one finding, across runs.

    A verdict carries forward across runs on finding_id (it is line-number-free), so
    the detail pane shows every slot, each labelled with the run that wrote it.
    """
    if not finding_id:
        return []
    rows = con.execute(
        f"""SELECT lv.* FROM ({LATEST_VERDICTS}) lv
            WHERE lv.finding_id = ?
            ORDER BY lv.run_id DESC, lv.seat, lv.model""", (finding_id,)).fetchall()
    return [_decorate_verdict(dict(r)) for r in rows]


def verdict_counts(con: sqlite3.Connection, run_id: int | None = None) -> dict[str, int]:
    """Latest-verdict slot counts per state, for one run or all of them."""
    sql = f"SELECT verdict, COUNT(*) n FROM ({LATEST_VERDICTS}) lv"
    args: list[Any] = []
    if run_id is not None:
        sql += " WHERE lv.run_id = ?"
        args.append(run_id)
    sql += " GROUP BY verdict"
    out = {s: 0 for s in VERDICT_STATES}
    for r in con.execute(sql, args):
        out[r["verdict"]] = r["n"]
    out["total"] = sum(out[s] for s in VERDICT_STATES)
    return out


def latest_verdicts(con: sqlite3.Connection, run_id: int | None = None,
                    state: str | None = None, limit: int = 500) -> list[dict[str, Any]]:
    """Latest verdict per slot, newest first, with what the evidence link needs.

    `occurrence_id` is the finding's first occurrence in the verdict's run, which is
    what /evidence renders. An unknown `state` yields nothing rather than silently
    widening to every state.
    """
    if state is not None and state not in VERDICT_STATES:
        return []
    sql = f"""SELECT lv.id, lv.run_id, lv.finding_id, lv.seat, lv.model, lv.verdict,
                     lv.reason, lv.cwe, lv.executed_score, lv.evidence_score,
                     lv.created_at, lv.rationale, r.target,
                     f.path, f.symbol,
                     (SELECT MIN(o.id) FROM occurrences o
                       WHERE o.finding_id = lv.finding_id AND o.run_id = lv.run_id)
                       AS occurrence_id
              FROM ({LATEST_VERDICTS}) lv
              JOIN runs r ON r.id = lv.run_id
              LEFT JOIN findings f ON f.id = lv.finding_id"""
    where: list[str] = []
    args: list[Any] = []
    if run_id is not None:
        where.append("lv.run_id = ?")
        args.append(run_id)
    if state:
        where.append("lv.verdict = ?")
        args.append(state)
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY lv.id DESC LIMIT ?"
    args.append(limit)
    return [_decorate_verdict(dict(r)) for r in con.execute(sql, args)]


#: A WHERE fragment over `live_occurrences o`: the occurrence's finding has a latest
#: verdict in state `?` in run `?`. Bind (run_id, state) in that order.
FINDING_HAS_VERDICT = (f"o.finding_id IN (SELECT lv.finding_id FROM ({LATEST_VERDICTS}) lv "
                       "WHERE lv.run_id = ? AND lv.verdict = ?)")


# ------------------------------------------------------------------ advisories

def advisories(con: sqlite3.Connection, run_id: int | None = None) -> list[dict[str, Any]]:
    """Advisory drafts `quarry report` recorded (migration _v8), newest first."""
    sql = """SELECT a.*, r.target, v.verdict, v.model, f.path AS finding_path, f.symbol
             FROM advisories a
             JOIN runs r ON r.id = a.run_id
             LEFT JOIN verdicts v ON v.id = a.verdict_id
             LEFT JOIN findings f ON f.id = a.finding_id"""
    args: list[Any] = []
    if run_id is not None:
        sql += " WHERE a.run_id = ?"
        args.append(run_id)
    sql += " ORDER BY a.id DESC"
    return [dict(r) for r in con.execute(sql, args)]


def advisory(con: sqlite3.Connection, aid: int) -> dict[str, Any] | None:
    r = con.execute(
        """SELECT a.*, r.target, r.git_sha, v.verdict, v.model, v.seat,
                  f.path AS finding_path, f.symbol,
                  (SELECT MIN(o.id) FROM occurrences o
                    WHERE o.finding_id = a.finding_id AND o.run_id = a.run_id)
                    AS occurrence_id
           FROM advisories a
           JOIN runs r ON r.id = a.run_id
           LEFT JOIN verdicts v ON v.id = a.verdict_id
           LEFT JOIN findings f ON f.id = a.finding_id
           WHERE a.id = ?""", (aid,)).fetchone()
    return dict(r) if r else None


def advisory_count(con: sqlite3.Connection, run_id: int) -> int:
    return con.execute("SELECT COUNT(*) c FROM advisories WHERE run_id=?",
                       (run_id,)).fetchone()["c"]


# ------------------------------------------------------------------ pipeline strip

def pipeline(con: sqlite3.Connection, run: dict[str, Any]) -> list[dict[str, Any]]:
    """The five stages of one run, each with its count and the set that count opens.

    Every count is a link, like every other number in the product. Ingest counts what
    it quarantined; scan counts raw occurrences and the tools that produced them; the
    funnel counts what is still live; validate counts latest-verdict slots; report
    counts advisory drafts recorded for the run.
    """
    rid = run["id"]
    quarantined = con.execute("SELECT COUNT(*) c FROM quarantined WHERE run_id=?",
                              (rid,)).fetchone()["c"]
    tools = con.execute(
        "SELECT COUNT(DISTINCT p.tool) c FROM occurrences o "
        "JOIN producers p ON p.id = o.producer_id WHERE o.run_id=?",
        (rid,)).fetchone()["c"]
    vc = verdict_counts(con, rid)
    return [
        {"name": "Ingest", "n": quarantined, "unit": "quarantined",
         "href": f"/runs/{rid}#quarantine"},
        {"name": "Scan", "n": run["total"], "unit": f"raw, {tools} tool(s)",
         "href": f"/runs/{rid}#funnel"},
        {"name": "Funnel", "n": run["live"], "unit": "live",
         "href": f"/triage?run={rid}"},
        {"name": "Validate", "n": vc["total"], "unit": f"verdicts, {vc['confirmed']} confirmed",
         "href": f"/validation?run={rid}"},
        {"name": "Report", "n": advisory_count(con, rid), "unit": "drafts",
         "href": f"/advisories?run={rid}"},
    ]
