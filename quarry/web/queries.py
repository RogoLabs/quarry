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
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .. import db, dismissals

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


#: A WHERE fragment over `live_occurrences o`: the occurrence is ready for triage.
#: A deep-review candidate is ready only once a funnel pass has seen it, which means
#: it cleared the Layer 2 gate: a gate failure is a kill or a defer, so a live deep
#: occurrence with any funnel event passed. Before this, candidates that no pass had
#: seen (a review still running, or one finished since the last `quarry funnel`)
#: reached triage with their quote unchecked and their refutation unread. An
#: operator event does not count: dismissing is not funnelling.
TRIAGE_READY = """(o.producer_id NOT IN (SELECT id FROM producers WHERE tool = 'deep')
     OR EXISTS (SELECT 1 FROM funnel_events g
                WHERE g.occurrence_id = o.id AND g.stage != 'operator'))"""


def held_for_funnel(con: sqlite3.Connection, run_id: int) -> int:
    """Live deep-review candidates that triage holds back until a funnel pass has
    seen them. The triage page states this number, so the live count above the
    console still adds up."""
    return con.execute(
        f"SELECT COUNT(*) c FROM live_occurrences o WHERE o.run_id = ? "
        f"AND NOT {TRIAGE_READY}", (run_id,)).fetchone()["c"]


def producer_groups(con: sqlite3.Connection, run_id: int,
                    verdict: str | None = None) -> list[ProducerGroup]:
    """Live findings, grouped by producer, banded and ordered for triage.

    `verdict` narrows to occurrences whose finding's latest verdict in this run is in
    that state (see FINDING_HAS_VERDICT); an unknown state yields no groups. Deep
    candidates no funnel pass has seen are left out (TRIAGE_READY)."""
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
        WHERE o.run_id = ? AND """ + TRIAGE_READY + extra + """
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
        WHERE o.run_id = ? AND o.producer_id = ? AND """ + TRIAGE_READY + extra + """
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
        "SELECT COUNT(*) c FROM live_occurrences o WHERE o.run_id=? AND o.producer_id=? "
        "AND " + TRIAGE_READY + extra, (run_id, producer_id, *args)).fetchone()["c"]


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


def research_finding(con: sqlite3.Connection, oid: int) -> dict[str, Any] | None:
    """The deep-review record behind an occurrence, or None for a scanner's.

    A deep occurrence used to show in the detail pane like any scanner hit: no model,
    no quote check, no refutation. Those are the facts its Layer 2 gate decided on,
    so the pane shows them and links back to the research run."""
    r = con.execute(
        """SELECT rf.id, rf.research_id, rf.lens, rf.model, rf.family, rf.title,
                  rf.quote_verified, rf.n_refuted, rf.n_survived, rf.refuter_errors,
                  rf.n_unsupported, rf.refutations, rr.run_id
           FROM research_findings rf JOIN research_runs rr ON rr.id = rf.research_id
           WHERE rf.occurrence_id = ? ORDER BY rf.id LIMIT 1""", (oid,)).fetchone()
    if r is None:
        return None
    d = dict(r)
    try:
        refs = json.loads(d.get("refutations") or "[]")
    except ValueError:
        refs = []
    d["refutations"] = [x for x in refs if isinstance(x, dict)] \
        if isinstance(refs, list) else []
    return d


def provenance(con: sqlite3.Connection, oid: int) -> list[dict[str, Any]]:
    """Every ledger event for one finding. This is what makes the rank auditable."""
    return [dict(r) for r in con.execute(
        "SELECT stage,action,deterministic,reason,score_delta,merged_into,actor,created_at "
        "FROM funnel_events WHERE occurrence_id=? ORDER BY id", (oid,))]


#: The run-page row for occurrences no funnel stage has seen. Not a ledger stage.
ARRIVED_AFTER_FUNNEL = "arrived after the funnel"


def funnel_stages(con: sqlite3.Connection, run_id: int) -> list[dict[str, Any]]:
    """Per-stage counts for /runs/:id. Every number here links to its own set —
    that is a build constraint, not a nicety (Seat 4).

    Counts come from the ledger, the same rows each cell's link opens. They came from
    the manifest snapshot, which disagreed with its own links twice: cross-tool-cluster
    reported a boost it never wrote, and operator dismissals, written after the
    snapshot, never appeared. The manifest still supplies the stage order and the
    stages that wrote no rows, so they show as zeroes rather than vanish.

    `remaining` is derived from the ledger too, so it holds across funnel passes: the
    occurrences that entered the funnel, less each stage's kills, defers and merges,
    plus the ones that stage itself brought back (the Layer 2 gate revives a deferred
    deep candidate once its refutation is in).

    Occurrences that no funnel pass has seen yet get their own row, so the table ends
    where the "live" card does. `drift` on the last row is the difference between the
    two, which should be zero.
    """
    import json as _json
    snapshot: list[dict[str, Any]] = []
    row = con.execute("SELECT manifest FROM runs WHERE id=?", (run_id,)).fetchone()
    if row and row["manifest"]:
        try:
            f = _json.loads(row["manifest"]).get("funnel")
        except (ValueError, TypeError):
            f = None
        if f and f.get("stages"):
            snapshot = [s for s in f["stages"] if isinstance(s, dict) and s.get("stage")]

    counts: dict[str, dict[str, int]] = defaultdict(dict)
    for r in con.execute(
            "SELECT stage, action, COUNT(*) n FROM funnel_events WHERE run_id=? "
            "AND occurrence_id IS NOT NULL GROUP BY stage, action", (run_id,)):
        counts[r["stage"]][r["action"]] = r["n"]
    ledger = con.execute("""
        SELECT stage, MIN(id) AS first_id, MIN(deterministic) AS d FROM funnel_events
        WHERE run_id=? GROUP BY stage ORDER BY first_id""", (run_id,)).fetchall()

    def stage_row(name: str, heuristic: bool) -> dict[str, Any]:
        c = counts.get(name, {})
        return {"stage": name, "heuristic": heuristic, "remaining": None,
                **{a: c.get(a, 0) for a in FUNNEL_ACTIONS},
                "restored": c.get("resurrect", 0)}

    heuristic = {r["stage"]: r["d"] == 0 for r in ledger}
    out = [stage_row(s["stage"], bool(s.get("heuristic")) or heuristic.get(s["stage"], False))
           for s in snapshot]
    seen = {s["stage"] for s in out}
    # Stages written after the snapshot, or every stage on a run with no snapshot.
    later = [stage_row(r["stage"], r["d"] == 0)
             for r in ledger if r["stage"] not in seen]
    funnel_ran = bool(out) or any(s["stage"] != "operator" for s in later)
    if not funnel_ran:
        return out + later

    funnel_rows = out + [s for s in later if s["stage"] != "operator"]
    rem = con.execute(
        "SELECT COUNT(DISTINCT occurrence_id) c FROM funnel_events WHERE run_id=? "
        "AND stage != 'operator' AND occurrence_id IS NOT NULL", (run_id,)).fetchone()["c"]
    for s in funnel_rows:
        rem += s["restored"] - s["kill"] - s["defer"] - s["merge"]
        s["remaining"] = rem
    after = [s for s in later if s["stage"] == "operator"]
    if n := arrived_total(con, run_id):
        after.insert(0, {"stage": ARRIVED_AFTER_FUNNEL, "arrived": n, "heuristic": False,
                         "remaining": rem + n,
                         **{a: 0 for a in FUNNEL_ACTIONS}, "restored": 0})
    for s in after:
        if s["stage"] == "operator":
            rem += s["restored"] - s["kill"] - s["defer"] - s["merge"]
            s["remaining"] = rem
        else:
            rem = s["remaining"]
    rows = funnel_rows + after
    # The ledger arithmetic should land on the live count. If it does not, say so on
    # the row rather than quietly replace it: a gap here is a ledger defect.
    live = con.execute("SELECT COUNT(*) c FROM live_occurrences WHERE run_id=?",
                       (run_id,)).fetchone()["c"]
    rows[-1]["drift"] = live - rows[-1]["remaining"]
    return rows


_ARRIVED_SQL = """FROM occurrences o
    WHERE o.run_id = ?
      AND NOT EXISTS (SELECT 1 FROM funnel_events f
                      WHERE f.occurrence_id = o.id AND f.stage != 'operator')"""


def arrived_total(con: sqlite3.Connection, run_id: int) -> int:
    """Occurrences of a run that no funnel stage has seen. An operator dismissal is
    not a funnel stage, so a dismissed arrival still counts as one."""
    return con.execute(f"SELECT COUNT(*) c {_ARRIVED_SQL}", (run_id,)).fetchone()["c"]


def arrived(con: sqlite3.Connection, run_id: int, limit: int = 300) -> list[dict[str, Any]]:
    """The set behind the "arrived after the funnel" row, shaped like `suppressed()`."""
    return [dict(r) for r in con.execute(
        f"""SELECT NULL AS id, NULL AS stage, 'arrived' AS action,
                   'no funnel stage has seen this occurrence' AS reason,
                   1 AS deterministic, 0 AS score_delta,
                   o.id AS occurrence_id, o.path, o.start_line, o.blob_sha, o.producer_id
            {_ARRIVED_SQL} ORDER BY o.id LIMIT ?""", (run_id, limit))]


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
    # Corpus-scope rows only: a repo dismissal written later is also a producer-level
    # operator row, and must not hide the corpus one from its own restore.
    e = dismissals.latest_corpus_event(con, producer_id)
    if e is None or e["action"] != "kill":
        return None
    if e["reason"] != dismissals.reason(dismissals.CORPUS_PREFIX, p["dismissed_note"]):
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


def restorable_occurrences(con: sqlite3.Connection, run_id: int,
                           producer_id: str) -> list[int]:
    """Occurrences in this run that are out only because of a dismissal.

    Wider than `operator_killed`: a dismissal also holds out the occurrences the
    funnel killed on its behalf (`dismissals.FUNNEL_REASONS` at `rule-precision-prior`)
    in a later run or a later pass, and undoing the dismissal must bring those back
    too. Narrower than a resurrect: anything else holding the occurrence out since
    its last resurrect (a test path, a merged duplicate, a Layer 2 kill) keeps it out,
    because a resurrect clears every suppression at once.
    """
    reasons = dismissals.FUNNEL_REASONS
    by_dismissal = (f"(e.actor = 'operator' OR (e.stage = ? AND e.action = 'kill' "
                    f"AND e.reason IN ({','.join('?' * len(reasons))})))")
    dargs = (dismissals.FUNNEL_STAGE, *reasons)
    return [r["id"] for r in con.execute(
        f"""SELECT o.id FROM occurrences o
            WHERE o.run_id = ? AND o.producer_id = ?
              AND o.id NOT IN (SELECT id FROM live_occurrences WHERE run_id = ?)
              AND NOT EXISTS (
                  SELECT 1 FROM funnel_events e
                  WHERE e.occurrence_id = o.id
                    AND e.action IN ('kill','defer','merge')
                    AND e.id > COALESCE((SELECT MAX(r.id) FROM funnel_events r
                                         WHERE r.occurrence_id = o.id
                                           AND r.action = 'resurrect'), 0)
                    AND NOT {by_dismissal})
            ORDER BY o.id""",
        (run_id, producer_id, run_id, *dargs))]


def restorable(con: sqlite3.Connection, run_id: int, producer_id: str) -> bool:
    """Would `POST /producers/{id}/restore` with this run change anything?"""
    if restorable_occurrences(con, run_id, producer_id) \
            or corpus_dismissal_run(con, producer_id) == run_id:
        return True
    run = con.execute("SELECT target FROM runs WHERE id=?", (run_id,)).fetchone()
    return bool(run) and dismissals.repo_dismissal(con, producer_id, run["target"]) is not None


def dismissals_for_run(con: sqlite3.Connection, run_id: int) -> list[dict[str, Any]]:
    """Every dismissal that reaches this run, with what a restore here would do.

    Without this list a dismissal made in an earlier run was invisible from the run
    it affected: the funnel killed the producer's new occurrences, and nothing on the
    page said which decision had done it or offered to undo it.

    `held` counts this run's occurrences the dismissal holds out (what a restore
    brings back). `undoes_switch` says whether a restore from this run also lifts the
    dismissal itself: always for a repo dismissal, which is keyed on the target, and
    for a corpus one only from the run that made it. Scope `run` is a dismissal from
    before repo dismissals were keyed on the target: it held this run's occurrences
    and nothing else.
    """
    run = con.execute("SELECT target FROM runs WHERE id=?", (run_id,)).fetchone()
    if run is None:
        return []
    out: list[dict[str, Any]] = []
    for p in con.execute(
            """SELECT p.id, p.dismissed_note, p.dismissed_at FROM producers p
               WHERE p.enabled = 0 AND EXISTS (SELECT 1 FROM occurrences o
                                               WHERE o.producer_id = p.id AND o.run_id = ?)
               ORDER BY p.id""", (run_id,)):
        made = corpus_dismissal_run(con, p["id"])
        out.append({"producer_id": p["id"], "scope": "corpus", "note": p["dismissed_note"],
                    "since": p["dismissed_at"], "from_run": made,
                    "undoes_switch": made == run_id})
    for pid, rec in sorted(dismissals.repo_dismissals(con, run["target"]).items()):
        out.append({"producer_id": pid, "scope": "repo", "note": rec["note"],
                    "since": rec["created_at"], "from_run": rec["run_id"],
                    "undoes_switch": True})
    listed = {d["producer_id"] for d in out}
    for r in con.execute(
            """SELECT DISTINCT e.producer_id FROM funnel_events e
               WHERE e.run_id = ? AND e.actor = 'operator' AND e.action = 'kill'
                 AND e.occurrence_id IS NOT NULL ORDER BY e.producer_id""", (run_id,)):
        if r["producer_id"] not in listed:
            out.append({"producer_id": r["producer_id"], "scope": "run", "note": None,
                        "since": None, "from_run": run_id, "undoes_switch": False})
    for d in out:
        d["held"] = len(restorable_occurrences(con, run_id, d["producer_id"]))
    return [d for d in out if d["scope"] != "run" or d["held"]]


# ------------------------------------------------- small reads the routes used to inline

def has_runs(con: sqlite3.Connection) -> bool:
    return con.execute("SELECT 1 FROM runs LIMIT 1").fetchone() is not None


def run_ids(con: sqlite3.Connection) -> list[int]:
    """Every run id, newest first."""
    return [r["id"] for r in con.execute("SELECT id FROM runs ORDER BY id DESC")]


def latest_run(con: sqlite3.Connection) -> int | None:
    """The newest run worth opening.

    `status='done'` alone meant that during your first scan `/triage` told you to
    go and run a scan. A run in flight is a better answer than an empty state.
    """
    r = con.execute("SELECT id FROM runs WHERE status='done' ORDER BY id DESC "
                    "LIMIT 1").fetchone()
    if r:
        return r["id"]
    r = con.execute("SELECT id FROM runs WHERE status='running' ORDER BY id DESC "
                    "LIMIT 1").fetchone()
    return r["id"] if r else None


def run_volume(con: sqlite3.Connection, run_id: int) -> dict[str, Any] | None:
    """A run's status and volume path: what deep review needs to start."""
    r = con.execute("SELECT status, volume_path FROM runs WHERE id=?",
                    (run_id,)).fetchone()
    return dict(r) if r else None


def producer_exists(con: sqlite3.Connection, producer_id: str) -> bool:
    return con.execute("SELECT 1 FROM producers WHERE id=?",
                       (producer_id,)).fetchone() is not None


def quarantined(con: sqlite3.Connection, run_id: int) -> list[dict[str, Any]]:
    """What ingest moved aside for a run."""
    return [dict(r) for r in con.execute(
        "SELECT kind,original_path,detail FROM quarantined WHERE run_id=?", (run_id,))]


def research_row(con: sqlite3.Connection, rid: int) -> dict[str, Any] | None:
    """The columns `/research/{id}/stop` checks before it signals anything."""
    r = con.execute("SELECT id, run_id, pid, status, heartbeat FROM research_runs "
                    "WHERE id=?", (rid,)).fetchone()
    return dict(r) if r else None


def research_claim_state(con: sqlite3.Connection, rid: int) -> dict[str, Any] | None:
    """The columns a resume claim overwrites, kept so a failed spawn can put them
    back (writes.release_research_claim)."""
    r = con.execute("SELECT status, pid, heartbeat FROM research_runs WHERE id=?",
                    (rid,)).fetchone()
    return dict(r) if r else None


def occurrence_detail(con: sqlite3.Connection, oid: int) -> dict[str, Any] | None:
    """One occurrence with everything the detail pane shows: its evidence window,
    its ledger events, its verdicts and, for a deep candidate, its research record.
    Triage and /evidence assembled this separately, line for line."""
    d = occurrence(con, oid)
    if not d:
        return None
    d["evidence"] = evidence(con, d["blob_sha"])
    d["provenance"] = provenance(con, oid)
    d["verdicts"] = verdicts_for_finding(con, d["finding_id"])
    d["research"] = research_finding(con, oid)
    return d


def run_summary(con: sqlite3.Connection, run_id: int) -> dict[str, Any] | None:
    r = con.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
    if not r:
        return None
    d = dict(r)
    d["total"] = con.execute("SELECT COUNT(*) c FROM occurrences WHERE run_id=?",
                             (run_id,)).fetchone()["c"]
    d["live"] = con.execute("SELECT COUNT(*) c FROM live_occurrences WHERE run_id=?",
                            (run_id,)).fetchone()["c"]
    # The producers triage lists, so the card and the console agree.
    d["producers"] = con.execute(
        "SELECT COUNT(DISTINCT o.producer_id) c FROM live_occurrences o "
        f"WHERE o.run_id=? AND {TRIAGE_READY}", (run_id,)).fetchone()["c"]
    d["held"] = held_for_funnel(con, run_id)
    m = db.read_manifest(con, run_id)
    tools = (m.get("scan") or {}).get("tools") or {}
    d["scan_tools"] = [{"tool": t, **i} for t, i in sorted(tools.items())
                       if isinstance(i, dict)]
    for t in d["scan_tools"]:
        # Runs scanned before `nothing_to_scan` was recorded: any note read as
        # "nothing to scan", which mislabelled opengrep's per-tree recovery. A note
        # with zero records is the closest reading of those older rows.
        t.setdefault("nothing_to_scan", bool(t.get("note")) and not t.get("records"))
    d["health"] = [{"source": src, "tool": tool, "message": msg}
                   for src, by_tool in sorted((m.get("health") or {}).items())
                   if isinstance(by_tool, dict)
                   for tool, msgs in sorted(by_tool.items()) for msg in (msgs or [])]
    # The vulnerability databases a scan read, and how old each was then. A clean
    # Trivy or OSV result is only as good as its database, and that age was printed
    # by `doctor` and stored by `scan` but never shown beside the result.
    from ..vulndb import STALE_DAYS
    d["stale_days"] = STALE_DAYS
    d["vulndb"] = []
    for name, a in sorted((m.get("vulndb") or {}).items()):
        if not isinstance(a, dict):
            continue
        age = a.get("age_days")
        d["vulndb"].append({"name": name, "built": a.get("built"), "age_days": age,
                            "basis": a.get("basis") or "",
                            "stale": not isinstance(age, (int, float)) or age > STALE_DAYS})
    return d


def scan_outcome(t: dict[str, Any]) -> str:
    """One word for a `run_summary()["scan_tools"]` row, in run.html's pill order:
    a skip wins over a failure, and a failure over nothing-to-scan."""
    if t.get("skipped"):
        return "skipped"
    if not t.get("ok"):
        return "failed"
    return "nothing to scan" if t.get("nothing_to_scan") else "ok"


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


def _deep_argv(argv: list[str], pid: Any, run_id: Any) -> tuple[bool, str]:
    """Is this command line `quarry deep <run_id> ...`? -> (verdict, why not)."""
    is_quarry = any(t == "quarry.cli" or t == "quarry" or t.endswith("/quarry")
                    for t in argv)
    if not is_quarry or "deep" not in argv:
        return False, f"pid {pid} now belongs to another program"
    if run_id is not None:
        i = argv.index("deep")
        if i + 1 >= len(argv) or argv[i + 1] != str(run_id):
            return False, f"pid {pid} is a deep review of a different run"
    return True, ""


#: The status the dashboard writes when it claims a research run for a resume, before
#: it spawns the worker. Only the reader interprets it (`_resume_status`); the worker
#: overwrites it with `running` when it claims the run itself (runner._claim).
RESUMING = "resuming"

#: How long a claimed resume may go without a worker pid before the claim counts as
#: failed and the run can be resumed again. The pid is recorded right after the
#: spawn returns, so this only matters when the spawn itself went wrong.
CLAIM_GRACE_SECONDS = 120


def _resume_status(row: dict[str, Any]) -> tuple[str, str]:
    """`live_status` for a run the dashboard has claimed for a resume.

    The claim exists so a second Resume, from another tab or a double click, is
    refused instead of starting a second worker on the same units: the second request
    sees `starting`, which is neither resumable nor stoppable. If the spawned process
    is gone, or never recorded, the claim lapses to `died` and Resume is offered again.

    The heartbeat check in `worker_identity` does not apply here: the heartbeat is the
    claim's own timestamp, written before the worker existed, so the worker always
    started after it. The command line is still checked, because pids are recycled.
    """
    pid = row.get("pid")
    if pid:
        if not _pid_alive(pid):
            return "died", f"the resumed worker (pid {pid}) exited before claiming the run"
        info = _ps(pid)
        if info is None:
            return "starting", f"resume requested; pid {pid} is alive but not yet verified"
        ok, why = _deep_argv(info["argv"], pid, row.get("run_id"))
        if not ok:
            return "died", why
        return "starting", f"resume requested; worker pid {pid} is starting"
    claimed = _utc_epoch(row.get("heartbeat"))
    age = None if claimed is None else max(0.0, _dt.datetime.now(
        _dt.timezone.utc).timestamp() - claimed)
    if age is None or age > CLAIM_GRACE_SECONDS:
        return "died", ("a resume was requested"
                        + (f" {_ago(age)} ago" if age is not None else "")
                        + " and no worker started")
    return "starting", f"resume requested {_ago(age)} ago; waiting for the worker"


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
    ok, why = _deep_argv(info["argv"], pid, row.get("run_id"))
    if not ok:
        return False, why
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
    if stored == RESUMING:
        return _resume_status(row)
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
    # Each candidate carries where its occurrence stands, so the card can link to it:
    # into triage when it is there, otherwise to its evidence and ledger, which say
    # what the funnel did with it.
    head["findings"] = [dict(r) for r in con.execute(
        f"""SELECT rf.*, o.run_id AS occ_run, o.producer_id AS occ_producer,
                   EXISTS (SELECT 1 FROM live_occurrences l
                           WHERE l.id = rf.occurrence_id) AS occ_live,
                   EXISTS (SELECT 1 FROM funnel_events g
                           WHERE g.occurrence_id = rf.occurrence_id
                             AND g.stage != 'operator') AS occ_funnelled
            FROM research_findings rf
            LEFT JOIN occurrences o ON o.id = rf.occurrence_id
            WHERE rf.research_id=?
            ORDER BY rf.quote_verified DESC, rf.n_survived DESC, rf.n_refuted ASC, rf.id
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
    and passed through unconverted; SQLite's space-separated UTC is converted. An
    isoformat value that carries its own offset (a database build time in the run
    manifest) says which clock it is on, so it is converted too.
    """
    if not ts:
        return "—"
    text = str(ts)
    fmt = "%Y-%m-%d %H:%M" if with_date else "%H:%M"
    try:
        if "T" in text:                      # isoformat() — local unless it says not
            dt = _dt.datetime.fromisoformat(text)
            if dt.tzinfo is not None:
                dt = dt.astimezone()
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

#: The rationale keys validate.record_verdict writes, in display order. reproduces_when
#: says which way differs_from_baseline reads: "same" for a missing defence (rate limit).
RATIONALE_KEYS = ("summary", "request", "observed", "baseline", "differs_from_baseline",
                  "reproduces_when", "determinism")


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


def verdict_counts_by_seat(con: sqlite3.Connection, run_id: int) -> dict[str, dict[str, int]]:
    """`verdict_counts` for one run, split by seat. The dynamic seat is a probe that
    ran; any other seat is a reviewer's opinion, and a sum across them hides which."""
    out: dict[str, dict[str, int]] = {}
    for r in con.execute(f"SELECT seat, verdict, COUNT(*) n FROM ({LATEST_VERDICTS}) lv "
                         "WHERE lv.run_id = ? GROUP BY seat, verdict ORDER BY seat",
                         (run_id,)):
        out.setdefault(r["seat"], {s: 0 for s in VERDICT_STATES})[r["verdict"]] = r["n"]
    for counts in out.values():
        counts["total"] = sum(counts[s] for s in VERDICT_STATES)
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


def digest(con: sqlite3.Connection, run_id: int,
           reports_root: "Path | None") -> dict[str, Any] | None:
    """The Layer 2 deep-review digest `quarry report` wrote for a run, or None.

    `quarry report` writes it beside the advisory drafts, and the dashboard said
    "0 drafts" next to it because no table recorded it. The run manifest now does
    (`disclosure.record_digest`), with the hash of what was written. A digest written
    before that is found at its default path and shown as unrecorded, with no hash to
    compare. Whether the file may be read is not decided here: the page that opens it
    applies the same confinement to <data root>/reports as an advisory.
    """
    from ..disclosure.report import digest_name
    rec = (db.read_manifest(con, run_id).get("report") or {})
    rec = rec.get("digest") if isinstance(rec, dict) else None
    if isinstance(rec, dict) and rec.get("path"):
        return {"run_id": run_id, "path": str(rec["path"]), "sha256": rec.get("sha256"),
                "n_findings": rec.get("n_findings"), "written_at": rec.get("written_at"),
                "recorded": True}
    if reports_root is not None:
        p = reports_root / str(run_id) / digest_name(run_id)
        if p.is_file():
            return {"run_id": run_id, "path": str(p), "sha256": None, "n_findings": None,
                    "written_at": None, "recorded": False}
    return None


# ------------------------------------------------- stages that run from the terminal
#
# Doctor, db sync, target scoring, ingest, scan, funnel, validate and report run only
# from the CLI, and several of them reach the network. The dashboard does not run any
# of them. It shows what each one last left behind and the command that runs it,
# shell-quoted, because a target name is text from a database and the command is
# meant to be pasted into a terminal.

def shell(*args: Any) -> str:
    """A command line with each argument quoted for a POSIX shell."""
    import shlex
    return " ".join(shlex.quote(str(a)) for a in args)


def run_stages(con: sqlite3.Connection, run: dict[str, Any],
               reports_root: "Path | None" = None) -> list[dict[str, Any]]:
    """Each CLI stage of one run: what it last did, and the command that runs it.

    Read from what the run already records (status, manifest, ledger, verdicts,
    advisory rows), so it costs no process and no network. `status` is a short state,
    `detail` says what that rests on, and `cmd` is the command to run next or again.
    """
    rid, target = run["id"], run["target"]
    m = db.read_manifest(con, rid)
    out: list[dict[str, Any]] = []

    ingest_detail = f"run status {run['status']}"
    if run["status"] == "done" and not run.get("volume_path"):
        ingest_detail += "; volume released, so deep review and validate need a new ingest"
    out.append({"stage": "Ingest", "status": run["status"], "detail": ingest_detail,
                "cmd": shell("quarry", "ingest", target),
                "note": "makes a new run of this target"})

    tools = run.get("scan_tools") or []
    n_scan = con.execute(
        "SELECT COUNT(*) c FROM occurrences o JOIN producers p ON p.id = o.producer_id "
        "WHERE o.run_id=? AND p.tool != 'deep'", (rid,)).fetchone()["c"]
    if tools:
        failed = sum(1 for t in tools if not t.get("ok") and not t.get("skipped"))
        skipped = sum(1 for t in tools if t.get("skipped"))
        status = "failed" if failed else "done"
        detail = (f"{len(tools)} scanner(s) recorded, {failed} failed, {skipped} skipped; "
                  f"{n_scan} occurrence(s)")
    elif n_scan:
        status, detail = "done", (f"{n_scan} occurrence(s); scanned before per-tool "
                                  "outcomes were kept")
    else:
        status, detail = "not run", "no scanner output for this run"
    out.append({"stage": "Scan", "status": status, "detail": detail,
                "cmd": shell("quarry", "scan", rid),
                "note": "a tool that already returned results is refused"})

    f = m.get("funnel") if isinstance(m.get("funnel"), dict) else {}
    # A run funnelled before passes were recorded has its stage list and no `passes`;
    # that is one pass (funnel._persist_summary reads it the same way).
    passes = len(f.get("passes") or []) or (1 if f.get("stages") else 0)
    funnelled = con.execute(
        "SELECT COUNT(DISTINCT occurrence_id) c FROM funnel_events WHERE run_id=? "
        "AND stage != 'operator' AND occurrence_id IS NOT NULL", (rid,)).fetchone()["c"]
    waiting = arrived_total(con, rid)
    if not funnelled and not passes:
        status = "not run"
    else:
        status = "behind" if waiting else "done"
    out.append({"stage": "Funnel", "status": status,
                "detail": (f"{passes} pass(es) recorded; {funnelled} occurrence(s) "
                           f"funnelled, {waiting} not yet"),
                "cmd": shell("quarry", "funnel", rid),
                "note": "acts only on occurrences no pass has seen"})

    rr = con.execute("SELECT COUNT(*) n, MAX(id) latest FROM research_runs WHERE run_id=?",
                     (rid,)).fetchone()
    # The newest research run's state as the reader computes it, never the column.
    newest = research_runs(con, rid=rr["latest"])[0] if rr["n"] else None
    out.append({"stage": "Deep review",
                "status": newest["status"] if newest else "not run",
                "detail": (f"{rr['n']} research run(s); newest is {rr['latest']}, "
                           f"{newest['done']} of {newest['units']} unit(s) done"
                           if newest else "no research run for this run"),
                "cmd": shell("quarry", "deep", rid),
                "note": "local models only; hours, not minutes",
                "href": f"/research/{rr['latest']}" if rr["n"] else "/research"})

    vc = verdict_counts(con, rid)
    out.append({"stage": "Validate", "status": "done" if vc["total"] else "not run",
                "detail": (f"{vc['total']} latest verdict(s): {vc['confirmed']} confirmed, "
                           f"{vc['needs-review']} needs review, {vc['rejected']} rejected"),
                "cmd": shell("quarry", "validate", rid, "--dry-run"),
                "note": "plans the probes; run it again without --dry-run to probe"})

    n_adv = advisory_count(con, rid)
    dg = digest(con, rid, reports_root)
    need = vc["confirmed"] and not n_adv
    out.append({"stage": "Report",
                "status": "behind" if need else ("done" if n_adv or dg else "not run"),
                "detail": (f"{n_adv} advisory draft(s)"
                           + ("; a deep-review digest" if dg else "")
                           + (f"; {vc['confirmed']} confirmed verdict(s) with no draft"
                              if need else "")),
                "cmd": shell("quarry", "report", rid),
                "note": "writes drafts to read before anything is sent"})
    return out


def environment(con: sqlite3.Connection, root: Path, db_path: Path) -> dict[str, Any]:
    """What `quarry doctor` checks that can be read without running anything.

    Doctor also probes the filesystem type, sync attributes and each tool's version,
    which means running processes; the page shows the tool versions the newest run
    recorded instead, and says which run that was.
    """
    from ..migrations import MIGRATIONS
    from ..sandbox import CLONE_PROFILE, PROFILE
    size = 0
    for p in (db_path, db_path.with_name(db_path.name + "-wal")):
        try:
            size += p.stat().st_size
        except OSError:
            pass
    newest = con.execute("SELECT id FROM runs ORDER BY id DESC LIMIT 1").fetchone()
    versions: dict[str, Any] = {}
    if newest:
        m = db.read_manifest(con, newest["id"])
        # Tool versions are the manifest's top-level strings; None is a tool that was
        # absent at ingest. Everything else there is a structured record.
        versions = {k: v for k, v in sorted(m.items()) if v is None or isinstance(v, str)}
    return {"root": str(root), "db": str(db_path), "db_bytes": size,
            "schema": con.execute("PRAGMA user_version").fetchone()[0],
            "schema_current": len(MIGRATIONS),
            "profiles": [{"name": "tier 1 scanner sandbox", "path": str(PROFILE),
                          "present": PROFILE.exists()},
                         {"name": "clone sandbox", "path": str(CLONE_PROFILE),
                          "present": CLONE_PROFILE.exists()}],
            "versions": versions, "versions_run": newest["id"] if newest else None}


def vulndb_status(con: sqlite3.Connection) -> dict[str, Any]:
    """Each vulnerability database's build time and age now, which scanner reads it,
    and when `quarry db sync` last reached the network for it (the egress ledger)."""
    from .. import vulndb
    readers = {v: k for k, v in vulndb.DB_OF_TOOL.items()}
    rows = []
    for name, a in vulndb.ages().items():
        age = a.get("age_days")
        last = con.execute(
            "SELECT MAX(created_at) t FROM egress WHERE stage='db-sync' AND note LIKE ?",
            (f"{name}%",)).fetchone()["t"]
        rows.append({"name": name, "built": a.get("built"), "age_days": age,
                     "basis": a.get("basis") or "", "reader": readers.get(name),
                     "stale": not isinstance(age, (int, float)) or age > vulndb.STALE_DAYS,
                     "last_sync": last})
    return {"rows": rows, "dir": str(vulndb.db_dir()), "stale_days": vulndb.STALE_DAYS}


def targets(con: sqlite3.Connection, limit: int = 100) -> dict[str, Any]:
    """Scored candidate targets, highest first. The `targets` table had no reader
    anywhere in the dashboard. Archived targets are listed and marked, not hidden."""
    rows = []
    for r in con.execute("SELECT * FROM targets ORDER BY score DESC, slug LIMIT ?", (limit,)):
        d = dict(r)
        d["ingest_cmd"] = shell("quarry", "ingest", d["slug"])
        d["why_cmd"] = shell("quarry", "targets", "why", d["slug"])
        rows.append(d)
    total = con.execute("SELECT COUNT(*) c FROM targets").fetchone()["c"]
    scanned = con.execute("SELECT COUNT(*) c FROM targets WHERE scanned_run IS NOT NULL"
                          ).fetchone()["c"]
    return {"rows": rows, "total": total, "scanned": scanned}


def advisory_count(con: sqlite3.Connection, run_id: int) -> int:
    return con.execute("SELECT COUNT(*) c FROM advisories WHERE run_id=?",
                       (run_id,)).fetchone()["c"]


# ------------------------------------------------------------------ pipeline strip

def run_urls(rid: int) -> dict[str, str]:
    """Where each of a run's pages lives. The run is in the path, not a query
    parameter, so a link copied from one page and the nav on the next both keep it:
    the nav used to drop it, and Triage opened from run 1 showed run 2."""
    return {"run": f"/runs/{rid}", "triage": f"/runs/{rid}/triage",
            "validation": f"/runs/{rid}/validation",
            "advisories": f"/runs/{rid}/advisories"}


def pipeline(con: sqlite3.Connection, run: dict[str, Any],
             reports_root: "Path | None" = None) -> list[dict[str, Any]]:
    """The five stages of one run, each with its count and the set that count opens.

    Every count is a link, like every other number in the product. Ingest counts what
    it quarantined; scan counts raw occurrences and the tools that produced them; the
    funnel counts what is still live; validate counts latest-verdict slots; report
    counts advisory drafts recorded for the run, and says when a deep-review digest
    sits beside them (found through `reports_root`, when given).
    """
    rid = run["id"]
    u = run_urls(rid)
    quarantined = con.execute("SELECT COUNT(*) c FROM quarantined WHERE run_id=?",
                              (rid,)).fetchone()["c"]
    # Layer 1 only. Deep review writes occurrences under the producer tool `deep`,
    # and counting it made the card read "8 tool(s)" for seven scanners.
    scan = con.execute(
        "SELECT COUNT(DISTINCT p.tool) tools, COUNT(o.id) n FROM occurrences o "
        "JOIN producers p ON p.id = o.producer_id WHERE o.run_id=? AND p.tool != 'deep'",
        (rid,)).fetchone()
    n_deep = run["total"] - scan["n"]
    vc = verdict_counts(con, rid)
    return [
        {"name": "Ingest", "n": quarantined, "unit": "quarantined",
         "href": f"{u['run']}#quarantine", "page": "run"},
        {"name": "Scan", "n": scan["n"],
         "unit": f"raw, {scan['tools']} scanner(s)"
                 + (f"; {n_deep} more from deep review" if n_deep else ""),
         "href": f"{u['run']}#funnel", "page": "run"},
        {"name": "Funnel", "n": run["live"], "unit": "live",
         "href": u["triage"], "page": "triage"},
        {"name": "Validate", "n": vc["total"], "unit": f"verdicts, {vc['confirmed']} confirmed",
         "href": u["validation"], "page": "validation"},
        {"name": "Report", "n": advisory_count(con, rid),
         "unit": "drafts" + ("; deep-review digest" if digest(con, rid, reports_root)
                             else ""),
         "href": u["advisories"], "page": "advisories"},
    ]
