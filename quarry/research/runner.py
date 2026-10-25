"""Deep-run orchestration.

A long run is defined by being interruptible. Work is chunked at the
(subsystem × lens × model) level and every unit's outcome is committed before the next
begins, so closing the laptop costs one unit rather than one night. Subsystems are
ordered by security relevance, so a run stopped after four hours has spent them on
controllers and models rather than locale files.
"""
from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable, Iterable

from .. import db, taint
from . import ensemble as E
from .pack import Subsystem, pack_subsystems
from .profile import profile_repo

Progress = Callable[[str], None]


def plan(con: sqlite3.Connection, run_id: int, src: Path, *, models: list[str],
         budget_tokens: int = 45_000, note: str = "") -> tuple[int, list[Subsystem], list]:
    """Profile, select lenses, pack subsystems, and write the work list."""
    prof = profile_repo(src)
    lenses, rejected = E.select_lenses(prof)
    subs = pack_subsystems(src, budget_tokens=budget_tokens,
                           profile_summary=prof.summary())

    with db.tx(con):
        cur = con.execute(
            """INSERT INTO research_runs (run_id, status, models, lenses, profile, note)
               VALUES (?,?,?,?,?,?)""",
            (run_id, "running", json.dumps(models),
             json.dumps([l.key for l in lenses]),
             json.dumps({"summary": prof.summary(),
                         "capabilities": prof.capabilities,
                         "artifact_kind": prof.artifact_kind,
                         "frameworks": prof.frameworks,
                         "skipped_lenses": [{"lens": k, "why": w} for k, w in rejected]},
                        default=str),
             note))
        rid = int(cur.lastrowid)
        for s in subs:
            for lens in lenses:
                for m in models:
                    con.execute(
                        """INSERT OR IGNORE INTO research_units
                             (research_id, subsystem, weight, lens, model, phase)
                           VALUES (?,?,?,?,?, 'hunt')""",
                        (rid, s.name, s.weight, lens.key, m))
    return rid, subs, lenses


def _finish(con, rid: int, status: str) -> None:
    con.execute("UPDATE research_runs SET status=?, finished_at=datetime('now'), "
                "pid=NULL WHERE id=?", (status, rid))


def _claim(con, rid: int) -> None:
    """Record who is doing the work, so a reader can check rather than trust."""
    import os
    import socket
    con.execute("UPDATE research_runs SET pid=?, host=?, status='running', "
                "heartbeat=datetime('now') WHERE id=?",
                (os.getpid(), socket.gethostname(), rid))


def _beat(con, rid: int) -> None:
    con.execute("UPDATE research_runs SET heartbeat=datetime('now') WHERE id=?", (rid,))


def execute(con: sqlite3.Connection, rid: int, src: Path, *,
            deadline: datetime | None = None, progress: Progress = print,
            refute: bool = True, num_ctx: int = 65536) -> dict:
    """Run the pending units. Safe to call again on the same research id — completed
    units are skipped, so a killed run resumes rather than restarts."""
    row = con.execute("SELECT * FROM research_runs WHERE id=?", (rid,)).fetchone()
    if row is None:
        raise RuntimeError(f"no research run {rid}")
    models = json.loads(row["models"])
    prof = profile_repo(src)
    lens_by_key = {l.key: l for l in E.CATALOGUE}
    subs = {s.name: s for s in pack_subsystems(src, budget_tokens=45_000,
                                               profile_summary=prof.summary())}
    _claim(con, rid)
    if deadline:
        con.execute("UPDATE research_runs SET deadline=? WHERE id=?",
                    (deadline.isoformat(timespec="seconds"), rid))

    stats = {"hunted": 0, "findings": 0, "verified": 0, "refuted": 0,
             "survived": 0, "errors": 0, "skipped_deadline": 0}

    # 'running' is included deliberately: a worker killed mid-unit leaves that row
    # claimed, and without it resume would skip the one unit that never finished.
    # `live_status()` already refuses to trust a status the dying process had to write,
    # so the same reasoning applies one level down.
    pending = con.execute(
        """SELECT * FROM research_units
           WHERE research_id=? AND status IN ('pending','error','running')
           ORDER BY weight DESC, subsystem, lens, model""", (rid,)).fetchall()
    progress(f"{len(pending)} units pending across {len(subs)} subsystem(s)")

    for u in pending:
        _beat(con, rid)
        if deadline and datetime.now() >= deadline:
            stats["skipped_deadline"] += 1
            continue
        sub = subs.get(u["subsystem"])
        lens = lens_by_key.get(u["lens"])
        if sub is None or lens is None:
            con.execute("UPDATE research_units SET status='error', error=? , "
                        "updated_at=datetime('now') WHERE id=?",
                        ("subsystem or lens no longer exists", u["id"]))
            continue

        # Claim it. Until this existed the runner only ever wrote pending/done/error,
        # so the currently-executing unit was indistinguishable from the hundreds that
        # had not started — and the UI's "In flight" section could not be true.
        con.execute("UPDATE research_units SET status='running', "
                    "updated_at=datetime('now') WHERE id=?", (u["id"],))
        con.commit()

        text = sub.render()
        t0 = time.time()
        try:
            raw, meta = E.call(u["model"], E.hunt_prompt(text, lens, sub.pack.manifest()),
                               E.FINDING_SCHEMA, num_ctx=num_ctx, num_predict=2200)
            found = E.parse_findings(raw, lens.key, u["model"])
            for f in found:
                f.quote_verified = E.verify_quote(f, src)
            secs = time.time() - t0
            _persist(con, rid, row["run_id"], u, found, src)
            con.execute(
                """UPDATE research_units SET status='done', seconds=?, n_findings=?,
                   tokens_in=?, error=NULL, updated_at=datetime('now') WHERE id=?""",
                (round(secs, 1), len(found), meta.get("prompt_eval_count", 0), u["id"]))
            stats["hunted"] += 1
            stats["findings"] += len(found)
            stats["verified"] += sum(1 for f in found if f.quote_verified)
            if found:
                progress(f"  {u['subsystem'][:34]:34s} {u['lens'][:22]:22s} "
                         f"{u['model'][:18]:18s} {secs:5.0f}s  {len(found)} finding(s)")
        except Exception as e:                          # noqa: BLE001 — a failed unit is data
            con.execute("UPDATE research_units SET status='error', error=?, seconds=?, "
                        "updated_at=datetime('now') WHERE id=?",
                        (str(e)[:300], round(time.time() - t0, 1), u["id"]))
            stats["errors"] += 1
            progress(f"  [error] {u['subsystem'][:28]} {u['lens'][:18]} "
                     f"{u['model'][:16]}: {str(e)[:80]}")

    if refute:
        stats.update(_refute_pass(con, rid, src, subs, models, deadline, progress))

    remaining = con.execute("SELECT COUNT(*) c FROM research_units WHERE research_id=? "
                            "AND status='pending'", (rid,)).fetchone()["c"]
    _finish(con, rid, "done" if not remaining else "stopped")
    return stats


def _persist(con, rid: int, run_id: int, unit, found: list[E.Finding], src: Path) -> None:
    """Findings become ordinary occurrences so the funnel, ledger and triage UI work
    on them unchanged. `producer_id` is per-lens, never one row for the whole layer."""
    from ..scanners.base import rel_or_none
    from ..taint import extract_evidence, finding_id
    target = con.execute("SELECT target, git_sha FROM runs WHERE id=?",
                         (run_id,)).fetchone()
    with db.tx(con):
        for f in found:
            # `file` is model output, i.e. target-influenced text. "/etc/hosts" or
            # "../../.ssh/id_ed25519" here used to be read UNSANDBOXED by
            # extract_evidence and stored as an evidence blob. It crosses the same taint
            # boundary as a scanner's SARIF uri, and a path that escapes the clone is
            # not a finding about this repo: drop it.
            if f.file:
                rel = rel_or_none(f.file, src)
                if rel is None:
                    continue
                f.file = rel
            pid = db.upsert_producer(con, "deep", f.lens,
                                     name=f"deep review: {f.lens}")
            ev = extract_evidence(src, Path(f.file), f.line) if f.file else None
            if ev is not None:
                if con.execute("SELECT 1 FROM evidence_blobs WHERE sha=?",
                               (ev.sha,)).fetchone() is None:
                    con.execute(
                        """INSERT INTO evidence_blobs
                             (sha,path,file_sha256,git_sha,start_line,end_line,body,bytes)
                           VALUES (?,?,?,?,?,?,?,?)""",
                        (ev.sha, ev.path, ev.file_sha256, target["git_sha"],
                         ev.start_line, ev.end_line, ev.body, ev.bytes_raw))
            fid = finding_id(target["target"], f.file, pid,
                             ev.match_sha if ev else None, fallback=f.quote or f.title)
            con.execute(
                """INSERT INTO findings (id,target,path,symbol_sha,producer_id,
                                         first_seen_run,last_seen_run)
                   VALUES (?,?,?,?,?,?,?)
                   ON CONFLICT(id) DO UPDATE SET last_seen_run=excluded.last_seen_run""",
                (fid, target["target"], f.file, ev.file_sha256 if ev else None, pid,
                 run_id, run_id))
            cur = con.execute(
                """INSERT INTO occurrences
                     (run_id,finding_id,producer_id,path,start_line,message,severity,
                      blob_sha,raw_result)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (run_id, fid, pid, f.file, f.line,
                 taint.scrub_text(f.title, 400), f.severity,
                 ev.sha if ev else None,
                 json.dumps({"lens": f.lens, "model": f.model,
                             "reasoning": f.reasoning,
                             "attacker_control": f.attacker_control,
                             "why_it_might_be_wrong": f.why_it_might_be_wrong,
                             "quote": f.quote}, default=str)[:200_000]))
            con.execute(
                """INSERT INTO research_findings
                     (research_id,occurrence_id,subsystem,lens,model,family,title,file,
                      quote,quote_verified,severity,reasoning,attacker_control,
                      self_critique)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (rid, cur.lastrowid, unit["subsystem"], f.lens, f.model,
                 E.family(f.model), taint.scrub_text(f.title, 200), f.file,
                 taint.scrub_text(f.quote, 400), int(f.quote_verified), f.severity,
                 taint.scrub_text(f.reasoning, 1200),
                 taint.scrub_text(f.attacker_control, 600),
                 taint.scrub_text(f.why_it_might_be_wrong, 600)))


def _refute_pass(con, rid: int, src: Path, subs: dict, models: list[str],
                 deadline, progress: Progress) -> dict:
    """Every finding is refuted by every model from a DIFFERENT family. Same-family
    review is the configuration measured to degrade findings by 37.6%, so a finding
    with no cross-family refuter available is left unrefuted rather than self-reviewed."""
    out = {"refuted": 0, "survived": 0}
    rows = con.execute(
        """SELECT * FROM research_findings WHERE research_id=? AND refutations='[]'
           ORDER BY quote_verified DESC, id""", (rid,)).fetchall()
    if rows:
        progress(f"refuting {len(rows)} finding(s) cross-family")
    for r in rows:
        if deadline and datetime.now() >= deadline:
            break
        refuters = [m for m in models if E.family(m) != r["family"]]
        if not refuters:
            continue
        sub = subs.get(r["subsystem"])
        if sub is None:
            continue
        f = E.Finding(lens=r["lens"], model=r["model"], title=r["title"],
                      file=r["file"] or "", quote=r["quote"] or "",
                      severity=r["severity"] or "info", reasoning=r["reasoning"] or "",
                      attacker_control=r["attacker_control"] or "",
                      why_it_might_be_wrong=r["self_critique"] or "",
                      quote_verified=bool(r["quote_verified"]))
        text = sub.render()
        for m in refuters:
            try:
                raw, _ = E.call(m, E.refute_prompt(text, f), E.REFUTE_SCHEMA,
                                num_ctx=65536, num_predict=700)
                f.refutations.append({"model": m, **json.loads(raw)})
            except Exception as e:                      # noqa: BLE001
                f.refutations.append({"model": m, "verdict": "error",
                                      "reason": str(e)[:200]})
        con.execute(
            """UPDATE research_findings SET refutations=?, n_refuted=?, n_survived=?,
               refuter_errors=? WHERE id=?""",
            (json.dumps(f.refutations, default=str), f.refuted, f.survived,
             f.refuter_errors, r["id"]))
        out["refuted"] += f.refuted
        out["survived"] += f.survived
    return out
