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
from . import grounding
from . import intent as intent_mod
from . import verdicts
from .pack import Subsystem, pack_subsystems
from .profile import profile_repo

Progress = Callable[[str], None]

# The budget a deep run holds fixed. Named so a replay (research.replay) can record the
# exact values it ran under, and a change to one shows up as a changed configuration
# rather than as a silent difference in results.
UNIT_BUDGET_TOKENS = 45_000
NUM_CTX = 65536
HUNT_NUM_PREDICT = 8192
REFUTE_NUM_PREDICT = 700


def plan(con: sqlite3.Connection, run_id: int, src: Path, *, models: list[str],
         budget_tokens: int = UNIT_BUDGET_TOKENS, note: str = "",
         lenses: Iterable[str] | None = None) -> tuple[int, list[Subsystem], list]:
    """Profile, select lenses, pack subsystems, and write the work list.

    `lenses` narrows the profile's selection to those keys (a replay holds its lens set
    fixed). It never adds a lens the profile rejected: a profile change that loses a
    lens is something a replay should show as missed plants, not paper over."""
    prof = profile_repo(src)
    selected, rejected = E.select_lenses(prof)
    lenses_arg, wanted = lenses, set(lenses or ())
    if lenses_arg is not None:
        selected = [l for l in selected if l.key in wanted]
    lenses = selected
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
                         "skipped_lenses": [{"lens": k, "why": w} for k, w in rejected],
                         "lens_filter": sorted(wanted) if lenses_arg is not None else None},
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
            refute: bool = True, num_ctx: int = NUM_CTX,
            route_intent: bool = True) -> dict:
    """Run the pending units. Safe to call again on the same research id — completed
    units are skipped, so a killed run resumes rather than restarts.

    `route_intent` gives the authorization lens and the refuter each route's declared
    access (research.intent). Off reproduces the prompts as they were before item 20,
    which is what a replay compares against."""
    row = con.execute("SELECT * FROM research_runs WHERE id=?", (rid,)).fetchone()
    if row is None:
        raise RuntimeError(f"no research run {rid}")
    models = json.loads(row["models"])
    prof = profile_repo(src)
    lens_by_key = {l.key: l for l in E.CATALOGUE}
    refused: list[tuple[str, str]] = []
    subs = {s.name: s for s in pack_subsystems(src, budget_tokens=UNIT_BUDGET_TOKENS,
                                               profile_summary=prof.summary(),
                                               refused=refused)}
    for path, why in refused:
        progress(f"  [refused] {taint.scrub_text(path, 120)}: {why}")
    imap = intent_mod.build(src) if route_intent else None
    if imap is not None and imap.error:
        progress(f"  [intent] route intent unavailable: {imap.error}")
    _claim(con, rid)
    # What answered, so a run can be reproduced: the Ollama version and each model's
    # digest. A tag like qwen3-coder:30b is mutable; the digest is not.
    prov = E.model_provenance(models)
    prov["refused_files"] = [{"path": p, "why": w} for p, w in refused]
    prov["route_intent"] = imap.summary() if imap is not None else {"disabled": True}
    with db.tx(con):
        db.update_manifest(con, row["run_id"],
                           lambda m: m.setdefault("deep", {}).__setitem__(str(rid), prov))
    if deadline:
        con.execute("UPDATE research_runs SET deadline=? WHERE id=?",
                    (deadline.isoformat(timespec="seconds"), rid))

    stats = {"hunted": 0, "findings": 0, "verified": 0, "refuted": 0,
             "survived": 0, "errors": 0, "skipped_deadline": 0}
    t_hunt = time.time()

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

        tag = E.new_tag()
        text = sub.render(tag)
        declared = (imap.for_files([f.path for f in sub.pack.files])
                    if imap is not None and lens.key in E.INTENT_LENSES else "")
        t0 = time.time()
        try:
            # 8192, not 2200: a thinking model that ignores think:false needs room for its
            # reasoning trace plus the answer or it truncates (see ensemble.call). This is
            # a ceiling, not a cost; a model that stops early never reaches it.
            raw, meta = E.call(u["model"],
                               E.hunt_prompt(text, lens, sub.pack.manifest(), tag,
                                             intent=declared),
                               E.FINDING_SCHEMA, num_ctx=num_ctx,
                               num_predict=HUNT_NUM_PREDICT)
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

    stats["hunt_seconds"] = round(time.time() - t_hunt, 1)
    t_refute = time.time()
    if refute:
        stats.update(_refute_pass(con, rid, src, subs, models, deadline, progress,
                                  intent=imap))
    stats["refute_seconds"] = round(time.time() - t_refute, 1)
    # Findings a human already judged intended on an earlier run. Still stored, refuted
    # and funnelled like any other; counted here so the run says how many of its
    # survivors are not new.
    prior = con.execute(
        f"""SELECT COUNT(*) AS n,
                  COALESCE(SUM({E.KEPT_SQL}), 0) AS kept
             FROM research_findings rf JOIN deep_verdicts dv ON dv.id = rf.prior_verdict_id
            WHERE rf.research_id = ? AND dv.verdict = 'intended'""", (rid,)).fetchone()
    stats["prior_intended"] = prior["n"]
    stats["prior_intended_survived"] = prior["kept"]

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
    # Model output is redacted like an evidence window. The secrets lens asks for
    # exactly the lines that hold secrets, and the quote and raw_result went to the DB
    # and the digest verbatim. Verification already ran on the unredacted quote.
    secrets = taint.run_secrets(src.parent)
    # The definition enclosing each quote, read from this run's clone before the quote is
    # redacted (a redacted quote is no longer in the file). Stored, because a later run
    # compares against it after this clone is gone.
    symbols = [intent_mod.locate(src, f.file, f.quote, f.line) if f.file else None
               for f in found]
    for f in found:
        for k in ("title", "quote", "reasoning", "attacker_control",
                  "why_it_might_be_wrong"):
            setattr(f, k, taint.redact_in(getattr(f, k) or "", secrets))
    with db.tx(con):
        for f, sym in zip(found, symbols):
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
            # An earlier human verdict on the same behaviour (same target, lens and file,
            # and a matching quote or enclosing symbol). Recorded, never used to drop.
            hit = verdicts.match(
                verdicts.candidates(con, target["target"], f.lens, f.file, rid),
                quote=f.quote, symbol=sym) if f.file else None
            prior = ({"verdict_id": hit[0]["verdict_id"], "verdict": hit[0]["verdict"],
                      "research_finding_id": hit[0]["rf_id"], "basis": hit[1]}
                     if hit else None)
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
                             "quote": f.quote, "symbol": sym,
                             **({"prior_human_verdict": prior} if prior else {})},
                            default=str)[:200_000]))
            con.execute(
                """INSERT INTO research_findings
                     (research_id,occurrence_id,subsystem,lens,model,family,title,file,
                      quote,quote_verified,severity,reasoning,attacker_control,
                      self_critique,symbol,prior_verdict_id,prior_match)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (rid, cur.lastrowid, unit["subsystem"], f.lens, f.model,
                 E.family(f.model), taint.scrub_text(f.title, 200), f.file,
                 taint.scrub_text(f.quote, 400), int(f.quote_verified), f.severity,
                 taint.scrub_text(f.reasoning, 1200),
                 taint.scrub_text(f.attacker_control, 600),
                 taint.scrub_text(f.why_it_might_be_wrong, 600),
                 taint.scrub_text(sym, 200) if sym else None,
                 prior["verdict_id"] if prior else None,
                 prior["basis"] if prior else None))


def _refute_once(m: str, text: str, f: E.Finding, tag: str, declared: str, prior: str,
                 secrets, src: Path, rejected: dict | None = None) -> dict:
    """One refuter call, its record, and for a `refuted` the grounding of its evidence.
    A failed call is a record with verdict "error", as before."""
    try:
        raw, _ = E.call(m, E.refute_prompt(text, f, tag, intent=declared, prior=prior,
                                           rejected=rejected),
                        E.REFUTE_SCHEMA, num_ctx=NUM_CTX, num_predict=REFUTE_NUM_PREDICT)
        rec = E.refutation_record(m, raw)
    except Exception as e:                              # noqa: BLE001
        return {"model": m, "verdict": "error", "reason": str(e)[:200]}
    if rec.get("verdict") == "refuted":
        # Grounded against the clone before redaction, on the model's own text: a
        # counter_quote naming a committed secret is still a quote of real code.
        rec["grounding"] = grounding.ground(
            src, claim_file=f.file, claim_quote=f.quote, claim_line=f.line,
            counter_quote=str(rec.get("counter_quote") or ""),
            counter_file=str(rec.get("counter_file") or ""),
            guard=str(rec.get("guard") or "")).as_record()
    for k in ("reason", "counter_quote", "guard"):
        if k in rec:
            rec[k] = taint.redact_in(str(rec[k]), secrets)
    return rec


def _refute_pass(con, rid: int, src: Path, subs: dict, models: list[str],
                 deadline, progress: Progress, *,
                 intent: intent_mod.IntentMap | None = None) -> dict:
    """Every finding is refuted by every model from a DIFFERENT family. Same-family
    review is the configuration measured to degrade findings by 37.6%, so a finding
    with no cross-family refuter available is left unrefuted rather than self-reviewed.

    The work is grouped by refuter MODEL, not by finding. Ollama holds one of these
    30B-class models in memory at a time, so refuting finding-by-finding — each finding
    calling the two models of other families in turn — evicts and reloads a model on
    almost every call. MEASURED on cve-services: that ordering reloaded a model ~3400
    times and crawled at minutes per finding, which would have taken days for 1708
    findings. Loading each model once and refuting every finding it is eligible for does
    the same work in a few hours. Within a model, quote-verified findings go first, so a
    deadline that cuts the pass short still spends the model on the strongest findings.
    Each finding's row is written the moment a refuter answers (the connection is in
    autocommit), so an interrupted pass resumes at the (finding, model) pair rather than
    restarting the whole run.

    Two kinds of context reach the refuter (IMPROVEMENT-PLAN item 20): the declared
    access of the routes in the claim's file, when `intent` is given, and, when the
    claim matched an earlier human verdict of `intended`, that verdict and its note.
    Both are evidence for the refuter to weigh, and the prompt says so."""
    out = {"refuted": 0, "survived": 0}
    secrets = taint.run_secrets(src.parent)
    priors: dict[int, str] = {}

    def prior_text(r) -> str:
        vid = r["prior_verdict_id"] if "prior_verdict_id" in r.keys() else None
        if not vid:
            return ""
        if vid not in priors:
            d = verdicts.detail(con, vid)
            priors[vid] = (verdicts.prior_context(d, r["prior_match"] or "matched")
                           if d and d["verdict"] == "intended" else "")
        return priors[vid]
    pending = con.execute(
        "SELECT COUNT(*) FROM research_findings WHERE research_id=? AND refutations='[]'",
        (rid,)).fetchone()[0]
    if pending:
        progress(f"refuting {pending} finding(s) cross-family")
    for m in models:
        if deadline and datetime.now() >= deadline:
            break
        mfam = E.family(m)
        # Findings this model may refute: a different family, and not one it has already
        # answered. A finding partway through the pass carries the other family's verdict
        # in its refutations, so the "already answered by m" filter is on the model's
        # presence there. Done in Python to keep a model name with a SQL-LIKE wildcard
        # (an underscore) from matching the wrong rows.
        rows = con.execute(
            """SELECT * FROM research_findings
               WHERE research_id=? AND family != ?
               ORDER BY quote_verified DESC, id""", (rid, mfam)).fetchall()
        # An error is not an answer: a model whose only record on a finding is a failed
        # call is asked again (IMPROVEMENT-PLAN item 5). Before this, --resume skipped
        # it forever and the finding stayed deferred at the Layer 2 gate; 14 candidates
        # on runs 1 and 2 were stuck that way.
        rows = [r for r in rows
                if not any(x.get("model") == m and x.get("verdict") != "error"
                           for x in json.loads(r["refutations"]))]
        if not rows:
            continue
        progress(f"  {m}: refuting {len(rows)} finding(s)")
        for r in rows:
            if deadline and datetime.now() >= deadline:
                break
            sub = subs.get(r["subsystem"])
            if sub is None:
                continue
            f = E.Finding(lens=r["lens"], model=r["model"], title=r["title"],
                          file=r["file"] or "", quote=r["quote"] or "",
                          severity=r["severity"] or "info", reasoning=r["reasoning"] or "",
                          attacker_control=r["attacker_control"] or "",
                          why_it_might_be_wrong=r["self_critique"] or "",
                          quote_verified=bool(r["quote_verified"]),
                          refutations=json.loads(r["refutations"]))
            # A retry replaces this model's failed calls with its new record, which keeps
            # their reasons, so one model never holds two records on one finding.
            earlier = [x.get("reason", "") for x in f.refutations
                       if x.get("model") == m and x.get("verdict") == "error"]
            f.refutations = [x for x in f.refutations
                             if not (x.get("model") == m and x.get("verdict") == "error")]
            tag = E.new_tag()
            text = sub.render(tag)
            declared = intent.for_file(f.file) if intent is not None else ""
            rec = _refute_once(m, text, f, tag, declared, prior_text(r), secrets, src)
            if E.ungrounded(rec) and f.quote_verified:
                # One more ask, told why the evidence did not hold (decision F). The model
                # is already loaded, so this is one call, not a reload. Whatever comes back
                # is final: a second ungrounded refutation counts as unsupported.
                retry = _refute_once(m, text, f, tag, declared, prior_text(r), secrets,
                                     src, rejected=rec)
                retry["earlier_ungrounded"] = [{k: rec.get(k) for k in (
                    "reason", "counter_file", "counter_quote", "guard", "grounding")}]
                rec = retry
            if earlier:
                rec["earlier_errors"] = earlier[-5:]
            f.refutations.append(rec)
            con.execute(
                """UPDATE research_findings SET refutations=?, n_refuted=?, n_survived=?,
                   refuter_errors=?, n_unsupported=? WHERE id=?""",
                (json.dumps(f.refutations, default=str), f.refuted, f.survived,
                 f.refuter_errors, f.unsupported, r["id"]))
    totals = con.execute(
        """SELECT COALESCE(SUM(n_refuted), 0) AS refuted,
                  COALESCE(SUM(n_survived), 0) AS survived,
                  COALESCE(SUM(n_unsupported), 0) AS unsupported
           FROM research_findings WHERE research_id=?""", (rid,)).fetchone()
    out["refuted"], out["survived"] = totals["refuted"], totals["survived"]
    out["unsupported"] = totals["unsupported"]
    return out
