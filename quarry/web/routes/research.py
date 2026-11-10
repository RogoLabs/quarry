"""Deep review: start a run, resume one, stop one, and watch one.

These are the routes that spawn processes and send signals, so each checks what it
is about to act on rather than trusting the form: the model list against the offered
one, the run against the database, a pid against the worker it claims to be.
"""
from __future__ import annotations

import json

from fastapi import Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from ... import db
from ...research.ensemble import family as _family
from .. import queries as q
from .. import writes
from ..context import RouteTable, web
from ..security import row_id

router = RouteTable()

#: Offered in the UI. The default selection is the CLI's (see cli.DEFAULT_DEEP_MODELS
#: for why gpt-oss:20b is no longer in it), so the two can't drift apart.
DEEP_DEFAULT = ["qwen3-coder:30b", "granite4.2:30b", "devstral:24b"]
DEEP_MODELS = [*DEEP_DEFAULT, "gpt-oss:20b", "qwen3.6:27b", "deepseek-coder-v2:16b",
               "codestral:22b"]


@router.get("/research", response_class=HTMLResponse)
def research_index(request: Request):
    w = web(request)
    with w.opened() as c:
        return w.render(request, "research.html", {
            "runs": q.research_runs(c), "ingested": q.ingested_runs(c),
            "models": DEEP_MODELS, "default_models": DEEP_DEFAULT,
            "family_of": {m: _family(m) for m in DEEP_MODELS},
        }, c)


@router.post("/research/start")
def research_start(request: Request, run_id: int = Form(...),
                   models: list[str] = Form(...), hours: float = Form(8.0),
                   note: str = Form("")):
    """Kick off a long run.

    Spawned as a detached subprocess rather than a background task, so the review
    outlives the web server: a long run must not end because a page was closed or
    the server reloaded. Progress lands in the database; the UI reads it.
    """
    # The model list becomes argv for a detached process, so it is checked against
    # the offered list rather than trusted from the form.
    unknown = sorted(set(models) - set(DEEP_MODELS))
    if unknown:
        raise HTTPException(400, f"Unknown model(s): {', '.join(unknown)}. Choose "
                                 "from the list on this page.")
    models = list(dict.fromkeys(models))
    fams = {_family(m) for m in models}
    if len(fams) < 2:
        raise HTTPException(400, "Select models from at least two families: "
                                 "same-family review is measured at -37.6%.")
    w = web(request)
    with w.opened() as c:
        run = q.run_volume(c, row_id(run_id))
    if run is None:
        raise HTTPException(404, "No such run.")
    if run["status"] != "done" or not run["volume_path"]:
        raise HTTPException(409, "That run has no ingested volume to review.")
    argv = ["-m", "quarry.cli", "deep", str(run_id), "--models", ",".join(models)]
    if hours and 0 < hours < float("inf"):
        argv += ["--hours", str(hours)]
    w.spawn(argv, f"deep-run{run_id}.log")
    return RedirectResponse("/research", status_code=303)


@router.post("/research/{rid}/resume")
def research_resume(request: Request, rid: int, hours: float = Form(0.0)):
    """Pick a dead or stopped run back up. Completed units are skipped, so this
    continues rather than restarts. `hours` 0, the default, sets no deadline: the run
    goes until every unit is hunted and refuted, and the 21:00 job is refused while it
    holds the run. It was a hidden 8, so a resume by hand always stopped after eight
    hours (2026-11-07).

    The run is claimed in the database BEFORE the worker is spawned. The check
    used to read the status, then spawn, with nothing held in between, so two
    clicks (or two tabs) could both see a stopped run and start two workers on the
    same units. Now the check and the claim happen in one write transaction
    (`BEGIN IMMEDIATE`, so a second request waits for the first to commit), the
    claim sets status `resuming`, and the second request reads that back as
    `starting` and is refused. The child's pid is recorded as soon as the spawn
    returns; the worker then claims the run for itself (runner._claim). A spawn
    that fails releases the claim, and a claim no worker ever took lapses after
    queries.CLAIM_GRACE_SECONDS, so a run cannot be locked out for good.
    """
    w = web(request)
    with w.opened() as c:
        with db.tx(c):
            rows = q.research_runs(c, rid=row_id(rid))
            if not rows:
                raise HTTPException(404, "No such research run.")
            row = rows[0]
            if row["status"] in q.LIVE_STATUSES:
                raise HTTPException(409, f"Research run {rid} still has a live or "
                                         "starting worker; stop it before resuming.")
            if not row["resumable"]:
                raise HTTPException(409, f"Research run {rid} is {row['status']} "
                                         "with no unit left to run and no answer "
                                         "owed; nothing to resume.")
            prior = q.research_claim_state(c, rid)
            writes.claim_research_run(c, rid)
        argv = ["-m", "quarry.cli", "deep", str(row["run_id"]),
                "--models", ",".join(json.loads(row["models"])),
                "--resume", str(rid)]
        if hours and 0 < hours < float("inf"):
            argv += ["--hours", str(hours)]
        try:
            proc = w.spawn(argv, f"deep-run{row['run_id']}.log",
                           env={q.RESUME_CLAIM_ENV: str(rid)})
        except OSError as e:
            writes.release_research_claim(c, rid, prior)
            raise HTTPException(500, f"The worker could not be started ({e}). The "
                                     "claim was released, so the run can be resumed "
                                     "again.") from e
        pid = getattr(proc, "pid", None)
        if isinstance(pid, int):
            writes.record_worker_pid(c, rid, pid)
    return RedirectResponse(f"/research/{rid}", status_code=303)


@router.post("/research/{rid}/stop")
def research_stop(request: Request, rid: int):
    """Signal a running deep review.

    There was no way to end an eight-hour detached subprocess except `kill` from a
    terminal, so this exists. It signals only a process it can show is this run's
    worker: a stored pid outlives its process, the OS recycles pids, and SIGTERM to
    a recycled pid kills whatever unrelated program now holds it. See
    `queries.worker_identity()` for what the check is.
    """
    import os
    import signal
    with web(request).opened() as c:
        row = q.research_row(c, row_id(rid))
    if row is None:
        raise HTTPException(404, "No such research run.")
    if row["status"] in q.TERMINAL_STATUSES:
        raise HTTPException(409, f"Research run {rid} is already {row['status']}; "
                                 "there is nothing to stop.")
    if not row["pid"]:
        raise HTTPException(409, f"Research run {rid} has no worker pid recorded; "
                                 "nothing was signalled.")
    if not q._pid_alive(row["pid"]):
        raise HTTPException(409, f"pid {row['pid']} is gone; nothing was signalled.")
    ok, why = q.worker_identity(row)
    if ok is not True:
        raise HTTPException(409, f"pid {row['pid']} could not be verified as this "
                                 f"run's worker ({why}); nothing was signalled.")
    try:
        os.kill(int(row["pid"]), signal.SIGTERM)
    except (OSError, ValueError, TypeError):
        pass          # exited between the check and the signal; live_status() says so
    return RedirectResponse(f"/research/{rid}", status_code=303)


@router.get("/research/{rid}", response_class=HTMLResponse)
def research_detail(request: Request, rid: int):
    w = web(request)
    with w.opened() as c:
        d = q.research_detail(c, row_id(rid))
        if not d:
            raise HTTPException(404, "No such research run.")
        return w.render(request, "research_detail.html", {"r": d}, c)


@router.get("/research/{rid}/progress", response_class=HTMLResponse)
def research_progress(request: Request, rid: int):
    """The volatile half of `/research/{rid}`, for htmx polling.

    Replaces `<meta http-equiv="refresh" content="20">`, which was a WCAG 2.2.1
    Level A failure (a content-set time limit with no mechanism to turn it off)
    and reloaded a 160-line document 1,440 times over an eight-hour run,
    destroying scroll position, focus and open state every twenty seconds.

    Candidate cards are deliberately NOT in this fragment: new candidates
    appearing under a reading cursor is the reflow that stops people reading. The
    template polls a count into a stable banner instead.

    SSE was considered and rejected. The worker is a detached subprocess the web
    process does not own, and progress lives in *mutable* columns
    (`research_units.updated_at`), so there is no append-only log for
    `Last-Event-ID` to replay; SSE here would be this same poll with a socket in
    front of it, pinning an anyio worker thread per open tab.
    """
    w = web(request)
    with w.opened() as c:
        d = q.research_detail(c, row_id(rid))
        if not d:
            raise HTTPException(404, "No such research run.")
        return w.render(request, "_research_progress.html", {"r": d}, c)
