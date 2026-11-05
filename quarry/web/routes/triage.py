"""Triage: the console, and the two operator dispositions it offers.

Per Seat 4, `/runs/{id}/triage` is the queue and its detail, with no route change
ever: moving between rows swaps columns in place. Dismiss and restore are the only
writes the console makes, and both append ledger rows (writes.py).
"""
from __future__ import annotations

from fastapi import Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from .. import queries as q
from .. import writes
from ..context import RouteTable, scoped_redirect, web
from ..security import row_id

router = RouteTable()


@router.get("/triage", response_class=HTMLResponse)
def triage_latest(request: Request, run: int | None = None):
    """Triage has no cross-run view: it always belongs to one run. With no run
    named, that is the newest one worth opening."""
    w = web(request)
    with w.opened() as c:
        run_id = row_id(run) if run is not None else q.latest_run(c)
        if run_id is None:
            return w.render(request, "empty.html", {}, c)
    return scoped_redirect(request, run_id, "triage")


@router.get("/runs/{run_id}/triage", response_class=HTMLResponse)
def triage(request: Request, run_id: int, producer: str | None = None,
           occ: int | None = None, band: str = "", undo: str = "",
           verdict: str = ""):
    w = web(request)
    with w.opened() as c:
        summary = q.run_summary(c, row_id(run_id))
        if summary is None:
            raise HTTPException(404, "No such run.")
        # An unknown state narrows to nothing (the queries refuse it) rather
        # than silently showing everything under a filter label.
        vf = verdict or None
        groups = q.producer_groups(c, run_id, verdict=vf)
        if band:
            groups = [g for g in groups if g.band == band]
        selected = producer or (groups[0].producer_id if groups else None)
        occs = q.occurrences_for(c, run_id, selected, verdict=vf) if selected else []
        n_occ_total = (q.occurrences_total(c, run_id, selected, verdict=vf)
                       if selected else 0)
        detail = None
        if occ is not None or occs:
            detail = q.occurrence_detail(c, row_id(occ) if occ is not None
                                         else occs[0]["id"])
            # An occurrence from another run would put that run's producer under
            # this run's dismiss buttons.
            if detail and detail["run_id"] != run_id:
                detail = None
        # The undo strip is a restore button. It renders only when there is a
        # dismissal of this producer in this run to undo, never because a URL
        # said so: `?undo=<anything>` used to render a working restore form.
        if undo and not q.restorable(c, run_id, undo):
            undo = ""
        # Every link inside the console keeps the active filters, so `J` and `j`
        # walk the filtered set rather than silently dropping the filter. `base`
        # ends in `?` or `&`, ready for the next parameter.
        from urllib.parse import urlencode
        keep = {}
        if band:
            keep["band"] = band
        if verdict:
            keep["verdict"] = verdict
        here = q.run_urls(run_id)["triage"]
        return w.render(request, "triage.html", {
            "run": summary, "groups": groups,
            "selected": selected, "occurrences": occs, "detail": detail, "band": band,
            "n_occ_total": n_occ_total, "undo": undo, "verdict": verdict,
            "here": here,
            "base": here + "?" + (urlencode(keep) + "&" if keep else ""),
            "verdict_counts": q.verdict_counts(c, run_id),
            "verdict_states": q.VERDICT_STATES,
            "pipeline": q.pipeline(c, summary, w.reports_root),
        }, c)


@router.post("/producers/{producer_id:path}/dismiss")
def dismiss(request: Request, producer_id: str, run_id: int = Form(...),
            scope: str = Form("repo"), note: str = Form("")):
    """`d` is repo-wide, "Dismiss everywhere" is corpus-wide. See
    quarry/dismissals.py for what each is keyed on.

    Both write one producer-level ledger row (`occurrence_id` NULL, which the
    schema reserves for exactly this) and kill the producer's live occurrences in
    this run. Corpus-wide also sets `enabled=0` on the producer: a disable, never a
    delete (D8). The producer-level row is what later funnel passes and `restore`
    read: for a repo dismissal it names the target through its run, and for a
    corpus one it tells "this run's dismissal disabled the producer" apart from
    "the producer was already disabled by something else".

    Repo dismissals used to write no producer-level row, so they reached only this
    run, and the next scan of the same repository brought the producer back.

    The note is the operator's reason, stored in the ledger reason. It is free
    text, so it is scrubbed of control characters and capped like any other
    stored string.

    The redirect carries `undo=` so the next page can render a strip with a working
    restore button. A disposition whose reversal the operator cannot reach is, on
    this product's own thesis, indistinguishable from a deletion.
    """
    from ... import taint
    if scope not in ("repo", "corpus"):
        raise HTTPException(400, "scope must be 'repo' or 'corpus'.")
    note = taint.scrub_text(note.strip(), 500)
    with web(request).opened() as c:
        if q.run_summary(c, row_id(run_id)) is None:
            raise HTTPException(404, "No such run.")
        if not q.producer_exists(c, producer_id):
            raise HTTPException(404, "No such producer.")
        writes.dismiss_producer(c, run_id, producer_id, scope, note)
    from urllib.parse import quote
    return RedirectResponse(
        f"{q.run_urls(run_id)['triage']}?undo={quote(producer_id, safe='')}",
        status_code=303)


@router.post("/producers/{producer_id:path}/restore")
def restore(request: Request, producer_id: str, run_id: int = Form(...),
            back: str = Form("")):
    """Undo a dismissal, and *only* that.

    A resurrect clears everything suppressing an occurrence, so a naive restore
    would also revive findings the deterministic funnel killed for unrelated
    reasons (a test path, a merged duplicate). The operator undoing their own
    decision must not silently override the funnel, so restore is scoped to
    occurrences held out only by a dismissal: the operator's kills, and the
    funnel's `producer dismissed` kills made on the dismissal's behalf
    (`queries.restorable_occurrences`). It used to undo only the first, so a run
    scanned after a dismissal could never get those findings back.

    A repo dismissal is keyed on the target, so a restore from any run of that
    target withdraws it. The corpus-wide switch is turned back on, and its note
    cleared, only when the disable being undone was written by a corpus-wide
    dismissal in THIS run. A producer disabled some other way, or from another run,
    stays disabled with its note intact; restore then brings back only this run's
    occurrences.

    `back=run` returns to the run page, where the list of dismissals lives;
    anything else returns to the run's triage. It is a choice between two fixed
    pages, never a URL from the form.
    """
    with web(request).opened() as c:
        run = q.run_summary(c, row_id(run_id))
        if run is None:
            raise HTTPException(404, "No such run.")
        writes.restore_producer(c, run_id, producer_id, run["target"])
    urls = q.run_urls(run_id)
    return RedirectResponse(urls["run"] + "#dismissals" if back == "run"
                            else urls["triage"], status_code=303)
