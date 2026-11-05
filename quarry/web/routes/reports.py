"""What the last two stages produced: validation verdicts, advisory drafts, and the
Layer 2 digest. Report files are read only through `Web.read_report_file`, which
refuses any path that does not resolve inside <data root>/reports."""
from __future__ import annotations

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse

from .. import queries as q
from ..context import RouteTable, scoped_redirect, web
from ..security import row_id

router = RouteTable()


# ------------------------------------------------------------ validation

@router.get("/validation", response_class=HTMLResponse)
def validation_all(request: Request, run: int | None = None, state: str = ""):
    """Every run's verdicts. `?run=N` is the old spelling of `/runs/N/validation`."""
    if run is not None:
        return scoped_redirect(request, row_id(run), "validation")
    return validation_page(request, None, state)


@router.get("/runs/{run_id}/validation", response_class=HTMLResponse)
def validation(request: Request, run_id: int, state: str = ""):
    return validation_page(request, row_id(run_id), state)


def validation_page(request: Request, run: int | None, state: str):
    """Latest verdict per (run, finding, seat, lens), newest first.

    `verdicts` had a writer (validate.record_verdict) and no reader anywhere in
    the dashboard, so a confirmation existed only in a terminal scrollback."""
    if state and state not in q.VERDICT_STATES:
        raise HTTPException(400, "state must be one of: "
                                 + ", ".join(q.VERDICT_STATES) + ".")
    w = web(request)
    with w.opened() as c:
        run_row = None
        if run is not None:
            run_row = q.run_summary(c, run)
            if run_row is None:
                raise HTTPException(404, "No such run.")
        rows = q.latest_verdicts(c, run_id=run, state=state or None)
        counts = q.verdict_counts(c, run)
        shown_total = counts[state] if state else counts["total"]
        return w.render(request, "validation.html", {
            "rows": rows, "counts": counts, "state": state, "run": run_row,
            "states": q.VERDICT_STATES, "shown_total": shown_total,
            "here": q.run_urls(run)["validation"] if run is not None else "/validation",
            "pipeline": q.pipeline(c, run_row, w.reports_root) if run_row else None,
        }, c)


# ------------------------------------------------------------ advisories

@router.get("/advisories", response_class=HTMLResponse)
def advisories_all(request: Request, run: int | None = None):
    """Every run's drafts. `?run=N` is the old spelling of `/runs/N/advisories`."""
    if run is not None:
        return scoped_redirect(request, row_id(run), "advisories")
    return advisories_page(request, None)


@router.get("/runs/{run_id}/advisories", response_class=HTMLResponse)
def advisories_list(request: Request, run_id: int):
    return advisories_page(request, row_id(run_id))


def advisories_page(request: Request, run: int | None):
    w = web(request)
    with w.opened() as c:
        run_row = None
        if run is not None:
            run_row = q.run_summary(c, run)
            if run_row is None:
                raise HTTPException(404, "No such run.")
        ids = [run] if run is not None else q.run_ids(c)
        digests = [d for d in (q.digest(c, rid, w.reports_root) for rid in ids) if d]
        return w.render(request, "advisories.html", {
            "rows": q.advisories(c, run), "run": run_row, "digests": digests,
            "pipeline": q.pipeline(c, run_row, w.reports_root) if run_row else None,
        }, c)


@router.get("/runs/{run_id}/digest", response_class=HTMLResponse)
def digest_detail(request: Request, run_id: int):
    """The Layer 2 digest, as escaped text like an advisory draft, read through the
    same confinement to <data root>/reports. Its path comes from the run manifest,
    which `quarry report --out` can point anywhere."""
    w = web(request)
    with w.opened() as c:
        run = q.run_summary(c, row_id(run_id))
        if run is None:
            raise HTTPException(404, "No such run.")
        d = q.digest(c, run_id, w.reports_root)
        if d is None:
            raise HTTPException(404, "No deep-review digest was written for this run.")
        return w.render(request, "digest.html", {
            "d": d, "run": run, "f": w.read_report_file(d["path"])}, c)


@router.get("/advisories/{aid}", response_class=HTMLResponse)
def advisory_detail(request: Request, aid: int):
    """Escaped preformatted text, never Markdown rendered to HTML: the draft
    carries target-controlled strings (routes, file names, response excerpts),
    and a renderer is one more parser between them and the page."""
    w = web(request)
    with w.opened() as c:
        a = q.advisory(c, row_id(aid))
        if a is None:
            raise HTTPException(404, "No such advisory.")
        return w.render(request, "advisory.html", {
            "a": a, "f": w.read_report_file(a["path"])}, c)
