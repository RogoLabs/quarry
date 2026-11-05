"""Runs: the front door, one run's page, its evidence, the egress ledger, and Setup."""
from __future__ import annotations

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from .. import queries as q
from ..context import RouteTable, web
from ..present import asset
from ..security import row_id

router = RouteTable()


@router.get("/", response_class=HTMLResponse)
def index(request: Request):
    """Runs is the front door: the pipeline starts there. With nothing ingested
    the empty state says what to type instead of redirecting to an empty table."""
    w = web(request)
    with w.opened() as c:
        if q.has_runs(c):
            return RedirectResponse("/runs", status_code=302)
        return w.render(request, "empty.html", {}, c)


@router.get("/favicon.ico")
def favicon():
    """Was a 404 on every page load, into the one log an operator might read."""
    return RedirectResponse(asset("favicon.svg"), status_code=302)


@router.get("/runs", response_class=HTMLResponse)
def runs_list(request: Request):
    w = web(request)
    with w.opened() as c:
        runs = q.all_runs(c)
        for r in runs:
            r["has_digest"] = q.digest(c, r["id"], w.reports_root) is not None
        return w.render(request, "runs.html", {"runs": runs}, c)


@router.get("/runs/{run_id}", response_class=HTMLResponse)
def run_detail(request: Request, run_id: int, stage: str | None = None,
               action: str | None = None, suppressed: str | None = None,
               arrived: str | None = None):
    """`?stage=X[&action=Y]` opens one funnel cell's set. `?suppressed=all` opens
    every occurrence that is not live, which is the set the "suppressed" card
    counts. `?arrived=1` opens the occurrences no funnel stage has seen."""
    w = web(request)
    with w.opened() as c:
        summary = q.run_summary(c, row_id(run_id))
        if not summary:
            raise HTTPException(404, "No such run.")
        if stage:
            rows = q.suppressed(c, run_id, stage, action)
            total = q.suppressed_total(c, run_id, stage, action)
        elif arrived:
            rows = q.arrived(c, run_id)
            total = q.arrived_total(c, run_id)
        elif suppressed:
            rows = q.not_live(c, run_id)
            total = summary["total"] - summary["live"]
        else:
            rows, total = [], 0
        return w.render(request, "run.html", {
            "run": summary,
            "stages": q.funnel_stages(c, run_id),
            "stage": stage,
            "action": action,
            "all_suppressed": bool(suppressed) and not stage and not arrived,
            "arrived": bool(arrived) and not stage,
            "suppressed": rows,
            "suppressed_total": total,
            "quarantine": q.quarantined(c, run_id),
            "led": q.egress_ledger(c, run_id),
            "pipeline": q.pipeline(c, summary, w.reports_root),
            "vc": q.verdict_counts(c, run_id),
            "dismissals": q.dismissals_for_run(c, run_id),
            "cli_stages": q.run_stages(c, summary, w.reports_root),
        }, c)


@router.get("/evidence/{occurrence_id}", response_class=HTMLResponse)
def evidence_fragment(request: Request, occurrence_id: int):
    """Used by the killed-set view: a suppressed finding must render its code too.

    The `<a>` carries both `href` and `hx-get`, and htmx is deferred, so a click in
    the load window follows the href. That used to land on a bare fragment with no
    <html> element; now it renders a full page.
    """
    w = web(request)
    with w.opened() as c:
        d = q.occurrence_detail(c, row_id(occurrence_id))
        if not d:
            raise HTTPException(404, "No such occurrence.")
        if request.headers.get("hx-request"):
            return w.templates.TemplateResponse(request, "_detail.html", {"detail": d})
        return w.render(request, "evidence.html", {"detail": d}, c)


@router.get("/egress", response_class=HTMLResponse)
def egress(request: Request):
    """The whole ledger, every run, no LIMIT.

    The per-run table was the last element on a page that can carry 300 suppressed
    rows, capped at twelve with no total and no "N more", and it mixed global
    `db sync` rows into a page titled with a specific run. To audit the core claim
    you had to scroll past everything else and then trust a truncated tail.
    """
    w = web(request)
    with w.opened() as c:
        return w.render(request, "egress.html", {"led": q.egress_ledger(c)}, c)


@router.get("/setup", response_class=HTMLResponse)
def setup(request: Request):
    """The stages that run only from a terminal and come before any run: doctor,
    `db sync` and target scoring. Read-only on purpose. Two of the three reach the
    network, and the dashboard starts nothing that does; it shows what each last
    left behind and the command to copy."""
    w = web(request)
    with w.opened() as c:
        return w.render(request, "setup.html", {
            "env": q.environment(c, w.paths.root, w.paths.db),
            "dbs": q.vulndb_status(c),
            "targets": q.targets(c),
        }, c)
