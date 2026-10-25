"""The triage dashboard. Loopback only.

Per Seat 4: `/triage` (the queue and its detail, no route change ever),
`/runs/{id}` (the funnel, which *is* the live progress view), `/runs` (history).
`/validation` lists the latest dynamic verdicts, `/advisories` the drafts `quarry
report` wrote. `/research*` is the deep-review layer; `/egress` is the containment
ledger. The nav runs in pipeline order.

The build constraint that drives the whole design: **every number in the funnel is a
link to the set it killed, and it renders code, not paths.** A funnel you cannot audit
is indistinguishable from a lie, and the code comes from evidence blobs so the pane
keeps working after the clone is gone.

That constraint had two holes when this file was reviewed, and both are closed here:
`queries.suppressed()` excluded `boost`, so two of eleven stages linked to an empty
table; and `POST /producers/{id}/restore` existed with no caller anywhere in the
templates, so the reversibility the UI advertised could not be exercised.
"""
from __future__ import annotations

import hashlib
import html
import json
import re
import secrets
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from markupsafe import Markup, escape
from starlette.datastructures import Headers, MutableHeaders
from starlette.exceptions import HTTPException as StarletteHTTPException

from .. import config, db
from ..research.ensemble import FAMILY as _MODEL_FAMILY, family as _family
from . import queries as q

# Offered in the UI. Ordered so the default selection spans families.
DEEP_MODELS = ["qwen3-coder:30b", "gpt-oss:20b", "devstral:24b",
               "qwen3.6:27b", "deepseek-coder-v2:16b", "codestral:22b"]

HERE = Path(__file__).resolve().parent

# ------------------------------------------------------------- request hygiene
#
# The dashboard renders findings from untrusted repositories and has routes that spawn
# processes and send signals, so "it only listens on loopback" is not a defence on its
# own: any page in the operator's browser can submit a form to 127.0.0.1, and a DNS
# rebinding page can read responses as its own origin. Three layers close that:
# a Host allowlist (rebinding), an Origin check plus a per-process form token on every
# state-changing request (CSRF), and headers that refuse framing.

#: The only Host values a loopback request legitimately carries. Starlette's
#: TrustedHostMiddleware cannot express `[::1]:PORT` (it splits on the first colon, so
#: the host compares as "["), which is why this is a regex rather than that class.
_LOOPBACK_HOST = re.compile(r"^(?:127\.0\.0\.1|localhost|\[::1\])(?::\d{1,5})?$",
                            re.IGNORECASE)

SECURITY_HEADERS = {
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


class LoopbackHostMiddleware:
    """Reject any request whose Host is not a loopback name (DNS rebinding).

    A rebinding attack points attacker.example at 127.0.0.1 after the page loads; the
    browser then treats the dashboard as same-origin with the attacker's page, but it
    still sends `Host: attacker.example`, which is what this refuses.
    """

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] in ("http", "websocket"):
            host = Headers(scope=scope).get("host", "")
            if not _LOOPBACK_HOST.match(host):
                if scope["type"] == "websocket":
                    await send({"type": "websocket.close", "code": 1008})
                else:
                    await PlainTextResponse("Invalid host header", status_code=400)(
                        scope, receive, send)
                return
        await self.app(scope, receive, send)


class SecurityHeadersMiddleware:
    """Stamp SECURITY_HEADERS on every response, static files and errors included."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def stamped(message) -> None:
            if message["type"] == "http.response.start":
                message.setdefault("headers", [])
                headers = MutableHeaders(scope=message)
                for k, v in SECURITY_HEADERS.items():
                    headers[k] = v
            await send(message)

        await self.app(scope, receive, stamped)


_SQLITE_INT_MAX = 2 ** 63 - 1


def row_id(n: int) -> int:
    """An id from the URL, or a 404 if SQLite could not even bind it.

    FastAPI parses `/evidence/99999999999999999999` as a perfectly good Python int, and
    sqlite3 then raises OverflowError at bind time, which surfaced as a 500. No row can
    have that id, so the honest answer is "not found".
    """
    if not -_SQLITE_INT_MAX - 1 <= n <= _SQLITE_INT_MAX:
        raise HTTPException(404, "No such record.")
    return n


def same_origin(request: Request) -> bool:
    """Did this request come from a page this server served?

    Origin is checked first. `Referrer-Policy: no-referrer` (set above) makes browsers
    send `Origin: null` on same-origin form POSTs, per the Fetch spec's origin
    serialisation, so `null` is treated as absent and the decision falls to
    Sec-Fetch-Site, which the referrer policy does not affect. Referer is the last
    resort for clients that send neither. A request carrying none of the three is
    refused.
    """
    served = f"{request.url.scheme}://{request.headers.get('host', '')}".lower()
    origin = request.headers.get("origin")
    if origin and origin != "null":
        return origin.lower() == served
    site = request.headers.get("sec-fetch-site")
    if site:
        return site == "same-origin"
    ref = request.headers.get("referer", "").lower()
    return bool(ref) and (ref == served or ref.startswith(served + "/"))

#: name -> (mtime_ns, content hash). See `asset()`.
_ASSET_REV: dict[str, tuple[int, str]] = {}


def asset(name: str) -> str:
    """`/static/<name>` with a content-hash query string.

    Needed because `StaticFiles` sets an ETag derived from `mtime + size` and never
    sets `Cache-Control`, so the browser falls back to heuristic freshness and may
    serve a memory-cached copy without revalidating — and a write that preserves both
    mtime and size yields a *valid* ETag for stale bytes. A content hash in the URL has
    neither hole.

    The hash is recomputed only when `mtime_ns` changes, so editing `app.css` takes
    effect on the next reload with no server restart. A startup-time hash would not:
    `uvicorn --reload` watches `*.py`.
    """
    p = HERE / "static" / name
    try:
        mtime = p.stat().st_mtime_ns
    except OSError:
        return f"/static/{name}"
    hit = _ASSET_REV.get(name)
    if hit is None or hit[0] != mtime:
        hit = (mtime, hashlib.sha256(p.read_bytes()).hexdigest()[:12])
        _ASSET_REV[name] = hit
    return f"/static/{name}?v={hit[1]}"


def rule_id(text: str, limit: int = 34) -> str:
    """Middle-truncate a rule id, preferring dot boundaries, bounded by `limit`.

    `word-break:break-all` rendered
    `javascript.express.security.audit.xss.mustache.var-in-href` as
    `…audit.xss.must / ache.var-in-hre / f` — the most important string in the primary
    column, made unreadable by its own overflow rule. CSS can only ellipsis at the end,
    which drops the tail; a left-ellipsis needs `direction:rtl` plus bidi control
    characters, which mangles mixed content. So it happens here, where it is
    deterministic and testable.

    Both ends carry information — the head names the language and family, the tail names
    the specific rule — so the middle goes. The result is never longer than `limit`,
    which is what keeps the CSS ellipsis a backstop rather than a second truncation.
    """
    text = str(text or "")
    if len(text) <= limit:
        return text

    parts = text.split(".")
    if len(parts) >= 3:
        # Keep the whole final segment when it leaves room for a meaningful head.
        tail = parts[-1]
        if len(tail) + 4 <= limit:
            head_budget = limit - len(tail) - 1          # 1 for the ellipsis
            head = ""
            for seg in parts[:-1]:
                nxt = seg if not head else f"{head}.{seg}"
                if len(nxt) > head_budget:
                    break
                head = nxt
            if head:
                return f"{head}\u2026{tail}"
            return f"{parts[0][:head_budget]}\u2026{tail}"

    # No usable dot structure: split the budget down the middle.
    keep = (limit - 1) // 2
    return f"{text[:limit - 1 - keep]}\u2026{text[-keep:]}"


def tail_path(text: str, limit: int = 34) -> str:
    """Keep the end of a path. The filename and line are what you read; the directory
    prefix repeats down the whole column."""
    text = str(text or "")
    return text if len(text) <= limit else "\u2026" + text[-(limit - 1):]


#: Characters that change how surrounding text is displayed without being displayed
#: themselves: bidi embeddings and overrides (U+202A-202E), bidi isolates
#: (U+2066-2069), zero-width spaces, joiners and directional marks (U+200B-200F), the
#: Arabic letter mark (U+061C) and the zero-width no-break space / BOM (U+FEFF).
#: Every one of them can arrive from a scanned repository in a path, a rule id, a
#: message, a code line or a model's quote, and an RLO in a filename is enough to make
#: `evil.py` read as something else on the screen whose job is to show what is true.
_INVISIBLE = re.compile("[‪-‮⁦-⁩​-‏؜﻿]")


def visible(text) -> Markup:
    """Escape `text` and render each invisible formatting character as a token such
    as `‹U+202E›`, so it is seen rather than obeyed."""
    if text is None:
        return Markup("")
    return Markup(_INVISIBLE.sub(lambda m: f"‹U+{ord(m.group()):04X}›",
                                 str(escape(text))))


def _finalize(value):
    """Jinja `finalize` hook: the backstop for any field the templates did not mark
    with `|visible`. Values without invisible characters pass through untouched, so
    autoescaping still applies to them as before."""
    if isinstance(value, str) and _INVISIBLE.search(value):
        return visible(value)
    return value


def create_app() -> FastAPI:
    paths = config.paths()

    # Per process, never persisted. A form rendered by a previous server process is
    # refused and the operator reloads; that is the whole cost.
    csrf_token = secrets.token_urlsafe(32)

    async def csrf_guard(request: Request) -> None:
        """Every state-changing request must be same-origin AND carry the form token.

        Installed as an app-wide dependency rather than per route, so a POST route
        added later is guarded without anyone remembering to opt it in.
        """
        if request.method in _SAFE_METHODS:
            return
        if not same_origin(request):
            raise HTTPException(403, "Cross-origin request refused. State-changing "
                                     "actions are accepted only from this dashboard's "
                                     "own pages.")
        form = await request.form()
        sent = form.get("csrf")
        if not isinstance(sent, str) or not secrets.compare_digest(sent, csrf_token):
            raise HTTPException(403, "Missing or stale form token. Reload the page "
                                     "and try again.")

    app = FastAPI(title="Quarry", docs_url=None, redoc_url=None,
                  dependencies=[Depends(csrf_guard)])
    # add_middleware prepends, so the last one added runs first: headers wrap
    # everything, including the 400 the Host check returns.
    app.add_middleware(LoopbackHostMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.state.csrf_token = csrf_token
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
    templates = Jinja2Templates(directory=HERE / "templates")
    templates.env.globals["csrf_token"] = csrf_token
    templates.env.filters["visible"] = visible
    templates.env.finalize = _finalize
    templates.env.filters["sev"] = lambda s: (s or "info").lower()

    # One clock on screen. The database stores UTC and naive-local side by side; see
    # queries.local().
    templates.env.filters["local"] = q.local
    templates.env.filters["until"] = q.until
    templates.env.filters["elapsed"] = q.elapsed
    templates.env.filters["rule_id"] = rule_id
    templates.env.filters["tail_path"] = tail_path
    templates.env.globals["asset"] = asset
    templates.env.globals["ACTION_NOUN"] = q.ACTION_NOUN

    # Exposed so tests can assert against the environment that actually serves
    # requests rather than rebuilding a copy of it. A copy is how
    # tests/test_template_contract.py would come to pass a template the real app
    # rejects — the same class of desync it exists to catch.
    app.state.templates = templates

    def con() -> sqlite3.Connection:
        return db.connect(paths.db)

    @contextmanager
    def opened() -> Iterator[sqlite3.Connection]:
        """One connection per request, closed when the request is done with it.

        Not a FastAPI yield-dependency: sync dependencies and sync routes run in
        separate threadpool calls, and sqlite3 refuses a connection used from a thread
        other than the one that opened it.
        """
        c = con()
        try:
            yield c
        finally:
            c.close()

    def _spawn(args: list[str], log_name: str) -> None:
        """Start `python <args>` detached, logging to <root>/logs/<log_name>.

        The child gets its own copy of the log descriptor, so the parent closes its
        handle as soon as Popen returns; it used to leak one per click.
        """
        import subprocess
        import sys as _sys
        log = paths.root / "logs"
        log.mkdir(parents=True, exist_ok=True)
        with (log / log_name).open("ab") as fh:
            subprocess.Popen([_sys.executable, *args],
                             cwd=str(Path(__file__).resolve().parents[2]),
                             stdout=fh, stderr=fh, stdin=subprocess.DEVNULL,
                             start_new_session=True)

    def latest_run(c: sqlite3.Connection) -> int | None:
        """The newest run worth opening.

        `status='done'` alone meant that during your first scan `/triage` told you to
        go and run a scan. A run in flight is a better answer than an empty state.
        """
        r = c.execute("SELECT id FROM runs WHERE status='done' ORDER BY id DESC "
                      "LIMIT 1").fetchone()
        if r:
            return r["id"]
        r = c.execute("SELECT id FROM runs WHERE status='running' ORDER BY id DESC "
                      "LIMIT 1").fetchone()
        return r["id"] if r else None

    def render(request: Request, name: str, ctx: dict, c: sqlite3.Connection | None = None):
        """TemplateResponse plus the context every page needs.

        The header's egress counter appears on every route, so it is merged here
        rather than repeated in eight call sites and forgotten in the ninth. It reads
        the totals only: it used to load and decorate the entire ledger on every
        request just to print two numbers.
        """
        close = c is None
        c = c or con()
        try:
            tot = q.egress_totals(c)
            ctx = {**ctx,
                   "egress_out": q.human_bytes(tot["bytes_out"]),
                   "egress_hosts": tot["n_destinations"]}
        finally:
            if close:
                c.close()
        return templates.TemplateResponse(request, name, ctx)

    # ------------------------------------------------------------ error pages

    @app.exception_handler(StarletteHTTPException)
    def http_error(request: Request, exc: StarletteHTTPException):
        """A themed page instead of a JSON blob.

        The most likely error in the product is the single-family refusal in
        `research_start`; returning raw JSON there lost the form, the model selection
        and the theme, and showed the operator a `{"detail": ...}` object.

        Registered on starlette's HTTPException, which FastAPI's subclasses, so the
        router's own 404 and 405 get the themed page too, not only the ones a route
        raises.
        """
        detail = str(exc.detail)
        if request.headers.get("hx-request"):
            return HTMLResponse(f'<p class="dim">{html.escape(detail)}</p>',
                                status_code=exc.status_code)
        # The status code has to survive the template. A 404 that answers 200 is the
        # same class of dishonesty as an unauditable funnel, one layer down.
        resp = render(request, "error.html", {"code": exc.status_code, "detail": detail})
        resp.status_code = exc.status_code
        return resp

    @app.exception_handler(Exception)
    def unhandled(request: Request, exc: Exception):
        """An unhandled exception renders a page that says what broke.

        The HTTPException handler above never saw these, so anything the code itself
        got wrong surfaced as starlette's bare `Internal Server Error`: unstyled,
        unattributed, and identical whether the database was missing or a template
        called a filter that did not exist.

        This is loopback-only, single-operator software, so naming the exception on the
        page is right: there is no one to leak it to. The exception text can carry
        attacker-chosen strings (a path, a rule id), so it is escaped like any other.
        The traceback still goes to the log.

        Starlette runs this handler outside the user middleware stack, so the security
        headers are applied here by hand.
        """
        import traceback
        traceback.print_exc()
        detail = f"{type(exc).__name__}: {exc}"
        if request.headers.get("hx-request"):
            resp = HTMLResponse(f'<p class="dim">{html.escape(detail)}</p>',
                                status_code=500)
        else:
            try:
                resp = render(request, "error.html", {"code": 500, "detail": detail})
                resp.status_code = 500
            except Exception:
                # The error page itself failed, most likely the same broken template
                # environment. Say so in plain text rather than recursing.
                resp = HTMLResponse(
                    "<h1>500</h1><p>" + html.escape(detail) + "</p><p>The error page "
                    "could not render either, which usually means the template "
                    "environment is broken. Check the server log.</p>", status_code=500)
        resp.headers.update(SECURITY_HEADERS)
        return resp

    # ---------------------------------------------------------------- routes

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request):
        """Runs is the front door: the pipeline starts there. With nothing ingested
        the empty state says what to type instead of redirecting to an empty table."""
        with opened() as c:
            if c.execute("SELECT 1 FROM runs LIMIT 1").fetchone():
                return RedirectResponse("/runs", status_code=302)
            return render(request, "empty.html", {}, c)

    @app.get("/favicon.ico")
    def favicon():
        """Was a 404 on every page load, into the one log an operator might read."""
        return RedirectResponse(asset("favicon.svg"), status_code=302)

    @app.get("/triage", response_class=HTMLResponse)
    def triage(request: Request, run: int | None = None, producer: str | None = None,
               occ: int | None = None, band: str = "", undo: str = "",
               verdict: str = ""):
        with opened() as c:
            run_id = row_id(run) if run is not None else latest_run(c)
            if run_id is None:
                return render(request, "empty.html", {}, c)
            summary = q.run_summary(c, run_id)
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
                detail_id = row_id(occ) if occ is not None else occs[0]["id"]
                detail = q.occurrence(c, detail_id)
                # An occurrence from another run would put that run's producer under
                # this run's dismiss buttons.
                if detail and detail["run_id"] != run_id:
                    detail = None
                if detail:
                    detail["evidence"] = q.evidence(c, detail["blob_sha"])
                    detail["provenance"] = q.provenance(c, detail_id)
                    detail["verdicts"] = q.verdicts_for_finding(c, detail["finding_id"])
            # The undo strip is a restore button. It renders only when there is a
            # dismissal of this producer in this run to undo, never because a URL
            # said so: `?undo=<anything>` used to render a working restore form.
            if undo and not q.restorable(c, run_id, undo):
                undo = ""
            # Every link inside the console keeps the active filters, so `J` and `j`
            # walk the filtered set rather than silently dropping the filter.
            from urllib.parse import urlencode
            keep = {"run": run_id}
            if band:
                keep["band"] = band
            if verdict:
                keep["verdict"] = verdict
            return render(request, "triage.html", {
                "run": summary, "groups": groups,
                "selected": selected, "occurrences": occs, "detail": detail, "band": band,
                "n_occ_total": n_occ_total, "undo": undo, "verdict": verdict,
                "base": "/triage?" + urlencode(keep),
                "verdict_counts": q.verdict_counts(c, run_id),
                "verdict_states": q.VERDICT_STATES,
            }, c)

    @app.post("/producers/{producer_id:path}/dismiss")
    def dismiss(producer_id: str, run_id: int = Form(...), scope: str = Form("repo"),
                note: str = Form("")):
        """`d` is repo-local, `D` is corpus-wide. Corpus-wide sets `enabled=0` on the
        producer: a disable, never a delete (D8), so it is reversible and the ledger
        records who did it and why.

        A corpus-wide dismissal also writes one producer-level ledger row
        (`occurrence_id` NULL, which the schema reserves for exactly this). That row
        is what lets `restore` tell "this run's dismissal disabled the producer" apart
        from "the producer was already disabled by something else".

        The redirect carries `undo=` so the next page can render a strip with a working
        restore button. A disposition whose reversal the operator cannot reach is, on
        this product's own thesis, indistinguishable from a deletion.
        """
        if scope not in ("repo", "corpus"):
            raise HTTPException(400, "scope must be 'repo' or 'corpus'.")
        with opened() as c:
            if q.run_summary(c, row_id(run_id)) is None:
                raise HTTPException(404, "No such run.")
            if c.execute("SELECT 1 FROM producers WHERE id=?",
                         (producer_id,)).fetchone() is None:
                raise HTTPException(404, "No such producer.")
            with db.tx(c):
                if scope == "corpus":
                    c.execute("UPDATE producers SET enabled=0, dismissed_at=datetime('now'), "
                              "dismissed_note=? WHERE id=?",
                              (note or "operator dismissal", producer_id))
                    db.funnel(c, run_id, producer_id=producer_id, stage="operator",
                              action="kill", deterministic=False, actor="operator",
                              reason="producer disabled corpus-wide: "
                                     + (note or "operator dismissal"))
                ids = [r["id"] for r in c.execute(
                    "SELECT id FROM live_occurrences WHERE run_id=? AND producer_id=?",
                    (run_id, producer_id))]
                for oid in ids:
                    db.funnel(c, run_id, occurrence_id=oid, producer_id=producer_id,
                              stage="operator", action="kill", deterministic=False,
                              actor="operator",
                              reason=note or (f"producer dismissed {'corpus-wide' if scope == 'corpus' else 'for this repo'}"))
        from urllib.parse import quote
        return RedirectResponse(
            f"/triage?run={run_id}&undo={quote(producer_id, safe='')}", status_code=303)

    @app.post("/producers/{producer_id:path}/restore")
    def restore(producer_id: str, run_id: int = Form(...)):
        """Undo an operator dismissal, and *only* that.

        A resurrect clears everything suppressing an occurrence, so a naive restore
        would also revive findings the deterministic funnel killed for unrelated
        reasons (a test path, a merged duplicate). The operator undoing their own
        decision must not silently override the funnel, so restore is scoped to
        occurrences whose only suppression came from the operator.

        The same goes for the producer's corpus-wide switch. It is turned back on, and
        its dismissal note cleared, only when the disable being undone was written by
        a corpus-wide dismissal in THIS run. A producer disabled some other way, or
        from another run, stays disabled with its note intact; restore then brings
        back only this run's operator kills.
        """
        with opened() as c:
            if q.run_summary(c, row_id(run_id)) is None:
                raise HTTPException(404, "No such run.")
            with db.tx(c):
                if q.corpus_dismissal_run(c, producer_id) == run_id:
                    c.execute("UPDATE producers SET enabled=1, dismissed_at=NULL, "
                              "dismissed_note=NULL WHERE id=?", (producer_id,))
                    db.funnel(c, run_id, producer_id=producer_id, stage="operator",
                              action="resurrect", deterministic=False, actor="operator",
                              reason="corpus-wide dismissal withdrawn")
                for oid in q.operator_killed(c, run_id, producer_id):
                    db.funnel(c, run_id, occurrence_id=oid, producer_id=producer_id,
                              stage="operator", action="resurrect", deterministic=False,
                              actor="operator", reason="operator dismissal withdrawn")
        return RedirectResponse(f"/triage?run={run_id}", status_code=303)

    # ------------------------------------------------------------ deep mode

    @app.get("/research", response_class=HTMLResponse)
    def research_index(request: Request):
        with opened() as c:
            return render(request, "research.html", {
                "runs": q.research_runs(c), "ingested": q.ingested_runs(c),
                "models": DEEP_MODELS, "family_of": {m: _family(m) for m in DEEP_MODELS},
            }, c)

    @app.post("/research/start")
    def research_start(run_id: int = Form(...), models: list[str] = Form(...),
                       hours: float = Form(8.0), note: str = Form("")):
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
        with opened() as c:
            run = c.execute("SELECT status, volume_path FROM runs WHERE id=?",
                            (row_id(run_id),)).fetchone()
        if run is None:
            raise HTTPException(404, "No such run.")
        if run["status"] != "done" or not run["volume_path"]:
            raise HTTPException(409, "That run has no ingested volume to review.")
        argv = ["-m", "quarry.cli", "deep", str(run_id), "--models", ",".join(models)]
        if hours and 0 < hours < float("inf"):
            argv += ["--hours", str(hours)]
        _spawn(argv, f"deep-run{run_id}.log")
        return RedirectResponse("/research", status_code=303)

    @app.post("/research/{rid}/resume")
    def research_resume(rid: int, hours: float = Form(8.0)):
        """Pick a dead or stopped run back up. Completed units are skipped, so this
        continues rather than restarts. Refused while a live worker still holds it,
        which would otherwise put two workers on one run."""
        with opened() as c:
            rows = q.research_runs(c, rid=row_id(rid))
        if not rows:
            raise HTTPException(404, "No such research run.")
        row = rows[0]
        if row["status"] in ("running", "unverified"):
            raise HTTPException(409, f"Research run {rid} still has a live worker; "
                                     "stop it before resuming.")
        argv = ["-m", "quarry.cli", "deep", str(row["run_id"]),
                "--models", ",".join(json.loads(row["models"])),
                "--resume", str(rid)]
        if hours and 0 < hours < float("inf"):
            argv += ["--hours", str(hours)]
        _spawn(argv, f"deep-run{row['run_id']}.log")
        return RedirectResponse(f"/research/{rid}", status_code=303)

    @app.post("/research/{rid}/stop")
    def research_stop(rid: int):
        """Signal a running deep review.

        There was no way to end an eight-hour detached subprocess except `kill` from a
        terminal, so this exists. It signals only a process it can show is this run's
        worker: a stored pid outlives its process, the OS recycles pids, and SIGTERM to
        a recycled pid kills whatever unrelated program now holds it. See
        `queries.worker_identity()` for what the check is.
        """
        import os
        import signal
        with opened() as c:
            row = c.execute("SELECT id, run_id, pid, status, heartbeat FROM research_runs "
                            "WHERE id=?", (row_id(rid),)).fetchone()
        if row is None:
            raise HTTPException(404, "No such research run.")
        row = dict(row)
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

    @app.get("/research/{rid}", response_class=HTMLResponse)
    def research_detail(request: Request, rid: int):
        with opened() as c:
            d = q.research_detail(c, row_id(rid))
            if not d:
                raise HTTPException(404, "No such research run.")
            return render(request, "research_detail.html", {"r": d}, c)

    @app.get("/research/{rid}/progress", response_class=HTMLResponse)
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
        with opened() as c:
            d = q.research_detail(c, row_id(rid))
            if not d:
                raise HTTPException(404, "No such research run.")
            return render(request, "_research_progress.html", {"r": d}, c)

    @app.get("/runs", response_class=HTMLResponse)
    def runs_list(request: Request):
        with opened() as c:
            return render(request, "runs.html", {"runs": q.all_runs(c)}, c)

    @app.get("/runs/{run_id}", response_class=HTMLResponse)
    def run_detail(request: Request, run_id: int, stage: str | None = None,
                   action: str | None = None, suppressed: str | None = None):
        """`?stage=X[&action=Y]` opens one funnel cell's set. `?suppressed=all` opens
        every occurrence that is not live, which is the set the "suppressed" card
        counts."""
        with opened() as c:
            summary = q.run_summary(c, row_id(run_id))
            if not summary:
                raise HTTPException(404, "No such run.")
            if stage:
                rows = q.suppressed(c, run_id, stage, action)
                total = q.suppressed_total(c, run_id, stage, action)
            elif suppressed:
                rows = q.not_live(c, run_id)
                total = summary["total"] - summary["live"]
            else:
                rows, total = [], 0
            return render(request, "run.html", {
                "run": summary,
                "stages": q.funnel_stages(c, run_id),
                "stage": stage,
                "action": action,
                "all_suppressed": bool(suppressed) and not stage,
                "suppressed": rows,
                "suppressed_total": total,
                "quarantine": [dict(r) for r in c.execute(
                    "SELECT kind,original_path,detail FROM quarantined WHERE run_id=?",
                    (run_id,))],
                "led": q.egress_ledger(c, run_id),
                "pipeline": q.pipeline(c, summary),
                "vc": q.verdict_counts(c, run_id),
            }, c)

    @app.get("/egress", response_class=HTMLResponse)
    def egress(request: Request):
        """The whole ledger, every run, no LIMIT.

        The per-run table was the last element on a page that can carry 300 suppressed
        rows, capped at twelve with no total and no "N more", and it mixed global
        `db sync` rows into a page titled with a specific run. To audit the core claim
        you had to scroll past everything else and then trust a truncated tail.
        """
        with opened() as c:
            return render(request, "egress.html", {"led": q.egress_ledger(c)}, c)

    # ------------------------------------------------------------ validation

    @app.get("/validation", response_class=HTMLResponse)
    def validation(request: Request, run: int | None = None, state: str = ""):
        """Latest verdict per (run, finding, seat, lens), newest first.

        `verdicts` had a writer (validate.record_verdict) and no reader anywhere in
        the dashboard, so a confirmation existed only in a terminal scrollback."""
        if state and state not in q.VERDICT_STATES:
            raise HTTPException(400, "state must be one of: "
                                     + ", ".join(q.VERDICT_STATES) + ".")
        with opened() as c:
            run_row = None
            if run is not None:
                run_row = q.run_summary(c, row_id(run))
                if run_row is None:
                    raise HTTPException(404, "No such run.")
            rows = q.latest_verdicts(c, run_id=run, state=state or None)
            counts = q.verdict_counts(c, run)
            shown_total = counts[state] if state else counts["total"]
            return render(request, "validation.html", {
                "rows": rows, "counts": counts, "state": state, "run": run_row,
                "states": q.VERDICT_STATES, "shown_total": shown_total,
            }, c)

    # ------------------------------------------------------------ advisories

    reports_root = paths.root / "reports"

    #: Larger than any advisory the template can produce by two orders of magnitude.
    ADVISORY_MAX_BYTES = 2 * 1024 * 1024

    def read_advisory(path_text: str) -> dict:
        """The draft's text, or why it is not shown.

        The path comes from the database, and the database is written by a CLI that
        accepts `--out` anywhere. The dashboard serves only files whose RESOLVED path
        is inside <data root>/reports, so a row pointing elsewhere (or a symlink
        inside reports pointing out) is refused rather than read.
        """
        root = reports_root.resolve()
        try:
            p = Path(path_text).resolve(strict=True)
        except (OSError, RuntimeError, ValueError):
            return {"ok": False, "why": "The file is gone from disk."}
        if not p.is_relative_to(root):
            return {"ok": False, "why": f"The file is outside {root}, so the dashboard "
                                         "does not open it. Read it from the terminal."}
        if not p.is_file():
            return {"ok": False, "why": "The path is not a regular file."}
        size = p.stat().st_size
        if size > ADVISORY_MAX_BYTES:
            return {"ok": False, "why": f"The file is {size} bytes, over the "
                                         f"{ADVISORY_MAX_BYTES} byte display limit."}
        body = p.read_bytes()
        return {"ok": True, "text": body.decode("utf-8", "replace"),
                "sha256": hashlib.sha256(body).hexdigest(), "bytes": size}

    @app.get("/advisories", response_class=HTMLResponse)
    def advisories_list(request: Request, run: int | None = None):
        with opened() as c:
            run_row = None
            if run is not None:
                run_row = q.run_summary(c, row_id(run))
                if run_row is None:
                    raise HTTPException(404, "No such run.")
            return render(request, "advisories.html", {
                "rows": q.advisories(c, run), "run": run_row,
            }, c)

    @app.get("/advisories/{aid}", response_class=HTMLResponse)
    def advisory_detail(request: Request, aid: int):
        """Escaped preformatted text, never Markdown rendered to HTML: the draft
        carries target-controlled strings (routes, file names, response excerpts),
        and a renderer is one more parser between them and the page."""
        with opened() as c:
            a = q.advisory(c, row_id(aid))
            if a is None:
                raise HTTPException(404, "No such advisory.")
            f = read_advisory(a["path"])
            return render(request, "advisory.html", {"a": a, "f": f}, c)

    @app.get("/evidence/{occurrence_id}", response_class=HTMLResponse)
    def evidence_fragment(request: Request, occurrence_id: int):
        """Used by the killed-set view: a suppressed finding must render its code too.

        The `<a>` carries both `href` and `hx-get`, and htmx is deferred, so a click in
        the load window follows the href. That used to land on a bare fragment with no
        <html> element; now it renders a full page.
        """
        with opened() as c:
            d = q.occurrence(c, row_id(occurrence_id))
            if not d:
                raise HTTPException(404, "No such occurrence.")
            d["evidence"] = q.evidence(c, d["blob_sha"])
            d["provenance"] = q.provenance(c, occurrence_id)
            d["verdicts"] = q.verdicts_for_finding(c, d["finding_id"])
            if request.headers.get("hx-request"):
                return templates.TemplateResponse(request, "_detail.html", {"detail": d})
            return render(request, "evidence.html", {"detail": d}, c)

    return app


app = create_app()
