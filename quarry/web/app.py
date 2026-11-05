"""The triage dashboard. Loopback only.

Per Seat 4: `/runs/{id}/triage` (the queue and its detail, no route change ever),
`/runs/{id}` (the funnel, which *is* the live progress view), `/runs` (history).
`/runs/{id}/validation` lists the latest dynamic verdicts, `/runs/{id}/advisories`
the drafts `quarry report` wrote; `/validation` and `/advisories` are the same across
every run. The run is in the path so the nav can keep it. `/research*` is the
deep-review layer; `/egress` is the containment ledger; `/setup` is what runs before
any run. The nav runs in pipeline order.

The build constraint that drives the whole design: **every number in the funnel is a
link to the set it killed, and it renders code, not paths.** A funnel you cannot audit
is indistinguishable from a lie, and the code comes from evidence blobs so the pane
keeps working after the clone is gone.

That constraint had two holes when this file was reviewed, and both are closed here:
`queries.suppressed()` excluded `boost`, so two of eleven stages linked to an empty
table; and `POST /producers/{id}/restore` existed with no caller anywhere in the
templates, so the reversibility the UI advertised could not be exercised.

Layout. This file was one `create_app` closure of several hundred lines with SQL
inline in its routes. It now only assembles the app: request hygiene (security.py),
the template environment (present.py), the per-app state every route needs
(context.py), the error pages, and the routers (routes/). Reads live in queries.py and
every write in writes.py. The names tests and callers imported from here are
re-exported below.
"""
from __future__ import annotations

import html
import secrets

from fastapi import Depends, FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from .. import config
from .context import Web
from .present import (HERE, _ASSET_REV, _INVISIBLE, _finalize, asset,  # noqa: F401
                      build_templates, rule_id, tail_path, visible)
from .routes import ROUTERS
from .routes.research import DEEP_MODELS  # noqa: F401
from .security import (SECURITY_HEADERS, LoopbackHostMiddleware,  # noqa: F401
                       SecurityHeadersMiddleware, csrf_guard, row_id, same_origin)

#: What this module offered before the split, still importable from here.
__all__ = ["app", "create_app", "DEEP_MODELS", "HERE", "SECURITY_HEADERS",
           "LoopbackHostMiddleware", "SecurityHeadersMiddleware", "asset", "row_id",
           "rule_id", "same_origin", "tail_path", "visible"]


def create_app() -> FastAPI:
    paths = config.paths()

    # Per process, never persisted. A form rendered by a previous server process is
    # refused and the operator reloads; that is the whole cost.
    csrf_token = secrets.token_urlsafe(32)

    # The guard is an app-wide dependency, so every route in every router below is
    # covered, including a POST route added later by someone who never heard of it.
    app = FastAPI(title="Quarry", docs_url=None, redoc_url=None,
                  dependencies=[Depends(csrf_guard(csrf_token))])
    # add_middleware prepends, so the last one added runs first: headers wrap
    # everything, including the 400 the Host check returns.
    app.add_middleware(LoopbackHostMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.state.csrf_token = csrf_token
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
    templates = build_templates(csrf_token)

    # Exposed so tests can assert against the environment that actually serves
    # requests rather than rebuilding a copy of it. A copy is how
    # tests/test_template_contract.py would come to pass a template the real app
    # rejects — the same class of desync it exists to catch.
    app.state.templates = templates
    app.state.web = web = Web(paths=paths, templates=templates)

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
        resp = web.render(request, "error.html", {"code": exc.status_code,
                                                  "detail": detail})
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
                resp = web.render(request, "error.html", {"code": 500, "detail": detail})
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

    # Flat, one entry per route, so `app.routes` lists every route as it did when they
    # all lived in this function (see context.RouteTable). No two paths overlap, so
    # the order across tables does not change which route answers a request.
    for table in ROUTERS:
        table.register(app)
    return app


app = create_app()
