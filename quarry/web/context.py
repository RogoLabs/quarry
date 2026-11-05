"""What every route needs from the running app, in one object.

These were closures inside `create_app`, which is why app.py was one function of
several hundred lines: every route had to live where it could see them. `create_app`
now builds one `Web` and stores it on `app.state.web`; a route in any router reads it
with `web(request)`.
"""
from __future__ import annotations

import hashlib
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from fastapi import Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from .. import config, db
from . import queries as q

#: Larger than any advisory the template can produce by two orders of magnitude.
ADVISORY_MAX_BYTES = 2 * 1024 * 1024


@dataclass
class Web:
    paths: config.Paths
    templates: Jinja2Templates

    @property
    def reports_root(self) -> Path:
        """The only directory the dashboard reads report files from."""
        return self.paths.root / "reports"

    def connect(self) -> sqlite3.Connection:
        return db.connect(self.paths.db)

    @contextmanager
    def opened(self) -> Iterator[sqlite3.Connection]:
        """One connection per request, closed when the request is done with it.

        Not a FastAPI yield-dependency: sync dependencies and sync routes run in
        separate threadpool calls, and sqlite3 refuses a connection used from a thread
        other than the one that opened it.
        """
        c = self.connect()
        try:
            yield c
        finally:
            c.close()

    def render(self, request: Request, name: str, ctx: dict,
               c: sqlite3.Connection | None = None):
        """TemplateResponse plus the context every page needs.

        The header's egress counter appears on every route, so it is merged here
        rather than repeated in eight call sites and forgotten in the ninth. It reads
        the totals only: it used to load and decorate the entire ledger on every
        request just to print two numbers.
        """
        close = c is None
        c = c or self.connect()
        try:
            tot = q.egress_totals(c)
            ctx = {**ctx,
                   "egress_out": q.human_bytes(tot["bytes_out"]),
                   "egress_hosts": tot["n_destinations"]}
        finally:
            if close:
                c.close()
        return self.templates.TemplateResponse(request, name, ctx)

    def spawn(self, args: list[str], log_name: str):
        """Start `python <args>` detached, logging to <root>/logs/<log_name>, and
        return the process so a caller can record its pid.

        The child gets its own copy of the log descriptor, so the parent closes its
        handle as soon as Popen returns; it used to leak one per click.
        """
        import subprocess
        import sys as _sys
        log = self.paths.root / "logs"
        log.mkdir(parents=True, exist_ok=True)
        with (log / log_name).open("ab") as fh:
            return subprocess.Popen([_sys.executable, *args],
                                    cwd=str(Path(__file__).resolve().parents[2]),
                                    stdout=fh, stderr=fh, stdin=subprocess.DEVNULL,
                                    start_new_session=True)

    def read_report_file(self, path_text: str) -> dict[str, Any]:
        """A report file's text, or why it is not shown.

        The path comes from the database or the run manifest, and both are written
        by a CLI that accepts `--out` anywhere. The dashboard serves only files whose
        RESOLVED path is inside <data root>/reports, so a row pointing elsewhere (or a
        symlink inside reports pointing out) is refused rather than read.
        """
        root = self.reports_root.resolve()
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


def web(request: Request) -> Web:
    return request.app.state.web


class RouteTable:
    """Routes declared in a module and registered flat on the app.

    Not an APIRouter. FastAPI 0.141 keeps an included router as one nested
    `_IncludedRouter` entry in `app.routes`, so the security tests, which enumerate
    `app.routes` to prove every POST route refuses a cross-site request, would have
    found no POST route at all and passed while covering nothing. Registering each
    route with `app.add_api_route` keeps `app.routes` the complete list it was when
    every route was declared inside `create_app`, and the app-wide CSRF dependency
    applies to each one exactly as before.
    """

    def __init__(self) -> None:
        self.entries: list[tuple[str, Any, list[str], dict[str, Any]]] = []

    def _add(self, methods: list[str], path: str, kw: dict[str, Any]):
        def deco(fn):
            self.entries.append((path, fn, methods, kw))
            return fn
        return deco

    def get(self, path: str, **kw: Any):
        return self._add(["GET"], path, kw)

    def post(self, path: str, **kw: Any):
        return self._add(["POST"], path, kw)

    def register(self, app) -> None:
        for path, fn, methods, kw in self.entries:
            app.add_api_route(path, fn, methods=methods, **kw)


def scoped_redirect(request: Request, run: int, page: str) -> RedirectResponse:
    """The old `/<page>?run=N` form, sent to `/runs/N/<page>` with every other
    parameter kept. Bookmarks and links written before the run moved into the
    path keep working, and there is one URL per view."""
    from urllib.parse import urlencode
    rest = [(k, v) for k, v in request.query_params.multi_items() if k != "run"]
    url = f"/runs/{run}/{page}" + (f"?{urlencode(rest)}" if rest else "")
    return RedirectResponse(url, status_code=302)
