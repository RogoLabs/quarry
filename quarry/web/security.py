"""Request hygiene for the dashboard.

The dashboard renders findings from untrusted repositories and has routes that spawn
processes and send signals, so "it only listens on loopback" is not a defence on its
own: any page in the operator's browser can submit a form to 127.0.0.1, and a DNS
rebinding page can read responses as its own origin. Three layers close that:
a Host allowlist (rebinding), an Origin check plus a per-process form token on every
state-changing request (CSRF), and headers that refuse framing.

Moved out of app.py unchanged. Everything here is installed app-wide by
`app.create_app`, so a route added in any router is covered without opting in.
"""
from __future__ import annotations

import re
import secrets
from typing import Awaitable, Callable

from fastapi import HTTPException, Request
from fastapi.responses import PlainTextResponse
from starlette.datastructures import Headers, MutableHeaders

#: The only Host values a loopback request legitimately carries. Starlette's
#: TrustedHostMiddleware cannot express `[::1]:PORT` (it splits on the first colon, so
#: the host compares as "["), which is why this is a regex rather than that class.
_LOOPBACK_HOST = re.compile(r"^(?:127\.0\.0\.1|localhost|\[::1\])(?::\d{1,5})?$",
                            re.IGNORECASE)

SECURITY_HEADERS = {
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "same-origin",
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

    Origin is checked first. `Referrer-Policy: same-origin` (set above) keeps a real
    Origin and Referer on the dashboard's own form POSTs while sending nothing to other
    sites. `no-referrer` made browsers send `Origin: null` here, which locked out
    Safari before 16.4: it sends no Sec-Fetch-Site either, so nothing proved the
    request was ours. `null` is still treated as absent, and the decision falls to
    Sec-Fetch-Site, then Referer. A request carrying none of the three is refused.
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


def csrf_guard(csrf_token: str) -> Callable[[Request], Awaitable[None]]:
    """The app-wide dependency for one server process and its form token."""

    async def guard(request: Request) -> None:
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

    return guard
