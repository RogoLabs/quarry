"""Concrete probe bodies, each with its own control.

Every probe is non-destructive by construction: it observes, it does not mutate or
delete data, and it does not try to take the target down.

The adjudication contract (validate.adjudicate_with_reason) is the same for every class:

  * confirmed needs the effect plus a control that lacks it (`baseline` and
    `differs_from_baseline`), so a response that is just how the route always behaves
    is never a confirmation;
  * rejected needs a negative control: a handler answered (`handled`, so not 404, 405 or
    nothing) and the attack behaved like the control did;
  * anything else is needs-review.

A probe decides only on the finding's own handler, a route whose static span encloses the
finding's line (routes.Route.encloses). On a sibling route in the same file it records
what it measured and leaves `differs_from_baseline` unset, so the verdict waits for a
human: a safe sibling says nothing about the flagged line, and an unsafe one is a
different finding. A rejection also needs a parameter the handler is known to read (a
path parameter, an OpenAPI query parameter, or one its body reads). A guessed `q` can
confirm but never reject, because a handler that ignores `q` behaves like any control.

Per class, the control and what decides:

  * authz, anonymous: a route declared protected by its own operation (a spec-wide
    requirement does not count), reached with no credentials. Control: an invalid
    credential, which a working check refuses. Baseline: a valid seeded credential,
    whose body the anonymous response must match. It never rejects: an anonymous refusal
    shows authentication, not whether one account can reach another's records.
  * rate limit: a lone request (baseline), then a bounded burst in one curl run. The
    finding is a missing defence, so it reproduces on sameness (reproduces_when="same").
  * XSS: a benign alphanumeric token (control) and a markup marker on the same parameter.
    Raw markup in a text/html response confirms; every declared parameter reflecting the
    control while encoding the markup and its quotes rejects.
  * command injection: an arithmetic echo whose product is not in the input (output),
    then `sleep 2` (timing), against a benign token. Rejects only when the handler
    refuses every metacharacter payload with 400/403/422 and accepts the benign token.
  * traversal: /etc/passwd inside the target's own container against a benign missing
    file. SSRF: the target's own root page fetched through it (an internal-only canary)
    and the never-resolvable `.invalid` sentinel, against a benign token. Neither
    reaches an external host. Both reject only on an explicit refusal the control did
    not get.
"""
from __future__ import annotations

import hashlib
import os
import re
import statistics
from dataclasses import dataclass
from urllib.parse import quote

from ..cwe import probe_class
from .routes import PATH_PARAM
from .validate import Candidate, ProbeEvidence, RunningTarget

ExecFn = "Callable[[list[str]], tuple[int, str]]"

# Paths whose name suggests an authentication or otherwise expensive endpoint, the
# natural target for the rate-limit and timing probes.
AUTH_HINTS = ("login", "signin", "sign-in", "sign_in", "auth", "token", "session",
              "password", "oauth", "account", "register", "reset")

# Status codes that mean the endpoint actually handled the request (as opposed to "wrong
# method" or "not found"), so the absence of a 429 among them is meaningful.
_REAL = {"200", "201", "204", "400", "401", "403", "409", "422", "429"}

# An explicit refusal of the input itself: the handler looked at it and said no.
_REFUSE = ("400", "403", "422")


def _fill(running: RunningTarget, path: str, *, first: str | None = None) -> str:
    """Substitute a value for every path parameter so the URL is requestable. A parameter
    named in `running.param_values` (vulnerability_id -> CVE-2024-3094) gets that value,
    so a probe reaches a record that exists; the rest fall back to the benign `1`. With
    `first`, the first parameter instead gets that payload (the injection case)."""
    pv = running.param_values or {}
    state = {"n": 0}

    def repl(m) -> str:
        state["n"] += 1
        if first is not None and state["n"] == 1:
            return first
        name = next(g for g in m.groups() if g)
        return pv.get(name, "1")

    return PATH_PARAM.sub(repl, path).strip("/")


def _concrete(running: RunningTarget, path: str) -> str:
    """The path with every parameter filled, leading slash kept, for a requestable URL."""
    return "/" + _fill(running, path)


def _status(exec_fn, url: str) -> str:
    rc, code = exec_fn(["-s", "-o", "/dev/null", "-w", "%{http_code}",
                        "--max-time", "5", url])
    return code.strip() if rc == 0 else ""


def _timing(exec_fn, url: str) -> tuple[str, float] | None:
    """(status, seconds). The status is what makes a timing comparison mean anything:
    two identifiers that both 404 time the router, not the auth check."""
    rc, out = exec_fn(["-s", "-o", "/dev/null", "-w", "%{http_code} %{time_total}",
                       "--max-time", "5", url])
    try:
        code, t = out.split()
        return (code, float(t)) if rc == 0 else None
    except ValueError:
        return None


def _auth_first(routes: list) -> list:
    """Routes with an auth-like path first, then the rest. Stable within each group."""
    return sorted(routes, key=lambda r: 0 if any(h in r.path.lower() for h in AUTH_HINTS)
                  else 1)


def _body(exec_fn, url: str) -> str:
    rc, out = exec_fn(["-s", "--max-time", "5", url])
    return out if rc == 0 else ""


def _inject(running: RunningTarget, route, payload: str) -> str:
    """Place a payload into a route's first path parameter, or as a query value when the
    route has none. Read-only: the result is a single GET URL."""
    base = running.base_url.rstrip("/")
    if PATH_PARAM.search(route.path):
        # First param gets the payload in one pass (so an angle-bracket payload is not
        # re-scanned as a param); the rest get their real value or the benign `1`.
        return base + "/" + _fill(running, route.path, first=payload)
    sep = "&" if "?" in route.path else "?"
    return base + _concrete(running, route.path) + f"{sep}q={payload}"


def _marker() -> str:
    return "qz" + os.urandom(4).hex()


# Signatures that mean a SQL interpreter saw malformed input, i.e. input reached a query
# unparameterised. Lower-cased comparison.
_SQL_ERRORS = ("sql syntax", "sqlite3.", "sqlite error", "operationalerror",
               "unrecognized token", "psycopg", "ora-00", "pg::", "syntax error at or near",
               "you have an error in your sql", "sqlstate", "unclosed quotation",
               "unterminated quoted", "mysql_fetch", "odbc", "mariadb")

# A read-only /etc/passwd line shape, the classic benign traversal signature. Inside the
# target's own container (host fs is not mounted), so this exposes nothing of the host.
_PASSWD = re.compile(r"root:[^:\n]*:0:0:")


def _has_sql_error(body: str) -> bool:
    low = body.lower()
    return any(sig in low for sig in _SQL_ERRORS)


# ------------------------------------------------------------------ requests

# curl's write-out, appended after the body so one request yields status, time and
# content type with the body. The marker cannot be confused with a body that merely
# contains "<<qz": the parse takes the last occurrence.
_WOUT = "\n<<qz|%{http_code}|%{time_total}|%{content_type}>>"


@dataclass(frozen=True)
class _Resp:
    """One measured response. `status` is "" when curl printed nothing usable and "000"
    when no HTTP response arrived (refused connection, timeout)."""
    status: str = ""
    body: str = ""
    ctype: str = ""
    secs: float = 0.0

    @property
    def ok(self) -> bool:
        return self.status[:1] == "2"

    @property
    def refused(self) -> bool:
        return self.status in ("401", "403")

    @property
    def reached(self) -> bool:
        """A handler answered: not a router miss, not a wrong method, not silence."""
        return bool(self.status) and self.status not in ("000", "404", "405")

    @property
    def html(self) -> bool:
        return self.ctype.split(";")[0].strip().lower() in ("text/html",
                                                           "application/xhtml+xml")

    def describe(self) -> str:
        if not self.status or self.status == "000":
            return "no HTTP response"
        ct = self.ctype.split(";")[0].strip() or "no content type"
        return f"HTTP {self.status}, {len(self.body.encode())} B, {ct}"


def _fetch(exec_fn, url: str, *, method: str = "GET", headers=(), data: str | None = None,
           max_time: int = 5, raw_path: bool = False) -> _Resp:
    """One request through the sidecar. `-g` stops curl reading `{}` and `[]` in a payload
    as its own URL globbing; `--path-as-is` (raw_path) stops it collapsing `../` before
    the request leaves, which silently turned every traversal payload into a plain path."""
    argv = ["-s", "-g", "--max-time", str(max_time)]
    if raw_path:
        argv.append("--path-as-is")
    if method != "GET":
        argv += ["-X", method]
    for h in headers:
        argv += ["-H", h]
    if data is not None:
        argv += ["-H", "Content-Type: application/json", "--data-binary", data]
    argv += ["-w", _WOUT, url]
    _rc, out = exec_fn(argv)
    body, sep, tail = (out or "").rpartition("\n<<qz|")
    if not sep:
        return _Resp()
    fields = tail.split(">>", 1)[0].split("|")
    try:
        secs = float(fields[1]) if len(fields) > 1 else 0.0
    except ValueError:
        secs = 0.0
    return _Resp(status=fields[0].strip(), body=body, secs=secs,
                 ctype=fields[2].strip() if len(fields) > 2 else "")


def _sha(body: str) -> str:
    return hashlib.sha256(body.encode()).hexdigest()[:16]


def _cred_header(scheme: str, value: str) -> str:
    """A credential header from a scheme: `X-API-KEY` -> `X-API-KEY: v`,
    `Authorization: Bearer` -> `Authorization: Bearer v`."""
    return f"{scheme} {value}" if ":" in scheme else f"{scheme}: {value}"


def _cred_label(scheme: str, who: str) -> str:
    """The same header for evidence text, with the secret replaced by whose it is."""
    return _cred_header(scheme, f"<{who}>")


# ------------------------------------------------------------------ the finding's route

def _own(routes: list, cand: Candidate) -> list:
    """Routes whose handler encloses the finding's line."""
    return [r for r in routes if r.encloses(cand.path, cand.start_line)]


def _scope(routes: list, cand: Candidate, ok=None) -> tuple[list, bool]:
    """(routes to probe, whether they are the finding's own). The finding's own routes
    when its line resolves to a handler the probe can address; otherwise every suitable
    route in the file, which the probe may measure but not decide on."""
    ok = ok or (lambda r: True)
    own = [r for r in _own(routes, cand) if ok(r)]
    if own:
        return own, True
    pool = [r for r in routes if ok(r)]
    # Routes with a parameter to put input into come first.
    return sorted(pool, key=lambda r: 0 if (r.params or r.query) else 1), False


def _readable(route) -> bool:
    return route.method in ("GET", "HEAD")


def _ev(own: bool, route, cand: Candidate, **kw) -> ProbeEvidence:
    """Evidence, with the decision withheld when the route is not the finding's own."""
    if not own and kw.get("differs_from_baseline") is not None:
        kw["differs_from_baseline"] = None
        kw["summary"] = (kw.get("summary", "") +
                         f"; {route.method} {route.path} is in the finding's file but its "
                         f"handler does not enclose line {cand.start_line}, so this is "
                         "held for review")
    return ProbeEvidence(**kw)


@dataclass(frozen=True)
class _Slot:
    """Where a probe puts its input: a path parameter by position, or a query name."""
    where: str          # "path" | "query"
    name: str
    index: int = 0
    declared: bool = True    # the handler is known to read it; a guess cannot reject


def _slots(route) -> list[_Slot]:
    out = [_Slot("path", next(g for g in m.groups() if g), i)
           for i, m in enumerate(PATH_PARAM.finditer(route.path))]
    out += [_Slot("query", q) for q in getattr(route, "query", ()) or ()]
    return out or [_Slot("query", "q", declared=False)]


def _url(running: RunningTarget, route, slot: _Slot, value: str, *,
         raw: bool = False) -> str:
    """A GET URL with `value` in `slot`, percent-encoded so the server decodes exactly the
    characters sent (raw=True leaves a path value as is, for a `../` that must arrive as
    path segments). Every other path parameter gets its seeded value or `1`."""
    base = running.base_url.rstrip("/")
    enc = value if raw else quote(value, safe="")
    pv = running.param_values or {}
    seen = {"i": -1}

    def repl(m) -> str:
        seen["i"] += 1
        if slot.where == "path" and seen["i"] == slot.index:
            return enc
        return quote(pv.get(next(g for g in m.groups() if g), "1"), safe="")

    path = "/" + PATH_PARAM.sub(repl, route.path).strip("/")
    if slot.where == "query":
        sep = "&" if "?" in path else "?"
        return f"{base}{path}{sep}{quote(slot.name, safe='')}={enc}"
    return base + path


# ------------------------------------------------------------------ authz, anonymous

def _valid_key(running: RunningTarget) -> tuple[str, str] | None:
    """(name, value) of a seeded credential, for the owner-credential baseline. A plain
    user's key first: it is the weakest principal that should see the route."""
    creds = running.credentials or {}
    for k in sorted(creds, key=lambda k: (k != "user_api_key", k)):
        if creds[k]:
            return k, creds[k]
    return None


def probe_broken_authz(running: RunningTarget, candidate: Candidate,
                       routes: list, exec_fn) -> ProbeEvidence:
    """Reach each GET route declared protected by its own operation with no credentials.
    Served, with an invalid credential refused and (when a seeded key exists) the same
    body a valid credential gets, is a confirmation. A refusal is not a rejection."""
    pool, own = _scope(routes, candidate,
                       lambda r: (r.auth_required is True and r.auth_scope == "operation"
                                  and _readable(r)))
    if not pool:
        inherited = [r for r in routes if r.auth_required and r.auth_scope == "global"]
        why = (f"; {len(inherited)} route(s) in the file inherit only the spec-wide "
               "security requirement, which also covers the public reads, so it is not "
               "counted as declared protection" if inherited else "")
        return ProbeEvidence(
            reproduced=False, determinism="unknown",
            summary="no route in the finding's file is declared auth-protected by its own "
                    f"operation (no per-operation OpenAPI security){why}, so "
                    "unauthenticated reach cannot be decided")

    denied, notes = 0, []
    for r in pool[:5]:
        url = running.base_url.rstrip("/") + _concrete(running, r.path)
        anon = _fetch(exec_fn, url)
        if anon.ok:
            return _anonymous_served(running, candidate, r, url, anon, exec_fn, own)
        denied += anon.refused
        notes.append(f"{r.method} {r.path} -> {anon.describe()}")

    if denied == len(notes):
        return ProbeEvidence(
            reproduced=False, determinism="deterministic",
            summary=f"all {denied} declared-protected route(s) refused unauthenticated "
                    "access (401/403). That shows authentication, not authorization: "
                    "whether one account can reach another's records is the cross-user "
                    "probe's question, so an anonymous refusal does not reject this",
            observed="; ".join(notes))
    return ProbeEvidence(
        reproduced=False, determinism="unknown",
        summary="declared-protected routes were neither clearly reachable nor clearly "
                "denied; inconclusive", observed="; ".join(notes))


def _anonymous_served(running, cand, r, url, anon: _Resp, exec_fn, own) -> ProbeEvidence:
    request = f"{r.method} {url}  (no credentials)"
    observed = f"no credentials: {anon.describe()}, body sha256 {_sha(anon.body)}"
    if not r.auth_header:
        return ProbeEvidence(
            reproduced=True, determinism="deterministic", request=request,
            observed=observed,
            summary=f"{r.method} {r.path} is declared protected by its own operation but "
                    f"answered {anon.status} with no credentials; the spec names no "
                    "header scheme, so no invalid-credential control could be sent")
    bad = _fetch(exec_fn, url, headers=[_cred_header(r.auth_header,
                                                     "quarry-invalid-" + os.urandom(6).hex())])
    parts = [f"invalid credential ({_cred_label(r.auth_header, 'invalid')}): "
             f"{bad.describe()}"]
    good = None
    if (vk := _valid_key(running)) is not None:
        good = _fetch(exec_fn, url, headers=[_cred_header(r.auth_header, vk[1])])
        parts.append(f"valid seeded credential ({_cred_label(r.auth_header, vk[0])}): "
                     f"{good.describe()}, body sha256 {_sha(good.body)}")
    baseline = "; ".join(parts)
    if not bad.refused:
        return ProbeEvidence(
            reproduced=True, determinism="deterministic", request=request,
            observed=observed, baseline=baseline,
            summary=f"{r.method} {r.path} is declared protected but answered "
                    f"{anon.status} to no credentials and {bad.status or 'nothing'} to an "
                    "invalid one; with no refusal to compare against, either the route "
                    "checks no credential at all or its spec is stale")
    if good is not None and not (good.ok and _sha(good.body) == _sha(anon.body)):
        return ProbeEvidence(
            reproduced=True, determinism="deterministic", request=request,
            observed=observed, baseline=baseline,
            summary=f"{r.method} {r.path} served a request with no credentials, but not "
                    "the response a valid seeded credential gets; this may be a public "
                    "view of the route rather than the protected one")
    return _ev(own, r, cand, reproduced=True, determinism="deterministic",
               request=request, observed=observed, baseline=baseline,
               differs_from_baseline=True, handled=True,
               summary=f"{r.method} {r.path} is declared protected by its own operation, "
                       f"refuses an invalid credential ({bad.status}) and serves a request "
                       f"with no credential at all ({anon.status})"
                       + (", byte for byte the response a valid credential gets"
                          if good is not None else ""))


# ------------------------------------------------------------------ rate limit

# Write-out for the burst: status, time, and the headers a throttle sets. %header{} needs
# curl 7.84 or later; the sidecar pins 8.11.1.
_RL_WOUT = ("<<qz|%{http_code}|%{time_total}|%header{retry-after}"
            "|%header{ratelimit-remaining}|%header{x-ratelimit-remaining}>>\n")
_RL_ROW = re.compile(r"<<qz\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^>]*)>>")
# A POST is burst only at a login-like endpoint, with a bogus credential: a failed login
# changes nothing. Never at a path that registers, resets or signs out.
_LOGIN_HINTS = ("login", "signin", "sign-in", "sign_in", "token", "session", "auth")
_NO_BURST = ("register", "signup", "sign-up", "reset", "password", "logout", "signout")
_BOGUS_LOGIN = '{"username": "quarry-no-such-user", "password": "quarry-wrong-password"}'


def _burstable(route) -> bool:
    if route.method in ("GET", "HEAD"):
        return True
    if route.method != "POST":
        return False
    segs = [s for s in route.path.lower().strip("/").split("/")
            if s and not PATH_PARAM.fullmatch(s)]
    last = segs[-1] if segs else ""
    return any(h in last for h in _LOGIN_HINTS) and not any(x in last for x in _NO_BURST)


def _burst(exec_fn, url: str, method: str, n: int) -> list[dict]:
    """n back-to-back requests in ONE curl run (one connection, sequential), so the
    burst is a burst: one sidecar per request spaced them a second apart. Each transfer
    is capped at 2 s, so 20 of them stay inside the sidecar's 60 s budget."""
    argv = ["-s", "-g", "--max-time", "2", "-w", _RL_WOUT]
    if method != "GET":
        argv += ["-X", method]
    if method == "POST":
        argv += ["-H", "Content-Type: application/json", "--data-binary", _BOGUS_LOGIN]
    for _ in range(n):
        argv += ["-o", "/dev/null", url]
    _rc, out = exec_fn(argv)
    rows = []
    for m in _RL_ROW.finditer(out or ""):
        try:
            secs = float(m[2])
        except ValueError:
            secs = 0.0
        rows.append({"status": m[1].strip(), "secs": secs, "retry_after": m[3].strip(),
                     "remaining": (m[4].strip() or m[5].strip())})
    return rows


def probe_missing_rate_limit(running: RunningTarget, candidate: Candidate,
                             routes: list, exec_fn, *, burst: int = 20) -> ProbeEvidence:
    """A lone request (baseline), then a bounded burst of `burst` back-to-back requests to
    the finding's own endpoint. Every request answered exactly like the lone one, with no
    429, 503, Retry-After or RateLimit header, reproduces a missing limit; a throttle, or
    a RateLimit-Remaining that counts down, is a limit that exists. GET, or a failed login
    POST: nothing is created or changed."""
    if probe_class(candidate.cwe) == "CWE-400":
        return ProbeEvidence(
            reproduced=False, determinism="unknown",
            summary="CWE-400 is resource consumption per request (mostly ReDoS); a request "
                    "rate limit neither confirms nor refutes it, so no burst was sent")
    pool, own = _scope(routes, candidate, _burstable)
    pool = _auth_first(pool)
    if not pool:
        return ProbeEvidence(reproduced=False, determinism="unknown",
                             summary="no GET or login-like POST route in the finding's file "
                                     "to exercise")
    r = pool[0]
    method = "GET" if r.method == "HEAD" else r.method
    url = running.base_url.rstrip("/") + _concrete(running, r.path)
    lone = (_burst(exec_fn, url, method, 1) or [{"status": "", "secs": 0.0,
                                                  "retry_after": "", "remaining": ""}])[0]
    request = f"{method} {url}  (x1, then x{burst} back to back in one connection)"
    if lone["status"] not in _REAL or lone["status"] == "429":
        return ProbeEvidence(
            reproduced=False, determinism="unknown", handled=False, request=request,
            observed=f"lone request: HTTP {lone['status'] or 'none'}",
            summary=f"{method} {r.path} answered {lone['status'] or 'nothing'} to a lone "
                    "request; no handler was measured, so a burst would mean nothing")
    rows = _burst(exec_fn, url, method, burst)
    statuses = [x["status"] for x in rows]
    elapsed = sum(x["secs"] for x in rows)
    baseline = (f"lone {method} {r.path} -> HTTP {lone['status']} in "
                f"{lone['secs'] * 1000:.0f} ms"
                + (f", RateLimit-Remaining {lone['remaining']}" if lone["remaining"]
                   else ", no 429, Retry-After or RateLimit header"))
    observed = (f"{len(rows)} of {burst} answered in {elapsed:.2f} s: "
                + ", ".join(f"{s}x{statuses.count(s)}" for s in sorted(set(statuses))))
    first = next((i for i, x in enumerate(rows, 1)
                  if x["status"] in ("429", "503") or x["retry_after"]), 0)
    counts = [int(x["remaining"]) for x in rows if x["remaining"].isdigit()]
    falling = len(counts) >= 2 and counts[-1] < counts[0]
    if first or falling or lone["remaining"]:
        how = (f"request {first} of the burst answered {rows[first - 1]['status']}"
               + (" with Retry-After" if rows[first - 1]["retry_after"] else "")
               if first else
               f"RateLimit-Remaining counted down from {counts[0]} to {counts[-1]}"
               if falling else f"the lone request already carried RateLimit-Remaining "
                               f"{lone['remaining']}")
        return _ev(own, r, candidate, reproduced=False, determinism="deterministic",
                   handled=True, reproduces_when="same", differs_from_baseline=True,
                   request=request, observed=observed, baseline=baseline,
                   summary=f"a rate limit is present on {method} {r.path}: {how}")
    if len(rows) == burst and all(s == lone["status"] for s in statuses):
        return _ev(own, r, candidate, reproduced=True, determinism="statistical",
                   reproduces_when="same", differs_from_baseline=False, handled=True,
                   request=request, observed=observed, baseline=baseline,
                   summary=f"no throttling over {burst} back-to-back {method} requests to "
                           f"{r.path} in {elapsed:.2f} s: every one answered "
                           f"{lone['status']} like the lone request, with no 429, 503, "
                           f"Retry-After or RateLimit header. A limit above {burst} "
                           "requests is not excluded")
    return ProbeEvidence(
        reproduced=False, determinism="unknown", request=request, observed=observed,
        baseline=baseline,
        summary=f"the burst to {r.path} answered {sorted(set(statuses)) or 'nothing'}, "
                f"not uniformly the lone request's {lone['status']} and with no throttle "
                "signal; inconclusive")


# ------------------------------------------------------------------ timing oracle

def probe_auth_timing_oracle(running: RunningTarget, candidate: Candidate,
                             routes: list, exec_fn, *, samples: int = 15) -> ProbeEvidence:
    """Measure whether an auth endpoint's response time separates a present identifier
    from an absent one, which leaks account existence. Statistical: many bounded samples
    per class, compared by median against the measured noise. GET-only, non-destructive.

    The two identifiers are supplied as a query parameter, a first approximation; a
    target whose auth takes a body is where request-shape knowledge sharpens this."""
    own_routes = [r for r in _own(routes, candidate) if _readable(r)]
    own = bool(own_routes)
    auth = own_routes[0] if own else next(
        (r for r in _auth_first(routes) if any(h in r.path.lower() for h in AUTH_HINTS)),
        None)
    if auth is None:
        return ProbeEvidence(reproduced=False, determinism="unknown",
                             summary="no auth-like route in the finding's file to time")
    base = running.base_url.rstrip("/") + _concrete(running, auth.path)
    sep = "&" if "?" in base else "?"
    present = f"{base}{sep}username=admin"
    absent = f"{base}{sep}username=zzqq-no-such-user-000"

    sa = [x for x in (_timing(exec_fn, present) for _ in range(samples)) if x is not None]
    sb = [x for x in (_timing(exec_fn, absent) for _ in range(samples)) if x is not None]
    if len(sa) < 5 or len(sb) < 5:
        return ProbeEvidence(reproduced=False, determinism="unknown",
                             summary="could not collect enough timing samples")
    codes = sorted({c for c, _ in sa} | {c for c, _ in sb})
    if not set(codes) <= _REAL:
        # A 404 or 405 to both identifiers times the router, not the auth check, so
        # equal medians say nothing about the finding. This was a rejection, and the
        # rejection carried forward to every later run.
        return ProbeEvidence(
            reproduced=False, determinism="unknown", handled=False,
            summary=f"{auth.path} answered {codes} to GET; no auth handler was timed",
            request=f"GET {present}  vs  GET {absent}", observed=f"HTTP {codes}")
    ta, tb = [t for _, t in sa], [t for _, t in sb]

    ma, mb = statistics.median(ta), statistics.median(tb)
    # Noise is the within-class spread, not the combined spread: the whole point is to
    # tell the between-class signal apart from each class's own jitter.
    noise = (statistics.pstdev(ta) + statistics.pstdev(tb)) / 2 or 1e-6
    delta = abs(ma - mb)
    # Separated when the medians differ by more than 10ms AND beyond twice the noise.
    if delta > 0.010 and delta > 2 * noise:
        return ProbeEvidence(
            reproduced=True, determinism="statistical",
            summary=f"response time separates by {delta * 1000:.1f}ms between a present and "
                    f"absent identifier on {auth.path} "
                    f"(median {ma * 1000:.1f} vs {mb * 1000:.1f}ms, n={len(ta)}/{len(tb)})",
            request=f"GET {present}  vs  GET {absent}",
            observed=f"Δmedian={delta * 1000:.1f}ms (noise≈{noise * 1000:.1f}ms)")
    # The absent identifier is the control: the present one behaved like it.
    return _ev(own, auth, candidate,
               reproduced=False, determinism="statistical", handled=True,
               summary=f"no timing separation on {auth.path}: Δmedian {delta * 1000:.1f}ms "
                       f"within noise (≈{noise * 1000:.1f}ms) over {len(ta)}/{len(tb)} "
                       "samples",
               request=f"GET {present}  vs  GET {absent}",
               observed=f"median {ma * 1000:.1f}ms, HTTP {sorted({c for c, _ in sa})}",
               baseline=f"absent identifier: median {mb * 1000:.1f}ms, "
                        f"HTTP {sorted({c for c, _ in sb})}",
               differs_from_baseline=False)


# ------------------------------------------------------------------ injection

def probe_injection_observable(running: RunningTarget, candidate: Candidate,
                               routes: list, exec_fn) -> ProbeEvidence:
    """Confirm injection through a benign, observable signal that never modifies or
    destroys data, each against a benign control on the same parameter: an unencoded
    reflected marker (XSS), a SQL error elicited by a single quote (SQLi), or a shell's
    arithmetic or delay (command injection). The check is chosen by the finding's CWE, so
    the probe sends only what that class needs."""
    pool, own = _scope(routes, candidate, _readable)
    if not pool:
        return ProbeEvidence(reproduced=False, determinism="unknown",
                             summary="no GET route in the finding's file to inject into")
    cwe = probe_class(candidate.cwe) or ""
    if cwe == "CWE-79":
        return _xss(running, candidate, pool, own, exec_fn)
    if cwe == "CWE-89":
        return _sqli(running, candidate, pool, own, exec_fn)
    if cwe == "CWE-77":
        return _cmdi(running, candidate, pool, own, exec_fn)
    return ProbeEvidence(reproduced=False, determinism="unknown",
                         summary=f"no in-band injection check for {cwe or 'this finding'}")


def _xss(running, cand, pool, own, exec_fn) -> ProbeEvidence:
    """Control: an alphanumeric token, which shows whether this parameter reaches the
    response at all. Attack: `"'><marker>` on the same parameter. Raw `<marker>` in an
    HTML response confirms. A rejection needs every declared parameter of the finding's
    route to reflect the control and to encode both the brackets and the quotes, because
    a value whose brackets are encoded but whose quotes are not can still break out of an
    attribute."""
    nonhtml, escaped, unreflected, quotes_raw = [], [], [], []
    for r in pool[:3] if not own else pool[:2]:
        slots = _slots(r)[:6] if own else _slots(r)[:2]
        for s in slots:
            tok, mark = _marker(), _marker()
            cu, au = _url(running, r, s, tok), _url(running, r, s, f"\"'><{mark}>")
            c, a = _fetch(exec_fn, cu), _fetch(exec_fn, au)
            if not (c.reached or a.reached):
                unreflected.append(s)
                continue
            reflected = tok in c.body
            control = (f"control GET {cu} -> {c.describe()}, benign token "
                       f"{'reflected as text' if reflected else 'not reflected'}")
            if f"<{mark}>" in a.body:
                if a.html:
                    return _ev(own, r, cand, reproduced=True, determinism="deterministic",
                               request=f"GET {au}",
                               observed=f"<{mark}> verbatim in the response, {a.describe()}",
                               baseline=control, differs_from_baseline=True, handled=True,
                               summary=f"markup sent in {s.where} parameter `{s.name}` of "
                                       f"{r.method} {r.path} came back unencoded in an HTML "
                                       "response; the benign token on the same parameter "
                                       "carried no markup")
                nonhtml.append((r, s, a))
                continue
            if not (reflected and mark in a.body):
                unreflected.append(s)
                continue
            at = a.body.find(mark)
            if '"' in a.body[max(0, at - 16):at] and "'" in a.body[max(0, at - 16):at]:
                quotes_raw.append((r, s))
                continue
            escaped.append((r, s, cu, au, c, a, control))
    if nonhtml:
        r, s, a = nonhtml[0]
        return ProbeEvidence(
            reproduced=False, determinism="unknown",
            summary=f"markup on `{s.name}` of {r.method} {r.path} came back raw, but in a "
                    f"{a.ctype or 'typeless'} response that a browser does not render as "
                    "HTML; whether a client renders it is a review question")
    if quotes_raw:
        r, s = quotes_raw[0]
        return ProbeEvidence(
            reproduced=False, determinism="unknown",
            summary=f"`{s.name}` of {r.method} {r.path} encoded the angle brackets but "
                    "returned the quotes raw; an attribute-context breakout is not excluded")
    if escaped and not unreflected and all(s.declared for _, s, *_ in escaped):
        r, s, cu, au, c, a, control = escaped[0]
        names = ", ".join(f"`{x[1].name}`" for x in escaped)
        return _ev(own, r, cand, reproduced=False, determinism="deterministic",
                   request=f"GET {au}", baseline=control, differs_from_baseline=False,
                   handled=True,
                   observed=f"marker reflected encoded, no raw markup, {a.describe()}",
                   summary=f"every declared parameter of {r.method} {r.path} ({names}) is "
                           "reflected and encodes markup and quotes; this reflection point "
                           "escapes its output")
    if escaped:
        return ProbeEvidence(
            reproduced=False, determinism="unknown",
            summary="markup came back encoded where it was reflected, but not every "
                    "parameter of the route was reflected (or the parameter was guessed), "
                    "so the finding's own sink is not excluded")
    return ProbeEvidence(
        reproduced=False, determinism="unknown",
        summary="no parameter tried carried the benign token back into the response; "
                "this probe cannot see the sink (stored or DOM XSS is not tested)")


def _sqli(running, cand, pool, own, exec_fn) -> ProbeEvidence:
    """A single quote against the plain value `1` on the same parameter. Never rejects: no
    error on a quote is not proof of parameterisation, since blind SQLi exists."""
    exercised = False
    for r in pool[:3]:
        for s in _slots(r)[:3]:
            pu, qu = _url(running, r, s, "1"), _url(running, r, s, "1'")
            p, q = _fetch(exec_fn, pu), _fetch(exec_fn, qu)
            exercised = exercised or bool(p.body or q.body)
            if _has_sql_error(q.body) and not _has_sql_error(p.body):
                # The plain value is the control. An empty control response is no
                # control: the route may simply have failed both ways.
                return _ev(own, r, cand, reproduced=True, determinism="deterministic",
                           summary=f"a single quote elicited a SQL error on {r.path} that "
                                   "a plain value did not; input reaches an "
                                   "unparameterised query",
                           request=f"GET {qu}", observed="SQL error signature in the response",
                           baseline=(f"GET {pu} -> {len(p.body)} bytes, no SQL error "
                                     "signature") if p.body else "",
                           differs_from_baseline=True if p.body else None)
    if not exercised:
        return ProbeEvidence(reproduced=False, determinism="unknown",
                             summary="the candidate route(s) returned nothing to inject into")
    return ProbeEvidence(
        reproduced=False, determinism="unknown",
        summary="no SQL error on a single quote; blind SQL injection was not tested, so "
                "this does not reject")


def _cmdi(running, cand, pool, own, exec_fn) -> ProbeEvidence:
    """Output: `echo $((a*b))` chained three ways; the product is not in the input, so a
    reflection of the payload cannot fake it. Timing: `sleep 2` the same three ways,
    confirmed only when a replay delays again. Both against a benign token. Nothing is
    written and nothing leaves the container: echo, shell arithmetic and sleep only."""
    a_, b_ = (1000 + int.from_bytes(os.urandom(2), "big") % 9000 for _ in range(2))
    prod = str(a_ * b_)
    out_v = (f";echo $(({a_}*{b_}))", f"|echo $(({a_}*{b_}))", f"$(echo $(({a_}*{b_})))")
    sleep_v = (";sleep 2", "|sleep 2", "$(sleep 2)")
    refusals = []
    for r in pool[:2]:
        for s in _slots(r)[:2]:
            cu = _url(running, r, s, _marker())
            c = _fetch(exec_fn, cu)
            if not c.reached or prod in c.body:
                continue
            control = f"control GET {cu} -> {c.describe()} in {c.secs:.2f} s, no {prod}"
            sent = []
            for v in out_v:
                u = _url(running, r, s, v)
                x = _fetch(exec_fn, u)
                sent.append((u, x))
                if prod in x.body:
                    return _ev(own, r, cand, reproduced=True, determinism="deterministic",
                               request=f"GET {u}", baseline=control,
                               differs_from_baseline=True, handled=True,
                               observed=f"{prod} in the response, {x.describe()}",
                               summary=f"`{v}` on {s.where} parameter `{s.name}` of "
                                       f"{r.method} {r.path} returned {prod}, which is not "
                                       "in the input: a shell evaluated it")
            for v in sleep_v:
                u = _url(running, r, s, v)
                x = _fetch(exec_fn, u, max_time=8)
                sent.append((u, x))
                if x.secs - c.secs >= 1.8:
                    x2, c2 = _fetch(exec_fn, u, max_time=8), _fetch(exec_fn, cu)
                    if x2.secs - c2.secs >= 1.8:
                        return _ev(own, r, cand, reproduced=True, determinism="statistical",
                                   request=f"GET {u}", differs_from_baseline=True,
                                   handled=True,
                                   baseline=f"control GET {cu}: {c.secs:.2f} s, then "
                                            f"{c2.secs:.2f} s on replay",
                                   observed=f"{x.secs:.2f} s, then {x2.secs:.2f} s on replay",
                                   summary=f"`{v}` on `{s.name}` of {r.method} {r.path} "
                                           f"delayed the response by "
                                           f"{x.secs - c.secs:.1f} s and "
                                           f"{x2.secs - c2.secs:.1f} s on a replay, against "
                                           "the benign token")
            if (s.declared and sent and all(x.status in _REFUSE for _, x in sent)
                    and c.status not in _REFUSE):
                refusals.append((r, s, cu, c, sent, control))
    if refusals:
        r, s, cu, c, sent, control = refusals[0]
        return _ev(own, r, cand, reproduced=False, determinism="deterministic",
                   request="; ".join(f"GET {u}" for u, _ in sent[:3]), baseline=control,
                   differs_from_baseline=False, handled=True,
                   observed=", ".join(sorted({x.status for _, x in sent})),
                   summary=f"{r.method} {r.path} refused all {len(sent)} shell-metacharacter "
                           f"payloads on `{s.name}` and accepted the benign token "
                           f"({c.status}): the handler validates this input before it can "
                           "reach a command")
    return ProbeEvidence(
        reproduced=False, determinism="unknown",
        summary="no command output, no replayed delay and no explicit refusal; an "
                "asynchronous or conditional command is not excluded, so this does not "
                "reject")


# ------------------------------------------------------------------ traversal / SSRF

_TRAVERSAL = ("../" * 8 + "etc/passwd", "....//" * 6 + "etc/passwd", "/etc/passwd")
_URL_HINTS = ("url", "uri", "link", "href", "src", "target", "callback", "webhook", "feed",
              "endpoint", "host", "redirect", "next", "image", "proxy", "fetch")
_FETCH_ERRORS = ("getaddrinfo", "could not resolve", "name or service not known",
                 "no such host", "nodename nor servname", "temporary failure in name",
                 "failed to resolve", "name resolution", "connection refused",
                 "failed to connect", "econnrefused", "enotfound", "max retries exceeded",
                 "newconnectionerror")
_SENTINEL = "quarry-ssrf-sentinel.invalid"


def probe_path_traversal_ssrf(running: RunningTarget, candidate: Candidate,
                              routes: list, exec_fn) -> ProbeEvidence:
    """CWE-22: /etc/passwd inside the target's own container (host files are not mounted),
    observed read-only, against a benign missing file. CWE-918: the target's own root page
    fetched through the parameter (an internal-only canary), and the `.invalid` sentinel
    that can never resolve, against a benign token. Neither reaches an external host."""
    pool, own = _scope(routes, candidate, _readable)
    if not pool:
        return ProbeEvidence(reproduced=False, determinism="unknown",
                             summary="no GET route in the finding's file to test")
    cwe = probe_class(candidate.cwe) or ""
    if cwe == "CWE-22":
        return _traversal(running, candidate, pool, own, exec_fn)
    if cwe == "CWE-918":
        return _ssrf(running, candidate, pool, own, exec_fn)
    return ProbeEvidence(reproduced=False, determinism="unknown",
                         summary=f"no traversal or SSRF check for {cwe or 'this finding'}")


def _explicit_refusal(sent, c: _Resp) -> bool:
    """Every attack was refused as input (400/403/422) while the control was not, and the
    control did reach something (not 405, not silence)."""
    return (bool(sent) and all(x.status in _REFUSE for _, x in sent)
            and bool(c.status) and c.status not in _REFUSE + ("405", "000"))


def _traversal(running, cand, pool, own, exec_fn) -> ProbeEvidence:
    refusals = []
    for r in pool[:2]:
        for s in _slots(r)[:2]:
            cu = _url(running, r, s, _marker() + ".txt")
            c = _fetch(exec_fn, cu)
            control = f"control GET {cu} -> {c.describe()}, no passwd line"
            sent = []
            for p in _TRAVERSAL:
                variants = [(_url(running, r, s, p), False)]
                if s.where == "path" and p.startswith("."):
                    variants.append((_url(running, r, s, p, raw=True), True))
                for u, raw in variants:
                    x = _fetch(exec_fn, u, raw_path=raw)
                    sent.append((u, x))
                    if _PASSWD.search(x.body) and not _PASSWD.search(c.body):
                        return _ev(own, r, cand, reproduced=True, determinism="deterministic",
                                   request=f"GET {u}" + ("  (--path-as-is)" if raw else ""),
                                   observed="root:...:0:0: in the response", baseline=control,
                                   differs_from_baseline=True, handled=True,
                                   summary=f"a traversal sequence on `{s.name}` of {r.method} "
                                           f"{r.path} returned a passwd-shaped file; the path "
                                           "escapes its intended directory")
            if s.declared and _explicit_refusal(sent, c):
                refusals.append((r, s, sent, control))
    if refusals:
        r, s, sent, control = refusals[0]
        return _ev(own, r, cand, reproduced=False, determinism="deterministic",
                   request="; ".join(f"GET {u}" for u, _ in sent[:3]), baseline=control,
                   differs_from_baseline=False, handled=True,
                   observed=", ".join(sorted({x.status for _, x in sent})),
                   summary=f"{r.method} {r.path} refused every traversal payload on "
                           f"`{s.name}` ({len(sent)} requests) and not the benign file "
                           "name: the handler rejects the path before it opens it")
    return ProbeEvidence(
        reproduced=False, determinism="unknown",
        summary="no passwd line and no explicit refusal; a router 404 and a handler's "
                "'no such file' look alike, so this does not reject")


def _canary_window(page: str, control: str) -> str:
    """A 40-character stretch of the target's root page that the control response does not
    contain. Taken from a page fetched directly, so finding it in the probe's response
    means the server fetched that page itself. Empty when the page is too short or shares
    every stretch with the control (a common layout)."""
    flat = " ".join(page.split())
    for i in range(0, max(0, len(flat) - 40) + 1, 40):
        w = flat[i:i + 40]
        if len(w) == 40 and w not in " ".join(control.split()):
            return w
    return ""


def _ssrf(running, cand, pool, own, exec_fn) -> ProbeEvidence:
    root = _fetch(exec_fn, running.base_url.rstrip("/") + "/")
    internal = running.base_url.rstrip("/") + "/"
    sentinel = f"http://{_SENTINEL}/"
    refusals = []
    for r in pool[:2]:
        slots = sorted(_slots(r), key=lambda s: 0 if any(h in s.name.lower()
                                                         for h in _URL_HINTS) else 1)
        for s in slots[:2]:
            cu = _url(running, r, s, _marker())
            c = _fetch(exec_fn, cu)
            iu, su = _url(running, r, s, internal), _url(running, r, s, sentinel)
            i, x = _fetch(exec_fn, iu, max_time=8), _fetch(exec_fn, su, max_time=8)
            control = f"control GET {cu} -> {c.describe()}"
            canary = _canary_window(root.body, c.body) if root.ok else ""
            if canary and canary in " ".join(i.body.split()):
                return _ev(own, r, cand, reproduced=True, determinism="deterministic",
                           request=f"GET {iu}", baseline=control, differs_from_baseline=True,
                           handled=True,
                           observed=f"a 40-character stretch of the target's own root page "
                                    f"in the response, {i.describe()}",
                           summary=f"`{s.name}` of {r.method} {r.path} made the server fetch "
                                   f"{internal} (an address only the internal network "
                                   "reaches) and return its content")
            # A handler that refuses the internal address but fetches an external-looking
            # one is the standard mitigation for a URL-fetching feature, so the refusal is
            # checked before the sentinel's fetch error can count as a reproduction.
            if (i.status in _REFUSE and x.reached and x.status not in _REFUSE
                    and c.status not in ("", "000", "405")):
                if s.declared:
                    refusals.append((r, s, iu, i, x, control))
                continue
            low, clow = x.body.lower(), c.body.lower()
            if _SENTINEL in low and any(e in low for e in _FETCH_ERRORS) \
                    and not any(e in clow for e in _FETCH_ERRORS):
                return _ev(own, r, cand, reproduced=True, determinism="deterministic",
                           request=f"GET {su}", baseline=control, differs_from_baseline=True,
                           handled=True,
                           observed="server-side fetch error naming the sentinel host",
                           summary=f"`{s.name}` of {r.method} {r.path} made the server "
                                   "attempt an outbound request to an attacker-supplied "
                                   "host, and did not refuse its own internal address")
    if refusals:
        r, s, iu, i, x, control = refusals[0]
        return _ev(own, r, cand, reproduced=False, determinism="deterministic",
                   request=f"GET {iu}", baseline=control, differs_from_baseline=False,
                   handled=True,
                   observed=f"internal address: {i.describe()}; .invalid sentinel: "
                            f"{x.describe()}",
                   summary=f"`{s.name}` of {r.method} {r.path} refused the internal address "
                           f"({i.status}) but handled an external-looking one "
                           f"({x.status}): the handler blocks internal targets")
    return ProbeEvidence(
        reproduced=False, determinism="unknown",
        summary="no in-band SSRF signal and no explicit refusal of an internal address; a "
                "blind fetch would need a callback listener, which this probe does not "
                "set up")
