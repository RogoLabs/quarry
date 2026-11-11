"""Concrete probe bodies, each with its own control.

Every probe is non-destructive by construction: it observes, it does not mutate or
delete data that existed before it ran, and it does not try to take the target down.
One exception is bounded and stated in its verdict: the cross-user probe may create two
records of its own through the target's API, as a seeded test account, inside the
contained throwaway instance, and its delete and modify checks only ever address those
two records, by ids the probe generated.

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
  * authz, cross-user: seeded account B creates two canary records; the anonymous client
    (control) and account A (probe) address them; B's own request is the baseline.
    Confirms when A gets B's result and the control was refused; rejects when A is
    refused like the control while B's own request worked.
  * rate limit: a lone request (baseline), then a bounded burst in one curl run. The
    finding is a missing defence, so it reproduces on sameness (reproduces_when="same").
  * timing: a present identifier against two absent ones shaped like it, interleaved;
    the two absent ones are an A/A control. Confirms on a separation of at least 10 ms
    that is three times the A/A difference and twice the spread; rejects only with a
    present identifier the seed shows exists, every difference under 10 ms and a spread
    small enough to have seen 10 ms (see _TIMING_FLOOR).
  * XSS: a benign alphanumeric token (control) and a markup marker on the same parameter.
    Raw markup in a text/html response confirms; every declared parameter reflecting the
    control while encoding the markup and its quotes rejects.
  * SQL injection: a single quote against the plain value `1`; a SQL error the plain
    value did not raise confirms. Rejects only when every declared parameter of the
    route refuses every metacharacter input (400/403/422) and handles the plain value.
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
import uuid as _uuid
from dataclasses import dataclass
from urllib.parse import quote

from ..cwe import probe_class
from .routes import PATH_PARAM, _norm_path
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


# curl drops dot segments from a URL's path unless told not to, so the traversal
# probe's `/files/../../etc/passwd` went out as `GET /etc/passwd`. Every probe request
# goes out as written, which is also what its recorded `request` says it sent.
def _status(exec_fn, url: str) -> str:
    rc, code = exec_fn(["-s", "--path-as-is", "-o", "/dev/null", "-w", "%{http_code}",
                        "--max-time", "5", url])
    return code.strip() if rc == 0 else ""


def _auth_first(routes: list) -> list:
    """Routes with an auth-like path first, then the rest. Stable within each group."""
    return sorted(routes, key=lambda r: 0 if any(h in r.path.lower() for h in AUTH_HINTS)
                  else 1)


def _body(exec_fn, url: str) -> str:
    rc, out = exec_fn(["-s", "--path-as-is", "--max-time", "5", url])
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
    as its own URL globbing; `--path-as-is` stops it collapsing `../` before the request
    leaves, which silently turned every traversal payload into a plain path. It is on for
    every request, not only traversal ones (`raw_path` now only documents intent): a
    probe's recorded `request` must be what was sent, and a filled path parameter can
    hold a dot segment too."""
    argv = ["-s", "-g", "--path-as-is", "--max-time", str(max_time)]
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
        return ProbeEvidence(exercised=False, 
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


# ------------------------------------------------------------------ authz, cross-user

def _template(text: str, subs: dict[str, str]) -> str:
    for k, v in subs.items():
        text = text.replace("{" + k + "}", v)
    return text


def _cross_user_target(spec, routes: list, cand: Candidate):
    """(resource, check, route, own) for the first declared resource one of the finding's
    routes addresses: its item GET (read), item DELETE (delete), or the request that
    modifies it. The finding's own routes are matched first."""
    def checks(res) -> dict:
        item, coll = _norm_path(res.item), _norm_path(res.collection)
        out = {("GET", item): "read", ("DELETE", item): "delete"}
        if res.modify == "post-collection":
            out[("POST", coll)] = "modify"
        elif res.modify in ("put-item", "patch-item"):
            out[(res.modify.split("-")[0].upper(), item)] = "modify"
        return out
    for pool, own in ((_own(routes, cand), True), (routes, False)):
        for r in pool:
            for res in spec.resources:
                if (check := checks(res).get(r.key)):
                    return res, check, r, own
    return None


class _CrossUser:
    """One run of the cross-user check: two canaries made by the owner, the requests
    sent, and their cleanup. Every request line in `log` names the account, never its
    key, so it is safe to store and replay with fresh keys."""

    def __init__(self, running, spec, res, exec_fn):
        self.running, self.spec, self.res, self.exec_fn = running, spec, res, exec_fn
        creds = running.credentials or {}
        self.keys = {res.owner: creds.get(res.owner, ""), res.other: creds.get(res.other, "")}
        self.owner = spec.accounts.get(res.owner, res.owner)
        self.other = spec.accounts.get(res.other, res.other)
        self.ids = (str(_uuid.uuid4()), str(_uuid.uuid4()))   # baseline canary, probe canary
        self.log: list[str] = []
        self.made: list[str] = []

    def as_(self, who: str) -> list[str]:
        key = self.keys.get(who, "")
        return [_cred_header(self.spec.header, key)] if key else []

    def call(self, who: str, method: str, path: str, data: str | None = None) -> _Resp:
        label = {self.res.owner: self.owner, self.res.other: self.other}.get(who, who)
        if who in self.keys:
            label = f"{label} ({_cred_label(self.spec.header, label + ' key')})"
        resp = _fetch(self.exec_fn, self.running.base_url.rstrip("/") + path,
                      method=method, headers=self.as_(who), data=data)
        self.log.append(f"{method} {path} as {label} -> {resp.status or 'no response'}")
        return resp

    def item(self, i: str) -> str:
        return _template(self.res.item, {"id": i})

    def body(self, tmpl: str, i: str, marker: str) -> str:
        return _template(tmpl, {**(self.running.param_values or {}),
                                "id": i, "marker": marker})

    def create(self) -> bool:
        for i in self.ids:
            if self.call(self.res.owner, "POST", self.res.collection,
                         self.body(self.res.body, i, _marker())).ok:
                self.made.append(i)
        return len(self.made) == 2

    def cleanup(self, gone: tuple[str, ...] = ()) -> str:
        """Delete, as the owner, every canary this run made that is not already gone.
        Returns a note for the verdict naming any that could not be removed."""
        left = []
        for i in self.made:
            if i in gone:
                continue
            d = self.call(self.res.owner, "DELETE", self.item(i))
            if not (d.ok or d.status == "404"):
                left.append(i)
        return (f"; canary {', '.join(left)} could not be deleted and remains in the "
                "throwaway instance" if left else "")

    def setup_note(self) -> str:
        return (f"created {self.res.name} canaries {self.ids[0]} (baseline) and "
                f"{self.ids[1]} (probe) as {self.owner} through POST "
                f"{self.res.collection}, in the contained throwaway instance")


def probe_cross_user(running: RunningTarget, candidate: Candidate,
                     routes: list, exec_fn) -> ProbeEvidence | None:
    """Account A addressing account B's record, against B's own request (baseline) and the
    anonymous client (control), on the per-user resources a seed recipe declared. None
    when no declared resource is served by a route in the finding's file, so the caller
    falls back to the anonymous probe."""
    spec = getattr(running, "cross_user", None)
    if spec is None or not getattr(spec, "resources", ()):
        return None
    hit = _cross_user_target(spec, routes, candidate)
    if hit is None:
        return None
    res, check, route, own = hit
    xu = _CrossUser(running, spec, res, exec_fn)
    missing = [k for k, v in xu.keys.items() if not v]
    if missing:
        return ProbeEvidence(exercised=False, 
            reproduced=False, determinism="unknown",
            summary=f"cross-user {check} check on {res.name} needs the seeded "
                    f"credentials {missing}, which the seed did not capture")
    if not xu.create():
        note = xu.cleanup()
        return ProbeEvidence(exercised=False, 
            reproduced=False, determinism="unknown", request="; ".join(xu.log),
            summary=f"cross-user {check} check on {res.name}: {xu.owner} could not create "
                    f"both canary records, so there is nothing to compare{note}")
    run = {"read": _xu_read, "delete": _xu_delete, "modify": _xu_modify}[check]
    return run(xu, route, candidate, own)


def _xu_evidence(xu: _CrossUser, route, cand, own, *, note: str = "", **kw) -> ProbeEvidence:
    kw["summary"] = f"{kw['summary']} ({xu.setup_note()}{note})"
    kw.setdefault("request", "; ".join(xu.log))
    kw.setdefault("determinism", "deterministic")
    return _ev(own, route, cand, **kw)


def _xu_read(xu: _CrossUser, route, cand, own) -> ProbeEvidence:
    _, a = xu.ids
    g_o = xu.call(xu.res.owner, "GET", xu.item(a))
    g_x = xu.call(xu.res.other, "GET", xu.item(a))
    g_n = xu.call("anonymous", "GET", xu.item(a))
    note = xu.cleanup()
    baseline = (f"{xu.owner} reading its own record: {g_o.describe()}; anonymous: "
                f"{g_n.describe()}")
    observed = f"{xu.other} reading {xu.owner}'s record: {g_x.describe()}"
    if not g_o.ok:
        return _xu_evidence(xu, route, cand, own, note=note, reproduced=False,
                            determinism="unknown", observed=observed, baseline=baseline,
                            summary=f"{xu.owner} cannot read its own {xu.res.name} "
                                    f"({g_o.status or 'no response'}), so the read check "
                                    "has no baseline")
    if g_n.ok:
        return _xu_evidence(xu, route, cand, own, note=note, reproduced=False,
                            determinism="unknown", observed=observed, baseline=baseline,
                            summary=f"{xu.res.name} records are served to anonymous "
                                    "clients, so reading one as another account crosses "
                                    "no boundary; whether they should be private is a "
                                    "design question")
    if not g_n.refused:
        return _xu_evidence(xu, route, cand, own, note=note, reproduced=False,
                            determinism="unknown", observed=observed, baseline=baseline,
                            summary=f"the anonymous control answered {g_n.status or 'nothing'}"
                                    ", neither served nor refused; inconclusive")
    if g_x.ok and _sha(g_x.body) == _sha(g_o.body):
        return _xu_evidence(xu, route, cand, own, note=note, reproduced=True,
                            observed=observed, baseline=baseline,
                            differs_from_baseline=True, handled=True,
                            summary=f"{xu.other} read {xu.owner}'s {xu.res.name} and got "
                                    "the owner's exact response, while the anonymous "
                                    "control was refused")
    if g_x.refused or g_x.status == "404":
        return _xu_evidence(xu, route, cand, own, note=note, reproduced=False,
                            observed=observed, baseline=baseline,
                            differs_from_baseline=False, handled=True,
                            summary=f"{xu.other} was refused {xu.owner}'s {xu.res.name} "
                                    f"({g_x.status}) like the anonymous control, while "
                                    "the owner read it")
    return _xu_evidence(xu, route, cand, own, note=note, reproduced=False,
                        determinism="unknown", observed=observed, baseline=baseline,
                        summary=f"{xu.other}'s read answered {g_x.status or 'nothing'}, "
                                "neither the owner's response nor a refusal; inconclusive")


def _xu_delete(xu: _CrossUser, route, cand, own) -> ProbeEvidence:
    o, a = xu.ids
    d_n = xu.call("anonymous", "DELETE", xu.item(o))
    d_o = xu.call(xu.res.owner, "DELETE", xu.item(o))       # baseline, and removes o
    d_x = xu.call(xu.res.other, "DELETE", xu.item(a))
    d_after = xu.call(xu.res.owner, "DELETE", xu.item(a))   # effect check, and removes a
    gone = tuple(i for i, d in ((o, d_o), (a, d_after)) if d.ok or d.status == "404")
    note = xu.cleanup(gone=gone)
    baseline = (f"{xu.owner} deleting its own baseline canary: {d_o.status or 'no response'}"
                f"; anonymous deleting it first: {d_n.status or 'no response'}")
    observed = (f"{xu.other} deleting {xu.owner}'s probe canary: "
                f"{d_x.status or 'no response'}; {xu.owner} deleting it afterwards: "
                f"{d_after.status or 'no response'} (404 means it was already gone)")
    common = dict(observed=observed, baseline=baseline, note=note)
    if d_n.ok:
        return _xu_evidence(xu, route, cand, own, reproduced=True, **common,
                            summary=f"an anonymous DELETE removed {xu.owner}'s "
                                    f"{xu.res.name}: the route deletes without "
                                    "authentication. Held for review because the anonymous "
                                    "request is this probe's negative control")
    if not d_o.ok:
        return _xu_evidence(xu, route, cand, own, reproduced=False, determinism="unknown",
                            handled=d_o.reached or None, **common,
                            summary=f"{xu.owner} could not delete its own {xu.res.name} "
                                    f"({d_o.status or 'no response'}), so a refusal to "
                                    f"{xu.other} would mean nothing")
    # d_o worked, so the baseline canary existed through the anonymous attempt: a 404
    # to the anonymous client hid an existing record, which is a refusal.
    if not (d_n.refused or d_n.status == "404"):
        return _xu_evidence(xu, route, cand, own, reproduced=False, determinism="unknown",
                            **common,
                            summary=f"the anonymous control answered {d_n.status}, neither "
                                    "a deletion nor a refusal; inconclusive")
    if d_x.ok and d_after.status == "404":
        return _xu_evidence(xu, route, cand, own, reproduced=True,
                            differs_from_baseline=True, handled=True, **common,
                            summary=f"{xu.other} deleted {xu.owner}'s {xu.res.name} "
                                    f"({d_x.status}; the owner then got 404), while the "
                                    f"anonymous control was refused ({d_n.status})")
    if (d_x.refused or d_x.status == "404") and d_after.ok:
        return _xu_evidence(xu, route, cand, own, reproduced=False,
                            differs_from_baseline=False, handled=True, **common,
                            summary=f"{xu.other} was refused deletion of {xu.owner}'s "
                                    f"{xu.res.name} ({d_x.status}) like the anonymous "
                                    f"control ({d_n.status}); the record survived and its "
                                    "owner deleted it")
    return _xu_evidence(xu, route, cand, own, reproduced=False, determinism="unknown",
                        **common,
                        summary=f"{xu.other}'s DELETE answered {d_x.status or 'nothing'} "
                                f"and the record then answered {d_after.status or 'nothing'}"
                                " to its owner; status and effect disagree, inconclusive")


def _xu_modify(xu: _CrossUser, route, cand, own) -> ProbeEvidence:
    o, a = xu.ids
    mk_n, mk_o, mk_x = _marker(), _marker(), _marker()
    tmpl = xu.res.modify_body or xu.res.body
    if xu.res.modify == "post-collection":
        def send(who, i, mk):
            return xu.call(who, "POST", xu.res.collection, xu.body(tmpl, i, mk))
    else:
        verb = xu.res.modify.split("-")[0].upper()

        def send(who, i, mk):
            return xu.call(who, verb, xu.item(i), xu.body(tmpl, i, mk))
    m_n = send("anonymous", o, mk_n)
    m_o = send(xu.res.owner, o, mk_o)
    m_x = send(xu.res.other, a, mk_x)
    g_o = xu.call(xu.res.owner, "GET", xu.item(o))
    g_a = xu.call(xu.res.owner, "GET", xu.item(a))
    note = xu.cleanup()
    baseline = (f"{xu.owner} changing its own baseline canary: {m_o.status or 'no response'}"
                f", change {'visible' if mk_o in g_o.body else 'not visible'} on read-back; "
                f"anonymous changing it: {m_n.status or 'no response'}")
    observed = (f"{xu.other} changing {xu.owner}'s probe canary: "
                f"{m_x.status or 'no response'}; {xu.owner} reading it back: "
                f"{g_a.describe()}, {xu.other}'s change "
                f"{'present' if mk_x in g_a.body else 'absent'}")
    common = dict(observed=observed, baseline=baseline, note=note)
    if not (m_o.ok and g_o.ok and mk_o in g_o.body):
        return _xu_evidence(xu, route, cand, own, reproduced=False, determinism="unknown",
                            **common,
                            summary=f"{xu.owner}'s own change to its {xu.res.name} did not "
                                    "show on read-back, so the modify request has no "
                                    "baseline")
    if m_n.ok:
        return _xu_evidence(xu, route, cand, own, reproduced=True, **common,
                            summary=f"an anonymous request to change {xu.owner}'s "
                                    f"{xu.res.name} answered {m_n.status}. Held for review "
                                    "because the anonymous request is this probe's "
                                    "negative control")
    if not (m_n.refused or m_n.status == "404") or not g_a.ok:
        return _xu_evidence(xu, route, cand, own, reproduced=False, determinism="unknown",
                            **common,
                            summary="the anonymous control or the owner's read-back of the "
                                    "probe canary was inconclusive")
    if mk_x in g_a.body:
        return _xu_evidence(xu, route, cand, own, reproduced=True,
                            differs_from_baseline=True, handled=True, **common,
                            summary=f"{xu.other}'s change to {xu.owner}'s {xu.res.name} "
                                    f"was stored (answered {m_x.status}), while the "
                                    f"anonymous control was refused ({m_n.status})")
    if m_x.refused or m_x.status == "404":
        return _xu_evidence(xu, route, cand, own, reproduced=False,
                            differs_from_baseline=False, handled=True, **common,
                            summary=f"{xu.other} was refused a change to {xu.owner}'s "
                                    f"{xu.res.name} ({m_x.status}) like the anonymous "
                                    "control, and the record was unchanged on read-back")
    return _xu_evidence(xu, route, cand, own, reproduced=False, determinism="unknown",
                        **common,
                        summary=f"{xu.other}'s change answered {m_x.status or 'nothing'} but "
                                "did not show on read-back; inconclusive")


def probe_authz(running: RunningTarget, candidate: Candidate,
                routes: list, exec_fn) -> ProbeEvidence:
    """The broken-authz lens: the cross-user check when a seed recipe declared a per-user
    resource that a route in the finding's file serves, otherwise the anonymous one."""
    return (probe_cross_user(running, candidate, routes, exec_fn)
            or probe_broken_authz(running, candidate, routes, exec_fn))


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
    argv = ["-s", "-g", "--path-as-is", "--max-time", "2", "-w", _RL_WOUT]
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
        return ProbeEvidence(exercised=False, 
            reproduced=False, determinism="unknown",
            summary="CWE-400 is resource consumption per request (mostly ReDoS); a request "
                    "rate limit neither confirms nor refutes it, so no burst was sent")
    pool, own = _scope(routes, candidate, _burstable)
    pool = _auth_first(pool)
    if not pool:
        return ProbeEvidence(exercised=False, reproduced=False, determinism="unknown",
                             summary="no GET or login-like POST route in the finding's file "
                                     "to exercise")
    r = pool[0]
    method = "GET" if r.method == "HEAD" else r.method
    url = running.base_url.rstrip("/") + _concrete(running, r.path)
    lone = (_burst(exec_fn, url, method, 1) or [{"status": "", "secs": 0.0,
                                                  "retry_after": "", "remaining": ""}])[0]
    request = f"{method} {url}  (x1, then x{burst} back to back in one connection)"
    if lone["status"] not in _REAL or lone["status"] == "429":
        return ProbeEvidence(exercised=False, 
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

# How the timing probe measures, and the thresholds that decide.
#
# Three classes of request on the same parameter, interleaved round by round with the
# order rotated, so drift (a warming cache, a GC pause, another container's load) lands
# on every class alike: a present identifier, and two absent ones shaped like it (same
# length and character classes, random letters and digits). The two absent identifiers
# are the control, an A/A comparison: they should behave the same, so the difference
# between their medians is what this target's timing does for no reason at all under
# these exact conditions. A sample is the server's share of one request: curl's time to
# first byte minus its time to the end of connection setup, so connect jitter is not
# counted. Samples go in a few curl runs of several requests each (one sidecar per run,
# one connection reused), the first request of each run discarded as a warm-up.
#
# _TIMING_FLOOR, 10 ms, kept from the earlier probe. Below it the container network and
# the host's scheduler are a likelier cause than the handler, and an oracle that small
# needs far more samples across a real network than this probe takes. It is the
# smallest separation that can confirm, and the largest a rejection may leave
# unexcluded.
# _TIMING_OVER_CONTROL, 3: a confirming separation is at least three times the A/A
# difference measured in the same run.
# _TIMING_OVER_SPREAD, 2: and more than twice the within-class spread, the population
# standard deviation averaged over the three classes, so the distributions barely
# overlap. The standard deviation in place of the median absolute deviation, on purpose:
# one slow outlier raises it, which makes confirming and rejecting both harder.
# A rejection needs the spread small enough that a separation at the floor would have
# shown (twice the spread under the floor), both present-to-absent differences and the
# A/A difference under the floor, the same status for every class, a present identifier
# known to exist (one a seed recipe created or named), a parameter the handler is known
# to read, and the finding's own route. Without a known identifier the "present" one
# may not exist, and then both sides are absent and equal timing means nothing.
_TIMING_FLOOR = 0.010
_TIMING_OVER_CONTROL = 3.0
_TIMING_OVER_SPREAD = 2.0
_TIMING_ROUNDS_PER_RUN = 5           # 1 warm-up + 5 rounds x 3 = 16 requests per curl run
_TIMING_MAX_TIME = 3                 # per request; 16 x 3 s stays inside the 60 s sidecar
_TIMING_WOUT = "<<qz|%{http_code}|%{time_pretransfer}|%{time_starttransfer}>>\n"
_TIMING_ROW = re.compile(r"<<qz\|([^|]*)\|([^|]*)\|([^>]*)>>")
# Parameter names that carry an account identifier.
_ID_HINTS = ("user", "login", "mail", "account", "handle", "identifier", "uid")


def _timed(exec_fn, urls: list[str]) -> list[tuple[str, float | None]]:
    """One curl run over `urls`, in order, on one connection. -> per URL (status, server
    seconds), seconds None when the request got no answer. Padded to len(urls)."""
    argv = ["-s", "-g", "--path-as-is", "--max-time", str(_TIMING_MAX_TIME),
            "-w", _TIMING_WOUT]
    for u in urls:
        argv += ["-o", "/dev/null", u]
    _rc, out = exec_fn(argv)
    rows: list[tuple[str, float | None]] = []
    for m in _TIMING_ROW.finditer(out or ""):
        code = m[1].strip()
        try:
            pre, first = float(m[2]), float(m[3])
        except ValueError:
            pre, first = 0.0, 0.0
        answered = bool(code) and code != "000" and first > 0
        rows.append((code, max(0.0, first - pre) if answered else None))
    return (rows + [("", None)] * len(urls))[:len(urls)]


def _id_slot(route) -> _Slot:
    """The parameter that carries the identifier: a declared one named like an account
    identifier, else the guessed query parameter `username`, which can confirm (a
    separation shows the handler read it) but never reject."""
    for s in _slots(route):
        if s.declared and any(h in s.name.lower() for h in _ID_HINTS):
            return s
    return _Slot("query", "username", declared=False)


def _known_identifier(running: RunningTarget, slot: _Slot) -> tuple[str, str] | None:
    """(value, why it is known to exist) for an identifier this run created or named:
    a seed recipe's value for the parameter, or the login of a seeded account whose key
    the target's own command printed back. None when nothing shows one exists."""
    pv = running.param_values or {}
    if pv.get(slot.name):
        return pv[slot.name], f"the seed recipe's value for `{slot.name}`"
    if "mail" in slot.name.lower():
        return None
    spec = getattr(running, "cross_user", None)
    creds = running.credentials or {}
    for key, login in (getattr(spec, "accounts", None) or {}).items():
        if login and creds.get(key):
            return login, (f"account {login}, created by the seed recipe; the target's own "
                           "command printed its API key, so it exists")
    return None


def _shaped_like(value: str) -> str:
    """A random identifier with the same length and character classes as `value`, so a
    handler whose work depends on input length or shape times it the same way."""
    out = []
    for ch in value:
        r = os.urandom(1)[0]
        out.append(chr(ord("0") + r % 10) if ch.isdigit()
                   else chr(ord("a") + r % 26) if ch.isalpha() else ch)
    s = "".join(out)
    return s if s != value else _shaped_like(value)


def _timing_samples(exec_fn, urls: tuple[str, str, str],
                    samples: int) -> tuple[list, list, list]:
    """`samples` rounds of the three URLs, interleaved with the order rotated each round,
    in curl runs of _TIMING_ROUNDS_PER_RUN rounds plus a discarded warm-up."""
    got: tuple[list, list, list] = ([], [], [])
    done = 0
    while done < samples:
        n = min(_TIMING_ROUNDS_PER_RUN, samples - done)
        order = [(i + j) % 3 for i in range(done, done + n) for j in range(3)]
        rows = _timed(exec_fn, [urls[0]] + [urls[c] for c in order])
        for c, row in zip(order, rows[1:]):
            got[c].append(row)
        done += n
    return got


def probe_auth_timing_oracle(running: RunningTarget, candidate: Candidate,
                             routes: list, exec_fn, *, samples: int = 15) -> ProbeEvidence:
    """Measure whether an auth endpoint's response time separates a present identifier
    from absent ones, which leaks account existence, against an A/A control of two absent
    identifiers. Statistical; thresholds and their reasons are above. GET only, with the
    identifier in a declared parameter or the query; no password is sent, so no lockout
    counter moves. A target whose auth takes a body is where request-shape knowledge
    sharpens this."""
    own_routes = [r for r in _own(routes, candidate) if _readable(r)]
    own = bool(own_routes)
    auth = own_routes[0] if own else next(
        (r for r in _auth_first(routes) if any(h in r.path.lower() for h in AUTH_HINTS)),
        None)
    if auth is None:
        return ProbeEvidence(exercised=False, reproduced=False, determinism="unknown",
                             summary="no auth-like route in the finding's file to time")
    slot = _id_slot(auth)
    known = _known_identifier(running, slot)
    present = known[0] if known else ("admin@quarry.test" if "mail" in slot.name.lower()
                                      else "admin")
    urls = (_url(running, auth, slot, present),
            _url(running, auth, slot, _shaped_like(present)),
            _url(running, auth, slot, _shaped_like(present)))
    request = f"GET {urls[0]}  vs  GET {urls[1]}  vs  GET {urls[2]}"
    got = _timing_samples(exec_fn, urls, samples)
    codes = [sorted({c or "none" for c, _ in g}) for g in got]
    every = sorted(set(codes[0]) | set(codes[1]) | set(codes[2]))
    if not set(every) <= _REAL:
        # A 404 or 405 to both identifiers times the router, not the auth check, so
        # equal medians say nothing about the finding. This was a rejection, and the
        # rejection carried forward to every later run.
        return ProbeEvidence(exercised=False, 
            reproduced=False, determinism="unknown", handled=False, request=request,
            summary=f"{auth.path} answered {every} to GET; no auth handler was timed",
            observed=f"HTTP {every}")
    tp, ta, tb = ([s for _, s in g if s is not None] for g in got)
    if min(len(tp), len(ta), len(tb)) < 5:
        return ProbeEvidence(exercised=False, reproduced=False, determinism="unknown",
                             request=request,
                             summary="could not collect enough timing samples "
                                     f"({len(tp)}/{len(ta)}/{len(tb)} of {samples})")
    if not codes[0] == codes[1] == codes[2]:
        return ProbeEvidence(
            reproduced=False, determinism="unknown", handled=True, request=request,
            observed=f"present: HTTP {codes[0]}; absent: HTTP {codes[1]} and {codes[2]}",
            summary=f"{auth.path} answered the identifiers with different statuses, so "
                    "the timing compares different code paths. A status that separates a "
                    "present identifier from an absent one is an existence oracle of its "
                    "own, which this probe leaves for review")

    mp, ma, mb = (statistics.median(t) for t in (tp, ta, tb))
    spread = sum(statistics.pstdev(t) for t in (tp, ta, tb)) / 3
    control = abs(ma - mb)
    dp = (mp - ma, mp - mb)
    same_side = dp[0] * dp[1] > 0
    signal = min(abs(dp[0]), abs(dp[1])) if same_side else 0.0
    widest = max(abs(dp[0]), abs(dp[1]))

    def ms(x: float) -> str:
        return f"{x * 1000:.1f} ms"
    who = f"`{present}` ({known[1]})" if known else f"`{present}` (guessed)"
    # Recorded on every outcome below, so a held or undecided result still shows what
    # was measured against what.
    measured = dict(handled=True, request=request,
                    baseline=(f"two absent identifiers shaped like the present one: "
                              f"median {ms(ma)} and {ms(mb)}, A/A difference "
                              f"{ms(control)}, HTTP {codes[1]}"),
                    observed=(f"present identifier {who}: median {ms(mp)}, HTTP "
                              f"{codes[0]}; separation {ms(signal)} from both absent ones; "
                              f"within-class spread {ms(spread)}; "
                              f"n={len(tp)}/{len(ta)}/{len(tb)}, interleaved"))
    if (signal >= _TIMING_FLOOR and signal > _TIMING_OVER_SPREAD * spread
            and signal >= _TIMING_OVER_CONTROL * control):
        return _ev(own, auth, candidate, reproduced=True, determinism="statistical",
                   differs_from_baseline=True, **measured,
                   summary=f"response time on `{slot.name}` of GET {auth.path} separates "
                           f"a present identifier from two absent ones by {ms(signal)} "
                           f"(median {ms(mp)} against {ms(ma)} and {ms(mb)}), at least "
                           f"{_TIMING_OVER_CONTROL:g} times the {ms(control)} the two "
                           f"absent ones differ by and more than {_TIMING_OVER_SPREAD:g} "
                           f"times the {ms(spread)} spread")
    precise = _TIMING_OVER_SPREAD * spread < _TIMING_FLOOR
    if widest < _TIMING_FLOOR and control < _TIMING_FLOOR and precise:
        if known is None or not slot.declared:
            why = ("the present identifier is a guess that may not exist, so both sides "
                   "may be absent" if known is None else
                   f"`{slot.name}` is a guessed parameter the handler may not read")
            return ProbeEvidence(
                reproduced=False, determinism="statistical", **measured,
                summary=f"no timing separation on GET {auth.path} (widest "
                        f"{ms(widest)}), but {why}; this does not reject")
        return _ev(own, auth, candidate, reproduced=False, determinism="statistical",
                   differs_from_baseline=False, **measured,
                   summary=f"no timing separation on `{slot.name}` of GET {auth.path}: "
                           f"the present identifier came within {ms(widest)} of both "
                           f"absent ones, at a {ms(spread)} spread. A separation of "
                           f"{ms(_TIMING_FLOOR)} or more is excluded for this request "
                           "shape; a smaller one, or one on a POST body, is not")
    return ProbeEvidence(
        reproduced=False, determinism="unknown", **measured,
        summary=f"timing on GET {auth.path} neither separates nor rules a separation out: "
                f"separation {ms(signal)}, A/A difference {ms(control)}, spread "
                f"{ms(spread)}" + ("" if precise else
                                   f"; too noisy to exclude {ms(_TIMING_FLOOR)}"))


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
        return ProbeEvidence(exercised=False, reproduced=False, determinism="unknown",
                             summary="no GET route in the finding's file to inject into")
    cwe = probe_class(candidate.cwe) or ""
    if cwe == "CWE-79":
        return _xss(running, candidate, pool, own, exec_fn)
    if cwe == "CWE-89":
        return _sqli(running, candidate, pool, own, exec_fn)
    if cwe == "CWE-77":
        return _cmdi(running, candidate, pool, own, exec_fn)
    return ProbeEvidence(exercised=False, reproduced=False, determinism="unknown",
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


# Inputs that put a SQL metacharacter into a parameter without being able to change
# data: an unbalanced quote of either kind or parenthesis breaks the statement, and
# `AND 1=2` can only narrow it to nothing. No tautology such as `OR 1=1`: in an UPDATE
# or DELETE that a handler runs on a GET, it would widen the statement to every row.
_SQL_META = ("1'", '1"', "1)", "1 AND 1=2")
_SQL_SLOTS = 6               # declared parameters tried per route of the finding's own


def _sqli(running, cand, pool, own, exec_fn) -> ProbeEvidence:
    """A single quote against the plain value `1` on the same parameter confirms when it
    raises a SQL error the plain value did not.

    No error on a quote is not a rejection, since blind SQL injection exists. A
    rejection needs the bar the command-injection and traversal probes use: on the
    finding's own route, every declared parameter refused every metacharacter input as
    input (400, 403 or 422, with no SQL error) while the plain value on the same
    parameter was handled and not refused. That is a handler validating the value, a
    typed id for example, before it can reach a query. A guessed parameter, a route
    with more parameters than were tried, or one parameter that accepted a
    metacharacter leaves it for review."""
    exercised = False
    refused: list = []
    accepted: list[str] = []
    routes = pool[:3]
    if own and len(pool) > len(routes):
        accepted.append(f"{len(pool) - len(routes)} more route(s) of the handler, untried")
    for r in routes:
        all_slots = _slots(r)
        slots = all_slots[:_SQL_SLOTS] if own else all_slots[:3]
        if own and len(all_slots) > len(slots):
            accepted.append(f"{len(all_slots) - len(slots)} parameter(s) of {r.path}, "
                            "untried")
        for s in slots:
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
            control_held = (p.reached and p.status not in _REFUSE
                            and not _has_sql_error(p.body))
            if not (own and s.declared and control_held and q.status in _REFUSE):
                accepted.append(f"`{s.name}`")
                continue
            sent = [(qu, q)] + [(u, _fetch(exec_fn, u))
                                for u in (_url(running, r, s, v) for v in _SQL_META[1:])]
            if all(x.status in _REFUSE and not _has_sql_error(x.body) for _, x in sent):
                refused.append((r, s, pu, p, sent))
            else:
                accepted.append(f"`{s.name}`")
    if refused and not accepted:
        r, s, pu, p, sent = refused[0]
        names = ", ".join(f"`{x[1].name}`" for x in refused)
        answers = [resp for hit in refused for _, resp in hit[4]]
        return _ev(own, r, cand, reproduced=False, determinism="deterministic",
                   handled=True, differs_from_baseline=False,
                   request="; ".join(f"GET {u}" for u, _ in sent),
                   baseline=f"control GET {pu} -> {p.describe()}, no SQL error signature",
                   observed=(f"HTTP {sorted({x.status for x in answers})} to all "
                             f"{len(answers)} metacharacter inputs, no SQL error signature"),
                   summary=f"{r.method} {r.path} refused every SQL metacharacter input "
                           f"on every declared parameter ({names}) as input, and handled "
                           f"the plain value ({p.status}): the handler validates these "
                           "values before they can reach a query. Input from a body, a "
                           "header or a cookie was not tested")
    if not exercised:
        return ProbeEvidence(exercised=False, reproduced=False, determinism="unknown",
                             summary="the candidate route(s) returned nothing to inject into")
    held = (f"; not refused, or not decidable: {', '.join(accepted[:6])}"
            if refused and accepted else "")
    return ProbeEvidence(
        reproduced=False, determinism="unknown",
        summary="no SQL error on a single quote; blind SQL injection was not tested, so "
                "this does not reject" + held)


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
        return ProbeEvidence(exercised=False, reproduced=False, determinism="unknown",
                             summary="no GET route in the finding's file to test")
    cwe = probe_class(candidate.cwe) or ""
    if cwe == "CWE-22":
        return _traversal(running, candidate, pool, own, exec_fn)
    if cwe == "CWE-918":
        return _ssrf(running, candidate, pool, own, exec_fn)
    return ProbeEvidence(exercised=False, reproduced=False, determinism="unknown",
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


def _canary_window(page: str, *others: str) -> str:
    """A 40-character stretch of the target's root page that none of `others` contains:
    the control response, and the target's own not-found page. Taken from a page fetched
    directly, so finding it in the probe's response means the server fetched that page
    itself. Empty when the page is too short or shares every stretch with them.

    The not-found page is there because of VulnLookup (2026-11-06): a feed route's
    control returned XML, so the first stretch of the root page's HTML layout passed,
    and the probe's request, an unknown feed format, returned the site's 404 page in the
    same layout. Sixteen confirmations on four routes, none a fetch."""
    flat = " ".join(page.split())
    seen = [" ".join(o.split()) for o in others]
    for i in range(0, max(0, len(flat) - 40) + 1, 40):
        w = flat[i:i + 40]
        if len(w) == 40 and not any(w in o for o in seen):
            return w
    return ""


def _ssrf(running, cand, pool, own, exec_fn) -> ProbeEvidence:
    root = _fetch(exec_fn, running.base_url.rstrip("/") + "/")
    # What the target serves when it fetched nothing: its page for an unknown path.
    missing = _fetch(exec_fn, running.base_url.rstrip("/") + "/" + _marker())
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
            canary = _canary_window(root.body, c.body, missing.body) if root.ok else ""
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
