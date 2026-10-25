"""Concrete probe bodies. Each is non-destructive by construction: it observes, it does
not mutate or delete, and it does not try to take the target down.

The first is broken authorization. Its cleanest, lowest-false-positive form is: a route
the target's own OpenAPI document declares protected (a non-empty security requirement),
reached with no credentials, that answers with success instead of 401/403. That is a
deterministic, replayable confirmation that the declared protection is not enforced.
When no route in the finding's file is declared protected, the probe says so and returns
needs-review rather than guessing. Sibling comparison and an authenticated-vs-anonymous
diff are enhancements for when no spec is available.
"""
from __future__ import annotations

import re
import statistics

from .validate import Candidate, ProbeEvidence, RunningTarget

ExecFn = "Callable[[list[str]], tuple[int, str]]"

# Paths whose name suggests an authentication or otherwise expensive endpoint, the
# natural target for the rate-limit and timing probes.
AUTH_HINTS = ("login", "signin", "sign-in", "sign_in", "auth", "token", "session",
              "password", "oauth", "account", "register", "reset")

# Status codes that mean the endpoint actually handled the request (as opposed to "wrong
# method" or "not found"), so the absence of a 429 among them is meaningful.
_REAL = {"200", "201", "204", "400", "401", "403", "409", "422", "429"}


def _concrete(path: str) -> str:
    """Substitute a benign value for every path parameter so the URL is requestable."""
    return "/" + re.sub(r"[:{<]\w+[}>]?", "1", path).strip("/")


def _status(exec_fn, url: str) -> str:
    rc, code = exec_fn(["-s", "-o", "/dev/null", "-w", "%{http_code}",
                        "--max-time", "5", url])
    return code.strip() if rc == 0 else ""


def _timing(exec_fn, url: str) -> float | None:
    rc, out = exec_fn(["-s", "-o", "/dev/null", "-w", "%{time_total}",
                       "--max-time", "5", url])
    try:
        return float(out.strip()) if rc == 0 else None
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
    if re.search(r"[:{<]\w+[}>]?", route.path):
        # one pass: first param gets the payload, the rest get a benign value, so the
        # payload is never re-scanned (an angle-bracket payload would look like a param).
        seen = {"n": 0}

        def repl(_m):
            seen["n"] += 1
            return payload if seen["n"] == 1 else "1"

        return base + "/" + re.sub(r"[:{<]\w+[}>]?", repl, route.path).strip("/")
    sep = "&" if "?" in route.path else "?"
    return base + _concrete(route.path) + f"{sep}q={payload}"


def _marker() -> str:
    import os
    return "qz" + os.urandom(4).hex()


# Signatures that mean a SQL interpreter saw malformed input, i.e. input reached a query
# unparameterised. Lower-cased comparison.
_SQL_ERRORS = ("sql syntax", "sqlite3.", "sqlite error", "operationalerror",
               "unrecognized token", "psycopg", "ora-00", "pg::", "syntax error at or near",
               "you have an error in your sql", "sqlstate", "unclosed quotation",
               "unterminated quoted", "mysql_fetch", "odbc", "mariadb")

# A read-only /etc/passwd line shape, the classic benign traversal signature. Inside the
# target's own container (host fs is not mounted), so this exposes nothing of the host.
_PASSWD = re.compile(r"root:.*:0:0:")


def _has_sql_error(body: str) -> bool:
    low = body.lower()
    return any(sig in low for sig in _SQL_ERRORS)


def probe_broken_authz(running: RunningTarget, candidate: Candidate,
                       routes: list, exec_fn) -> ProbeEvidence:
    """Reach each declared-protected GET route in the finding's file with no credentials.
    A 2xx is a confirmation; a uniform 401/403 is a rejection; neither is needs-review."""
    protected = [r for r in routes
                 if r.auth_required and r.method in ("GET", "HEAD")]
    if not protected:
        return ProbeEvidence(
            reproduced=False, determinism="unknown",
            summary="no route in the finding's file is declared auth-protected "
                    "(no OpenAPI security signal), so unauth reach cannot be decided")

    denied = 0
    for r in protected:
        url = running.base_url.rstrip("/") + _concrete(r.path)
        code = _status(exec_fn, url)
        if code and code[0] == "2":
            return ProbeEvidence(
                reproduced=True, determinism="deterministic",
                summary=f"{r.method} {r.path} is declared auth-protected but returned "
                        f"{code} with no credentials",
                request=f"{r.method} {url}  (no Authorization header)",
                observed=f"HTTP {code}")
        if code in ("401", "403"):
            denied += 1

    if denied == len(protected):
        return ProbeEvidence(
            reproduced=False, determinism="deterministic",
            summary=f"all {denied} declared-protected route(s) denied unauthenticated "
                    "access (401/403)")
    return ProbeEvidence(
        reproduced=False, determinism="unknown",
        summary="declared-protected routes were neither clearly reachable nor clearly "
                "denied; inconclusive")


def probe_missing_rate_limit(running: RunningTarget, candidate: Candidate,
                             routes: list, exec_fn, *, burst: int = 30) -> ProbeEvidence:
    """Send a small bounded burst at an auth or expensive endpoint and watch for
    throttling. A 429 means a limit exists (rejection); a burst of real responses with no
    429 means none was observed (confirmation). Bounded and GET-only, so non-destructive."""
    targets = _auth_first(routes)
    if not targets:
        return ProbeEvidence(reproduced=False, determinism="unknown",
                             summary="no route in the finding's file to exercise")
    r = targets[0]
    url = running.base_url.rstrip("/") + _concrete(r.path)
    statuses: list[str] = []
    for _ in range(burst):
        code = _status(exec_fn, url)
        statuses.append(code)
        if code == "429":
            break

    if "429" in statuses:
        return ProbeEvidence(
            reproduced=False, determinism="deterministic",
            summary=f"rate limiting present: 429 after {len(statuses)} request(s) to {r.path}",
            request=f"GET {url}  (x{len(statuses)})", observed="HTTP 429")

    real = [c for c in statuses if c in _REAL]
    if not real:
        return ProbeEvidence(
            reproduced=False, determinism="unknown",
            summary=f"endpoint {r.path} returned only {sorted(set(statuses))} to GET; not a "
                    "meaningful rate-limit test (try the declared method)")
    return ProbeEvidence(
        reproduced=True, determinism="statistical",
        summary=f"no throttling observed over {len(statuses)} rapid requests to {r.path} "
                "(no 429, no backoff)",
        request=f"GET {url}  (x{len(statuses)})",
        observed=f"{len(statuses)}x handled, 0x 429")


def probe_auth_timing_oracle(running: RunningTarget, candidate: Candidate,
                             routes: list, exec_fn, *, samples: int = 15) -> ProbeEvidence:
    """Measure whether an auth endpoint's response time separates a present identifier
    from an absent one, which leaks account existence. Statistical: many bounded samples
    per class, compared by median against the measured noise. GET-only, non-destructive.

    The two identifiers are supplied as a query parameter, a first approximation; a
    target whose auth takes a body is where request-shape knowledge sharpens this."""
    auth = next((r for r in _auth_first(routes)
                 if any(h in r.path.lower() for h in AUTH_HINTS)), None)
    if auth is None:
        return ProbeEvidence(reproduced=False, determinism="unknown",
                             summary="no auth-like route in the finding's file to time")
    base = running.base_url.rstrip("/") + _concrete(auth.path)
    sep = "&" if "?" in base else "?"
    present = f"{base}{sep}username=admin"
    absent = f"{base}{sep}username=zzqq-no-such-user-000"

    ta = [t for t in (_timing(exec_fn, present) for _ in range(samples)) if t is not None]
    tb = [t for t in (_timing(exec_fn, absent) for _ in range(samples)) if t is not None]
    if len(ta) < 5 or len(tb) < 5:
        return ProbeEvidence(reproduced=False, determinism="unknown",
                             summary="could not collect enough timing samples")

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
    return ProbeEvidence(
        reproduced=False, determinism="statistical",
        summary=f"no timing separation on {auth.path}: Δmedian {delta * 1000:.1f}ms within "
                f"noise (≈{noise * 1000:.1f}ms) over {len(ta)}/{len(tb)} samples")


def probe_injection_observable(running: RunningTarget, candidate: Candidate,
                               routes: list, exec_fn) -> ProbeEvidence:
    """Confirm injection through a benign, observable signal that never modifies or
    destroys data: an unencoded reflected marker (XSS), a SQL error elicited by a single
    quote on the read path (SQLi), or the output of `id` (command injection). The exact
    check is chosen by the finding's CWE, so the probe sends only what that class needs."""
    targets = [r for r in routes if r.params] or routes
    if not targets:
        return ProbeEvidence(reproduced=False, determinism="unknown",
                             summary="no route in the finding's file to inject into")
    cwe = (candidate.cwe or "").upper()
    exercised = False
    encoded_hit = None            # reflected, but safely encoded: positive evidence of safety
    for r in targets:
        if cwe == "CWE-79":                                  # reflected XSS
            mark = _marker()
            url = _inject(running, r, f"<{mark}>")
            body = _body(exec_fn, url)
            exercised = exercised or bool(body)
            if f"<{mark}>" in body:
                return ProbeEvidence(
                    reproduced=True, determinism="deterministic",
                    summary=f"a marker was reflected unencoded on {r.path}; output is not "
                            "HTML-encoded",
                    request=f"GET {url}",
                    observed=f"<{mark}> present verbatim in the response")
            if mark in body:       # the token came back, but its brackets were encoded/stripped
                encoded_hit = r.path
        elif cwe == "CWE-89":                                # SQL injection
            quoted_url = _inject(running, r, "1'")
            base = _body(exec_fn, _inject(running, r, "1"))
            quoted = _body(exec_fn, quoted_url)
            exercised = exercised or bool(base or quoted)
            if _has_sql_error(quoted) and not _has_sql_error(base):
                return ProbeEvidence(
                    reproduced=True, determinism="deterministic",
                    summary=f"a single quote elicited a SQL error on {r.path} that a plain "
                            "value did not; input reaches an unparameterised query",
                    request=f"GET {quoted_url}",
                    observed="SQL error signature in the response")
        elif cwe == "CWE-77":                                # command injection
            for vec in (";id", "|id", "$(id)"):
                body = _body(exec_fn, _inject(running, r, vec))
                exercised = exercised or bool(body)
                if "uid=" in body and "gid=" in body:
                    return ProbeEvidence(
                        reproduced=True, determinism="deterministic",
                        summary=f"an injected `id` executed on {r.path}; its output appears "
                                "in the response",
                        request=f"GET {_inject(running, r, vec)}",
                        observed="uid=/gid= in the response")
    if encoded_hit is not None:
        return ProbeEvidence(
            reproduced=False, determinism="deterministic",
            summary=f"the marker was reflected on {encoded_hit} but HTML-encoded; the output "
                    "is escaped, so this reflected-XSS candidate does not reproduce")
    if not exercised:
        return ProbeEvidence(reproduced=False, determinism="unknown",
                             summary="the candidate route(s) returned nothing to inject into")
    return ProbeEvidence(
        reproduced=False, determinism="unknown",
        summary="no in-band injection signal for this class (no raw reflection, no SQL error, "
                "no command output); this technique did not reproduce it, but blind variants "
                "were not tested")


def probe_path_traversal_ssrf(running: RunningTarget, candidate: Candidate,
                              routes: list, exec_fn) -> ProbeEvidence:
    """CWE-22: a traversal sequence that reaches /etc/passwd inside the target's own
    container (host files are not mounted), observed read-only. CWE-918: a parameter
    pointing at an internal address that makes the server itself issue the request,
    observed in-band. Both are confirmations without exfiltration or mutation."""
    targets = [r for r in routes if r.params] or routes
    if not targets:
        return ProbeEvidence(reproduced=False, determinism="unknown",
                             summary="no route in the finding's file to test")
    cwe = (candidate.cwe or "").upper()
    exercised = False

    if cwe == "CWE-22":
        payloads = ("../../../../../../etc/passwd",
                    "....//....//....//etc/passwd",
                    "%2e%2e%2f%2e%2e%2fetc%2fpasswd")
        for r in targets:
            for p in payloads:
                body = _body(exec_fn, _inject(running, r, p))
                exercised = exercised or bool(body)
                if _PASSWD.search(body):
                    return ProbeEvidence(
                        reproduced=True, determinism="deterministic",
                        summary=f"a traversal sequence on {r.path} returned a passwd-shaped "
                                "file; the path escapes its intended directory",
                        request=f"GET {_inject(running, r, p)}",
                        observed="root:...:0:0: in the response")
    elif cwe == "CWE-918":
        sentinel = "quarry-ssrf-sentinel.invalid"
        for r in targets:
            body = _body(exec_fn, _inject(running, r, f"http://{sentinel}/"))
            exercised = exercised or bool(body)
            low = body.lower()
            if sentinel in low and any(s in low for s in
                                       ("getaddrinfo", "could not resolve", "no such host",
                                        "connection refused", "failed to connect", "econnrefused")):
                return ProbeEvidence(
                    reproduced=True, determinism="deterministic",
                    summary=f"a URL parameter on {r.path} made the server attempt an outbound "
                            "request to an attacker-supplied host",
                    request=f"GET {_inject(running, r, 'http://' + sentinel + '/')}",
                    observed="server-side fetch error naming the sentinel host")

    if not exercised:
        return ProbeEvidence(reproduced=False, determinism="unknown",
                             summary="the candidate route(s) returned nothing to test")
    return ProbeEvidence(
        reproduced=False, determinism="unknown",
        summary="no in-band traversal/SSRF signal observed; a blind or out-of-band variant "
                "would need a callback listener, which this probe does not set up")
