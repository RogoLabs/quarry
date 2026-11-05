"""A stand-in for the curl sidecar in hermetic probe tests.

A probe talks to the target only through exec_fn(argv), where argv is curl's. This parses
the argv the probes build (method, headers, body, -o, -w, one or more URLs), calls a
Python handler for each request, and prints what curl would: the body unless it went to
/dev/null, then the -w write-out with %{http_code}, %{time_total}, %{content_type} and
%header{name} filled in. The handler sees decoded paths and query values, as a server
would. Not a test module (no test_ prefix); imported by the probe tests.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, unquote, urlsplit


@dataclass
class Request:
    method: str
    url: str
    path: str                     # percent-decoded
    raw_path: str                 # as sent
    query: dict[str, str]
    headers: dict[str, str]       # lower-cased names
    data: str | None
    path_as_is: bool


@dataclass
class Reply:
    status: int = 200
    body: str = ""
    ctype: str = "text/html; charset=utf-8"
    secs: float = 0.01
    headers: dict[str, str] = field(default_factory=dict)


def _expand(fmt: str, r: Reply) -> str:
    out = fmt.replace("%{http_code}", f"{r.status:03d}" if r.status else "000")
    out = out.replace("%{time_total}", f"{r.secs:.6f}")
    out = out.replace("%{content_type}", r.ctype)
    hdrs = {k.lower(): v for k, v in r.headers.items()}
    return re.sub(r"%header\{([^}]*)\}", lambda m: hdrs.get(m[1].lower(), ""), out)


def curl(handler):
    """exec_fn for a handler(Request) -> Reply | (status, body) | (status, body, ctype).
    Every request is kept on `.requests`, in order."""
    requests: list[Request] = []

    def run(argv: list[str]):
        method, headers, data, wfmt, path_as_is = "GET", {}, None, "", False
        outs: list[str] = []
        urls: list[tuple[str, bool]] = []          # (url, its body goes to /dev/null)
        pending_null = False
        i = 0
        while i < len(argv):
            a = argv[i]
            if a in ("-X", "--request"):
                method = argv[i + 1]
                i += 2
            elif a in ("-H", "--header"):
                k, _, v = argv[i + 1].partition(":")
                headers[k.strip().lower()] = v.strip()
                i += 2
            elif a in ("--data-binary", "-d", "--data"):
                data = argv[i + 1]
                method = "POST" if method == "GET" else method
                i += 2
            elif a in ("-w", "--write-out"):
                wfmt = argv[i + 1]
                i += 2
            elif a in ("-o", "--output"):
                pending_null = argv[i + 1] == "/dev/null"
                i += 2
            elif a in ("--max-time", "-m"):
                i += 2
            elif a == "--path-as-is":
                path_as_is = True
                i += 1
            elif a.startswith("-"):
                i += 1
            else:
                urls.append((a, pending_null))
                pending_null = False
                i += 1
        for url, null in urls:
            parts = urlsplit(url)
            req = Request(method=method, url=url, path=unquote(parts.path),
                          raw_path=parts.path,
                          query={k: v for k, v in parse_qsl(parts.query,
                                                            keep_blank_values=True)},
                          headers=dict(headers), data=data, path_as_is=path_as_is)
            requests.append(req)
            got = handler(req)
            if not isinstance(got, Reply):
                got = Reply(*got)
            outs.append(("" if null else got.body) + _expand(wfmt, got))
        return 0, "".join(outs)

    run.requests = requests
    return run
