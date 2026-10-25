"""Route discovery: map a finding to the request that reaches it.

A probe needs a concrete request, and a finding only knows a file and a symbol. Route
discovery closes that gap. Three sources feed one RouteMap, each route tagged with where
it came from:

  * static   — route definitions parsed from source. The backbone: it is the only source
               that can tie a flagged handler to its URL, and it sees undocumented routes.
  * openapi  — an OpenAPI/Swagger document the running target serves, which gives the real
               request shape (methods, params, declared auth). Enriches static routes.
  * crawl    — links followed from the running target, for routes neither of the above
               surfaced.

Static is required under any configuration, because the finding-to-route link is itself
static. The others are added behind the same RouteSource interface and merged by
(method, path). This module ships the static source and the map; openapi and crawl sources
plug in next.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

METHODS = ("get", "post", "put", "patch", "delete")

# Express / JS: app.get('/x', ...), router.post("/x", ...)
_JS_ROUTE = re.compile(
    r"\b(?:app|router|r)\.(get|post|put|patch|delete)\s*\(\s*[\"'`]([^\"'`]+)[\"'`]",
    re.I)
# FastAPI / decorator style: @app.get("/x"), @router.post("/x")
_PY_DECOR = re.compile(
    r"@(?:\w+)\.(get|post|put|patch|delete)\s*\(\s*[\"']([^\"']+)[\"']", re.I)
# Flask / Django-ish: @app.route("/x", methods=["GET","POST"])
_PY_ROUTE = re.compile(
    r"@(?:\w+)\.route\s*\(\s*[\"']([^\"']+)[\"'](?:[^)]*methods\s*=\s*\[([^\]]*)\])?",
    re.I)

_SRC_EXTS = (".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx", ".py")
_SKIP = {"node_modules", ".git", "dist", "build", "venv", ".venv", "__pycache__",
         "vendor", "target", ".next"}


@dataclass(frozen=True)
class Route:
    method: str                 # upper-case HTTP method
    path: str                   # as declared, e.g. "/users/:id" or "/users/{id}"
    handler_file: str = ""      # repo-relative source file the route was declared in
    source: str = "static"      # static | openapi | crawl
    auth_required: bool | None = None
    params: tuple[str, ...] = ()

    @property
    def key(self) -> tuple[str, str]:
        return (self.method, _norm_path(self.path))


def _norm_path(path: str) -> str:
    """Normalise path-param syntax so :id, {id} and <id> compare equal across sources."""
    p = re.sub(r"[:{<]\w+[}>]?", "{}", path)
    return "/" + p.strip("/")


class RouteSource(Protocol):
    name: str
    def discover(self, src: Path) -> list[Route]: ...


@dataclass
class StaticRouteSource:
    """Parse route definitions from source. Framework-agnostic by pattern, covering the
    Express, FastAPI and Flask shapes first; more frameworks are additive."""
    name: str = "static"
    max_file_bytes: int = 400_000

    def discover(self, src: Path) -> list[Route]:
        src = src.resolve()
        out: list[Route] = []
        for p in self._files(src):
            try:
                if p.stat().st_size > self.max_file_bytes:
                    continue
                text = p.read_text(errors="replace")
            except OSError:
                continue
            rel = str(p.relative_to(src))
            out.extend(self._routes_in(text, rel))
        # stable, de-duplicated
        seen: dict[tuple, Route] = {}
        for r in out:
            seen.setdefault((r.method, r.path, r.handler_file), r)
        return sorted(seen.values(), key=lambda r: (r.handler_file, r.path, r.method))

    def _files(self, src: Path):
        import os
        for dp, dn, fn in os.walk(src):
            dn[:] = [d for d in dn if d not in _SKIP]
            for name in fn:
                if Path(name).suffix.lower() in _SRC_EXTS:
                    yield Path(dp) / name

    def _routes_in(self, text: str, rel: str) -> list[Route]:
        found: list[Route] = []
        for m in _JS_ROUTE.finditer(text):
            found.append(Route(m.group(1).upper(), m.group(2), rel, "static",
                               params=_path_params(m.group(2))))
        for m in _PY_DECOR.finditer(text):
            found.append(Route(m.group(1).upper(), m.group(2), rel, "static",
                               params=_path_params(m.group(2))))
        for m in _PY_ROUTE.finditer(text):
            path = m.group(1)
            methods = m.group(2)
            if methods:
                verbs = [v.strip().strip("\"'").upper()
                         for v in methods.split(",") if v.strip()]
            else:
                verbs = ["GET"]               # Flask defaults to GET
            for v in verbs:
                if v.lower() in METHODS:
                    found.append(Route(v, path, rel, "static",
                                       params=_path_params(path)))
        return found


def _path_params(path: str) -> tuple[str, ...]:
    return tuple(re.findall(r"[:{<](\w+)[}>]?", path))


@dataclass
class RouteMap:
    """Merged routes from every source, keyed by (method, normalised path). Later sources
    enrich earlier ones rather than overwrite: a static route gains the declared auth and
    params from a matching OpenAPI route."""
    routes: dict[tuple[str, str], Route] = field(default_factory=dict)
    by_file: dict[str, list[tuple[str, str]]] = field(default_factory=dict)

    def add(self, route: Route) -> None:
        k = route.key
        existing = self.routes.get(k)
        if existing is None:
            self.routes[k] = route
        else:
            self.routes[k] = _merge(existing, route)
        if route.handler_file:
            self.by_file.setdefault(route.handler_file, [])
            if k not in self.by_file[route.handler_file]:
                self.by_file[route.handler_file].append(k)

    def add_all(self, routes: list[Route]) -> None:
        for r in routes:
            self.add(r)

    def for_finding(self, handler_file: str) -> list[Route]:
        """Routes declared in the file a finding lives in. The probe's entry points."""
        return [self.routes[k] for k in self.by_file.get(handler_file, [])]


def _merge(a: Route, b: Route) -> Route:
    """Combine two routes with the same key. Prefer a known auth flag and a richer param
    list; keep the handler_file from whichever static source has one; union provenance."""
    source = a.source if a.source == b.source else f"{a.source}+{b.source}"
    return Route(
        method=a.method,
        path=a.path if a.handler_file else b.path,
        handler_file=a.handler_file or b.handler_file,
        source=source,
        auth_required=a.auth_required if a.auth_required is not None else b.auth_required,
        params=a.params if len(a.params) >= len(b.params) else b.params,
    )


def build_route_map(src: Path, sources: list[RouteSource] | None = None) -> RouteMap:
    """Discover routes from every source and merge. Static only, unless more are passed."""
    sources = sources or [StaticRouteSource(), OpenApiFileRouteSource()]
    rmap = RouteMap()
    for s in sources:
        rmap.add_all(s.discover(src))
    return rmap


# ------------------------------------------------------------------ OpenAPI

_OPENAPI_FILES = ("openapi.json", "openapi.yaml", "openapi.yml",
                  "swagger.json", "swagger.yaml", "swagger.yml")


def _security_required(sec) -> bool | None:
    """Whether an OpenAPI `security` value makes authentication mandatory.

    The list is a set of alternatives, any one of which satisfies the operation. An empty
    requirement object `{}` among them is the alternative "no credentials", so
    `[{}, {bearer: []}]` means anonymous access is allowed. An empty list `[]` declares no
    requirement at all. Only a list where every alternative names a scheme is mandatory.
    A value that is not a list is malformed, and the auth flag stays unknown."""
    if not isinstance(sec, list):
        return None
    return bool(sec) and all(isinstance(req, dict) and req for req in sec)


def routes_from_openapi(doc: dict) -> list[Route]:
    """Parse an OpenAPI/Swagger document into routes, with declared parameters and auth.

    A route carries auth_required=True when the operation (or, absent an operation-level
    `security`, the document) makes a security requirement mandatory, which is exactly the
    signal the authz probe wants: the spec itself says this endpoint is meant to be
    protected. An operation-level `security: []` overrides a global requirement, and an
    optional requirement (an empty object among the alternatives) is not protection."""
    paths = doc.get("paths")
    if not isinstance(paths, dict):
        return []
    global_sec = doc.get("security")
    global_security = _security_required(global_sec) if global_sec is not None else False
    out: list[Route] = []
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        for method, op in item.items():
            if method.lower() not in METHODS or not isinstance(op, dict):
                continue
            sec = op.get("security")
            auth = _security_required(sec) if sec is not None else global_security
            params = tuple(
                p.get("name") for p in op.get("parameters", []) or []
                if isinstance(p, dict) and p.get("in") == "path" and p.get("name"))
            out.append(Route(method.upper(), path, "", "openapi",
                             auth_required=auth, params=params))
    return out


@dataclass
class OpenApiFileRouteSource:
    """An OpenAPI/Swagger document committed to the repo. Hermetic, no running target."""
    name: str = "openapi"

    def discover(self, src: Path) -> list[Route]:
        import json
        import yaml
        for name in _OPENAPI_FILES:
            p = src / name
            if not p.is_file():
                continue
            try:
                text = p.read_text(errors="replace")
                doc = json.loads(text) if name.endswith(".json") else yaml.safe_load(text)
            except (OSError, ValueError, yaml.YAMLError):
                continue
            if isinstance(doc, dict):
                return routes_from_openapi(doc)
        return []


# ------------------------------------------------------------------ runtime sources
# These need a running target. `exec_fn` runs a command in a sidecar on the isolated
# network (DockerRuntime.probe_exec), so discovery stays inside containment.

def fetch_openapi_routes(exec_fn, base_url: str,
                         specs=("/openapi.json", "/swagger.json",
                                "/v3/api-docs", "/swagger/v1/swagger.json")) -> list[Route]:
    """Fetch an OpenAPI document the running target serves and parse it. Read-only."""
    import json
    for spec in specs:
        rc, out = exec_fn(["-s", "--max-time", "5", base_url.rstrip("/") + spec])
        if rc != 0 or not out.strip():
            continue
        try:
            doc = json.loads(out)
        except ValueError:
            continue
        if isinstance(doc, dict) and doc.get("paths"):
            return routes_from_openapi(doc)
    return []


_HREF = re.compile(r"""(?:href|action|src)\s*=\s*["']([^"'#?]+)""", re.I)


def crawl_routes(exec_fn, base_url: str, *, max_fetch: int = 20) -> list[Route]:
    """A bounded, GET-only, same-origin crawl: a backstop for routes neither static
    extraction nor an OpenAPI document surfaced. Never mutates; only follows links."""
    seen_paths: set[str] = set()
    queue = ["/"]
    fetched = 0
    out: list[Route] = []
    while queue and fetched < max_fetch:
        path = queue.pop(0)
        if path in seen_paths:
            continue
        seen_paths.add(path)
        rc, body = exec_fn(["-s", "--max-time", "5", base_url.rstrip("/") + path])
        fetched += 1
        if rc != 0:
            continue
        out.append(Route("GET", path, "", "crawl"))
        for href in _HREF.findall(body):
            if href.startswith("http"):
                continue                       # off-origin, ignore
            nxt = "/" + href.lstrip("/")
            if nxt not in seen_paths and nxt not in queue:
                queue.append(nxt)
    return out
