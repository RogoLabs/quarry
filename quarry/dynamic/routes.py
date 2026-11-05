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
static. The others are merged into it by (method, path), which only works when the static
path is the one the server actually answers on, so static extraction resolves mount
prefixes: FastAPI `APIRouter(prefix=)` and `include_router`, Flask `url_prefix` and
`register_blueprint`, Flask-RESTX `Namespace`, `Api(prefix=)` and `add_namespace`, Express
`app.use` with `require` or `import`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

METHODS = ("get", "post", "put", "patch", "delete")

# Express / JS: app.get('/x', ...), router.post("/x", ...). The object is captured so a
# route on a mounted router picks up its mount prefix.
_JS_ROUTE = re.compile(
    r"\b(\w+)\.(get|post|put|patch|delete)\s*\(\s*[\"'`]([^\"'`]+)[\"'`]", re.I)
# The objects a JS route may be declared on: the common names, plus any variable the
# file binds to express.Router() / Router(). Not every `x.get("/...")`, because
# `axios.get("/api/x")` in client code is a request, not a route.
_JS_ROUTER_NAMES = {"app", "router", "r"}
_JS_ROUTER_VAR = re.compile(r"(?:const|let|var)\s+(\w+)\s*=\s*(?:express\.)?Router\s*\(")
_JS_REQUIRE = re.compile(
    r"(?:const|let|var)\s+(\w+)\s*=\s*require\(\s*[\"'](\.[^\"']+)[\"']\s*\)"
    r"|import\s+(\w+)\s+from\s+[\"'](\.[^\"']+)[\"']")
# app.use('/api', usersRouter) and app.use('/api', require('./routes/users'))
_JS_USE = re.compile(
    r"\b(\w+)\.use\s*\(\s*[\"'`]([^\"'`]+)[\"'`]\s*,\s*"
    r"(?:(\w+)\s*[,)]|require\(\s*[\"'](\.[^\"']+)[\"']\s*\))")
# FastAPI / decorator style: @app.get("/x"), @router.post("/x")
_PY_DECOR = re.compile(
    r"@(\w+)\.(get|post|put|patch|delete)\s*\(\s*[\"']([^\"']+)[\"']", re.I)
# Flask: @app.route("/x", methods=["GET","POST"]) on a function. Flask-RESTX and
# flask-smorest: @ns.route("/x", "/y") on a Resource or MethodView class, whose methods
# are the class's get/post/... functions. The arguments are read with _call_args.
_PY_ROUTE = re.compile(r"@(\w+)\.route\s*\(")
_PY_STR_ARG = re.compile(r"\s*[\"']([^\"']*)[\"']\s*(?:,|$)")
_PY_METHODS = re.compile(r"\bmethods\s*=\s*[\[(]([^\])]*)[\])]")
_PY_DECORATED = re.compile(r"^([ \t]*)(?:async[ \t]+)?(def|class)[ \t]+\w+", re.M)
_PY_VERB_DEF = re.compile(
    r"^([ \t]+)(?:async[ \t]+)?def[ \t]+(get|post|put|patch|delete)\s*\(", re.M)
# ns = Namespace("users", path="/u"); api = Api(blueprint, prefix="/v1")
_PY_NAMESPACE = re.compile(r"(\w+)\s*=\s*Namespace\s*\(")
_PY_API = re.compile(r"(\w+)\s*=\s*Api\s*\(")
# router = APIRouter(prefix="/users"), bp = Blueprint("users", __name__, url_prefix="/u")
_PY_ROUTER = re.compile(r"(\w+)\s*=\s*(APIRouter|Blueprint)\s*\(([^)]*)\)")
# app.include_router(users.router, prefix="/api"), app.register_blueprint(bp, url_prefix=),
# api.add_namespace(users.ns, path="/users")
_PY_MOUNT = re.compile(
    r"\b(\w+)\.(include_router|register_blueprint|add_namespace)\s*\(\s*([\w.]+)\s*"
    r"(?:,([^)]*))?\)")
_PY_FROM = re.compile(r"^\s*from\s+([\w.]+)\s+import\s+\(?([^)\n]+)\)?", re.M)
_PY_IMPORT = re.compile(r"^\s*import\s+([\w.]+)(?:\s+as\s+(\w+))?", re.M)


# One path parameter in any framework's syntax: Flask <name> and <converter:name> (with
# converter arguments too), OpenAPI and FastAPI {name} and {name:path}, Express :name.
# Shared with the probes, which substitute a value for each one.
PATH_PARAM = re.compile(r"<(?:[^<>:]+:)?(\w+)>|\{(\w+)(?::[^}]*)?\}|:(\w+)")


def _call_args(text: str, open_paren: int) -> str:
    """The text between the parenthesis at `open_paren` and its match, skipping string
    literals. Constructor calls nest (`Api(bp, version=version("x"))`), which a `[^)]*`
    pattern stops inside."""
    depth, i, quote = 0, open_paren, ""
    while i < len(text):
        c = text[i]
        if quote:
            if c == "\\":
                i += 1
            elif c == quote:
                quote = ""
        elif c in "\"'":
            quote = c
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return text[open_paren + 1:i]
        i += 1
    return text[open_paren + 1:]


def _str_args(args: str) -> list[str]:
    """The leading positional string literals of a call's arguments."""
    out, pos = [], 0
    while (m := _PY_STR_ARG.match(args, pos)):
        out.append(m[1])
        pos = m.end()
    return out


def _class_verbs(text: str, start: int, indent: str) -> list[str]:
    """HTTP verbs a class defines as methods: its body runs from the line after `start`
    until the next non-blank line indented no deeper than the class itself."""
    lines = text[start:].splitlines()[1:]
    body = []
    for line in lines:
        if line.strip() and not line.lstrip().startswith("#") and \
                len(line) - len(line.lstrip()) <= len(indent):
            break
        body.append(line)
    code = [ln for ln in body if ln.strip() and not ln.lstrip().startswith("#")]
    if not code:
        return []
    depth = len(code[0]) - len(code[0].lstrip())     # the class body's own indent
    found = {m[2].lower() for m in _PY_VERB_DEF.finditer("\n".join(body))
             if len(m[1]) == depth}                  # not a function nested in a method
    return [v.upper() for v in METHODS if v in found]


def _line_of(text: str, offset: int) -> int:
    """1-based line number of a character offset."""
    return text.count("\n", 0, offset) + 1


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip())


def _code(line: str) -> str:
    """A line without a trailing comment or surrounding space. Approximate: a `#` inside
    a string literal cuts the line short, which only shortens a header scan."""
    return line.split("#", 1)[0].strip()


def _py_def_span(lines: list[str], def_idx: int) -> tuple[int, int]:
    """(first, last) 1-based lines of the def or class at `def_idx` (0-based), its
    decorators included. Decorators span several lines in Flask-RESTX code
    (`@ns.doc(\\n responses={...}\\n)`), so the walk up takes every line at the def's
    indent that starts with `@` or closes a bracket, and every deeper line between them,
    and stops at a blank line or any other statement at that indent. A blank line between
    two decorators ends the walk early, which only makes the span shorter."""
    if not (0 <= def_idx < len(lines)):
        return (0, 0)
    ind = _indent(lines[def_idx])
    start = def_idx
    k = def_idx - 1
    while k >= 0 and def_idx - k <= 80:
        line = lines[k]
        if not line.strip():
            break
        here, code = _indent(line), _code(line)
        if here < ind:
            break
        if here == ind:
            if code.startswith("@"):
                start = k
            elif not code or code[0] in ")]}":
                pass                           # a comment or a decorator's closing bracket
            else:
                break                          # a statement: the previous sibling's end
        k -= 1
    # The header may run over several lines (a long signature); the body starts after the
    # first line whose code ends with ':'.
    h = def_idx
    while h < len(lines) - 1 and h - def_idx < 30 and not _code(lines[h]).endswith(":"):
        h += 1
    end = h
    for j in range(h + 1, len(lines)):
        line = lines[j]
        if not line.strip() or not _code(line):
            continue
        if _indent(line) <= ind:
            break
        end = j
    return (start + 1, end + 1)


def _class_verb_spans(text: str, start: int, indent: str) -> dict[str, tuple[int, int]]:
    """VERB -> (first, last) line of that verb's method in the class at `start`. A
    Flask-RESTX Resource serves each verb from its own method, so a finding inside
    `delete` belongs to the DELETE route and not to the GET beside it."""
    lines = text.splitlines()
    cls = _line_of(text, start) - 1
    _, cls_end = _py_def_span(lines, cls)
    body = [i for i in range(cls + 1, cls_end) if _code(lines[i])]
    if not body:
        return {}
    depth = _indent(lines[body[0]])
    out: dict[str, tuple[int, int]] = {}
    for i in range(cls + 1, cls_end):
        m = _PY_VERB_DEF.match(lines[i])
        if m and len(m[1]) == depth and m[2].upper() not in out:
            out[m[2].upper()] = _py_def_span(lines, i)
    return out


# Query parameters a handler body reads. Flask `request.args.get("x")`, `request.args["x"]`,
# `request.values.get("x")`; Express `req.query.x` and `req.query["x"]`.
_PY_QUERY = re.compile(
    r"request\.(?:args|values)(?:\.get(?:list)?\(\s*|\[\s*)[\"'](\w+)[\"']")
_JS_QUERY = re.compile(r"\breq\.query(?:\.(\w+)|\[\s*[\"'](\w+)[\"']\s*\])")


def _query_params(text: str, span: tuple[int, int], rel: str) -> tuple[str, ...]:
    """Query parameter names read inside a handler's own lines, in first-seen order."""
    if not span[0]:
        return ()
    body = "\n".join(text.splitlines()[span[0] - 1:span[1]])
    pat = _PY_QUERY if rel.endswith(".py") else _JS_QUERY
    names: list[str] = []
    for m in pat.finditer(body):
        name = next(g for g in m.groups() if g)
        if name not in names:
            names.append(name)
    return tuple(names)


def _kwarg(args: str | None, name: str) -> str | None:
    m = re.search(rf"\b{name}\s*=\s*[\"']([^\"']*)[\"']", args or "")
    return m[1] if m else None


def _join(*parts: str) -> str:
    """Join URL path pieces with exactly one slash between them; "" pieces vanish."""
    segs = [p.strip("/") for p in parts if p and p.strip("/")]
    return "/" + "/".join(segs) if segs else "/"


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
    # Where a mandatory security requirement was declared: "operation" when the operation
    # itself names one, "global" when it only inherits the document's top-level
    # `security`. A global requirement is a default the author applied to every
    # operation, public reads included (VulnLookup's spec marks its whole read API that
    # way), so only "operation" counts as "this route is declared protected".
    auth_scope: str = ""
    # How a credential is presented for this route's scheme, from the spec's security
    # schemes: a header name ("X-API-KEY") or "Authorization: Bearer". Empty when unknown.
    auth_header: str = ""
    # Query parameter names the route reads: OpenAPI `in: query`, or the handler body's
    # own `request.args.get("x")` / `req.query.x`. A probe injects into a declared name
    # before it falls back to a guessed `q`, and only a declared name can reject.
    query: tuple[str, ...] = ()
    # The handler's lines in handler_file, 1-based and inclusive, decorators included.
    # Static routes only; 0 when unknown. This is what ties a finding's line to the
    # route that serves it, rather than to every route in the same file.
    line: int = 0
    end_line: int = 0

    @property
    def key(self) -> tuple[str, str]:
        return (self.method, _norm_path(self.path))

    def encloses(self, path: str, line: int | None) -> bool:
        """Whether a finding at `path`:`line` sits inside this route's own handler."""
        return (bool(line) and bool(self.line) and self.handler_file == path
                and self.line <= int(line) <= self.end_line)


def _norm_path(path: str) -> str:
    """Normalise path-param syntax so :id, {id}, <id> and <int:id> compare equal across
    sources."""
    p = PATH_PARAM.sub("{}", path)
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
        """Two passes. First every file is read for its routes, its router objects and
        what it mounts; then each route gets the prefixes of every mount that reaches
        its router. Routes on a mounted router used to keep their bare path, so probes
        hit /users instead of /api/users and read 404 as "handled"."""
        src = src.resolve()
        texts: dict[str, str] = {}
        for p in self._files(src):
            try:
                if p.stat().st_size > self.max_file_bytes:
                    continue
                texts[str(p.relative_to(src))] = p.read_text(errors="replace")
            except OSError:
                continue
        mounts = _Mounts(texts)
        out: list[Route] = []
        for rel, text in texts.items():
            for obj, method, path, span in self._routes_in(text, rel):
                query = _query_params(text, span, rel)
                for prefix in mounts.prefixes(rel, obj):
                    full = _join(prefix, path) if prefix else path
                    out.append(Route(method, full, rel, "static",
                                     params=_path_params(full), query=query,
                                     line=span[0], end_line=span[1]))
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

    def _routes_in(self, text: str, rel: str) -> list[tuple[str, str, str, tuple[int, int]]]:
        """(object, METHOD, path, (first line, last line) of its handler) for every route
        declared in one file."""
        found: list[tuple[str, str, str, tuple[int, int]]] = []
        lines = text.splitlines()
        if not rel.endswith(".py"):
            routers = _JS_ROUTER_NAMES | set(_JS_ROUTER_VAR.findall(text))
            for m in _JS_ROUTE.finditer(text):
                if m[1] in routers:
                    open_paren = text.index("(", m.start(2))
                    end = open_paren + 1 + len(_call_args(text, open_paren))
                    span = (_line_of(text, m.start()), _line_of(text, end))
                    found.append((m[1], m[2].upper(), m[3], span))
            return found
        for m in _PY_DECOR.finditer(text):
            target = _PY_DECORATED.search(text, m.end())
            span = (_py_def_span(lines, _line_of(text, target.start()) - 1)
                    if target is not None else (0, 0))
            found.append((m[1], m[2].upper(), m[3], span))
        for m in _PY_ROUTE.finditer(text):
            args = _call_args(text, m.end() - 1)
            paths = _str_args(args)
            target = _PY_DECORATED.search(text, m.end())
            if not paths or target is None:
                continue
            if target[2] == "class":           # a Resource: its methods are the verbs
                spans = _class_verb_spans(text, target.start(), target[1])
                verbs = [v for v in _class_verbs(text, target.start(), target[1])]
            else:
                if (meth := _PY_METHODS.search(args)):
                    verbs = [v.strip().strip("\"'").upper()
                             for v in meth[1].split(",") if v.strip()]
                else:
                    verbs = ["GET"]           # Flask defaults to GET
                whole = _py_def_span(lines, _line_of(text, target.start()) - 1)
                spans = {v: whole for v in verbs}
            found.extend((m[1], v, path, spans.get(v, (0, 0))) for path in paths
                         for v in verbs if v.lower() in METHODS)
        return found


class _Mounts:
    """Where each router object is mounted, resolved across files. A mount whose target
    cannot be pinned to exactly one file is ignored rather than guessed, so a route is
    never given a prefix that belongs to a different router."""

    def __init__(self, texts: dict[str, str]):
        self.texts = texts
        # (file, obj) -> its own prefix: APIRouter(prefix=) or Blueprint(url_prefix=)
        self.local: dict[tuple[str, str], str] = {}
        # (target file, target obj or None) -> [(mounting file, mounting obj, prefix,
        #                                         replaces the target's own prefix)]
        self.into: dict[tuple[str, str | None], list[tuple[str, str, str, bool]]] = {}
        for rel, text in texts.items():
            if rel.endswith(".py"):
                self._python(rel, text)
            else:
                self._js(rel, text)

    # -- parsing -----------------------------------------------------------
    def _python(self, rel: str, text: str) -> None:
        for m in _PY_ROUTER.finditer(text):
            kw = "prefix" if m[2] == "APIRouter" else "url_prefix"
            self.local[(rel, m[1])] = _kwarg(m[3], kw) or ""
        for m in _PY_NAMESPACE.finditer(text):
            # A RESTX namespace is served under path=, or /<name> when none is given.
            args = _call_args(text, m.end() - 1)
            name = (_str_args(args) or [""])[0]
            path = _kwarg(args, "path")
            self.local[(rel, m[1])] = path if path is not None else _join(name)
        names = self._py_imports(rel, text)
        for m in _PY_API.finditer(text):
            # Api(app_or_blueprint, prefix=): the Api is mounted on its first argument.
            args = _call_args(text, m.end() - 1)
            host = re.match(r"\s*([A-Za-z_][\w.]*)\s*(?:,|$)", args)
            if host is None:
                continue
            frm = self._py_target(rel, host[1], names) or (rel, host[1])
            self.into.setdefault((rel, m[1]), []).append(
                (frm[0], frm[1], _kwarg(args, "prefix") or "", False))
        for m in _PY_MOUNT.finditer(text):
            target = self._py_target(rel, m[3], names)
            if target is None:
                continue
            if m[2] == "include_router":       # FastAPI prepends to the router's prefix
                prefix, replaces = _kwarg(m[4], "prefix") or "", False
            else:                              # Flask url_prefix= and RESTX path= replace
                kw = "url_prefix" if m[2] == "register_blueprint" else "path"
                prefix = _kwarg(m[4], kw)
                replaces = prefix is not None
                prefix = prefix or ""
            self.into.setdefault(target, []).append((rel, m[1], prefix, replaces))

    def _py_imports(self, rel: str, text: str) -> dict[str, tuple[str, str | None]]:
        """Local name -> (module, attribute or None) for what a file imports."""
        names: dict[str, tuple[str, str | None]] = {}
        for m in _PY_IMPORT.finditer(text):
            names[m[2] or m[1].split(".")[0]] = (m[1], None)
        for m in _PY_FROM.finditer(text):
            for part in m[2].split(","):
                bits = part.split()
                if not bits:
                    continue
                alias = bits[2] if len(bits) == 3 and bits[1] == "as" else bits[0]
                names[alias] = (m[1], bits[0])
        return names

    def _py_target(self, rel: str, expr: str, names) -> tuple[str, str] | None:
        head, _, attr = expr.partition(".")
        if not attr:
            if (rel, head) in self.local:
                return rel, head
            if head not in names:
                return None
            mod, name = names[head]
            f = self._py_module(rel, mod)      # from .users import router [as x]
            return (f, name) if f and name else None
        if head not in names:
            return None
        mod, name = names[head]                # from .routers import users; users.router
        f = self._py_module(rel, f"{mod}.{name}" if name else mod)
        return (f, attr) if f else None

    def _py_module(self, rel: str, mod: str) -> str | None:
        dots = len(mod) - len(mod.lstrip("."))
        parts = [p for p in mod.lstrip(".").split(".") if p]
        if dots:
            base = Path(rel).parent
            for _ in range(dots - 1):
                base = base.parent
            stem = (base / Path(*parts)) if parts else base
            cands = [f"{stem}.py", f"{stem}/__init__.py"]
            hits = [c.removeprefix("./") for c in cands
                    if c.removeprefix("./") in self.texts]
        else:
            tail = "/".join(parts)
            hits = [f for f in self.texts
                    if f == f"{tail}.py" or f.endswith(f"/{tail}.py")
                    or f == f"{tail}/__init__.py" or f.endswith(f"/{tail}/__init__.py")]
        return hits[0] if len(hits) == 1 else None

    def _js(self, rel: str, text: str) -> None:
        req = {}
        for m in _JS_REQUIRE.finditer(text):
            var, spec = (m[1], m[2]) if m[1] else (m[3], m[4])
            req[var] = spec
        local = set(_JS_ROUTER_VAR.findall(text))
        for m in _JS_USE.finditer(text):
            var, spec = m[3], m[4]
            if var and var in local:
                target = (rel, var)
            else:
                spec = spec or req.get(var or "")
                f = self._js_module(rel, spec) if spec else None
                if f is None:
                    continue
                target = (f, None)
            self.into.setdefault(target, []).append((rel, m[1], m[2], False))

    def _js_module(self, rel: str, spec: str) -> str | None:
        import posixpath
        base = posixpath.normpath(posixpath.join(posixpath.dirname(rel), spec))
        for ext in ("", ".js", ".ts", ".mjs", ".cjs", "/index.js", "/index.ts"):
            if f"{base}{ext}" in self.texts:
                return f"{base}{ext}"
        return None

    # -- resolution ----------------------------------------------------------
    def prefixes(self, rel: str, obj: str, _seen: frozenset = frozenset()) -> list[str]:
        """Every full prefix a route on `obj` in `rel` is served under. [""] when it is
        not mounted anywhere, which is the old behaviour."""
        key = (rel, obj)
        if key in _seen:
            return [""]
        own = self.local.get(key, "")
        mounts = self.into.get(key, []) + (
            self.into.get((rel, None), []) if obj not in ("app",) else [])
        if not mounts:
            return [own]
        out = []
        for frm, frm_obj, prefix, replaces in mounts:
            for outer in self.prefixes(frm, frm_obj, _seen | {key}):
                out.append(_join(outer, prefix) if replaces else _join(outer, prefix, own))
        return sorted(set(out))


def _path_params(path: str) -> tuple[str, ...]:
    return tuple(next(g for g in m.groups() if g) for m in PATH_PARAM.finditer(path))


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
    list; keep the handler_file, and the handler's lines, from whichever static source
    has one; union provenance and query names."""
    source = a.source if a.source == b.source else f"{a.source}+{b.source}"
    auth_from = a if a.auth_required is not None else b
    lines_from = a if a.handler_file else b
    return Route(
        method=a.method,
        path=a.path if a.handler_file else b.path,
        handler_file=a.handler_file or b.handler_file,
        source=source,
        auth_required=auth_from.auth_required,
        params=a.params if len(a.params) >= len(b.params) else b.params,
        auth_scope=auth_from.auth_scope,
        auth_header=a.auth_header or b.auth_header,
        query=a.query + tuple(q for q in b.query if q not in a.query),
        line=lines_from.line, end_line=lines_from.end_line,
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
# Committed specs are looked for this deep, outside test and example trees, so a fixture
# spec for some other service is not read as this one's. VulnLookup keeps its generated
# swagger.json at docs/_static/files/.
_OPENAPI_MAX_DEPTH = 4
_OPENAPI_MAX_BYTES = 8_000_000
_OPENAPI_SKIP = _SKIP | {"test", "tests", "testdata", "fixtures", "examples", "example",
                         "e2e", "mocks"}


def _base_path(doc: dict) -> str:
    """The path every operation is served under: Swagger 2 `basePath`, or the path of
    OpenAPI 3's first server URL (absolute or relative). Flask-RESTX on a blueprint
    writes `basePath: /api` and keys its paths without it."""
    if isinstance(doc.get("basePath"), str):
        return doc["basePath"]
    servers = doc.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        from urllib.parse import urlparse
        url = str(servers[0].get("url") or "")
        if "{" not in url:                     # a templated server has no fixed path
            return urlparse(url).path if "://" in url else url
    return ""


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
    schemes = _security_schemes(doc)
    base = _base_path(doc)
    out: list[Route] = []
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        shared = item.get("parameters") if isinstance(item.get("parameters"), list) else []
        for method, op in item.items():
            if method.lower() not in METHODS or not isinstance(op, dict):
                continue
            sec = op.get("security")
            auth = _security_required(sec) if sec is not None else global_security
            scope = ("operation" if sec is not None else "global") if auth else ""
            declared = [p for p in list(shared) + list(op.get("parameters", []) or [])
                        if isinstance(p, dict) and p.get("name")]
            params = tuple(p["name"] for p in declared if p.get("in") == "path")
            query = tuple(dict.fromkeys(p["name"] for p in declared if p.get("in") == "query"))
            out.append(Route(method.upper(), _join(base, path) if base else path, "",
                             "openapi", auth_required=auth, params=params,
                             auth_scope=scope, query=query,
                             auth_header=_auth_header(sec if sec is not None else global_sec,
                                                      schemes) if auth else ""))
    return out


def _security_schemes(doc: dict) -> dict:
    """Scheme name -> definition, from OpenAPI 3 `components.securitySchemes` or Swagger 2
    `securityDefinitions`."""
    comp = doc.get("components")
    found = comp.get("securitySchemes") if isinstance(comp, dict) else None
    found = found if isinstance(found, dict) else doc.get("securityDefinitions")
    return found if isinstance(found, dict) else {}


def _auth_header(sec, schemes: dict) -> str:
    """How to present a credential for the first scheme of a mandatory requirement: an
    apiKey header's name, or `Authorization: Bearer` / `Authorization: Basic`. Empty for
    a cookie or query key, or an unknown scheme: the authz probe then has no invalid-
    credential control to send, and says so."""
    if not isinstance(sec, list):
        return ""
    for req in sec:
        for name in (req or {}):
            s = schemes.get(name)
            if not isinstance(s, dict):
                continue
            kind = str(s.get("type", "")).lower()
            if kind == "apikey" and str(s.get("in", "")).lower() == "header" and s.get("name"):
                return str(s["name"])
            if kind == "http" and str(s.get("scheme", "")).lower() in ("bearer", "basic"):
                return f"Authorization: {str(s['scheme']).capitalize()}"
            if kind in ("oauth2", "openidconnect"):
                return "Authorization: Bearer"
            if kind == "basic":                       # Swagger 2
                return "Authorization: Basic"
    return ""


@dataclass
class OpenApiFileRouteSource:
    """OpenAPI/Swagger documents committed to the repo. Hermetic, no running target.
    Every spec found is read, shallowest first, and a later one only enriches routes an
    earlier one did not describe (RouteMap merges, never overwrites)."""
    name: str = "openapi"

    def discover(self, src: Path) -> list[Route]:
        import json
        import os
        import yaml
        src = Path(src)
        found: list[tuple[int, str]] = []
        for dp, dn, fn in os.walk(src):
            rel = Path(dp).relative_to(src)
            depth = len(rel.parts)
            dn[:] = sorted(d for d in dn if d not in _OPENAPI_SKIP
                           and depth < _OPENAPI_MAX_DEPTH)
            for name in fn:
                if name in _OPENAPI_FILES:
                    found.append((depth, str(rel / name)))
        out: list[Route] = []
        for _, rel in sorted(found):
            p = src / rel
            try:
                if p.is_symlink() or p.stat().st_size > _OPENAPI_MAX_BYTES:
                    continue
                text = p.read_text(errors="replace")
                doc = json.loads(text) if rel.endswith(".json") else yaml.safe_load(text)
            except (OSError, ValueError, yaml.YAMLError):
                continue
            if isinstance(doc, dict) and ("openapi" in doc or "swagger" in doc):
                out.extend(routes_from_openapi(doc))
        return out


# ------------------------------------------------------------------ runtime sources
# These need a running target. `exec_fn` runs a command in a sidecar on the isolated
# network (DockerRuntime.probe_exec), so discovery stays inside containment.

def fetch_openapi_routes(exec_fn, base_url: str,
                         specs=("/openapi.json", "/swagger.json",
                                "/v3/api-docs", "/swagger/v1/swagger.json",
                                "/api/swagger.json", "/api/openapi.json")) -> list[Route]:
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
