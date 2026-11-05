"""A route's declared access, read as the project's stated intent (IMPROVEMENT-PLAN 20).

Run 1 kept 2 of 1,708 raw findings, and both read as deliberate behaviour: `GET
/cve-id/:id` runs `mw.optionallyValidateUser` and has an unauthenticated branch on
purpose. The hunter and the refuter both had that middleware name in front of them, buried
in a 45k-token pack. Neither was told, in one place, what each route declares about who may
call it. This module says it, from two sources:

  * the source: the middleware an Express route lists before its handler, the decorators
    on a Flask, FastAPI or Flask-RESTX view (and a Resource's `method_decorators`), and
    FastAPI `Depends(...)` in the signature. Names as written, never executed.
  * a committed OpenAPI document: the operation's own `security`, or the spec-wide one it
    inherits.

Both are evidence with limits, and the text handed to a model says which limit applies. A
decorator list is what the author wrote, not what runs. A spec is documentation, not
enforcement, and a spec-wide `security` with no per-operation override over-declares:
VulnLookup's swagger.json (MEASURED on run 3's clone: 155 operations, global `apikey`, 0
operations with their own `security`) marks `GET /browse/` protected as surely as `DELETE
/bundle/`. That case is named as over-declaration, never passed off as proof of a check.

Routes come from `quarry.dynamic.routes` (the static route map Layer 3 uses, mount prefixes
resolved), so a route here has the same path Layer 3 would probe. This module only adds
what each declaration says about access.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from .. import taint
from ..dynamic import routes as R

METHODS = ("get", "post", "put", "patch", "delete")

# ------------------------------------------------------------------ shared scanning


def _skip_string(text: str, i: int) -> int:
    """Index just past the string literal that opens at `i` (', " or `)."""
    q = text[i]
    j = i + 1
    while j < len(text):
        c = text[j]
        if c == "\\":
            j += 2
            continue
        if c == q:
            return j + 1
        j += 1
    return j


def _split_args(text: str, open_paren: int) -> tuple[list[str], int]:
    """The top-level comma-separated arguments of the call whose `(` is at `open_paren`,
    and the index of its closing `)`. Strings and nested brackets are skipped, so
    `param(['id']).isString()` stays one argument."""
    depth, start, args = 0, open_paren + 1, []
    i = open_paren
    while i < len(text):
        c = text[i]
        if c in "\"'`":
            i = _skip_string(text, i)
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                args.append(text[start:i])
                return [a.strip() for a in args if a.strip()], i
        elif c == "," and depth == 1:
            args.append(text[start:i])
            start = i + 1
        i += 1
    args.append(text[start:])
    return [a.strip() for a in args if a.strip()], len(text)


def _one_line(s: str, limit: int = 80) -> str:
    """Target text for a prompt line: control characters gone, one line, bounded."""
    s = " ".join(taint.scrub_text(s, 400).split())
    return s if len(s) <= limit else s[:limit - 3] + "..."


def _norm(path: str) -> str:
    """Path-parameter syntax folded (:id, {id}, <int:id> compare equal)."""
    return "/" + R.PATH_PARAM.sub("{}", path).strip("/")


def _segments(path: str) -> list[str]:
    return [s for s in _norm(path).split("/") if s]


def _join(*parts: str) -> str:
    segs = [p.strip("/") for p in parts if p and p.strip("/")]
    return "/" + "/".join(segs) if segs else "/"


# ------------------------------------------------------------------ Express

_JS_CALL = re.compile(r"\b([A-Za-z_$][\w$]*)\.(get|post|put|patch|delete|use|all)\s*\(")
_JS_ROUTER_VAR = re.compile(r"(?:const|let|var)\s+(\w+)\s*=\s*(?:express\.)?Router\s*\(")
_JS_ROUTERS = {"app", "router", "r"}
_JS_HEAD = re.compile(r"[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*")
_JS_INLINE = re.compile(r"(?:async\s+)?(?:function\b|\([^()]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>)")


def _strip_js_comments(text: str) -> str:
    """// and /* */ comments blanked to spaces, newlines kept, so offsets and line
    numbers still match the file. cve-services puts a `/* #swagger ... */` block between
    a route's path and its middleware, and an apostrophe in that prose would otherwise
    open a string that never closes."""
    out = list(text)
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c in "\"'`":
            i = _skip_string(text, i)
            continue
        if text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            out[i:j] = " " * (j - i)
            i = j
            continue
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            for k in range(i, j):
                if out[k] != "\n":
                    out[k] = " "
            i = j
            continue
        i += 1
    return "".join(out)


def _js_arg_name(arg: str) -> list[str]:
    """What one route argument is called: `mw.validateUser`, `param(...)` for a call
    (validator chains included), `<inline function>`. An array of middleware is
    expanded, since Express accepts one."""
    a = " ".join(arg.split())
    if a.startswith("[") and a.endswith("]"):
        inner, _ = _split_args(f"({a[1:-1]})", 0)
        return [n for x in inner for n in _js_arg_name(x)]
    if _JS_INLINE.match(a):
        return ["<inline function>"]
    m = _JS_HEAD.match(a)
    if not m:
        return [_one_line(a, 40)]
    name = re.sub(r"\s+", "", m[0])
    return [name + ("(...)" if a[m.end():].lstrip().startswith("(") else "")]


@dataclass
class _Decl:
    """One route declaration found in a file, as written there."""
    method: str
    path: str                      # the declared path, before any mount prefix
    guards: list[str]              # middleware / decorators, in order, as written
    handler: str = ""
    router_level: list[str] = field(default_factory=list)   # router.use(...) before it


def _js_decls(text: str) -> list[_Decl]:
    clean = _strip_js_comments(text)
    routers = _JS_ROUTERS | set(_JS_ROUTER_VAR.findall(clean))
    uses: list[tuple[int, str, list[str]]] = []      # (offset, router, names)
    out: list[_Decl] = []
    for m in _JS_CALL.finditer(clean):
        obj, verb = m[1], m[2].lower()
        if obj not in routers:
            continue
        args, _ = _split_args(clean, m.end() - 1)
        if not args:
            continue
        first = args[0]
        is_path = first[:1] in "\"'`" and first[-1:] == first[:1]
        if verb == "use":
            if not is_path:                          # router-wide middleware
                uses.append((m.start(), obj,
                             [n for a in args for n in _js_arg_name(a)]))
            continue
        if not is_path or verb == "all" or len(args) < 2:
            continue
        guards = [n for a in args[1:-1] for n in _js_arg_name(a)]
        handler = _js_arg_name(args[-1])[0]
        before = [n for pos, o, names in uses if o == obj and pos < m.start()
                  for n in names]
        out.append(_Decl(verb.upper(), first[1:-1], guards, handler, before))
    return out


# ------------------------------------------------------------------ Python

# Decorators that document an operation rather than gate it. Listing them would bury
# the one decorator that matters (`auth_func`) under five `ns.doc(...)` lines.
_DOC_ONLY = re.compile(
    r"\.(?:doc|expect|marshal_with|marshal_list_with|marshal|response|param|produces|"
    r"header|deprecated|hide|vendor)\b|^@(?:staticmethod|classmethod|property)\b")
_PY_VERB_ROUTE = re.compile(r"^@(\w+)\.(get|post|put|patch|delete)\s*\(", re.I)
_PY_ROUTE = re.compile(r"^@(\w+)\.route\s*\(")
_DEPENDS = re.compile(r"\b(Depends|Security)\(\s*([\w.]+)")
_PY_HEAD = re.compile(r"(async\s+)?(def|class)\s+(\w+)")
_METHOD_DECORATORS = re.compile(r"^\s*method_decorators\s*=\s*[\[(]", re.M)


def _py_expr_end(text: str, i: int) -> int:
    """Index of the newline that ends the logical line starting at `i` (brackets and
    strings may carry it over several physical lines)."""
    depth = 0
    while i < len(text):
        c = text[i]
        if c in "\"'":
            i = _skip_string(text, i)
            continue
        if c == "#" and depth == 0:
            j = text.find("\n", i)
            return len(text) if j < 0 else j
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth = max(0, depth - 1)
        elif c == "\n" and depth == 0:
            return i
        i += 1
    return len(text)


@dataclass
class _PyBlock:
    indent: int
    decorators: list[str]
    kind: str            # def | class
    name: str
    start: int           # offset of the def/class keyword
    header: str          # the def line(s) through the colon
    body_end: int = 0    # offset where the block's body ends


def _py_blocks(text: str) -> list[_PyBlock]:
    """Every def and class with the decorators stacked on it, in file order."""
    blocks: list[_PyBlock] = []
    pending: list[str] = []
    pending_indent = -1
    i, n = 0, len(text)
    while i < n:
        j = text.find("\n", i)
        j = n if j < 0 else j
        line = text[i:j]
        s = line.lstrip()
        ind = len(line) - len(s)
        if s.startswith("@"):
            end = _py_expr_end(text, i + ind)
            if not pending:
                pending_indent = ind
            pending.append(" ".join(text[i + ind:end].split()))
            i = end + 1
            continue
        m = _PY_HEAD.match(s)
        if m:
            end = _py_expr_end(text, i + ind)
            blocks.append(_PyBlock(ind, pending if pending_indent == ind else [],
                                   m[2], m[3], i + ind, " ".join(text[i + ind:end].split())))
            pending = []
            i = end + 1
            continue
        if s and not s.startswith("#"):
            pending = []
        i = j + 1
    # A block's body runs until the next code line indented no deeper than it.
    for b in blocks:
        k = text.find("\n", b.start)
        end = n
        while 0 <= k < n:
            nxt = text.find("\n", k + 1)
            nxt = n if nxt < 0 else nxt
            ln = text[k + 1:nxt]
            st = ln.lstrip()
            if st and not st.startswith("#") and len(ln) - len(st) <= b.indent \
                    and not st.startswith((")", "]", "}")):
                end = k + 1
                break
            k = nxt if nxt < n else -1
        b.body_end = end
    return blocks


def _gates(decorators: list[str]) -> list[str]:
    """Decorators that may gate access: not the route itself, not documentation."""
    out = []
    for d in decorators:
        if _PY_VERB_ROUTE.match(d) or _PY_ROUTE.match(d) or _DOC_ONLY.search(d):
            continue
        out.append(_one_line(d[1:]))
    return out


def _depends(*texts: str) -> list[str]:
    return [f"{m[1]}({m[2]})" for t in texts for m in _DEPENDS.finditer(t)]


def _route_paths(decorator: str) -> tuple[list[str], list[str]]:
    """(paths, methods) a `@x.route(...)` or `@x.get(...)` decorator declares."""
    open_paren = decorator.index("(")
    args, _ = _split_args(decorator, open_paren)
    paths = [a[1:-1] for a in args if a[:1] in "\"'" and a[-1:] == a[:1]]
    vm = _PY_VERB_ROUTE.match(decorator)
    if vm:
        return paths[:1], [vm[2].upper()]
    meth = re.search(r"\bmethods\s*=\s*[\[(]([^\])]*)[\])]", decorator)
    if meth:
        verbs = [v.strip().strip("\"'").upper() for v in meth[1].split(",") if v.strip()]
        return paths, [v for v in verbs if v.lower() in METHODS]
    return paths, ["GET"]


def _py_decls(text: str) -> list[_Decl]:
    blocks = _py_blocks(text)
    out: list[_Decl] = []
    for b in blocks:
        routes = [d for d in b.decorators if _PY_VERB_ROUTE.match(d) or _PY_ROUTE.match(d)]
        if not routes:
            continue
        if b.kind == "def":
            gates = _gates(b.decorators) + _depends(b.header, *routes)
            for d in routes:
                paths, verbs = _route_paths(d)
                out.extend(_Decl(v, p, gates, b.name) for p in paths for v in verbs)
            continue
        # A Flask-RESTX / MethodView Resource: its verbs are its methods, and its gates
        # are the class's decorators, its `method_decorators`, and each method's own.
        cls_gates = _gates(b.decorators)
        body = text[b.start:b.body_end]
        md = _METHOD_DECORATORS.search(body)
        if md:
            items, _ = _split_args(body, md.end() - 1)
            cls_gates += [f"{_one_line(x)} (method_decorators)" for x in items]
        inner = [x for x in blocks if b.start < x.start < b.body_end and x.kind == "def"
                 and x.name in METHODS]
        if inner:
            depth = min(x.indent for x in inner)
            inner = [x for x in inner if x.indent == depth]
        for x in inner:
            gates = cls_gates + _gates(x.decorators) + _depends(x.header)
            for d in routes:
                paths, _ = _route_paths(d)
                out.extend(_Decl(x.name.upper(), p, gates, f"{b.name}.{x.name}")
                           for p in paths)
    return out


def declarations(text: str, rel: str) -> list[_Decl]:
    """Every route declared in one file, with what it declares about access."""
    if rel.endswith(".py"):
        return _py_decls(text)
    if Path(rel).suffix.lower() in (".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"):
        return _js_decls(text)
    return []


# ------------------------------------------------------------------ OpenAPI


@dataclass(frozen=True)
class SpecSecurity:
    """What a committed OpenAPI document says about one operation, and from where."""
    level: str          # operation | operation-none | operation-optional | global |
                        # global-optional | none | malformed
    schemes: tuple[str, ...]
    spec: str           # repo-relative path of the document
    ops_total: int      # operations in that document
    ops_overriding: int  # operations that carry their own `security`

    def describe(self) -> str:
        """One line for a route. The spec-wide caveat is said once per document, in
        `spec_note`, not repeated under every route that inherits it."""
        names = ", ".join(f"`{_one_line(s, 40)}`" for s in self.schemes) or "a scheme"
        if self.level == "operation":
            return (f"OpenAPI: the operation itself declares {names} (stated intent; "
                    f"documentation, not proof the code checks it).")
        if self.level == "operation-none":
            return "OpenAPI: the operation declares `security: []`, i.e. public by design."
        if self.level == "operation-optional":
            return (f"OpenAPI: the operation allows {names} OR anonymous access, so "
                    f"unauthenticated calls are allowed by design.")
        if self.level == "global":
            if self.ops_overriding == 0:
                return (f"OpenAPI: nothing on the operation; it inherits the spec-wide "
                        f"{names}, which over-declares (see the note on "
                        f"{_one_line(self.spec, 60)}). Not evidence of a check.")
            return (f"OpenAPI: nothing on the operation; it inherits the spec-wide "
                    f"{names}. {self.ops_overriding} of {self.ops_total} operations "
                    f"override it and this one does not, which is weak evidence.")
        if self.level == "global-optional":
            return "OpenAPI: inherits a spec-wide requirement that allows anonymous access."
        if self.level == "none":
            return "OpenAPI: no security is declared for this operation."
        return "OpenAPI: the `security` value is malformed and says nothing usable."


def spec_note(doc: dict, spec: str) -> str:
    """What one document's top-level `security` is worth, said once. The case item 20
    names: a spec-wide requirement that no operation overrides is applied to public and
    private routes alike, so it over-declares and proves nothing about any one route."""
    ops = [op for item in (doc.get("paths") or {}).values() if isinstance(item, dict)
           for m, op in item.items() if m.lower() in METHODS and isinstance(op, dict)]
    own = sum(1 for op in ops if "security" in op)
    gsec = doc.get("security")
    where = _one_line(spec, 80)
    if not gsec or R._security_required(gsec) is not True:
        return (f"{where}: {len(ops)} operation(s), {own} with their own `security`, "
                f"no mandatory spec-wide requirement.")
    names = ", ".join(f"`{_one_line(s, 40)}`" for s in _schemes(gsec))
    if own == 0:
        return (f"{where}: {len(ops)} operation(s) and none declares its own `security`, "
                f"so the spec-wide {names} requirement is applied to every one of them. "
                f"That OVER-DECLARES: public routes are marked protected too. Do not read "
                f"it as evidence that any one route checks credentials.")
    return (f"{where}: a spec-wide {names} requirement; {own} of {len(ops)} operation(s) "
            f"declare their own `security`. An operation that does not is covered only "
            f"by the spec-wide line, which is weak evidence of a check.")


def _schemes(sec) -> tuple[str, ...]:
    if not isinstance(sec, list):
        return ()
    return tuple(sorted({k for req in sec if isinstance(req, dict) for k in req}))


def spec_operations(doc: dict, spec: str) -> dict[tuple[str, str], SpecSecurity]:
    """(METHOD, normalised path) -> what the document declares for that operation.

    Unlike `routes_from_openapi`, which folds a spec-wide and a per-operation
    requirement into one `auth_required` flag, this keeps where the requirement came
    from: that difference is the whole point of item 20."""
    paths = doc.get("paths")
    if not isinstance(paths, dict):
        return {}
    base = R._base_path(doc)
    gsec = doc.get("security")
    ops: list[tuple[str, str, dict]] = []
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        for method, op in item.items():
            if method.lower() in METHODS and isinstance(op, dict):
                ops.append((method.upper(), _join(base, path) if base else path, op))
    overriding = sum(1 for _, _, op in ops if "security" in op)
    out: dict[tuple[str, str], SpecSecurity] = {}
    for method, path, op in ops:
        if "security" in op:
            sec = op["security"]
            req = R._security_required(sec)
            level = ("malformed" if req is None else "operation" if req
                     else "operation-none" if sec == [] else "operation-optional")
        elif gsec is None or gsec == []:
            sec, level = None, "none"
        else:
            sec = gsec
            req = R._security_required(gsec)
            level = "malformed" if req is None else "global" if req else "global-optional"
        out.setdefault((method, _norm(path)),
                       SpecSecurity(level, _schemes(sec), spec, len(ops), overriding))
    return out


def _find_specs(src: Path) -> list[str]:
    """Committed OpenAPI documents, shallowest first, by the rule Layer 3 uses."""
    found: list[tuple[int, str]] = []
    for dp, dn, fn in os.walk(src):
        rel = Path(dp).relative_to(src)
        depth = len(rel.parts)
        dn[:] = sorted(d for d in dn if d not in R._OPENAPI_SKIP
                       and depth < R._OPENAPI_MAX_DEPTH)
        for name in fn:
            if name in R._OPENAPI_FILES:
                found.append((depth, str(rel / name)))
    return [rel for _, rel in sorted(found)]


def _load_spec(src: Path, rel: str) -> dict | None:
    import yaml
    p = src / rel
    try:
        if p.is_symlink() or p.stat().st_size > R._OPENAPI_MAX_BYTES:
            return None
        text = p.read_text(errors="replace")
        doc = json.loads(text) if rel.endswith(".json") else yaml.safe_load(text)
    except (OSError, ValueError, yaml.YAMLError):
        return None
    return doc if isinstance(doc, dict) and ("openapi" in doc or "swagger" in doc) else None


# ------------------------------------------------------------------ the map


@dataclass(frozen=True)
class DeclaredAccess:
    method: str
    path: str
    file: str
    guards: tuple[str, ...]
    handler: str = ""
    router_level: tuple[str, ...] = ()
    spec: SpecSecurity | None = None
    prefix_resolved: bool = True

    def render(self) -> str:
        where = _one_line(self.file, 100) + ("" if self.prefix_resolved
                                             else ", mount prefix not resolved")
        lines = [f"- {self.method} {_one_line(self.path, 120)}  ({where})"]
        if self.router_level:
            lines.append("    router-wide middleware before it: "
                         + ", ".join(self.router_level[:8]))
        if self.guards:
            g = ", ".join(self.guards[:10]) + (" ..." if len(self.guards) > 10 else "")
            lines.append(f"    on the route, in order: {g}")
        else:
            lines.append("    on the route: nothing besides the handler")
        if self.handler:
            lines.append(f"    handler: {_one_line(self.handler, 80)}")
        if self.spec is not None:
            lines.append(f"    {self.spec.describe()}")
        return "\n".join(lines)


PREAMBLE = (
    "What each route below declares about who may call it, read from the source "
    "(middleware and decorators, as written) and from any committed OpenAPI document. "
    "Treat it as the project's stated intent, with limits: a name is not proof the "
    "check runs or is correct, and an OpenAPI document is documentation, not "
    "enforcement. Use it to tell a deliberate public route from a forgotten check. A "
    "route that declares optional or no authentication on purpose, and returns only what "
    "an anonymous caller is meant to see, is not a finding by that fact alone. A route "
    "that lacks a check its neighbours declare is the strongest signal there is.")


@dataclass
class IntentMap:
    routes: list[DeclaredAccess] = field(default_factory=list)
    specs: list[str] = field(default_factory=list)
    spec_notes: dict[str, str] = field(default_factory=dict)
    error: str = ""

    def summary(self) -> dict:
        """What the run recorded about intent, for the manifest."""
        levels: dict[str, int] = {}
        for r in self.routes:
            k = r.spec.level if r.spec else "not-in-spec"
            levels[k] = levels.get(k, 0) + 1
        return {"routes": len(self.routes), "specs": self.specs,
                "with_guards": sum(1 for r in self.routes if r.guards or r.router_level),
                "spec_levels": levels, "error": self.error}

    def _render(self, chosen: list[DeclaredAccess], limit: int, budget_chars: int,
                lead: str) -> str:
        if not chosen:
            return ""
        out = [PREAMBLE, ""]
        if lead:
            out += [lead, ""]
        if not self.specs:
            out += ["No committed OpenAPI document was found, so only the source speaks "
                    "here.", ""]
        for spec in sorted({r.spec.spec for r in chosen if r.spec is not None}):
            if spec in self.spec_notes:
                out += [f"Note on {self.spec_notes[spec]}", ""]
        used = sum(len(x) for x in out)
        shown = 0
        for r in chosen[:limit]:
            block = r.render()
            if used + len(block) > budget_chars:
                break
            out.append(block)
            used += len(block) + 1
            shown += 1
        if shown < len(chosen):
            out.append(f"({len(chosen) - shown} further route(s) not listed.)")
        return "\n".join(out)

    def for_files(self, files, *, limit: int = 60, budget_chars: int = 12_000) -> str:
        """The block for a hunt unit: every route declared in the unit's files."""
        wanted = set(files)
        return self._render([r for r in self.routes if r.file in wanted], limit,
                            budget_chars, "")

    def for_file(self, file: str, *, limit: int = 20, budget_chars: int = 5_000) -> str:
        """The block for one claim: routes declared in its file, or, when that file
        declares none (a controller whose routes live in a sibling index.js), in the
        files beside it, said as such."""
        if not file:
            return ""
        own = [r for r in self.routes if r.file == file]
        if own:
            return self._render(own, limit, budget_chars, "")
        folder = str(Path(file).parent)
        near = [r for r in self.routes if str(Path(r.file).parent) == folder]
        return self._render(near, limit, budget_chars,
                            f"The claim's file declares no routes; these are declared "
                            f"in files beside it ({_one_line(folder, 80)}/).")


def build(src: Path) -> IntentMap:
    """Every route the static route map finds, with what its declaration and any
    committed OpenAPI document say about access. Best effort: a failure returns an
    empty map with the error named, and a deep run goes on without intent rather than
    stopping."""
    src = Path(src).resolve()
    imap = IntentMap()
    try:
        static = R.StaticRouteSource().discover(src)
        ops: dict[tuple[str, str], SpecSecurity] = {}
        for rel in _find_specs(src):
            doc = _load_spec(src, rel)
            if doc is None:
                continue
            imap.specs.append(rel)
            imap.spec_notes[rel] = spec_note(doc, rel)
            for k, v in spec_operations(doc, rel).items():
                ops.setdefault(k, v)
        by_file: dict[str, list[_Decl]] = {}
        for rel in sorted({r.handler_file for r in static}):
            try:
                by_file[rel] = declarations((src / rel).read_text(errors="replace"), rel)
            except OSError:
                by_file[rel] = []
        claimed: set[int] = set()
        seen: set[tuple[str, str, str]] = set()
        for r in static:
            decls = by_file.get(r.handler_file, [])
            full = _segments(r.path)
            best, best_len = None, -1
            for d in decls:
                seg = _segments(d.path)
                if d.method == r.method and len(seg) <= len(full) \
                        and full[len(full) - len(seg):] == seg and len(seg) > best_len:
                    best, best_len = d, len(seg)
            if best is not None:
                claimed.add(id(best))
            key = (r.method, _norm(r.path), r.handler_file)
            if key in seen:
                continue
            seen.add(key)
            imap.routes.append(DeclaredAccess(
                r.method, r.path, r.handler_file,
                tuple(best.guards) if best else (), best.handler if best else "",
                tuple(best.router_level) if best else (),
                ops.get((r.method, _norm(r.path)))))
        # A declaration the route map did not place (an unrecognised router object)
        # still says something; it is listed with its path as written.
        for rel, decls in by_file.items():
            for d in decls:
                key = (d.method, _norm(d.path), rel)
                if id(d) in claimed or key in seen:
                    continue
                seen.add(key)
                imap.routes.append(DeclaredAccess(
                    d.method, d.path, rel, tuple(d.guards), d.handler,
                    tuple(d.router_level), ops.get((d.method, _norm(d.path))),
                    prefix_resolved=False))
    except Exception as e:                               # noqa: BLE001 (best effort)
        imap.routes, imap.error = [], f"{type(e).__name__}: {str(e)[:200]}"
    imap.routes.sort(key=lambda r: (r.file, _norm(r.path), r.method))
    return imap


# ------------------------------------------------------------------ enclosing symbol

_SYM_PY = re.compile(r"^([ \t]*)(?:async[ \t]+)?(def|class)[ \t]+(\w+)")
_SYM_JS = (
    re.compile(r"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*"
               r"([A-Za-z_$][\w$]*)"),
    re.compile(r"^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*"
               r"(?:async\s+)?(?:function\b|\([^)]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>)"),
    re.compile(r"^\s*([A-Za-z_$][\w$]*)\s*:\s*(?:async\s+)?(?:function\b|\([^)]*\)\s*=>)"),
    re.compile(r"^\s*(?:static\s+)?(?:async\s+)?(?!(?:if|for|while|switch|catch|return|"
               r"function)\b)([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{"),
)
_SYM_ROUTE = re.compile(r"\b\w+\.(get|post|put|patch|delete)\s*\(\s*[\"'`]([^\"'`]+)")


def _ws(s: str) -> str:
    return " ".join(s.split())


def quote_line(lines: list[str], quote: str, hint: int | None = None) -> int | None:
    """0-based index of the line the quote starts on, or None when it is not in the
    file. When the first line of the quote occurs more than once, the occurrence where
    the whole quote follows wins, then the one nearest the model's line number."""
    qlines = [_ws(x) for x in quote.splitlines() if x.strip()]
    if not qlines:
        return None
    first = qlines[0]
    cands = [i for i, ln in enumerate(lines) if first in _ws(ln)]
    if not cands:
        return None
    whole = _ws(quote)
    full = [i for i in cands if whole in _ws(" ".join(lines[i:i + len(qlines) + 2]))]
    pool = full or cands
    if hint:
        return min(pool, key=lambda i: abs((i + 1) - hint))
    return pool[0]


def _past_decorators(lines: list[str], idx: int) -> int:
    """A quote on a decorator (`@typed(auth_func)`) belongs to the def BELOW it, not the
    one above. When line `idx` is a decorator or inside one's brackets, the index of the
    def or class the stack decorates; otherwise `idx` unchanged."""
    start = None
    for k in range(idx, max(-1, idx - 12), -1):
        s = lines[k].lstrip()
        if _SYM_PY.match(lines[k]):
            return idx
        if s.startswith("@"):
            start = k
            break
    if start is None:
        return idx
    indent = len(lines[start]) - len(lines[start].lstrip())
    for k in range(start + 1, min(len(lines), start + 40)):
        m = _SYM_PY.match(lines[k])
        if m:
            return k if len(m[1]) == indent else idx
    return idx


def symbol_at(lines: list[str], idx: int, *, python: bool, max_up: int = 400) -> str | None:
    """The nearest enclosing definition at or above line `idx`: a Python def or class
    (qualified by its class, so two Resources' `delete` methods differ), a JS function
    or method, or an Express route declaration (`GET /cve-id/:id`), whichever is
    nearest. A route file's middleware lines belong to the route they sit in."""
    if python:
        idx = _past_decorators(lines, idx)
    for i in range(idx, max(-1, idx - max_up), -1):
        ln = lines[i]
        if python:
            m = _SYM_PY.match(ln)
            if m:
                name, indent = m[3], len(m[1])
                if indent:
                    for k in range(i - 1, max(-1, i - max_up), -1):
                        c = _SYM_PY.match(lines[k])
                        if c and c[2] == "class" and len(c[1]) < indent:
                            return f"{c[3]}.{name}"
                return name
            continue
        r = _SYM_ROUTE.search(ln)
        if r:
            return f"{r[1].upper()} {r[2]}"
        for pat in _SYM_JS:
            m = pat.match(ln)
            if m:
                return m[1]
    return None


def locate(src: Path, file: str, quote: str, line: int | None = None) -> str | None:
    """The definition enclosing the quote, or None when the file or the quote cannot be
    found. Reads only inside the clone, through the same path checks as quote
    verification, and the same one-same-named-file stand-in."""
    from ..scanners.base import rel_or_none
    rel = rel_or_none(file, src) if file else None
    if not rel or not quote.strip():
        return None
    import glob
    p = src / rel
    if not p.is_file():
        # The stand-in rule quote verification uses: one same-named file, or nothing.
        same = list(src.rglob(glob.escape(Path(rel).name))) if Path(rel).name else []
        if len(same) != 1:
            return None
        p = same[0]
        rel = str(p.relative_to(src))
    try:
        if p.is_symlink() or not p.resolve().is_relative_to(src.resolve()) \
                or not p.is_file():
            return None
        text = p.read_text(errors="replace")
    except OSError:
        return None
    lines = text.splitlines()
    idx = quote_line(lines, quote, line)
    if idx is None:
        return None
    return symbol_at(lines, idx, python=rel.endswith(".py"))
