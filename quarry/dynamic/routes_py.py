"""Static routes for Python frameworks whose route table sits apart from the handler.

Django declares routes in URLconf lists (`urlpatterns` of `path`, `re_path`, legacy `url`,
`include`, DRF routers) and Starlette in `Route`/`Mount` lists. The handler, its lines and
what it declares about access then live somewhere else, often in another file. This module
reads both with `ast`: the target's code is parsed, never imported or run.

Resolution is static and conservative. A name is followed through the file's own
definitions and imports to exactly one file, or not at all. A path piece is a string
literal, a module-level string constant of the same file, or an f-string, `+`
concatenation or `.format()` of those. Anything else is not guessed: the piece adds
nothing to the path, the route carries `prefix_resolved=False`, and the expression is
recorded in `unresolved` (IMPROVEMENT-PLAN item 12).

Declared access is read where the route is resolved, names as written: wrappers in the
URLconf (`login_required(views.x)`), decorators on the view, access mixins and
`permission_classes`/`authentication_classes`/`permission_required` on a class view and
its bases, `@method_decorator` on `dispatch`, an `@action`'s own `permission_classes`, and
project-wide declarations from settings (a login-required MIDDLEWARE entry, DRF's
`DEFAULT_PERMISSION_CLASSES` for a DRF view that sets none). Starlette: decorators on the
endpoint and `middleware=` on the Route, Mount or app.
"""
from __future__ import annotations

import ast
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

VERBS = ("GET", "POST", "PUT", "PATCH", "DELETE")


@dataclass
class Found:
    """One route as a framework extractor found it, before it becomes a routes.Route."""
    method: str
    path: str
    file: str                       # the handler's file (the URLconf when unresolved)
    line: int
    end_line: int
    handler: str
    guards: tuple[str, ...] = ()
    app_guards: tuple[str, ...] = ()
    prefix_resolved: bool = True
    query: tuple[str, ...] = ()


class Unresolved:
    """An ordered, de-duplicated record of what could not be resolved, file:line first."""

    def __init__(self) -> None:
        self._items: dict[str, None] = {}

    def add(self, file: str, line: int, what: str) -> None:
        self._items.setdefault(f"{file}:{line}: {_short(what, 160)}", None)

    def __iter__(self):
        return iter(self._items)

    def __len__(self) -> int:
        return len(self._items)


# ------------------------------------------------------------------ small helpers

def _short(s: str, limit: int = 120) -> str:
    s = " ".join(str(s).split())
    return s if len(s) <= limit else s[:limit - 3] + "..."


def _callee(node) -> str:
    """The last name of a call's function: `path` for `path(...)` and `urls.path(...)`."""
    f = node.func if isinstance(node, ast.Call) else node
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        return f.attr
    return ""


def _last_name(node) -> str:
    """`ListAPIView` for `generics.ListAPIView`, `Generic` for `Generic[T]`."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Subscript):
        return _last_name(node.value)
    if isinstance(node, ast.Call):
        return _last_name(node.func)
    return ""


def _root_name(node) -> str:
    while isinstance(node, ast.Attribute):
        node = node.value
    return node.id if isinstance(node, ast.Name) else ""


def _toplevel(body):
    """Module-level statements, those inside a module-level if/try/with included: a
    URLconf often adds patterns under `if settings.DEBUG:`. Every branch is read, since a
    static reader cannot know which one runs."""
    for st in body:
        yield st
        if isinstance(st, ast.If):
            yield from _toplevel(st.body)
            yield from _toplevel(st.orelse)
        elif isinstance(st, (ast.Try, getattr(ast, "TryStar", ast.Try))):
            yield from _toplevel(st.body)
            for h in st.handlers:
                yield from _toplevel(h.body)
            yield from _toplevel(st.orelse)
            yield from _toplevel(st.finalbody)
        elif isinstance(st, (ast.With, ast.AsyncWith)):
            yield from _toplevel(st.body)


def _span(node) -> tuple[int, int]:
    """(first, last) line of a def or class, its decorators included."""
    first = min([d.lineno for d in getattr(node, "decorator_list", [])] + [node.lineno])
    return first, getattr(node, "end_lineno", None) or node.lineno


def _head_span(cls) -> tuple[int, int]:
    """A class view's own lines for a verb it inherits: its decorators, its header and
    the attributes before its first method. Not the whole class, which would also
    enclose its other methods, so a probe on GET could decide a finding that sits in
    `destroy` (IMPROVEMENT-PLAN item 3)."""
    first, last = _span(cls)
    defs = [st for st in cls.body
            if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
    if defs:
        last = max(first, _span(defs[0])[0] - 1)
        while last > first and not _line_has_code(cls, last):
            last -= 1
    return first, last


def _line_has_code(cls, line: int) -> bool:
    """Whether any statement of the class body or its header covers `line`."""
    if line <= cls.lineno:
        return True
    return any(st.lineno <= line <= (getattr(st, "end_lineno", None) or st.lineno)
               for st in cls.body)


def _call_span(node) -> tuple[int, int]:
    return node.lineno, getattr(node, "end_lineno", None) or node.lineno


def _arg(call: ast.Call, pos: int, kw: str):
    """A call's argument by position, else by keyword; None when absent."""
    if len(call.args) > pos and not isinstance(call.args[pos], ast.Starred):
        return call.args[pos]
    for k in call.keywords:
        if k.arg == kw:
            return k.value
    return None


def _assign_parts(st) -> list[tuple[str, ast.AST]]:
    """(name, value) for a module-level `name = v`, `name: T = v` or `name += v`."""
    if isinstance(st, ast.Assign):
        return [(t.id, st.value) for t in st.targets if isinstance(t, ast.Name)]
    if isinstance(st, ast.AnnAssign) and isinstance(st.target, ast.Name) and st.value:
        return [(st.target.id, st.value)]
    if isinstance(st, ast.AugAssign) and isinstance(st.target, ast.Name):
        return [(st.target.id, st.value)]
    return []


def _str_list(node) -> list[str] | None:
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        out = [e.value for e in node.elts
               if isinstance(e, ast.Constant) and isinstance(e.value, str)]
        return out if len(out) == len(node.elts) else None
    return None


def _lookup(env, node) -> str | None:
    """A name's string value: from a plain dict of constants (by bare name only), or an
    Env that also follows an import to another file's constant."""
    if hasattr(env, "lookup"):
        return env.lookup(node)
    return env.get(node.id) if isinstance(node, ast.Name) else None


def str_parts(node, env) -> list[str | None] | None:
    """The pieces of a string expression in order, each a known string or None where a
    static reader cannot compute it (a call, a setting, an unknown name). Literals,
    constants, f-strings, `+` and `"...".format(...)` are read; None when the
    expression is not a string expression at all (a number, a list)."""
    if isinstance(node, ast.Constant):
        return [node.value] if isinstance(node.value, str) else None
    if isinstance(node, (ast.Name, ast.Attribute)):
        return [_lookup(env, node)]
    if isinstance(node, ast.JoinedStr):
        out: list[str | None] = []
        for v in node.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                out.append(v.value)
            elif isinstance(v, ast.FormattedValue) and v.conversion == -1 \
                    and v.format_spec is None:
                out += str_parts(v.value, env) or [None]
            else:
                out.append(None)
        return out
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        a, b = str_parts(node.left, env), str_parts(node.right, env)
        return None if a is None or b is None else a + b
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
            and node.func.attr == "format":
        return _format_parts(node, env)
    if isinstance(node, ast.Call):
        return [None]
    return None


def _format_parts(node: ast.Call, env) -> list[str | None]:
    import string
    base = str_parts(node.func.value, env)
    if base is None or any(p is None for p in base) or \
            any(isinstance(a, ast.Starred) for a in node.args) or \
            any(k.arg is None for k in node.keywords):
        return [None]

    def val(n):
        p = str_parts(n, env)
        return "".join(p) if p is not None and all(x is not None for x in p) else None
    pos = [val(a) for a in node.args]
    kws = {k.arg: val(k.value) for k in node.keywords}
    out: list[str | None] = []
    auto = 0
    try:
        for lit, fld, spec, conv in string.Formatter().parse("".join(base)):
            if lit:
                out.append(lit)
            if fld is None:
                continue
            if fld == "":
                v, auto = pos[auto], auto + 1
            elif fld.isdigit():
                v = pos[int(fld)]
            elif fld.isidentifier():
                v = kws[fld]
            else:
                v = None                       # {0.attr}, {x[k]}
            out.append(None if spec or conv else v)
    except (IndexError, KeyError, ValueError):
        return [None]
    return out


def eval_str(node, env) -> str | None:
    """The string, when every piece of it is known; None otherwise."""
    parts = str_parts(node, env)
    if parts is None or any(p is None for p in parts):
        return None
    return "".join(parts)


def eval_prefix(node, env) -> tuple[str | None, bool]:
    """(value, complete). When pieces are unknown only at the start (after a regex `^`),
    the expression is a path behind a prefix the reader cannot see, such as
    `r"^{}api/v2/".format(get_system_setting("url_prefix"))`: the value is the known rest,
    with the `^` kept, and complete is False. The unknown piece is left out, never filled
    in. None when an unknown piece sits anywhere else, or nothing is known after it."""
    parts = str_parts(node, env)
    if parts is None:
        return None, False
    if all(p is not None for p in parts):
        return "".join(parts), True
    last = max(i for i, p in enumerate(parts) if p is None)
    head, tail = parts[:last], "".join(parts[last + 1:])
    if any(p not in (None, "", "^") for p in head) or not tail.lstrip("^/"):
        return None, False
    return ("^" if "^" in head else "") + tail, False


def _parse_expr(expr: str):
    try:
        return ast.parse("(" + expr.strip() + "\n)", mode="eval").body
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return None


def eval_text_prefix(expr: str, env) -> tuple[str | None, bool]:
    """eval_prefix of an expression given as source text."""
    node = _parse_expr(expr)
    return eval_prefix(node, env) if node is not None else (None, False)


class Env:
    """The names one file can turn into strings: its own module-level constants, and a
    constant it imports from exactly one other file of the tree (`from .api import path`).
    `extra` holds values bound for one call, such as a helper's parameter defaults."""

    def __init__(self, idx: "PyIndex", rel: str, extra: dict[str, str] | None = None):
        self.idx, self.rel, self.extra = idx, rel, extra or {}

    def lookup(self, node) -> str | None:
        if isinstance(node, ast.Name):
            if node.id in self.extra:
                return self.extra[node.id]
            v = self.idx.consts(self.rel).get(node.id)
            if v is not None or node.id in self.idx.assigned(self.rel):
                return v
            ref = self.idx.resolve_name(self.rel, node.id)
        else:
            ref = self.idx.resolve_expr(self.rel, node)
        if ref is not None and ref.kind == "assign" and ref.file:
            return self.idx.consts(ref.file).get(ref.name)
        return None


# ------------------------------------------------------------------ the module index

@dataclass
class Ref:
    """What a name resolves to: a def or class node, a module-level assigned name, or a
    module (its file when it is in the tree, and its absolute dotted name when known)."""
    kind: str                       # def | class | assign | module
    file: str | None
    node: ast.AST | None = None
    name: str = ""
    dotted: str = ""


class PyIndex:
    """The tree's Python files, parsed on demand, with what a static reader can resolve:
    imports to files (exactly one, or nothing), module-level definitions, and
    module-level string constants."""

    def __init__(self, texts: dict[str, str]):
        self.texts = {k: v for k, v in texts.items() if k.endswith(".py")}
        self._tree: dict[str, ast.Module | None] = {}
        self._top: dict[str, list] = {}
        self._imports: dict[str, tuple[dict, list]] = {}
        self._defs: dict[str, dict[str, Ref]] = {}
        self._assigned: dict[str, set[str]] = {}
        self._consts: dict[str, dict[str, str]] = {}
        self._hits: dict[tuple[str, str], list[str]] = {}
        # every path suffix of every file ("b/c.py", "a/b/c.py", ...) -> the files with it,
        # so an absolute module name is looked up rather than matched against every file
        self._suffix: dict[str, list[str]] = {}
        for f in sorted(self.texts):
            parts = f.split("/")
            for i in range(len(parts)):
                self._suffix.setdefault("/".join(parts[i:]), []).append(f)
        self.unparsed: list[str] = []

    def tree(self, rel: str):
        if rel not in self._tree:
            t = None
            text = self.texts.get(rel)
            if text is not None:
                try:
                    t = ast.parse(text, filename=rel)
                except (SyntaxError, ValueError, RecursionError, MemoryError):
                    self.unparsed.append(rel)
            self._tree[rel] = t
        return self._tree[rel]

    def top(self, rel: str) -> list:
        if rel not in self._top:
            t = self.tree(rel)
            self._top[rel] = list(_toplevel(t.body)) if t is not None else []
        return self._top[rel]

    def source(self, rel: str, node) -> str:
        """The node's text as the author wrote it, on one line; unparsed as a fallback."""
        seg = None
        try:
            seg = ast.get_source_segment(self.texts.get(rel, ""), node)
        except Exception:                                  # noqa: BLE001
            seg = None
        if not seg:
            try:
                seg = ast.unparse(node)
            except Exception:                              # noqa: BLE001
                seg = "<expr>"
        return _short(seg)

    def imports(self, rel: str) -> tuple[dict, list]:
        """(local name -> ("module", dotted, None) | ("from", module, attr), star modules)."""
        if rel not in self._imports:
            names: dict[str, tuple] = {}
            stars: list[str] = []
            for st in self.top(rel):
                if isinstance(st, ast.Import):
                    for a in st.names:
                        if a.asname:
                            names[a.asname] = ("module", a.name, None)
                        else:
                            head = a.name.split(".")[0]
                            names[head] = ("module", head, None)
                elif isinstance(st, ast.ImportFrom):
                    mod = "." * st.level + (st.module or "")
                    for a in st.names:
                        if a.name == "*":
                            stars.append(mod)
                        else:
                            names[a.asname or a.name] = ("from", mod, a.name)
            self._imports[rel] = (names, stars)
        return self._imports[rel]

    def defs(self, rel: str) -> dict[str, Ref]:
        if rel not in self._defs:
            out: dict[str, Ref] = {}
            for st in self.top(rel):
                if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    out[st.name] = Ref("def", rel, st, st.name)
                elif isinstance(st, ast.ClassDef):
                    out[st.name] = Ref("class", rel, st, st.name)
            self._defs[rel] = out
        return self._defs[rel]

    def assigned(self, rel: str) -> set[str]:
        if rel not in self._assigned:
            self._assigned[rel] = {n for st in self.top(rel) for n, _ in _assign_parts(st)}
        return self._assigned[rel]

    def consts(self, rel: str) -> dict[str, str]:
        """Module-level string constants: a name assigned exactly once at module level
        whose value eval_str can compute from earlier constants."""
        if rel not in self._consts:
            counts = Counter(n for st in self.top(rel) for n, _ in _assign_parts(st))
            vals: dict[str, str] = {}
            for st in self.top(rel):
                if isinstance(st, ast.AugAssign):
                    continue
                for n, v in _assign_parts(st):
                    if counts[n] == 1:
                        s = eval_str(v, vals)
                        if s is not None:
                            vals[n] = s
            self._consts[rel] = vals
        return self._consts[rel]

    def env(self, rel: str, extra: dict[str, str] | None = None) -> Env:
        return Env(self, rel, extra)

    def module_hits(self, rel: str | None, mod: str) -> list[str]:
        """Files a module name can be: relative to `rel` for a dotted-relative name, else
        any file whose path ends with the module's path."""
        dots = len(mod) - len(mod.lstrip("."))
        parts = [p for p in mod.lstrip(".").split(".") if p]
        if dots:
            if rel is None:
                return []
            base = Path(rel).parent
            for _ in range(dots - 1):
                base = base.parent
            stem = (base / Path(*parts)) if parts else base
            cands = [f"{stem}.py", f"{stem}/__init__.py"]
            return [c.removeprefix("./") for c in cands if c.removeprefix("./") in self.texts]
        tail = "/".join(parts)
        if not tail:
            return []
        key = ("", tail)
        if key not in self._hits:
            self._hits[key] = sorted(set(self._suffix.get(f"{tail}.py", []))
                                     | set(self._suffix.get(f"{tail}/__init__.py", [])))
        return self._hits[key]

    def module_file(self, rel: str | None, mod: str) -> str | None:
        hits = self.module_hits(rel, mod)
        return hits[0] if len(hits) == 1 else None

    def resolve_name(self, rel: str, name: str, depth: int = 0) -> Ref | None:
        if depth > 6 or self.tree(rel) is None:
            return None
        d = self.defs(rel).get(name)
        if d is not None:
            return d
        if name in self.assigned(rel):
            return Ref("assign", rel, name=name)
        names, stars = self.imports(rel)
        imp = names.get(name)
        if imp is not None:
            kind, mod, attr = imp
            if kind == "module":
                return Ref("module", self.module_file(rel, mod), dotted=mod)
            sub = mod + attr if not mod.strip(".") else f"{mod}.{attr}"
            hits = self.module_hits(rel, sub)
            if len(hits) == 1:
                return Ref("module", hits[0], dotted="" if sub.startswith(".") else sub)
            f = self.module_file(rel, mod)
            if f and f != rel:
                return self.resolve_name(f, attr, depth + 1)
            return None
        for mod in stars:
            f = self.module_file(rel, mod)
            if f and f != rel:
                r = self.resolve_name(f, name, depth + 1)
                if r is not None:
                    return r
        return None

    def resolve_expr(self, rel: str, node, depth: int = 0) -> Ref | None:
        """A Name or dotted Attribute, followed to what it names."""
        if depth > 8:
            return None
        if isinstance(node, ast.Name):
            return self.resolve_name(rel, node.id)
        if not isinstance(node, ast.Attribute):
            return None
        base = self.resolve_expr(rel, node.value, depth + 1)
        if base is None or base.kind != "module":
            return None
        if base.dotted:
            sub = f"{base.dotted}.{node.attr}"
            hits = self.module_hits(None, sub)
            if len(hits) == 1:
                return Ref("module", hits[0], dotted=sub)
        if base.file and base.file.endswith("__init__.py"):
            pkg = str(Path(base.file).parent)
            for c in (f"{pkg}/{node.attr}.py", f"{pkg}/{node.attr}/__init__.py"):
                c = c.removeprefix("./")
                if c in self.texts:
                    return Ref("module", c, dotted=f"{base.dotted}.{node.attr}"
                               if base.dotted else "")
        if base.file:
            return self.resolve_name(base.file, node.attr, 1)
        return None

    def assigned_values(self, rel: str, name: str) -> list:
        """Every module-level value given to `name`: `=`, `+=`, and the arguments of
        `name.append/extend/insert(...)`."""
        out = []
        for st in self.top(rel):
            for n, v in _assign_parts(st):
                if n == name:
                    out.append(v)
            if isinstance(st, ast.Expr) and isinstance(st.value, ast.Call):
                c = st.value
                if isinstance(c.func, ast.Attribute) and isinstance(c.func.value, ast.Name) \
                        and c.func.value.id == name and c.args:
                    if c.func.attr in ("append", "extend"):
                        out.append(c.args[0])
                    elif c.func.attr == "insert" and len(c.args) > 1:
                        out.append(c.args[1])
        return out


# ------------------------------------------------------------------ views and access

# Decorators that document a view or say which methods it takes, not who may call it.
_NOT_GATE = re.compile(
    r"^(?:staticmethod|classmethod|property|cached_property|extend_schema\w*|"
    r"swagger_auto_schema|require_http_methods|require_GET|require_POST|require_safe|"
    r"api_view|action|detail_route|list_route|wraps|functools\.wraps|"
    r"(?:functools\.)?(?:lru_)?cache)\b")
_ACCESS_ATTRS = ("permission_classes", "authentication_classes", "permission_required")
_ACCESS_MIXIN = re.compile(
    r"(?:Login|Permission|Auth|Staff|Superuser|Admin|Access|UserPassesTest|Owner|Group|"
    r"Role)\w*Mixin$")
_DRF_BASES = {"APIView", "GenericAPIView", "ViewSet", "GenericViewSet", "ModelViewSet",
              "ReadOnlyModelViewSet", "ViewSetMixin"}
# Methods a generic class view serves when the class itself defines none.
_CBV_VERBS = {
    "TemplateView": "GET", "ListView": "GET", "DetailView": "GET",
    "ArchiveIndexView": "GET", "YearArchiveView": "GET", "MonthArchiveView": "GET",
    "WeekArchiveView": "GET", "DayArchiveView": "GET", "TodayArchiveView": "GET",
    "DateDetailView": "GET", "RedirectView": "GET POST PUT PATCH DELETE",
    "FormView": "GET POST", "CreateView": "GET POST", "UpdateView": "GET POST",
    "DeleteView": "GET POST DELETE", "LoginView": "GET POST", "LogoutView": "GET POST",
    "PasswordChangeView": "GET POST", "PasswordResetView": "GET POST",
    "PasswordResetConfirmView": "GET POST", "PasswordChangeDoneView": "GET",
    "PasswordResetDoneView": "GET", "PasswordResetCompleteView": "GET",
    "CreateAPIView": "POST", "ListAPIView": "GET", "RetrieveAPIView": "GET",
    "DestroyAPIView": "DELETE", "UpdateAPIView": "PUT PATCH",
    "ListCreateAPIView": "GET POST", "RetrieveUpdateAPIView": "GET PUT PATCH",
    "RetrieveDestroyAPIView": "GET DELETE",
    "RetrieveUpdateDestroyAPIView": "GET PUT PATCH DELETE",
}
# DRF viewset actions: the method and whether the route is on one object (detail).
_ACTIONS = {"list": ("GET", False), "create": ("POST", False),
            "retrieve": ("GET", True), "update": ("PUT", True),
            "partial_update": ("PATCH", True), "destroy": ("DELETE", True)}
_ACTIONS_OF = {
    "ModelViewSet": "list create retrieve update partial_update destroy",
    "ReadOnlyModelViewSet": "list retrieve",
    "ListModelMixin": "list", "CreateModelMixin": "create",
    "RetrieveModelMixin": "retrieve", "UpdateModelMixin": "update partial_update",
    "DestroyModelMixin": "destroy",
}


@dataclass
class ClassInfo:
    """A class view and what its own body and its bases (as far as they resolve) say."""
    name: str
    file: str
    node: ast.ClassDef
    methods: dict = field(default_factory=dict)   # name -> (file, node, owner class)
    gates: list = field(default_factory=list)
    attrs: dict = field(default_factory=dict)     # access attr -> (file, value, owner)
    known: list = field(default_factory=list)     # base names that are not in the tree
    lookup: str = "pk"

    @property
    def is_drf(self) -> bool:
        return any(k in _DRF_BASES or k.endswith(("APIView", "ViewSet")) for k in self.known)

    @property
    def is_viewset(self) -> bool:
        return any(k.endswith("ViewSet") or k == "ViewSetMixin" for k in self.known)

    def verbs(self) -> list[str]:
        v = {m.upper() for m in self.methods if m.upper() in VERBS}
        for k in self.known:
            v |= set(_CBV_VERBS.get(k, "").split())
        return [m for m in VERBS if m in v]

    def actions(self) -> list[str]:
        a = {m for m in self.methods if m in _ACTIONS}
        for k in self.known:
            a |= set(_ACTIONS_OF.get(k, "").split())
        return [x for x in _ACTIONS if x in a]

    def own(self, method: str):
        """The method's node when this class itself defines it, else None."""
        hit = self.methods.get(method)
        return hit[1] if hit and hit[2] == self.name and hit[0] == self.file else None


class Views:
    """What a view declares about access, read from its definition and its bases."""

    def __init__(self, idx: PyIndex):
        self.idx = idx
        self._ci: dict[tuple, ClassInfo] = {}

    def gate(self, file: str, dec) -> str:
        """A decorator as a gate, or "" when it only documents or picks methods."""
        text = self.idx.source(file, dec)
        if _NOT_GATE.match(text):
            if _callee(dec) == "action" and isinstance(dec, ast.Call):
                kws = [k for k in dec.keywords
                       if k.arg in ("permission_classes", "authentication_classes")]
                if kws:
                    return "action(" + ", ".join(
                        f"{k.arg}={self.idx.source(file, k.value)}" for k in kws) + ")"
            return ""
        if text.startswith("method_decorator(") and isinstance(dec, ast.Call) and dec.args \
                and _NOT_GATE.match(self.idx.source(file, dec.args[0])):
            return ""
        return text

    def gates(self, file: str, node) -> list[str]:
        return [g for d in getattr(node, "decorator_list", []) if (g := self.gate(file, d))]

    def class_info(self, file: str, cnode: ast.ClassDef) -> ClassInfo:
        key = (file, cnode.lineno, cnode.name)
        if key in self._ci:
            return self._ci[key]
        info = ClassInfo(cnode.name, file, cnode)
        lookups: dict[str, str] = {}
        seen: set[tuple] = set()

        def visit(f: str, c: ast.ClassDef, depth: int) -> None:
            k = (f, c.lineno, c.name)
            if k in seen or depth > 8:
                return
            seen.add(k)
            via = "" if depth == 0 else f" (from {c.name})"
            info.gates.extend(g + via for g in self.gates(f, c))
            for st in c.body:
                if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    info.methods.setdefault(st.name, (f, st, c.name))
                for n, v in _assign_parts(st):
                    if n in _ACCESS_ATTRS:
                        info.attrs.setdefault(n, (f, v, c.name))
                    elif n in ("lookup_url_kwarg", "lookup_field") and \
                            isinstance(v, ast.Constant) and isinstance(v.value, str):
                        lookups.setdefault(n, v.value)
            for b in c.bases:
                name = _last_name(b)
                if _ACCESS_MIXIN.search(name):
                    info.gates.append(f"{name} (mixin{', from ' + c.name if depth else ''})")
                ref = self.idx.resolve_expr(f, b)
                if ref is not None and ref.kind == "class":
                    visit(ref.file, ref.node, depth + 1)
                elif name:
                    info.known.append(name)

        visit(file, cnode, 0)
        info.lookup = lookups.get("lookup_url_kwarg") or lookups.get("lookup_field") or "pk"
        for attr in _ACCESS_ATTRS:
            if attr in info.attrs:
                f, v, owner = info.attrs[attr]
                info.gates.append(f"{attr} = {self.idx.source(f, v)}"
                                  + ("" if owner == cnode.name else f" (from {owner})"))
        disp = info.methods.get("dispatch")
        if disp:
            info.gates.extend(f"{g} (on dispatch)" for g in self.gates(disp[0], disp[1]))
        self._ci[key] = info
        return info


def _func_methods(fnode) -> list[str]:
    """Methods a function view takes: its method decorators, else GET plus every method
    its body compares `request.method` against."""
    for d in fnode.decorator_list:
        name = _callee(d) if isinstance(d, ast.Call) else _last_name(d)
        if name in ("require_GET", "require_safe"):
            return ["GET"]
        if name == "require_POST":
            return ["POST"]
        if name in ("require_http_methods", "api_view") and isinstance(d, ast.Call):
            got = _str_list(d.args[0]) if d.args else None
            if got is None and name == "api_view":
                for k in d.keywords:
                    if k.arg == "http_method_names":
                        got = _str_list(k.value)
            if got is None and name == "api_view" and not d.args:
                return ["GET"]
            if got is not None:
                return [m for m in VERBS if m in {g.upper() for g in got}]
        if name == "api_view":
            return ["GET"]
    seen = {"GET"}
    for n in ast.walk(fnode):
        if isinstance(n, ast.Compare) and isinstance(n.left, ast.Attribute) \
                and n.left.attr == "method":
            for c in n.comparators:
                vals = [c.value] if isinstance(c, ast.Constant) else (_str_list(c) or [])
                seen |= {str(v).upper() for v in vals}
    return [m for m in VERBS if m in seen]


def _is_drf_func(fnode) -> bool:
    return any((_callee(d) if isinstance(d, ast.Call) else _last_name(d)) == "api_view"
               for d in fnode.decorator_list)


def _decorates(fnode, name: str) -> bool:
    return any((_callee(d) if isinstance(d, ast.Call) else _last_name(d)) == name
               for d in fnode.decorator_list)


# ------------------------------------------------------------------ Django settings

_LOGIN_MW = re.compile(r"LoginRequired|login_required", re.I)
_TEST_DIRS = {"test", "tests", "testing", "unittests", "fixtures", "examples", "example",
              "docs"}


def _strings(idx: PyIndex, rel: str, node, depth: int = 0) -> list[str]:
    """The string literals a settings list is built from: its own elements, `*spread`
    and `+` pieces, and a same-file name it is assigned from
    (`MIDDLEWARE = DJANGO_MIDDLEWARE_CLASSES`)."""
    if depth > 3 or node is None:
        return []
    if isinstance(node, ast.Constant):
        return [node.value] if isinstance(node.value, str) else []
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return [s for e in node.elts for s in _strings(idx, rel, e, depth)]
    if isinstance(node, ast.Starred):
        return _strings(idx, rel, node.value, depth + 1)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _strings(idx, rel, node.left, depth) + _strings(idx, rel, node.right, depth)
    if isinstance(node, ast.Name) and node.id not in ("MIDDLEWARE", "MIDDLEWARE_CLASSES"):
        return [s for v in idx.assigned_values(rel, node.id)
                for s in _strings(idx, rel, v, depth + 1)]
    return []


class Settings:
    """Project-wide declarations in Django settings modules: a login-required entry in
    MIDDLEWARE, and DRF's default permission and authentication classes. Read from every
    settings-like module outside test and docs trees, each named with its file."""

    def __init__(self, idx: PyIndex):
        self.middleware: list[tuple[str, str]] = []
        self.drf: dict[str, list[tuple[str, str]]] = {}
        for rel, text in sorted(idx.texts.items()):
            if "MIDDLEWARE" not in text and "REST_FRAMEWORK" not in text:
                continue
            if set(Path(rel).parts[:-1]) & _TEST_DIRS:
                continue
            for st in idx.top(rel):
                for n, v in _assign_parts(st):
                    if n in ("MIDDLEWARE", "MIDDLEWARE_CLASSES"):
                        for s in _strings(idx, rel, v):
                            if _LOGIN_MW.search(s) and (s, rel) not in self.middleware:
                                self.middleware.append((s, rel))
                    elif n == "REST_FRAMEWORK" and isinstance(v, ast.Dict):
                        for k, val in zip(v.keys, v.values):
                            if isinstance(k, ast.Constant) and k.value in (
                                    "DEFAULT_PERMISSION_CLASSES",
                                    "DEFAULT_AUTHENTICATION_CLASSES"):
                                self.drf.setdefault(k.value, []).append(
                                    (idx.source(rel, val), rel))
                if isinstance(st, ast.Expr) and isinstance(st.value, ast.Call):
                    c = st.value
                    if isinstance(c.func, ast.Attribute) and c.func.attr in (
                            "append", "insert") and _root_name(c.func) in (
                            "MIDDLEWARE", "MIDDLEWARE_CLASSES") and c.args:
                        last = c.args[-1]
                        if isinstance(last, ast.Constant) and isinstance(last.value, str) \
                                and _LOGIN_MW.search(last.value) \
                                and (last.value, rel) not in self.middleware:
                            self.middleware.append((last.value, rel))

    def app_guards(self, *, drf: bool, own_perm: bool, own_auth: bool) -> tuple[str, ...]:
        """The project-wide declarations that apply to one view: the MIDDLEWARE entry to
        every view, a DRF default only to a DRF view that does not set its own."""
        out = [f"{mw} (settings MIDDLEWARE in {f}, project-wide)" for mw, f in self.middleware]
        if drf:
            for key, own in (("DEFAULT_PERMISSION_CLASSES", own_perm),
                             ("DEFAULT_AUTHENTICATION_CLASSES", own_auth)):
                if not own:
                    out += [f"{key} {v} (REST_FRAMEWORK in {f}; the view sets none)"
                            for v, f in self.drf.get(key, [])]
        return tuple(dict.fromkeys(out))


# ------------------------------------------------------------------ Django URLconf

def regex_to_path(rx: str) -> str | None:
    """A Django `re_path`/`url` pattern as a literal path template, or None when it is not
    one. Named groups become <name>, unnamed groups <arg1>..., anchors and escapes go, and
    an optional piece (`/?`, `(...)?`) is left out, which is the shortest URL that
    matches. A pattern with regex syntax left after that (alternation or a class outside
    a group, a lookaround, a quantifier on a literal) is not rendered, because a probe
    would request it verbatim."""
    s = rx[1:] if rx.startswith("^") else rx
    if s.endswith("$") and not s.endswith("\\$"):
        s = s[:-1]
    elif s.endswith("\\Z"):
        s = s[:-2]
    out: list[str] = []
    i, n, k = 0, len(s), 0
    while i < n:
        c = s[i]
        if c == "\\":
            if i + 1 < n and s[i + 1] in "./-_~:@!,;=&+% #":
                out.append(s[i + 1])
                i += 2
                continue
            return None                       # \d, \w, \s ... outside a group
        if c == "(":
            j = _group_end(s, i)
            if j is None:
                return None
            inner = s[i + 1:j]
            if j + 1 < n and s[j + 1] == "?" and not inner.startswith(("?=", "?!", "?<=",
                                                                       "?<!")):
                i = j + 2                     # an optional group: left out
                continue
            if inner.startswith("?P<") and ">" in inner:
                name = inner[3:inner.index(">")]
                if not name.isidentifier():
                    return None
                piece = f"<{name}>"
            elif inner.startswith("?:"):
                piece = regex_to_path(inner[2:])
                if piece is None or "<" in piece:
                    return None
            elif inner.startswith("?"):
                return None                   # lookaround, inline flags, backreference
            else:
                k += 1
                piece = f"<arg{k}>"
            i = j + 1
            if i < n and s[i] in "*+{":
                return None
            out.append(piece)
            continue
        if c in "[]{}*+|^$)":
            return None
        if c == "?":
            if out:
                out.pop()                     # an optional literal: left out
            i += 1
            continue
        out.append(c)                         # '.' matches itself, so it stays
        i += 1
    return "".join(out)


def _group_end(s: str, i: int) -> int | None:
    depth, j, in_class = 0, i, False
    while j < len(s):
        c = s[j]
        if c == "\\":
            j += 2
            continue
        if in_class:
            if c == "]":
                in_class = False
        elif c == "[":
            in_class = True
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return j
        j += 1
    return None


_HAS_REGEX = re.compile(r"[\\^$()\[\]{}*+?|]")


class Django:
    """Routes from every URLconf in the tree. A URLconf that no other one includes is a
    root and is served from "/"; an included one is reached only through its includer,
    with the includer's pattern as its prefix, the way Django concatenates them."""

    def __init__(self, idx: PyIndex, unresolved: Unresolved):
        self.idx = idx
        self.views = Views(idx)
        self.unres = unresolved
        self.out: list[Found] = []
        self._settings: Settings | None = None
        self.included: set[str] = set()
        self.ambiguous: set[str] = set()
        self.walked: set[str] = set()
        self.emit = False

    @property
    def settings(self) -> Settings:
        if self._settings is None:
            self._settings = Settings(self.idx)
        return self._settings

    def confs(self) -> list[str]:
        return sorted(rel for rel, text in self.idx.texts.items()
                      if "urlpatterns" in text and self.idx.tree(rel) is not None
                      and "urlpatterns" in self.idx.assigned(rel))

    def run(self) -> list[Found]:
        confs = self.confs()
        if not confs:
            return []
        self.emit = False                     # pass 1: which URLconfs are included
        for rel in confs:
            self._conf(rel, "", True, frozenset())
        self.emit = True
        roots = [c for c in confs if c not in self.included]
        for rel in roots:
            self._conf(rel, "", rel not in self.ambiguous, frozenset())
        for rel in confs:                     # included only from a cycle: still read
            if rel not in self.walked:
                self._conf(rel, "", rel not in self.ambiguous, frozenset())
        return self.out

    # -- walking ---------------------------------------------------------------
    def _conf(self, rel: str, prefix: str, ok: bool, seen: frozenset) -> None:
        if self.emit:
            self.walked.add(rel)
        self._name(rel, "urlpatterns", prefix, ok, seen, "")

    def _name(self, rel, name, prefix, ok, seen, vprefix) -> None:
        key = (rel, name)
        if key in seen:
            return
        for v in self.idx.assigned_values(rel, name):
            self._walk(rel, v, prefix, ok, seen | {key}, vprefix)

    def _walk(self, rel, node, prefix, ok, seen, vprefix) -> None:
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            for e in node.elts:
                self._walk(rel, e, prefix, ok, seen, vprefix)
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            self._walk(rel, node.left, prefix, ok, seen, vprefix)
            self._walk(rel, node.right, prefix, ok, seen, vprefix)
        elif isinstance(node, ast.Starred):
            self._walk(rel, node.value, prefix, ok, seen, vprefix)
        elif isinstance(node, ast.Attribute) and node.attr == "urls":
            self._router_urls(rel, node.value, prefix, ok, seen)
        elif isinstance(node, (ast.Name, ast.Attribute)):
            ref = self.idx.resolve_expr(rel, node)
            if ref is None:
                return                        # outside the tree (admin.site.urls, ...)
            if ref.kind == "assign":
                if ref.name == "urlpatterns" and ref.file != rel:
                    self.included.add(ref.file)
                    if self.emit:
                        self.walked.add(ref.file)
                self._name(ref.file, ref.name, prefix, ok, seen, vprefix)
            elif ref.kind == "module" and ref.file:
                self._included_module(ref.file, prefix, ok, seen)
        elif isinstance(node, ast.Call):
            fn = _callee(node)
            if fn in ("path", "re_path", "url"):
                self._pattern(rel, node, fn, prefix, ok, seen, vprefix)
            elif fn == "patterns" and node.args:          # Django < 1.10
                vp = eval_str(node.args[0], self.idx.env(rel)) or ""
                for a in node.args[1:]:
                    self._walk(rel, a, prefix, ok, seen, vp)
            elif fn == "i18n_patterns":
                self.unres.add(rel, node.lineno, "i18n_patterns: the language prefix")
                for a in node.args:
                    self._walk(rel, a, prefix, False, seen, vprefix)
            elif fn == "format_suffix_patterns" and node.args:
                self._walk(rel, node.args[0], prefix, ok, seen, vprefix)
            elif fn == "include" and node.args:
                self._include(rel, node, prefix, ok, seen)

    def _included_module(self, file, prefix, ok, seen) -> None:
        if "urlpatterns" in self.idx.assigned(file):
            self.included.add(file)
            self._conf(file, prefix, ok, seen)

    def _include(self, rel, call, prefix, ok, seen) -> None:
        target = _arg(call, 0, "arg") or _arg(call, 0, "module")
        if isinstance(target, ast.Tuple) and target.elts:
            target = target.elts[0]           # include((patterns, app_name), ...)
        if isinstance(target, ast.Constant) and isinstance(target.value, str):
            hits = self.idx.module_hits(rel, target.value)
            if len(hits) == 1:
                self._included_module(hits[0], prefix, ok, seen)
            elif len(hits) > 1:
                self.unres.add(rel, call.lineno, f"include({target.value!r}) matches "
                               f"{len(hits)} files")
                self.ambiguous.update(hits)
            return                            # 0 hits: an installed app, not this tree
        if target is not None:
            self._walk(rel, target, prefix, ok, seen, "")

    def _pattern(self, rel, call, fn, prefix, ok, seen, vprefix) -> None:
        pat = _arg(call, 0, "route" if fn == "path" else "regex")
        view = _arg(call, 1, "view")
        if pat is None or view is None:
            return
        nests = (isinstance(view, ast.Call) and _callee(view) == "include") \
            or isinstance(view, ast.Tuple) \
            or (isinstance(view, ast.Attribute) and view.attr == "urls")
        raw, complete = eval_prefix(pat, self.idx.env(rel))
        piece = None
        if raw is not None:
            piece = raw if fn == "path" else regex_to_path(raw)
        if piece is None:
            what = (f"{fn}() pattern {self.idx.source(rel, pat)}" if raw is None else
                    f"{fn}() pattern {raw!r} is not a literal path")
            self.unres.add(rel, call.lineno, what)
            if not nests:
                return                        # the route's own path is unknown
            piece, ok = "", False
        elif not complete:                    # a leading piece left out, never guessed
            self.unres.add(rel, call.lineno, f"{fn}() pattern {self.idx.source(rel, pat)}: "
                           f"its leading part is not computable and is left out")
            ok = False
        full = prefix + piece
        if isinstance(view, ast.Attribute) and view.attr == "urls":
            self._walk(rel, view, full, ok, seen, "")     # router.urls, admin.site.urls
        elif isinstance(view, ast.Call) and _callee(view) == "include":
            self._include(rel, view, full, ok, seen)
        elif isinstance(view, ast.Tuple):
            if view.elts:
                self._walk(rel, view.elts[0], full, ok, seen, "")
        elif self.emit:
            self._view(rel, call, view, full, ok, vprefix)

    # -- views -----------------------------------------------------------------
    def _unwrap(self, rel, node) -> tuple[ast.AST, list[str]]:
        """The view inside its URLconf wrappers, and the wrappers as written:
        `login_required(cache_page(60)(views.x))` is views.x behind two. A call whose one
        argument is not view-like (`redirect_view("home")`) is a view factory, not a
        wrapper, and is itself the view."""
        guards: list[str] = []
        for _ in range(6):
            if isinstance(node, ast.Call) and len(node.args) == 1 and not (
                    isinstance(node.func, ast.Attribute) and node.func.attr == "as_view") \
                    and isinstance(node.args[0], (ast.Name, ast.Attribute, ast.Call,
                                                  ast.Lambda)):
                guards.append(self.idx.source(rel, node.func))
                node = node.args[0]
                continue
            break
        return node, guards

    def _view(self, rel, call, view, path, ok, vprefix, wrappers=(), depth=0) -> None:
        node, outer = self._unwrap(rel, view)
        guards = list(wrappers) + outer
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and node.func.attr == "as_view":
            amap = None
            if node.args and isinstance(node.args[0], ast.Dict):
                amap = {k.value.upper(): v.value for k, v in zip(node.args[0].keys,
                                                                  node.args[0].values)
                        if isinstance(k, ast.Constant) and isinstance(v, ast.Constant)
                        and str(k.value).upper() in VERBS}
            guards += [f"as_view({k.arg}={self.idx.source(rel, k.value)})"
                       for k in node.keywords if k.arg in _ACCESS_ATTRS]
            ref = self.idx.resolve_expr(rel, node.func.value)
            if ref is not None and ref.kind == "class":
                return self._class_view(ref.file, ref.node, path, ok, guards, amap)
            name = _last_name(node.func.value)
            verbs = (list(amap) if amap else _CBV_VERBS.get(name, "GET").split())
            return self._unresolved_view(rel, call, node, path, ok, guards, verbs)
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            dotted = f"{vprefix}.{node.value}" if vprefix else node.value
            mod, _, attr = dotted.rpartition(".")
            f = self.idx.module_file(None, mod) if mod else None
            ref = self.idx.resolve_name(f, attr) if f else None
        elif isinstance(node, (ast.Name, ast.Attribute)):
            ref = self.idx.resolve_expr(rel, node)
        else:
            ref = None
        if ref is not None and ref.kind == "assign" and depth < 3:
            vals = self.idx.assigned_values(ref.file, ref.name)
            if len(vals) == 1:                # token_view = ratelimit(...)(obtain_token)
                return self._view(ref.file, call, vals[0], path, ok, vprefix, guards,
                                  depth + 1) if ref.file == rel else \
                    self._view_elsewhere(ref.file, vals[0], call, rel, path, ok, guards)
        if ref is not None and ref.kind == "def":
            return self._func_view(ref.file, ref.node, path, ok, guards)
        if ref is not None and ref.kind == "class":
            return self._class_view(ref.file, ref.node, path, ok, guards, None)
        self._unresolved_view(rel, call, node, path, ok, guards, ["GET"])

    def _view_elsewhere(self, file, value, call, rel, path, ok, guards) -> None:
        """A view assigned in another module: its wrappers are read there."""
        node, outer = self._unwrap(file, value)
        g = list(guards) + outer
        ref = self.idx.resolve_expr(file, node) if isinstance(
            node, (ast.Name, ast.Attribute)) else None
        if ref is not None and ref.kind == "def":
            return self._func_view(ref.file, ref.node, path, ok, g)
        if ref is not None and ref.kind == "class":
            return self._class_view(ref.file, ref.node, path, ok, g, None)
        self._unresolved_view(rel, call, node, path, ok, g, ["GET"])

    def _emit(self, method, path, file, span, handler, guards, app, ok) -> None:
        full = "/" + path
        if not ok:              # a left-out piece can leave "//" behind; the rest is literal
            full = re.sub(r"/{2,}", "/", full)
        self.out.append(Found(method, full, file, span[0], span[1], handler,
                              tuple(dict.fromkeys(guards)), app, ok))

    def _unresolved_view(self, rel, call, node, path, ok, guards, verbs) -> None:
        """A view this tree does not define (an installed app's, or a lambda): the route
        is still served, so it is kept, tied to the URLconf line that declares it."""
        app = self.settings.app_guards(drf=False, own_perm=False, own_auth=False)
        for m in verbs:
            self._emit(m, path, rel, _call_span(call), self.idx.source(rel, node)[:80],
                       guards, app, ok)

    def _func_view(self, file, fnode, path, ok, guards) -> None:
        gates = guards + self.views.gates(file, fnode)
        app = self.settings.app_guards(drf=_is_drf_func(fnode),
                                       own_perm=_decorates(fnode, "permission_classes"),
                                       own_auth=_decorates(fnode, "authentication_classes"))
        for m in _func_methods(fnode):
            self._emit(m, path, file, _span(fnode), fnode.name, gates, app, ok)

    def _class_app(self, info: ClassInfo) -> tuple[str, ...]:
        return self.settings.app_guards(drf=info.is_drf,
                                        own_perm="permission_classes" in info.attrs,
                                        own_auth="authentication_classes" in info.attrs)

    def _class_view(self, file, cnode, path, ok, guards, amap) -> None:
        info = self.views.class_info(file, cnode)
        app = self._class_app(info)
        if amap:                              # ViewSet.as_view({'get': 'list'})
            pairs = [(m, amap[m]) for m in VERBS if m in amap]
        elif info.is_viewset:
            return                            # a viewset needs a router or an action map
        else:
            pairs = [(m, m.lower()) for m in (info.verbs() or ["GET"])]
        for method, meth in pairs:
            own = info.own(meth)
            span = _span(own) if own is not None else _head_span(cnode)
            handler = f"{cnode.name}.{meth}" if own is not None else cnode.name
            mine = self.views.gates(file, own) if own is not None else []
            self._emit(method, path, file, span, handler, guards + info.gates + mine,
                       app, ok)

    # -- DRF routers -----------------------------------------------------------
    def _router_urls(self, rel, obj, prefix, ok, seen) -> None:
        ref = self.idx.resolve_expr(rel, obj)
        if ref is None or ref.kind != "assign":
            return
        key = ("router", ref.file, ref.name)
        if key in seen or not self.emit:
            return
        ctor = next((v for v in self.idx.assigned_values(ref.file, ref.name)
                     if isinstance(v, ast.Call) and _callee(v).endswith("Router")), None)
        if ctor is None:
            return
        trailing = "/"
        for k in ctor.keywords:
            if k.arg == "trailing_slash" and isinstance(k.value, ast.Constant):
                trailing = k.value.value if isinstance(k.value.value, str) \
                    else ("/" if k.value.value else "")
        for f, reg in self._registrations(ref.file, ref.name, seen | {key}):
            p_node, vs = _arg(reg, 0, "prefix"), _arg(reg, 1, "viewset")
            if p_node is None or vs is None:
                continue
            p, complete = eval_prefix(p_node, self.idx.env(f))
            if p is not None and _HAS_REGEX.search(p):
                p = regex_to_path(p)
            if p is None:
                self.unres.add(f, reg.lineno,
                               f"router.register prefix {self.idx.source(f, p_node)}")
                continue
            if not complete:
                self.unres.add(f, reg.lineno, f"router.register prefix "
                               f"{self.idx.source(f, p_node)}: leading part left out")
            vref = self.idx.resolve_expr(f, vs)
            if vref is not None and vref.kind == "class":
                self._viewset(vref.file, vref.node, prefix + p, trailing, ok and complete)

    def _registrations(self, rel, name, seen) -> list[tuple[str, ast.Call]]:
        """`name.register(...)` calls at module level, `name.registry.extend(other.registry)`,
        and the ones inside a helper the router is passed to (`add_urls(router)`)."""
        out: list[tuple[str, ast.Call]] = []
        for st in self.idx.top(rel):
            calls = [st.value] if isinstance(st, ast.Expr) else \
                [v for _, v in _assign_parts(st)]
            for c in calls:
                if not isinstance(c, ast.Call):
                    continue
                f = c.func
                if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) \
                        and f.value.id == name and f.attr == "register":
                    out.append((rel, c))
                elif isinstance(f, ast.Attribute) and f.attr == "extend" and \
                        isinstance(f.value, ast.Attribute) and f.value.attr == "registry" \
                        and _root_name(f.value) == name and c.args and \
                        isinstance(c.args[0], ast.Attribute):
                    other = self.idx.resolve_expr(rel, c.args[0].value)
                    if other is not None and other.kind == "assign" and \
                            ("router", other.file, other.name) not in seen:
                        out += self._registrations(
                            other.file, other.name, seen | {("router", other.file, other.name)})
                else:
                    idxs = [i for i, a in enumerate(c.args)
                            if isinstance(a, ast.Name) and a.id == name]
                    if not idxs:
                        continue
                    fref = self.idx.resolve_expr(rel, f)
                    if fref is None or fref.kind != "def":
                        continue
                    params = [a.arg for a in fref.node.args.posonlyargs + fref.node.args.args]
                    if idxs[0] >= len(params):
                        continue
                    param = params[idxs[0]]
                    for n in ast.walk(fref.node):
                        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) \
                                and n.func.attr == "register" and \
                                isinstance(n.func.value, ast.Name) and \
                                n.func.value.id == param:
                            out.append((fref.file, n))
        return out

    def _viewset(self, file, cnode, base, trailing, ok) -> None:
        """The routes DRF's SimpleRouter/DefaultRouter generates for one registration:
        list and create on `prefix/`, the object actions on `prefix/<lookup>/`, and each
        `@action` under either."""
        info = self.views.class_info(file, cnode)
        app = self._class_app(info)
        detail = f"{base}/<{info.lookup}>"
        for action in info.actions():
            method, is_detail = _ACTIONS[action]
            own = info.own(action)
            span = _span(own) if own is not None else _head_span(cnode)
            handler = f"{cnode.name}.{action}" if own is not None else cnode.name
            mine = self.views.gates(file, own) if own is not None else []
            self._emit(method, (detail if is_detail else base) + trailing, file, span,
                       handler, info.gates + mine, app, ok)
        for mname, (mfile, mnode, owner) in info.methods.items():
            dec = next((d for d in mnode.decorator_list if isinstance(d, ast.Call)
                        and _callee(d) in ("action", "detail_route", "list_route")), None)
            if dec is None:
                continue
            kw = {k.arg: k.value for k in dec.keywords}
            if _callee(dec) == "action":
                d = kw.get("detail")
                is_detail = bool(d.value) if isinstance(d, ast.Constant) else False
            else:
                is_detail = _callee(dec) == "detail_route"
            url_path = eval_str(kw["url_path"], self.idx.env(mfile)) \
                if "url_path" in kw else mname
            if url_path is None:
                self.unres.add(mfile, dec.lineno, "@action url_path "
                               + self.idx.source(mfile, kw["url_path"]))
                continue
            methods = _str_list(kw["methods"]) if "methods" in kw else ["get"]
            here = mfile == file and owner == cnode.name
            span = _span(mnode) if here else _head_span(cnode)
            gates = info.gates + self.views.gates(mfile, mnode)
            for m in [x for x in VERBS if x in {s.upper() for s in methods or []}]:
                self._emit(m, f"{detail if is_detail else base}/{url_path}{trailing}",
                           file if not here else mfile, span,
                           f"{cnode.name}.{mname}", gates, app, ok)


# ------------------------------------------------------------------ Starlette

_APPS = ("Starlette", "Router", "FastAPI")


class Starlette:
    """Routes from Starlette `Route` lists, with the paths of every `Mount` that encloses
    them, lexically or by name (`Mount("/api", routes=api.routes)`), and a sub-application
    mounted with `app.mount("/v1", sub)`. Starlette joins a Mount's path (trailing slash
    dropped) and its routes' paths as they are written."""

    def __init__(self, idx: PyIndex, unresolved: Unresolved):
        self.idx = idx
        self.views = Views(idx)
        self.unres = unresolved
        # (file, name) -> [(from file, from container, prefix, ok, middleware)]
        self.edges: dict[tuple[str, str], list[tuple]] = {}

    def _from_starlette(self, rel: str, call, name: str) -> bool:
        if not isinstance(call, ast.Call) or _callee(call) != name:
            return False
        base = _root_name(call.func) if isinstance(call.func, ast.Attribute) else \
            (call.func.id if isinstance(call.func, ast.Name) else "")
        imp = self.idx.imports(rel)[0].get(base)
        return bool(imp) and "starlette" in imp[1]

    def _mws(self, rel, call) -> list[str]:
        mw = _arg(call, 99, "middleware")
        if not isinstance(mw, (ast.List, ast.Tuple)):
            return []
        out = []
        for e in mw.elts:
            if isinstance(e, ast.Call) and _callee(e) == "Middleware" and e.args:
                out.append(f"{self.idx.source(rel, e.args[0])} (middleware)")
            else:
                out.append(f"{self.idx.source(rel, e)} (middleware)")
        return out

    def _path(self, rel, node) -> tuple[str, bool]:
        if node is None:
            return "", True
        p, complete = eval_prefix(node, self.idx.env(rel))
        if p is None or not complete:
            self.unres.add(rel, node.lineno, "Mount path " + self.idx.source(rel, node))
            return p or "", False
        return p, True

    def _lexical(self, rel, node, parents, tops):
        """(container name, prefix, ok, middleware) from the Mounts and apps around
        `node`, up to the module-level statement that holds it."""
        cur, prefix, ok, mws = node, "", True, []
        while True:
            par = parents.get(cur)
            if par is None:
                return None, prefix, ok, mws
            if isinstance(par, ast.Call) and self._from_starlette(rel, par, "Mount") \
                    and cur is not _arg(par, 0, "path"):
                p, pok = self._path(rel, _arg(par, 0, "path"))
                prefix, ok = p.rstrip("/") + prefix, ok and pok
                mws = self._mws(rel, par) + mws
            elif isinstance(par, ast.Call) and _callee(par) in _APPS:
                mws = self._mws(rel, par) + mws
            if id(par) in tops:
                return _container(par), prefix, ok, mws
            cur = par

    def run(self) -> list[Found]:
        routes = []
        for rel, text in sorted(self.idx.texts.items()):
            if "starlette" not in text and "fastapi" not in text.lower():
                continue
            t = self.idx.tree(rel)
            if t is None:
                continue
            parents = {c: p for p in ast.walk(t) for c in ast.iter_child_nodes(p)}
            tops = {id(st) for st in self.idx.top(rel)}
            for node in ast.walk(t):
                if not isinstance(node, ast.Call):
                    continue
                if self._from_starlette(rel, node, "Route"):
                    routes.append((rel, node, parents, tops))
                elif self._from_starlette(rel, node, "Mount"):
                    target = _arg(node, 1, "app") or _arg(node, 99, "routes")
                    if isinstance(target, (ast.Name, ast.Attribute)):
                        cont, lp, ok, mws = self._lexical(rel, node, parents, tops)
                        p, pok = self._path(rel, _arg(node, 0, "path"))
                        self._edge(rel, target, cont, lp + p.rstrip("/"), ok and pok,
                                   mws + self._mws(rel, node))
                elif _callee(node) in _APPS and isinstance(
                        _arg(node, 99, "routes"), (ast.Name, ast.Attribute)):
                    cont, lp, ok, mws = self._lexical(rel, node, parents, tops)
                    self._edge(rel, _arg(node, 99, "routes"), cont, lp, ok,
                               mws + self._mws(rel, node))
                elif isinstance(node.func, ast.Attribute) and node.func.attr == "mount" \
                        and isinstance(node.func.value, ast.Name) and len(node.args) >= 2 \
                        and isinstance(node.args[1], (ast.Name, ast.Attribute)):
                    p, pok = self._path(rel, node.args[0])
                    self._edge(rel, node.args[1], node.func.value.id, p.rstrip("/"), pok, [])
        out: list[Found] = []
        for rel, call, parents, tops in routes:
            out += self._route(rel, call, parents, tops)
        return out

    def _edge(self, rel, target, cont, prefix, ok, mws) -> None:
        ref = self.idx.resolve_expr(rel, target)
        if ref is not None and ref.kind == "assign":
            self.edges.setdefault((ref.file, ref.name), []).append(
                (rel, cont, prefix, ok, tuple(mws)))

    def prefixes(self, rel, name, seen=frozenset()) -> list[tuple[str, bool, tuple]]:
        key = (rel, name)
        edges = self.edges.get(key, []) if name else []
        if not edges or key in seen:
            return [("", True, ())]
        out = []
        for frm, cont, p, ok, mws in edges:
            for op, ook, omws in self.prefixes(frm, cont, seen | {key}):
                out.append((op + p, ok and ook, omws + mws))
        return out

    def _route(self, rel, call, parents, tops) -> list[Found]:
        cont, lp, ok, mws = self._lexical(rel, call, parents, tops)
        pnode = _arg(call, 0, "path")
        p, complete = eval_prefix(pnode, self.idx.env(rel)) if pnode is not None \
            else (None, False)
        if p is None or not complete:
            if pnode is not None:
                self.unres.add(rel, call.lineno, "Route path " + self.idx.source(rel, pnode))
            if p is None:
                return []
            ok = False
        ep = _arg(call, 1, "endpoint")
        declared = _str_list(_arg(call, 99, "methods")) if _arg(call, 99, "methods") else None
        ref = self.idx.resolve_expr(rel, ep) if isinstance(ep, (ast.Name, ast.Attribute)) \
            else None
        own_mw = self._mws(rel, call)
        per: list[tuple[str, str, tuple[int, int], str, list[str]]] = []
        if ref is not None and ref.kind == "def":
            verbs = [m for m in VERBS if m in {d.upper() for d in declared or ["GET"]}]
            per = [(m, ref.file, _span(ref.node), ref.node.name,
                    self.views.gates(ref.file, ref.node)) for m in verbs]
        elif ref is not None and ref.kind == "class":
            info = self.views.class_info(ref.file, ref.node)
            verbs = info.verbs() or ["GET"]
            if declared:
                verbs = [m for m in verbs if m in {d.upper() for d in declared}]
            for m in verbs:
                own = info.own(m.lower())
                per.append((m, ref.file, _span(own) if own is not None else _head_span(ref.node),
                            f"{ref.node.name}.{m.lower()}" if own is not None
                            else ref.node.name,
                            info.gates + (self.views.gates(ref.file, own)
                                          if own is not None else [])))
        else:
            verbs = [m for m in VERBS if m in {d.upper() for d in declared or ["GET"]}]
            label = self.idx.source(rel, ep)[:80] if ep is not None else "<endpoint>"
            per = [(m, rel, _call_span(call), label, []) for m in verbs]
        out = []
        for op, ook, omws in self.prefixes(rel, cont):
            full = op + lp + p
            for m, file, span, handler, gates in per:
                out.append(Found(m, full, file, span[0], span[1], handler,
                                 tuple(dict.fromkeys(gates + own_mw)),
                                 tuple(dict.fromkeys(list(omws) + mws)), ok and ook))
        return out


def _container(stmt) -> str | None:
    """The module-level name a statement builds: `routes = [...]`, `routes += [...]`,
    `routes.append(Route(...))`."""
    for n, _ in _assign_parts(stmt):
        return n
    if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
        f = stmt.value.func
        if isinstance(f, ast.Attribute) and f.attr in ("append", "extend", "insert") \
                and isinstance(f.value, ast.Name):
            return f.value.id
    return None
