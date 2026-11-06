"""JavaScript and TypeScript pieces of static route discovery: same-file string constants
for mount prefixes (Express `app.use(API_PREFIX, router)`), and NestJS controllers.

NestJS declares a route with decorators: `@Controller('cats')` on the class, `@Get(':id')`
on a method, and access with `@UseGuards(...)`, `@Roles(...)` and the like on either.
`app.setGlobalPrefix('api')` adds a prefix to every route, and `useGlobalGuards` or an
`APP_GUARD` provider adds a guard to every route. All of it is read from the text, never
run: comments and string contents are blanked to find the structure, and values are read
from the original text at the same offsets.

A prefix is a string literal, a module-level `const` string of the same file, or a
template literal or `+` concatenation of those. Anything else adds nothing to the path,
the route carries `prefix_resolved=False`, and the expression is recorded as unresolved.
"""
from __future__ import annotations

import re

from .routes_py import Found, Unresolved

_IDENT = r"[A-Za-z_$][\w$]*"


def blank_code(text: str, *, strings: bool = True) -> str:
    """The text with comments, and (when `strings`) the contents of string and template
    literals, replaced by spaces. Quotes and newlines stay, so offsets and line numbers
    still match the original."""
    out = list(text)
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c in "\"'`":
            j = i + 1
            while j < n and text[j] != c:
                j += 2 if text[j] == "\\" else 1
            if strings:
                for k in range(i + 1, min(j, n)):
                    if out[k] != "\n":
                        out[k] = " "
            i = j + 1
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


def _match_forward(code: str, i: int) -> int:
    """Index of the bracket that closes the one at `i`, in blanked code; len(code) when
    it never closes."""
    pairs = {"(": ")", "[": "]", "{": "}"}
    stack = []
    for j in range(i, len(code)):
        c = code[j]
        if c in pairs:
            stack.append(pairs[c])
        elif c in ")]}":
            if not stack or stack.pop() != c:
                return len(code)
            if not stack:
                return j
    return len(code)


def _match_backward(code: str, j: int) -> int | None:
    pairs = {")": "(", "]": "[", "}": "{"}
    stack = []
    for i in range(j, -1, -1):
        c = code[i]
        if c in pairs:
            stack.append(pairs[c])
        elif c in "([{":
            if not stack or stack.pop() != c:
                return None
            if not stack:
                return i
    return None


def _split_top(code: str, text: str, start: int, end: int, sep: str = ",") -> list[str]:
    """Top-level pieces of text[start:end], split on `sep`, using the blanked `code` for
    structure."""
    out, depth, last = [], 0, start
    for i in range(start, end):
        c = code[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == sep and depth == 0:
            out.append(text[last:i])
            last = i + 1
    out.append(text[last:end])
    return [p.strip() for p in out if p.strip()]


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


# ------------------------------------------------------------------ constants

_CONST = re.compile(rf"^(?:export\s+)?(?:const|let|var)\s+({_IDENT})\s*(?::\s*string\s*)?="
                    r"\s*(.+?)\s*;?\s*$", re.M)


def js_consts(text: str) -> dict[str, str]:
    """Module-level string constants: `const NAME = ...` at the start of a line, declared
    once, whose value js_eval can compute from earlier ones."""
    clean = blank_code(text, strings=False)
    found = [(m[1], m[2]) for m in _CONST.finditer(clean)]
    counts: dict[str, int] = {}
    for name, _ in found:
        counts[name] = counts.get(name, 0) + 1
    vals: dict[str, str] = {}
    for name, expr in found:
        if counts[name] == 1:
            v = js_eval(expr, vals)
            if v is not None:
                vals[name] = v
    return vals


def _unquote(s: str) -> str | None:
    q = s[0]
    body = s[1:-1]
    out, i = [], 0
    while i < len(body):
        c = body[i]
        if c == "\\" and i + 1 < len(body):
            out.append(body[i + 1])
            i += 2
            continue
        if c == q:
            return None                       # two literals, not one
        out.append(c)
        i += 1
    return "".join(out)


def js_parts(expr: str, consts: dict[str, str]) -> list[str | None] | None:
    """The pieces of a JS string expression, each a known string or None where it cannot
    be computed (a member expression, a call, an unknown name): literals, constants,
    template literals and `+`. None when the text is not one expression."""
    expr = expr.strip()
    while expr.startswith("(") and expr.endswith(")"):
        expr = expr[1:-1].strip()
    if not expr:
        return None
    code = blank_code(expr)
    pieces = _split_top(code, expr, 0, len(expr), "+")
    if not pieces:
        return None
    out: list[str | None] = []
    for p in pieces:
        if len(p) >= 2 and p[0] in "\"'" and p[-1] == p[0]:
            v = _unquote(p)
            if v is None:
                return None
            out.append(v)
        elif len(p) >= 2 and p[0] == "`" and p[-1] == "`":
            out += _template(p[1:-1], consts)
        elif re.fullmatch(_IDENT, p):
            out.append(consts.get(p))
        else:
            out.append(None)
    return out


def js_eval(expr: str, consts: dict[str, str]) -> str | None:
    """The string, when every piece of it is known."""
    parts = js_parts(expr, consts)
    if parts is None or any(p is None for p in parts):
        return None
    return "".join(parts)


def js_eval_prefix(expr: str, consts: dict[str, str]) -> tuple[str | None, bool]:
    """(value, complete), by the rule routes_py.eval_prefix states: unknown pieces may
    only lead the expression, and are then left out of the value, never filled in."""
    parts = js_parts(expr, consts)
    if parts is None:
        return None, False
    if all(p is not None for p in parts):
        return "".join(parts), True
    last = max(i for i, p in enumerate(parts) if p is None)
    head, tail = parts[:last], "".join(parts[last + 1:])
    if any(p not in (None, "") for p in head) or not tail.strip("/"):
        return None, False
    return tail, False


def _template(body: str, consts: dict[str, str]) -> list[str | None]:
    out: list[str | None] = []
    buf: list[str] = []
    i = 0
    while i < len(body):
        if body.startswith("${", i):
            j = body.find("}", i)
            if j < 0:
                return [None]
            out.append("".join(buf))
            buf = []
            out.append(consts.get(body[i + 2:j].strip()))
            i = j + 1
            continue
        if body[i] == "\\" and i + 1 < len(body):
            buf.append(body[i + 1])
            i += 2
            continue
        buf.append(body[i])
        i += 1
    out.append("".join(buf))
    return out


def looks_like_path_expr(expr: str) -> bool:
    """Whether an `app.use` first argument that did not resolve is a path at all: a
    template literal or a concatenation is a string, and an UPPER_CASE name is a constant
    by convention. A camelCase name is middleware (`app.use(auth, router)`), which mounts
    the router at "/" and is not an unresolved prefix."""
    e = expr.strip()
    return e.startswith("`") or "+" in blank_code(e) or bool(re.fullmatch(r"[A-Z][A-Z0-9_]*", e))


# ------------------------------------------------------------------ NestJS

_VERB_DECOR = {"Get": "GET", "Post": "POST", "Put": "PUT", "Patch": "PATCH",
               "Delete": "DELETE"}
# Decorators that document an operation or shape its response, not who may call it.
# Swagger's auth decorators (ApiBearerAuth, ApiSecurity, ...) state intent and are kept.
_NEST_DOC = re.compile(
    r"^(?:Api(?!BearerAuth|Security|BasicAuth|OAuth2|Cookie)\w*|HttpCode|Header|Render|"
    r"Redirect|Version|Controller|All|Head|Options|Get|Post|Put|Patch|Delete|Sse)\b")
_CLASS = re.compile(rf"\b(?:export\s+)?(?:default\s+)?(?:abstract\s+)?class\s+({_IDENT})")
_DECOR = re.compile(rf"@({_IDENT}(?:\.{_IDENT})*)\s*")
_MEMBER = re.compile(
    rf"(?:(?:public|private|protected|static|async|readonly|override)\s+)*({_IDENT})\s*"
    r"(?:<[^>(){}]*>)?\s*\(")
_QUERY = re.compile(r"@Query\s*\(\s*['\"](\w+)['\"]")


def _join(*parts: str) -> str:
    segs = [p.strip("/") for p in parts if p and p.strip("/")]
    return "/" + "/".join(segs) if segs else "/"


def _short(s: str, limit: int = 120) -> str:
    s = " ".join(s.split())
    return s if len(s) <= limit else s[:limit - 3] + "..."


class _Decorator:
    def __init__(self, text: str, code: str, start: int, end: int, name: str,
                 args: tuple[int, int] | None):
        self.start, self.end, self.name, self.args = start, end, name, args
        self.text = _short(text[start + 1:end])

    def arg_text(self, text: str) -> str:
        return text[self.args[0]:self.args[1]] if self.args else ""


def _decorator_at(text: str, code: str, i: int) -> _Decorator | None:
    m = _DECOR.match(code, i)
    if not m:
        return None
    end = m.end()
    args = None
    if end < len(code) and code[end] == "(":
        close = _match_forward(code, end)
        args = (end + 1, close)
        end = close + 1
    return _Decorator(text, code, i, end, m[1], args)


def _decorators_before(text: str, code: str, pos: int) -> list[_Decorator]:
    """The run of decorators that ends just before `pos` (a class keyword)."""
    out: list[_Decorator] = []
    i = pos
    while True:
        j = i - 1
        while j >= 0 and code[j].isspace():
            j -= 1
        if j < 0:
            break
        if code[j] == ")":
            k = _match_backward(code, j)
            if k is None:
                break
            s = k - 1
            while s >= 0 and code[s].isspace():
                s -= 1
            e = s + 1
            while s >= 0 and (code[s].isalnum() or code[s] in "_$."):
                s -= 1
            if s < 0 or code[s] != "@" or e == s + 1:
                break
            d = _decorator_at(text, code, s)
            if d is None:
                break
            out.insert(0, d)
            i = s
            continue
        e = j + 1
        s = j
        while s >= 0 and (code[s].isalnum() or code[s] in "_$."):
            s -= 1
        if s < 0 or code[s] != "@" or e == s + 1:
            break
        d = _decorator_at(text, code, s)
        if d is None:
            break
        out.insert(0, d)
        i = s
    return out


def _members(text: str, code: str, open_brace: int, close: int):
    """(decorators, method name, params (start, end), member start, member end) for each
    method in a class body, scanning only the body's own level."""
    i = open_brace + 1
    run: list[_Decorator] = []
    while i < close:
        while i < close and code[i].isspace():
            i += 1
        if i >= close:
            break
        c = code[i]
        if c == "@":
            d = _decorator_at(text, code, i)
            if d is None:
                i += 1
                continue
            run.append(d)
            i = d.end
            continue
        if c == ";":
            run = []
            i += 1
            continue
        m = _MEMBER.match(code, i)
        if m:
            p_open = m.end() - 1
            p_close = _match_forward(code, p_open)
            j = p_close + 1
            depth = 0
            while j < close:                  # the body's brace, past a return type
                cj = code[j]
                if cj in "(<[":
                    depth += 1
                elif cj in ")>]":
                    depth -= 1
                elif cj == "{" and depth <= 0:
                    break
                elif cj == ";" and depth <= 0:
                    break
                j += 1
            if j < close and code[j] == "{":
                body_end = _match_forward(code, j)
                yield run, m[1], (p_open + 1, p_close), (run[0].start if run else i), body_end
                i = body_end + 1
            else:
                i = j + 1
            run = []
            continue
        # a property or anything else: skip to the end of the statement at this level
        j = i
        while j < close:
            cj = code[j]
            if cj in "([{":
                j = _match_forward(code, j) + 1
                continue
            if cj in ";\n":
                break
            j += 1
        i = j + 1
        run = []


def _paths(text: str, d: _Decorator | None, consts: dict[str, str], unres: Unresolved,
           rel: str, *, obj_key: str = "") -> list[tuple[str, bool]]:
    """The paths a `@Controller(...)` or `@Get(...)` argument names: none, a string, an
    array, an object's `path:` (controllers), or a constant."""
    if d is None or not d.args:
        return [("", True)]
    raw = d.arg_text(text).strip()
    if not raw:
        return [("", True)]
    code = blank_code(raw)
    if raw.startswith("{") and obj_key:       # @Controller({ path: 'cats', host: ... })
        inner_end = len(raw) - 1 if raw.endswith("}") else len(raw)
        val = None
        for prop in _split_top(code, raw, 1, inner_end):
            m = re.match(rf"{obj_key}\s*:\s*(.*)$", prop, re.S)
            if m:
                val = m[1].strip()
                break
        if not val:
            return [("", True)]
        raw, code = val, blank_code(val)
    if raw.startswith("[") and raw.endswith("]"):
        items = _split_top(code, raw, 1, len(raw) - 1)
    else:
        items = [_split_top(code, raw, 0, len(raw))[0]] if raw else []
    out = []
    for it in items:
        v, complete = js_eval_prefix(it, consts)
        if not complete:
            unres.add(rel, _line_of(text, d.start), f"@{d.name}({_short(it, 80)})")
        out.append((v or "", complete))
    return out or [("", True)]


class Nest:
    """Routes from NestJS controllers across the tree, with the global prefix and global
    guards applied."""

    def __init__(self, texts: dict[str, str], unresolved: Unresolved):
        self.texts = {k: v for k, v in texts.items()
                      if k.endswith((".ts", ".js", ".mjs", ".cjs"))}
        self.unres = unresolved

    def _globals(self) -> tuple[list[tuple[str, bool]], set[str], list[str]]:
        prefixes: list[tuple[str, bool]] = []
        excluded: set[str] = set()
        guards: list[str] = []
        for rel, text in sorted(self.texts.items()):
            if "setGlobalPrefix" not in text and "useGlobalGuards" not in text \
                    and "APP_GUARD" not in text:
                continue
            code = blank_code(text)
            consts = js_consts(text)
            for m in re.finditer(r"\.setGlobalPrefix\s*\(", code):
                close = _match_forward(code, m.end() - 1)
                args = _split_top(code, text, m.end(), close)
                if not args:
                    continue
                v, complete = js_eval_prefix(args[0], consts)
                if not complete:
                    self.unres.add(rel, _line_of(text, m.start()),
                                   f"setGlobalPrefix({_short(args[0], 80)})")
                prefixes.append((v or "", complete))
                if len(args) > 1:
                    for s in re.findall(r"['\"]([^'\"]+)['\"]", args[1]):
                        excluded.add(_join(s))
            for m in re.finditer(r"\buseGlobalGuards\s*\(", code):
                close = _match_forward(code, m.end() - 1)
                for a in _split_top(code, text, m.end(), close):
                    name = re.match(rf"(?:new\s+)?({_IDENT}(?:\.{_IDENT})*)", a)
                    if name:
                        guards.append(f"{name[1]} (global guard, {rel})")
            for m in re.finditer(rf"provide\s*:\s*APP_GUARD\s*,\s*use(?:Class|Existing)\s*:"
                                 rf"\s*({_IDENT})", code):
                guards.append(f"{m[1]} (global guard, {rel})")
        return prefixes, excluded, list(dict.fromkeys(guards))

    def run(self) -> list[Found]:
        files = [(rel, text) for rel, text in sorted(self.texts.items())
                 if "@Controller" in text and "@nestjs/" in text]
        if not files:
            return []
        prefixes, excluded, guards = self._globals()
        distinct = {p for p, ok in prefixes if ok}
        unresolved_global = any(not ok for _, ok in prefixes) or len(distinct) > 1
        if len(distinct) > 1:
            self.unres.add("(project)", 0, "setGlobalPrefix is called with "
                           f"{len(distinct)} different values")
        gprefix = "" if unresolved_global else next(iter(distinct), "")
        out: list[Found] = []
        for rel, text in files:
            out += self._file(rel, text, gprefix, not unresolved_global, excluded,
                              tuple(guards))
        return out

    def _file(self, rel, text, gprefix, gok, excluded, app_guards) -> list[Found]:
        code = blank_code(text)
        consts = js_consts(text)
        out: list[Found] = []
        for cm in _CLASS.finditer(code):
            decs = _decorators_before(text, code, cm.start())
            ctrl = next((d for d in decs if d.name == "Controller"), None)
            if ctrl is None:
                continue
            open_brace = code.find("{", cm.end())
            if open_brace < 0:
                continue
            close = _match_forward(code, open_brace)
            cls_gates = [d.text for d in decs if not _NEST_DOC.match(d.name)]
            cprefixes = _paths(text, ctrl, consts, self.unres, rel, obj_key="path")
            for run, name, params, start, end in _members(text, code, open_brace, close):
                verbs = [(d, _VERB_DECOR[d.name]) for d in run if d.name in _VERB_DECOR]
                if not verbs:
                    continue
                gates = cls_gates + [d.text for d in run if not _NEST_DOC.match(d.name)]
                query = tuple(dict.fromkeys(_QUERY.findall(text[params[0]:params[1]])))
                span = (_line_of(text, start), _line_of(text, end))
                for d, method in verbs:
                    for mp, mok in _paths(text, d, consts, self.unres, rel):
                        for cp, cok in cprefixes:
                            local = _join(cp, mp)
                            full = local if local in excluded else _join(gprefix, local)
                            out.append(Found(method, full, rel, span[0], span[1],
                                             f"{cm[1]}.{name}", tuple(dict.fromkeys(gates)),
                                             app_guards, gok and cok and mok, query))
        return out
