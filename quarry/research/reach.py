"""How near a finding's file sits to a route: the order of the Layer 2 review list.

Decision N (IMPROVEMENT-PLAN). A refuter that argues the attacker cannot reach the
claimed code quotes no guard, so decision F counts it as "not rebutted" and the claim
goes to a human. On VulnLookup on 2026-11-07, 127 of 429 kept findings carried such an
argument. Killing on reach was rejected: for an aggregator the code that parses
third-party feeds is attack surface no route touches, and one such refutation trusted a
provider's own index listing. Reach orders the list instead, and kills nothing:

    route     the file declares a route (`dynamic.routes`, the probes' route map)
    imported  a file that declares a route imports it, directly or through others
    none      neither, by this approximation

The import graph is approximate on purpose. Python imports are resolved by module path
(an exact match from the repository root, else a unique suffix, since a service's code
is often imported from below the root); JavaScript and TypeScript only by relative
specifier. Dynamic imports, plugin registries and stored data a route writes and a
worker reads are invisible to it. That is why it ranks and never kills.
"""
from __future__ import annotations

import ast
import re
import sqlite3
from collections import defaultdict
from pathlib import Path

ROUTE, IMPORTED, NONE = "route", "imported", "none"

#: Sort key for `research_findings rf`; NULL (not classified) sorts with `none`.
RANK_SQL = "CASE rf.reach WHEN 'route' THEN 0 WHEN 'imported' THEN 1 ELSE 2 END"

_LABELS = {ROUTE: "declares a route",
           IMPORTED: "imported by code that declares a route",
           NONE: "no route found (approximate import graph)"}


def label(reach: str | None) -> str:
    """What a reader is told about a finding's reach."""
    return _LABELS.get(reach or "", "not ranked yet")

_PY = {".py"}
_JS = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}
_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "site-packages", "__pycache__"}
_MAX_BYTES = 2_000_000          # a vendored or minified file this size routes nothing
_JS_SPEC = re.compile(
    r"""(?:require\s*\(\s*|import\s*\(\s*|\bfrom\s+|\bimport\s+)['"](\.{1,2}/[^'"]+)['"]""")
_JS_EXT = ("", ".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx",
           "/index.js", "/index.ts", "/index.mjs", "/index.jsx", "/index.tsx")


def _files(src: Path) -> dict[str, Path]:
    out: dict[str, Path] = {}
    for p in src.rglob("*"):
        if p.suffix not in _PY | _JS or p.is_symlink() or not p.is_file():
            continue
        rel = p.relative_to(src)
        if _SKIP_DIRS & set(rel.parts[:-1]):
            continue
        try:
            if p.stat().st_size > _MAX_BYTES:
                continue
        except OSError:
            continue
        out[rel.as_posix()] = p
    return out


def _py_modules(files: dict[str, Path]) -> tuple[dict[str, str], dict[str, set[str]]]:
    """Dotted name from the root to file, and every dotted suffix to the files ending so."""
    exact: dict[str, str] = {}
    suffix: dict[str, set[str]] = defaultdict(set)
    for rel in files:
        if not rel.endswith(".py"):
            continue
        parts = rel[:-3].split("/")
        if parts[-1] == "__init__":
            parts = parts[:-1]
        if not parts:
            continue
        exact[".".join(parts)] = rel
        for i in range(len(parts)):
            suffix[".".join(parts[i:])].add(rel)
    return exact, suffix


def _py_imports(rel: str, path: Path, exact: dict[str, str],
                suffix: dict[str, set[str]]) -> set[str]:
    try:
        tree = ast.parse(path.read_text(errors="replace"))
    except (SyntaxError, ValueError, OSError, RecursionError):
        return set()
    pkg = rel.rsplit("/", 1)[0].split("/") if "/" in rel else []
    names: list[str] = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            names += [a.name for a in n.names]
        elif isinstance(n, ast.ImportFrom):
            base = n.module or ""
            if n.level:
                up = pkg[:len(pkg) - (n.level - 1)] if n.level - 1 <= len(pkg) else []
                base = ".".join(up + ([base] if base else []))
            if base:
                names.append(base)
            names += [f"{base}.{a.name}" if base else a.name for a in n.names]
    out: set[str] = set()
    for name in names:
        if name in exact:
            out.add(exact[name])
        elif len(suffix.get(name, ())) == 1:
            out |= suffix[name]
    out.discard(rel)
    return out


def _js_imports(rel: str, path: Path, files: dict[str, Path]) -> set[str]:
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return set()
    here = Path(rel).parent
    out: set[str] = set()
    for spec in _JS_SPEC.findall(text):
        base = (here / spec).as_posix()
        parts: list[str] = []
        for seg in base.split("/"):         # normalise ./ and ../ without touching disk
            if seg == "..":
                if parts:
                    parts.pop()
            elif seg not in ("", "."):
                parts.append(seg)
        target = "/".join(parts)
        for ext in _JS_EXT:
            if target + ext in files:
                out.add(target + ext)
                break
    out.discard(rel)
    return out


def import_graph(src: Path) -> dict[str, set[str]]:
    """File to the repository files it imports, by the approximation above."""
    files = _files(src)
    exact, suffix = _py_modules(files)
    graph: dict[str, set[str]] = {}
    for rel, p in files.items():
        graph[rel] = (_py_imports(rel, p, exact, suffix) if rel.endswith(".py")
                      else _js_imports(rel, p, files))
    return graph


def classify(src: Path, route_files: set[str] | None = None) -> dict[str, str]:
    """Every file that declares a route, or that one imports, mapped to its reach.
    A file absent from the result is `none`."""
    if route_files is None:
        from ..dynamic.routes import build_route_map
        route_files = set(build_route_map(src).by_file)
    graph = import_graph(src)
    out = {f: ROUTE for f in route_files}
    frontier = list(route_files)
    while frontier:
        for g in graph.get(frontier.pop(), ()):
            if g not in out:
                out[g] = IMPORTED
                frontier.append(g)
    return out


def fill(con: sqlite3.Connection, rid: int, reach_map: dict[str, str]) -> int:
    """Set reach on this research run's findings that have none yet. Returns how many."""
    rows = con.execute("SELECT id, file FROM research_findings "
                       "WHERE research_id=? AND reach IS NULL", (rid,)).fetchall()
    for r in rows:
        con.execute("UPDATE research_findings SET reach=? WHERE id=?",
                    (reach_map.get(r["file"] or "", NONE), r["id"]))
    return len(rows)
