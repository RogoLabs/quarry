"""The package names a clone's own manifests declare, for the prior-advisory lookup.

The OSV name match used the repository name, which is often not what a project publishes
under (IMPROVEMENT-PLAN item 19). This reads the name each manifest declares, nearest the
finding's file first and then up to the clone root, so a monorepo's package that holds
the flagged file comes before the workspace root:

  * package.json `name`, npm. A package marked `"private": true` is never published, so
    an npm advisory under that name is about another project; it is listed, not searched.
  * pyproject.toml `[project].name`, else `[tool.poetry].name`; setup.cfg `[metadata]
    name`; setup.py's literal `name=` inside `setup(`, read as text and never run. PyPI.
  * go.mod `module`, Go.
  * Cargo.toml `[package].name`, crates.io. A workspace-only Cargo.toml has none.

Every file is target-controlled. Each is read only if it is a regular file inside the
clone, under a size cap, and a name is kept only if it is shaped like a name in its
registry. Nothing here touches the network.
"""
from __future__ import annotations

import configparser
import json
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

_CAP = 1024 * 1024

# What a published name can look like, per OSV ecosystem. Anything else is dropped.
_SHAPE = {
    "npm": re.compile(r"(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*", re.I),
    "PyPI": re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?"),
    "Go": re.compile(r"[A-Za-z0-9][A-Za-z0-9._~/+-]*"),
    "crates.io": re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]*"),
}
_MAX_NAME = 214
_SETUP_CALL = re.compile(r"\bsetup\s*\(")
_SETUP_NAME = re.compile(r"\bname\s*=\s*([\"'])([^\"'\n]{1,214})\1")
_GO_MODULE = re.compile(r"^\s*module\s+\"?([^\s\"]+)\"?\s*$", re.M)

MANIFESTS = ("package.json", "pyproject.toml", "setup.cfg", "setup.py", "go.mod",
             "Cargo.toml")


@dataclass(frozen=True)
class PackageName:
    ecosystem: str               # OSV ecosystem name
    name: str
    source: str                  # the manifest, relative to the clone
    skip: str = ""               # why it is not searched by name, "" when it is


def _read(src: Path, p: Path) -> str | None:
    try:
        if p.is_symlink() or not p.is_file() or p.stat().st_size > _CAP:
            return None
        if not p.resolve().is_relative_to(src.resolve()):
            return None
        return p.read_text(errors="replace")
    except OSError:
        return None


def _shaped(eco: str, name) -> str | None:
    if not isinstance(name, str):
        return None
    name = name.strip()
    if not name or len(name) > _MAX_NAME or not _SHAPE[eco].fullmatch(name):
        return None
    return name


def _from(manifest: str, text: str) -> list[tuple[str, str, str]]:
    """(ecosystem, name, skip) the manifest declares."""
    out: list[tuple[str, str, str]] = []
    if manifest == "package.json":
        try:
            doc = json.loads(text)
        except ValueError:
            return out
        if isinstance(doc, dict) and (n := _shaped("npm", doc.get("name"))):
            out.append(("npm", n, "private, not published to npm"
                        if doc.get("private") is True else ""))
    elif manifest in ("pyproject.toml", "Cargo.toml"):
        try:
            doc = tomllib.loads(text)
        except (tomllib.TOMLDecodeError, ValueError):
            return out
        if manifest == "Cargo.toml":
            pkg = doc.get("package")
            if isinstance(pkg, dict) and (n := _shaped("crates.io", pkg.get("name"))):
                out.append(("crates.io", n, ""))
            return out
        project = doc.get("project")
        poetry = (doc.get("tool") or {}).get("poetry") if isinstance(doc.get("tool"),
                                                                     dict) else None
        for table in (project, poetry):
            if isinstance(table, dict) and (n := _shaped("PyPI", table.get("name"))):
                out.append(("PyPI", n, ""))
                break
    elif manifest == "setup.cfg":
        cp = configparser.ConfigParser(interpolation=None)
        try:
            cp.read_string(text)
        except configparser.Error:
            return out
        if (n := _shaped("PyPI", cp.get("metadata", "name", fallback=None))):
            out.append(("PyPI", n, ""))
    elif manifest == "setup.py":
        call = _SETUP_CALL.search(text)
        m = _SETUP_NAME.search(text, call.end()) if call else None
        if m and (n := _shaped("PyPI", m.group(2))):
            out.append(("PyPI", n, ""))
    elif manifest == "go.mod":
        m = _GO_MODULE.search(text)
        if m and (n := _shaped("Go", m.group(1))):
            out.append(("Go", n, ""))
    return out


def _key(eco: str, name: str) -> tuple[str, str]:
    low = name.lower()
    if eco == "PyPI":
        low = re.sub(r"[-_.]+", "-", low)
    elif eco == "crates.io":
        low = low.replace("_", "-")
    return eco, low


def declared_packages(src: Path, file: str | None = None) -> list[PackageName]:
    """Package names the clone's manifests declare: the directory of `file` first, then
    each parent up to the clone root (the root alone when `file` is None). One entry per
    name and ecosystem, the nearest manifest kept."""
    src = Path(src)
    dirs: list[Path] = []
    if file:
        d = (src / file).parent
        while True:
            try:
                d.relative_to(src)
            except ValueError:
                break
            dirs.append(d)
            if d == src:
                break
            d = d.parent
    if src not in dirs:
        dirs.append(src)
    seen: set[tuple[str, str]] = set()
    out: list[PackageName] = []
    for d in dirs:
        for manifest in MANIFESTS:
            text = _read(src, d / manifest)
            if text is None:
                continue
            rel = str((d / manifest).relative_to(src))
            for eco, name, skip in _from(manifest, text):
                if _key(eco, name) in seen:
                    continue
                seen.add(_key(eco, name))
                out.append(PackageName(eco, name, rel, skip))
    return out
