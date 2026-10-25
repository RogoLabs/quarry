"""Repo packing for whole-context review.

The gated design assumed repos too large to read. That assumption is false for a
large class of interesting targets: `cve-validation-library` is 26 files and ~109k
tokens, and every model in the ensemble has a 131k–262k context. When the whole
repository fits, chunking is not a necessary evil — it is a self-inflicted blindfold,
and it is precisely what produced the predecessor's 40 `already-mitigated` rejections.

So: pack the whole thing, in dependency-ish order, with the parts that are data rather
than logic summarised instead of included.
"""
from __future__ import annotations

import json
import re
import os
from dataclasses import dataclass, field
from pathlib import Path

CODE_EXT = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py", ".go", ".rb", ".php",
            ".java", ".rs", ".c", ".h", ".cpp", ".cs", ".kt", ".swift", ".sh", ".bash"}
CONFIG_EXT = {".json", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".env"}
DOC_EXT = {".md", ".rst", ".txt"}
SKIP_DIR = {".git", "node_modules", "vendor", ".venv", "venv", "dist", "build",
            "coverage", "__pycache__", ".next", "target", ".tox"}
# Files that are data, not logic. Included as a described skeleton, never in full.
DATA_HINTS = ("schema", "fixture", "testdata", "test-data", "snapshot", "lock")

CHARS_PER_TOKEN = 3.6


@dataclass
class PackedFile:
    path: str
    text: str
    kind: str          # code | config | doc | data-summary
    bytes_original: int

    @property
    def tokens(self) -> int:
        return int(len(self.text) / CHARS_PER_TOKEN)


@dataclass
class Pack:
    root: Path
    files: list[PackedFile] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)

    @property
    def tokens(self) -> int:
        return sum(f.tokens for f in self.files)

    def render(self, include_data: bool = True) -> str:
        out = []
        for f in self.files:
            if f.kind == "data-summary" and not include_data:
                continue
            out.append(f"===== FILE: {f.path} =====\n{f.text}")
        return "\n\n".join(out)

    def manifest(self) -> str:
        rows = [f"  {f.path}  ({f.kind}, ~{f.tokens} tok)" for f in self.files]
        return "\n".join(rows)


def _summarise_json_schema(text: str, path: str) -> str:
    """A 130 KB JSON Schema is 36k tokens of mostly boilerplate. What a reviewer needs
    is its shape: what it constrains, and where the constraints are weak."""
    try:
        doc = json.loads(text)
    except ValueError:
        return f"[unparseable JSON, {len(text)} bytes]"

    lines: list[str] = []

    def walk(node, prefix="", depth=0):
        if depth > 3 or len(lines) > 220:
            return
        if not isinstance(node, dict):
            return
        interesting = {k: v for k, v in node.items() if k in (
            "type", "pattern", "format", "enum", "minLength", "maxLength", "minimum",
            "maximum", "minItems", "maxItems", "additionalProperties", "required",
            "oneOf", "anyOf", "allOf", "$ref", "uniqueItems")}
        if interesting:
            bits = []
            for k, v in interesting.items():
                if k in ("required", "enum") and isinstance(v, list):
                    bits.append(f"{k}=[{len(v)} items]" if len(v) > 6 else f"{k}={v}")
                elif k in ("oneOf", "anyOf", "allOf") and isinstance(v, list):
                    bits.append(f"{k}[{len(v)}]")
                elif k == "pattern":
                    bits.append(f"pattern={v!r}")     # patterns matter: ReDoS surface
                else:
                    bits.append(f"{k}={v}")
            if bits:
                lines.append(f"{prefix}: {', '.join(bits)}")
        for key in ("properties", "definitions", "$defs", "patternProperties"):
            sub = node.get(key)
            if isinstance(sub, dict):
                for name, child in sub.items():
                    walk(child, f"{prefix}.{name}" if prefix else name, depth + 1)
        for key in ("items", "additionalProperties", "contains"):
            sub = node.get(key)
            if isinstance(sub, dict):
                walk(sub, f"{prefix}[]", depth + 1)

    walk(doc, "")
    patterns = [l for l in lines if "pattern=" in l]
    head = (f"[JSON Schema skeleton — {len(text)} bytes summarised. "
            f"{len(lines)} constrained nodes, {len(patterns)} regex patterns.]")
    return head + "\n" + "\n".join(lines[:220])


def pack_repo(root: Path, *, max_file_bytes: int = 200_000) -> Pack:
    root = root.resolve()
    pack = Pack(root=root)
    entries: list[tuple[int, Path]] = []

    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in SKIP_DIR]
        for name in fn:
            p = Path(dp) / name
            ext = p.suffix.lower()
            if ext not in CODE_EXT | CONFIG_EXT | DOC_EXT:
                continue
            try:
                size = p.stat().st_size
            except OSError:
                continue
            if size > max_file_bytes:
                pack.skipped.append((str(p.relative_to(root)), f"{size} bytes, over cap"))
                continue
            # order: entry points and code first, data last
            rank = 0 if ext in CODE_EXT else (1 if ext in CONFIG_EXT else 2)
            if any(h in str(p).lower() for h in DATA_HINTS):
                rank += 2
            entries.append((rank, p))

    for rank, p in sorted(entries, key=lambda t: (t[0], str(t[1]))):
        rel = str(p.relative_to(root))
        try:
            text = p.read_text(errors="replace")
        except OSError:
            continue
        ext = p.suffix.lower()
        is_data = any(h in rel.lower() for h in DATA_HINTS)

        # Only summarise what is genuinely too big. A 7 KB test record is the *shape of
        # the input the library validates* — the most useful thing a reviewer can read.
        # Summarising it away was the packer reproducing the blindfold it exists to remove.
        if ext == ".json" and len(text) > 20_000:
            body, kind = _summarise_json_schema(text, rel), "data-summary"
        elif ext in DOC_EXT:
            body, kind = text[:6000], "doc"
        else:
            body, kind = text, "code" if ext in CODE_EXT else "config"
        pack.files.append(PackedFile(rel, body, kind, len(text)))

    return pack


# ---------------------------------------------------------------- subsystems

@dataclass
class Subsystem:
    name: str
    pack: Pack
    repo_map: str

    @property
    def weight(self) -> float:
        return subsystem_weight(self.name)

    @property
    def tokens(self) -> int:
        return self.pack.tokens + int(len(self.repo_map) / CHARS_PER_TOKEN)

    def render(self) -> str:
        return (f"===== REPOSITORY MAP (orientation only — full source follows for "
                f"the '{self.name}' subsystem) =====\n{self.repo_map}\n\n"
                f"===== SUBSYSTEM: {self.name} =====\n{self.pack.render()}")


# Directories that are configuration for humans and tools, not attack surface. They
# were producing subsystems like `.claude/rules` and `.github/ISSUE_TEMPLATE` — 48k
# tokens of prompt files reviewed for SQL injection.
NON_REVIEWABLE = re.compile(
    r"^(\.github|\.claude|\.config|\.vscode|\.idea|docs?|doc|examples?|"
    r"\.devcontainer|\.circleci|\.husky|public/assets|db/migrate)(/|$)", re.I)

# Security-relevance weights for ordering a long run. A run that is stopped after four
# hours should have spent them on controllers and models, not on locale files.
SUBSYSTEM_WEIGHTS: tuple[tuple[str, float], ...] = (
    (r"controller|handler|route|endpoint|api|resolver", 5.0),
    (r"auth|session|token|permission|policy|abilit|guard|middleware", 5.0),
    (r"model|entity|schema|migration|repositor", 3.5),
    (r"service|core|lib|domain|usecase", 3.0),
    (r"job|worker|task|queue|consumer", 2.5),
    (r"util|helper|common|shared", 2.0),
    (r"view|template|component|page|ui|asset|style", 1.0),
    (r"test|spec|fixture|mock|factor", 0.2),
)


def subsystem_weight(name: str) -> float:
    low = name.lower()
    best = 1.5
    for pat, w in SUBSYSTEM_WEIGHTS:
        if re.search(pat, low):
            best = max(best, w) if w > 1.0 else min(best, w)
    return best


def build_repo_map(pack: Pack, profile_summary: str = "", *,
                   max_tokens: int = 6_000) -> str:
    """A whole-repo skeleton that fits in a few thousand tokens.

    Every subsystem pack carries this. Without it the reviewer is back to the
    predecessor's single-file blindness — it would not know that the authorization
    check it is looking for lives in a directory it was never shown. Signatures only,
    never bodies.
    """
    lines: list[str] = []
    if profile_summary:
        lines += [profile_summary, ""]
    lines.append("File tree with exported symbols:")
    sig = re.compile(
        r"^\s*(?:export\s+)?(?:async\s+)?"
        r"(?:function|class|const|def|module|interface|type|public|private|protected)\s+"
        r"([A-Za-z_$][\w$]*)"
        r"|^\s*(?:def|class)\s+([A-Za-z_][\w]*)"
        r"|^\s*(?:app|router|bp)\.(get|post|put|patch|delete)\(\s*['\"]([^'\"]+)",
        re.M)
    for f in pack.files:
        if f.kind not in ("code",):
            lines.append(f"  {f.path}  [{f.kind}]")
            continue
        names: list[str] = []
        for m in sig.finditer(f.text):
            n = m.group(1) or m.group(2) or (f"{m.group(3).upper()} {m.group(4)}"
                                             if m.group(3) else None)
            if n and n not in names:
                names.append(n)
        shown = ", ".join(names[:10]) + ("…" if len(names) > 10 else "")
        lines.append(f"  {f.path}  ({f.tokens} tok){': ' + shown if shown else ''}")

    # A map that does not fit is not orientation, it is the problem it was meant to
    # solve. On a ~1M-token web app the unbounded version was 48k tokens — larger than the
    # subsystem it was supposed to contextualise.
    budget_chars = int(max_tokens * CHARS_PER_TOKEN)
    out = "\n".join(lines)
    if len(out) <= budget_chars:
        return out
    keep, used = [], 0
    for line in lines:
        if used + len(line) > budget_chars:
            break
        keep.append(line)
        used += len(line) + 1
    return "\n".join(keep) + f"\n  … repository map truncated at {max_tokens} tokens " \
                              f"({len(lines) - len(keep)} further files not listed)"


def _subsystem_key(rel: str, depth: int = 2) -> str:
    parts = Path(rel).parts
    if len(parts) <= 1:
        return "(root)"
    return "/".join(parts[:min(depth, len(parts) - 1)])


def pack_subsystems(root: Path, *, budget_tokens: int = 40_000,
                    profile_summary: str = "", include_tests: bool = False,
                    ) -> list[Subsystem]:
    """Split a repo into review units that each fit a context.

    Whole-repo review is strictly better when it fits — `cve-validation-library` is
    30k tokens against 131k–262k windows, so there is no reason to chunk it. This is
    the fallback for the repos that do not fit: `cve-services` at ~560k and
    a private web app at ~1.08M.

    Units follow directory structure rather than a fixed line count, because a
    subsystem boundary is where the author put one. Oversized directories split by
    file, and the repo map travels with every unit so nothing is reviewed blind.
    """
    full = pack_repo(root)
    repo_map = build_repo_map(full, profile_summary)
    map_tokens = int(len(repo_map) / CHARS_PER_TOKEN)
    room = max(8_000, budget_tokens - map_tokens)

    if full.tokens <= room:
        return [Subsystem("(whole repository)", full, repo_map)]

    groups: dict[str, list[PackedFile]] = {}
    for f in full.files:
        if NON_REVIEWABLE.match(f.path):
            continue
        key = _subsystem_key(f.path)
        if not include_tests and subsystem_weight(key) < 0.5:
            continue
        groups.setdefault(key, []).append(f)

    units: list[Subsystem] = []
    for name, files in sorted(groups.items()):
        files.sort(key=lambda f: f.path)
        batch: list[PackedFile] = []
        total = 0
        part = 0
        for f in files:
            if batch and total + f.tokens > room:
                part += 1
                units.append(Subsystem(f"{name} (part {part})",
                                       Pack(root=root, files=batch), repo_map))
                batch, total = [], 0
            batch.append(f)
            total += f.tokens
        if batch:
            label = name if part == 0 else f"{name} (part {part + 1})"
            units.append(Subsystem(label, Pack(root=root, files=batch), repo_map))

    # Order by security relevance. A long run is meant to be interruptible, so the
    # value has to be front-loaded: stopping after four hours should mean the
    # controllers and models were reviewed, not the locale files.
    units.sort(key=lambda u: (-subsystem_weight(u.name), -u.pack.tokens, u.name))
    return units
