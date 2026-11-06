"""Is a refutation's evidence real, and is it on the claim's own code path?

IMPROVEMENT-PLAN decision F. MEASURED 2026-11-05 on the planted-bug replay
(`research.replay`): across three replays the refute pass killed all 46 claims, every
plant included, and none of the 46 refutations carried a `counter_quote`. The reasons
cited checks the code does not have: that `download` calls `secure_filename`, that the
role route carries `auth.requireAdmin`, that `tickets.history` goes through
`visibleTicket`. Each of those exists, in a sibling in the same file: `remove` calls
`secure_filename`, the other admin routes carry `auth.requireAdmin`, the other ticket
controllers call `visibleTicket`. That is how a guard-deletion bug looks, and it is why
checking that a counter_quote exists somewhere in the file would let every one of those
refutations through.

So a `refuted` verdict has to carry three things: `counter_file`, `counter_quote` copied
from it, and `guard`, the expression inside that quote the refuter says stops the attack
(`secure_filename(name)`, `auth.requireAdmin`, `g.user['id']`). It is grounded only when
the quote is in the file and the guard's own line, inside the quote, is on the claim's
path.

Why the guard and not just the quote, MEASURED 2026-11-05: the first version of this
check placed the counter_quote alone. On the next two replays (15 refutations each) 12
and 13 refutations grounded, 8 and 10 of them on a quote from inside the very definition
the claim quotes, which is always real and always on the path, beside a reason the quote
does not support: the head of `download` quoted beside "sanitized by
`secure_filename()`", the planted role route quoted beside "requires both
`auth.requireUser` and `auth.requireAdmin`". Plants were still killed on guards that do
not exist. Naming the guard makes the reason checkable.

A line is on the claim's path when it is:

  * inside the definition that encloses the claim's quote (its function, method or
    Express route line, with a Python function's decorators counted as part of it);
  * inside a definition the claim's definition names (a function it calls, a handler its
    route registers);
  * inside a definition that names the claim's definition (a route line or wrapper that
    registers or calls the claimed function);
  * or at module level, before any definition, where an `app.use(...)` or a router-wide
    middleware sits.

An import line is never on the path: `from werkzeug.utils import secure_filename` is at
module level in the file whose `download` does not call it.

What this cannot do: it proves the cited code exists where it would have to be, not that
it does what the refuter says. A refuter can still quote `if not os.path.isfile(path):`
from inside `download` and call it a traversal guard, or quote a guard from inside a
comment. "Definition" is the heuristic `intent.symbol_at` uses, and its errors go both
ways:

  * toward accepting a refutation: "names" is a whole-word match on the bare name, so a
    common name such as `get` can put a sibling on the path;
  * toward rejecting one: `symbol_at` gives a line the nearest definition above it, so a
    router-wide `app.use(auth.requireAdmin)` written after the first route is read as
    part of that route, and a refutation citing it is not grounded. The claim then goes
    to a human as "not rebutted", which costs triage time, not the finding.
"""
from __future__ import annotations

import glob
import re
from bisect import bisect_right
from dataclasses import dataclass
from pathlib import Path

from ..scanners.base import rel_or_none
from .intent import _ws, quote_line, symbol_at

#: The same floor a claim's quote has (ensemble.MIN_QUOTE_CHARS): a shorter span, such as
#: `@login_required`, occurs on most routes and locates nothing.
MIN_COUNTER_CHARS = 16
#: A guard is one expression (`g.user`, `secure_filename(name)`, `auth.requireAdmin`);
#: under this it is a fragment such as `auth` that names nothing.
MIN_GUARD_CHARS = 6

_IMPORT = re.compile(
    r"^\s*(?:import\s|from\s+[\w.]+\s+import\s|"
    r"(?:const|let|var)\s+[\w${}\s,:]+=\s*require\s*\(|require\s*\()")
_ROUTE_SYMBOL = re.compile(r"^(?:GET|POST|PUT|PATCH|DELETE) ")


@dataclass(frozen=True)
class Grounding:
    ok: bool
    why: str

    def as_record(self) -> dict:
        return {"ok": self.ok, "why": self.why}


def _read(root: Path, file: str) -> tuple[str, list[str]] | None:
    """(relative path, lines) of a file inside the clone, through the checks quote
    verification uses: model-supplied path confined to the clone, one same-named file
    standing in only when the named path does not exist, never through a symlink."""
    rel = rel_or_none(file, root) if file else None
    if not rel:
        return None
    p = root / rel
    if not p.is_file():
        name = Path(rel).name
        same = list(root.rglob(glob.escape(name))) if name else []
        if len(same) != 1:
            return None
        p = same[0]
        rel = str(p.relative_to(root))
    try:
        if p.is_symlink() or not p.resolve().is_relative_to(root.resolve()) \
                or not p.is_file():
            return None
        return rel, p.read_text(errors="replace").splitlines()
    except OSError:
        return None


class _Joined:
    """A file's lines whitespace-normalised and joined by single spaces, the way quote
    verification matches a claim, with a map from an offset back to its line."""

    def __init__(self, lines: list[str]):
        self.starts: list[int] = []
        self.idxs: list[int] = []
        parts: list[str] = []
        off = 0
        for i, ln in enumerate(lines):
            w = _ws(ln)
            if not w:
                continue
            self.starts.append(off)
            self.idxs.append(i)
            parts.append(w)
            off += len(w) + 1
        self.text = " ".join(parts)

    def line(self, offset: int) -> int:
        return self.idxs[bisect_right(self.starts, offset) - 1]

    def find_all(self, needle: str) -> list[int]:
        out, k = [], self.text.find(needle) if needle else -1
        while k != -1:
            out.append(k)
            k = self.text.find(needle, k + 1)
        return out


def occurrences(lines: list[str], quote: str) -> list[int]:
    """0-based indexes of every line a whitespace-normalised `quote` starts on. A quote
    may span lines."""
    j = _Joined(lines)
    return sorted({j.line(k) for k in j.find_all(_ws(quote))})


def guard_lines(lines: list[str], quote: str, guard: str) -> list[int]:
    """The lines where `guard` sits inside an occurrence of `quote`. Checking the line
    the quote starts on is not enough: a quote that opens in the claimed function and
    runs on into its sibling would put the sibling's guard "on the path"."""
    j = _Joined(lines)
    needle, g = _ws(quote), _ws(guard)
    out: set[int] = set()
    for k in j.find_all(needle):
        at = needle.find(g)
        while at != -1:
            out.add(j.line(k + at))
            at = needle.find(g, at + 1)
    return sorted(out)


class _Defs:
    """Each line's enclosing definition, and the contiguous block of lines it owns."""

    def __init__(self, rel: str, lines: list[str]):
        self.rel, self.lines = rel, lines
        py = rel.endswith(".py")
        self.sym = [symbol_at(lines, i, python=py) for i in range(len(lines))]

    def block(self, idx: int) -> tuple[int, int]:
        lo = hi = idx
        while lo > 0 and self.sym[lo - 1] == self.sym[idx]:
            lo -= 1
        while hi + 1 < len(self.lines) and self.sym[hi + 1] == self.sym[idx]:
            hi += 1
        return lo, hi

    def text(self, idx: int) -> str:
        lo, hi = self.block(idx)
        return "\n".join(self.lines[lo:hi + 1])


def _bare(sym: str | None) -> str | None:
    """The name a caller would write: `Resource.delete` -> `delete`. A route line has
    none; nothing calls `GET /x`."""
    if not sym or _ROUTE_SYMBOL.match(sym):
        return None
    return sym.rsplit(".", 1)[-1]


def _names(text: str, name: str) -> bool:
    return re.search(rf"(?<![\w$]){re.escape(name)}(?![\w$])", text) is not None


def ground(src: Path, *, claim_file: str, claim_quote: str, claim_line: int | None,
           counter_quote: str | None, counter_file: str | None,
           guard: str | None) -> Grounding:
    """Decide whether a `refuted` verdict's evidence grounds it: `counter_quote` copied
    from `counter_file`, and `guard`, the expression in that quote the refuter says stops
    the attack, on a line that is on the claim's path. `src` is the clone; every path is
    model output and is confined to it."""
    cq = counter_quote or ""
    if not cq.strip():
        return Grounding(False, "no counter_quote: the refutation quotes no code")
    if len(_ws(cq).replace(" ", "")) < MIN_COUNTER_CHARS:
        return Grounding(False, f"counter_quote is under {MIN_COUNTER_CHARS} characters, "
                                f"too short to locate one place in the code")
    g = _ws(guard or "")
    if not g:
        return Grounding(False, "no guard: the refutation does not name the expression "
                                "that stops the attack")
    if len(g.replace(" ", "")) < MIN_GUARD_CHARS:
        return Grounding(False, f"guard {g!r} is under {MIN_GUARD_CHARS} characters and "
                                f"names nothing")
    if g not in _ws(cq):
        return Grounding(False, f"guard {g!r} is not in the counter_quote")
    target = (counter_file or "").strip() or claim_file
    got = _read(src, target)
    if got is None:
        return Grounding(False, f"counter_file {target!r} is not a file in the repository")
    rel, lines = got
    if not occurrences(lines, cq):
        return Grounding(False, f"counter_quote not found in {rel}")
    hits = [i for i in guard_lines(lines, cq, g) if not _IMPORT.match(lines[i])]
    if not hits:
        return Grounding(False, f"guard {g!r} sits only on an import in {rel}; an import "
                                f"is not a check")

    claim = _read(src, claim_file) if claim_file else None
    cidx = quote_line(claim[1], claim_quote, claim_line) if claim else None
    if claim is None or cidx is None:
        # The claim's own place is unknown, so only existence can be checked.
        return Grounding(True, f"guard {g!r} found in {rel}; the claim's location could "
                               f"not be found, so its path was not checked")
    crel, clines = claim
    cdefs = _Defs(crel, clines)
    csym = cdefs.sym[cidx]
    cblock = cdefs.block(cidx)
    ctext = cdefs.text(cidx)
    cname = _bare(csym)
    odefs = cdefs if rel == crel else _Defs(rel, lines)

    seen: list[str] = []
    for i in hits:
        osym = odefs.sym[i]
        if rel == crel and cblock[0] <= i <= cblock[1]:
            return Grounding(True, f"guard {g!r} is in {csym or 'the module body'}, the "
                                   f"definition the claim quotes ({rel}:{i + 1})")
        if osym is None:
            return Grounding(True, f"guard {g!r} is at module level in {rel}:{i + 1}, "
                                   f"outside any definition")
        oname = _bare(osym)
        if oname and _names(ctext, oname):
            return Grounding(True, f"guard {g!r} is in {osym} ({rel}:{i + 1}), which the "
                                   f"claim's {csym or 'code'} names")
        if cname and _names(odefs.text(i), cname):
            return Grounding(True, f"guard {g!r} is in {osym} ({rel}:{i + 1}), which names "
                                   f"the claim's {csym}")
        seen.append(f"{osym} ({rel}:{i + 1})")
    where = ", ".join(seen[:4]) + (f" and {len(seen) - 4} more" if len(seen) > 4 else "")
    return Grounding(False, f"guard {g!r} occurs only in {where}, not on the path of the "
                            f"claim's {csym or 'code'}: a check in a sibling does not "
                            f"protect this one")
