"""How things look on the page: filters, globals, and the template environment.

Moved out of app.py unchanged, plus `build_templates`, which is the registration
block that was inline in `create_app`. Every filter and global a template uses is
registered there, and tests/test_template_contract.py checks the environment the app
actually serves from (`app.state.templates`), not a copy of this list.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from fastapi.templating import Jinja2Templates
from markupsafe import Markup, escape

from ..taint import _CONTROL as _TAINT_CONTROL
from . import queries as q

HERE = Path(__file__).resolve().parent

#: name -> (mtime_ns, content hash). See `asset()`.
_ASSET_REV: dict[str, tuple[int, str]] = {}


def asset(name: str) -> str:
    """`/static/<name>` with a content-hash query string.

    Needed because `StaticFiles` sets an ETag derived from `mtime + size` and never
    sets `Cache-Control`, so the browser falls back to heuristic freshness and may
    serve a memory-cached copy without revalidating — and a write that preserves both
    mtime and size yields a *valid* ETag for stale bytes. A content hash in the URL has
    neither hole.

    The hash is recomputed only when `mtime_ns` changes, so editing `app.css` takes
    effect on the next reload with no server restart. A startup-time hash would not:
    `uvicorn --reload` watches `*.py`.
    """
    p = HERE / "static" / name
    try:
        mtime = p.stat().st_mtime_ns
    except OSError:
        return f"/static/{name}"
    hit = _ASSET_REV.get(name)
    if hit is None or hit[0] != mtime:
        hit = (mtime, hashlib.sha256(p.read_bytes()).hexdigest()[:12])
        _ASSET_REV[name] = hit
    return f"/static/{name}?v={hit[1]}"


def rule_id(text: str, limit: int = 34) -> str:
    """Middle-truncate a rule id, preferring dot boundaries, bounded by `limit`.

    `word-break:break-all` rendered
    `javascript.express.security.audit.xss.mustache.var-in-href` as
    `…audit.xss.must / ache.var-in-hre / f` — the most important string in the primary
    column, made unreadable by its own overflow rule. CSS can only ellipsis at the end,
    which drops the tail; a left-ellipsis needs `direction:rtl` plus bidi control
    characters, which mangles mixed content. So it happens here, where it is
    deterministic and testable.

    Both ends carry information — the head names the language and family, the tail names
    the specific rule — so the middle goes. The result is never longer than `limit`,
    which is what keeps the CSS ellipsis a backstop rather than a second truncation.
    """
    text = str(text or "")
    if len(text) <= limit:
        return text

    parts = text.split(".")
    if len(parts) >= 3:
        # Keep the whole final segment when it leaves room for a meaningful head.
        tail = parts[-1]
        if len(tail) + 4 <= limit:
            head_budget = limit - len(tail) - 1          # 1 for the ellipsis
            head = ""
            for seg in parts[:-1]:
                nxt = seg if not head else f"{head}.{seg}"
                if len(nxt) > head_budget:
                    break
                head = nxt
            if head:
                return f"{head}…{tail}"
            return f"{parts[0][:head_budget]}…{tail}"

    # No usable dot structure: split the budget down the middle.
    keep = (limit - 1) // 2
    return f"{text[:limit - 1 - keep]}…{text[-keep:]}"


def tail_path(text: str, limit: int = 34) -> str:
    """Keep the end of a path. The filename and line are what you read; the directory
    prefix repeats down the whole column."""
    text = str(text or "")
    return text if len(text) <= limit else "…" + text[-(limit - 1):]


#: Characters that change how surrounding text is displayed, or are not displayed at
#: all: bidi embeddings, overrides and isolates, zero-width spaces, joiners and marks,
#: the BOM, and the rest of the set the taint boundary strips (C0 and C1 controls but
#: tab, newline and carriage return, soft hyphen, word joiners and invisible
#: operators, line and paragraph separators, the Unicode tag block). Every one can
#: arrive from a scanned repository in a path, a rule id, a message, a code line or a
#: model's quote, and an RLO in a filename is enough to make `evil.py` read as
#: something else on the screen whose job is to show what is true.
#:
#: It was a narrower list of its own, so a character the taint boundary knew about
#: (a word joiner, a tag character) could reach the page unmarked in any text stored
#: before scrubbing, or never scrubbed. One definition now serves both.
_INVISIBLE = _TAINT_CONTROL


def visible(text) -> Markup:
    """Escape `text` and render each invisible formatting character as a token such
    as `‹U+202E›`, so it is seen rather than obeyed."""
    if text is None:
        return Markup("")
    return Markup(_INVISIBLE.sub(lambda m: f"‹U+{ord(m.group()):04X}›",
                                 str(escape(text))))


def _finalize(value):
    """Jinja `finalize` hook: the backstop for any field the templates did not mark
    with `|visible`. Values without invisible characters pass through untouched, so
    autoescaping still applies to them as before."""
    if isinstance(value, str) and _INVISIBLE.search(value):
        return visible(value)
    return value


def build_templates(csrf_token: str) -> Jinja2Templates:
    """The one template environment, with every filter and global registered."""
    templates = Jinja2Templates(directory=HERE / "templates")
    templates.env.globals["csrf_token"] = csrf_token
    templates.env.filters["visible"] = visible
    templates.env.finalize = _finalize
    templates.env.filters["sev"] = lambda s: (s or "info").lower()

    # One clock on screen. The database stores UTC and naive-local side by side; see
    # queries.local().
    templates.env.filters["local"] = q.local
    templates.env.filters["until"] = q.until
    templates.env.filters["elapsed"] = q.elapsed
    templates.env.filters["rule_id"] = rule_id
    templates.env.filters["tail_path"] = tail_path
    templates.env.globals["asset"] = asset
    templates.env.globals["ACTION_NOUN"] = q.ACTION_NOUN
    return templates
