"""Every filter and global a template uses must be registered.

MEASURED, twice in one day. `/triage` returned 200 while `/runs`, `/runs/{id}`,
`/research`, `/research/{id}` and `/egress` returned a bare "Internal Server Error";
the log said `TemplateAssertionError: No filter named 'local'`. Triage survived only
because it is the one page rendering no timestamp, so the one page not calling the
new filter.

The cause is an asymmetry in reloading, not a typo:

* `.claude/launch.json` ran uvicorn with no `--reload`, so the module — and with it
  the Jinja environment and its filter registry — was frozen at process start.
* `Jinja2Templates` defaults `auto_reload=True`, so templates *were* re-read from
  disk on every request.

Editing a template to use a new filter took effect immediately; registering that
filter did not. `--reload` closes it, but a config flag is not a guarantee — the
desync returns the moment anyone runs uvicorn by hand, and it already happened twice
(`rule_id`, then `local`).

Be precise about what tests can and cannot see here, because the tidy version of
this story is false and was disproved while writing it:

* A filter used but registered *nowhere* — route tests DO catch, because they build a
  fresh app and the template is genuinely broken. Verified by injecting one.
* A filter registered in the code on disk while the *running process* predates the
  registration — no test can catch. Templates and code were consistent on disk today;
  only the live process was stale. That is a reload problem, and `--reload` is its fix.

So this file is not what would have caught today's outage. What it buys is narrower
and still worth having: it names the template and the filter instead of yielding a
traceback, it costs no server, and it covers every template rather than only the ones
some route happens to render — `_candidate_body.html` renders only when a research run
has findings, which the seeded fixture does not produce.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
from jinja2 import nodes

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quarry.web.app import create_app                 # noqa: E402

TEMPLATES = Path(__file__).resolve().parents[1] / "quarry" / "web" / "templates"

#: Names Jinja ships with. Anything else create_app() has to register.
BUILTIN_FILTERS = frozenset({
    "abs", "attr", "batch", "capitalize", "center", "count", "default", "d",
    "dictsort", "escape", "e", "filesizeformat", "first", "float", "forceescape",
    "format", "groupby", "indent", "int", "items", "join", "last", "length", "list",
    "lower", "map", "max", "min", "pprint", "random", "reject", "rejectattr",
    "replace", "reverse", "round", "safe", "select", "selectattr", "slice", "sort",
    "string", "striptags", "sum", "title", "tojson", "trim", "truncate", "unique",
    "upper", "urlencode", "urlize", "wordcount", "wordwrap", "xmlattr",
})

#: Jinja's own globals, plus names its constructs bind into scope.
BUILTIN_GLOBALS = frozenset({
    "range", "dict", "lipsum", "cycler", "joiner", "namespace",
    "loop", "self", "varargs", "kwargs", "true", "false", "none",
})

TEMPLATE_NAMES = sorted(p.name for p in TEMPLATES.glob("*.html"))


@pytest.fixture(scope="module")
def env():
    """The environment that serves requests — not a reconstruction of it.

    `create_app()` publishes it on `app.state.templates`, so there is one source of
    truth. Rebuilding the registrations here would let this gate pass a template the
    real app rejects, which is the same desync inverted.
    """
    return create_app().state.templates.env


def test_there_are_templates_to_check():
    """Guard against this whole file passing on an empty glob."""
    assert len(TEMPLATE_NAMES) >= 10, TEMPLATE_NAMES


def test_the_app_publishes_its_environment(env):
    """If this stops being true the fixture above silently tests nothing."""
    assert env.filters and env.globals
    assert "asset" in env.globals, "the shell needs asset() on every page"


@pytest.mark.parametrize("name", TEMPLATE_NAMES)
def test_every_filter_a_template_uses_is_registered(env, name):
    """The exact failure: a template called `|local` and nothing provided it."""
    ast = env.parse((TEMPLATES / name).read_text(), name=name)
    used = {n.name for n in ast.find_all(nodes.Filter)}
    missing = sorted(f for f in used
                     if f not in env.filters and f not in BUILTIN_FILTERS)
    assert not missing, (
        f"{name} uses filter(s) {missing} that create_app() does not register — "
        "the 500 that only appears on a server started before the registration")


@pytest.mark.parametrize("name", TEMPLATE_NAMES)
def test_every_global_a_template_calls_is_registered(env, name):
    """`asset()` and `ACTION_NOUN` are globals and would fail the same way.

    Only *called* names and known globals are checked: a bare `{{ run }}` is
    per-request context this cannot see.
    """
    ast = env.parse((TEMPLATES / name).read_text(), name=name)
    called = {c.node.name for c in ast.find_all(nodes.Call)
              if isinstance(c.node, nodes.Name)}
    called |= {g.node.name for g in ast.find_all(nodes.Getattr)
               if isinstance(g.node, nodes.Name) and g.node.name in env.globals}
    missing = sorted(c for c in called
                     if c not in env.globals and c not in BUILTIN_GLOBALS)
    assert not missing, f"{name} calls unregistered global(s) {missing}"


@pytest.mark.parametrize("name", TEMPLATE_NAMES)
def test_every_template_compiles(env, name):
    """A syntax error in a template is a 500 that no route test reaches either,
    because a route only compiles the templates it happens to render."""
    env.get_template(name)


def test_the_dev_server_reloads_code_and_templates_together():
    """The config half of the fix. Jinja hot-reloads templates unconditionally, so a
    server that does not reload code is guaranteed to desync the moment a template
    starts using a new filter."""
    import json
    cfg = json.loads((Path(__file__).resolve().parents[1]
                      / ".claude" / "launch.json").read_text())
    args = cfg["configurations"][0]["runtimeArgs"]
    assert "--reload" in args, (
        "launch.json must pass --reload, or template edits take effect while the "
        "code that supports them does not")
