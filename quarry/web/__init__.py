"""Web package.

`queries` is pure SQLite and must stay importable without FastAPI installed — the CLI
and the tests use it, and a read model that drags a web framework in is a read model
you cannot reuse. `app` is imported lazily for the same reason.
"""
from . import queries   # noqa: F401


def create_app():
    from .app import create_app as _f
    return _f()
