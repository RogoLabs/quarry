"""The http_routes capability counts route decorators on any object.

VulnLookup names its Flask blueprints and flask-restx namespaces for what they serve
(`@user_bp.route`, `@stats_ns.route`). The old pattern only knew objects named app, bp
or router, so ~400 routes counted as 1, and the authorization lens (Layer 2 needs 5,
Layer 3 needs 3) never ran on it.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quarry.research.ensemble import select_lenses       # noqa: E402
from quarry.research.profile import profile_repo         # noqa: E402

BLUEPRINT = '''from flask import Blueprint
from flask_restx import Namespace, Resource

user_bp = Blueprint("user", __name__)
stats_ns = Namespace("stats")


@user_bp.route("/user/<int:uid>")
def show(uid): ...


@user_bp.route("/user/<int:uid>/edit", methods=["POST"])
def edit(uid): ...


@home_bp.get("/")
def index(): ...


@stats_ns.route("/ranking")
class Ranking(Resource): ...


@stats_ns.route("/most_sighted")
class MostSighted(Resource): ...


admin.add_url_rule("/admin", view_func=dashboard)
'''

MOCKS = '''from unittest import mock


@mock.patch("a.b")
@mock.patch("a.c")
@mock.patch.object(Thing, "x")
@pytest.mark.parametrize("x", [1])
@functools.lru_cache(maxsize=None)
def test_it(): ...
'''


def test_blueprints_and_namespaces_count_as_routes(tmp_path):
    (tmp_path / "views.py").write_text(BLUEPRINT)
    prof = profile_repo(tmp_path)
    assert prof.capabilities.get("http_routes") == 6
    lenses, _ = select_lenses(prof)
    assert "broken-authz-idor" in [lens.key for lens in lenses]


def test_test_decorators_are_not_routes(tmp_path):
    (tmp_path / "test_x.py").write_text(MOCKS)
    assert profile_repo(tmp_path).capabilities.get("http_routes", 0) == 0
