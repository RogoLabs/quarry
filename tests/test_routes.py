"""Route discovery: static extraction across common frameworks, path-param
normalisation so sources merge, and linking a finding to its route by file.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quarry.dynamic.routes import (                                 # noqa: E402
    StaticRouteSource, RouteMap, Route, build_route_map, _norm_path, routes_from_openapi)


def test_static_extracts_express(tmp_path):
    (tmp_path / "server.js").write_text(
        "app.get('/users', h)\n"
        "router.post(\"/users/:id/posts\", h)\n"
        "r.delete(`/users/:id`, h)\n")
    routes = StaticRouteSource().discover(tmp_path)
    got = {(r.method, r.path) for r in routes}
    assert ("GET", "/users") in got
    assert ("POST", "/users/:id/posts") in got
    assert ("DELETE", "/users/:id") in got
    post = next(r for r in routes if r.method == "POST")
    assert post.params == ("id",) and post.handler_file == "server.js"


def test_static_extracts_fastapi_and_flask(tmp_path):
    (tmp_path / "api.py").write_text(
        "@app.get('/items/{item_id}')\n"
        "def get_item(item_id): ...\n"
        "@router.post('/items')\n"
        "def make(): ...\n"
        "@app.route('/legacy', methods=['GET', 'POST'])\n"
        "def legacy(): ...\n"
        "@app.route('/health')\n"
        "def health(): ...\n")
    routes = StaticRouteSource().discover(tmp_path)
    got = {(r.method, r.path) for r in routes}
    assert ("GET", "/items/{item_id}") in got
    assert ("POST", "/items") in got
    assert ("GET", "/legacy") in got and ("POST", "/legacy") in got
    assert ("GET", "/health") in got                 # route() defaults to GET


def test_path_normalisation():
    assert _norm_path("/u/:id") == _norm_path("/u/{id}") == _norm_path("u/<id>/") == "/u/{}"


def test_routemap_merges_across_param_syntax_and_enriches():
    m = RouteMap()
    m.add(Route("GET", "/u/:id", handler_file="server.js", source="static"))
    m.add(Route("GET", "/u/{id}", source="openapi", auth_required=True,
                params=("id",)))
    assert len(m.routes) == 1                         # same route, two syntaxes
    merged = next(iter(m.routes.values()))
    assert merged.source == "static+openapi"
    assert merged.handler_file == "server.js"         # kept from static
    assert merged.auth_required is True               # enriched from openapi


def test_for_finding_links_by_file(tmp_path):
    (tmp_path / "users.js").write_text("app.get('/users/:id', h)\n")
    (tmp_path / "health.js").write_text("app.get('/health', h)\n")
    rmap = build_route_map(tmp_path)
    linked = rmap.for_finding("users.js")
    assert [r.path for r in linked] == ["/users/:id"]
    assert rmap.for_finding("nonexistent.js") == []


def test_openapi_optional_security_is_not_auth_required():
    # `[{}, {bearer: []}]` lists anonymous access as one of the alternatives, so the spec
    # does not say the route is protected and the authz probe must not treat it as such.
    doc = {"paths": {
        "/maybe": {"get": {"security": [{}, {"bearer": []}]}},
        "/anon-last": {"get": {"security": [{"bearer": []}, {}]}},
        "/must": {"get": {"security": [{"bearer": []}]}},
    }}
    got = {r.path: r.auth_required for r in routes_from_openapi(doc)}
    assert got == {"/maybe": False, "/anon-last": False, "/must": True}


def test_openapi_global_optional_security_is_not_auth_required():
    doc = {"security": [{}, {"apiKey": []}], "paths": {"/x": {"get": {}}}}
    assert routes_from_openapi(doc)[0].auth_required is False


def test_openapi_operation_empty_security_overrides_global():
    doc = {"security": [{"bearer": []}], "paths": {
        "/login": {"post": {"security": []}},       # explicitly public
        "/me": {"get": {}},                          # inherits the global requirement
    }}
    got = {r.path: r.auth_required for r in routes_from_openapi(doc)}
    assert got == {"/login": False, "/me": True}


def test_openapi_malformed_security_is_unknown():
    doc = {"paths": {"/x": {"get": {"security": "bearer"}}}}
    assert routes_from_openapi(doc)[0].auth_required is None


# ------------------------------------------------------------------ mount prefixes
# IMPROVEMENT-PLAN item 12: routes on a mounted router kept their bare path, so a
# probe asked for /users and read the 404 as "handled".

def _paths(tmp_path, file):
    return sorted((r.method, r.path) for r in StaticRouteSource().discover(tmp_path)
                  if r.handler_file == file)


def test_fastapi_router_prefix_and_include_router(tmp_path):
    (tmp_path / "app" / "routers").mkdir(parents=True)
    (tmp_path / "app" / "routers" / "users.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter(prefix='/users', tags=['u'])\n"
        "@router.get('/{user_id}')\n"
        "def get_user(user_id): ...\n")
    (tmp_path / "app" / "routers" / "items.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "@router.post('/items')\n"
        "def make(): ...\n")
    (tmp_path / "app" / "main.py").write_text(
        "from fastapi import FastAPI\n"
        "from .routers import users\n"
        "from app.routers.items import router as items_router\n"
        "app = FastAPI()\n"
        "app.include_router(users.router, prefix='/api/v1')\n"
        "app.include_router(items_router, prefix='/api')\n"
        "@app.get('/health')\n"
        "def health(): ...\n")
    assert _paths(tmp_path, "app/routers/users.py") == [("GET", "/api/v1/users/{user_id}")]
    assert _paths(tmp_path, "app/routers/items.py") == [("POST", "/api/items")]
    assert _paths(tmp_path, "app/main.py") == [("GET", "/health")]


def test_flask_blueprint_url_prefix_and_register_override(tmp_path):
    (tmp_path / "views.py").write_text(
        "bp = Blueprint('admin', __name__, url_prefix='/admin')\n"
        "@bp.route('/users/<int:uid>', methods=['GET', 'DELETE'])\n"
        "def user(uid): ...\n")
    (tmp_path / "other.py").write_text(
        "api = Blueprint('api', __name__, url_prefix='/ignored')\n"
        "@api.route('/ping')\n"
        "def ping(): ...\n")
    (tmp_path / "app.py").write_text(
        "from views import bp\n"
        "from other import api\n"
        "app.register_blueprint(bp)\n"
        "app.register_blueprint(api, url_prefix='/api')\n")
    assert _paths(tmp_path, "views.py") == [("DELETE", "/admin/users/<int:uid>"),
                                            ("GET", "/admin/users/<int:uid>")]
    assert _paths(tmp_path, "other.py") == [("GET", "/api/ping")]   # register-time wins


def test_express_use_with_require_import_and_nesting(tmp_path):
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes" / "users.js").write_text(
        "const router = require('express').Router()\n"
        "const posts = require('./posts')\n"
        "router.get('/:id', h)\n"
        "router.use('/:id/posts', posts)\n"
        "module.exports = router\n")
    (tmp_path / "routes" / "posts.js").write_text(
        "const express = require('express')\nconst postsRouter = express.Router()\n"
        "postsRouter.post('/', h)\nmodule.exports = postsRouter\n")
    (tmp_path / "routes" / "admin.ts").write_text("router.delete('/cache', h)\n")
    (tmp_path / "server.js").write_text(
        "const users = require('./routes/users')\n"
        "import admin from './routes/admin'\n"
        "app.use('/api/users', users)\n"
        "app.use('/admin', admin)\n"
        "app.use('/v2', require('./routes/users'))\n"
        "axios.get('/not/a/route')\n"
        "app.get('/health', h)\n")
    assert _paths(tmp_path, "routes/users.js") == [("GET", "/api/users/:id"),
                                                   ("GET", "/v2/:id")]
    assert _paths(tmp_path, "routes/posts.js") == [("POST", "/api/users/:id/posts"),
                                                   ("POST", "/v2/:id/posts")]
    assert _paths(tmp_path, "routes/admin.ts") == [("DELETE", "/admin/cache")]
    assert _paths(tmp_path, "server.js") == [("GET", "/health")]


def test_a_prefixed_static_route_now_merges_with_its_openapi_entry(tmp_path):
    (tmp_path / "users.py").write_text(
        "router = APIRouter(prefix='/users')\n@router.get('/{uid}')\ndef u(uid): ...\n")
    rmap = build_route_map(tmp_path)
    rmap.add_all(routes_from_openapi({"paths": {"/users/{uid}": {"get": {
        "security": [{"bearer": []}]}}}}))
    [r] = rmap.for_finding("users.py")
    assert r.path == "/users/{uid}" and r.auth_required is True
    assert r.source == "static+openapi"


def test_an_ambiguous_mount_target_adds_no_prefix(tmp_path):
    for d in ("a", "b"):
        (tmp_path / d).mkdir()
        (tmp_path / d / "users.py").write_text("router = APIRouter()\n@router.get('/x')\ndef x(): ...\n")
    (tmp_path / "main.py").write_text("from users import router\n"
                                      "app.include_router(router, prefix='/api')\n")
    assert _paths(tmp_path, "a/users.py") == [("GET", "/x")]
