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


def test_flask_restx_namespaces_resources_and_api_prefix(tmp_path):
    # VulnLookup's shape: an Api on a /api blueprint, with nested parentheses in the
    # constructor, namespaces mounted by path= from an absolute import, and Resource
    # classes whose methods are the verbs.
    (tmp_path / "web" / "api").mkdir(parents=True)
    (tmp_path / "web" / "api" / "__init__.py").write_text(
        "from flask import Blueprint\n"
        "from flask_restx import Api\n"
        "bp = Blueprint(\n    'apiv1', __name__, url_prefix='/api'\n)\n"
        "def setup():\n"
        "    api = Api(\n"
        "        bp,\n"
        "        version=version('x') if cfg.get('A', True) else '1.0',\n"
        "        description='see (this)',\n"
        "        prefix='/v1',\n"
        "    )\n"
        "    from web.api import vuln\n"
        "    from web.api import users\n"
        "    api.add_namespace(vuln.vuln_ns, path='/vulnerability')\n"
        "    api.add_namespace(vuln.legacy_ns, path='/')\n"
        "    api.add_namespace(\n        users.users_ns\n    )\n")
    (tmp_path / "web" / "api" / "vuln.py").write_text(
        "vuln_ns = Namespace('vulnerability', description='x (y)')\n"
        "legacy_ns = Namespace('legacy')\n"
        "@legacy_ns.route(\n    'cve/<string:vid>', doc=False\n)\n"
        "@vuln_ns.route('/<string:vid>')\n"
        "class Vulnerability(Resource):\n"
        "    @limit()\n"
        "    def get(self, vid):\n"
        "        def post(): ...\n"          # a nested function is not a verb of the class
        "        return {}\n"
        "\n"
        "    # a comment at class depth does not end the body\n"
        "    def delete(self, vid): ...\n"
        "@vuln_ns.route('/bulk', '/many')\n"
        "class Bulk(Resource):\n"
        "    def post(self): ...\n"
        "def helper(): ...\n"
        "def get(): ...\n")              # a module-level get is not a Resource method
    (tmp_path / "web" / "api" / "users.py").write_text(
        "users_ns = Namespace('users', path='/u')\n"
        "@users_ns.route('/<int:uid>')\n"
        "class User(Resource):\n"
        "    async def put(self, uid): ...\n")
    assert _paths(tmp_path, "web/api/vuln.py") == [
        ("DELETE", "/api/v1/cve/<string:vid>"),
        ("DELETE", "/api/v1/vulnerability/<string:vid>"),
        ("GET", "/api/v1/cve/<string:vid>"),
        ("GET", "/api/v1/vulnerability/<string:vid>"),
        ("POST", "/api/v1/vulnerability/bulk"), ("POST", "/api/v1/vulnerability/many")]
    assert _paths(tmp_path, "web/api/users.py") == [("PUT", "/api/v1/u/<int:uid>")]


def test_a_namespace_without_a_mount_path_uses_its_own(tmp_path):
    (tmp_path / "app.py").write_text(
        "api = Api(app)\n"
        "ns = Namespace('cwe')\n"
        "api.add_namespace(ns)\n"
        "@ns.route('/<cwe_id>')\n"
        "class C(Resource):\n"
        "    def get(self, cwe_id): ...\n"
        "@app.route('/plain', methods=('POST',))\n"
        "def plain(): ...\n")
    assert _paths(tmp_path, "app.py") == [("GET", "/cwe/<cwe_id>"), ("POST", "/plain")]


def test_flask_converters_normalise_and_name_their_parameter():
    from quarry.dynamic.routes import _path_params
    assert _norm_path("/u/<int:uid>") == _norm_path("/u/{uid}") == "/u/{}"
    assert _norm_path("/c/<string(length=2):code>/x") == "/c/{}/x"
    assert _norm_path("/f/{p:path}") == "/f/{}"
    assert _path_params("/a/<int:uid>/b/<name>/{x}/:y") == ("uid", "name", "x", "y")


def test_probe_urls_fill_converter_parameters_once():
    from quarry.dynamic.probes import _concrete, _inject
    from quarry.dynamic.validate import RunningTarget
    assert _concrete("/api/browse/<string:vendor>/products") == "/api/browse/1/products"
    running = RunningTarget("http://web:10001", stop=lambda: None, network="n")
    route = Route("GET", "/api/c/<string:a>/<int:b>")
    assert _inject(running, route, "MARK") == "http://web:10001/api/c/MARK/1"


def test_openapi_base_path_and_server_path_prefix_every_route():
    swagger = {"swagger": "2.0", "basePath": "/api",
               "paths": {"/vulnerability/{vid}": {"get": {}}}}
    assert [r.path for r in routes_from_openapi(swagger)] == ["/api/vulnerability/{vid}"]
    v3 = {"openapi": "3.0.0", "servers": [{"url": "https://x.example/v2/"}],
          "paths": {"/items": {"get": {}}}}
    assert [r.path for r in routes_from_openapi(v3)] == ["/v2/items"]
    relative = {"openapi": "3.0.0", "servers": [{"url": "/rest"}], "paths": {"/a": {"get": {}}}}
    assert [r.path for r in routes_from_openapi(relative)] == ["/rest/a"]
    templated = {"openapi": "3.0.0", "servers": [{"url": "{scheme}://h/{base}"}],
                 "paths": {"/a": {"get": {}}}}
    assert [r.path for r in routes_from_openapi(templated)] == ["/a"]


def test_a_committed_spec_below_the_root_is_found_but_not_a_test_fixture(tmp_path):
    import json
    from quarry.dynamic.routes import OpenApiFileRouteSource
    (tmp_path / "docs" / "_static" / "files").mkdir(parents=True)
    (tmp_path / "docs" / "_static" / "files" / "swagger.json").write_text(json.dumps(
        {"swagger": "2.0", "basePath": "/api", "security": [{"k": []}],
         "paths": {"/users/{uid}": {"get": {}}}}))
    (tmp_path / "tests" / "fixtures").mkdir(parents=True)
    (tmp_path / "tests" / "fixtures" / "openapi.json").write_text(json.dumps(
        {"openapi": "3.0.0", "paths": {"/fixture": {"get": {}}}}))
    (tmp_path / "swagger.json").write_text(json.dumps({"paths": {"/notaspec": {}}}))
    (tmp_path / "api.py").write_text(
        "bp = Blueprint('a', __name__, url_prefix='/api')\n"
        "api = Api(bp)\n"
        "ns = Namespace('users')\n"
        "api.add_namespace(ns)\n"
        "@ns.route('/<int:uid>')\n"
        "class U(Resource):\n"
        "    def get(self, uid): ...\n")
    assert [r.path for r in OpenApiFileRouteSource().discover(tmp_path)] == ["/api/users/{uid}"]
    [r] = build_route_map(tmp_path).for_finding("api.py")
    assert r.source == "static+openapi" and r.auth_required is True
