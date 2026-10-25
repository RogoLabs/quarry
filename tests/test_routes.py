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
