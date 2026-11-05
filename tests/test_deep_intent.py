"""IMPROVEMENT-PLAN item 20, first half: a route's declared access as stated intent.

The authz lens and the refuter are told what each route declares about who may call it:
the middleware or decorators on it, and what a committed OpenAPI document says. The spec
is evidence with limits, and the case the plan names is VulnLookup's: a spec-wide
`apikey` with no per-operation override marks every route protected, public ones too.
No model and no network here: E.call is replaced where a prompt is captured.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quarry import db                                        # noqa: E402
from quarry.research import ensemble as E                    # noqa: E402
from quarry.research import intent, runner                   # noqa: E402

# The shape of cve-services' src/controller/cve-id.controller/index.js: a swagger
# comment (with an apostrophe in it) between the path and the middleware.
EXPRESS = """\
const express = require('express')
const router = express.Router()
const mw = require('../../middleware/middleware')
const controller = require('./cve-id.controller')

router.use(mw.requestLogger)

router.get('/cve-id/:id',
  /*
  #swagger.tags = ['CVE ID']
  #swagger.description = "Doesn't need a login; anonymous callers get a redacted record"
  */
  mw.rateLimiter,
  mw.optionallyValidateUser,
  param(['id']).isString().trim(),
  parseError,
  controller.CVEID_GET_SINGLE
)

router.put('/cve-id/:id', mw.validateUser, [mw.onlySecretariat, mw.validateOrg],
  controller.CVEID_UPDATE_SINGLE)

router.delete('/cve-id/:id', (req, res) => res.sendStatus(405))

module.exports = router
"""

# The shape of VulnLookup's website/web/api/v1/bundle.py (Flask-RESTX).
RESTX = '''\
from flask_restx import Namespace, Resource

bundle_ns = Namespace("bundle", description="Bundle related operations.")


@bundle_ns.route("/<string:bundle_uuid>")
class BundleItem(Resource):
    @typed(bundle_ns.doc(description="Get a bundle with its UUID."))
    @typed(
        bundle_ns.response(200, "Success.")
    )
    def get(self, bundle_uuid):
        return {}, 200

    @typed(bundle_ns.doc(description="Delete a bundle."))
    @typed(auth_func)
    @typed(permission_required("bundle:delete"))
    def delete(self, bundle_uuid):
        return {}, 204


@bundle_ns.route("/")
class BundlesList(Resource):
    method_decorators = [rate_limited]

    def get(self):
        return [], 200
'''

FLASK = '''\
from fastapi import APIRouter, Depends
from flask import Blueprint

bp = Blueprint("notes", __name__, url_prefix="/notes")
router = APIRouter(prefix="/items")


@bp.route("/<int:note_id>", methods=["GET", "PUT"])
@login_required
def note(note_id):
    return ""


@router.get("/{item_id}", dependencies=[Depends(verify_key)])
async def item(item_id: int, user=Depends(current_user)):
    return {}
'''


def _by(decls, method, path):
    hits = [d for d in decls if d.method == method and d.path == path]
    assert len(hits) == 1, (method, path, [(d.method, d.path) for d in decls])
    return hits[0]


def test_express_middleware_is_read_in_order_past_a_swagger_comment():
    decls = intent.declarations(EXPRESS, "src/controller/cve-id.controller/index.js")
    get = _by(decls, "GET", "/cve-id/:id")
    assert get.guards == ["mw.rateLimiter", "mw.optionallyValidateUser", "param(...)",
                          "parseError"]
    assert get.handler == "controller.CVEID_GET_SINGLE"
    assert get.router_level == ["mw.requestLogger"]
    put = _by(decls, "PUT", "/cve-id/:id")
    assert put.guards == ["mw.validateUser", "mw.onlySecretariat", "mw.validateOrg"]
    delete = _by(decls, "DELETE", "/cve-id/:id")
    assert delete.guards == [] and delete.handler == "<inline function>"


def test_restx_gates_skip_documentation_and_include_method_decorators():
    decls = intent.declarations(RESTX, "website/web/api/v1/bundle.py")
    assert _by(decls, "GET", "/<string:bundle_uuid>").guards == []
    d = _by(decls, "DELETE", "/<string:bundle_uuid>")
    assert d.guards == ["typed(auth_func)", 'typed(permission_required("bundle:delete"))']
    assert d.handler == "BundleItem.delete"
    assert _by(decls, "GET", "/").guards == ["rate_limited (method_decorators)"]


def test_flask_and_fastapi_function_routes():
    decls = intent.declarations(FLASK, "app/views.py")
    for m in ("GET", "PUT"):
        assert _by(decls, m, "/<int:note_id>").guards == ["login_required"]
    assert _by(decls, "GET", "/{item_id}").guards == ["Depends(current_user)",
                                                      "Depends(verify_key)"]


def _spec(security_global=None, op_security=None, n_ops=3):
    paths = {f"/thing{i}": {"get": {"responses": {}}} for i in range(n_ops)}
    if op_security is not None:
        paths["/thing0"]["get"]["security"] = op_security
    doc = {"swagger": "2.0", "basePath": "/api", "paths": paths}
    if security_global is not None:
        doc["security"] = security_global
    return doc


def test_a_spec_wide_requirement_nobody_overrides_is_called_over_declaration():
    """VulnLookup's swagger.json: global apikey, no operation with its own security."""
    doc = _spec([{"apikey": []}])
    ops = intent.spec_operations(doc, "docs/swagger.json")
    s = ops[("GET", "/api/thing0")]
    assert s.level == "global" and s.ops_overriding == 0
    assert "over-declares" in s.describe() and "Not evidence of a check" in s.describe()
    note = intent.spec_note(doc, "docs/swagger.json")
    assert "OVER-DECLARES" in note and "3 operation(s)" in note


def test_per_operation_security_is_kept_apart_from_the_spec_wide_one():
    ops = intent.spec_operations(_spec([{"apikey": []}], [{"bearer": []}]), "s.json")
    assert ops[("GET", "/api/thing0")].level == "operation"
    other = ops[("GET", "/api/thing1")]
    assert other.level == "global" and other.ops_overriding == 1
    assert "weak evidence" in other.describe()
    assert intent.spec_operations(_spec([{"apikey": []}], []), "s.json")[
        ("GET", "/api/thing0")].level == "operation-none"
    assert intent.spec_operations(_spec(None, [{}, {"bearer": []}]), "s.json")[
        ("GET", "/api/thing0")].level == "operation-optional"
    assert intent.spec_operations(_spec(None), "s.json")[
        ("GET", "/api/thing1")].level == "none"


def _repo(tmp_path: Path) -> Path:
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "views.py").write_text(
        'from flask import Blueprint\n\nbp = Blueprint("notes", __name__, '
        'url_prefix="/notes")\n\n\n@bp.route("/<int:note_id>", methods=["DELETE"])\n'
        '@login_required\ndef delete(note_id):\n    return ""\n\n\n'
        '@bp.route("/public")\ndef public():\n    return ""\n')
    (tmp_path / "app" / "models.py").write_text("class Note:\n    pass\n")
    (tmp_path / "wsgi.py").write_text(
        "from flask import Flask\nfrom app import views\n\napp = Flask(__name__)\n"
        "app.register_blueprint(views.bp)\n")
    (tmp_path / "openapi.json").write_text(json.dumps({
        "openapi": "3.0.0", "security": [{"apikey": []}],
        "paths": {"/notes/{note_id}": {"delete": {}}, "/notes/public": {"get": {}}}}))
    return tmp_path


def test_build_ties_the_route_map_to_declarations_and_the_spec(tmp_path):
    m = intent.build(_repo(tmp_path))
    assert not m.error and m.specs == ["openapi.json"]
    by = {(r.method, r.path): r for r in m.routes}
    d = by[("DELETE", "/notes/<int:note_id>")]
    assert d.guards == ("login_required",) and d.spec.level == "global"
    assert by[("GET", "/notes/public")].guards == ()
    block = m.for_files(["app/views.py"])
    assert "Note on openapi.json" in block and "OVER-DECLARES" in block
    assert "nothing besides the handler" in block
    # A claim in a file that declares no routes gets its neighbours', said as such.
    near = m.for_file("app/models.py")
    assert "declared in files beside it" in near and "DELETE /notes/<int:note_id>" in near
    assert m.for_file("elsewhere/x.py") == ""


def test_build_is_best_effort(tmp_path, monkeypatch):
    def boom(self, src):
        raise RuntimeError("parser fell over")
    monkeypatch.setattr(intent.R.StaticRouteSource, "discover", boom)
    m = intent.build(tmp_path)
    assert m.routes == [] and "parser fell over" in m.error
    assert m.for_files(["x.py"]) == ""


def test_the_enclosing_symbol_of_a_quote(tmp_path):
    (tmp_path / "index.js").write_text(EXPRESS)
    (tmp_path / "bundle.py").write_text(RESTX)
    assert intent.locate(tmp_path, "index.js", "mw.rateLimiter,\n  mw.optionallyValidateUser,"
                         ) == "GET /cve-id/:id"
    assert intent.locate(tmp_path, "index.js", "mw.validateUser, [mw.onlySecretariat"
                         ) == "PUT /cve-id/:id"
    # Two Resources each have a delete or get; the class qualifies the method.
    assert intent.locate(tmp_path, "bundle.py", "@typed(auth_func)") == "BundleItem.delete"
    assert intent.locate(tmp_path, "bundle.py", "return [], 200") == "BundlesList.get"
    assert intent.locate(tmp_path, "bundle.py", "not in the file at all") is None
    assert intent.locate(tmp_path, "../outside.py", "anything") is None


def test_every_prompt_header_still_carries_the_tag():
    lens = next(l for l in E.CATALOGUE if l.key == "broken-authz-idor")
    f = E.Finding(lens=lens.key, model="qwen3.6:27b", title="t", file="a.js", quote="q",
                  severity="high", reasoning="", attacker_control="",
                  why_it_might_be_wrong="")
    tag = E.new_tag()
    for prompt in (E.hunt_prompt("body", lens, "m", tag, intent="- GET /x"),
                   E.refute_prompt("body", f, tag, intent="- GET /x", prior="judged")):
        headers = [l for l in prompt.splitlines() if l.startswith("===== ")]
        assert headers and all(f"===== {tag} " in h for h in headers)
        assert f"===== {tag} DECLARED ACCESS" in prompt
    assert f"===== {tag} PRIOR HUMAN VERDICT" in E.refute_prompt("b", f, tag, prior="x")
    # Without either, the prompts are what they were before item 20.
    assert "DECLARED ACCESS" not in E.hunt_prompt("body", lens, "m", tag)
    assert "PRIOR HUMAN VERDICT" not in E.refute_prompt("body", f, tag)


def _planned(tmp_path, lenses):
    src = tmp_path / "vol" / "src"
    src.mkdir(parents=True)
    (src / "routes").mkdir()
    (src / "routes" / "index.js").write_text(EXPRESS.replace("cve-id", "x") * 3)
    (src / "package.json").write_text('{"scripts": {"start": "node ."}, '
                                      '"dependencies": {"express": "4"}}')
    con = db.init(tmp_path / "t.db")
    con.execute("INSERT INTO runs (id,target,clone_url,status) VALUES (1,'o/r','x','done')")
    rid, _, chosen = runner.plan(con, 1, src, models=["qwen3.6:27b", "devstral:24b"],
                                 lenses=lenses)
    return con, rid, src, chosen


def test_only_the_authz_lens_hunts_with_declared_access(tmp_path, monkeypatch):
    con, rid, src, chosen = _planned(tmp_path, ["broken-authz-idor", "error-and-disclosure"])
    assert {l.key for l in chosen} == {"broken-authz-idor", "error-and-disclosure"}
    prompts: list[tuple[str, str]] = []

    def fake_call(model, prompt, schema, *, num_ctx=0, num_predict=0):
        lens = prompt.split("YOUR LENS: ")[1].split(" ")[0].strip() if "YOUR LENS" in \
            prompt else "refute"
        prompts.append((lens, prompt))
        return json.dumps({"findings": []}), {}

    monkeypatch.setattr(E, "call", fake_call)
    monkeypatch.setattr(E, "model_provenance", lambda models: {})
    stats = runner.execute(con, rid, src, progress=lambda *_: None)
    authz = [p for k, p in prompts if k.startswith("broken-authz-idor")]
    other = [p for k, p in prompts if k.startswith("error-and-disclosure")]
    assert len(authz) == 2 and len(other) == 2
    assert all("DECLARED ACCESS" in p and "mw.optionallyValidateUser" in p for p in authz)
    assert not any("DECLARED ACCESS" in p for p in other)
    assert {"hunt_seconds", "refute_seconds", "prior_intended"} <= set(stats)
    manifest = json.loads(con.execute("SELECT manifest FROM runs WHERE id=1").fetchone()[0])
    assert manifest["deep"][str(rid)]["route_intent"]["routes"] > 0


def test_route_intent_off_reproduces_the_old_prompt(tmp_path, monkeypatch):
    con, rid, src, _ = _planned(tmp_path, ["broken-authz-idor"])
    prompts: list[str] = []
    monkeypatch.setattr(E, "call", lambda m, p, s, **k: (prompts.append(p) or
                                                         json.dumps({"findings": []}), {}))
    monkeypatch.setattr(E, "model_provenance", lambda models: {})
    runner.execute(con, rid, src, progress=lambda *_: None, route_intent=False)
    assert prompts and not any("DECLARED ACCESS" in p for p in prompts)
    manifest = json.loads(con.execute("SELECT manifest FROM runs WHERE id=1").fetchone()[0])
    assert manifest["deep"][str(rid)]["route_intent"] == {"disabled": True}


def test_a_lens_filter_never_adds_a_lens_the_profile_rejected(tmp_path):
    _, _, _, chosen = _planned(tmp_path, ["broken-authz-idor", "multi-tenancy-isolation"])
    assert [l.key for l in chosen] == ["broken-authz-idor"]
