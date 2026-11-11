"""The cross-user authz probe (decision D): account A addressing account B's record,
against B's own request (baseline) and the anonymous client (control).

A stateful fake stands in for VulnLookup's API: X-API-KEY auth, a create-or-update POST
on the collection, public reads, and deletes and updates allowed to the record's owner
and the admin. Switches turn each check's bug on. The probe may create two canary records
as the owner and must leave neither behind, touch nothing else, and never store a key.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quarry.dynamic.validate import (                                         # noqa: E402
    Candidate, RunningTarget, adjudicate, adjudicate_with_reason, NO_BASELINE)
from quarry.dynamic.routes import Route, StaticRouteSource                    # noqa: E402
from quarry.dynamic.probes import probe_authz, probe_cross_user               # noqa: E402
from quarry.dynamic.seed import CrossUser, OwnedResource, get as get_recipe   # noqa: E402
from fakecurl import Reply, curl                                              # noqa: E402

KEYS = {"k-admin-000000000001": ("quarry_admin", True),
        "k-user-0000000000002": ("quarry_user", False),
        "k-user2-000000000003": ("quarry_user2", False)}
CREDS = {"admin_api_key": "k-admin-000000000001", "user_api_key": "k-user-0000000000002",
         "user2_api_key": "k-user2-000000000003"}
SIGHTING = OwnedResource(
    name="sighting", collection="/api/sighting/", item="/api/sighting/{id}",
    body='{"uuid": "{id}", "vulnerability": "{vulnerability_id}", "type": "seen", '
         '"source": "quarry-canary-{marker}"}',
    owner="user_api_key", other="user2_api_key", modify="post-collection")
SPEC = CrossUser(header="X-API-KEY",
                 accounts={"admin_api_key": "quarry_admin", "user_api_key": "quarry_user",
                           "user2_api_key": "quarry_user2"},
                 resources=(SIGHTING,))


def _running(**kw):
    return RunningTarget(base_url="http://web:10001", stop=lambda: None, network="net",
                         credentials=dict(CREDS), cross_user=SPEC,
                         param_values={"vulnerability_id": "CVE-2021-44228"}, **kw)


def _cand(line=5, cwe="CWE-639"):
    return Candidate("f1", 1, "o/r", "website/api/sighting.py", line, "prod", cwe, "idor")


def _routes(method, path="/api/sighting/<uuid:sighting_uuid>", line=5):
    """One static route in the finding's file whose handler encloses `line`."""
    return [Route(method, path, "website/api/sighting.py", "static", line=line - 2,
                  end_line=line + 2)]


class VL:
    """A VulnLookup-shaped store. `delete_any`, `modify_any`: any authenticated account
    may delete or update any record (the bug). `public`: GET needs no key."""

    def __init__(self, *, delete_any=False, modify_any=False, public=True,
                 anon_delete=False, check_after_write=False, owner_cannot_delete=False):
        self.records: dict[str, dict] = {}
        self.delete_any, self.modify_any, self.public = delete_any, modify_any, public
        self.anon_delete, self.check_after_write = anon_delete, check_after_write
        self.owner_cannot_delete = owner_cannot_delete
        self.fake = curl(self.handle)

    def who(self, req):
        return KEYS.get(req.headers.get("x-api-key", ""), (None, False))

    def may(self, req, rec, any_flag):
        login, admin = self.who(req)
        return admin or login == rec["owner"] or (any_flag and login is not None)

    def handle(self, req):
        login, _ = self.who(req)
        if req.path.rstrip("/") == "/api/sighting" and req.method == "POST":
            if login is None:
                return Reply(401, '{"Error": "Authentication required."}', "application/json")
            doc = json.loads(req.data)
            rec = self.records.get(doc["uuid"])
            if rec is None:
                self.records[doc["uuid"]] = {"owner": login, **doc}
                return Reply(201, json.dumps({"data": doc}), "application/json")
            if self.check_after_write:
                rec.update(doc)                          # the bug: write, then check
            if not self.may(req, rec, self.modify_any):
                return Reply(403, '{"message": "no"}', "application/json")
            rec.update(doc)
            return Reply(201, json.dumps({"data": rec}), "application/json")
        if req.path.startswith("/api/sighting/"):
            rid = req.path.rsplit("/", 1)[-1]
            rec = self.records.get(rid)
            if req.method == "GET":
                if not self.public and login is None:
                    return Reply(401, "{}", "application/json")
                if rec is None or (not self.public and not self.may(req, rec, False)):
                    return Reply(404, '{"message": "Sighting not found."}', "application/json")
                return Reply(200, json.dumps(rec, sort_keys=True), "application/json")
            if req.method == "DELETE":
                if login is None and not self.anon_delete:
                    return Reply(401, '{"Error": "Authentication required."}',
                                 "application/json")
                if rec is None:
                    return Reply(404, '{"message": "Sighting not found."}', "application/json")
                if login is not None and (self.owner_cannot_delete
                                          or not self.may(req, rec, self.delete_any)):
                    return Reply(403, '{"message": "no"}', "application/json")
                del self.records[rid]
                return Reply(200, '{"message": "Sighting deleted successfully."}',
                             "application/json")
        return Reply(404, "{}", "application/json")


def _no_secret(ev):
    text = " ".join([ev.summary, ev.request, ev.observed, ev.baseline])
    assert not any(k in text for k in KEYS), text


def _only_canaries(vl, ev):
    """Every state-changing request named one of the two records the probe made, and the
    probe left nothing behind."""
    made = {json.loads(r.data)["uuid"] for r in vl.fake.requests
            if r.method == "POST" and r.headers.get("x-api-key") == CREDS["user_api_key"]}
    for r in vl.fake.requests:
        if r.method == "DELETE":
            assert r.path.rsplit("/", 1)[-1] in made, r.path
        if r.method == "POST":
            assert json.loads(r.data)["uuid"] in made
    assert vl.records == {}, vl.records
    assert "contained throwaway instance" in ev.summary          # recorded in the verdict


# ---- delete ----

def test_delete_is_rejected_when_ownership_is_enforced():
    vl = VL()
    ev = probe_cross_user(_running(), _cand(), _routes("DELETE"), vl.fake)
    assert ev.reproduced is False and ev.handled is True
    assert ev.differs_from_baseline is False and adjudicate(ev) == "rejected"
    assert "quarry_user2 was refused" in ev.summary and "403" in ev.summary
    _only_canaries(vl, ev)
    _no_secret(ev)


def test_delete_is_confirmed_when_another_account_can_delete():
    vl = VL(delete_any=True)
    ev = probe_cross_user(_running(), _cand(), _routes("DELETE"), vl.fake)
    assert ev.reproduced is True and ev.differs_from_baseline is True
    assert adjudicate(ev) == "confirmed"
    assert "owner then got 404" in ev.summary and "401" in ev.summary
    _only_canaries(vl, ev)
    _no_secret(ev)


def test_an_anonymous_delete_is_held_not_confirmed():
    # The anonymous request is the negative control; when it succeeds the comparison is
    # gone, so a human reviews what is plainly a missing-authentication bug.
    vl = VL(anon_delete=True)
    ev = probe_cross_user(_running(), _cand(), _routes("DELETE"), vl.fake)
    assert ev.reproduced is True
    assert adjudicate_with_reason(ev) == ("needs-review", NO_BASELINE)
    assert vl.records == {}


def test_no_baseline_when_the_owner_cannot_delete_its_own_record():
    vl = VL(owner_cannot_delete=True)
    ev = probe_cross_user(_running(), _cand(), _routes("DELETE"), vl.fake)
    assert adjudicate(ev) == "needs-review" and "could not delete its own" in ev.summary
    assert "could not be deleted and remains" in ev.summary    # said, not hidden


# ---- read ----

def test_a_public_read_crosses_no_boundary():
    vl = VL(public=True)
    ev = probe_cross_user(_running(), _cand(), _routes("GET"), vl.fake)
    assert adjudicate(ev) == "needs-review" and "anonymous" in ev.summary
    assert vl.records == {}


def test_a_private_read_is_rejected_when_another_account_is_refused():
    vl = VL(public=False)
    ev = probe_cross_user(_running(), _cand(), _routes("GET"), vl.fake)
    assert adjudicate(ev) == "rejected"
    _no_secret(ev)


def test_a_private_read_is_confirmed_when_another_account_gets_the_owners_record():
    class Leaky(VL):
        def may(self, req, rec, any_flag):
            return self.who(req)[0] is not None           # any account reads any record
    vl = Leaky(public=False)
    ev = probe_cross_user(_running(), _cand(), _routes("GET"), vl.fake)
    assert adjudicate(ev) == "confirmed" and "exact response" in ev.summary


# ---- modify ----

def _modify_routes(line=5):
    return _routes("POST", path="/api/sighting/", line=line)


def test_modify_is_rejected_when_refused_and_unchanged():
    vl = VL()
    ev = probe_cross_user(_running(), _cand(), _modify_routes(), vl.fake)
    assert adjudicate(ev) == "rejected" and "unchanged on read-back" in ev.summary
    _only_canaries(vl, ev)


def test_modify_is_confirmed_when_another_accounts_change_is_stored():
    vl = VL(modify_any=True)
    ev = probe_cross_user(_running(), _cand(), _modify_routes(), vl.fake)
    assert adjudicate(ev) == "confirmed"
    _only_canaries(vl, ev)


def test_a_403_after_the_write_is_still_a_confirmation():
    # Write first, check second: the status says no, the record says yes. The read-back
    # is what decides, which is why a modify check needs one.
    vl = VL(check_after_write=True)
    ev = probe_cross_user(_running(), _cand(), _modify_routes(), vl.fake)
    assert adjudicate(ev) == "confirmed" and "answered 403" in ev.summary


# ---- scope and fallbacks ----

def test_a_finding_outside_the_handler_is_measured_but_held():
    vl = VL(delete_any=True)
    ev = probe_cross_user(_running(), _cand(line=80), _routes("DELETE", line=5), vl.fake)
    assert ev.reproduced is True and ev.differs_from_baseline is None
    assert adjudicate(ev) == "needs-review" and "held for review" in ev.summary
    assert vl.records == {}


def test_missing_credentials_send_nothing():
    vl = VL()
    running = _running()
    running.credentials.pop("user2_api_key")
    ev = probe_cross_user(running, _cand(), _routes("DELETE"), vl.fake)
    assert adjudicate(ev) == "untested" and vl.fake.requests == []
    assert "user2_api_key" in ev.summary


def test_no_declared_resource_falls_back_to_the_anonymous_probe():
    other = [Route("GET", "/api/vulnerability/<string:vid>", "website/api/sighting.py",
                   "static", line=3, end_line=7)]
    fake = curl(lambda req: Reply(200, "{}", "application/json"))
    assert probe_cross_user(_running(), _cand(), other, fake) is None
    ev = probe_authz(_running(), _cand(), other, fake)
    assert "declared auth-protected" in ev.summary          # the anonymous probe answered


def test_without_a_seed_spec_the_authz_lens_is_the_anonymous_probe():
    running = RunningTarget(base_url="http://web:10001", stop=lambda: None)
    fake = curl(lambda req: Reply(200, "{}"))
    assert probe_cross_user(running, _cand(), _routes("DELETE"), fake) is None


@pytest.mark.parametrize("name", ["bundle", "sighting", "comment"])
def test_the_vulnlookup_resources_match_the_routes_static_extraction_finds(tmp_path, name):
    """The recipe's paths must key-match the static routes for VulnLookup's Flask-RESTX
    layout, or the probe never fires. A minimal copy of that layout, mounted the same way
    (Api on an /api blueprint, add_namespace(path=)), is enough to pin it."""
    (tmp_path / "api").mkdir()
    (tmp_path / "api" / "__init__.py").write_text(
        "bp = Blueprint('apiv1', __name__, url_prefix='/api')\n"
        "def setup():\n"
        "    api = Api(bp)\n"
        f"    from api import {name}\n"
        f"    api.add_namespace({name}.ns, path='/{name}')\n")
    conv = "uuid" if name == "sighting" else "string"
    (tmp_path / "api" / f"{name}.py").write_text(
        f"ns = Namespace('{name}')\n"
        f"@ns.route('/<{conv}:{name}_uuid>')\n"
        "class Item(Resource):\n"
        "    def get(self, x):\n"
        "        return {}\n"
        "    def delete(self, x):\n"
        "        return {}\n"
        "@ns.route('/')\n"
        "class Items(Resource):\n"
        "    def post(self):\n"
        "        return {}\n")
    static = {r.key for r in StaticRouteSource().discover(tmp_path)}
    res = next(r for r in get_recipe("vulnlookup").cross_user.resources if r.name == name)
    from quarry.dynamic.routes import _norm_path
    assert ("DELETE", _norm_path(res.item)) in static
    assert ("GET", _norm_path(res.item)) in static
    assert ("POST", _norm_path(res.collection)) in static
