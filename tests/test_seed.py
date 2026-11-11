"""Seeding runs the target's own documented commands in the contained instance to make
it testable: test accounts (and their API keys) and real probe inputs. A step failure is
recorded, never fatal, and the probes stay read-only.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quarry.dynamic import seed as S                               # noqa: E402
from quarry.dynamic.seed import SeedRecipe, SeedStep, run_seed, SeedError  # noqa: E402


class FakeRuntime:
    """Records service_exec calls and answers from a canned map keyed by the command."""
    def __init__(self, answers=None):
        self.calls: list[tuple[str, list[str]]] = []
        self.answers = answers or {}

    def service_exec(self, running, argv, *, service="", timeout=900):
        self.calls.append((service, argv))
        for key, (rc, out) in self.answers.items():
            if key in argv:
                return rc, out
        return 0, ""


def _recipe(**kw):
    base = dict(name="t", steps=(SeedStep(argv=("echo", "hi"), describe="hi"),))
    base.update(kw)
    return SeedRecipe(**base)


def test_captures_a_value_and_substitutes_the_generated_password():
    recipe = SeedRecipe(name="t", param_values={"id": "CVE-1"}, steps=(
        SeedStep(argv=("mkuser", "--password", "{password}"), describe="make user"),
        SeedStep(argv=("getkey", "admin"), capture=r"([0-9A-Za-z]{10,})",
                 capture_as="admin_api_key", describe="get key"),
    ))
    rt = FakeRuntime({"getkey": (0, "key=ABC123def456XYZ\n")})
    res = run_seed(rt, object(), recipe)
    assert res.param_values == {"id": "CVE-1"}
    assert res.credentials == {"admin_api_key": "ABC123def456XYZ"}
    # {password} was replaced by a real secret, the same one across steps, never literal.
    pw_arg = rt.calls[0][1][-1]
    assert pw_arg != "{password}" and len(pw_arg) >= 16


def test_an_optional_step_failure_is_recorded_not_fatal():
    recipe = _recipe(steps=(
        SeedStep(argv=("boom",), describe="boom", optional=True),
        SeedStep(argv=("fine",), describe="fine"),
    ))
    rt = FakeRuntime({"boom": (3, "nope")})
    res = run_seed(rt, object(), recipe)
    assert any("boom" in n and "rc=3" in n for n in res.notes)
    assert ("", ["fine"]) in rt.calls              # kept going after the failure


def test_a_required_step_failure_raises():
    recipe = _recipe(steps=(SeedStep(argv=("boom",), optional=False, describe="boom"),))
    with pytest.raises(SeedError):
        run_seed(FakeRuntime({"boom": (1, "x")}), object(), recipe)


def test_a_runtime_without_service_exec_is_a_recorded_gap():
    class NoExec:
        pass
    res = run_seed(NoExec(), object(), _recipe())
    assert res.credentials == {} and any("service exec" in n for n in res.notes)


def test_a_capture_that_does_not_match_is_noted_without_inventing_a_value():
    recipe = _recipe(steps=(SeedStep(argv=("getkey",), capture=r"KEY=(\w+)",
                                     capture_as="admin_api_key", describe="get key"),))
    res = run_seed(FakeRuntime({"getkey": (0, "No such user.")}), object(), recipe)
    assert "admin_api_key" not in res.credentials
    assert any("not found" in n for n in res.notes)


def test_the_vulnlookup_recipe_uses_the_projects_own_commands():
    r = S.get("vulnlookup")
    assert r is not None and "vulnlookup" in S.names()
    cmds = [st.argv for st in r.steps]
    assert any("create_admin" in a for a in cmds)
    assert any("create_user" in a for a in cmds)
    assert sum("user_get_api_key" in a for a in cmds) == 3    # one per account
    # Every step runs the project's own Flask CLI; nothing reaches into a datastore.
    assert all(a[:5] == ("poetry", "run", "flask", "--app", "website.app") for a in cmds)
    assert r.param_values.get("vulnerability_id", "").startswith("CVE-")
    # No credential is hard-coded: accounts use the generated {password} placeholder.
    assert all("{password}" in a or "user_get_api_key" in a for a in cmds)


# A key shaped like VulnLookup's, `secrets.token_urlsafe(64)`: 86 characters, with `-`
# and `_` in it. The old capture, `([0-9A-Za-z]{16,})`, took the first run of letters
# and digits only, a fragment the target answered with 401.
VL_KEY = ("Xq3-vT9_kLm2PzR8wNcY4bHs6JdF1gAeU7oKiQ5tZrWx0Cy-MnB_pVfGh3LsDj9Ek2Ra6Tu8Wq1Yz4Nc7Op"
          "5Ab")


def test_the_vulnlookup_key_capture_takes_the_whole_key():
    assert len(VL_KEY) == 86 and "-" in VL_KEY and "_" in VL_KEY
    step = next(st for st in S.get("vulnlookup").steps if st.capture_as == "admin_api_key")
    # Lines of the kind a CLI may print before the key, a poetry notice and a log line
    # with a long word in it; made up for the test, not copied from VulnLookup's output.
    out = ("Skipping virtualenv creation, as specified in config file.\n"
           "WARNING:website.web.bootstrap:VulnerabilityLookupInstanceConfiguration loaded\n"
           f"{VL_KEY}\n")
    recipe = SeedRecipe(name="t", steps=(step,))
    res = run_seed(FakeRuntime({"user_get_api_key": (0, out)}), object(), recipe)
    assert res.credentials == {"admin_api_key": VL_KEY}


def test_the_vulnlookup_key_capture_invents_nothing_for_a_missing_user():
    step = next(st for st in S.get("vulnlookup").steps if st.capture_as == "user_api_key")
    res = run_seed(FakeRuntime({"user_get_api_key": (0, "No such user.\n")}), object(),
                   SeedRecipe(name="t", steps=(step,)))
    assert "user_api_key" not in res.credentials


def test_the_vulnlookup_cross_user_spec_uses_only_keys_the_recipe_captures():
    import json
    r = S.get("vulnlookup")
    captured = {st.capture_as for st in r.steps if st.capture_as}
    spec = r.cross_user
    assert spec is not None and spec.header == "X-API-KEY"
    assert set(spec.accounts) == captured
    for res in spec.resources:
        assert {res.owner, res.other} <= captured and res.owner != res.other
        assert "{id}" in res.item and res.collection.endswith("/")
        # The body is valid JSON once filled, carries the probe's own id, and puts no CVE
        # id in free text (a bundle adds a sighting for each one it finds there).
        filled = res.body.replace("{id}", "00000000-0000-4000-8000-000000000000") \
                         .replace("{marker}", "qz00").replace("{vulnerability_id}", "CVE-1")
        doc = json.loads(filled)
        assert doc["uuid"].startswith("00000000")
        assert "CVE" not in doc.get("description", "") + doc.get("name", "")
    # Peers for the records plain users can create; the admin's bundle against a user.
    owners = {res.name: (res.owner, res.other) for res in spec.resources}
    assert owners["sighting"] == owners["comment"] == ("user_api_key", "user2_api_key")
    assert owners["bundle"] == ("admin_api_key", "user_api_key")


# The bundle POST fills in uuid, origin and both timestamps, then validates against
# Security_Advisory_Bundle.json (VulnLookup 7d77b9b): no property outside this set
# (additionalProperties is false), name and description required, and
# related_vulnerabilities a list of at least one non-empty string.
VL_BUNDLE_PROPERTIES = {"uuid", "vulnerability_lookup_origin", "creation_timestamp",
                        "timestamp", "name", "description", "description_format",
                        "related_vulnerabilities", "meta"}


def test_the_vulnlookup_bundle_canary_passes_the_bundle_schema():
    """The canary sent `related_vulnerabilities: []` and its description named no CVE, so
    the list stayed empty, failed `minItems: 1`, and all 8 bundle creates on 2026-11-10
    were answered 400."""
    import json
    r = S.get("vulnlookup")
    res = next(x for x in r.cross_user.resources if x.name == "bundle")
    doc = json.loads(res.body.replace("{id}", "00000000-0000-4000-8000-000000000000")
                     .replace("{marker}", "qz00")
                     .replace("{vulnerability_id}", r.param_values["vulnerability_id"]))
    assert set(doc) <= VL_BUNDLE_PROPERTIES
    assert isinstance(doc["name"], str) and isinstance(doc["description"], str)
    rel = doc["related_vulnerabilities"]
    assert isinstance(rel, list) and rel and all(isinstance(v, str) and v for v in rel)
    assert rel == ["CVE-2021-44228"], "the one entry is the probe's own CVE"


def test_a_recipe_hands_its_cross_user_spec_to_the_probes():
    spec = S.CrossUser(header="X-API-KEY")
    res = run_seed(FakeRuntime(), object(), _recipe(cross_user=spec))
    assert res.cross_user is spec
