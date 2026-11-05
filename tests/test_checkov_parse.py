"""Checkov's SARIF report, parsed hermetically (IMPROVEMENT-PLAN P4, item 1).

`results_sarif.sarif` is written by a tool that read the target, so every `uri` in it
is target-influenced. Each one must cross `rel_or_none` and the taint boundary: kept as
a clone-relative path, or dropped. A hostile or malformed entry costs that one finding
(or, for a document whose structure is broken, the tool's output, loudly). It never
becomes a row with an unvalidated path, and it never costs the good findings beside it.

The live test in test_scanner_argv.py needs checkov installed and shows the argv gives
clone-relative uris. These need nothing installed and pin what the parser does with
whatever the report says.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quarry import db, orchestrator                       # noqa: E402
from quarry.scanners import base, tools                   # noqa: E402
from quarry.scanners.base import rel_or_none              # noqa: E402
from test_scan_bookkeeping import _scan_env               # noqa: E402

DOCKERFILE = "FROM python:3.12\nRUN pip install flask\nCMD [\"python\"]\n"


def _result(uri, *, rule="CKV_DOCKER_2", line=1, message="Ensure HEALTHCHECK"):
    loc = {"physicalLocation": {"artifactLocation": {"uri": uri},
                                "region": {"startLine": line, "endLine": line + 1}}}
    return {"ruleId": rule, "level": "error", "message": {"text": message},
            "locations": [loc]}


def _sarif(results) -> dict:
    return {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "Checkov", "rules": [
            {"id": "CKV_DOCKER_2", "properties": {"tags": ["CWE-693"]}},
            "not a rule"]}},
        "results": results}]}


@pytest.fixture
def vol(tmp_path):
    """A run volume: the clone at src/, Checkov's report under out/, and host files
    beside it that no finding may name."""
    mount = tmp_path / "vol"
    src = mount / "src"
    for rel in ("Dockerfile", "docker/Dockerfile", "src/Dockerfile", "deploy/Dockerfile",
                "ci/Dockerfile"):
        (src / rel).parent.mkdir(parents=True, exist_ok=True)
        (src / rel).write_text(DOCKERFILE)
    (mount / "out").mkdir()
    outside = tmp_path / "home"
    outside.mkdir()
    (outside / "Dockerfile").write_text(DOCKERFILE)
    (outside / "id_rsa").write_text("-----BEGIN OPENSSH PRIVATE KEY-----\n")
    (src / "link").symlink_to(outside)
    sibling = mount / "src-evil"             # shares the clone's path as a prefix
    sibling.mkdir()
    (sibling / "Dockerfile").write_text(DOCKERFILE)
    return mount


def _hostile(vol: Path) -> list:
    src, outside = vol / "src", vol.parent / "home"
    return [
        "/etc/passwd",                                      # absolute, outside
        str(outside / "Dockerfile"),                        # absolute, a real host file
        str(vol / "out" / "checkov.json"),                  # absolute, on the run volume
        "../out/results_sarif.sarif",                       # escapes to the run volume
        "../../home/id_rsa",                                # escapes to a host file
        "docker/../../../home/Dockerfile",                  # escapes after normalising
        "file:///etc/shadow",                               # scheme plus absolute
        f"file://{outside}/Dockerfile",                     # scheme plus host file
        "https://evil.example/Dockerfile",                  # remote scheme
        str(vol / "src-evil" / "Dockerfile"),               # the clone's path as a prefix
        "link/id_rsa",                                      # a symlink out of the clone
        "Dockerfile\x1b[31m",                               # ANSI in a path
        "Docker\u202efile",                                 # bidi override in a path
        "Dockerfile\x00.txt",                               # NUL
        "C:\\Users\\op\\.ssh\\id_rsa",                      # a drive letter
        "",                                                 # empty
        None,                                               # missing
        7, ["Dockerfile"], {"uri": "Dockerfile"},           # not a string at all
    ]


GOOD = {"Dockerfile", "docker/Dockerfile", "src/Dockerfile", "deploy/Dockerfile",
        "ci/Dockerfile"}


def _good(vol: Path) -> list:
    src = (vol / "src").resolve()
    return [
        _result("Dockerfile", line=2),
        _result("docker/Dockerfile"),
        # A repo's own top-level src/ is kept as it is: a prefix strip would have
        # turned this into a path to the root Dockerfile.
        _result("src/Dockerfile"),
        _result(str(src / "deploy" / "Dockerfile")),        # absolute, inside the clone
        _result(f"file://{src}/ci/Dockerfile"),             # file:// inside the clone
    ]


def _write_report(vol: Path, doc) -> Path:
    report = vol / "out" / "results_sarif.sarif"
    report.write_text(doc if isinstance(doc, str) else json.dumps(doc))
    return vol / "out" / "checkov.json"


@pytest.mark.parametrize("uri", [7, 3.5, True, ["Dockerfile"], {"uri": "Dockerfile"}])
def test_rel_or_none_drops_a_path_that_is_not_a_string(tmp_path, uri):
    """rel_or_none promises that one malformed path costs one finding. A uri that was
    not a string raised AttributeError instead, and the parser's caller turned that
    into a failed tool: every Checkov finding in the report was lost to one entry."""
    (tmp_path / "Dockerfile").write_text(DOCKERFILE)
    assert rel_or_none(uri, tmp_path) is None


def test_checkov_paths_are_relative_to_the_clone_and_kept_as_given(vol):
    out = _write_report(vol, _sarif(_good(vol)))
    recs = list(tools.Checkov().parse(out, vol / "src"))
    assert sorted(r.path for r in recs) == sorted(GOOD)
    assert all((vol / "src" / r.path).is_file() for r in recs)
    by_path = {r.path: r for r in recs}
    root = by_path["Dockerfile"]
    assert (root.tool, root.rule_id, root.start_line, root.end_line) == (
        "checkov", "CKV_DOCKER_2", 2, 3)
    assert root.cwe == "CWE-693" and root.severity == "high"


def test_hostile_checkov_uris_are_dropped_and_cost_only_themselves(vol):
    """Every hostile uri sits in one report beside the good ones. Each must be dropped
    on its own: none may become a record, and none may take the good findings with it."""
    hostile = _hostile(vol)
    results = _good(vol) + [_result(u, rule=f"CKV_HOSTILE_{i}") for i, u in enumerate(hostile)]
    out = _write_report(vol, _sarif(results))
    recs = list(tools.Checkov().parse(out, vol / "src"))
    assert sorted(r.path for r in recs) == sorted(GOOD)
    assert not [r for r in recs if r.rule_id.startswith("CKV_HOSTILE_")]
    for r in recs:
        assert not Path(r.path).is_absolute() and ".." not in Path(r.path).parts
        assert (vol / "src" / r.path).resolve().is_relative_to((vol / "src").resolve())


def test_checkov_message_is_scrubbed_and_snippet_is_not_kept(vol):
    res = _result("Dockerfile", message="ok\x1b[2J\x1b[31m red \u202eevil")
    res["locations"][0]["physicalLocation"]["region"]["snippet"] = {"text": "AWS_KEY=x"}
    out = _write_report(vol, _sarif([res]))
    (rec,) = tools.Checkov().parse(out, vol / "src")
    assert "\x1b" not in rec.message and "\u202e" not in rec.message
    assert "snippet" not in json.dumps(rec.raw)


@pytest.mark.parametrize("results", [
    ["a string", 7, None, ["list"]],                                    # non-dict results
    [{"ruleId": "CKV_X"}],                                              # no locations
    [{"ruleId": "CKV_X", "locations": []}],                             # empty locations
    [{"ruleId": "CKV_X", "locations": [{}]}],                           # no physicalLocation
    [{"ruleId": "CKV_X", "locations": [{"physicalLocation": {}}]}],     # no artifactLocation
    [{"ruleId": "CKV_X",
      "locations": [{"physicalLocation": {"artifactLocation": {}}}]}],  # no uri
], ids=["non-dict", "no-locations", "empty-locations", "no-physical", "no-artifact",
        "no-uri"])
def test_checkov_results_missing_fields_are_dropped_one_at_a_time(vol, results):
    out = _write_report(vol, _sarif(_good(vol) + results))
    recs = list(tools.Checkov().parse(out, vol / "src"))
    assert sorted(r.path for r in recs) == sorted(GOOD)


def test_a_checkov_result_without_rule_or_region_keeps_its_validated_path(vol):
    res = {"locations": [{"physicalLocation": {"artifactLocation": {"uri": "Dockerfile"}}}]}
    out = _write_report(vol, _sarif([res]))
    (rec,) = tools.Checkov().parse(out, vol / "src")
    assert (rec.path, rec.rule_id, rec.start_line, rec.message) == (
        "Dockerfile", "unknown", None, "")


class _Res:
    returncode, duration_s = 1, 0.1             # checkov exits 1 when a check fails

    def stderr_bytes(self) -> bytes:
        return b""


def _run_with_report(vol: Path, monkeypatch, doc):
    """Checkov.run end to end with the sandboxed child replaced by one that writes `doc`
    as the report, so the outcome is what Scanner.run makes of a parse."""
    ck = tools.Checkov()
    monkeypatch.setattr(ck, "available", lambda: "/usr/local/bin/checkov")

    def fake_tier1(rundir, argv, *, name, cwd, timeout, **kw):
        _write_report(vol, doc)
        return _Res()

    monkeypatch.setattr(base, "tier1", fake_tier1)
    return ck.run(vol, vol / "src", timeout=60)


@pytest.mark.parametrize("bad", [
    {"ruleId": "X", "locations": ["Dockerfile"]},
    {"ruleId": "X", "locations": {"0": {}}},
    {"ruleId": "X", "locations": [{"physicalLocation": "/etc/passwd"}]},
    {"ruleId": "X", "locations": [{"physicalLocation": {"artifactLocation": "/etc/passwd"}}]},
    {**_result("Dockerfile"), "message": "not a mapping"},
    {**_result("Dockerfile"), "properties": "not a mapping"},
    {**_result("Dockerfile"), "partialFingerprints": ["x"]},
], ids=["location-str", "locations-dict", "physical-str", "artifact-str", "message-str",
        "properties-str", "fingerprints-list"])
def test_a_damaged_checkov_result_is_dropped_or_refused_never_stored(vol, monkeypatch, bad):
    """One structurally damaged result beside the good ones may cost that result or the
    whole report, but only loudly: the outcome is a success carrying every good finding
    and nothing else, or a failure with an error. Never a success built on a path that
    skipped the boundary, and never a success that quietly lost the good findings."""
    outcome = _run_with_report(vol, monkeypatch, _sarif(_good(vol) + [bad]))
    if outcome.ok:
        assert sorted(r.path for r in outcome.records) == sorted(GOOD)
    else:
        assert outcome.error and outcome.records == []


@pytest.mark.parametrize("doc", [
    [_result("/etc/passwd")],                                   # a list, not a log
    {"runs": {"tool": {}, "results": [_result("/etc/passwd")]}},
    {"runs": ["not a run"]},
    "{not json",
], ids=["doc-list", "runs-dict", "run-str", "not-json"])
def test_a_report_that_is_not_a_sarif_log_is_refused_not_read_as_clean(vol, monkeypatch,
                                                                       doc):
    """A report Quarry cannot read is a failed tool, not a scan that found nothing."""
    outcome = _run_with_report(vol, monkeypatch, doc)
    assert not outcome.ok and outcome.error and outcome.records == []


def test_hostile_checkov_paths_never_reach_the_database(tmp_path, monkeypatch):
    """Through orchestrator.scan with the real adapter: only validated paths become
    findings, occurrences and evidence, and the hostile results leave no row at all."""
    ck = tools.Checkov()
    c, paths = _scan_env(tmp_path, monkeypatch, {"checkov": ck})
    mount = tmp_path / "vol"
    src = mount / "src"
    for rel in GOOD:
        (src / rel).parent.mkdir(parents=True, exist_ok=True)
        (src / rel).write_text(DOCKERFILE)
    (mount / "out").mkdir()
    outside = tmp_path / "home"
    outside.mkdir()
    (outside / "Dockerfile").write_text(DOCKERFILE)
    (outside / "id_rsa").write_text("-----BEGIN OPENSSH PRIVATE KEY-----\n")
    (src / "link").symlink_to(outside)
    (mount / "src-evil").mkdir()
    (mount / "src-evil" / "Dockerfile").write_text(DOCKERFILE)
    hostile = _hostile(mount)
    doc = _sarif(_good(mount) + [_result(u, rule="CKV_HOSTILE") for u in hostile])
    monkeypatch.setattr(ck, "available", lambda: "/usr/local/bin/checkov")
    monkeypatch.setattr(base, "tier1", lambda *a, **kw: (_write_report(mount, doc), _Res())[1])

    s = orchestrator.scan(paths, c, 1)

    assert s.per_tool["checkov"]["ok"] and s.per_tool["checkov"]["records"] == len(GOOD)
    stored = {
        "occurrences": [r[0] for r in c.execute("SELECT path FROM occurrences")],
        "findings": [r[0] for r in c.execute("SELECT path FROM findings")],
        "evidence_blobs": [r[0] for r in c.execute("SELECT path FROM evidence_blobs")],
    }
    assert set(stored["occurrences"]) == set(stored["findings"]) == GOOD
    # Windows are content-addressed, so identical Dockerfiles share one blob.
    assert stored["evidence_blobs"] and set(stored["evidence_blobs"]) <= GOOD
    assert not c.execute("SELECT 1 FROM occurrences WHERE blob_sha IS NULL").fetchone()
    assert not c.execute("SELECT 1 FROM producers WHERE rule_id='CKV_HOSTILE'").fetchone()
    raws = " ".join(r[0] for r in c.execute("SELECT raw_result FROM occurrences"))
    for u in hostile:
        if isinstance(u, str) and len(u) > 3:
            assert json.dumps(u)[1:-1] not in raws, u
    assert db.read_manifest(c, 1)["scan"]["tools"]["checkov"]["captured"] == len(GOOD)
