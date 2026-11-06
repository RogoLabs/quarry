"""finding_id: line-number-free, but not file-wide.

Keyed on the whole file's hash, every same-rule finding in a file shared one id, so a
rejected verdict carried forward onto real siblings, and any byte change in the file
reset every verdict in it. These pin the replacement: rule + path + the flagged
line(s) with whitespace stripped.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quarry import db, funnel, taint                # noqa: E402
from test_funnel import add, con                    # noqa: E402,F401


def _fid(root: Path, line: int, end: int | None = None) -> str:
    ev = taint.extract_evidence(root, Path("a.py"), line, end_line=end)
    return taint.finding_id("o/r", "a.py", "bandit:B307", ev.match_sha)


def test_same_rule_siblings_in_one_file_get_distinct_ids(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\neval(a)\ny = 2\neval(b)\n")
    assert _fid(tmp_path, 2) != _fid(tmp_path, 4)


def test_id_survives_moves_reindent_and_unrelated_edits(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\neval(a)\n")
    before = _fid(tmp_path, 2)
    # three lines inserted above, the flagged line re-indented, a byte changed elsewhere
    (tmp_path / "a.py").write_text("# new\n# new\nx = 2\nif True:\n    eval( a )\n")
    assert _fid(tmp_path, 5) == before
    # but a changed token is a different finding
    (tmp_path / "a.py").write_text("x = 1\neval(b)\n")
    assert _fid(tmp_path, 2) != before


def test_multi_line_match_keys_on_every_flagged_line(tmp_path):
    (tmp_path / "a.py").write_text("call(\n  a,\n)\ncall(\n  b,\n)\n")
    assert _fid(tmp_path, 1, 3) != _fid(tmp_path, 4, 6)


def test_lineless_findings_key_on_their_message():
    a = taint.finding_id("o/r", "poetry.lock", "osv-scanner:GHSA-1", None, fallback="aiohttp 3.1: x")
    b = taint.finding_id("o/r", "poetry.lock", "osv-scanner:GHSA-1", None, fallback="yarl 1.0: x")
    assert a != b


def _probe(con, fid, **over):
    """The probe identity validate.record_verdict stores (item 18): the lens, the sha
    of its probe source as it is now, and the occurrence's evidence window."""
    from quarry.dynamic.lenses import CATALOGUE
    from quarry.dynamic.validate import probe_source_sha
    lens = CATALOGUE[0]
    blob = con.execute("SELECT blob_sha FROM occurrences WHERE finding_id=?",
                       (fid,)).fetchone()["blob_sha"]
    return {"id": lens.key, "source_sha": probe_source_sha(lens), "method": "GET",
            "route": "/x", "evidence_blob": blob, **over}


def _controlled(con, fid, **probe_over):
    """What a controlled Layer 3 rejection stores (validate.record_verdict)."""
    return json.dumps({"baseline": "GET /x?q=1 -> 200", "differs_from_baseline": False,
                       "handled": True, "probe": _probe(con, fid, **probe_over)})


def _reject(con, fid, **kw):
    kw = {"reason": "deterministic", "rationale": _controlled(con, fid), **kw}
    db.verdict(con, fid, 0, verdict="rejected", **kw)


def test_rejected_verdict_does_not_kill_a_sibling(con):
    """REGRESSION. With a file-wide id, rejecting one eval() rejected all of them."""
    rejected = add(con, "bandit", "B307", "src/a.py", 10)
    sibling = add(con, "bandit", "B307", "src/a.py", 20)
    con.execute("INSERT INTO runs (id,target,clone_url,status) VALUES (0,'o/r','x','done')")
    fid = con.execute("SELECT finding_id FROM occurrences WHERE id=?",
                      (rejected,)).fetchone()["finding_id"]
    _reject(con, fid)
    funnel.run(con, 1)
    alive = {r["id"] for r in con.execute("SELECT id FROM live_occurrences")}
    assert rejected not in alive and sibling in alive


@pytest.mark.parametrize("kw", [
    {"rationale": None},                                    # written before controls
    {"reason": "statistical"},                              # a timing miss
    {"rationale": json.dumps({"baseline": "GET /x -> 404", "differs_from_baseline": False,
                              "handled": False})},          # no handler answered
    {"seat": "chair"},                                      # not a Layer 3 probe
], ids=["no-control", "statistical", "unhandled", "not-dynamic"])
def test_only_a_controlled_deterministic_rejection_carries_forward(con, kw):
    """A carried-forward rejection kills the finding in every later run, so it takes
    the strongest rejection Layer 3 makes. A timing probe that 404'd both identifiers
    was enough before."""
    oid = add(con, "bandit", "B307", "src/a.py", 10)
    con.execute("INSERT INTO runs (id,target,clone_url,status) VALUES (0,'o/r','x','done')")
    fid = con.execute("SELECT finding_id FROM occurrences WHERE id=?",
                      (oid,)).fetchone()["finding_id"]
    _reject(con, fid, **kw)
    funnel.run(con, 1)
    assert oid in {r["id"] for r in con.execute("SELECT id FROM live_occurrences")}


@pytest.mark.parametrize("when, differs, carried", [
    ("same", True, False),      # what the rate-limit probe writes when it sees a throttle
    ("same", False, False),     # never carried, whatever the comparison field says
    ("differs", False, True),   # the same identity on a differs-shaped rejection is
], ids=["rate-limit", "same-any-shape", "control"])
def test_a_rate_limit_rejection_is_not_carried_forward(con, when, differs, carried):
    """IMPROVEMENT-PLAN item 3, decided 2026-11-06. A throttle the rate-limit probe saw
    is usually configured outside the flagged handler's evidence window (an app-wide
    limiter, a proxy, the environment), so item 18's identity check could not reopen
    the kill when the limiter went away. It stays a verdict on its own run, even with
    the full identity a carried rejection needs. The control case shows the identity
    itself is good enough to carry, so the difference is reproduces_when alone."""
    oid = add(con, "bandit", "B307", "src/a.py", 10)
    con.execute("INSERT INTO runs (id,target,clone_url,status) VALUES (0,'o/r','x','done')")
    fid = con.execute("SELECT finding_id FROM occurrences WHERE id=?",
                      (oid,)).fetchone()["finding_id"]
    lens = "missing-rate-limit" if when == "same" else None
    probe = _probe(con, fid, **({"id": lens} if lens else {}))
    if lens:
        from quarry.dynamic.lenses import CATALOGUE
        from quarry.dynamic.validate import probe_source_sha
        probe["source_sha"] = probe_source_sha(next(x for x in CATALOGUE if x.key == lens))
    _reject(con, fid, rationale=json.dumps({
        "baseline": "lone GET /login -> HTTP 401", "differs_from_baseline": differs,
        "handled": True, "reproduces_when": when, "probe": probe}))
    funnel.run(con, 1)
    alive = oid in {r["id"] for r in con.execute("SELECT id FROM live_occurrences")}
    assert alive is not carried


@pytest.mark.parametrize("change,why", [
    ({"source_sha": "0" * 64}, "the probe that rejected it has changed since"),
    ({"evidence_blob": "another-window"}, "code around the flagged line changed"),
    (None, "rejected before probes recorded their identity"),
], ids=["probe-changed", "window-changed", "no-identity"])
def test_a_carried_rejection_reopens_when_what_it_measured_changed(con, change, why):
    """IMPROVEMENT-PLAN item 18. finding_id keys on the flagged line(s) only, so an
    old rejection used to outlive a fixed probe and a rewritten handler around an
    unchanged line, and the kill reason claimed "symbol content unchanged"."""
    oid = add(con, "bandit", "B307", "src/a.py", 10)
    con.execute("INSERT INTO runs (id,target,clone_url,status) VALUES (0,'o/r','x','done')")
    fid = con.execute("SELECT finding_id FROM occurrences WHERE id=?",
                      (oid,)).fetchone()["finding_id"]
    rationale = (json.dumps({"baseline": "GET /x -> 200", "differs_from_baseline": False,
                             "handled": True}) if change is None
                 else _controlled(con, fid, **change))
    _reject(con, fid, rationale=rationale)
    funnel.run(con, 1)
    assert oid in {r["id"] for r in con.execute("SELECT id FROM live_occurrences")}, why


def test_a_carried_rejection_names_its_run_probe_and_route(con):
    oid = add(con, "bandit", "B307", "src/a.py", 10)
    con.execute("INSERT INTO runs (id,target,clone_url,status) VALUES (0,'o/r','x','done')")
    fid = con.execute("SELECT finding_id FROM occurrences WHERE id=?",
                      (oid,)).fetchone()["finding_id"]
    _reject(con, fid)
    funnel.run(con, 1)
    reason = con.execute("SELECT reason FROM funnel_events WHERE occurrence_id=? AND "
                         "stage='rejected-carry-forward' AND action='kill'",
                         (oid,)).fetchone()["reason"]
    assert reason.startswith("rejected in run 0 by probe ") and "against GET /x" in reason
    assert "probe source and evidence window unchanged" in reason


def test_carry_forward_uses_the_latest_verdict(con):
    oid = add(con, "bandit", "B307", "src/a.py", 10)
    con.execute("INSERT INTO runs (id,target,clone_url,status) VALUES (0,'o/r','x','done')")
    fid = con.execute("SELECT finding_id FROM occurrences WHERE id=?",
                      (oid,)).fetchone()["finding_id"]
    _reject(con, fid)
    db.verdict(con, fid, 0, verdict="confirmed")
    funnel.run(con, 1)
    assert oid in {r["id"] for r in con.execute("SELECT id FROM live_occurrences")}
    assert con.execute("SELECT 1 FROM funnel_events WHERE occurrence_id=? AND "
                       "stage='rejected-carry-forward' AND action='boost'",
                       (oid,)).fetchone()


def test_persist_gives_same_rule_siblings_their_own_findings(tmp_path):
    """Through the real writer: two B307 hits in one file are two findings."""
    from quarry import orchestrator
    from quarry.scanners.base import Record
    (tmp_path / "a.py").write_text("x = 1\neval(a)\ny = 2\neval(b)\n")
    c = db.init(tmp_path / "t.db")
    c.execute("INSERT INTO runs (id,target,clone_url,status) VALUES (1,'o/r','x','done')")
    recs = [Record(tool="bandit", rule_id="B307", path="a.py", start_line=n) for n in (2, 4)]
    summary = orchestrator.ScanSummary(1)
    orchestrator._persist(c, 1, "o/r", None, tmp_path, "bandit", recs, summary)
    assert c.execute("SELECT COUNT(DISTINCT finding_id) n FROM occurrences").fetchone()["n"] == 2


@pytest.mark.parametrize("spelling", [
    "CVEProject/cve-services", "https://github.com/CVEProject/cve-services",
    "https://github.com/CVEProject/cve-services.git", "github.com/CVEProject/cve-services/",
    "git@github.com:CVEProject/cve-services.git", "HTTPS://GitHub.com/CVEProject/cve-services"])
def test_every_spelling_of_a_github_target_is_one_target(spelling):
    """IMPROVEMENT-PLAN item 14. finding_id hashes the target string, so a run
    ingested by URL had different ids from one ingested as owner/repo, and verdicts
    did not carry between them."""
    from quarry.ingest.clone import canonical_target
    assert canonical_target(spelling) == "CVEProject/cve-services"


def test_a_non_github_url_keeps_its_host():
    from quarry.ingest.clone import canonical_target
    assert canonical_target("https://gitlab.com/o/r.git") == "https://gitlab.com/o/r"
