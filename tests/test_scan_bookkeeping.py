"""Small bookkeeping defects that each made a report say something untrue: a finding
count that counted occurrences, a timed-out tool reported as a clean run, a stale
output file re-ingested, a run row stuck at "running", a sync that hung or inherited
the operator's credentials, an egress ledger that named no host, and lineless SCA
findings clustered with SAST hits on lines 1-9.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quarry import db, funnel, orchestrator, vulndb       # noqa: E402
from quarry.sandbox.spawn import ToolResult                # noqa: E402
from quarry.scanners import base                           # noqa: E402
from quarry.scanners.base import Record, Scanner           # noqa: E402
from test_funnel import add, con                           # noqa: E402,F401


def test_distinct_findings_count_is_not_the_occurrence_count(tmp_path):
    (tmp_path / "a.py").write_text("eval(a)\nx = 1\neval(a)\neval(b)\n")
    c = db.init(tmp_path / "t.db")
    c.execute("INSERT INTO runs (id,target,clone_url,status) VALUES (1,'o/r','x','done')")
    recs = [Record(tool="bandit", rule_id="B307", path="a.py", start_line=n) for n in (1, 3, 4)]
    s = orchestrator.ScanSummary(1)
    orchestrator._persist(c, 1, "o/r", None, tmp_path, "bandit", recs, s)
    assert s.occurrences == 3
    assert s.findings == 2, "lines 1 and 3 are the same content, so the same finding"


class _Tool(Scanner):
    name = binary = "faketool"

    def available(self):
        return "/usr/bin/true"

    def argv(self, src, out):
        return [self.binary]

    def parse(self, out, src):
        import json
        return [Record(tool=self.name, rule_id=r, path="a.py")
                for r in json.loads(out.read_text())]


def _rundir(tmp_path: Path) -> Path:
    (tmp_path / "out").mkdir()
    (tmp_path / "out" / "faketool.json").write_text('["stale-from-last-scan"]')
    return tmp_path


def _tier1(rc):
    def fake(rundir, argv, *, name, cwd=None, timeout=1800):
        return ToolResult(argv, rc, rundir / "x", rundir / "y", 1.0)
    return fake


def test_timeout_is_a_failure_not_a_clean_run(tmp_path, monkeypatch):
    rundir = _rundir(tmp_path)
    monkeypatch.setattr(base, "tier1", _tier1(-9))
    out = _Tool().run(rundir, rundir / "src", timeout=5)
    assert not out.ok and "timed out after 5s" in out.error
    assert not out.records


def test_stale_output_from_a_previous_scan_is_not_reingested(tmp_path, monkeypatch):
    """The tool exits 0 but writes nothing; the old out/<tool>.json must be gone."""
    rundir = _rundir(tmp_path)
    monkeypatch.setattr(base, "tier1", _tier1(0))
    out = _Tool().run(rundir, rundir / "src")
    assert not (rundir / "out" / "faketool.json").exists()
    assert not out.ok and not out.records


def test_volume_creation_failure_marks_the_run_failed(tmp_path, monkeypatch):
    c = db.init(tmp_path / "t.db")
    monkeypatch.setattr(orchestrator, "tool_manifest", lambda: {})

    def boom(*a, **k):
        raise OSError("hdiutil: create failed")
    monkeypatch.setattr(orchestrator.RunVolume, "create", boom)
    with pytest.raises(OSError):
        orchestrator.ingest(SimpleNamespace(runs=tmp_path), c, "o/r")
    assert c.execute("SELECT status FROM runs").fetchone()["status"] == "failed"


def test_sync_timeout_is_reported_not_raised(monkeypatch):
    monkeypatch.setattr(vulndb.shutil, "which", lambda b: "/usr/bin/true")

    def hang(*a, **k):
        raise subprocess.TimeoutExpired(a[0], k.get("timeout"))
    monkeypatch.setattr(vulndb.subprocess, "run", hang)
    r = vulndb._sync("grype", ["grype", "db", "update"], {}, 7)
    assert not r.ok and "timed out after 7s" in r.detail


def test_sync_runs_with_a_minimal_environment_and_logs_real_hosts(tmp_path, monkeypatch):
    monkeypatch.setenv("QUARRY_DBS", str(tmp_path / "dbs"))
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "do-not-inherit")
    monkeypatch.setenv("GITHUB_TOKEN", "do-not-inherit")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.internal:3128")
    monkeypatch.setattr(vulndb.shutil, "which", lambda b: f"/usr/bin/{b}")
    seen: list[dict] = []

    def run(argv, **k):
        seen.append(k["env"])
        return subprocess.CompletedProcess(argv, 0, "", "")
    monkeypatch.setattr(vulndb.subprocess, "run", run)

    c = db.init(tmp_path / "t.db")
    vulndb.sync_all(c)
    assert len(seen) == 3
    for env in seen:
        assert "AWS_SECRET_ACCESS_KEY" not in env and "GITHUB_TOKEN" not in env
        assert env["HTTPS_PROXY"] == "http://proxy.internal:3128"
        assert env["HOME"].startswith(str(tmp_path))
    hosts = {r["destination"] for r in c.execute("SELECT destination FROM egress")}
    assert hosts == {"mirror.gcr.io", "ghcr.io", "grype.anchore.io",
                     "osv-vulnerabilities.storage.googleapis.com"}


def test_lineless_sca_finding_does_not_cluster_with_early_sast_hits(con):
    sca = add(con, "osv-scanner", "GHSA-x", "requirements.txt", None,
              "requests 2.0: GHSA-x", blob=False)
    sast = add(con, "opengrep", "generic.r", "requirements.txt", 3)
    funnel.run(con, 1)
    assert not con.execute("SELECT COUNT(*) FROM issue_members").fetchone()[0]
    assert not con.execute("SELECT 1 FROM funnel_events WHERE stage='cross-tool-cluster' "
                           "AND occurrence_id IN (?,?)", (sca, sast)).fetchone()


def test_osv_without_manifests_is_a_clean_empty_scan(tmp_path):
    """osv-scanner exits 128 on a repo with no package manifests and writes nothing.
    That is an empty scan, not refused output."""
    from quarry.scanners.tools import OSVScanner
    osv = OSVScanner()
    out = tmp_path / "osv-scanner.json"
    assert osv.nothing_to_scan(128, out, b"No package sources found, --help for usage")
    assert not osv.nothing_to_scan(128, out, b"some other failure")
    out.write_text("{}")
    assert not osv.nothing_to_scan(128, out, b"No package sources found")
