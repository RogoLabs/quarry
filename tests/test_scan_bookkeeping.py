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


def test_osv_filters_the_offline_uncoverable_git_ecosystem(tmp_path):
    """A lockfile can pin a git dependency (git+ssh://...#<sha>), which osv-scanner puts
    in the GIT ecosystem. OSV has no offline GIT database, and osv-scanner aborts the
    whole offline scan (exit 127) when one ecosystem's db will not load, taking the npm
    findings with it. The scanner ships a config that ignores GIT, and writes it where
    Tier 1 can read it."""
    from quarry.scanners.tools import OSVScanner, OSV_CONFIG_NAME, OSV_CONFIG_TOML
    assert 'ecosystem = "GIT"' in OSV_CONFIG_TOML and "ignore = true" in OSV_CONFIG_TOML

    osv = OSVScanner()
    out = tmp_path / "out" / "osv-scanner.json"
    out.parent.mkdir(parents=True)
    argv = osv.argv(tmp_path / "src", out)
    assert "--config" in argv
    assert argv[argv.index("--config") + 1] == str(out.parent / OSV_CONFIG_NAME)


def test_osv_run_stages_the_git_ignore_config(tmp_path, monkeypatch):
    """run() must write the config into the per-run out/ dir before the sandboxed scan,
    because that path is what Tier 1 can read and what argv points `--config` at."""
    from quarry.scanners import base
    from quarry.scanners.tools import OSVScanner, OSV_CONFIG_NAME, OSV_CONFIG_TOML
    (tmp_path / "out").mkdir()
    # Stop before the real scan; we only assert the config was staged first.
    monkeypatch.setattr(base.Scanner, "run",
                        lambda self, rundir, src, *, timeout=1800: "stubbed")
    assert OSVScanner().run(tmp_path, tmp_path / "src") == "stubbed"
    assert (tmp_path / "out" / OSV_CONFIG_NAME).read_text() == OSV_CONFIG_TOML


def test_osv_seeds_register_every_ecosystem():
    """OSV only downloads a database for an ecosystem it resolves a package in. An empty
    manifest (or, for npm, one with no resolved URL) registers nothing, so its database
    is never fetched and the first real target in that language fails with exit 127. Each
    seed must declare a real package; npm additionally needs the resolved URL."""
    from quarry.vulndb import SEEDS_DIR
    seeds = {f.name: f.read_text() for f in SEEDS_DIR.iterdir() if f.is_file()}
    # The lockfiles that were previously empty and so never triggered a download.
    assert '"node_modules/' in seeds["package-lock.json"]
    assert '"resolved"' in seeds["package-lock.json"]          # npm registers only with it
    assert "specs:\n    rake" in seeds["Gemfile.lock"]
    assert '"name"' in seeds["composer.lock"]


# ---------------------------------------------------------------- scan outcomes

class _Canned(Scanner):
    """A scanner whose outcome is fixed, so orchestrator.scan runs end to end."""
    def __init__(self, name, outcome_fn):
        self.name = self.binary = name
        self._fn = outcome_fn

    def run(self, rundir, src, *, timeout=1800):
        return self._fn()


def _scan_env(tmp_path, monkeypatch, tools):
    from quarry.scanners import base as sbase
    src = tmp_path / "vol" / "src"
    src.mkdir(parents=True)
    (src / "app.py").write_text("eval(x)\n")
    (src / "poetry.lock").write_text("")
    vol = SimpleNamespace(mount=tmp_path / "vol", src=src)
    monkeypatch.setattr(orchestrator.RunVolume, "attach_existing", lambda rid, runs: vol)
    import quarry.scanners as scanners
    monkeypatch.setattr(scanners, "registry", lambda: tools)
    c = db.init(tmp_path / "t.db")
    c.execute("INSERT INTO runs (id,target,clone_url,status) VALUES (1,'o/r','x','done')")
    return c, SimpleNamespace(runs=tmp_path)


def _ok(*recs):
    return lambda: base.ScanOutcome("t", True, 0, 1.0, list(recs))


def test_each_tool_outcome_is_kept_in_the_manifest(tmp_path, monkeypatch):
    """It was printed and dropped, so a timed-out Trivy looked like a clean one."""
    timed_out = lambda: base.ScanOutcome("trivy", False, -9, 5.0, error="timed out after 5s")
    tools = {"bandit": _Canned("bandit", _ok(Record("bandit", "B307", "app.py", 1))),
             "trivy": _Canned("trivy", timed_out)}
    c, paths = _scan_env(tmp_path, monkeypatch, tools)
    s = orchestrator.scan(paths, c, 1)
    kept = db.read_manifest(c, 1)["scan"]["tools"]
    assert kept["bandit"]["ok"] and kept["bandit"]["records"] == 1
    assert (kept["bandit"]["lined"], kept["bandit"]["captured"]) == (1, 1)
    assert not kept["trivy"]["ok"] and "timed out" in kept["trivy"]["error"]
    assert s.health["trivy"] == ["failed: timed out after 5s"]
    assert db.read_manifest(c, 1)["health"]["scan"] == {"trivy": ["failed: timed out after 5s"]}


def test_a_tool_that_returned_results_is_not_scanned_into_the_run_again(tmp_path, monkeypatch):
    """Run 1 got 9 OSV findings from a re-scan after the funnel, none of them funnelled.
    A tool that failed can be re-run; one that succeeded would duplicate every finding."""
    state = {"fail": True}
    def osv():
        if state["fail"]:
            return base.ScanOutcome("osv-scanner", False, 127, 1.0, error="exit 127")
        return base.ScanOutcome("osv-scanner", True, 0, 1.0, [])
    tools = {"bandit": _Canned("bandit", _ok(Record("bandit", "B307", "app.py", 1))),
             "osv-scanner": _Canned("osv-scanner", osv)}
    c, paths = _scan_env(tmp_path, monkeypatch, tools)
    orchestrator.scan(paths, c, 1)
    with pytest.raises(orchestrator.AlreadyScanned, match="bandit"):
        orchestrator.scan(paths, c, 1, only=["bandit"])
    state["fail"] = False
    orchestrator.scan(paths, c, 1, only=["osv-scanner"])          # the failed one may rerun
    with pytest.raises(orchestrator.AlreadyScanned, match="osv-scanner"):
        orchestrator.scan(paths, c, 1, only=["osv-scanner"])


def test_a_tool_whose_paths_miss_the_clone_is_flagged(tmp_path, monkeypatch):
    """Checkov reported `src/<path>`, so 21 of 21 findings had no evidence window and
    quote-verify killed them all while the run said done."""
    recs = [Record("checkov", "CKV_DOCKER_2", f"src/d{i}/Dockerfile", 1) for i in range(3)]
    c, paths = _scan_env(tmp_path, monkeypatch, {"checkov": _Canned("checkov", _ok(*recs))})
    s = orchestrator.scan(paths, c, 1)
    assert "evidence captured for 0 of 3" in s.health["checkov"][0]


def test_a_tool_that_skips_files_silently_is_flagged(tmp_path, monkeypatch):
    """IMPROVEMENT-PLAN item 15. Opengrep skipped every tests/ and vendor/ file and
    the run said done; 0 of 904 opengrep hits across runs 1 to 3 were under test
    paths. The tool's own target report is compared with the tree."""
    cov = base.Coverage(
        scanned={"app.py", "lib/huge.py"},
        skipped={"exceeded_size_limit": {"lib/big.py"},
                 "analysis_failed_parser_or_internal_error": {"lib/huge.py"}},
        errors={"Timeout": 3})
    tools = {"opengrep": _Canned("opengrep", lambda: base.ScanOutcome(
        "opengrep", True, 0, 1.0, [Record("opengrep", "r", "app.py", 1)], coverage=cov))}
    c, paths = _scan_env(tmp_path, monkeypatch, tools)
    src = tmp_path / "vol" / "src"
    for rel in ("lib/big.py", "lib/huge.py", "tests/test_app.py", "vendor/x/y.go",
                "README.md"):
        (src / rel).parent.mkdir(parents=True, exist_ok=True)
        (src / rel).write_text("x\n")

    s = orchestrator.scan(paths, c, 1)

    kept = db.read_manifest(c, 1)["scan"]["tools"]["opengrep"]["coverage"]
    assert (kept["scanned"], kept["expected"]) == (2, 5)        # README.md is not source
    assert kept["unexplained"] == {"n": 2, "examples": ["tests/test_app.py",
                                                        "vendor/x/y.go"]}
    assert kept["skipped"]["exceeded_size_limit"] == {"n": 1, "examples": ["lib/big.py"]}
    msgs = s.health["opengrep"]
    assert any("2 of 5 source file(s) were neither scanned nor reported skipped" in m
               for m in msgs)
    assert any("larger than --max-target-bytes, e.g. lib/big.py" in m for m in msgs)
    assert any("per-file timeout" in m for m in msgs)
    assert any("Timeout 3" in m for m in msgs)
    assert db.read_manifest(c, 1)["health"]["scan"]["opengrep"] == msgs


def test_a_skipped_directory_explains_the_files_under_it():
    """Opengrep names an ignored tree once (`vendor`), not file by file; those files
    must not be reported a second time as unexplained."""
    cov = base.Coverage(scanned={"app/a.py"},
                        skipped={"semgrepignore_patterns_match": {"vendor", "tests"}})
    s = orchestrator.coverage_summary(
        cov, {"app/a.py", "vendor/lib/v.py", "tests/t.py", "testsuite/x.py"})
    assert s["unexplained"] == {"n": 1, "examples": ["testsuite/x.py"]}
    msgs = orchestrator.coverage_health(s)
    assert msgs[0].startswith("2 path(s) skipped by an ignore list")


def test_full_coverage_raises_no_warning_and_a_missing_report_does():
    clean = {"scanned": 4, "expected": 4, "skipped": {}, "errors": {},
             "unexplained": {"n": 0, "examples": []}, "unreported": []}
    assert orchestrator.coverage_health(clean) == []
    gone = {**clean, "scanned": 0, "unreported": ["combined"]}
    assert "no target report from 1 invocation(s) (combined)" in \
        orchestrator.coverage_health(gone)[0]


def test_osv_with_lockfiles_and_no_findings_is_questioned():
    h = orchestrator.scan_health(
        {"osv-scanner": {"ok": True, "records": 0, "note": ""}}, lockfiles=2)
    assert "0 vulnerabilities across 2 lockfile(s)" in h["osv-scanner"][0]
    clean = orchestrator.scan_health(
        {"osv-scanner": {"ok": True, "records": 0, "note": "no package manifests to scan"}},
        lockfiles=0)
    assert clean["osv-scanner"] == []


def test_a_tool_that_loses_everything_to_deterministic_stages_is_flagged(con):
    for i in range(3):
        add(con, "checkov", "CKV_DOCKER_2", f"src/d{i}/Dockerfile", 1, blob=False)
    add(con, "bandit", "B307", "src/a.py", 10)
    res = funnel.run(con, 1)
    assert "all 3 new occurrence(s) killed" in res.health["checkov"][0]
    assert "quote-verify" in res.health["checkov"][0]
    assert res.health["bandit"] == []
    assert db.read_manifest(con, 1)["health"]["funnel"].keys() == {"checkov"}


def test_osv_severity_follows_the_score_and_unresolved_paths_are_dropped(tmp_path):
    """IMPROVEMENT-PLAN item 14. Any CVSS v3 vector read as "high", so lodash's
    A:L-only 5.3 (GHSA-29mw-wpgm-hmr9, from a real offline scan of the seeds) sat
    beside a 9.8. And a manifest outside the clone became a finding on "."."""
    import json
    from quarry.scanners.tools import OSVScanner
    src = tmp_path / "src"
    src.mkdir()
    (src / "package-lock.json").write_text("{}")
    v3 = [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"}]
    pkg = {"package": {"name": "lodash", "version": "4.17.20"},
           "vulnerabilities": [{"id": "GHSA-29mw-wpgm-hmr9", "severity": v3},
                               {"id": "GHSA-crit", "severity": v3},
                               {"id": "GHSA-none"}],
           "groups": [{"ids": ["GHSA-29mw-wpgm-hmr9", "CVE-2020-28500"], "max_severity": "5.3"},
                      {"ids": ["GHSA-crit"], "max_severity": "9.8"},
                      {"ids": ["GHSA-none"], "max_severity": ""}]}
    out = tmp_path / "osv.json"
    out.write_text(json.dumps({"results": [
        {"source": {"path": str(src / "package-lock.json")}, "packages": [pkg]},
        {"source": {"path": "/Users/someone/elsewhere/package-lock.json"}, "packages": [pkg]},
    ]}))
    recs = list(OSVScanner().parse(out, src))
    assert {r.path for r in recs} == {"package-lock.json"}
    assert {r.rule_id: r.severity for r in recs} == {
        "GHSA-29mw-wpgm-hmr9": "medium", "GHSA-crit": "critical", "GHSA-none": "unscored"}


def test_trivy_inline_ignores_are_reported(tmp_path, monkeypatch):
    """IMPROVEMENT-PLAN item 14, measured on trivy 0.76.1: `#trivy:ignore:AVD-DS-0001`
    removes DS-0001 from the SARIF and nothing says so. Quarry cannot stop Trivy
    obeying it, so the run says which files carry one."""
    tools = {"trivy": _Canned("trivy", _ok())}
    c, paths = _scan_env(tmp_path, monkeypatch, tools)
    src = tmp_path / "vol" / "src"
    (src / "Dockerfile").write_text("#trivy:ignore:AVD-DS-0001\nFROM alpine\n")
    (src / "node_modules").mkdir()
    (src / "node_modules" / "x.tf").write_text("# trivy:ignore:AVD-AWS-0086\n")
    s = orchestrator.scan(paths, c, 1)
    assert any("2 file(s) carry trivy:ignore" in m and "Dockerfile" in m
               for m in s.health["trivy"])
    assert orchestrator.trivy_inline_ignores(src) == ["Dockerfile", "node_modules/x.tf"]
