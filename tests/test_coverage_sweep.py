"""`quarry doctor --coverage` (IMPROVEMENT-PLAN item 23, the part left open).

Four adapters skipped whole directories by default and said nothing. Each fix holds
for the tool version it was measured on, so the check has to run against whatever is
installed now. The unit tests pin what each tool is expected to read and how a short
result is judged; the live tests run the real adapters under Tier 1.

MEASURED, 2026-11-05, with the four pre-fix configurations put back in one sweep
(each tool's previous argv or environment, otherwise the real adapters; opengrep on
its python and dockerfile trees only): the sweep reported gitleaks missing
node_modules/pkg, bandit missing .github/scripts, checkov missing node_modules/pkg,
.venv/lib and .github/scripts, and opengrep without --x-ignore-semgrepignore-files
missing 7 of the 12 directories. Those are the losses items 15 and 23 measured by hand.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quarry.scanners import sweep, tools                 # noqa: E402
from quarry.scanners.base import Record, ScanOutcome      # noqa: E402

DIRS = sweep.PLANTED_DIRS


def _outcome(tool, paths, ok=True, **kw):
    return ScanOutcome(tool, ok, 0 if ok else 2, 1.0,
                       [Record(tool, "r", p, 1) for p in paths], **kw)


# ------------------------------------------------------------------ expectations

def test_every_adapter_declares_what_it_reads():
    """A new adapter falls back to "something from all twelve directories", which is
    strict on purpose. Every current one has its own line."""
    for name in tools.registry():
        assert name in sweep.EXPECTED_FILES or name in sweep.WORKFLOW_ONLY, name


def test_expected_paths_per_tool():
    assert sweep.expected("zizmor") == (".github/workflows/ci.yml",)
    trivy = sweep.expected("trivy")
    assert len(trivy) == 2 * len(DIRS)
    assert {"node_modules/pkg/Dockerfile", "node_modules/pkg/requirements.txt"} <= set(trivy)
    assert sweep.expected("checkov")[-1] == ".github/workflows/ci.yml"
    assert sweep.expected("bandit") == tuple(f"{d}/x.py" for d in DIRS)
    assert sweep.expected("some-new-tool") == DIRS


def test_location_of_respects_directory_boundaries():
    assert sweep.location_of(".github/scripts/x.py") == ".github/scripts"
    assert sweep.location_of(".github/workflows/ci.yml") == ".github/workflows"
    assert sweep.location_of("tests/x.py") == "tests"
    assert sweep.location_of("test/x.py") == "test"
    assert sweep.location_of("applesauce/x.py") is None          # not under app/
    assert sweep.location_of("vendor/x.py") is None              # vendor/lib was planted
    assert sweep.location_of("package-lock.json") is None


# ------------------------------------------------------------------ judging

def test_a_full_result_passes():
    r = sweep.judge("bandit", _outcome("bandit", [f"{d}/x.py" for d in DIRS]), "1.9.4")
    assert (r.state, r.missed, r.problem, r.dirs_read) == ("pass", [], False, (12, 12))
    assert r.read == {d: 1 for d in sorted(DIRS)}


def test_one_skipped_directory_is_named():
    paths = [f"{d}/x.py" for d in DIRS if d != ".venv/lib"] + ["README.md"]
    r = sweep.judge("bandit", _outcome("bandit", paths))
    assert r.state == "missed" and r.problem
    assert r.missed == [".venv/lib/x.py"]
    assert sweep.missed_by_dir(r.missed) == {".venv/lib": ["x.py"]}
    assert r.dirs_read == (11, 12)


def test_a_file_kind_dropped_inside_a_read_directory_is_still_a_miss():
    """Trivy still reading node_modules/pkg's Dockerfile does not cover its
    requirements.txt: that is the per-file part of the expectation."""
    paths = [f"{d}/{f}" for d in DIRS for f in ("Dockerfile", "requirements.txt")
             if (d, f) != ("node_modules/pkg", "requirements.txt")]
    r = sweep.judge("trivy", _outcome("trivy", paths))
    assert r.missed == ["node_modules/pkg/requirements.txt"]
    assert sweep.missed_by_dir(r.missed) == {"node_modules/pkg": ["requirements.txt"]}


def test_an_unknown_tool_needs_something_from_each_directory():
    paths = [f"{d}/anything.txt" for d in DIRS if d != "dist"]
    r = sweep.judge("some-new-tool", _outcome("some-new-tool", paths))
    assert r.missed == ["dist"] and sweep.missed_by_dir(r.missed) == {"dist": []}


def test_a_failed_run_misses_everything_and_is_not_a_pass():
    r = sweep.judge("checkov", _outcome("checkov", [], ok=False, error="exit 2, no SARIF"))
    assert r.state == "failed" and r.problem
    assert r.detail == "exit 2, no SARIF"
    assert len(r.missed) == len(sweep.expected("checkov"))


def test_a_tool_that_did_not_run_is_skipped_not_failed():
    r = sweep.judge("trivy", ScanOutcome("trivy", False, -1, 0.0,
                                         skipped="trivy not installed"))
    assert r.state == "skipped" and not r.problem and r.missed == []


def test_missing_offline_databases_are_a_skip_with_the_fix(tmp_path, monkeypatch):
    monkeypatch.setenv("QUARRY_DBS", str(tmp_path / "no-dbs"))
    assert "quarry db sync" in sweep.not_runnable(tools.TrivyFS())
    assert "PyPI" in sweep.not_runnable(tools.OSVScanner())
    assert sweep.not_runnable(tools.Bandit()) == ""
    og = tools.Opengrep()
    if og.available():
        monkeypatch.setenv("QUARRY_RULES", str(tmp_path / "no-rules"))
        assert "rule pack absent" in sweep.not_runnable(og)


# ------------------------------------------------------------------ the CLI

def test_doctor_coverage_exits_non_zero_on_a_miss(monkeypatch):
    from typer.testing import CliRunner
    from quarry import cli, orchestrator
    monkeypatch.setattr(orchestrator, "tool_manifest", lambda: {"bandit": "bandit 1.9.4"})
    short = sweep.judge("bandit", _outcome(
        "bandit", [f"{d}/x.py" for d in DIRS if d != ".github/scripts"]), "bandit 1.9.4")
    full = sweep.judge("gitleaks", _outcome("gitleaks", [f"{d}/x.py" for d in DIRS]))
    monkeypatch.setattr(sweep, "run_sweep", lambda **kw: ([full, short], 1.0))

    r = CliRunner().invoke(cli.app, ["doctor", "--coverage"], env={"COLUMNS": "200"})

    assert r.exit_code == 1, r.output
    assert "MISSED" in r.output and ".github/scripts (x.py)" in r.output
    assert "1 of 2 tool(s) that ran" in r.output

    monkeypatch.setattr(sweep, "run_sweep", lambda **kw: ([full], 1.0))
    r = CliRunner().invoke(cli.app, ["doctor", "--coverage"], env={"COLUMNS": "200"})
    assert r.exit_code == 0, r.output
    assert "all 1 tool(s) that ran returned results" in r.output


# ------------------------------------------------------------------ live, Tier 1

def _fast_opengrep(monkeypatch):
    """The python and dockerfile trees only: the planted files it is expected to read
    are Python and Dockerfiles, and its directory skips come from ignore handling, not
    from the rules (with these two trees and the flag removed, the sweep reported 7 of
    the 12 directories missed). The full pack took 26 s of a 32 s sweep; doctor runs
    the full pack."""
    pack = tools.rules_dir() / "opengrep_opengrep-rules"
    trees = [pack / t for t in ("python", "dockerfile") if (pack / t).is_dir()]
    monkeypatch.setattr(tools.Opengrep, "config_paths", lambda self: trees)


def test_every_installed_tool_reads_every_planted_file(tmp_path, monkeypatch):
    if not any(sc.available() for sc in tools.registry().values()):
        pytest.skip("no scanner installed")
    _fast_opengrep(monkeypatch)

    results, wall = sweep.run_sweep(tmp_path, timeout=300)

    assert [r.tool for r in results] == list(tools.registry())
    for r in results:
        assert r.state in ("pass", "skipped"), (r.tool, r.state, r.detail,
                                                sweep.missed_by_dir(r.missed))
    if any(r.tool == "opengrep" and r.state == "pass" for r in results):
        cov = next(r.coverage for r in results if r.tool == "opengrep")
        assert cov["expected"] == len(DIRS) and cov["unexplained"]["n"] == 0
        assert cov["unreported"] == []
    # The planted tokens and Gitleaks' unredacted report go with the run directory.
    assert list(tmp_path.iterdir()) == []
    assert "ghp_" not in repr(results)


def test_a_new_default_skip_is_reported_as_a_miss(tmp_path, monkeypatch):
    """A negative control on a real tool: give bandit one more exclude, as an upgrade
    that adds a default skip would, and the sweep has to name that directory."""
    if not tools.Bandit().available():
        pytest.skip("bandit not installed")
    real = tools.Bandit.argv

    def with_new_skip(self, src, out):
        argv = real(self, src, out)
        argv[argv.index("-x") + 1] += f",{src}/node_modules/*"
        return argv
    monkeypatch.setattr(tools.Bandit, "argv", with_new_skip)

    results, _ = sweep.run_sweep(tmp_path, only=["bandit"], timeout=300)

    (r,) = results
    assert r.state == "missed", (r.state, r.detail)
    assert r.missed == ["node_modules/pkg/x.py"]
    assert r.dirs_read == (11, 12)
