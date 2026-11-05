"""`quarry doctor --coverage`: does every installed scanner still read every directory?

Four adapters skipped whole trees by default and said nothing (IMPROVEMENT-PLAN items
15 and 23): Opengrep's built-in ignore list, Bandit's substring excludes, Checkov's
node_modules and dot-directory rules, and Gitleaks' global path allowlist. Each was
fixed with a flag, an environment variable or a config, and each fix was measured on
one tool version. An upgrade can bring a default skip back with no error and no
warning, and a scan of a real target cannot tell "nothing found here" from "never read
here". So this plants the same findings in twelve directories, runs each installed
adapter exactly as a scan does (`Scanner.run`: Tier 1, the real argv, the real
environment), and names every directory a tool should have read and returned nothing
from.

The fixture is Quarry's own content, never a target's. It is a git work tree because
the clone a scan reads is one, and git state has changed a tool's file selection
before: Bandit's excludes depended on whether its working directory was inside a work
tree (item 23). It lives on the boot volume, not a case-sensitive
sparse image; no skip measured so far depends on the filesystem's case handling. The
planted tokens are random per sweep, never printed, and the whole directory
(Gitleaks' unredacted report included) is deleted before returning.
"""
from __future__ import annotations

import secrets
import shutil
import string
import subprocess
import tempfile
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from ..sandbox.spawn import BASE_ENV, db_dir
from .base import ScanOutcome

#: The twelve directories of IMPROVEMENT-PLAN item 23. Each is a place at least one
#: tool's defaults skipped, or a common home for code no default should skip.
PLANTED_DIRS = ("app", "tests", "test", "vendor/lib", "node_modules/pkg", "build", "dist",
                ".venv/lib", "third_party", "examples", "docs", ".github/scripts")
WORKFLOW_DIR = ".github/workflows"

# The variable is `GH`, not a credential's usual name: tests/test_no_paid_models.py
# refuses that name anywhere in the source, and Gitleaks matches the token itself.
PYTHON = 'import os\neval(input())\nGH = "{token}"\n'
DOCKERFILE = "FROM python:3.6\nRUN apt-get update && apt-get install -y curl\n"
REQUIREMENTS = "jinja2==2.10\n"
# An issue title reaches a shell unquoted: zizmor's template-injection audit.
WORKFLOW = """name: ci
on:
  issues:
    types: [opened]
jobs:
  greet:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.issue.title }}"
"""

#: Which planted file each tool must return a result from, in every planted directory.
#: Per file rather than per directory, so a tool that still reads a directory's
#: Dockerfile but has started skipping its requirements.txt is caught. MEASURED on
#: 2026-11-05, every pair below returned at least one result from all twelve
#: directories: gitleaks 8.30.1, opengrep 1.27.1 (full pack), bandit 1.9.4,
#: osv-scanner 2.7.0, trivy 0.76.1 and checkov 3.3.13, with osv-scanner and trivy on
#: `quarry db sync` databases 8 days old. Results nobody expects (opengrep's secrets
#: rules, for one) are counted but not required.
EXPECTED_FILES: dict[str, tuple[str, ...]] = {
    "gitleaks": ("x.py",),
    "opengrep": ("x.py", "Dockerfile"),
    "bandit": ("x.py",),
    "osv-scanner": ("requirements.txt",),
    "trivy": ("Dockerfile", "requirements.txt"),
    "checkov": ("Dockerfile",),
}
#: Planted files outside the twelve directories, by tool. zizmor reads only GitHub
#: Actions workflows and actions, so the workflow is all it is expected to read.
EXTRA_FILES: dict[str, tuple[str, ...]] = {
    "checkov": (f"{WORKFLOW_DIR}/ci.yml",),
    "zizmor": (f"{WORKFLOW_DIR}/ci.yml",),
}
#: Tools that read none of the twelve directories' files.
WORKFLOW_ONLY = frozenset({"zizmor"})


def expected(tool: str) -> tuple[str, ...]:
    """Clone-relative paths `tool` must return a result from. A path is a file or, for
    a tool this module does not know, a whole planted directory: an adapter added
    later has to return something from all twelve until its own line is written
    here, rather than pass by default."""
    extra = EXTRA_FILES.get(tool, ())
    if tool in WORKFLOW_ONLY:
        return extra
    if tool not in EXPECTED_FILES:
        return (*PLANTED_DIRS, *extra)
    return (*(f"{d}/{f}" for d in PLANTED_DIRS for f in EXPECTED_FILES[tool]), *extra)


def location_of(path: str) -> str | None:
    """The planted directory a clone-relative path falls under, or None for anything
    else (the root, or a path the fixture never planted)."""
    for d in sorted((*PLANTED_DIRS, WORKFLOW_DIR), key=len, reverse=True):
        if path == d or path.startswith(d + "/"):
            return d
    return None


def missed_by_dir(missed: list[str]) -> dict[str, list[str]]:
    """Missed expectations grouped by planted directory, for the report: the directory
    is what a default skip drops, the file names say which kinds of file went with it."""
    out: dict[str, list[str]] = {}
    for m in missed:
        d = location_of(m) or m
        out.setdefault(d, [])
        if m != d:
            out[d].append(m[len(d) + 1:])
    return out


@dataclass
class ToolCoverage:
    tool: str
    version: str | None
    state: str                      # pass | missed | failed | skipped
    seconds: float = 0.0
    records: int = 0
    expected: tuple[str, ...] = ()
    read: dict[str, int] = field(default_factory=dict)    # planted dir -> results
    missed: list[str] = field(default_factory=list)       # expected paths, no result
    detail: str = ""
    coverage: dict[str, Any] | None = None                # orchestrator.coverage_summary

    @property
    def problem(self) -> bool:
        """A tool that ran and came back short. Skipped is not a problem: the tool is
        absent or cannot run here, and doctor's tool table already says so."""
        return self.state in ("missed", "failed")

    @property
    def dirs_read(self) -> tuple[int, int]:
        """(directories with every expectation met, directories expected)."""
        dirs = {location_of(e) or e for e in self.expected}
        return len(dirs - set(missed_by_dir(self.missed))), len(dirs)


def judge(tool: str, outcome: ScanOutcome, version: str | None = None) -> ToolCoverage:
    """Compare one adapter's outcome with what it is expected to read. A failed run
    misses everything it was expected to read; it is not a pass with zero results."""
    exp = expected(tool)
    if outcome.skipped:
        return ToolCoverage(tool, version, "skipped", expected=exp, detail=outcome.skipped)
    paths = {r.path for r in outcome.records}
    read = Counter(loc for r in outcome.records if (loc := location_of(r.path)))
    missed = [e for e in exp
              if e not in paths and not any(p.startswith(e + "/") for p in paths)]
    if not outcome.ok:
        state, detail = "failed", outcome.error or f"exit {outcome.returncode}"
    else:
        state, detail = ("missed" if missed else "pass"), outcome.note
    return ToolCoverage(tool, version, state, round(outcome.duration_s, 1),
                        len(outcome.records), exp, dict(sorted(read.items())),
                        missed, detail)


def not_runnable(scanner) -> str:
    """Why an installed tool cannot be measured on this machine, or "". Trivy and
    osv-scanner scan offline from `quarry db sync`'s databases, and with none they
    fail on every directory, which says nothing about directory skips."""
    from .tools import Opengrep
    root = db_dir()
    if scanner.name == "trivy" and not (root / "trivy" / "db" / "trivy.db").is_file():
        return f"trivy database absent under {root}; run `quarry db sync` first"
    if scanner.name == "osv-scanner" and not any((root / "osv").rglob("PyPI/all.zip")):
        return (f"OSV PyPI database absent under {root}; the fixture's requirements.txt "
                f"needs it. Run `quarry db sync` first")
    if isinstance(scanner, Opengrep) and scanner.available() and not scanner.config_paths():
        from .tools import rules_dir
        return f"opengrep rule pack absent under {rules_dir()}"
    return ""


def _token() -> str:
    alnum = string.ascii_letters + string.digits
    return "ghp_" + "".join(secrets.choice(alnum) for _ in range(36))


def _git(src: Path, *args: str) -> None:
    # The operator's git config stays out: a global hook, template or signing rule
    # has no business running over a fixture, and signing would prompt.
    env = {"PATH": BASE_ENV["PATH"], "LANG": "C", "HOME": str(src.parent),
           "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null"}
    subprocess.run(["git", "-C", str(src), *args], env=env, check=True,
                   capture_output=True, timeout=60)


def plant(src: Path) -> None:
    """Write the fixture into `src` and commit it. Each x.py gets its own token."""
    for d in PLANTED_DIRS:
        p = src / d
        p.mkdir(parents=True, exist_ok=True)
        (p / "x.py").write_text(PYTHON.format(token=_token()))
        (p / "Dockerfile").write_text(DOCKERFILE)
        (p / "requirements.txt").write_text(REQUIREMENTS)
    (src / WORKFLOW_DIR).mkdir(parents=True, exist_ok=True)
    (src / WORKFLOW_DIR / "ci.yml").write_text(WORKFLOW)
    _git(src, "init", "-q")
    _git(src, "add", "-A", "-f")
    _git(src, "-c", "user.email=doctor@quarry.invalid", "-c", "user.name=quarry doctor",
         "-c", "commit.gpgsign=false", "commit", "-q", "-m", "coverage fixture")


def scratch_base() -> Path:
    """Where run volumes are mounted, so the sweep's run directory sits where a real
    run's does and the Tier 1 profile treats it the same way."""
    from ..ingest.volume import MOUNT_BASE
    MOUNT_BASE.mkdir(parents=True, exist_ok=True)
    return MOUNT_BASE


def run_sweep(base: Path | None = None, *, only: list[str] | None = None,
              timeout: int = 600,
              progress: Callable[[str], None] | None = None) -> tuple[list[ToolCoverage], float]:
    """Plant the fixture in a fresh run directory under `base`, run every installed
    adapter over it, and return one verdict per tool plus the wall time in seconds."""
    from .. import orchestrator
    from .tools import registry

    t0 = time.monotonic()
    versions = orchestrator.tool_manifest()
    rundir = Path(tempfile.mkdtemp(prefix="doctor-coverage-", dir=base or scratch_base()))
    try:
        src = rundir / "src"
        plant(src)
        source = orchestrator.source_files(src)
        results: list[ToolCoverage] = []
        for name, sc in registry().items():
            if only and name not in only:
                continue
            if progress:
                progress(name)
            if why := not_runnable(sc):
                results.append(ToolCoverage(name, versions.get(name), "skipped",
                                            expected=expected(name), detail=why))
                continue
            outcome = sc.run(rundir, src, timeout=timeout)
            res = judge(name, outcome, versions.get(name))
            if outcome.coverage is not None:
                res.coverage = orchestrator.coverage_summary(outcome.coverage, source)
            results.append(res)
        return results, round(time.monotonic() - t0, 1)
    finally:
        shutil.rmtree(rundir, ignore_errors=True)
