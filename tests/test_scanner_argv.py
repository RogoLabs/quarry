"""D14: a target's suppressions are parsed, never obeyed.

Each flag here was checked against the installed binary (gitleaks 8.30.1, zizmor
1.31.1): without it, a `# gitleaks:allow` comment hid a live token, and a target's
.github/zizmor.yml turned eight findings into "No findings to report".
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quarry.scanners import tools                    # noqa: E402

SRC, OUT = Path("/vol/src"), Path("/vol/out/x.json")


def test_gitleaks_ignores_inline_allow_comments():
    assert "--ignore-gitleaks-allow" in tools.Gitleaks().argv(SRC, OUT)


# --- IMPROVEMENT-PLAN item 23: each tool's own silent directory skips ------------
# Same content planted in every directory a tool is known to skip by default. Each
# list was MEASURED missing on the previous argv (bandit 1.9.4, checkov, gitleaks
# 8.30.1) and is found by the adapter now.

def _plant(src, rels, text):
    for rel in rels:
        (src / rel).parent.mkdir(parents=True, exist_ok=True)
        (src / rel).write_text(text)


def test_bandit_default_excludes_do_not_match_by_substring():
    argv = tools.Bandit().argv(SRC, OUT)
    assert argv[argv.index("-x") + 1] == "/vol/src/.git/*"


def test_bandit_scans_github_and_cvss_paths(tmp_path):
    import pytest
    b = tools.Bandit()
    if not b.available():
        pytest.skip("bandit not installed")
    src = tmp_path / "src"
    want = {"app/a.py", ".github/scripts/x.py", "lib/CVSS.py", "lib/pyCVSScalc.py",
            ".gitlab/ci.py", "hg_tools.hgx/h.py"}
    _plant(src, want, "eval(input())\n")
    _plant(src, [".git/hooks/h.py"], "eval(input())\n")

    outcome = b.run(tmp_path, src, timeout=300)

    assert outcome.ok, outcome.error
    assert {r.path for r in outcome.records} == want          # and nothing from .git/


def test_checkov_does_not_skip_dot_or_node_modules_directories(tmp_path):
    import pytest
    ck = tools.Checkov()
    assert ck.env() == {"CKV_IGNORED_DIRECTORIES": ".git",
                        "CKV_IGNORE_HIDDEN_DIRECTORIES": "false"}
    if not ck.available():
        pytest.skip("checkov not installed")
    src = tmp_path / "src"
    want = {"app/Dockerfile", "node_modules/pkg/Dockerfile", ".venv/lib/Dockerfile",
            ".github/actions/build/Dockerfile"}
    _plant(src, want, 'FROM python:3.6\nRUN pip install flask\nCMD ["python"]\n')

    outcome = ck.run(tmp_path, src, timeout=300)

    assert outcome.ok, outcome.error
    assert {r.path for r in outcome.records} == want


def test_gitleaks_config_is_the_default_without_its_path_allowlist():
    from quarry.scanners import gitleaks_config as gc
    argv = tools.Gitleaks().argv(SRC, OUT)
    assert argv[argv.index("--config") + 1] == "/vol/out/gitleaks-config.toml"
    text = gc.CONFIG.read_text()
    assert text.count("[[rules]]") > 200
    allow = text.split("\n[allowlist]\n", 1)[1].split("\n]\n", 1)[0]
    for gone in ("node_modules", "package-lock", "poetry", "vendor/", "dist-info"):
        assert gone not in allow, gone
    assert "regexes = [" in text and "stopwords = [" in text   # value filters stay
    assert "Copyright (c) 2019 Zachary Rice" in text


def test_gitleaks_config_matches_the_installed_binary():
    """A new gitleaks version ships new rules and maybe new allowlist paths. The
    vendored copy must be regenerated from it, and an unclassified path stops that."""
    import subprocess
    import pytest
    from quarry.scanners import gitleaks_config as gc
    g = tools.Gitleaks().available()
    if not g:
        pytest.skip("gitleaks not installed")
    installed = subprocess.run([g, "version"], capture_output=True, text=True,
                               timeout=20).stdout.strip()
    assert gc.config_version(gc.CONFIG.read_text()) == installed, \
        "regenerate: python -m quarry.scanners.gitleaks_config $(which gitleaks)"
    with pytest.raises(ValueError, match="unclassified"):
        gc.build(gc.extract_default(Path(g)).replace(
            "paths = [\n", "paths = [\n    '''(?:^|/)new_dir/''',\n", 1), installed)


def test_gitleaks_finds_tokens_in_dependency_trees_and_lockfiles(tmp_path):
    import secrets
    import string
    import pytest
    gl = tools.Gitleaks()
    if not gl.available():
        pytest.skip("gitleaks not installed")
    src = tmp_path / "src"
    abc = string.ascii_letters + string.digits

    def tok():
        return "ghp_" + "".join(secrets.choice(abc) for _ in range(36))
    for rel in ("app/x.py", "node_modules/pkg/x.py", "vendor/github.com/o/r/x.go",
                ".venv/lib/python3.12/site-packages/p/x.py", "bower_components/x.js"):
        _plant(src, [rel], f'GH = "{tok()}"\n')
    (src / "package-lock.json").write_text(
        '{"packages": {"node_modules/a": {"resolved": '
        f'"https://u:{tok()}@npm.example.com/a.tgz"}}}}}}\n')

    outcome = gl.run(tmp_path, src, timeout=300)

    assert outcome.ok, outcome.error
    assert {r.path for r in outcome.records} == {
        "app/x.py", "node_modules/pkg/x.py", "vendor/github.com/o/r/x.go",
        ".venv/lib/python3.12/site-packages/p/x.py", "bower_components/x.js",
        "package-lock.json"}


def test_a_config_write_never_follows_a_link_a_tool_left(tmp_path):
    """Tier 0 writes tool configs into out/, where every sandboxed tool can write.
    A link planted there must not turn that write into one outside the run."""
    from quarry.scanners.base import write_tool_config
    victim = tmp_path / "victim.txt"
    victim.write_text("operator file\n")
    (tmp_path / "out").mkdir()
    (tmp_path / "out" / "gitleaks-config.toml").symlink_to(victim)

    path = write_tool_config(tmp_path, "gitleaks-config.toml", "x = 1\n")

    assert victim.read_text() == "operator file\n"
    assert not path.is_symlink() and path.read_text() == "x = 1\n"


def test_zizmor_neither_discovers_target_config_nor_honours_ignores():
    argv = tools.Zizmor().argv(SRC, OUT)
    assert "--no-config" in argv and "--no-ignores" in argv
    assert argv[-1] == str(SRC)


# Checkov names every uri after the directory it was handed: `-d <rundir>/src` gave
# `src/<path>`, a path that is not in the clone, so every Checkov finding lost its
# evidence window and was killed by quote-verify (21 of 21 on runs 1 and 2).
def test_checkov_scans_from_inside_the_clone():
    ck = tools.Checkov()
    argv = ck.argv(SRC, OUT)
    assert argv[argv.index("-d") + 1] == "."
    assert ck.workdir(Path("/vol"), SRC) == SRC


def test_checkov_paths_are_relative_to_the_clone(tmp_path):
    import pytest
    ck = tools.Checkov()
    if not ck.available():
        pytest.skip("checkov not installed")
    src = tmp_path / "src"
    dockerfile = 'FROM python:3.12\nRUN pip install flask\nCMD ["python"]\n'
    # A repo-root src/ is the case a prefix-strip would get wrong.
    for rel in ("Dockerfile", "docker/Dockerfile", "src/Dockerfile"):
        (src / rel).parent.mkdir(parents=True, exist_ok=True)
        (src / rel).write_text(dockerfile)

    outcome = ck.run(tmp_path, src, timeout=300)

    assert outcome.ok, outcome.error
    paths = {r.path for r in outcome.records}
    assert paths == {"Dockerfile", "docker/Dockerfile", "src/Dockerfile"}
    assert all((src / p).is_file() for p in paths)


# --- opengrep: one crashing rule tree must not zero the whole tool ---------------
# MEASURED on VulnLookup: the `generic` tree crashed opengrep-core ("exited with
# unexpected output") and the combined run wrote an empty SARIF, losing the other 24
# trees' 645 findings while reporting success. The adapter now falls back to one
# invocation per tree, so a crash costs only that tree.

def test_opengrep_argv_single_config_is_the_same_shape():
    og = tools.Opengrep()
    one = og._argv(SRC, OUT, [Path("/rules/python")])
    assert one.count("--config") == 1 and one[-1] == str(SRC)
    assert "--taint-intrafile" in one and "--verbose" in one and "--quiet" not in one


def test_opengrep_does_not_apply_its_builtin_ignore_list():
    """IMPROVEMENT-PLAN item 15: with the target's .semgrepignore quarantined, opengrep
    fell back to a built-in list and skipped test/, vendor/, build/ and dist/."""
    argv = tools.Opengrep().argv(SRC, OUT)
    assert "--x-ignore-semgrepignore-files" in argv
    assert argv[argv.index("--json-output") + 1] == "/vol/out/x.targets.json"
    assert Path("/vol/out/x.targets.json") in tools.Opengrep().outputs(OUT)


_OS_SYSTEM_RULE = """rules:
- id: os-system
  languages: [python]
  severity: WARNING
  message: os.system call
  pattern: os.system(...)
"""
_DEFAULT_IGNORED = ("tests/t.py", "test/u.py", "vendor/lib/v.py", "build/b.py",
                    "dist/d.py", "node_modules/pkg/n.py")


def test_opengrep_scans_the_trees_its_default_ignore_list_names(tmp_path):
    """Live, under Tier 1. MEASURED before the fix with this layout: only app/a.py
    was scanned and the other files produced nothing and no warning."""
    import pytest
    og = tools.Opengrep()
    if not og.available():
        pytest.skip("opengrep not installed")
    rules = tmp_path / "rules" / "python"
    rules.mkdir(parents=True)
    (rules / "os-system.yml").write_text(_OS_SYSTEM_RULE)
    og.config_paths = lambda: [rules]
    src = tmp_path / "src"
    for rel in ("app/a.py", *_DEFAULT_IGNORED):
        (src / rel).parent.mkdir(parents=True, exist_ok=True)
        (src / rel).write_text("import os\nos.system(input())\n")
    # Over --max-target-bytes: skipped, and the skip must be reported, not silent.
    (src / "app" / "big.py").write_text("import os\nos.system(input())\n"
                                        + "#" * 2_100_000 + "\n")

    outcome = og.run(tmp_path, src, timeout=300)

    assert outcome.ok, outcome.error
    want = {"app/a.py", *_DEFAULT_IGNORED}
    assert {r.path for r in outcome.records} == want
    cov = outcome.coverage
    assert cov is not None and cov.unreported == []
    assert cov.scanned == want
    assert cov.skipped == {"exceeded_size_limit": {"app/big.py"}}


def test_opengrep_target_report_is_read_through_the_taint_boundary(tmp_path):
    import json
    src = tmp_path / "src"
    (src / "app").mkdir(parents=True)
    report = {
        "paths": {
            "scanned": [f"{src}/app/a.py", f"{src}/app/huge.py", "/etc/passwd"],
            "skipped": [{"path": f"{src}/app/big.py", "reason": "exceeded_size_limit"},
                        {"path": f"{src}/app/huge.py",
                         "reason": "analysis_failed_parser_or_internal_error"},
                        {"path": "../../escape.py", "reason": "exceeded_size_limit"}],
        },
        "errors": [{"type": "Timeout", "path": f"{src}/app/huge.py"}] * 3
                  + [{"type": ["PartialParsing", [{"path": "x"}]], "path": "x"}],
    }
    out = tmp_path / "out" / "opengrep.json"
    out.parent.mkdir()
    tools.Opengrep.targets_path(out).write_text(json.dumps(report))

    cov = tools.Opengrep().coverage(out, src, label="combined")

    assert cov.scanned == {"app/a.py", "app/huge.py"}      # /etc/passwd refused
    assert cov.skipped == {"exceeded_size_limit": {"app/big.py"},
                           "analysis_failed_parser_or_internal_error": {"app/huge.py"}}
    assert cov.errors == {"Timeout": 3, "PartialParsing": 1}
    assert tools.Opengrep().coverage(tmp_path / "out" / "none.json", src,
                                     label="python").unreported == ["python"]


def test_opengrep_recovers_per_tree_when_the_combined_run_crashes(tmp_path, monkeypatch):
    from quarry.scanners import base, tools as T
    (tmp_path / "out").mkdir()
    (tmp_path / "src").mkdir()
    trees = [tmp_path / "rules" / n for n in ("python", "generic", "javascript")]
    for t in trees:
        t.mkdir(parents=True)
    og = T.Opengrep()
    monkeypatch.setattr(og, "available", lambda: "/usr/bin/opengrep")
    monkeypatch.setattr(og, "config_paths", lambda: trees)
    monkeypatch.setattr(og, "workdir", lambda rundir, src: src)

    class R:
        def __init__(self, rc):
            self.returncode, self.duration_s = rc, 1.0

        def stderr_bytes(self):
            return b""

    names = []

    def fake_tier1(rundir, argv, *, name, cwd, timeout):
        names.append(name)
        out = Path(argv[argv.index("--sarif-output") + 1])
        out.write_text("{}")
        if argv.count("--config") != 1:              # combined run: core crash, nothing
            return R(2)
        tree = Path(argv[argv.index("--config") + 1]).name
        if tree != "generic":                        # a crashed tree writes no report
            import json
            Path(argv[argv.index("--json-output") + 1]).write_text(json.dumps(
                {"paths": {"scanned": [f"{tree}.src"], "skipped": []}}))
        return R(2) if tree == "generic" else R(0)   # one tree crashes, the rest are fine

    monkeypatch.setattr(base, "tier1", fake_tier1)
    monkeypatch.setattr(T, "tier1", fake_tier1)

    def fake_parse(out, src):
        name = Path(out).stem                         # opengrep / opengrep-python / ...
        tree = name.split("-", 1)[1] if "-" in name else "combined"
        if tree in ("python", "javascript"):
            return [base.Record(tool="opengrep", rule_id=f"{tree}.rule", path="app.py")]
        return []                                     # combined and generic yield nothing

    monkeypatch.setattr(og, "parse", fake_parse)

    outcome = og.run(tmp_path, tmp_path / "src", timeout=300)
    assert outcome.ok and outcome.returncode == 0
    assert {r.rule_id for r in outcome.records} == {"python.rule", "javascript.rule"}
    assert "generic" in outcome.note and "1 of 3" in outcome.note
    # Coverage is the union of the trees that reported, and the one that did not is named.
    assert outcome.coverage.scanned == {"python.src", "javascript.src"}
    assert outcome.coverage.unreported == ["generic"]
    # Each run keeps its own log; one shared name left only the last tree's.
    assert names == ["opengrep", "opengrep-python", "opengrep-generic",
                     "opengrep-javascript"]


def test_opengrep_with_every_tree_failing_is_a_failure(tmp_path, monkeypatch):
    """MEASURED: an option opengrep 1.27.1 rejects made the combined run and all 25
    per-tree runs exit 2 with no output, and the adapter returned ok=True."""
    from quarry.scanners import base, tools as T
    (tmp_path / "out").mkdir()
    (tmp_path / "src").mkdir()
    trees = [tmp_path / "rules" / n for n in ("python", "generic")]
    og = T.Opengrep()
    monkeypatch.setattr(og, "available", lambda: "/usr/bin/opengrep")
    monkeypatch.setattr(og, "config_paths", lambda: trees)
    monkeypatch.setattr(og, "workdir", lambda rundir, src: src)

    class R:
        returncode, duration_s = 2, 1.0

        def stderr_bytes(self):
            return b"Error: No such option"

    monkeypatch.setattr(base, "tier1", lambda *a, **k: R())
    monkeypatch.setattr(T, "tier1", lambda *a, **k: R())
    outcome = og.run(tmp_path, tmp_path / "src", timeout=300)
    assert not outcome.ok and "every rule tree failed (2 of 2)" in outcome.error
    assert outcome.coverage.unreported == ["python", "generic"]


def test_opengrep_keeps_combined_result_when_it_does_not_crash(tmp_path, monkeypatch):
    from quarry.scanners import base, tools as T
    (tmp_path / "out").mkdir()
    (tmp_path / "src").mkdir()
    og = T.Opengrep()
    monkeypatch.setattr(og, "available", lambda: "/usr/bin/opengrep")
    monkeypatch.setattr(og, "config_paths", lambda: [tmp_path / "rules" / "python"])
    monkeypatch.setattr(og, "workdir", lambda rundir, src: src)
    per_tree = {"n": 0}

    class R:
        def __init__(self, rc):
            self.returncode, self.duration_s = rc, 1.0

        def stderr_bytes(self):
            return b""

    def fake_tier1(rundir, argv, *, name, cwd, timeout):
        if argv.count("--config") == 1 and "opengrep-" in argv[argv.index("--sarif-output") + 1]:
            per_tree["n"] += 1
        Path(argv[argv.index("--sarif-output") + 1]).write_text("{}")
        return R(0)

    monkeypatch.setattr(base, "tier1", fake_tier1)
    monkeypatch.setattr(T, "tier1", fake_tier1)
    monkeypatch.setattr(og, "parse",
                        lambda out, src: [base.Record(tool="opengrep", rule_id="r", path="a")])
    outcome = og.run(tmp_path, tmp_path / "src", timeout=300)
    assert outcome.ok and len(outcome.records) == 1 and outcome.note == ""
    assert per_tree["n"] == 0                          # no fallback when combined succeeds


def _slow_tree_setup(tmp_path, monkeypatch, *, second_pass_ok: bool):
    from quarry.scanners import base, tools as T
    (tmp_path / "out").mkdir()
    (tmp_path / "src").mkdir()
    trees = [tmp_path / "rules" / n for n in ("python", "generic", "go", "rust")]
    og = T.Opengrep()
    monkeypatch.setattr(og, "available", lambda: "/usr/bin/opengrep")
    monkeypatch.setattr(og, "config_paths", lambda: trees)
    monkeypatch.setattr(og, "workdir", lambda rundir, src: src)
    budgets: list[tuple[str, int]] = []

    class R:
        def __init__(self, rc, secs):
            self.returncode, self.duration_s = rc, secs

    def fake_tier1(rundir, argv, *, name, cwd, timeout):
        out = Path(argv[argv.index("--sarif-output") + 1])
        if argv.count("--config") != 1:              # combined run: core crash
            out.write_text("{}")
            return R(2, 1.0)
        tree = Path(argv[argv.index("--config") + 1]).name
        budgets.append((tree, timeout))
        if tree == "python" and (timeout <= 75 or not second_pass_ok):
            return R(-9, float(timeout))             # killed at the end of its budget
        out.write_text("{}")
        import json
        Path(argv[argv.index("--json-output") + 1]).write_text(json.dumps(
            {"paths": {"scanned": [f"{tree}.src"], "skipped": []}}))
        return R(0, 2.0)

    monkeypatch.setattr(base, "tier1", fake_tier1)
    monkeypatch.setattr(T, "tier1", fake_tier1)
    monkeypatch.setattr(og, "parse", lambda out, src: [] if Path(out).stem == "opengrep"
                        else [base.Record(tool="opengrep", rule_id=f"{Path(out).stem}.rule",
                                          path="a.py")])
    return og, budgets


def test_a_tree_that_outruns_its_slice_is_rerun_with_the_time_left(tmp_path, monkeypatch):
    """MEASURED on run 4: four trees were killed at the 72 s slice with no output while
    about 1500 s of opengrep's 1800 s budget went unused."""
    og, budgets = _slow_tree_setup(tmp_path, monkeypatch, second_pass_ok=True)
    outcome = og.run(tmp_path, tmp_path / "src", timeout=300)
    assert budgets[:4] == [("python", 75), ("generic", 75), ("go", 75), ("rust", 75)]
    assert budgets[4][0] == "python" and budgets[4][1] > 200
    assert "opengrep-python.rule" in {r.rule_id for r in outcome.records}
    assert "rerun with the time the others left: python" in outcome.note
    assert "skipped" not in outcome.note
    assert outcome.coverage.unreported == []


def test_a_tree_still_out_of_time_after_the_rerun_is_named(tmp_path, monkeypatch):
    og, budgets = _slow_tree_setup(tmp_path, monkeypatch, second_pass_ok=False)
    outcome = og.run(tmp_path, tmp_path / "src", timeout=300)
    assert [t for t, _ in budgets].count("python") == 2
    assert outcome.ok and "1 of 4" in outcome.note and "(out of time: python)" in outcome.note
    assert outcome.coverage.unreported == ["python"]


# --- opengrep: a crash is pinned to a file, not charged to the whole tree ----------
# MEASURED on VulnLookup (run 7, opengrep 1.27.1): the generic tree crashed on every
# run ("opengrep-core exited with -10!", SIGBUS from a worker thread's stack overflow)
# and lost all 123 of its findings over 1,139 files. One file caused it. It crashes
# alone at -j 2 and above and scans cleanly at -j 1.

_CRASH = (b"opengrep-core exited with -10!\n"
          b"Error: opengrep-core exited with unexpected output\n")


def _crash_setup(tmp_path, monkeypatch, *, crashes_alone=False, every_file=False):
    """A clone with a file that crashes the generic tree whenever it is in a parallel
    run. The fake writes a real SARIF result and target report for every file it is
    given, so the real parser and coverage reader run."""
    import json
    from quarry.scanners import base, tools as T
    src = tmp_path / "src"
    files = ["a.py", "lib/b.py", "lib/c.conf", "lib/d.py", "docs/e.md", "docs/f.md"]
    for rel in files + [".git/HEAD"]:
        (src / rel).parent.mkdir(parents=True, exist_ok=True)
        (src / rel).write_text("x = 1\n")
    (tmp_path / "outside").mkdir()
    (tmp_path / "outside" / "host.py").write_text("x = 1\n")
    (src / "link").symlink_to(tmp_path / "outside")
    (src / "lib" / "l.py").symlink_to(tmp_path / "outside" / "host.py")
    (tmp_path / "out").mkdir()
    trees = [tmp_path / "rules" / n for n in ("python", "generic")]
    og = T.Opengrep()
    monkeypatch.setattr(og, "available", lambda: "/usr/bin/opengrep")
    monkeypatch.setattr(og, "config_paths", lambda: trees)
    monkeypatch.setattr(og, "workdir", lambda rundir, src: rundir / "out")
    runs: list[dict] = []
    root = src.resolve()

    class R:
        def __init__(self, rc, err=b""):
            self.returncode, self.duration_s, self._err = rc, 1.0, err

        def stderr_bytes(self):
            return self._err

    def under(targets):
        """What a run over these targets reads: files, and the files under a
        directory, never through a link or into .git."""
        got = []
        for t in map(Path, targets):
            if t.is_file() and not t.is_symlink():
                got.append(t.relative_to(root).as_posix())
            elif t.is_dir() and not t.is_symlink():
                got += [p.relative_to(root).as_posix() for p in t.rglob("*")
                        if p.is_file() and not p.is_symlink()
                        and not ({".git", "link"} & set(p.relative_to(root).parts))]
        return sorted(got)

    def fake_tier1(rundir, argv, *, name, cwd, timeout):
        out = Path(argv[argv.index("--sarif-output") + 1])
        report = Path(argv[argv.index("--json-output") + 1])
        targets = argv[argv.index("--verbose") + 1:]
        jobs = argv[argv.index("-j") + 1] if "-j" in argv else None
        tree = (Path(argv[argv.index("--config") + 1]).name
                if argv.count("--config") == 1 else "combined")
        seen = under(targets)
        runs.append({"name": name, "tree": tree, "files": seen, "jobs": jobs,
                     "targets": len(targets),
                     "argv_bytes": sum(len(t) + 1 for t in targets)})
        out.write_text("{}")
        crash = tree in ("combined", "generic") and bool(seen) and (
            every_file or ("lib/c.conf" in seen and (jobs != "1" or crashes_alone)))
        if crash:
            report.write_text(json.dumps({
                "errors": [{"message": "Error: opengrep-core exited with unexpected "
                                       "output"}],
                "paths": {"scanned": [], "skipped": []}}))
            return R(2, _CRASH)
        results = [{"ruleId": f"x.opengrep_opengrep-rules.{tree}.rule",
                    "locations": [{"physicalLocation": {
                        "artifactLocation": {"uri": str(root / f)},
                        "region": {"startLine": 1}}}]} for f in seen]
        out.write_text(json.dumps({"runs": [{"tool": {"driver": {}},
                                             "results": results}]}))
        report.write_text(json.dumps({"paths": {
            "scanned": [str(root / f) for f in seen], "skipped": []}}))
        return R(0)

    monkeypatch.setattr(base, "tier1", fake_tier1)
    monkeypatch.setattr(T, "tier1", fake_tier1)
    return og, runs, files


def _under(paths, files):
    """The files a set of reported paths (files or directories) accounts for."""
    return {f for f in files for p in paths if f == p or f.startswith(p + "/")}


def test_a_file_that_crashes_a_tree_is_isolated_and_scanned_alone(tmp_path, monkeypatch):
    og, runs, files = _crash_setup(tmp_path, monkeypatch)

    outcome = og.run(tmp_path, tmp_path / "src", timeout=300)

    assert outcome.ok
    got = {(r.rule_id, r.path) for r in outcome.records}
    # Every file's generic finding is back, the crashing one included (at -j 1).
    assert {p for t, p in got if t == "generic.rule"} == set(files)
    assert {p for t, p in got if t == "python.rule"} == set(files)
    assert len(outcome.records) == 2 * len(files)        # no file counted twice
    assert outcome.coverage.scanned == set(files)
    assert not outcome.coverage.skipped and outcome.coverage.unreported == []
    assert "scanned alone with -j 1: lib/c.conf" in outcome.note
    assert "produced no usable output" not in outcome.note
    split = [r for r in runs if r["name"].startswith("opengrep-generic.")]
    assert [r["files"] for r in split if r["jobs"] == "1"] == [["lib/c.conf"]]
    # Split runs never name .git or a link, and each keeps its own log.
    assert all(".git/HEAD" not in r["files"] and "lib/l.py" not in r["files"]
               for r in split)
    assert len({r["name"] for r in split}) == len(split)
    assert [r["name"] for r in runs].count("opengrep-python") == 1


def test_a_file_that_crashes_even_alone_is_a_named_skip(tmp_path, monkeypatch):
    og, runs, files = _crash_setup(tmp_path, monkeypatch, crashes_alone=True)

    outcome = og.run(tmp_path, tmp_path / "src", timeout=300)

    assert outcome.ok
    generic = {r.path for r in outcome.records if r.rule_id == "generic.rule"}
    assert generic == set(files) - {"lib/c.conf"}
    reason = "crashed opengrep-core even alone with -j 1, generic rules"
    assert outcome.coverage.skipped == {reason: {"lib/c.conf"}}
    assert "crashed even alone, not scanned: lib/c.conf" in outcome.note
    # And the orchestrator names it, by reason, in the run's health.
    from quarry import orchestrator
    summary = orchestrator.coverage_summary(outcome.coverage, set(files))
    assert summary["skipped"][reason] == {"n": 1, "examples": ["lib/c.conf"]}
    assert any("lib/c.conf" in m for m in orchestrator.coverage_health(summary))


def test_a_crash_on_every_file_stops_after_a_few_and_names_the_rest(tmp_path, monkeypatch):
    """A rule that kills opengrep-core on any input would otherwise run every file
    alone, twice."""
    og, runs, files = _crash_setup(tmp_path, monkeypatch, every_file=True)

    outcome = og.run(tmp_path, tmp_path / "src", timeout=300)

    assert outcome.ok                                  # the python tree still counts
    assert not any(r.rule_id == "generic.rule" for r in outcome.records)
    skipped = outcome.coverage.skipped
    crashed = skipped["crashed opengrep-core even alone with -j 1, generic rules"]
    untried = skipped["every split run crashed opengrep-core, generic rules"]
    assert len(crashed) == og.ISOLATE_GIVE_UP
    assert crashed | _under(untried, files) == set(files)
    assert "the crash did not depend on the file" in outcome.note
    assert "produced no usable output and were skipped: generic" in outcome.note


def test_isolation_splits_a_group_before_its_paths_outgrow_the_command_line(
        tmp_path, monkeypatch):
    og, runs, files = _crash_setup(tmp_path, monkeypatch)
    monkeypatch.setattr(og, "ISOLATE_ARGV_BYTES", 1)

    outcome = og.run(tmp_path, tmp_path / "src", timeout=300)

    split = [r for r in runs if r["name"].startswith("opengrep-generic.")]
    assert split and all(r["targets"] == 1 for r in split)   # one path each
    assert {r.path for r in outcome.records if r.rule_id == "generic.rule"} == set(files)


def test_isolation_stops_at_its_deadline_and_names_what_it_did_not_reach(
        tmp_path, monkeypatch):
    import time as _time
    og, runs, files = _crash_setup(tmp_path, monkeypatch)
    from quarry.scanners import base, tools as T
    clock = {"t": _time.time()}
    inner = T.tier1

    def slow_tier1(rundir, argv, **kw):
        clock["t"] += 40                              # every run costs 40 s
        return inner(rundir, argv, **kw)

    monkeypatch.setattr(T, "tier1", slow_tier1)
    monkeypatch.setattr(base, "tier1", slow_tier1)
    monkeypatch.setattr(_time, "time", lambda: clock["t"])

    outcome = og.run(tmp_path, tmp_path / "src", timeout=200)

    late = outcome.coverage.skipped[
        "out of time isolating an opengrep-core crash, generic rules"]
    generic = {r.path for r in outcome.records if r.rule_id == "generic.rule"}
    assert late and generic | _under(late, files) == set(files)   # scanned or named
    assert "out of time before they were scanned" in outcome.note


def test_opengrep_argv_takes_explicit_targets_and_jobs():
    og = tools.Opengrep()
    argv = og._argv(SRC, OUT, [Path("/rules/generic")],
                    targets=[SRC / "a.py", SRC / "lib"], jobs=1)
    assert argv[-3:] == ["--verbose", "/vol/src/a.py", "/vol/src/lib"]
    assert argv[argv.index("-j") + 1] == "1"
    assert "-j" not in og._argv(SRC, OUT, [Path("/rules/generic")])


def test_split_entries_never_follow_a_link_or_enter_git(tmp_path):
    src = tmp_path / "src"
    (src / "app").mkdir(parents=True)
    (src / "app" / "a.py").write_text("x\n")
    (src / ".git").mkdir()
    (tmp_path / "host").mkdir()
    (src / "linked").symlink_to(tmp_path / "host")
    (src / "app" / "l.py").symlink_to(tmp_path / "host")
    assert tools.Opengrep._entries(src, "") == ["app"]
    assert tools.Opengrep._entries(src, "app") == ["app/a.py"]
    assert tools.Opengrep._entries(src, "linked") is None        # refused, not listed
    assert tools.Opengrep._entries(src, "app/a.py") is None      # a file
