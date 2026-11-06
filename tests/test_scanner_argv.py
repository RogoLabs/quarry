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
