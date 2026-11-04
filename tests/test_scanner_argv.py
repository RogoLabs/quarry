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
    assert "--taint-intrafile" in one and "--quiet" in one


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

    def fake_tier1(rundir, argv, *, name, cwd, timeout):
        out = Path(argv[argv.index("--sarif-output") + 1])
        out.write_text("{}")
        if argv.count("--config") != 1:              # combined run: core crash, nothing
            return R(2)
        tree = Path(argv[argv.index("--config") + 1]).name
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
