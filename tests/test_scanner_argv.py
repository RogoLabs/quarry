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
