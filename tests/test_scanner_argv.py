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
