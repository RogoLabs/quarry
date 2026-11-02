from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quarry.cwe import normalise, probe_class                      # noqa: E402
from quarry.disclosure.report import _title                         # noqa: E402


@pytest.mark.parametrize("raw,want", [
    ("CWE-22: Improper Limitation of a Pathname to a Restricted Directory", "CWE-22"),
    ("cwe-079", "CWE-79"), ("CWE_89", "CWE-89"), ("CWE 918", "CWE-918"), (78, "CWE-78"),
    ("CWE-79", "CWE-79"), ("", None), (None, None), ("CVE-2024-1", None),
    ("CWE-", None), (0, None), (True, None)])
def test_normalise(raw, want):
    assert normalise(raw) == want


def test_probe_class_folds_equivalents_and_report_titles_follow():
    assert probe_class("CWE-78: OS Command Injection") == "CWE-77"
    assert probe_class("CWE-1333") == "CWE-400"
    assert probe_class("CWE-22") == "CWE-22"
    assert _title("CWE-78") == "Command Injection"
