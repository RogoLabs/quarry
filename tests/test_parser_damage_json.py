"""Bandit and Gitleaks: one malformed entry costs that entry, counted (IMPROVEMENT-PLAN
P4). The SARIF parsers got this on 2026-11-06; these two JSON parsers still raised out
of the parser and lost every good finding beside the bad one."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quarry.scanners import base                              # noqa: E402
from quarry.scanners.tools import Bandit, Gitleaks             # noqa: E402


def _parse(scanner, doc, tmp_path):
    src = tmp_path / "src"
    (src / "app").mkdir(parents=True)
    (src / "app" / "a.py").write_text("x = 1\n")
    out = tmp_path / "out.json"
    out.write_text(json.dumps(doc))
    scanner.dropped = {}
    return list(scanner.parse(out, src)), scanner.dropped, src


def test_bandit_keeps_the_good_entries_beside_a_bad_one(tmp_path):
    src = str(tmp_path / "src")
    good = {"filename": f"{src}/app/a.py", "test_id": "B105", "line_number": 1,
            "issue_text": "hardcoded", "issue_severity": "LOW", "issue_cwe": {"id": 259}}
    doc = {"results": [good, "not an entry", {**good, "issue_cwe": "CWE-259"},
                       {**good, "filename": "/etc/passwd"}, good]}
    recs, dropped, _ = _parse(Bandit(), doc, tmp_path)
    assert len(recs) == 2 and recs[0].cwe == "CWE-259"
    assert dropped == {base.DAMAGED_RESULT: 2, base.NO_PATH: 1}


def test_gitleaks_keeps_the_good_entries_beside_a_bad_one(tmp_path):
    src = str(tmp_path / "src")
    good = {"File": f"{src}/app/a.py", "RuleID": "generic-api-key", "StartLine": 1,
            "EndLine": 1, "Description": "key", "Secret": "abc123", "Fingerprint": "f"}
    doc = [good, 7, {**good, "File": 42}, good]
    recs, dropped, _ = _parse(Gitleaks(), doc, tmp_path)
    assert len(recs) == 2
    assert dropped == {base.DAMAGED_RESULT: 1, base.NO_PATH: 1}   # 7, then File: 42
    assert all("Secret" not in r.raw for r in recs)
