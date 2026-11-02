"""IMPROVEMENT-PLAN item 7: a scan records how old each vulnerability database was,
and says so when it is past STALE_DAYS. A clean result from a months-old database
otherwise reads exactly like a clean result from today's."""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quarry import db, orchestrator, vulndb                       # noqa: E402
from quarry.scanners import base                                   # noqa: E402
from test_scan_bookkeeping import _Canned, _ok, _scan_env          # noqa: E402

NOW = datetime(2026, 11, 2, 12, 0, tzinfo=timezone.utc)


def _dbs(root: Path) -> Path:
    (root / "trivy" / "db").mkdir(parents=True)
    (root / "trivy" / "db" / "metadata.json").write_text(json.dumps(
        {"Version": 2, "UpdatedAt": "2026-10-28T19:18:03.419608319Z",
         "NextUpdate": "2026-10-29T19:18:03.419608078Z"}))
    (root / "grype" / "6").mkdir(parents=True)
    (root / "grype" / "6" / "import.json").write_text(json.dumps(
        {"source": "x/vulnerability-db_v6.1.10_2026-10-12T00:24:28Z_1793168610.tar.zst"}))
    for eco, day in (("PyPI", 30), ("npm", 31)):
        z = root / "osv" / "osv-scalibr" / eco / "all.zip"
        z.parent.mkdir(parents=True)
        z.write_bytes(b"")
        t = datetime(2026, 10, day, tzinfo=timezone.utc).timestamp()
        os.utime(z, (t, t))
    return root


def test_each_database_build_time_is_read_from_its_own_metadata(tmp_path):
    a = vulndb.ages(NOW, _dbs(tmp_path))
    assert a["trivy"]["built"] == "2026-10-28T19:18:03.419608+00:00"   # nanoseconds cut
    assert a["trivy"]["age_days"] == 4.7
    assert a["grype"]["built"] == "2026-10-12T00:24:28+00:00"
    assert a["osv"]["built"] == "2026-10-30T00:00:00+00:00"             # the oldest zip
    assert "2 ecosystem" in a["osv"]["basis"]


def test_a_missing_database_has_no_age_and_says_why(tmp_path):
    a = vulndb.ages(NOW, tmp_path)
    assert all(v["built"] is None and v["age_days"] is None for v in a.values())
    w = vulndb.stale_warnings(a, ["trivy", "osv-scanner", "bandit"])
    assert set(w) == {"trivy", "osv-scanner"}
    assert "build time unknown" in w["trivy"][0]


def test_stale_warnings_only_past_the_threshold():
    a = {"trivy": {"age_days": vulndb.STALE_DAYS + 0.5}, "osv": {"age_days": 1.0}}
    w = vulndb.stale_warnings(a, ["trivy", "osv-scanner"])
    assert "8 days old" in w["trivy"][0] and w["osv-scanner"] == []


def test_scan_keeps_the_age_of_each_database_it_used(tmp_path, monkeypatch):
    ages = {"trivy": {"built": "2026-09-01T00:00:00+00:00", "age_days": 62.0, "basis": "b"},
            "grype": {"built": None, "age_days": None, "basis": "b"},
            "osv": {"built": "2026-11-01T00:00:00+00:00", "age_days": 1.5, "basis": "b"}}
    monkeypatch.setattr(vulndb, "ages", lambda: ages)
    tools = {"trivy": _Canned("trivy", _ok()), "bandit": _Canned("bandit", _ok())}
    c, paths = _scan_env(tmp_path, monkeypatch, tools)
    orchestrator.scan(paths, c, 1)
    m = db.read_manifest(c, 1)
    assert m["vulndb"] == {"trivy": ages["trivy"]}          # only what this scan read
    assert "62 days old" in m["health"]["vulndb"]["trivy"][0]
