"""Validate's probe budget goes to findings a probe can address.

On the 2026-11-06 test run every rule's precision was still 0 on a fresh database, so
candidates came out in occurrence order: 38 of VulnLookup's 50 slots went to findings in
files with no route, where every probe can only answer "no route to inject into", while
65 of the 448 eligible findings sat in files that serve one. Two occurrences of one
finding in one file were also probed twice.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quarry import db                                   # noqa: E402
from quarry.dynamic import validate                     # noqa: E402

# (finding, producer, path) in occurrence order. The xss rule is plentiful and sits in
# files without routes first, the way an occurrence-ordered list looked on VulnLookup.
OCCURRENCES = [
    ("x1", "p:xss", "lib/a.py"), ("x2", "p:xss", "lib/b.py"), ("x3", "p:xss", "lib/c.py"),
    ("x4", "p:xss", "web/views.py"), ("x5", "p:xss", "web/views.py"),
    ("x5", "p:xss", "web/views.py"),                     # a second occurrence, same file
    ("s1", "p:ssrf", "web/fetch.py"), ("s2", "p:ssrf", "lib/net.py"),
    ("c1", "p:cmd", "web/admin.py"),
]
ROUTED = {"web/views.py", "web/fetch.py", "web/admin.py"}


@pytest.fixture
def con(tmp_path):
    p = tmp_path / "quarry.db"
    db.init(p)
    c = db.connect(p)
    with db.tx(c):
        c.execute("INSERT INTO runs (id, target, clone_url) VALUES (1,'o/r','https://x')")
        c.execute("""INSERT INTO producers (id, tool, rule_id, cwe, n_adjudicated, n_confirmed)
                     VALUES ('p:xss','opengrep','xss','CWE-79',0,0),
                            ('p:ssrf','opengrep','ssrf','CWE-918',0,0),
                            ('p:cmd','opengrep','cmd','CWE-78',0,0)""")
        for i, (fid, pid, path) in enumerate(OCCURRENCES, start=10):
            c.execute("""INSERT OR IGNORE INTO findings
                           (id,target,path,producer_id,first_seen_run,last_seen_run)
                         VALUES (?,?,?,?,1,1)""", (fid, "o/r", path, pid))
            c.execute("""INSERT INTO occurrences
                           (id,run_id,finding_id,producer_id,path,start_line,message)
                         VALUES (?,1,?,?,?,?,'m')""", (i, fid, pid, path, i))
    return c


def _routes(path):
    return ["GET /x"] if path in ROUTED else []


def test_without_a_route_map_the_order_is_unchanged_but_duplicates_go(con):
    ids = [c.finding_id for c in validate.select_candidates(con, 1)]
    assert ids == ["x1", "x2", "x3", "x4", "x5", "s1", "s2", "c1"]


def test_routed_findings_come_first_and_classes_take_turns(con):
    cands = validate.select_candidates(con, 1, routed=_routes)
    ids = [c.finding_id for c in cands]
    # routed: xss, ssrf and cmd take turns, then xss again; unrouted: xss, ssrf, xss, xss
    assert ids == ["x4", "s1", "c1", "x5", "x1", "s2", "x2", "x3"]


def test_the_limit_applies_after_ordering(con):
    cands = validate.select_candidates(con, 1, limit=3, routed=_routes)
    assert [c.finding_id for c in cands] == ["x4", "s1", "c1"]
    assert all(c.path in ROUTED for c in cands)
