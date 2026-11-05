"""The dashboard items in docs/IMPROVEMENT-PLAN.md P3.

Each test names the defect it pins. They render through TestClient like the rest of
the web suite, against the same seeded database: one run of `o/r` with a noisy bandit
rule, a corroborated pair, and a test-path occurrence the funnel kills.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quarry.web import queries as q             # noqa: E402

from test_web import ORIGIN, _post, seeded      # noqa: E402,F401


def _second_run(con, rid=2, target="o/r2"):
    con.execute("INSERT INTO runs (id,target,clone_url,git_sha,status) "
                "VALUES (?,?,'https://y','def456','done')", (rid, target))
    con.commit()


# ============================================================ 1. run-scoped pages

def test_run_pages_live_under_the_run_and_the_nav_keeps_it(seeded):
    """P3 item 1. The nav dropped the run, so Triage opened from run 1 showed run 2,
    whichever was newest."""
    client, con = seeded
    _second_run(con)
    for page in ("triage", "validation", "advisories"):
        r = client.get(f"/runs/1/{page}")
        assert r.status_code == 200, page
        for other in ("triage", "validation", "advisories"):
            assert f'href="/runs/1/{other}"' in r.text, (page, other)
        assert 'href="/runs/2/' not in r.text, f"{page} links into another run"
        assert 'aria-label="Pipeline for run 1"' in r.text, f"{page} has no pipeline strip"
    # the strip marks the stage whose page this is
    page = client.get("/runs/1/validation").text
    strip = page.split('aria-label="Pipeline for run 1"', 1)[1].split("</nav>", 1)[0]
    assert strip.count('aria-current="page"') == 1
    assert 'href="/runs/1/validation" class="on" aria-current="page"' in strip


def test_pages_inside_a_run_keep_it_in_the_nav(seeded):
    client, con = seeded
    _second_run(con)
    oid = con.execute("SELECT id FROM live_occurrences WHERE run_id=1 LIMIT 1"
                      ).fetchone()["id"]
    for url in ("/runs/1", f"/evidence/{oid}"):
        assert 'href="/runs/1/triage"' in client.get(url).text, url
    # a page with no run keeps the plain sections
    page = client.get("/research").text
    assert 'href="/triage"' in page and 'href="/validation"' in page


def test_the_old_query_parameter_urls_redirect_to_the_run(seeded):
    """Bookmarks written before the move keep working, and land on one URL per view."""
    client, con = seeded
    cases = {
        "/triage?run=1&verdict=confirmed": "/runs/1/triage?verdict=confirmed",
        "/validation?run=1&state=rejected": "/runs/1/validation?state=rejected",
        "/advisories?run=1": "/runs/1/advisories",
    }
    for old, new in cases.items():
        r = client.get(old, follow_redirects=False)
        assert r.status_code == 302 and r.headers["location"] == new, old
    # no run named: triage is the newest run's; validation and advisories stay global
    _second_run(con)
    r = client.get("/triage", follow_redirects=False)
    assert r.headers["location"] == "/runs/2/triage"
    assert client.get("/validation", follow_redirects=False).status_code == 200
    assert client.get("/advisories", follow_redirects=False).status_code == 200


def test_a_missing_run_is_404_on_every_scoped_page(seeded):
    client, _ = seeded
    for page in ("triage", "validation", "advisories"):
        assert client.get(f"/runs/9999/{page}").status_code == 404, page
        assert client.get(f"/runs/99999999999999999999999/{page}").status_code == 404


def test_dismiss_returns_to_the_runs_own_triage(seeded):
    client, _ = seeded
    r = _post(client, "/producers/bandit:B101/dismiss", {"run_id": 1})
    assert r.headers["location"].startswith("/runs/1/triage?undo=")
    r = _post(client, "/producers/bandit:B101/restore", {"run_id": 1})
    assert r.headers["location"] == "/runs/1/triage"


def test_run_urls_is_the_one_place_the_shapes_live():
    assert q.run_urls(7) == {"run": "/runs/7", "triage": "/runs/7/triage",
                             "validation": "/runs/7/validation",
                             "advisories": "/runs/7/advisories"}
