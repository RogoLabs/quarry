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


# ============================================================ 2. deep candidates

def _deep_candidate(con, *, path="src/deep.py", survived=1, refuted=0, verified=1,
                    refutations='[{"model": "c:2d", "verdict": "defend", "reason": "holds"}]'):
    """A Layer 2 candidate that arrived after the seeded funnel pass, as a review
    finished since then would."""
    from test_funnel import add
    oid = add(con, "deep", "authz", path, 12, message="missing authz")
    rid = con.execute("INSERT INTO research_runs (run_id,status,models,lenses,profile) "
                      "VALUES (1,'done','[\"a:1b\",\"c:2d\"]','[\"authz\"]','{}')"
                      ).lastrowid
    rf = con.execute(
        "INSERT INTO research_findings (research_id,occurrence_id,subsystem,lens,model,"
        "family,title,file,quote,quote_verified,n_survived,n_refuted,refutations) "
        "VALUES (?,?,'api','authz','a:1b','a','missing authz',?,'q',?,?,?,?)",
        (rid, oid, path, verified, survived, refuted, refutations)).lastrowid
    con.commit()
    return oid, rid, rf


def test_deep_candidates_reach_triage_only_after_the_funnel_has_seen_them(seeded):
    """P3 item 2. Candidates no funnel pass had seen were live, so triage listed them
    with their quote unchecked and their refutation unread."""
    from quarry import funnel
    client, con = seeded
    oid, _, _ = _deep_candidate(con)
    assert oid in {r["id"] for r in con.execute("SELECT id FROM live_occurrences")}
    assert "deep:authz" not in {g.producer_id for g in q.producer_groups(con, 1)}
    assert q.held_for_funnel(con, 1) == 1
    assert q.run_summary(con, 1)["held"] == 1
    page = client.get("/runs/1/triage").text
    assert "held for the funnel" in page and "quarry funnel 1" in page
    assert "deep:authz" not in page

    funnel.run(con, 1)                       # survived a cross-family refuter: passes
    assert "deep:authz" in {g.producer_id for g in q.producer_groups(con, 1)}
    assert q.held_for_funnel(con, 1) == 0
    assert "held for the funnel" not in client.get("/runs/1/triage").text


def test_a_failed_gate_never_reaches_triage(seeded):
    from quarry import funnel
    _, con = seeded
    _deep_candidate(con, survived=0, refuted=2)
    funnel.run(con, 1)
    assert "deep:authz" not in {g.producer_id for g in q.producer_groups(con, 1)}
    assert q.held_for_funnel(con, 1) == 0, "a killed candidate is not held, it is out"


def test_the_triage_detail_and_the_research_record_link_both_ways(seeded):
    """A deep occurrence showed no model, quote check or refutation, and neither page
    linked to the other."""
    from quarry import funnel
    from urllib.parse import quote
    client, con = seeded
    oid, rid, rf = _deep_candidate(con)
    funnel.run(con, 1)
    page = client.get(f"/runs/1/triage?producer={quote('deep:authz')}&occ={oid}").text
    assert f'href="/research/{rid}#cand-{rf}"' in page
    assert "quote verified" in page and "survived ×1" in page and "family a" in page
    assert "c:2d" in page and "holds" in page
    # and the research card links into triage, at this occurrence
    rpage = client.get(f"/research/{rid}").text
    assert f'id="cand-{rf}"' in rpage
    assert f"/runs/1/triage?producer=deep%3Aauthz&amp;occ={oid}" in rpage
    # the evidence page carries the same section
    assert f"#cand-{rf}" in client.get(f"/evidence/{oid}").text


def test_a_research_card_whose_occurrence_is_not_in_triage_says_where_it_is(seeded):
    from quarry import funnel
    client, con = seeded
    _, rid, _ = _deep_candidate(con)
    assert "waiting for the funnel" in client.get(f"/research/{rid}").text
    killed, rid2, _ = _deep_candidate(con, path="src/k.py", survived=0, refuted=1)
    funnel.run(con, 1)
    page = client.get(f"/research/{rid2}").text
    assert "out of the funnel" in page and f'href="/evidence/{killed}"' in page


def test_the_scan_card_does_not_count_deep_review_as_a_scanner(seeded):
    """P3 item 3. The card read "8 tool(s)" for seven scanners plus `deep`."""
    _, con = seeded
    before = q.pipeline(con, q.run_summary(con, 1))[1]
    assert before["unit"] == "raw, 2 scanner(s)"
    _deep_candidate(con)
    summary = q.run_summary(con, 1)
    scan = q.pipeline(con, summary)[1]
    assert scan["name"] == "Scan"
    assert scan["unit"] == "raw, 2 scanner(s); 1 more from deep review"
    assert scan["n"] == summary["total"] - 1 == before["n"]


def _scanned_with(con, tools: dict, vulndb: dict | None = None):
    from quarry import db

    def change(m):
        m.setdefault("scan", {}).setdefault("tools", {}).update(tools)
        if vulndb is not None:
            m["vulndb"] = vulndb
    db.update_manifest(con, 1, change)
    con.commit()


TRIVY_OK = {"ok": True, "rc": 0, "seconds": 3.0, "records": 4, "skipped": "",
            "error": "", "note": ""}


def test_the_run_page_shows_each_databases_age_at_scan_time(seeded):
    """P3 item 3, plan item 7. `scan` stored the age; no page read it."""
    client, con = seeded
    _scanned_with(con, {"trivy": TRIVY_OK, "osv-scanner": TRIVY_OK}, {
        "trivy": {"built": "2026-10-28T19:18:03+00:00", "age_days": 5.1,
                  "basis": "metadata.json UpdatedAt"},
        "osv": {"built": "2026-10-20T00:00:00+00:00", "age_days": 9.0,
                "basis": "oldest of 6 ecosystem zip download times"},
        "grype": {"built": None, "age_days": None, "basis": "import.json missing"}})
    page = client.get("/runs/1").text
    head = "Vulnerability databases at scan time (stale past 7 days)"
    assert head in page
    table = page.split(head, 1)[1].split("</table>", 1)[0]
    rows = {n: table.split(f'<td class="mono sm">{n}</td>', 1)[1].split("</tr>", 1)[0]
            for n in ("trivy", "osv", "grype")}
    assert "5.1 d" in rows["trivy"] and "stale" not in rows["trivy"]
    assert "metadata.json UpdatedAt" in rows["trivy"]
    assert "9.0 d" in rows["osv"] and "stale" in rows["osv"]
    assert "?" in rows["grype"] and "stale" in rows["grype"] and "unknown" in rows["grype"]


def test_a_run_scanned_before_ages_were_kept_says_so(seeded):
    client, con = seeded
    assert "Database ages were not recorded" not in client.get("/runs/1").text
    _scanned_with(con, {"trivy": TRIVY_OK})
    assert "Database ages were not recorded" in client.get("/runs/1").text


def test_an_offset_timestamp_is_shown_on_the_local_clock():
    import datetime as dt
    got = q.local("2026-10-28T19:18:03.419608+00:00")
    want = dt.datetime(2026, 10, 28, 19, 18, 3, tzinfo=dt.timezone.utc).astimezone()
    assert got == want.strftime("%Y-%m-%d %H:%M")
    assert q.local("2026-08-24T18:36:41") == "2026-08-24 18:36", "naive stays local"


def test_a_scanner_occurrence_has_no_deep_review_section(seeded):
    client, con = seeded
    oid = con.execute("SELECT id FROM live_occurrences WHERE run_id=1 LIMIT 1"
                      ).fetchone()["id"]
    assert q.research_finding(con, oid) is None
    assert 'id="deep-review"' not in client.get(f"/evidence/{oid}").text
