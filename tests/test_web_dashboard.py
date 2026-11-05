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

from test_web import (ORIGIN, _post, _utc_now, bystander, seeded,  # noqa: E402,F401
                      worker)


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


# ============================================================ 4. dismiss semantics

def _occ(con, run_id, tool, rule, path, line=10):
    """`test_funnel.add` for any run. The finding id is line-number-free in spirit
    here too: the same (tool, rule, path, line) in a later run is the same finding."""
    from quarry import db
    pid = db.upsert_producer(con, tool, rule)
    fid = f"f{tool}{rule}{path}{line}"
    con.execute("INSERT OR IGNORE INTO findings (id,target,path,producer_id,"
                "first_seen_run,last_seen_run) VALUES (?,?,?,?,?,?)",
                (fid, "o/r", path, pid, run_id, run_id))
    sha = f"blob{tool}{rule}{path}{line}"
    con.execute("INSERT OR IGNORE INTO evidence_blobs (sha,path,file_sha256,start_line,"
                "end_line,body,bytes) VALUES (?,?,?,?,?,?,?)",
                (sha, path, "x", max(1, line - 40), line + 40, b"", 0))
    oid = con.execute("INSERT INTO occurrences (run_id,finding_id,producer_id,path,"
                      "start_line,message,severity,blob_sha,raw_result) "
                      "VALUES (?,?,?,?,?,'','medium',?,'{}')",
                      (run_id, fid, pid, path, line, sha)).lastrowid
    con.commit()
    return oid


def _rescan(con, rid, target, rows):
    """A new run of `target` with these (tool, rule, path) occurrences, funnelled."""
    from quarry import funnel
    _second_run(con, rid, target)
    ids = [_occ(con, rid, t, r, p, 20 + i) for i, (t, r, p) in enumerate(rows)]
    funnel.run(con, rid)
    return ids


def _live_ids(con) -> set[int]:
    return {r["id"] for r in con.execute("SELECT id FROM live_occurrences")}


def _ledger_size(con) -> tuple[int, int]:
    return (con.execute("SELECT COUNT(*) c FROM occurrences").fetchone()["c"],
            con.execute("SELECT COUNT(*) c FROM funnel_events").fetchone()["c"])


def test_a_repo_dismissal_holds_for_the_next_run_of_the_same_repo(seeded):
    """P3 item 4. "Dismiss for this repo" killed only this run's occurrences, so the
    next scan of the same repository brought the producer straight back."""
    from quarry import dismissals
    client, con = seeded
    _post(client, "/producers/bandit:B101/dismiss",
          {"run_id": 1, "scope": "repo", "note": "style, not security"})
    row = con.execute("SELECT reason FROM funnel_events WHERE occurrence_id IS NULL "
                      "AND producer_id='bandit:B101'").fetchone()
    assert row["reason"] == "producer dismissed for this repo: style, not security"
    assert con.execute("SELECT enabled FROM producers WHERE id='bandit:B101'"
                       ).fetchone()["enabled"] == 1, "a repo dismissal disables nothing"

    b101, b113 = _rescan(con, 2, "o/r", [("bandit", "B101", "src/x.py"),
                                         ("bandit", "B113", "src/y.py")])
    assert b101 not in _live_ids(con) and b113 in _live_ids(con)
    why = con.execute("SELECT stage, reason FROM funnel_events WHERE occurrence_id=? "
                      "AND action='kill'", (b101,)).fetchone()
    assert (why["stage"], why["reason"]) == (dismissals.FUNNEL_STAGE, dismissals.FUNNEL_REPO)

    other, = _rescan(con, 3, "someone/else", [("bandit", "B101", "src/x.py")])
    assert other in _live_ids(con), "a repo dismissal must not reach another repository"

    size = _ledger_size(con)
    r = _post(client, "/producers/bandit:B101/restore", {"run_id": 2})
    assert r.status_code == 303
    assert b101 in _live_ids(con), "restore must undo the funnel's dismissal kill"
    assert dismissals.repo_dismissal(con, "bandit:B101", "o/r") is None
    later, = _rescan(con, 4, "o/r", [("bandit", "B101", "src/x.py")])
    assert later in _live_ids(con), "a withdrawn repo dismissal no longer holds"
    after = _ledger_size(con)
    assert after[0] >= size[0] and after[1] > size[1], "restoring appends; it never deletes"


def test_restore_undoes_the_funnels_corpus_dismissal_kill_in_a_later_run(seeded):
    client, con = seeded
    _post(client, "/producers/bandit:B101/dismiss",
          {"run_id": 1, "scope": "corpus", "note": "noise"})
    b101, = _rescan(con, 2, "o/r", [("bandit", "B101", "src/x.py")])
    assert b101 not in _live_ids(con)
    assert q.restorable_occurrences(con, 2, "bandit:B101") == [b101]
    assert q.operator_killed(con, 2, "bandit:B101") == [], \
        "the old rule missed it: the kill was the funnel's, on the dismissal's behalf"

    _post(client, "/producers/bandit:B101/restore", {"run_id": 2})
    assert b101 in _live_ids(con)
    row = con.execute("SELECT enabled, dismissed_note FROM producers "
                      "WHERE id='bandit:B101'").fetchone()
    assert row["enabled"] == 0 and row["dismissed_note"] == "noise", \
        "the corpus switch is undone only from the run that threw it"
    _post(client, "/producers/bandit:B101/restore", {"run_id": 1})
    assert con.execute("SELECT enabled FROM producers WHERE id='bandit:B101'"
                       ).fetchone()["enabled"] == 1


def test_a_dismissal_never_lets_restore_revive_an_unrelated_kill(seeded):
    """The funnel's path-class kill on a test file stands through dismiss and restore,
    in a later run as in the first."""
    client, con = seeded
    _post(client, "/producers/bandit:B101/dismiss", {"run_id": 1, "scope": "repo"})
    src, test = _rescan(con, 2, "o/r", [("bandit", "B101", "src/x.py"),
                                        ("bandit", "B101", "tests/test_x.py")])
    assert q.restorable_occurrences(con, 2, "bandit:B101") == [src]
    _post(client, "/producers/bandit:B101/restore", {"run_id": 2})
    assert src in _live_ids(con) and test not in _live_ids(con)


def test_a_repo_dismissal_does_not_hide_the_corpus_one_from_restore(seeded):
    """Both write producer-level operator rows; restore read only the newest."""
    client, con = seeded
    _post(client, "/producers/bandit:B101/dismiss",
          {"run_id": 1, "scope": "corpus", "note": "noise"})
    _post(client, "/producers/bandit:B101/dismiss", {"run_id": 1, "scope": "repo"})
    assert q.corpus_dismissal_run(con, "bandit:B101") == 1
    _post(client, "/producers/bandit:B101/restore", {"run_id": 1})
    assert con.execute("SELECT enabled FROM producers WHERE id='bandit:B101'"
                       ).fetchone()["enabled"] == 1


def test_the_dismiss_form_takes_a_note_and_the_ledger_keeps_it(seeded):
    client, con = seeded
    page = client.get("/runs/1/triage").text
    form = page.split('class="actions"', 1)[1].split("</form>", 1)[0]
    assert 'name="note"' in form and "every later funnel pass" in form
    _post(client, "/producers/bandit:B101/dismiss",
          {"run_id": 1, "scope": "repo", "note": "  vendored‮ copy  "})
    reasons = {r["reason"] for r in con.execute(
        "SELECT reason FROM funnel_events WHERE producer_id='bandit:B101' "
        "AND actor='operator'")}
    assert reasons == {"vendored copy", "producer dismissed for this repo: vendored copy"}


def test_a_dismissal_by_the_operator_is_not_a_tool_losing_its_output(seeded):
    """Funnel health warns when every new occurrence of a tool died to deterministic
    stages. The dismissal kill is deterministic in the ledger, but it is the
    operator's decision, and warning about it would cry wolf."""
    from quarry import db
    client, con = seeded
    _post(client, "/producers/bandit:B101/dismiss", {"run_id": 1, "scope": "repo"})
    _rescan(con, 2, "o/r", [("bandit", "B101", "src/x.py")])
    health = (db.read_manifest(con, 2).get("health") or {}).get("funnel") or {}
    assert not health.get("bandit")


def test_dismissals_that_reach_a_run_are_listed_with_a_way_back(seeded):
    """A dismissal made in run 1 killed run 2's occurrences, and run 2's page neither
    said so nor offered to undo it."""
    client, con = seeded
    _post(client, "/producers/bandit:B101/dismiss",
          {"run_id": 1, "scope": "corpus", "note": "noise"})
    _post(client, "/producers/bandit:B113/dismiss", {"run_id": 1, "scope": "repo"})
    _rescan(con, 2, "o/r", [("bandit", "B101", "src/x.py"),
                            ("bandit", "B113", "src/y.py")])
    ds = {d["producer_id"]: d for d in q.dismissals_for_run(con, 2)}
    assert ds["bandit:B101"]["scope"] == "corpus" and ds["bandit:B101"]["held"] == 1
    assert ds["bandit:B101"]["from_run"] == 1 and not ds["bandit:B101"]["undoes_switch"]
    assert ds["bandit:B113"]["scope"] == "repo" and ds["bandit:B113"]["undoes_switch"]
    page = client.get("/runs/2").text
    section = page.split('id="dismissals"', 1)[1].split("</table>", 1)[0]
    assert "bandit:B101" in section and "noise" in section
    assert "stays disabled until restored from run 1" in section
    assert section.count(f'name="csrf" value="{client.app.state.csrf_token}"') == 2
    r = _post(client, "/producers/bandit:B113/restore", {"run_id": 2, "back": "run"})
    assert r.headers["location"] == "/runs/2#dismissals"
    r = _post(client, "/producers/bandit:B113/restore",
              {"run_id": 2, "back": "https://attacker.example/"})
    assert r.headers["location"] == "/runs/2/triage", "back is a choice, never a URL"


# ============================================================ 5. keyboard

def _attrs(tag: str) -> dict[str, str]:
    import re
    return dict(re.findall(r'([\w:-]+)="([^"]*)"', tag))


def test_the_key_handler_refuses_where_the_console_is_hidden(seeded):
    """P3 item 5. Below 720px the console is hidden by CSS but its forms stay in the
    DOM, and `d` still submitted the hidden dismiss form."""
    client, _ = seeded
    page = client.get("/runs/1/triage").text
    css = client.get("/static/app.css").text
    assert "@media (max-width:719px)" in css, "the breakpoint the handler mirrors"
    handler = page.split("key(e) {", 1)[1]
    gate = "if (window.matchMedia('(max-width: 719px)').matches) return;"
    assert gate in handler
    assert handler.index(gate) < handler.index("e.key === 'd'"), \
        "the gate must run before any key is dispatched"


def test_row_moves_swap_columns_in_place_and_keep_the_url(seeded):
    """`j`/`k` did full page loads, which lost every column's scroll position."""
    import re
    client, _ = seeded
    page = client.get("/runs/1/triage").text
    for col in ("pcol", "ocol", "dcol"):
        assert f'id="{col}"' in page, col
    prows = [_attrs(t) for t in re.findall(r'<a class="prow[^>]*>', page)]
    orows = [_attrs(t) for t in re.findall(r'<a class="orow[^>]*>', page)]
    assert prows and orows
    for a in prows:
        assert a["hx-get"] == a["href"] and a["hx-push-url"] == "true"
        assert (a["hx-target"], a["hx-select"], a["hx-select-oob"]) == \
            ("#ocol", "#ocol", "#dcol"), "a producer move replaces columns 2 and 3"
    for a in orows:
        assert a["hx-get"] == a["href"] and a["hx-push-url"] == "true"
        assert (a["hx-target"], a["hx-select"]) == ("#dcol", "#dcol"), \
            "an occurrence move replaces only the detail column"
        assert "hx-select-oob" not in a
    # the swap moves the selection in the column that was not replaced
    assert '@htmx:before-request="pick($event.detail.elt)"' in page
    assert "this.pick(next);" in page


def test_an_htmx_row_request_returns_the_columns_it_selects(seeded):
    client, con = seeded
    oid = con.execute("SELECT id FROM live_occurrences WHERE run_id=1 AND "
                      "producer_id='bandit:B101' LIMIT 1").fetchone()["id"]
    r = client.get(f"/runs/1/triage?producer=bandit%3AB101&occ={oid}",
                   headers={"HX-Request": "true"})
    assert r.status_code == 200
    assert 'id="ocol"' in r.text and 'id="dcol"' in r.text
    selected = r.text.split('class="orow sel"', 1)[1].split(">", 1)[0]
    assert f"occ={oid}" in selected, "the response selects the requested row"


def test_history_is_not_cached_in_local_storage(seeded):
    """htmx's Back cache would write findings from untrusted repositories, and the
    form token, to localStorage."""
    client, _ = seeded
    page = client.get("/runs/1/triage").text
    assert '"historyCacheSize":0' in page and '"refreshOnHistoryMiss":true' in page


def test_the_centring_script_binds_once_however_often_it_is_swapped_in(seeded):
    client, _ = seeded
    page = client.get("/runs/1/triage").text
    assert "window.quarryCentreBound" in page


# ============================================================ 6. the Layer 2 digest

def _write_digest(run_id=1, text="# Deep-review candidates\n\n<script>x</script>‮\n"):
    from quarry import config
    from quarry.disclosure import digest_name
    d = config.paths().root / "reports" / str(run_id)
    d.mkdir(parents=True, exist_ok=True)
    p = d / digest_name(run_id)
    p.write_bytes(text.encode())
    return p


def test_a_digest_on_disk_is_listed_with_the_advisories(seeded):
    """P3 item 6. `quarry report` wrote reports/2/2-deep-review-candidates.md and the
    page said "0 drafts"."""
    client, con = seeded
    assert "No digest for this run" in client.get("/runs/1/advisories").text
    assert client.get("/runs/1/digest").status_code == 404
    _write_digest()
    page = client.get("/runs/1/advisories").text
    section = page.split('id="digests"', 1)[1]
    assert 'href="/runs/1/digest"' in section and "1-deep-review-candidates.md" in section
    assert "not\n            recorded" in section or "not recorded" in section
    assert 'href="/runs/1/digest"' in client.get("/advisories").text
    assert 'href="/runs/1/digest"' in client.get("/runs").text
    from quarry import config
    strip = q.pipeline(con, q.run_summary(con, 1), config.paths().root / "reports")
    assert strip[-1]["unit"] == "drafts; deep-review digest"
    assert "drafts; deep-review digest" in client.get("/runs/1").text

    body = client.get("/runs/1/digest").text
    assert "Candidates for triage, not confirmed vulnerabilities" in body
    assert "<script>x" not in body and "&lt;script&gt;x" in body
    assert "‮" not in body and "‹U+202E›" in body
    assert "nothing to check the file against" in body


def test_a_recorded_digest_is_checked_against_its_hash(seeded):
    import hashlib
    from quarry import db
    from quarry.disclosure import ResearchDigest, record_digest
    client, con = seeded
    p = _write_digest(text="# three candidates\n")
    with db.tx(con):
        record_digest(con, 1, ResearchDigest(path=p, n_findings=3,
                                             sha256=hashlib.sha256(p.read_bytes()).hexdigest()))
    d = q.digest(con, 1, None)
    assert d["recorded"] and d["n_findings"] == 3 and d["path"] == str(p.resolve())
    assert "matches the file" in client.get("/runs/1/digest").text
    p.write_text("# edited afterwards\n")
    assert "file changed since it was written" in client.get("/runs/1/digest").text


def test_a_digest_path_outside_reports_is_refused(seeded, tmp_path):
    """The path is in the manifest and `quarry report --out` accepts anywhere."""
    from quarry import db
    from quarry.disclosure import ResearchDigest, record_digest
    client, con = seeded
    secret = tmp_path / "secret.md"
    secret.write_text("TOP SECRET\n")
    with db.tx(con):
        record_digest(con, 1, ResearchDigest(path=secret, n_findings=1, sha256="0" * 64))
    page = client.get("/runs/1/digest").text
    assert "TOP SECRET" not in page and "does not open it" in page


def test_quarry_report_records_the_digest_it_writes(seeded, monkeypatch, tmp_path):
    """The CLI wiring: the digest `report` writes lands in the run manifest."""
    import hashlib
    from typer.testing import CliRunner
    from quarry import cli, disclosure, ingest
    _, con = seeded
    p = _write_digest(text="# two\n")
    dg = disclosure.ResearchDigest(path=p, n_findings=2,
                                   sha256=hashlib.sha256(p.read_bytes()).hexdigest())
    monkeypatch.setattr(ingest.RunVolume, "attach_existing",
                        classmethod(lambda cls, *a, **k: type("V", (), {"src": tmp_path})()))
    monkeypatch.setattr(disclosure, "draft_reports", lambda *a, **k: [])
    monkeypatch.setattr(disclosure, "draft_research_digest", lambda *a, **k: dg)
    r = CliRunner().invoke(cli.app, ["report", "1"], env={"COLUMNS": "200"})
    assert r.exit_code == 0, r.output
    d = q.digest(con, 1, None)
    assert d and d["recorded"] and d["sha256"] == dg.sha256 and d["n_findings"] == 2


# ============================================================ 7. resume claim

def _stopped_research(con, rid=1):
    """A research run on ingest run 1, stopped with a unit left to do."""
    con.execute("INSERT INTO research_runs (id,run_id,status,models,lenses,profile) "
                "VALUES (?,1,'stopped','[\"a:1b\",\"c:2d\"]','[]','{}')", (rid,))
    con.execute("INSERT INTO research_units (research_id,subsystem,weight,lens,model,"
                "phase,status) VALUES (?,'src',1.0,'x','a:1b','hunt','pending')", (rid,))
    con.commit()


def _row(con, rid=1):
    return dict(con.execute("SELECT * FROM research_runs WHERE id=?", (rid,)).fetchone())


def test_a_second_resume_is_refused_while_the_first_is_starting(seeded, monkeypatch,
                                                                worker):
    """P3 item 7. Nothing locked between the status check and the spawn, so two
    clicks started two workers on one run."""
    import subprocess
    client, con = seeded
    _stopped_research(con)
    seen = []
    from quarry import config, db
    db_path = config.paths().db
    real = subprocess.Popen

    def popen(argv, *a, **k):
        # Only the worker spawn is faked; `ps`, which the liveness check runs, is real.
        if "quarry.cli" not in argv:
            return real(argv, *a, **k)
        # What the database says at the moment of the spawn: already claimed. Read on
        # a connection of this thread's own; the route runs in a worker thread.
        other = db.connect(db_path)
        try:
            seen.append(_row(other)["status"])
        finally:
            other.close()
        return worker                    # a live process that looks like `deep 1`
    monkeypatch.setattr(subprocess, "Popen", popen)

    assert _post(client, "/research/1/resume").status_code == 303
    assert seen == [q.RESUMING], "the claim must be written before the spawn"
    assert _row(con)["pid"] == worker.pid
    assert q.live_status(_row(con))[0] == "starting"
    assert not q.research_runs(con, rid=1)[0]["resumable"]

    r = _post(client, "/research/1/resume")
    assert r.status_code == 409 and "starting worker" in r.text
    assert len(seen) == 1, "a second worker was started"
    page = client.get("/research/1").text
    assert '<span class="pill accent">starting</span>' in page
    assert "/research/1/resume" not in page, "no Resume is offered while it starts"


def test_a_claim_with_no_worker_lapses_and_the_run_is_resumable_again(seeded, bystander):
    _, con = seeded
    _stopped_research(con)
    base = {"status": q.RESUMING, "run_id": 1}
    assert q.live_status({**base, "pid": None, "heartbeat": _utc_now()})[0] == "starting"
    old = _utc_now(minutes=-(q.CLAIM_GRACE_SECONDS / 60 + 1))
    status, why = q.live_status({**base, "pid": None, "heartbeat": old})
    assert status == "died" and "no worker started" in why
    status, why = q.live_status({**base, "pid": 999_999_999, "heartbeat": _utc_now()})
    assert status == "died" and "exited before claiming" in why
    status, why = q.live_status({**base, "pid": bystander.pid, "heartbeat": _utc_now()})
    assert status == "died" and "another program" in why, "a recycled pid is not a worker"
    con.execute("UPDATE research_runs SET status=?, pid=NULL, heartbeat=? WHERE id=1",
                (q.RESUMING, old))
    con.commit()
    assert q.research_runs(con, rid=1)[0]["resumable"]


def test_a_failed_spawn_releases_the_claim(seeded, monkeypatch):
    import subprocess
    client, con = seeded
    _stopped_research(con)

    def broken(*a, **k):
        raise OSError("no python here")
    monkeypatch.setattr(subprocess, "Popen", broken)
    r = _post(client, "/research/1/resume")
    assert r.status_code == 500 and "claim was released" in r.text
    assert _row(con)["status"] == "stopped"
    assert q.research_runs(con, rid=1)[0]["resumable"]


def test_a_finished_run_has_nothing_to_resume(seeded, monkeypatch):
    import subprocess
    client, con = seeded
    _stopped_research(con)
    con.execute("UPDATE research_units SET status='done' WHERE research_id=1")
    con.commit()
    spawned = []
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: spawned.append(a))
    r = _post(client, "/research/1/resume")
    assert r.status_code == 409 and "nothing to resume" in r.text and not spawned
    assert _row(con)["status"] == "stopped", "a refused resume claims nothing"


def test_a_scanner_occurrence_has_no_deep_review_section(seeded):
    client, con = seeded
    oid = con.execute("SELECT id FROM live_occurrences WHERE run_id=1 LIMIT 1"
                      ).fetchone()["id"]
    assert q.research_finding(con, oid) is None
    assert 'id="deep-review"' not in client.get(f"/evidence/{oid}").text
