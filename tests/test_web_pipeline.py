"""The pipeline's last two stages on the dashboard: verdicts and advisory drafts.

`verdicts` had a writer (validate.record_verdict) and no reader anywhere in the web
layer, and `quarry report` wrote drafts no page could find. These pin the new views,
the triage filter, and the one security property the advisory page adds: it reads
files named by a database row, so it must refuse any path outside <data root>/reports.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quarry import config, db                    # noqa: E402
from quarry.migrations import MIGRATIONS, migrate  # noqa: E402
from quarry.web import queries as q             # noqa: E402

from test_web import ORIGIN, seeded             # noqa: E402,F401

RLO = "‮"


def _finding(con, path_like: str) -> tuple[str, int]:
    """(finding_id, occurrence_id) of a live occurrence whose path contains `path_like`."""
    r = con.execute("SELECT o.finding_id, o.id FROM live_occurrences o "
                    "WHERE o.run_id=1 AND o.path LIKE ? ORDER BY o.id LIMIT 1",
                    (f"%{path_like}%",)).fetchone()
    return r["finding_id"], r["id"]


def _verdict(con, fid, state, *, model="idor", run_id=1, rationale=None, **kw):
    with db.tx(con):
        return db.verdict(con, fid, run_id, verdict=state, model=model,
                          rationale=rationale, **kw)


EVIDENCE = {"summary": f"read order 2 as user 1{RLO}", "request": "GET /orders/2",
            "observed": "HTTP 200 {\"id\": 2}", "baseline": "HTTP 403",
            "differs_from_baseline": True, "determinism": "3/3"}


# ------------------------------------------------------------------ schema

def test_migration_v8_creates_the_advisories_table(seeded):
    _, con = seeded
    cols = {r[1] for r in con.execute("PRAGMA table_info(advisories)")}
    assert {"id", "run_id", "finding_id", "verdict_id", "path", "created_at",
            "sha256"} <= cols
    assert con.execute("PRAGMA user_version").fetchone()[0] == len(MIGRATIONS)
    assert migrate(con) == 0, "re-running migrations must be a no-op"


# ------------------------------------------------------------------ verdicts

def test_latest_verdict_per_slot_wins(seeded):
    """validate appends; the state of a (finding, seat, lens) slot is its newest row."""
    _, con = seeded
    fid, _ = _finding(con, "mod0")
    _verdict(con, fid, "confirmed")
    _verdict(con, fid, "rejected")                     # same slot, later: wins
    _verdict(con, fid, "needs-review", model="ssrf")   # another lens: its own slot
    counts = q.verdict_counts(con, 1)
    assert counts == {"confirmed": 0, "needs-review": 1, "rejected": 1, "total": 2}
    slots = q.verdicts_for_finding(con, fid)
    assert {(v["model"], v["verdict"]) for v in slots} == {("idor", "rejected"),
                                                           ("ssrf", "needs-review")}


def test_the_detail_pane_shows_the_verdict_and_its_evidence_as_code(seeded):
    client, con = seeded
    fid, oid = _finding(con, "mod1")
    _verdict(con, fid, "confirmed", executed_score=100, reason="reproduced",
             rationale=json.dumps(EVIDENCE))
    for page in (client.get(f"/evidence/{oid}").text,
                 client.get(f"/evidence/{oid}", headers={"hx-request": "1"}).text):
        assert "Validation" in page
        assert "pill verified" in page and "lens idor" in page
        assert "executed 100" in page
        assert "GET /orders/2" in page and "HTTP 403" in page
        assert 'class="vcode"' in page
        # target-controlled: escaped, and the bidi override shown, not obeyed
        assert "HTTP 200 {&#34;id&#34;: 2}" in page or "HTTP 200 {&quot;id&quot;: 2}" in page
        assert RLO not in page and "‹U+202E›" in page


def test_a_non_json_rationale_is_still_shown(seeded):
    client, con = seeded
    fid, oid = _finding(con, "mod2")
    _verdict(con, fid, "needs-review", rationale="<b>hand written</b>")
    page = client.get(f"/evidence/{oid}").text
    assert "&lt;b&gt;hand written&lt;/b&gt;" in page


def test_validation_page_lists_and_filters_latest_verdicts(seeded):
    client, con = seeded
    a, oid_a = _finding(con, "mod0")
    b, _ = _finding(con, "mod1")
    _verdict(con, a, "confirmed", rationale=json.dumps(EVIDENCE))
    _verdict(con, b, "needs-review")
    page = client.get("/validation").text
    assert "common state" in page, "the page must say needs-review is the norm"
    assert f"/evidence/{oid_a}" in page
    only = client.get("/validation?state=confirmed").text
    assert "pill verified" in only and "pill incomplete\">needs review" not in only
    assert client.get("/validation?run=1&state=rejected").status_code == 200
    assert client.get("/validation?state=nonsense").status_code == 400
    assert client.get("/validation?run=9999").status_code == 404


def test_run_page_has_the_pipeline_strip_and_a_linked_validation_card(seeded):
    client, con = seeded
    fid, _ = _finding(con, "mod0")
    _verdict(con, fid, "confirmed")
    page = client.get("/runs/1").text
    for stage in ("Ingest", "Scan", "Funnel", "Validate", "Report"):
        assert f'<span class="pn">{stage}</span>' in page, stage
    for href in ("/runs/1#quarantine", "/runs/1#funnel", "/triage?run=1",
                 "/validation?run=1", "/advisories?run=1"):
        assert f'href="{href}"' in page, href
    for state in ("confirmed", "needs-review", "rejected"):
        assert f"/validation?run=1&amp;state={state}" in page, state
    assert 'id="funnel"' in page and 'id="quarantine"' in page


def test_triage_filters_by_verdict_state(seeded):
    client, con = seeded
    fid, oid = _finding(con, "mod3")
    _verdict(con, fid, "confirmed")
    groups = q.producer_groups(con, 1, verdict="confirmed")
    assert [g.n_live for g in groups] == [1]
    assert q.producer_groups(con, 1, verdict="rejected") == []
    assert q.producer_groups(con, 1, verdict="bogus") == []
    page = client.get("/triage?run=1&verdict=confirmed").text
    assert f"occ={oid}" in page, "the one confirmed occurrence is in the filtered queue"
    assert page.count('class="orow') == 1
    # the filter survives the j/k links
    assert "verdict=confirmed&producer=" in page
    empty = client.get("/triage?run=1&verdict=rejected").text
    assert "No live finding in this run has a latest verdict" in empty


# ------------------------------------------------------------------ advisories

def _draft(tmp_root: Path, name: str, text: str) -> Path:
    d = tmp_root / "reports" / "1"
    d.mkdir(parents=True, exist_ok=True)
    p = d / name
    p.write_bytes(text.encode())
    return p


def _advisory(con, fid, path: Path | str, sha: str | None = None) -> int:
    with db.tx(con):
        vid = db.verdict(con, fid, 1, verdict="confirmed", model="idor",
                         rationale=json.dumps(EVIDENCE))
        body = Path(path).read_bytes() if sha is None else b""
        return db.advisory(con, 1, fid, str(path),
                           sha or hashlib.sha256(body).hexdigest(), verdict_id=vid)


def test_advisory_list_and_detail_render_escaped_text(seeded):
    client, con = seeded
    fid, _ = _finding(con, "mod0")
    root = config.paths().root
    text = f"# Missing Authorization\n\n<script>alert(1)</script> [x](http://e){RLO}\n"
    aid = _advisory(con, fid, _draft(root, "1-cwe-862-a.md", text))
    listing = client.get("/advisories").text
    assert f"/advisories/{aid}" in listing
    assert f"/advisories/{aid}" in client.get("/advisories?run=1").text
    page = client.get(f"/advisories/{aid}").text
    assert "Review before sending" in page
    assert "<script>alert(1)" not in page and "&lt;script&gt;alert(1)" in page
    assert "<h1>Missing" not in page, "Markdown must not be rendered to HTML"
    assert RLO not in page and "‹U+202E›" in page
    assert "matches the file" in page
    assert "Copy Markdown" in page


def test_an_edited_draft_is_flagged(seeded):
    client, con = seeded
    fid, _ = _finding(con, "mod0")
    p = _draft(config.paths().root, "1-x.md", "original\n")
    aid = _advisory(con, fid, p)
    p.write_text("edited after the fact\n")
    page = client.get(f"/advisories/{aid}").text
    assert "file changed since it was written" in page


def test_advisory_paths_outside_reports_are_refused(seeded, tmp_path):
    """The path is a database row and `quarry report --out` accepts anywhere, so the
    page must only open files that RESOLVE inside <data root>/reports."""
    client, con = seeded
    fid, _ = _finding(con, "mod0")
    root = config.paths().root
    secret = tmp_path / "secret.txt"
    secret.write_text("TOP SECRET\n")
    reports = root / "reports" / "1"
    reports.mkdir(parents=True, exist_ok=True)
    link = reports / "link.md"
    link.symlink_to(secret)
    cases = [str(secret),                                  # plainly outside
             str(reports / ".." / ".." / ".." / "secret.txt"),
             str(link)]                                    # symlink pointing out
    for path in cases:
        aid = _advisory(con, fid, path, sha="0" * 64)
        page = client.get(f"/advisories/{aid}").text
        assert "TOP SECRET" not in page, path
        assert "does not open it" in page or "gone from disk" in page, path
    aid = _advisory(con, fid, str(reports / "missing.md"), sha="0" * 64)
    assert "gone from disk" in client.get(f"/advisories/{aid}").text
    assert client.get("/advisories/999999").status_code == 404


def test_draft_reports_returns_what_the_report_command_records(tmp_path):
    """`quarry report` records one advisories row per draft from these fields."""
    from test_disclosure import _confirm, _db
    from quarry.disclosure import draft_reports
    con, src = _db(tmp_path)
    _confirm(con, "f1")
    drafts = draft_reports(con, 1, src, out_dir=tmp_path / "reports")
    assert len(drafts) == 1
    d = drafts[0]
    assert d.finding_id == "f1"
    assert d.sha256 == hashlib.sha256(d.path.read_bytes()).hexdigest()
    vid = con.execute("SELECT MAX(id) m FROM verdicts WHERE finding_id='f1'").fetchone()["m"]
    assert d.verdict_id == vid
    with db.tx(con):
        db.advisory(con, 1, d.finding_id, str(d.path), d.sha256, verdict_id=d.verdict_id)
    assert q.advisories(con, 1)[0]["sha256"] == d.sha256


# ------------------------------------------------------------------ shell

def test_home_goes_to_runs_when_there_are_runs(seeded):
    client, _ = seeded
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"] == "/runs"


def test_home_is_the_empty_state_with_no_runs(tmp_path, monkeypatch):
    home = tmp_path / "empty-home"
    home.mkdir()
    monkeypatch.setenv("QUARRY_HOME", str(home))
    con = db.init(config.paths().db)
    con.close()
    from fastapi.testclient import TestClient
    from quarry.web.app import create_app
    client = TestClient(create_app(), base_url=ORIGIN)
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 200 and "Nothing ingested yet" in r.text


def test_nav_is_in_pipeline_order_and_marks_the_current_page(seeded):
    client, _ = seeded
    page = client.get("/validation").text
    order = [page.index(f'href="{h}"') for h in
             ("/runs", "/triage", "/validation", "/advisories", "/research", "/egress")]
    assert order == sorted(order)
    assert 'href="/validation" class="on" aria-current="page"' in page


def test_the_shell_has_a_skip_link_and_the_brand(seeded):
    client, _ = seeded
    page = client.get("/runs").text
    assert 'href="#main"' in page and 'id="main"' in page
    assert ">Quarry<" in page and 'href="https://rogolabs.net"' in page
    assert "quarry-theme" in page and "oa-theme" not in page


def test_the_keysheet_is_a_modal_dialog(seeded):
    client, _ = seeded
    page = client.get("/triage").text
    assert 'role="dialog"' in page and 'aria-modal="true"' in page
    assert 'aria-labelledby="keysheet-title"' in page
    assert "x-cloak" in page
    css = client.get("/static/app.css").text
    assert ".keysheet{" in css.replace(" ", "") and "[x-cloak]" in css


def test_the_model_checkboxes_are_a_named_group(seeded):
    client, _ = seeded
    page = client.get("/research").text
    assert "<fieldset" in page and "<legend>Models, at least two families</legend>" in page


def test_no_em_dash_in_rendered_template_text(seeded):
    """House style. Jinja comments may keep theirs; nothing rendered may."""
    import re
    tpl = Path(q.__file__).resolve().parent / "templates"
    for f in tpl.glob("*.html"):
        text = re.sub(r"\{#.*?#\}", "", f.read_text(), flags=re.S)
        text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
        assert "—" not in text, f"{f.name} renders an em dash"
