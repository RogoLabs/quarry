"""The disclosure report: GHSA-shaped Markdown rendered from a confirmed verdict, the
security-contact and ecosystem detection, and writing reports from the database.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quarry import db                                                   # noqa: E402
from quarry.disclosure import (                                         # noqa: E402
    DisclosureContext, render_report, build_reports,
    SecurityContact, extract_security_contacts, guess_ecosystem)

ACME = (SecurityContact("email", "security@acme.example", "SECURITY.md"),)


def _ctx(**over):
    base = dict(
        target="acme/widgets", clone_url="https://github.com/acme/widgets",
        git_sha="abc1234", cwe="CWE-862", file="app/api.py", symbol="get_order",
        line=42, summary="GET /orders/{id} is declared protected but returned 200 with no "
        "credentials", request="GET http://web:8080/orders/1  (no Authorization header)",
        observed="HTTP 200", determinism="deterministic", ecosystem="PyPI",
        package="widgets", security_contacts=ACME, run_id=7,
        verdict_time="2026-10-25T12:00:00")
    base.update(over)
    return DisclosureContext(**base)


def test_guess_ecosystem():
    assert guess_ecosystem("Python") == "PyPI"
    assert guess_ecosystem("TypeScript") == "npm"
    assert guess_ecosystem("Haskell") == "(unknown)"


def _values(src):
    return [(c.kind, c.value) for c in extract_security_contacts(src)]


def test_extract_security_contact(tmp_path):
    assert extract_security_contacts(tmp_path) == []
    (tmp_path / "SECURITY.md").write_text("Email us at secteam@acme.example to report.")
    assert _values(tmp_path) == [("email", "secteam@acme.example")]


def test_extract_security_contact_ghsa(tmp_path):
    (tmp_path / "SECURITY.md").write_text("Use github.com/acme/widgets/security/advisories.")
    assert [c.kind for c in extract_security_contacts(tmp_path)] == ["ghsa"]


def test_extract_security_contact_ghsa_url_is_kept(tmp_path):
    (tmp_path / "SECURITY.md").write_text(
        "Report at https://github.com/acme/widgets/security/advisories/new please.")
    assert _values(tmp_path) == [
        ("ghsa", "https://github.com/acme/widgets/security/advisories/new")]


def test_image_filename_is_not_an_email(tmp_path):
    (tmp_path / "SECURITY.md").write_text(
        "![logo](img/logo@2x.png)\n<img src=\"a/icon@3x.webp\">\nsee docs/x@y.md\n")
    assert extract_security_contacts(tmp_path) == []


def test_do_not_email_yields_ghsa_not_the_address(tmp_path):
    (tmp_path / "SECURITY.md").write_text(
        "Do not email security@example.com; use GitHub security advisories.")
    assert [c.kind for c in extract_security_contacts(tmp_path)] == ["ghsa"]


def test_contacts_are_all_returned_in_priority_order(tmp_path):
    (tmp_path / "SECURITY.md").write_text(
        "Ask questions at help@acme.example.\n"
        "Report privately to [the team](mailto:psirt@acme.example).\n"
        "Or use https://github.com/acme/widgets/security/advisories/new\n")
    wk = tmp_path / ".well-known"
    wk.mkdir()
    (wk / "security.txt").write_text(
        "Contact: mailto:security@acme.example\n"
        "Contact: https://acme.example/report\n"
        "Expires: 2030-01-01T00:00:00.000Z\n")
    got = extract_security_contacts(tmp_path)
    assert [(c.kind, c.value) for c in got] == [
        ("ghsa", "https://github.com/acme/widgets/security/advisories/new"),
        ("email", "security@acme.example"),          # security.txt Contact: lines
        ("url", "https://acme.example/report"),
        ("email", "psirt@acme.example"),             # mailto: link
        ("email", "help@acme.example"),              # bare address in the text
    ]
    assert got[1].source == ".well-known/security.txt, Contact: line"


def test_contacts_never_read_through_a_symlink_out_of_the_repo(tmp_path):
    outside = tmp_path / "outside.md"
    outside.write_text("security@leaked.example")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "SECURITY.md").symlink_to(outside)
    assert extract_security_contacts(repo) == []


def test_every_contact_is_rendered_for_the_reporter_to_choose():
    contacts = (SecurityContact("ghsa", "https://github.com/acme/widgets/security/advisories/new",
                                "SECURITY.md, reporting link"),
                SecurityContact("email", "security@acme.example", "SECURITY.md, mailto link"))
    md = render_report(_ctx(security_contacts=contacts))
    disclosure = md.split("## Disclosure", 1)[1]
    assert "Choose one before sending" in disclosure
    assert "`https://github.com/acme/widgets/security/advisories/new`" in disclosure
    assert "`security@acme.example`" in disclosure
    assert disclosure.index("advisories/new") < disclosure.index("security@acme.example")


def test_render_report_is_a_ghsa_advisory_not_a_cve_record():
    md = render_report(_ctx())
    assert md.startswith("# Missing Authorization in widgets")
    for heading in ("## Summary", "## Package", "## Affected versions", "## Severity",
                    "## Proof of concept", "## Suggested remediation", "## Disclosure"):
        assert heading in md, heading
    assert "Ecosystem: PyPI" in md
    assert "abc1234" in md                               # the exact commit, not a range
    assert "does not infer a range" in md               # honest about versions
    assert "Proposed:" in md and "reporter to confirm" in md   # severity not invented
    assert "security@acme.example" in md
    assert "GET http://web:8080/orders/1" in md         # replayable PoC
    assert "review before sending" in md
    # it must NOT present itself as a CVE record / CNA container
    assert "cveMetadata" not in md and "cnaContainer" not in md


def test_render_report_without_contact_points_at_ghsa():
    md = render_report(_ctx(security_contacts=()))
    assert "GHSA" in md or "Report a vulnerability" in md


# ------------------------------------------------------------------ Markdown injection

EVIL = "https://evil.example"
TEMPLATE_H2 = ["Summary", "Package", "Affected versions", "Severity", "Location",
               "Description", "Proof of concept", "Suggested remediation", "Disclosure"]
FOOTER = "review before sending, not a published advisory."


def _hostile_ctx():
    # Every target-controlled field tries to break out: close the PoC fence, start a
    # heading, load a remote image, plant a link, emit raw HTML, hide text with bidi.
    return _ctx(
        request=f"GET /a\n```\n# Injected from request\n![x]({EVIL}/req.png)\n"
                f"<img src={EVIL}/req-html.png>\n```",
        observed=f"HTTP 200\r````\r## Injected from observed\n````",
        summary=f"# Injected from summary ![t]({EVIL}/sum.png) [click]({EVIL}/l) "
                f"<img src={EVIL}/sum-html.png> <script>x</script> `tick\u202eevil` "
                f"and an em dash \u2014 here\n\n## Injected via newline",
        package="w`idg``ets", target="acme/```evil\n# Injected from target",
        file="app/`x`.py\n![f](" + EVIL + "/file.png)", symbol="a]b(c)",
        clone_url=f"{EVIL}/r\n<img src={EVIL}/clone.png>",
        git_sha="abc```\n# sha", determinism="deterministic\n# det",
        security_contacts=(SecurityContact("email", f"<img src={EVIL}/c.png>",
                                           f"[m]({EVIL})\n# Injected from contact"),),
        baseline=f"HTTP 401\n```\n# Injected from baseline",
        verdict_time=f"[t]({EVIL}/time)")


def _html(md):
    mdit = pytest.importorskip("markdown_it")
    return mdit.MarkdownIt("commonmark").render(md)


def test_hostile_strings_cannot_inject_markdown_structure():
    md = render_report(_hostile_ctx())
    html = _html(md)
    heads = re.findall(r"<h([1-6])>(.*?)</h\1>", html, re.S)
    assert [h for lvl, h in heads if lvl == "2"] == TEMPLATE_H2
    assert [lvl for lvl, _ in heads] == ["1"] + ["2"] * len(TEMPLATE_H2)
    assert "Injected" not in heads[0][1]
    assert "<img" not in html and "<script" not in html       # no remote image, no HTML
    assert f'href="{EVIL}' not in html                          # no planted link
    assert "\u202e" not in md                                   # bidi stripped
    # the footer is still prose after every fence has closed
    outside_code = re.sub(r"<pre>.*?</pre>|<code>.*?</code>", "", html, flags=re.S)
    assert FOOTER in outside_code


def test_poc_fence_outlasts_backticks_in_the_request():
    md = render_report(_ctx(request="GET /x\n`````\n# not a heading"))
    assert "``````\nGET /x\n`````\n# not a heading\n``````" in md


def test_code_spans_outlast_backticks_in_names():
    md = render_report(_ctx(package="a``b", file="c`d.py", symbol=None, line=None))
    assert "Package / project: ```a``b```" in md
    assert "``c`d.py``" in md


def test_free_text_neutralises_images_links_and_html():
    md = render_report(_ctx(summary=f"x ![i]({EVIL}/a.png) [l]({EVIL}) <b>y</b>"))
    assert f"![i]({EVIL}" not in md and "(image removed)" in md
    assert f"\\[l\\]({EVIL})" in md and "\\<b\\>y\\</b\\>" in md


def test_rendered_advisory_has_no_em_dash():
    for ctx in (_ctx(), _ctx(security_contacts=()), _hostile_ctx(),
                _ctx(summary="route open \u2014 no credentials needed")):
        assert "\u2014" not in render_report(ctx)


def test_review_before_sending_footer_is_always_present():
    for ctx in (_ctx(), _ctx(security_contacts=(), summary="", request="", observed="",
                             git_sha=None, symbol=None, line=None, cwe=None),
                _hostile_ctx()):
        md = render_report(ctx)
        assert md.rstrip().endswith("This is a reporter's draft to\n" + FOOTER)


CONFIRMED_EVIDENCE = json.dumps({
    "summary": "protected route open", "request": "GET http://web:8080/orders/1",
    "observed": "HTTP 200", "determinism": "deterministic",
    "baseline": "HTTP 401 with no credentials on /orders", "differs_from_baseline": True})


def _db(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text("@app.get('/orders/{id}')\ndef o(): ...\n")
    (src / "SECURITY.md").write_text("Report to security@acme.example")
    p = tmp_path / "quarry.db"
    db.init(p)
    con = db.connect(p)
    with db.tx(con):
        con.execute("""INSERT INTO runs (id,target,clone_url,git_sha)
                       VALUES (1,'acme/widgets','https://github.com/acme/widgets','deadbee')""")
        con.execute("INSERT INTO producers (id,tool,rule_id,cwe) VALUES ('p','og','r','CWE-862')")
        for fid, line in (("f1", 42), ("f2", 50)):
            con.execute("""INSERT INTO findings (id,target,path,symbol,producer_id,first_seen_run,last_seen_run)
                           VALUES (?,'acme/widgets','app.py','get_order','p',1,1)""", (fid,))
            con.execute("""INSERT INTO occurrences (run_id,finding_id,producer_id,path,start_line)
                           VALUES (1,?,'p','app.py',?)""", (fid, line))
    return con, src


def _confirm(con, fid="f1", **over):
    kw = dict(verdict="confirmed", cwe="CWE-862", executed_score=100,
              rationale=CONFIRMED_EVIDENCE)
    kw.update(over)
    with db.tx(con):
        db.verdict(con, fid, 1, **kw)


def test_build_reports_from_db(tmp_path):
    con, src = _db(tmp_path)
    _confirm(con, "f1")
    # a needs-review verdict (a reproduction held for want of a baseline) is never drafted
    _confirm(con, "f2", verdict="needs-review", executed_score=50,
             reason="no baseline comparison recorded")

    written = build_reports(con, 1, src, out_dir=tmp_path / "reports")
    assert len(written) == 1
    text = written[0].read_text()
    assert "Missing Authorization in widgets" in text
    assert "GET http://web:8080/orders/1" in text
    assert "security@acme.example" in text
    assert "deadbee" in text


def test_build_reports_latest_dynamic_verdict_wins(tmp_path):
    con, src = _db(tmp_path)
    # f1: confirmed, then a re-run of validate rejected it. Withdrawn.
    _confirm(con, "f1")
    _confirm(con, "f1", verdict="rejected", executed_score=50)
    # f2: held for review, then a later run confirmed it with a baseline. Drafted.
    _confirm(con, "f2", verdict="needs-review", executed_score=50)
    _confirm(con, "f2")
    written = build_reports(con, 1, src, out_dir=tmp_path / "reports")
    assert [p.name.endswith("-f2.md") for p in written] == [True]


def test_build_reports_later_needs_review_withdraws_a_confirmation(tmp_path):
    con, src = _db(tmp_path)
    _confirm(con, "f1")
    _confirm(con, "f1", verdict="needs-review", executed_score=50)
    assert build_reports(con, 1, src, out_dir=tmp_path / "reports") == []


def test_build_reports_ignores_non_dynamic_seats(tmp_path):
    # A model seat's "confirmed" is an argument, not a probe; the advisory says
    # "confirmed dynamically", so only seat='dynamic' may produce one.
    con, src = _db(tmp_path)
    _confirm(con, "f1", seat="chair", model="some-model")
    assert build_reports(con, 1, src, out_dir=tmp_path / "reports") == []
    # and a later non-dynamic verdict does not mask the latest dynamic one
    _confirm(con, "f2")
    _confirm(con, "f2", seat="chair", model="some-model", verdict="rejected")
    written = build_reports(con, 1, src, out_dir=tmp_path / "reports")
    assert len(written) == 1 and written[0].name.endswith("-f2.md")


def test_build_reports_skips_confirmed_without_stored_baseline(tmp_path):
    # A confirmed verdict written before the baseline rule (or by hand) has no control
    # comparison in its evidence; it is not drafted.
    con, src = _db(tmp_path)
    old = json.loads(CONFIRMED_EVIDENCE)
    del old["baseline"], old["differs_from_baseline"]
    _confirm(con, "f1", rationale=json.dumps(old))
    _confirm(con, "f2", rationale=json.dumps({**old, "baseline": "HTTP 200",
                                              "differs_from_baseline": False}))
    assert build_reports(con, 1, src, out_dir=tmp_path / "reports") == []
