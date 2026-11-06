"""The disclosure report: GHSA-shaped Markdown rendered from a confirmed verdict, the
security-contact and ecosystem detection, and writing reports from the database. Also
the conditions, limits, confidence and prior-advisory sections, with and without the
replay/probe/conditions rationale keys a verdict may or may not carry.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quarry import db                                                   # noqa: E402
from quarry.disclosure import (                                         # noqa: E402
    DisclosureContext, render_report, build_reports, draft_reports,
    SecurityContact, extract_security_contacts, guess_ecosystem,
    draft_research_digest, ResearchDigest)
from quarry.disclosure.report import find_security_policy              # noqa: E402
from quarry.vulndb import PriorAdvisory, PriorCheck                     # noqa: E402
# The end-to-end seeded run reuses the Layer 3 loop's hermetic target and fake runtime.
from test_run_validation import FakeRuntime, scanned                    # noqa: E402,F401
from test_vulndb_prior import _osv_zip, _rec                            # noqa: E402

ACME = (SecurityContact("email", "security@acme.example", "SECURITY.md"),)


@pytest.fixture(autouse=True)
def _no_live_vulndb(tmp_path, monkeypatch):
    """draft_reports reads the local OSV copy; point it at an empty directory so no test
    depends on, or reads, the operator's synced databases."""
    monkeypatch.setenv("QUARRY_DBS", str(tmp_path / "no-vulndb"))


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
                    "## Confidence", "## Conditions", "## Proof of concept",
                    "## Limitations and weakest link", "## Prior advisories checked",
                    "## Suggested remediation", "## Disclosure"):
        assert heading in md, heading
    assert "Ecosystem: PyPI" in md
    assert "abc1234" in md                               # the exact commit, not a range
    assert "does not infer a range" in md               # honest about versions
    assert "Class default:" in md and "reporter to confirm" in md   # severity not invented
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
TEMPLATE_H2 = ["Summary", "Package", "Affected versions", "Severity", "Confidence",
               "Location", "Description", "Conditions", "Proof of concept",
               "Limitations and weakest link", "Prior advisories checked",
               "Suggested remediation", "Disclosure"]
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
        verdict_time=f"[t]({EVIL}/time)",
        # The rationale and manifest carry target-derived strings too: the route path
        # comes from the target's source or its served spec.
        probe={"id": "p`\n# Injected from probe id", "source_sha": "``\n## sha",
               "route": f"/x\n```\n# Injected from route ![r]({EVIL}/r.png)",
               "method": "GET\n## Injected from method"},
        conditions={"seed": f"s\n# Injected from seed <img src={EVIL}/s.png>",
                    "env_keys": ["A\n# Injected from env"], "auth": "anonymous"},
        validate={"provisioning": {"build_network": "x\n# Injected from bn",
                                   "mem_limit": f"[m]({EVIL})", "dotenv": "\n# d"},
                  "service": "web\n## Injected from service"},
        seed_notes=(f"note\n# Injected from note ![n]({EVIL}/n.png)",),
        prior=_hostile_prior(),
        replay={"attempts": 3, "reproduced": 3, "control_held": 3, "after_restart": None})


def _hostile_prior():
    return PriorCheck(True, ecosystems=("PyPI\n# Injected from ecosystem",),
                      entries_read=5, downloaded=f"[d]({EVIL})", package="w\n# pkg",
                      package_ecosystem="PyPI", repo="github.com/a/b\n# repo",
                      matches=[PriorAdvisory(
                          id="GHSA-x\n# Injected from id", aliases=(f"<img src={EVIL}/a>",),
                          cwes=("CWE-862",), summary=f"# Injected from summary ![s]({EVIL}/s)",
                          modified="2026", ecosystem="PyPI", basis="package name")])


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


def test_build_reports_reads_a_missing_defence_confirmation_the_right_way_round(tmp_path):
    # The rate-limit probe confirms on sameness (reproduces_when "same"): the burst was
    # answered like the lone request. Its supporting comparison is differs False, and a
    # "same" record with differs True (a throttle appeared) is no confirmation.
    con, src = _db(tmp_path)
    same = {**json.loads(CONFIRMED_EVIDENCE), "reproduces_when": "same",
            "baseline": "lone GET /login -> HTTP 401 in 4 ms"}
    _confirm(con, "f1", rationale=json.dumps({**same, "differs_from_baseline": False}))
    _confirm(con, "f2", rationale=json.dumps({**same, "differs_from_baseline": True}))
    written = build_reports(con, 1, src, out_dir=tmp_path / "reports")
    assert [p.name.endswith("-f1.md") for p in written] == [True]


# ---- Layer 2 -> report bridge: the deep-review digest ------------------------------
# A deep run writes research_findings that `validate` and `report` never read. The bridge
# lets `report` emit a triage digest of the survivors so the night's real output is not
# stranded in the dashboard. A survivor is quote-verified AND defended by a cross-family
# model (n_survived > 0); everything below is that filter, the labelling, and taint safety.

def _research_db(tmp_path, findings):
    """A db with one run, one research run, and the given research_findings rows. Each item
    in `findings` overrides columns on a sensible default survivor."""
    p = tmp_path / "quarry.db"
    db.init(p)
    con = db.connect(p)
    with db.tx(con):
        con.execute("""INSERT INTO runs (id,target,clone_url,git_sha)
                       VALUES (1,'acme/widgets','https://github.com/acme/widgets','deadbee')""")
        con.execute("""INSERT INTO research_runs (id,run_id,status,models,lenses,profile)
                       VALUES (1,1,'done','[]','[]','{}')""")
        for f in findings:
            row = dict(research_id=1, subsystem="src/api", lens="broken-authz-idor",
                       model="devstral:24b", family="mistral", title="A finding",
                       file="app/api.py", quote="x = 1", quote_verified=1,
                       severity="high", reasoning="because", attacker_control="GET it",
                       self_critique="maybe", refutations="[]", n_refuted=0, n_survived=1)
            row.update(f)
            cols = ",".join(row)
            con.execute(
                f"INSERT INTO research_findings ({cols}) VALUES "
                f"({','.join('?' * len(row))})", tuple(row.values()))
    return con


def test_research_digest_includes_quote_verified_survivor(tmp_path):
    con = _research_db(tmp_path, [dict(
        title="Unauthenticated read of order data", file="app/orders.py",
        model="granite4.2:30b", family="granite4.2", n_survived=1, n_refuted=1,
        refutations=json.dumps([
            {"model": "qwen3.6:27b", "verdict": "survives", "reason": "the route has no guard"},
            {"model": "devstral:24b", "verdict": "refuted", "reason": "a check runs upstream"}]))])
    dg = draft_research_digest(con, 1, out_dir=tmp_path / "reports")
    assert isinstance(dg, ResearchDigest) and dg.n_findings == 1
    text = dg.path.read_text()
    assert "Unauthenticated read of order data" in text
    assert "app/orders.py" in text
    assert "granite4.2:30b" in text
    # the two refuter voices both appear, with their plain-language verdict words
    assert "qwen3.6:27b" in text and "devstral:24b" in text
    assert "defended" in text and "refuted" in text
    # and it is labelled a candidate, never a confirmation
    assert "not confirmed" in text.lower() or "not a published advisory" in text.lower()
    assert "candidates" in text.lower()


def test_research_digest_excludes_unverified_and_undefended(tmp_path):
    con = _research_db(tmp_path, [
        dict(title="defended-and-verified", quote_verified=1, n_survived=1),   # in
        dict(title="not-verified", quote_verified=0, n_survived=1),            # out
        dict(title="nobody-defended", quote_verified=1, n_survived=0),         # out
    ])
    dg = draft_research_digest(con, 1, out_dir=tmp_path / "reports")
    assert dg is not None and dg.n_findings == 1
    text = dg.path.read_text()
    assert "defended-and-verified" in text
    assert "not-verified" not in text
    assert "nobody-defended" not in text


def test_research_digest_none_when_no_survivors(tmp_path):
    con = _research_db(tmp_path, [dict(quote_verified=1, n_survived=0)])
    assert draft_research_digest(con, 1, out_dir=tmp_path / "reports") is None
    # and no file is written for an empty digest
    assert not (tmp_path / "reports" / "1-deep-review-candidates.md").exists()


def test_research_digest_neutralizes_markdown_injection(tmp_path):
    # Finding text is model output derived from target source; it must not be able to forge
    # a heading, a link, or a code fence in a document a human is about to read.
    con = _research_db(tmp_path, [dict(
        title="# PWNED heading",
        reasoning="see [click me](http://evil.example) and `backtick`",
        quote="``` not a fence\nrm -rf /\n```")])
    dg = draft_research_digest(con, 1, out_dir=tmp_path / "reports")
    text = dg.path.read_text()
    # the forged heading is escaped, so no line begins with "# PWNED"
    assert not any(line.startswith("# PWNED") for line in text.splitlines())
    assert "\\# PWNED" in text
    # the link brackets are escaped, so no live Markdown link survives
    assert "[click me](http://evil.example)" not in text
    # the quote's fence cannot close the code block it sits in
    assert "```` not a fence" in text or "\n````\n" in text


def test_research_digest_shows_each_findings_human_verdicts(tmp_path):
    """Item 20. A human verdict reached the refuter and `deep-survivors` but not the
    digest, so a reader met a finding a human had already judged intended as new."""
    from quarry.research import verdicts
    con = _research_db(tmp_path, [
        dict(title="Judged and matched"),
        dict(title="Nobody has looked"),
        dict(title="The earlier one", quote_verified=0)])       # not in the digest
    judged, fresh, earlier = (r[0] for r in con.execute(
        "SELECT id FROM research_findings ORDER BY id"))
    matched = verdicts.record(con, earlier, "intended",
                              "documented as public; see [docs](http://evil.example)",
                              actor="jerry")
    con.execute("UPDATE research_findings SET prior_verdict_id=?, prior_match=? WHERE id=?",
                (matched, "overlapping quote", judged))
    verdicts.record(con, judged, "unclear", "# need the controller", actor="ops")
    verdicts.record(con, earlier, "real", "owning_cna leaks", actor="jerry")

    text = draft_research_digest(con, 1, out_dir=tmp_path / "reports").path.read_text()
    one, two = (s for s in text.split("\n### ")[1:])
    assert one.startswith("Judged and matched") and two.startswith("Nobody has looked")
    lines = one.splitlines()
    assert f"- Research finding: #{judged}" in lines
    assert any(l.startswith("- Human verdict: unclear, by `ops`, ") and
               l.endswith(r"UTC. Note: \# need the controller") for l in lines), lines
    prior = next(l for l in lines if l.startswith("- Matched an earlier finding:"))
    assert prior.startswith(f"- Matched an earlier finding: #{earlier} (run 1, overlapping "
                            "quote), The earlier one in `app/api.py`, judged intended, by "
                            "`jerry`, ")
    assert "[docs](http://evil.example)" not in prior and r"\[docs\]" in prior
    assert "That finding's verdict has since changed to real, by `jerry`" in prior
    assert prior.endswith("Note: owning_cna leaks")

    lines = two.splitlines()
    assert f"- Human verdict: none recorded. Record one with `quarry deep-verdict {fresh} " \
           f"intended|real|unclear --note \"...\"`" in lines
    assert "- Matched an earlier finding: none; new to human review" in lines
    assert not any(l.startswith("# need") for l in text.splitlines())


# ---- conditions, limits and confidence -----------------------------------------------
# A verdict written before the probes recorded replay/probe/conditions has none of those
# keys, and one written after has all three. The draft must be honest either way: it
# never claims reproducibility without replay counts, never guesses a missing condition,
# and never prints a credential or an --env value.

REPLAYED = {"attempts": 3, "reproduced": 3, "control_held": 3, "after_restart": True}
PROBE = {"id": "broken-authz-idor", "source_sha": "0123456789abcdef0123",
         "route": "/orders/{id}", "method": "get"}
CONDITIONS = {"seed": "vulnlookup", "env_keys": ["INSTANCE_UUID"], "auth": "user"}
VALIDATE = {"provisioning": {"build_network": "default", "dotenv": ".env.sample",
                             "env_files": [], "env_overrides": ["INSTANCE_UUID"],
                             "mem_limit": "6g"},
            "seed": "vulnlookup", "service": "vulnerability_lookup"}
HEAD_LINE = ("Current HEAD was not re-checked: report drafting makes no network request "
             "unless run with --check-head. Confirm the issue reproduces on the latest "
             "commit before sending.")


def _section(md, title):
    """The body of one H2 section."""
    return md.split(f"\n## {title}\n", 1)[1].split("\n## ", 1)[0].strip()


def _bullets(text):
    return [line for line in text.splitlines() if line.startswith("- ")]


def test_without_replay_the_draft_says_observed_once_and_never_reproducible():
    md = render_report(_ctx())
    assert "reproducible" not in md.lower() and "reproduced" not in md.lower()
    assert "observed once and was not replayed" in _section(md, "Description")
    assert "single observation" in _section(md, "Confidence")
    assert _section(md, "Limitations and weakest link").startswith(
        "Weakest link: The result was observed once and was not replayed.")


@pytest.mark.parametrize("bad", [
    {"attempts": "3", "reproduced": 3, "control_held": 3},          # a string count
    {"attempts": True, "reproduced": True, "control_held": True},   # a bool is not a count
    {"attempts": 2, "reproduced": 3, "control_held": 2},            # more than attempted
    {"attempts": 3, "reproduced": 3, "control_held": 3, "after_restart": "yes"},
    [3, 3, 3],
])
def test_a_malformed_replay_record_is_not_evidence_of_reproduction(bad):
    md = render_report(_ctx(replay=bad))
    assert "reproducible" not in md.lower() and "reproduced" not in md.lower()
    assert "could not be read" in _section(md, "Confidence")
    assert "observed once and was not replayed" in md


def test_replay_evidence_is_reported_as_counts():
    md = render_report(_ctx(replay=REPLAYED))
    conf = _section(md, "Confidence")
    assert "replayed 3 times" in conf and "reproduced 3 of 3" in conf
    assert "control held 3 of 3" in conf and "reproduced again" in conf
    assert "reproduced on 3 of 3 replays" in _section(md, "Description")
    assert "not replayed" not in md
    assert "reproducible" not in md.lower()               # counts, never the adjective
    # every replay agreed, so the weakest link left is file-to-route
    assert _section(md, "Limitations and weakest link").startswith(
        "Weakest link: Quarry matched the flagged file to the route it probed and "
        "did not trace")


def test_replays_with_no_restart_name_the_restart_as_the_weakest_link():
    md = render_report(_ctx(replay={**REPLAYED, "after_restart": None}))
    weakest = _section(md, "Limitations and weakest link").splitlines()[0]
    assert "after a restart" in weakest
    assert "No replay ran after a restart" in _section(md, "Confidence")


@pytest.mark.parametrize("replay", [
    {**REPLAYED, "reproduced": 2},
    {**REPLAYED, "control_held": 1},
    {**REPLAYED, "after_restart": False},
])
def test_disagreeing_replays_are_held_as_needs_review(replay):
    md = render_report(_ctx(replay=replay))
    conf = _section(md, "Confidence")
    assert "replays disagreed" in conf and "needs-review" in conf
    assert _section(md, "Limitations and weakest link").startswith(
        "Weakest link: Replays disagreed")
    assert "reproducible" not in md.lower()


def test_severity_is_a_class_default_kept_apart_from_confidence():
    for ctx in (_ctx(), _ctx(replay=REPLAYED)):
        md = render_report(ctx)
        sev, conf = _section(md, "Severity"), _section(md, "Confidence")
        assert sev.startswith("Class default: **High** for CWE-862")
        assert "not an impact the probe demonstrated" in sev
        assert "confirmed" not in sev.lower() and "replay" not in sev.lower()
        assert "High" not in conf and "class default" not in conf.lower()
    sev = _section(render_report(_ctx(cwe="CWE-1336")), "Severity")
    assert sev.startswith("No class default for CWE-1336")


def test_a_needs_review_verdict_is_never_rendered_as_confirmed():
    md = render_report(_ctx(verdict="needs-review", verdict_reason="did not replay"))
    assert _section(md, "Confidence").startswith("**Needs review** (did not replay)")
    assert "confirmed dynamically" not in md
    assert _section(md, "Limitations and weakest link").startswith(
        "Weakest link: The verdict is needs-review, not confirmed (did not replay).")


def test_conditions_without_records_say_not_recorded_and_guess_nothing():
    cond = _section(render_report(_ctx()), "Conditions")
    assert "- Commit observed: `abc1234`" in _bullets(cond)
    for label in ("Route and method", "Probe", "Authentication", "Seed recipe",
                  "Environment overrides used to boot",
                  "Build network, memory limit and .env source", "Compose service probed"):
        line = next(b for b in _bullets(cond) if b.startswith(f"- {label}:"))
        assert "not recorded" in line, line
    # probes are anonymous today, but that is not recorded on this verdict, so not said
    assert "anonymous" not in cond and "not seeded" not in cond
    assert "- Commit observed: not recorded" in render_report(_ctx(git_sha=None))


def test_conditions_from_the_rationale_and_the_manifest():
    md = render_report(_ctx(probe=PROBE, conditions=CONDITIONS, validate=VALIDATE,
                            replay=REPLAYED))
    cond = _section(md, "Conditions")
    assert not any("not recorded" in b for b in _bullets(cond))
    assert not any("recorded for the run" in b for b in _bullets(cond))  # verdict's own
    assert "- Route and method: `GET` `/orders/{id}`" in cond
    assert "- Probe: `broken-authz-idor`, source hash `0123456789ab`" in cond
    assert ("- Authentication: a seeded test account with role `user` from recipe "
            "`vulnlookup`; its key and password are not in this draft") in cond
    assert "- Seed recipe: `vulnlookup`" in cond
    assert "- Environment overrides used to boot: `INSTANCE_UUID` (names only" in cond
    assert "- Build network: default" in cond
    assert "- Memory limit per service: `6g`" in cond
    assert "- .env file used for interpolation: `.env.sample`" in cond
    assert "- Compose service probed: `vulnerability_lookup`" in cond
    limits = _section(md, "Limitations and weakest link")
    assert "seeded with recipe `vulnlookup`" in limits
    assert "operator overrides for `INSTANCE_UUID`" in limits


def test_the_manifest_alone_supplies_run_level_conditions():
    # A verdict from before the probes recorded conditions still gets what the run
    # manifest holds, and a run with no recipe says so, distinct from "not recorded".
    md = render_report(_ctx(validate={**VALIDATE, "seed": None}))
    cond = _section(md, "Conditions")
    # the manifest holds the run's latest validation, so its values say where they came from
    assert ("- Seed recipe: none (the instance was not seeded) (recorded for the run)"
            in cond)
    assert ("- Environment overrides used to boot: `INSTANCE_UUID` (names only; the values "
            "are not in this draft) (recorded for the run)") in cond
    assert "- Authentication: not recorded" in cond
    assert "The instance was not seeded." in _section(md, "Limitations and weakest link")
    anon = _section(render_report(_ctx(conditions={"seed": None, "env_keys": [],
                                                   "auth": "anonymous"})), "Conditions")
    assert "- Authentication: anonymous (the probe sent no credentials)" in anon
    assert "- Environment overrides used to boot: none" in anon


SECRETS = ("hunter2", "6f1c2d3e-aaaa-bbbb-cccc-000000000001", "sk_live_abcdef0123456789",
           "abcdef0123456789abcdef", "s3ss10nc00k1e", "qwerty12345", "tok9876543210",
           "s3cr3t", "Zm9vOmJhcg", "keyABCDEF0123456789")


def test_no_secret_value_reaches_a_draft():
    md = render_report(_ctx(
        request=("GET http://web:8080/orders/1?api_key=qwerty12345&page=2\n"
                 "Authorization: Bearer sk_live_abcdef0123456789\n"
                 "X-API-KEY: abcdef0123456789abcdef\n"
                 "Proxy-Authorization: Basic Zm9vOmJhcg=="),
        observed=('HTTP 200\nSet-Cookie: session=s3ss10nc00k1e; Path=/\n'
                  '{"apikey": "tok9876543210", "id": 1}'),
        conditions={"seed": "vulnlookup", "auth": "keyABCDEF0123456789",
                    "env_keys": ["DB_PASSWORD=hunter2", "INSTANCE_UUID", "s3cr3t value!"]}))
    for s in SECRETS:
        assert s not in md, s
    assert "`DB_PASSWORD`" in md and "`INSTANCE_UUID`" in md        # the names stay
    assert "1 entry withheld" in md
    assert "Authentication: recorded, but withheld" in md
    assert "Authorization: Bearer <redacted>" in md
    assert "Proxy-Authorization: Basic <redacted>" in md
    assert "page=2" in md and '"id": 1' in md                       # the rest stays verbatim
    assert "replaced with `<redacted>`" in md
    # a provisioning record shaped as {KEY: value} by mistake still yields names only
    md = render_report(_ctx(validate={"provisioning": {
        "env_overrides": {"INSTANCE_UUID": "6f1c2d3e-aaaa-bbbb-cccc-000000000001"}}}))
    assert "6f1c2d3e" not in md and "`INSTANCE_UUID`" in md


def test_redaction_leaves_an_injection_payload_intact():
    # An injection probe puts its payload in whatever parameter the route takes, a login
    # form's password included. The PoC is worthless without it, so it stays.
    req = "GET http://web:8080/login?user=a&password=%27%20OR%201%3D1--&token=x"
    md = render_report(_ctx(request=req))
    assert req in md and "<redacted>" not in md


def test_a_seeded_confirmed_run_drafts_no_credential(scanned, monkeypatch):
    """End to end through the Layer 3 loop: a seed step runs with a generated password
    and captures an API key, the probe confirms against a baseline, and the draft names
    the recipe and the service but holds neither value."""
    from dataclasses import replace
    from quarry.dynamic import lenses, probes
    from quarry.dynamic.seed import SeedRecipe, SeedStep
    from quarry.dynamic.validate import RunningTarget, run_validation
    con, rundir = scanned

    def with_baseline(running, cand, routes, exec_fn):
        ev = probes.probe_broken_authz(running, cand, routes, exec_fn)
        return replace(ev, baseline="GET /health -> 200 (unprotected sibling)",
                       differs_from_baseline=True)
    monkeypatch.setattr(lenses, "CATALOGUE", tuple(
        replace(lens, run=with_baseline) if lens.key == "broken-authz-idor" else lens
        for lens in lenses.CATALOGUE))

    class Seeded(FakeRuntime):
        provisioning = {"build_network": "none", "dotenv": ".env", "env_files": [],
                        "env_overrides": ["INSTANCE_UUID"], "mem_limit": "2g"}

        def start(self, spec, rundir):
            return RunningTarget("http://web:8080", stop=self._stop, network="net",
                                 service="web", port=8080)

        def service_exec(self, running, argv, *, service="", timeout=900):
            self.argv = list(argv)
            return 0, "APIKEY=abcdef0123456789\n"

    rt = Seeded({"/secret": "200"})
    recipe = SeedRecipe(name="t", steps=(SeedStep(
        argv=("mkadmin", "--password", "{password}"), capture=r"APIKEY=(\w+)",
        capture_as="admin_api_key"),))
    assert run_validation(con, 1, rundir, rt, seed=recipe).confirmed == 1
    password = rt.argv[2]
    text = draft_reports(con, 1, rundir / "src", out_dir=rundir / "reports")[0] \
        .path.read_text()
    assert "abcdef0123456789" not in text and password not in text
    assert "- Seed recipe: `t`" in text and "captured admin_api_key" in text
    assert "- Environment overrides used to boot: `INSTANCE_UUID`" in text
    assert "- Compose service probed: `web`" in text
    # run_validation replays a confirmation (item 17). This runtime cannot restart, so
    # the draft reports three in-place replays and says none ran after a restart.
    assert "were replayed 3 times: the effect reproduced 3 of 3 times" in text
    assert "No replay ran after a restart of the target service." in text
    assert "observed once" not in text


def test_head_line_is_always_present():
    for ctx in (_ctx(), _ctx(git_sha=None), _ctx(replay=REPLAYED), _hostile_ctx()):
        assert HEAD_LINE in _section(render_report(ctx), "Affected versions")


# ---- prior advisories checked ---------------------------------------------------------

def test_prior_advisories_not_checked_says_so_plainly():
    sec = _section(render_report(_ctx()), "Prior advisories checked")
    assert "- Prior advisories: not checked (offline)." in sec
    assert "- SECURITY.md in the clone: not checked (the clone was not available)" in sec
    assert "Nothing was searched for an earlier report" in sec


def _adv(i, cwes, basis="package name", modified="2025-01-01"):
    return PriorAdvisory(f"GHSA-{i}", (f"CVE-2025-{i}",), cwes, f"issue {i}", modified,
                         "PyPI", basis)


def test_prior_advisories_lists_matches_same_weakness_first():
    matches = ([_adv(1, ("CWE-79",), modified="2026-01-01"),
                _adv(2, ("CWE-862",), basis="reference URL"), _adv(3, ("CWE-862",))]
               + [_adv(10 + i, ()) for i in range(10)])
    prior = PriorCheck(True, ecosystems=("PyPI",), entries_read=26723,
                       downloaded="2026-10-28", package="widgets", package_ecosystem="PyPI",
                       repo="github.com/acme/widgets", matches=matches)
    sec = _section(render_report(_ctx(prior=prior, security_policy=())),
                   "Prior advisories checked")
    assert "- Prior advisories: 13 found, 2 of them recorded with CWE-862." in sec
    assert ("Searched 26,723 records in the local OSV copies for PyPI (oldest copy "
            "downloaded 2026-10-28), by package name `widgets` in PyPI and by repository "
            "`github.com/acme/widgets`.") in sec
    ids = re.findall(r"`(GHSA-\d+)`", sec)
    assert ids[:3] == ["GHSA-3", "GHSA-2", "GHSA-1"]   # same CWE, then basis, then newest
    assert len(ids) == 10 and "and 3 more not listed here" in sec
    assert "matched by reference URL" in sec
    assert ("- SECURITY.md in the clone: absent (looked for `SECURITY.md`, "
            "`.github/SECURITY.md`, `docs/SECURITY.md`)") in sec
    assert "A miss here does not show the issue is new." in sec


def test_prior_advisories_none_found_states_what_was_searched():
    prior = PriorCheck(True, ecosystems=("PyPI", "npm"), entries_read=100,
                       package="widgets", package_ecosystem="PyPI",
                       repo="github.com/acme/widgets")
    sec = _section(render_report(_ctx(prior=prior, security_policy=("SECURITY.md",))),
                   "Prior advisories checked")
    assert sec.startswith("- Prior advisories: none found. Searched 100 records in the "
                          "local OSV copies for PyPI, npm, by package name")
    assert "`SECURITY.md` present" in sec
    gap = PriorCheck(False, "no local OSV database; quarry db sync downloads one")
    sec = _section(render_report(_ctx(prior=gap)), "Prior advisories checked")
    assert sec.startswith("- Prior advisories: not checked (offline; no local OSV database")


def test_security_policy_presence(tmp_path):
    assert find_security_policy(tmp_path / "not-mounted") is None
    repo = tmp_path / "repo"
    repo.mkdir()
    assert find_security_policy(repo) == ()
    outside = tmp_path / "outside.md"
    outside.write_text("policy")
    (repo / "SECURITY.md").symlink_to(outside)          # a link out of the clone
    assert find_security_policy(repo) == ()
    (repo / ".github").mkdir()
    (repo / ".github" / "SECURITY.md").write_text("policy")
    assert find_security_policy(repo) == (".github/SECURITY.md",)


def test_draft_reports_carries_conditions_prior_check_and_policy(tmp_path):
    con, src = _db(tmp_path)
    ev = {**json.loads(CONFIRMED_EVIDENCE), "replay": REPLAYED, "probe": PROBE,
          "conditions": CONDITIONS}
    _confirm(con, "f1", rationale=json.dumps(ev))
    with db.tx(con):
        db.update_manifest(con, 1, lambda m: m.update(validate=VALIDATE))
        db.set_health(con, 1, "validate",
                      {"seed": ["seed step [read quarry_user API key]: captured user_api_key"]})
    root = tmp_path / "dbs"
    _osv_zip(root, "PyPI", [_rec("GHSA-prior", "PyPI", "widgets", cwes=["CWE-862"])])
    d = draft_reports(con, 1, src, out_dir=tmp_path / "reports", vulndb_root=root)[0]
    text = d.path.read_text()
    assert "`GHSA-prior` (CWE-862; matched by package name)" in text
    assert "- SECURITY.md in the clone: `SECURITY.md` present" in text
    assert "role `user` from recipe `vulnlookup`" in text
    assert "captured user_api_key" in text
    assert "reproduced 3 of 3" in text and "reproducible" not in text.lower()
    assert d.sha256 == hashlib.sha256(d.path.read_bytes()).hexdigest()


def test_draft_reports_without_a_local_osv_copy_says_not_checked(tmp_path):
    con, src = _db(tmp_path)
    _confirm(con, "f1")                     # the evidence has no replay/probe/conditions
    text = build_reports(con, 1, src, out_dir=tmp_path / "reports")[0].read_text()
    assert "- Prior advisories: not checked (offline; no local OSV database" in text
    assert "- Authentication: not recorded" in text
    assert "observed once and was not replayed" in text
    assert "reproducible" not in text.lower()
    assert HEAD_LINE in text
