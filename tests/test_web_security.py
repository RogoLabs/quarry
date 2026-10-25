"""The dashboard is a local web server that renders attacker-chosen strings and has
routes that spawn processes and send signals. These are the regressions for the
defects a review proved against it: CSRF, DNS rebinding, a bind-anything `serve`, a
SIGTERM to whatever holds a stale pid, invisible bidi characters, a restore that
undid more than the dismissal, unescaped error text, and counts that overstated
what a table showed.
"""
from __future__ import annotations

import gzip
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient          # noqa: E402

from quarry.web import queries as q             # noqa: E402

from test_funnel import add                        # noqa: E402
from test_web import (ORIGIN, _post, _spawn_sleeper, _utc_now,  # noqa: E402,F401
                      bystander, seeded, worker)


def _state_changing_routes(app) -> list[str]:
    return sorted(r.path for r in app.routes
                  if "POST" in getattr(r, "methods", set()))


def _fill(path: str) -> str:
    return (path.replace("{producer_id:path}", "bandit:B101")
                .replace("{rid}", "1"))


# ===================================================================== CSRF

def test_every_state_changing_route_refuses_a_cross_site_post(seeded):
    """REGRESSION. Any page in the operator's browser could submit a form to
    127.0.0.1:8099 and dismiss a producer, start an eight-hour run, or SIGTERM a
    worker. Enumerated from the app, so a POST route added later is covered too."""
    client, con = seeded
    routes = _state_changing_routes(client.app)
    assert len(routes) >= 5, routes
    before = con.execute("SELECT COUNT(*) c FROM funnel_events").fetchone()["c"]
    token = client.app.state.csrf_token
    for path in routes:
        url = _fill(path)
        form = {"run_id": 1, "models": ["qwen3-coder:30b", "gpt-oss:20b"]}
        # a foreign Origin, even holding the right token (it cannot, but assume worse)
        r = client.post(url, data={**form, "csrf": token},
                        headers={"Origin": "https://attacker.example"},
                        follow_redirects=False)
        assert r.status_code == 403, f"{path} accepted a cross-origin POST"
        # no Origin, no Sec-Fetch-Site, no Referer: nothing proves where it came from
        r = client.post(url, data={**form, "csrf": token}, follow_redirects=False)
        assert r.status_code == 403, f"{path} accepted a POST with no provenance"
        # same origin, but no token
        r = client.post(url, data=form, headers={"Origin": ORIGIN},
                        follow_redirects=False)
        assert r.status_code == 403, f"{path} accepted a POST without the form token"
        r = client.post(url, data={**form, "csrf": "stale"},
                        headers={"Origin": ORIGIN}, follow_redirects=False)
        assert r.status_code == 403, f"{path} accepted a wrong form token"
    after = con.execute("SELECT COUNT(*) c FROM funnel_events").fetchone()["c"]
    assert after == before, "a refused request still wrote to the ledger"


def test_the_dashboards_own_forms_still_work(seeded):
    """Same Origin plus the token from the page is accepted. Also the
    `Origin: null` case, which privacy settings can still produce, so Sec-Fetch-Site
    has to carry the decision there."""
    client, _ = seeded
    assert _post(client, "/producers/bandit:B101/dismiss",
                 {"run_id": 1}).status_code == 303
    token = client.app.state.csrf_token
    r = client.post("/producers/bandit:B101/restore",
                    data={"run_id": 1, "csrf": token},
                    headers={"Origin": "null", "Sec-Fetch-Site": "same-origin"},
                    follow_redirects=False)
    assert r.status_code == 303
    r = client.post("/producers/bandit:B101/restore",
                    data={"run_id": 1, "csrf": token},
                    headers={"Origin": "null", "Sec-Fetch-Site": "cross-site"},
                    follow_redirects=False)
    assert r.status_code == 403
    r = client.post("/producers/bandit:B101/restore",
                    data={"run_id": 1, "csrf": token},
                    headers={"Referer": ORIGIN + "/triage"}, follow_redirects=False)
    assert r.status_code == 303


def test_a_browser_without_fetch_metadata_can_still_post(seeded):
    """Safari before 16.4 sends no Sec-Fetch-Site. With `Referrer-Policy: same-origin`
    it sends a real Origin and Referer on our own forms, and that has to be enough."""
    client, _ = seeded
    _post(client, "/producers/bandit:B101/dismiss", {"run_id": 1})
    r = client.post("/producers/bandit:B101/restore",
                    data={"run_id": 1, "csrf": client.app.state.csrf_token},
                    headers={"Origin": ORIGIN, "Referer": ORIGIN + "/triage"},
                    follow_redirects=False)
    assert r.status_code == 303


def test_every_form_carries_the_token(seeded):
    """The token is only a defence if every form renders it."""
    client, con = seeded
    con.execute("INSERT INTO research_runs (id,run_id,status,models,lenses,profile) "
                "VALUES (1,1,'stopped','[\"a:1b\",\"c:2d\"]','[]','{}')")
    con.execute("INSERT INTO research_units (research_id,subsystem,weight,lens,model,"
                "phase,status) VALUES (1,'src',1.0,'x','a:1b','hunt','pending')")
    con.commit()
    r = _post(client, "/producers/bandit:B101/dismiss", {"run_id": 1})
    pages = [client.get(r.headers["location"]).text, client.get("/research").text,
             client.get("/research/1").text]
    token = client.app.state.csrf_token
    n_forms = 0
    for page in pages:
        for form in page.split("<form")[1:]:
            n_forms += 1
            body = form.split("</form>")[0]
            assert f'name="csrf" value="{token}"' in body, body[:200]
    assert n_forms >= 4, "expected the dismiss, restore, start and resume forms"


def test_research_start_accepts_only_offered_models_and_real_runs(seeded, monkeypatch):
    """The model list becomes argv for a detached process; it was never checked
    against the list the page offers, and run_id was never checked at all."""
    client, con = seeded
    spawned = []
    import subprocess
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: spawned.append(a))
    r = _post(client, "/research/start",
              {"run_id": 1, "models": ["qwen3-coder:30b", "--evil=1"]})
    assert r.status_code == 400 and "Unknown model" in r.text
    r = _post(client, "/research/start",
              {"run_id": 999, "models": ["qwen3-coder:30b", "gpt-oss:20b"]})
    assert r.status_code == 404
    r = _post(client, "/research/start",
              {"run_id": 1, "models": ["qwen3-coder:30b", "gpt-oss:20b"]})
    assert r.status_code == 409, "run 1 has no volume, so there is nothing to review"
    assert not spawned
    con.execute("UPDATE runs SET volume_path='/nonexistent' WHERE id=1")
    con.commit()
    r = _post(client, "/research/start",
              {"run_id": 1, "models": ["qwen3-coder:30b", "gpt-oss:20b"]})
    assert r.status_code == 303 and len(spawned) == 1


def test_spawning_does_not_leak_the_log_handle(seeded, monkeypatch):
    """The server opened a log file per click and never closed its copy."""
    client, con = seeded
    con.execute("UPDATE runs SET volume_path='/nonexistent' WHERE id=1")
    con.commit()
    handles = []
    import subprocess
    monkeypatch.setattr(subprocess, "Popen",
                        lambda *a, **k: handles.append(k["stdout"]))
    _post(client, "/research/start",
          {"run_id": 1, "models": ["qwen3-coder:30b", "gpt-oss:20b"]})
    assert handles and all(h.closed for h in handles)


# ============================================================ host and headers

def test_a_foreign_host_header_is_refused(seeded):
    """DNS rebinding: the attacker's name resolves to 127.0.0.1, the browser calls
    the dashboard same-origin with the attacker's page, and only Host gives it away."""
    client, _ = seeded
    assert client.get("/triage", headers={"Host": "attacker.example"}).status_code == 400
    assert client.get("/triage",
                      headers={"Host": "attacker.example:8099"}).status_code == 400
    for host in ("127.0.0.1", "127.0.0.1:8099", "localhost:8099", "[::1]:8099", "[::1]"):
        assert client.get("/triage", headers={"Host": host}).status_code == 200, host


def test_every_response_refuses_framing_and_sniffing(seeded):
    client, _ = seeded
    for url in ("/triage", "/runs/9999", "/static/app.css", "/no-such-route"):
        r = client.get(url)
        assert r.headers["x-frame-options"] == "DENY", url
        assert "frame-ancestors 'none'" in r.headers["content-security-policy"], url
        assert r.headers["x-content-type-options"] == "nosniff", url
        assert r.headers["referrer-policy"] == "same-origin", url
    bad = client.get("/triage", headers={"Host": "attacker.example"})
    assert bad.headers["x-frame-options"] == "DENY"


# ================================================================ serve

@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.5", "::", "example.com"])
def test_serve_refuses_a_non_loopback_bind(host, monkeypatch, tmp_path):
    """REGRESSION. `quarry serve --host 0.0.0.0` put an unauthenticated dashboard that
    spawns processes on every interface, silently."""
    from typer.testing import CliRunner
    from quarry import cli
    import uvicorn
    monkeypatch.setenv("QUARRY_HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    called = []
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: called.append(k))
    r = CliRunner().invoke(cli.app, ["serve", "--host", host])
    assert r.exit_code != 0 and not called
    assert "loopback" in r.output


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1"])
def test_serve_accepts_loopback(host, monkeypatch, tmp_path):
    from typer.testing import CliRunner
    from quarry import cli
    import uvicorn
    monkeypatch.setenv("QUARRY_HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    called = []
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: called.append(k))
    r = CliRunner().invoke(cli.app, ["serve", "--host", host])
    assert r.exit_code == 0, r.output
    assert called and called[0]["host"] == host


# ================================================================ CLI markup

def test_cli_escapes_untrusted_strings(seeded):
    """REGRESSION. rich parses `[...]` as markup, so a scanned file named `a[/b].py`
    crashed `quarry killed` with a MarkupError; a name like `[red]x` restyled the
    output. Paths, reasons and quarantine entries all come from the target repo."""
    from typer.testing import CliRunner
    from quarry import cli
    _, con = seeded
    oid = add(con, "bandit", "B999", "a[/b].py", 7)
    con.execute("INSERT INTO funnel_events (run_id,occurrence_id,producer_id,stage,"
                "action,deterministic,reason,actor) VALUES (1,?,'bandit:B999',"
                "'path-class','kill',1,'[bold]because[/]','system')", (oid,))
    con.execute("INSERT INTO quarantined (run_id,kind,original_path,detail) "
                "VALUES (1,'symlink','x[/y]','[red]d')")
    con.commit()
    runner = CliRunner()
    r = runner.invoke(cli.app, ["killed", "1", "--limit", "50"],
                      env={"COLUMNS": "300"})
    assert r.exit_code == 0, r.output
    assert "a[/b].py" in r.output and "[bold]because[/]" in r.output
    r = runner.invoke(cli.app, ["quarantine", "1"], env={"COLUMNS": "300"})
    assert r.exit_code == 0, r.output
    assert "x[/y]" in r.output and "[red]d" in r.output


def test_cli_output_strings_carry_no_em_dash():
    """House style for printed output. Comments may keep theirs; strings may not."""
    import ast
    src = (Path(q.__file__).resolve().parents[1] / "cli.py").read_text()
    bad = [n.lineno for n in ast.walk(ast.parse(src))
           if isinstance(n, ast.Constant) and isinstance(n.value, str)
           and "\u2014" in n.value]
    assert not bad, f"em dash in cli.py string(s) at line(s) {bad}"


# ============================================================ stop identity

def _research_row(con, rid, *, pid, status="running", heartbeat=None):
    con.execute("INSERT INTO research_runs (id,run_id,status,models,lenses,profile,"
                "pid,heartbeat) VALUES (?,1,?,'[\"a:1b\",\"c:2d\"]','[]','{}',?,?)",
                (rid, status, pid, heartbeat))
    con.commit()


def test_stop_never_signals_a_process_that_is_not_the_worker(seeded, bystander):
    """REGRESSION. /stop sent SIGTERM to whatever pid the row held. After the worker
    dies the OS recycles that pid, so Stop killed an unrelated program."""
    client, con = seeded
    _research_row(con, 1, pid=bystander.pid, heartbeat=_utc_now())
    r = _post(client, "/research/1/stop")
    assert r.status_code == 409 and "nothing was signalled" in r.text
    assert bystander.poll() is None, "an unrelated process was killed"


def test_stop_refuses_a_worker_that_started_after_the_last_heartbeat(seeded, worker):
    """Same program name, same argv, wrong process: it was born after the heartbeat
    the real worker last wrote, so it cannot be that worker."""
    client, con = seeded
    _research_row(con, 1, pid=worker.pid, heartbeat=_utc_now(minutes=-60))
    assert _post(client, "/research/1/stop").status_code == 409
    assert worker.poll() is None


def test_stop_refuses_terminal_runs(seeded, worker):
    client, con = seeded
    for i, st in enumerate(q.TERMINAL_STATUSES, start=1):
        _research_row(con, i, pid=worker.pid, status=st, heartbeat=_utc_now())
        r = _post(client, f"/research/{i}/stop")
        assert r.status_code == 409 and "nothing to stop" in r.text
    assert worker.poll() is None


def test_stop_signals_the_verified_worker(seeded, worker):
    client, con = seeded
    _research_row(con, 1, pid=worker.pid, heartbeat=_utc_now())
    assert _post(client, "/research/1/stop").status_code == 303
    assert worker.wait(timeout=10) is not None, "the real worker was not signalled"


# ============================================================ invisible characters

RLO = "‮"
HOSTILE = (f"src/{RLO}yp.exe", f"rule{RLO}x", f"msg{RLO}gsm", f"code{RLO}line",
           "zw​sp", "iso⁦late", "bom﻿", "alm؜")
_CONTROLS = "‪‫‬‭‮⁦⁧⁨⁩" \
            "​‌‍‎‏؜﻿"


def _no_raw_controls(text: str, where: str) -> None:
    hit = sorted({f"U+{ord(ch):04X}" for ch in text if ch in _CONTROLS})
    assert not hit, f"{where} carries raw invisible formatting characters: {hit}"


def test_bidi_and_zero_width_characters_render_as_visible_tokens(seeded):
    """REGRESSION. Attacker-chosen paths, rule ids, messages and code lines reached
    the page with their bidi overrides intact, so a filename could display as
    something it is not on the screen whose job is to show what is true."""
    client, con = seeded
    oid = add(con, "opengrep", f"rule{RLO}x", f"src/{RLO}yp.exe", 5,
              message=f"msg{RLO}gsm​")
    body = gzip.compress(f"ok\ncode{RLO}line⁦x⁩\nend".encode())
    con.execute("UPDATE evidence_blobs SET body=?, start_line=4 WHERE sha="
                "(SELECT blob_sha FROM occurrences WHERE id=?)", (body, oid))
    con.execute("INSERT INTO funnel_events (run_id,occurrence_id,producer_id,stage,"
                "action,deterministic,reason,actor) VALUES (1,?,?,'path-class','kill',"
                "1,?,'system')", (oid, f"opengrep:rule{RLO}x", f"because{RLO}"))
    con.execute("INSERT INTO quarantined (run_id,kind,original_path,detail) "
                "VALUES (1,'symlink',?,?)", (f"q/{RLO}p", f"d{RLO}"))
    con.commit()
    pid = f"opengrep:rule{RLO}x"
    from urllib.parse import quote
    pages = {
        "triage": client.get(f"/triage?run=1&producer={quote(pid)}&occ={oid}").text,
        "evidence": client.get(f"/evidence/{oid}").text,
        "fragment": client.get(f"/evidence/{oid}", headers={"hx-request": "1"}).text,
        "killed": client.get("/runs/1?stage=path-class&action=kill").text,
        "all": client.get("/runs/1?suppressed=all").text,
    }
    for name, text in pages.items():
        _no_raw_controls(text, name)
    assert "‹U+202E›" in pages["triage"]
    assert "code‹U+202E›line‹U+2066›" in pages["evidence"]
    assert "‹U+200B›" in pages["triage"]


def test_model_output_on_the_research_page_is_made_visible(seeded):
    """Deep-review quotes, titles and reasoning are model output about attacker
    code: the same characters arrive by that route too."""
    client, con = seeded
    con.execute("INSERT INTO research_runs (id,run_id,status,models,lenses,profile) "
                "VALUES (5,1,'done','[\"a:1b\"]','[]',?)",
                (f'{{"summary": "sum{RLO}"}}',))
    con.execute(
        "INSERT INTO research_findings (research_id,lens,model,family,subsystem,file,"
        "title,severity,quote,quote_verified,reasoning,attacker_control,self_critique,"
        "refutations) VALUES (5,'x','a:1b','a',?,?,?,'high',?,1,?,?,?,?)",
        (f"sub{RLO}", f"f{RLO}.py", f"title{RLO}", f"quote{RLO}", f"why{RLO}",
         f"ctl{RLO}", f"crit{RLO}",
         f'[{{"model": "c:2d", "verdict": "v{RLO}", "reason": "r{RLO}"}}]'))
    con.commit()
    page = client.get("/research/5").text
    _no_raw_controls(page, "/research/5")
    assert page.count("‹U+202E›") >= 9


def test_no_template_carries_a_bidi_prefix():
    """The review found templates prepending an unclosed U+202B (RLE) to get a left
    ellipsis. Truncation happens in Python (`tail_path`, `rule_id`), so no template
    may embed a bidi control, raw or as a character reference."""
    tpl = Path(q.__file__).resolve().parent / "templates"
    for f in tpl.glob("*.html"):
        text = f.read_text()
        _no_raw_controls(text, f.name)
        for ref in ("&#8234;", "&#8235;", "&#8236;", "&#8237;", "&#8238;",
                    "&#x202", "&#X202"):
            assert ref not in text, f"{f.name} embeds {ref}"


# ============================================================ restore scope

def test_restore_does_not_reenable_a_producer_this_dismissal_did_not_disable(seeded):
    """REGRESSION. Restore set `enabled=1` and erased the note whatever had disabled
    the producer, so undoing a repo-scoped dismissal silently re-enabled a
    corpus-wide disable made elsewhere."""
    client, con = seeded
    con.execute("UPDATE producers SET enabled=0, dismissed_at=datetime('now'), "
                "dismissed_note='disabled elsewhere' WHERE id='bandit:B101'")
    con.commit()
    live = lambda: con.execute("SELECT COUNT(*) c FROM live_occurrences "  # noqa: E731
                               "WHERE run_id=1").fetchone()["c"]
    before = live()
    _post(client, "/producers/bandit:B101/dismiss", {"run_id": 1, "scope": "repo"})
    assert live() < before
    _post(client, "/producers/bandit:B101/restore", {"run_id": 1})
    row = con.execute("SELECT enabled, dismissed_note FROM producers "
                      "WHERE id='bandit:B101'").fetchone()
    assert row["enabled"] == 0 and row["dismissed_note"] == "disabled elsewhere"
    assert live() == before, "this run's operator kills are still restored"


def test_restore_does_not_undo_another_runs_corpus_dismissal(seeded):
    client, con = seeded
    con.execute("INSERT INTO runs (id,target,clone_url,status) "
                "VALUES (2,'o/r2','https://y','done')")
    con.commit()
    _post(client, "/producers/bandit:B101/dismiss",
          {"run_id": 2, "scope": "corpus", "note": "noise"})
    _post(client, "/producers/bandit:B101/dismiss", {"run_id": 1, "scope": "repo"})
    _post(client, "/producers/bandit:B101/restore", {"run_id": 1})
    row = con.execute("SELECT enabled, dismissed_note FROM producers "
                      "WHERE id='bandit:B101'").fetchone()
    assert row["enabled"] == 0 and row["dismissed_note"] == "noise"
    # and run 2's own restore does undo it
    _post(client, "/producers/bandit:B101/restore", {"run_id": 2})
    row = con.execute("SELECT enabled, dismissed_note FROM producers "
                      "WHERE id='bandit:B101'").fetchone()
    assert row["enabled"] == 1 and row["dismissed_note"] is None


def test_an_arbitrary_undo_parameter_renders_no_restore_form(seeded):
    """REGRESSION. `/triage?undo=<anything>` rendered a working restore button for
    whatever the URL named."""
    client, _ = seeded
    for undo in ("bandit:B101", "made-up:producer", "<script>"):
        page = client.get(f"/triage?run=1&undo={undo}").text
        assert "/restore" not in page, undo
    _post(client, "/producers/bandit:B101/dismiss", {"run_id": 1})
    assert "/restore" in client.get("/triage?run=1&undo=bandit:B101").text


# ============================================================ errors

def test_error_text_is_escaped(seeded):
    """REGRESSION. Exception text was interpolated into HTML unescaped, and the text
    can carry attacker strings (a path, a rule id)."""
    client, _ = seeded
    app = client.app

    @app.get("/__test_xss")
    def boom():
        raise RuntimeError("<script>alert(1)</script>")

    c = TestClient(app, raise_server_exceptions=False, base_url=ORIGIN)
    for headers in ({}, {"hx-request": "true"}):
        r = c.get("/__test_xss", headers=headers)
        assert r.status_code == 500
        assert "<script>alert(1)" not in r.text
        assert "&lt;script&gt;" in r.text
        assert r.headers["x-frame-options"] == "DENY", \
            "the 500 handler runs outside the middleware stack"


def test_router_404s_get_the_themed_page(seeded):
    client, _ = seeded
    r = client.get("/no-such-route")
    assert r.status_code == 404 and '<html lang="en">' in r.text


def test_unrepresentable_and_missing_ids_are_404_not_500(seeded):
    client, _ = seeded
    for url in ("/evidence/99999999999999999999999", "/runs/99999999999999999999999",
                "/research/99999999999999999999999", "/triage?run=9999",
                "/triage?run=99999999999999999999999",
                "/triage?run=1&occ=99999999999999999999999"):
        r = client.get(url)
        assert r.status_code == 404, f"{url} -> {r.status_code}"


def test_requests_close_their_connections(seeded, monkeypatch):
    """Every route opened a sqlite connection and left it for the garbage collector.

    Tracked through a Connection subclass because the connections are opened on
    threadpool threads, and sqlite3 refuses any use of them (even a probe) from the
    test's thread."""
    import sqlite3
    opened = []

    class Tracked(sqlite3.Connection):
        closed = False

        def close(self):
            self.closed = True
            super().close()

    real = sqlite3.connect

    def tracking(*a, **k):
        c = real(*a, factory=Tracked, **k)
        opened.append(c)
        return c

    client, _ = seeded
    monkeypatch.setattr(sqlite3, "connect", tracking)
    for url in ("/triage", "/runs", "/runs/1", "/research", "/egress", "/evidence/1",
                "/runs/9999"):
        client.get(url)
    assert len(opened) >= 7
    assert all(c.closed for c in opened), \
        f"{sum(not c.closed for c in opened)} of {len(opened)} connections left open"


# ============================================================ honest counts

def test_the_suppressed_card_opens_every_non_live_occurrence(seeded):
    """REGRESSION. The card linked to `?stage=&action=kill`, which rendered nothing,
    beneath a comment saying every card was a link to its set."""
    client, con = seeded
    page = client.get("/runs/1").text
    assert "?stage=&amp;action=kill" not in page
    assert "/runs/1?suppressed=all" in page
    summary = q.run_summary(con, 1)
    rows = q.not_live(con, 1)
    assert len(rows) == summary["total"] - summary["live"] > 0
    live = {r["id"] for r in con.execute("SELECT id FROM live_occurrences")}
    assert not {r["occurrence_id"] for r in rows} & live
    assert {r["action"] for r in rows} <= {"kill", "defer", "merge"}
    r = client.get("/runs/1?suppressed=all")
    assert r.status_code == 200 and "tests/test_a.py" in r.text


def test_the_per_run_egress_table_states_what_it_shows(seeded):
    client, con = seeded
    for i in range(15):
        con.execute("INSERT INTO egress (run_id,stage,destination,bytes_out) "
                    "VALUES (1,'clone','github.com',?)", (i,))
    con.commit()
    page = client.get("/runs/1").text
    assert "12 of the 15" in page


def test_capped_research_lists_state_their_denominator(seeded):
    client, con = seeded
    con.execute("INSERT INTO research_runs (id,run_id,status,models,lenses,profile) "
                "VALUES (7,1,'done','[\"a:1b\"]','[]','{}')")
    for i in range(30):
        con.execute("INSERT INTO research_units (research_id,subsystem,weight,lens,"
                    "model,phase,status) VALUES (7,?,1.0,'x','a:1b','hunt','done')",
                    (f"s{i}",))
    for i in range(65):
        con.execute("INSERT INTO research_findings (research_id,lens,model,family,"
                    "subsystem,file,title,severity,quote,quote_verified,reasoning,"
                    "attacker_control) VALUES (7,'x','a:1b','a','s','f.py','t','low',"
                    "'q',0,'r','a')")
    con.commit()
    page = client.get("/research/7").text
    assert "showing 25 of 30 units" in page
    assert "showing 60 of 65" in page


def test_the_header_counter_does_not_load_the_ledger(seeded, monkeypatch):
    """The header on every page loaded the whole egress ledger to print two totals."""
    client, _ = seeded
    calls = []
    monkeypatch.setattr(q, "egress_ledger",
                        lambda *a, **k: calls.append(a) or {"rows": []})
    assert client.get("/triage").status_code == 200
    assert client.get("/runs").status_code == 200
    assert not calls
