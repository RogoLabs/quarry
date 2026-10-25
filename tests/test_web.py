"""UI tests.

The dashboard is the funnel's last stage, so its failures look like clean repos.
These assert the two things the design actually promises: the triage unit is the
producer, and every suppression is visible and reversible.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# fastapi is imported hard, not skipped over. It is a declared runtime dependency
# (pyproject.toml), so a missing install is a broken environment rather than an
# optional extra — and skipping meant `pytest` reported "1 skipped", a green run,
# and zero web coverage.
from fastapi.testclient import TestClient          # noqa: E402

from quarry import db, funnel                   # noqa: E402
from quarry.migrations import migrate           # noqa: E402
from quarry.web import queries as q             # noqa: E402

from test_funnel import add                        # noqa: E402


@pytest.fixture
def seeded(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("QUARRY_HOME", str(home))
    from quarry import config
    paths = config.paths()
    con = db.init(paths.db)
    migrate(con)
    con.execute("INSERT INTO runs (id,target,clone_url,git_sha,status,license_spdx,license_osi) "
                "VALUES (1,'o/r','https://x','abc123','done','MIT',1)")
    # a noisy rule, a corroborated pair, and something the funnel will kill
    for i in range(6):
        add(con, "bandit", "B101", f"src/mod{i}.py", 10 + i)
    add(con, "bandit", "B113", "src/net.py", 42)
    add(con, "opengrep", "python.requests.best-practice.use-timeout", "src/net.py", 42)
    add(con, "bandit", "B101", "tests/test_a.py", 3)
    funnel.run(con, 1)
    from quarry.web.app import create_app
    # The app refuses any Host that is not loopback (DNS rebinding), so the client
    # must present one; TestClient's default "testserver" is exactly what it rejects.
    return TestClient(create_app(), base_url=ORIGIN), con


#: What a browser on the dashboard sends: the served origin.
ORIGIN = "http://127.0.0.1:8099"


def _post(client, url, data=None, **kw):
    """POST the way the dashboard's own forms do: same Origin, form token included."""
    data = {**(data or {}), "csrf": client.app.state.csrf_token}
    headers = {"Origin": ORIGIN, **kw.pop("headers", {})}
    kw.setdefault("follow_redirects", False)
    return client.post(url, data=data, headers=headers, **kw)


def test_triage_renders_and_groups_by_producer(seeded):
    client, con = seeded
    r = client.get("/triage")
    assert r.status_code == 200
    assert "Producers" in r.text and "the unit of decision" in r.text
    # the band headers are the sort key, and severity is explicitly not
    assert "unmeasured" in r.text
    assert "never severity" in r.text


def test_producer_groups_collapse_findings_into_decisions(seeded):
    _, con = seeded
    groups = q.producer_groups(con, 1)
    live = con.execute("SELECT COUNT(*) c FROM live_occurrences WHERE run_id=1").fetchone()["c"]
    assert len(groups) < live, "grouping must reduce the number of decisions"
    b101 = next(g for g in groups if g.rule_id == "B101")
    assert b101.n_live == 6, "the test-path occurrence was killed; the six source ones remain"


def test_corroborated_producers_sort_above_solo_ones(seeded):
    _, con = seeded
    groups = q.producer_groups(con, 1)
    corroborated = [i for i, g in enumerate(groups) if g.corroborated]
    solo = [i for i, g in enumerate(groups) if not g.corroborated]
    assert corroborated and solo
    assert max(corroborated) < min(solo), "independent agreement ranks first"


def test_dismiss_is_reversible_and_deletes_nothing(seeded):
    client, con = seeded
    live = lambda: con.execute(              # noqa: E731
        "SELECT COUNT(*) c FROM live_occurrences WHERE run_id=1").fetchone()["c"]
    total = con.execute("SELECT COUNT(*) c FROM occurrences").fetchone()["c"]
    before = live()

    r = _post(client, "/producers/bandit:B101/dismiss",
                    data={"run_id": 1, "scope": "corpus", "note": "style, not security"},
                    follow_redirects=False)
    assert r.status_code == 303
    assert live() == before - 6

    row = con.execute("SELECT enabled, dismissed_note FROM producers "
                      "WHERE id='bandit:B101'").fetchone()
    assert row["enabled"] == 0, "dismissal disables, never deletes"
    assert row["dismissed_note"] == "style, not security"
    assert con.execute("SELECT COUNT(*) c FROM occurrences").fetchone()["c"] == total

    events = con.execute("SELECT COUNT(*) c, MIN(actor) a FROM funnel_events "
                         "WHERE stage='operator' AND action='kill' "
                         "AND occurrence_id IS NOT NULL").fetchone()
    assert events["c"] == 6 and events["a"] == "operator"
    # plus exactly one producer-level row: the record of the corpus-wide disable
    assert con.execute("SELECT COUNT(*) c FROM funnel_events WHERE occurrence_id IS NULL "
                       "AND producer_id='bandit:B101' AND action='kill'"
                       ).fetchone()["c"] == 1

    _post(client, "/producers/bandit:B101/restore", data={"run_id": 1}, follow_redirects=False)
    assert live() == before, "restore must bring back exactly what the operator killed"


def test_restore_does_not_override_the_deterministic_funnel(seeded):
    """The operator withdrawing their own dismissal must not silently revive findings
    the funnel killed for unrelated reasons — a test path here."""
    client, con = seeded
    killed_by_funnel = con.execute(
        """SELECT o.id FROM occurrences o
           JOIN funnel_events e ON e.occurrence_id = o.id
           WHERE e.stage='path-class' AND e.action='kill'""").fetchone()["id"]

    _post(client, "/producers/bandit:B101/dismiss",
                data={"run_id": 1, "scope": "corpus"}, follow_redirects=False)
    _post(client, "/producers/bandit:B101/restore", data={"run_id": 1}, follow_redirects=False)

    alive = {r["id"] for r in con.execute("SELECT id FROM live_occurrences")}
    assert killed_by_funnel not in alive, \
        "a test-path kill must survive the operator restoring an unrelated dismissal"


def test_funnel_page_links_every_number_to_its_killed_set(seeded):
    client, con = seeded
    r = client.get("/runs/1")
    assert r.status_code == 200
    assert "every number is a link to the set it killed" in r.text
    assert "recall risk" in r.text, "heuristic stages must be flagged"
    # the link target must actually render the suppressed rows
    killed = client.get("/runs/1?stage=path-class")
    assert killed.status_code == 200
    assert "tests/test_a.py" in killed.text


def test_stages_that_suppressed_nothing_are_still_shown(seeded):
    """A stage that leaves no ledger rows would vanish from the table, and a stage
    you cannot see is a stage you cannot audit."""
    _, con = seeded
    stages = [s["stage"] for s in q.funnel_stages(con, 1)]
    assert "symbol-containment" in stages
    assert "exact-dedup" in stages
    assert len(stages) >= 11


def test_evidence_comes_from_the_blob_not_the_clone(seeded):
    """There is no clone in this test at all — the pane must still render."""
    client, con = seeded
    oid = con.execute("SELECT id FROM live_occurrences WHERE run_id=1 LIMIT 1").fetchone()["id"]
    r = client.get(f"/evidence/{oid}")
    assert r.status_code == 200
    assert "Provenance" in r.text


def test_provenance_explains_every_point_of_the_score(seeded):
    _, con = seeded
    oid = con.execute("""SELECT occurrence_id FROM occurrence_rank
                         WHERE run_id=1 ORDER BY score DESC LIMIT 1""").fetchone()["occurrence_id"]
    prov = q.provenance(con, oid)
    scored = [p for p in prov if p["score_delta"]]
    assert scored, "a ranked finding must be able to say why"
    total = sum(p["score_delta"] for p in prov)
    stored = con.execute("SELECT score FROM occurrence_rank WHERE occurrence_id=?",
                         (oid,)).fetchone()["score"]
    assert abs(total - stored) < 1e-6, "the rank must equal the sum of its explanations"


def test_runs_index_renders(seeded):
    client, _ = seeded
    r = client.get("/runs")
    assert r.status_code == 200 and "o/r" in r.text


def test_a_dead_worker_is_reported_as_dead_not_running(seeded, monkeypatch):
    """REGRESSION. The first deep run showed `running` indefinitely after its process
    was killed: `status` is only ever written by the worker, so it cannot report the
    worker dying. Liveness is now computed by the reader."""
    from quarry.web import queries as q
    row = {"status": "running", "pid": 999_999_999, "heartbeat": None,
           "done": 2, "units": 21, "errored": 0}
    status, why = q.live_status(row)
    assert status == "died" and "gone" in why


def test_heartbeat_age_is_computed_in_utc(seeded):
    """REGRESSION. SQLite's datetime('now') is UTC; comparing it against a naive local
    datetime.now() reported '-300m ago' on a UTC-5 machine."""
    import datetime as dt
    from quarry.web import queries as q
    hb = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=45)) \
        .replace(tzinfo=None).isoformat(sep=" ", timespec="seconds")
    status, why = q.live_status({"status": "running", "pid": 999_999_999,
                                 "heartbeat": hb})
    assert status == "died"
    assert "-" not in why.split("activity")[-1], f"negative age leaked: {why}"
    assert "45m" in why


def _utc_now(minutes: float = 0.0) -> str:
    """A heartbeat as SQLite's datetime('now') writes it, offset by `minutes`."""
    import datetime as dt
    return (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=minutes)) \
        .replace(tzinfo=None).isoformat(sep=" ", timespec="seconds")


def _spawn_sleeper(*argv: str):
    """A harmless child whose `ps` command line ends with `argv`. `-c` ignores the
    trailing arguments, which is what lets it pose as `quarry.cli deep 1`."""
    import subprocess
    import sys as _sys
    return subprocess.Popen([_sys.executable, "-c", "import time; time.sleep(60)", *argv])


@pytest.fixture
def worker():
    """A process that looks exactly like `python -m quarry.cli deep 1 ...`."""
    p = _spawn_sleeper("quarry.cli", "deep", "1", "--models", "a:1b,c:2d")
    yield p
    p.kill()
    p.wait()


@pytest.fixture
def bystander():
    """A live process that is NOT a quarry worker: what a recycled pid points at."""
    p = _spawn_sleeper()
    yield p
    p.kill()
    p.wait()


def test_a_live_worker_is_reported_as_running(worker):
    """The worker's argv and a heartbeat written after it started: both checks pass."""
    status, why = q.live_status({"status": "running", "pid": worker.pid, "run_id": 1,
                                 "heartbeat": _utc_now()})
    assert status == "running" and "alive" in why


def test_a_recycled_pid_is_not_reported_as_running(worker, bystander):
    """REGRESSION. A live pid was taken as proof of a live worker, but pids are
    recycled: after the worker dies its pid can be handed to any program.

    Two shapes. A non-quarry process holding the pid fails the argv check. A process
    that happens to look like a worker but started after the run's last heartbeat
    cannot be the process that wrote that heartbeat."""
    status, why = q.live_status({"status": "running", "pid": bystander.pid,
                                 "run_id": 1, "heartbeat": _utc_now()})
    assert status == "died" and "another program" in why

    status, why = q.live_status({"status": "running", "pid": worker.pid, "run_id": 1,
                                 "heartbeat": _utc_now(minutes=-60)})
    assert status == "died" and "reused" in why

    status, _ = q.live_status({"status": "running", "pid": worker.pid, "run_id": 2,
                               "heartbeat": _utc_now()})
    assert status == "died", "a deep review of another run is not this run's worker"


def test_an_unverifiable_worker_is_neither_running_nor_resumable(worker):
    """No heartbeat means the start-time check cannot run. That is not `running`
    (Stop would signal an unproven pid) and not resumable (it may still be alive)."""
    status, _ = q.live_status({"status": "running", "pid": worker.pid, "run_id": 1,
                               "heartbeat": None})
    assert status == "unverified"


def test_finished_runs_are_never_second_guessed(seeded):
    from quarry.web import queries as q
    for terminal in ("done", "stopped", "failed"):
        status, _ = q.live_status({"status": terminal, "pid": 999_999_999})
        assert status == terminal


# ===================================================================== gates
# Every assertion in the suite above is on rendered *prose*, which means a change
# that preserves the copy and destroys the layout passes all of them — precisely the
# change the design pass was. These are the structural gates.

ROUTES = ["/triage", "/runs", "/runs/1", "/research", "/egress", "/validation",
          "/advisories"]


def test_every_route_renders_and_extends_the_shell(seeded):
    client, _ = seeded
    for route in ROUTES:
        r = client.get(route)
        assert r.status_code == 200, f"{route} -> {r.status_code}"
        assert '<html lang="en">' in r.text, f"{route} does not extend base.html"
        assert "/static/app.css" in r.text, f"{route} does not load the stylesheet"


def test_no_page_carries_its_own_stylesheet(seeded):
    """The whole CSS refactor, as one assertion.

    Six per-template blocks held 13 selectors defined in more than one file, 10 of
    which had already silently diverged. This is what stops one growing back.
    """
    client, _ = seeded
    for route in ROUTES:
        assert "<style" not in client.get(route).text, f"{route} embeds a stylesheet"


def test_only_a_server_computed_datum_may_be_an_inline_style(seeded):
    """Inline styles outrank every @layer, so a stylesheet that tolerates them can be
    silently overridden. There were 85; the one permitted use is the bar's `--pct`."""
    import re as _re
    client, _ = seeded
    for route in ROUTES:
        for decl in _re.findall(r'style="([^"]*)"', client.get(route).text):
            assert decl.startswith("--pct:"), f"{route} has inline style {decl!r}"


def test_the_shell_never_asserts_its_own_header_height(seeded):
    """`calc(100vh - 46px)` was hand-copied into six files, one as an inline style
    attribute that a `.page` grep would miss."""
    client, _ = seeded
    for route in ROUTES:
        text = client.get(route).text
        assert "100vh" not in text and "46px" not in text, route


def test_the_evidence_fragment_is_styled_in_both_contexts(seeded):
    """The defect that made the stylesheet urgent.

    `_detail.html` renders as an include in /triage and as an htmx fragment in
    /runs/{id}'s #peek. Ten of its classes lived only in triage.html's own block, so
    the killed-set pane rendered source in proportional sans with
    `white-space: normal` — Python with its indentation collapsed, on the screen that
    exists to make the funnel auditable.
    """
    client, _ = seeded
    css = client.get("/static/app.css").text
    for cls in ("dhead", "code", "sec", "prov", "msg", "dtags", "loc", "ln", "hit"):
        assert f".{cls}" in css, f".{cls} is not in the shared stylesheet"
    assert "white-space:pre" in css.replace(" ", "")

    frag = client.get("/evidence/1", headers={"hx-request": "true"})
    assert frag.status_code == 200 and "codepane" in frag.text
    assert '<html lang="en">' in client.get("/evidence/1").text


def test_every_funnel_number_links_to_its_own_action(seeded):
    """`suppressed()` filtered `action IN ('kill','defer','merge')` while run.html
    emitted one identical href for all four columns, so a boost count opened
    "Suppressed at X — 0 shown" over an empty table. Two of eleven stages."""
    client, con = seeded
    assert "action=" in client.get("/runs/1").text, \
        "funnel cells do not scope their links by action"
    rows = con.execute(
        "SELECT DISTINCT stage, action FROM funnel_events WHERE run_id=1").fetchall()
    assert rows
    for row in rows:
        if row["action"] not in q.FUNNEL_ACTIONS:
            continue
        assert q.suppressed(con, 1, row["stage"], row["action"]), \
            f"{row['action']} at {row['stage']} resolves to nothing"
        r = client.get(f"/runs/1?stage={row['stage']}&action={row['action']}")
        assert r.status_code == 200
        assert q.ACTION_NOUN[row["action"]] in r.text, \
            "the heading does not name the action taken"


def test_boost_is_auditable(seeded):
    """Named separately because `boost` is the action that was excluded outright.

    The real funnel emits boosts, so this asserts against what it actually produced
    rather than against fabricated rows: for every stage that boosted anything, the
    set behind that number must be non-empty and must match its own count.
    """
    client, con = seeded
    boosts = con.execute(
        "SELECT stage, COUNT(*) n FROM funnel_events "
        "WHERE run_id=1 AND action='boost' GROUP BY stage").fetchall()
    assert boosts, "the fixture funnel produced no boosts to audit"
    for row in boosts:
        rows = q.suppressed(con, 1, row["stage"], "boost")
        assert len(rows) == row["n"]
        assert q.suppressed_total(con, 1, row["stage"], "boost") == row["n"]
        assert all(r["action"] == "boost" for r in rows), \
            "the action filter leaked other actions into the set"
        page = client.get(f"/runs/1?stage={row['stage']}&action=boost")
        assert "Boosted at" in page.text, "a boost is not a suppression"


def test_an_unknown_action_yields_nothing_rather_than_everything(seeded):
    """A filter that silently widens on bad input is worse than one that refuses."""
    _, con = seeded
    assert q.suppressed(con, 1, None, "nonsense") == []
    assert q.suppressed_total(con, 1, None, "nonsense") == 0


def test_restore_is_reachable_from_the_interface(seeded):
    """Thirty lines of careful, tested inverse logic that no template referenced. The
    UI said "Reversible — writes a ledger event, deletes nothing" and offered no way
    to reverse anything."""
    client, _ = seeded
    r = _post(client, "/producers/bandit:B101/dismiss",
                    data={"run_id": 1, "scope": "repo"}, follow_redirects=False)
    assert r.status_code == 303
    assert "undo=" in r.headers["location"], \
        "the redirect does not carry the undo affordance"
    assert "/restore" in client.get(r.headers["location"]).text, \
        "no restore control on the page after a dismissal"


def test_the_keyboard_contract_survives(seeded):
    """The handler walks these selectors. Renaming one silently disables the
    throughput mechanism, and there is no JS test runner here to catch it."""
    client, _ = seeded
    page = client.get("/triage").text
    for token in (".orow", ".prow", "form.actions", 'value="repo"',
                  'value="corpus"', "scrollIntoView"):
        assert token in page, f"missing from the triage page: {token}"


def test_modifier_chords_cannot_fire_a_disposition(seeded):
    """Cmd-D — the universal bookmark chord — arrived as key 'd' with metaKey set,
    fell through a guard that checked only input/textarea, and dismissed a producer
    while the bookmark dialog covered the redirect."""
    client, _ = seeded
    page = client.get("/triage").text
    assert "e.metaKey || e.ctrlKey || e.altKey" in page
    assert "closest('input,textarea,select,button,[contenteditable]')" in page


def test_corpus_wide_dismissal_has_no_keybinding(seeded):
    """A slipped shift key must not change the blast radius from one run to every
    future run against every repository."""
    client, _ = seeded
    page = client.get("/triage").text
    assert "'D'" not in page and '"D"' not in page


def test_no_auto_refreshing_page_reload(seeded):
    """WCAG 2.2.1 is Level A: a content-set time limit needs a mechanism, not a
    notice. The old meta refresh reloaded a 160-line document ~1,440 times over an
    eight-hour run, resetting scroll and focus every twenty seconds."""
    client, _ = seeded
    for route in ROUTES:
        assert 'http-equiv="refresh"' not in client.get(route).text, route


def test_tables_are_machine_readable(seeded):
    """The funnel was a div grid of spans, so a screen reader read eight rows of bare
    numbers with no column association — on the screen the product rests on."""
    client, _ = seeded
    page = client.get("/runs/1").text
    assert "<caption" in page
    assert 'scope="col"' in page and 'scope="row"' in page


def test_the_selected_row_exists_in_the_accessibility_tree(seeded):
    """Selection was a background tint at 1.22:1 and nothing else."""
    client, _ = seeded
    assert 'aria-current="true"' in client.get("/triage").text


def test_severity_is_always_labelled_a_claim_and_never_coloured(seeded):
    """Claimed severity predicts nothing here: critical 0/11, high 3%, medium 0/26."""
    client, _ = seeded
    page = client.get("/triage").text
    assert "claims" in page
    assert "pill inert" in page, "the severity chip must carry the inert role"


def test_the_egress_ledger_has_a_page_and_a_counter(seeded):
    """`bytes_out` was stored from the first migration and never rendered, and the
    per-run table was capped at twelve with no total and no "N more"."""
    client, _ = seeded
    r = client.get("/egress")
    assert r.status_code == 200 and "bytes out" in r.text
    for route in ROUTES:
        assert "/egress" in client.get(route).text, f"{route} has no egress counter"


def test_a_404_answers_404(seeded):
    client, _ = seeded
    r = client.get("/runs/9999")
    assert r.status_code == 404
    assert '<html lang="en">' in r.text, "errors must render a themed page"


# ---- truncation ------------------------------------------------------------
# `word-break:break-all` rendered the primary column's rule ids as broken mid-token
# fragments. These are the properties that replaced it.

from quarry.web.app import rule_id, tail_path   # noqa: E402


@pytest.mark.parametrize("text", [
    "javascript.express.security.audit.xss.mustache.var-in-href",
    "python.requests.best-practice.use-raise-for-status",
    "python.lang.security.audit.dynamic-urllib-use-detected",
    "dockerfile.best-practice.missing-no-install-recommends",
    "some-enormous-single-token-with-no-dots-at-all-whatsoever",
    "B113", "DS-0002", "", None,
])
def test_rule_id_never_exceeds_its_bound(text):
    """The bound is what keeps the CSS ellipsis a backstop rather than a second
    truncation — two ellipses in one string is worse than one."""
    assert len(rule_id(text)) <= 34


@pytest.mark.parametrize("text", [
    "javascript.express.security.audit.xss.mustache.var-in-href",
    "python.requests.best-practice.use-raise-for-status",
])
def test_rule_id_keeps_the_distinguishing_tail(text):
    """The tail names the specific rule, so it is the half that must survive. Truncating
    from the right — which is all CSS can do — drops exactly the informative part."""
    out = rule_id(text)
    assert out.endswith(text.rsplit(".", 1)[-1])
    assert out.startswith(text.split(".", 1)[0][:4])
    assert "…" in out


def test_rule_id_leaves_short_ids_alone():
    for short in ("B113", "DS-0002", "python.lang.security"):
        assert rule_id(short) == short


def test_rule_id_never_breaks_mid_token_when_dots_are_available():
    """The actual defect: `…audit.xss.must / ache.var-in-hre / f`."""
    out = rule_id("javascript.express.security.audit.xss.mustache.var-in-href")
    head, _, tail = out.partition("…")
    assert not head.endswith("."), "head should end on a segment, not a separator"
    assert tail == "var-in-href"


def test_tail_path_keeps_the_filename_and_line():
    out = tail_path("bin/lib/objects/abstract_daterange_object.py:120")
    assert len(out) <= 34
    assert out.endswith("abstract_daterange_object.py:120")
    assert out.startswith("…")
    assert tail_path("a.py:1") == "a.py:1"


# ---- clocks ----------------------------------------------------------------
# The database speaks two: SQLite's datetime('now') is UTC (started_at, heartbeat,
# created_at, updated_at) while cli.py writes research_runs.deadline from Python's
# datetime.now(), which is naive local. Enforcement is consistent — runner.py compares
# local to local — so this was purely a display defect, but a five-hour one with
# nothing on screen saying which column was which.

def test_utc_rows_are_rendered_in_local_time():
    """A UTC timestamp must not appear verbatim beside a local-time deadline."""
    import datetime as dt
    utc = "2026-08-24 15:36:42"
    got = q.local(utc)
    expect = (dt.datetime.strptime(utc, "%Y-%m-%d %H:%M:%S")
              .replace(tzinfo=dt.timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M"))
    assert got == expect


def test_naive_local_timestamps_pass_through_unconverted():
    """isoformat() writes a `T`; converting it again would double-shift the deadline."""
    assert q.local("2026-08-24T18:36:41") == "2026-08-24 18:36"
    assert q.local("2026-08-24T18:36:41", with_date=False) == "18:36"


def test_a_budget_reads_as_a_duration_not_a_timestamp():
    """The operator's decision is "let it finish or stop it"."""
    import datetime as dt
    soon = (dt.datetime.now() + dt.timedelta(hours=2, minutes=5)).isoformat(timespec="seconds")
    assert q.until(soon) in ("2h 04m left", "2h 05m left")
    past = (dt.datetime.now() - dt.timedelta(hours=1)).isoformat(timespec="seconds")
    assert q.until(past) == "deadline passed"
    assert q.until(None) == "no deadline"


def test_elapsed_reads_from_utc():
    import datetime as dt
    ago = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=43))
    assert q.elapsed(ago.strftime("%Y-%m-%d %H:%M:%S")) in ("42m", "43m")
    assert q.elapsed(None) == "—"


def test_clock_helpers_never_raise_on_bad_input():
    """These run on every row of every page."""
    for bad in (None, "", "not-a-date", "2026-13-45 99:99:99", 12345):
        q.local(bad); q.until(bad); q.elapsed(bad)


def test_no_template_renders_a_raw_timestamp(seeded):
    """The gate: every timestamp on screen goes through a clock filter."""
    import re
    from pathlib import Path as _P
    tpl = _P(q.__file__).resolve().parent / "templates"
    raw = []
    for f in tpl.glob("*.html"):
        for i, line in enumerate(f.read_text().splitlines(), 1):
            if re.search(r"\{\{\s*\w+\.(started_at|created_at|deadline|heartbeat|"
                         r"updated_at)\s*\}\}", line):
                raw.append(f"{f.name}:{i}")
    assert not raw, f"raw timestamps rendered at {raw}"


def test_in_flight_can_actually_show_a_unit_in_flight(seeded):
    """The section was renamed from "Recent units" to "In flight" while the runner
    only ever wrote pending/done/error — so it sorted on a status that never existed
    and the executing unit was indistinguishable from hundreds that had not started.

    runner.py now claims a unit before working it. This asserts the claim is visible
    and sorts first, because a heading that cannot be true is worse than a vague one.
    """
    client, con = seeded
    con.execute("INSERT INTO research_runs (id,run_id,status,models,lenses,profile) "
                "VALUES (9,1,'running','[\"a:1b\",\"c:2d\"]','[\"injection\"]','{}')")
    for st, sub in (("done", "src/a"), ("error", "src/b"),
                    ("running", "src/live"), ("pending", "src/c")):
        con.execute("INSERT INTO research_units (research_id,subsystem,weight,lens,"
                    "model,phase,status,seconds,n_findings) "
                    "VALUES (9,?,1.0,'injection','a:1b','hunt',?,1.0,0)", (sub, st))
    con.commit()

    order = [r["subsystem"] for r in con.execute(
        """SELECT subsystem FROM research_units WHERE research_id=9
           ORDER BY CASE status WHEN 'running' THEN 0 WHEN 'error' THEN 1
                                WHEN 'pending' THEN 2 ELSE 3 END, updated_at DESC""")]
    assert order[0] == "src/live", \
        "the unit actually executing must sort first — that is the whole point"

    page = client.get("/research/9").text
    assert "In flight" in page
    assert "src/live" in page
    assert "pill accent" in page, "a running unit needs its own visible state"


def test_a_claimed_unit_is_retried_after_a_crash(seeded):
    """Claiming a unit means a worker killed mid-unit leaves it in 'running'. If the
    resume query did not include that status, the one unit that never finished would be
    the one unit never retried — the same class of dishonesty as a status only the
    dying process could have written."""
    from pathlib import Path as _P
    src = (_P(q.__file__).resolve().parents[1] / "research" / "runner.py").read_text()
    assert "'pending','error','running'" in src, \
        "resume must reclaim units whose worker died holding them"


def test_a_zombie_worker_is_not_reported_as_running():
    """MEASURED. Research run 3's worker exited at 15:56; twenty-five minutes later the
    dashboard still read "running · pid 80566 alive" while `ps` showed `STAT Z`,
    `<defunct>`, and ollama had no model loaded.

    `kill -0` succeeds on a zombie — it keeps its PID entry until the parent reaps it —
    so existence is not liveness. Only STALL_SECONDS caught it, twenty-five minutes
    late, on the one screen whose job is to report exactly this. Same defect 5e7e14a
    closed one layer up.
    """
    import os
    import subprocess
    import sys

    # A real zombie: exits immediately, parent deliberately does not wait().
    child = subprocess.Popen([sys.executable, "-c", "raise SystemExit(0)"])
    try:
        for _ in range(200):                      # let it exit and become defunct
            state = subprocess.run(["ps", "-o", "stat=", "-p", str(child.pid)],
                                   capture_output=True, text=True).stdout.strip()
            if state.startswith("Z"):
                break
            os.sched_yield() if hasattr(os, "sched_yield") else None
        else:
            pytest.skip("could not produce a zombie on this platform")

        assert os.kill(child.pid, 0) is None, "precondition: kill -0 succeeds"
        assert q._pid_alive(child.pid) is False, \
            "a defunct process is not a running worker"

        row = {"pid": child.pid, "status": "running", "heartbeat": None,
               "finished_at": None, "deadline": None}
        state, why = q.live_status(row)
        assert state != "running", f"a dead worker reported {state!r}"
    finally:
        child.wait()


def test_a_live_pid_is_still_reported_as_alive():
    """The zombie check must not make every run look dead."""
    import os
    assert q._pid_alive(os.getpid()) is True
    assert q._pid_alive(999999) is False
    assert q._pid_alive(None) is False
    assert q._pid_alive(0) is False


def test_an_unhandled_exception_renders_a_page_that_says_what_broke(seeded):
    """You saw `Internal Server Error` — unstyled, unattributed, and identical
    whether the database was missing or a template called a filter that did not
    exist. Five routes returned exactly that while /triage worked, and the only way
    to learn why was to read uvicorn's stdout.

    The HTTPException handler never saw these; nothing handled them at all.
    """
    client, _ = seeded
    app = client.app

    @app.get("/__test_boom")
    def boom():
        raise RuntimeError("simulated failure")

    from fastapi.testclient import TestClient
    c = TestClient(app, raise_server_exceptions=False, base_url=ORIGIN)

    r = c.get("/__test_boom")
    assert r.status_code == 500
    assert '<html lang="en">' in r.text, "a 500 must still be a themed page"
    assert "RuntimeError" in r.text and "simulated failure" in r.text, \
        "the page must name what broke; the alternative is reading the server log"

    h = c.get("/__test_boom", headers={"hx-request": "true"})
    assert h.status_code == 500 and "simulated failure" in h.text, \
        "an htmx swap must not silently do nothing"
