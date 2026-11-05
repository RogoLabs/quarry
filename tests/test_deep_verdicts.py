"""IMPROVEMENT-PLAN item 20, second half: a human verdict on a deep survivor, and the
next deep run reading it.

Run 1's two survivors read as intended behaviour, but only in a Markdown file. Here the
verdict is a row, a later run on the same target matches its findings against it, and a
match on `intended` reaches the refuter as context and the survivor list as "previously
judged intended". Never as a silent drop: the finding is still stored and refuted.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quarry import db                                        # noqa: E402
from quarry.research import ensemble as E                    # noqa: E402
from quarry.research import runner, verdicts                 # noqa: E402
from test_deep_intent import EXPRESS                         # noqa: E402

NOTE = "optionallyValidateUser is deliberate: anonymous callers get a redacted record"
MW_QUOTE = "mw.rateLimiter,\n  mw.optionallyValidateUser,"
FILE = "src/controller/cve-id.controller/index.js"


@pytest.fixture
def env(tmp_path):
    src = tmp_path / "vol" / "src"
    (src / Path(FILE).parent).mkdir(parents=True)
    # Two routes that share the middleware pair: a verdict on one must not cover both.
    text = EXPRESS + ("\nrouter.get('/cve-id/:id/history',\n  mw.rateLimiter,\n"
                      "  mw.optionallyValidateUser,\n  controller.CVEID_HISTORY\n)\n")
    (src / FILE).write_text(text)
    c = db.init(tmp_path / "t.db")
    for run_id, target in ((1, "o/r"), (2, "o/r"), (3, "other/x")):
        c.execute("INSERT INTO runs (id,target,clone_url,status) VALUES (?,?,'x','done')",
                  (run_id, target))
        c.execute("INSERT INTO research_runs (id,run_id,status,models) VALUES (?,?,"
                  "'running','[]')", (run_id, run_id))
    return c, src


def _finding(quote=MW_QUOTE, title="Unauthenticated users can read CVE IDs", line=None):
    return E.Finding(lens="broken-authz-idor", model="devstral:24b", title=title,
                     file=FILE, quote=quote, severity="medium", reasoning="r",
                     attacker_control="a GET without a token", why_it_might_be_wrong="w",
                     line=line, quote_verified=True)


def _persist(con, src, rid, f):
    runner._persist(con, rid, rid, {"subsystem": "src/controller"}, [f], src)
    return con.execute("SELECT * FROM research_findings WHERE research_id=? "
                       "ORDER BY id DESC LIMIT 1", (rid,)).fetchone()


# ---------------------------------------------------------------- recording


def test_a_verdict_is_checked_and_appended_never_overwritten(env):
    con, src = env
    rf = _persist(con, src, 1, _finding())
    with pytest.raises(verdicts.VerdictError):
        verdicts.record(con, rf["id"], "fine", NOTE)
    with pytest.raises(verdicts.VerdictError):
        verdicts.record(con, rf["id"], "intended", "   ")
    with pytest.raises(verdicts.VerdictError):
        verdicts.record(con, 999, "intended", NOTE)
    first = verdicts.record(con, rf["id"], "Unclear", "need to read the controller")
    second = verdicts.record(con, rf["id"], "intended", NOTE, actor="jerry")
    assert second > first
    rows = con.execute("SELECT verdict FROM deep_verdicts ORDER BY id").fetchall()
    assert [r[0] for r in rows] == ["unclear", "intended"]          # both kept
    latest = verdicts.latest(con, rf["id"])
    assert latest["verdict"] == "intended" and latest["actor"] == "jerry"
    assert latest["created_at"]                                    # timestamped


def test_persist_records_the_enclosing_symbol(env):
    con, src = env
    rf = _persist(con, src, 1, _finding())
    assert rf["symbol"] == "GET /cve-id/:id"
    raw = json.loads(con.execute("SELECT raw_result FROM occurrences WHERE id=?",
                                 (rf["occurrence_id"],)).fetchone()[0])
    assert raw["symbol"] == "GET /cve-id/:id" and "prior_human_verdict" not in raw


# ---------------------------------------------------------------- matching rules


def test_quotes_overlap_needs_a_meaningful_span():
    assert verdicts.quotes_overlap("mw.optionallyValidateUser,", MW_QUOTE)
    assert verdicts.quotes_overlap("  mw.rateLimiter,   mw.optionallyValidateUser, ",
                                   MW_QUOTE)
    assert not verdicts.quotes_overlap("mw.rateLimiter", MW_QUOTE)     # under 16 chars
    assert not verdicts.quotes_overlap("", MW_QUOTE)
    assert not verdicts.quotes_overlap("res.status(200).json(x)", MW_QUOTE)


def test_match_prefers_the_newest_and_respects_a_differing_symbol():
    old = {"verdict_id": 1, "quote": MW_QUOTE, "symbol": "GET /cve-id/:id"}
    new = {"verdict_id": 2, "quote": "something else entirely here", "symbol": "GET /x"}
    hit = verdicts.match([new, old], quote="mw.optionallyValidateUser,",
                         symbol="GET /cve-id/:id")
    assert hit[0]["verdict_id"] == 1 and "symbol" in hit[1]
    assert verdicts.match([new], quote="something else entirely here",
                          symbol=None)[1] == "overlapping quote"
    # Same quote, but both symbols are known and differ: different code, no match.
    assert verdicts.match([old], quote=MW_QUOTE, symbol="GET /cve-id/:id/history") is None
    # An old row from before v9 has no symbol, so the quote alone decides.
    legacy = {**old, "symbol": None}
    assert verdicts.match([legacy], quote=MW_QUOTE, symbol="GET /cve-id/:id/history")


# ---------------------------------------------------------------- the next run


def _call_recorder(monkeypatch):
    prompts: list[str] = []

    def fake_call(model, prompt, schema, *, num_ctx=0, num_predict=0):
        prompts.append(prompt)
        return json.dumps({"verdict": "survives", "reason": "could not kill it"}), {}

    monkeypatch.setattr(E, "call", fake_call)
    return prompts


class _Sub:
    def render(self, tag: str = "") -> str:
        return f"===== {tag} FILE: x =====\nconst x = 1\n"


def test_the_next_run_matches_shows_the_refuter_and_lists_it_apart(env, monkeypatch):
    con, src = env
    first = _persist(con, src, 1, _finding())
    vid = verdicts.record(con, first["id"], "intended", NOTE)

    # Run 2 quotes one line of the same route, and separately the same middleware pair
    # in the route below it, which no human has judged.
    same = _persist(con, src, 2, _finding(quote="mw.optionallyValidateUser,", line=14))
    other = _persist(con, src, 2, _finding(title="History is public too", line=40))
    assert same["prior_verdict_id"] == vid and "symbol" in same["prior_match"]
    assert other["symbol"] == "GET /cve-id/:id/history" and other["prior_verdict_id"] is None
    raw = json.loads(con.execute("SELECT raw_result FROM occurrences WHERE id=?",
                                 (same["occurrence_id"],)).fetchone()[0])
    assert raw["prior_human_verdict"]["verdict"] == "intended"

    prompts = _call_recorder(monkeypatch)
    runner._refute_pass(con, 2, src, {"src/controller": _Sub()},
                        ["devstral:24b", "qwen3.6:27b"], None, lambda *_: None)
    with_prior = [p for p in prompts if "PRIOR HUMAN VERDICT" in p]
    assert len(with_prior) == 1 and NOTE in with_prior[0]
    assert "History is public too" in "".join(p for p in prompts
                                              if "PRIOR HUMAN VERDICT" not in p)

    # Both survived; the one a human already called intended is not presented as new.
    rows = {r["id"]: r for r in verdicts.survivors(con, 2)}
    assert rows[same["id"]]["prior_verdict"] == "intended"
    assert rows[other["id"]]["prior_verdict"] is None
    # Never dropped: it is still an occurrence the funnel and dashboard can see.
    assert con.execute("SELECT COUNT(*) FROM occurrences WHERE id=?",
                       (same["occurrence_id"],)).fetchone()[0] == 1


def test_a_verdict_does_not_cross_targets_and_a_changed_mind_wins(env, monkeypatch):
    con, src = env
    first = _persist(con, src, 1, _finding())
    verdicts.record(con, first["id"], "intended", NOTE)
    elsewhere = _persist(con, src, 3, _finding())
    assert elsewhere["prior_verdict_id"] is None

    # The human changes their mind; the newest verdict is the one a later run matches,
    # and only `intended` reaches the refuter as context.
    real = verdicts.record(con, first["id"], "real", "the redaction misses owning_cna")
    again = _persist(con, src, 2, _finding())
    assert again["prior_verdict_id"] == real
    prompts = _call_recorder(monkeypatch)
    runner._refute_pass(con, 2, src, {"src/controller": _Sub()},
                        ["devstral:24b", "qwen3.6:27b"], None, lambda *_: None)
    assert prompts and not any("PRIOR HUMAN VERDICT" in p for p in prompts)
    assert verdicts.survivors(con, 2)[0]["prior_verdict"] == "real"


def test_execute_counts_survivors_already_judged_intended(env, monkeypatch):
    con, src = env
    first = _persist(con, src, 1, _finding())
    verdicts.record(con, first["id"], "intended", NOTE)
    con.execute("UPDATE research_runs SET models=? WHERE id=2",
                (json.dumps(["devstral:24b", "qwen3.6:27b"]),))
    con.execute("INSERT INTO research_units (research_id, subsystem, lens, model) "
                "VALUES (2, '(whole repository)', 'broken-authz-idor', 'devstral:24b')")

    def fake_call(model, prompt, schema, *, num_ctx=0, num_predict=0):
        if "THE CLAIM" in prompt:
            return json.dumps({"verdict": "survives", "reason": "true as stated"}), {}
        return json.dumps({"findings": [{
            "title": "Anonymous read", "file": FILE, "quote": MW_QUOTE,
            "severity": "medium", "reasoning": "r", "attacker_control": "a",
            "why_it_might_be_wrong": "w"}]}), {}

    monkeypatch.setattr(E, "call", fake_call)
    monkeypatch.setattr(E, "model_provenance", lambda models: {})
    stats = runner.execute(con, 2, src, progress=lambda *_: None)
    assert stats["findings"] == 1
    assert stats["prior_intended"] == 1 and stats["prior_intended_survived"] == 1


# ---------------------------------------------------------------- CLI


def test_cli_records_and_lists_verdicts(tmp_path, monkeypatch):
    from typer.testing import CliRunner
    from quarry import cli, config
    monkeypatch.setenv("QUARRY_HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    con = db.init(config.paths().db)
    src = tmp_path / "vol" / "src"
    (src / Path(FILE).parent).mkdir(parents=True)
    (src / FILE).write_text(EXPRESS)
    for run_id in (1, 2):
        con.execute("INSERT INTO runs (id,target,clone_url,status) VALUES (?,'o/r','x',"
                    "'done')", (run_id,))
        con.execute("INSERT INTO research_runs (id,run_id,status,models) VALUES (?,?,"
                    "'done','[]')", (run_id, run_id))
    first = _persist(con, src, 1, _finding())
    con.execute("UPDATE research_findings SET n_survived=1")
    con.commit()

    r = CliRunner().invoke(cli.app, ["deep-verdict", str(first["id"]), "maybe",
                                     "--note", "x"])
    assert r.exit_code == 1 and "intended, real, unclear" in r.output
    r = CliRunner().invoke(cli.app, ["deep-verdict", str(first["id"]), "intended",
                                     "--note", NOTE])
    assert r.exit_code == 0, r.output
    assert "intended" in r.output

    second = _persist(con, src, 2, _finding())
    con.execute("UPDATE research_findings SET n_survived=1 WHERE id=?", (second["id"],))
    con.commit()
    r = CliRunner().invoke(cli.app, ["deep-survivors", "2"], env={"COLUMNS": "300"})
    assert r.exit_code == 0, r.output
    assert "previously judged intended" in r.output and NOTE in r.output
    assert "0 new" in r.output
    r = CliRunner().invoke(cli.app, ["deep-survivors", "1"], env={"COLUMNS": "300"})
    assert "1 new" in r.output and f"#{first['id']} intended" in r.output
