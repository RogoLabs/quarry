"""IMPROVEMENT-PLAN item 21: a fixed replay so a Layer 2 change can be measured.

The scoring is pure and tested here without a model. One end-to-end test drives the
real runner with E.call replaced, so the plumbing from hunt to score is covered too.
"""
from __future__ import annotations

import copy
import json
import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quarry.research import ensemble as E                    # noqa: E402
from quarry.research import replay                           # noqa: E402

CORPUS = replay.load()


def test_the_committed_corpus_passes_preflight():
    assert replay.preflight(CORPUS) == []
    assert len(CORPUS.repos) == 2 and len(CORPUS.plants) == 7
    assert {p.lens for p in CORPUS.plants} <= set(CORPUS.lenses)
    assert sum(p.kind == "guard-deletion" for p in CORPUS.plants) == 3


@pytest.fixture
def corpus(tmp_path):
    root = tmp_path / "corpus"
    shutil.copytree(replay.DEFAULT_CORPUS, root)
    return root


def _edit(path: Path, old: str, new: str) -> None:
    text = path.read_text()
    assert old in text
    path.write_text(text.replace(old, new))


def test_preflight_catches_a_broken_plant(corpus):
    # Put the deleted guard back: the plant is gone, and preflight must say so.
    _edit(corpus / "ticket_api" / "routes" / "admin.js",
          "auth.requireUser, admin.setRole", "auth.requireUser, auth.requireAdmin, "
          "admin.setRole")
    # An anchor that no longer matches the source.
    _edit(corpus / "notes_app" / "notes" / "files.py",
          "path = os.path.join(_user_dir(), name)", "path = os.path.join(_user_dir(), n)")
    # The answer leaking into a repository.
    (corpus / "notes_app" / "NOTES.md").write_text("The planted bug is in admin.py\n")
    problems = replay.preflight(replay.load(corpus))
    joined = "\n".join(problems)
    assert "T2: the planted route still declares auth.requireAdmin" in joined
    assert "N3: anchor not in notes/files.py" in joined
    assert "mentions 'plant'" in joined


def test_preflight_wants_a_sibling_population(corpus):
    p = corpus / "notes_app" / "notes" / "admin.py"
    text = p.read_text().replace("@login_required\n@admin_required\ndef disable_user",
                                 "@login_required\ndef disable_user")
    text = text.replace("@login_required\n@admin_required\ndef promote_user",
                        "@login_required\ndef promote_user")
    p.write_text(text)
    assert any("N1: 1 sibling(s) declare admin_required" in x
               for x in replay.preflight(replay.load(corpus)))


FILES = {"notes_app": {"notes/views.py", "notes/admin.py", "notes/files.py", "wsgi.py"},
         "ticket_api": {"routes/tickets.js", "controllers/tickets.js", "routes/admin.js",
                        "controllers/admin.js"}}


def _f(**kw):
    base = {"repo": "notes_app", "id": 1, "model": "m", "lens": "broken-authz-idor",
            "file": "notes/views.py", "quote": "", "quote_verified": 1, "symbol": None,
            "title": "", "reasoning": "", "n_survived": 0, "n_refuted": 1}
    return {**base, **kw}


def _plant(pid):
    return next(p for p in CORPUS.plants if p.id == pid)


def test_match_by_symbol_anchor_and_mention():
    n2, n4, t1 = _plant("N2"), _plant("N4"), _plant("T1")
    assert replay.match(n2, _f(symbol="view_note"), FILES["notes_app"]) == "symbol"
    assert replay.match(n4, _f(quote="def search_notes():\n    q = request.args.get"),
                        FILES["notes_app"]) == "anchor"
    hit = _f(repo="ticket_api", file="routes/tickets.js",
             symbol="GET /tickets/:id", title="History endpoint has no auth",
             reasoning="the /history route skips requireUser")
    assert replay.match(t1, hit, FILES["ticket_api"]) == "mention"
    # The model named the file by its basename; one such file, so it stands in.
    assert replay.match(n2, _f(file="views.py", symbol="view_note"),
                        FILES["notes_app"]) == "symbol"


def test_an_unverified_or_misplaced_claim_never_finds_a_plant():
    n2 = _plant("N2")
    assert replay.match(n2, _f(symbol="view_note", quote_verified=0),
                        FILES["notes_app"]) is None
    assert replay.match(n2, _f(file="notes/admin.py", symbol="view_note"),
                        FILES["notes_app"]) is None
    assert replay.match(n2, _f(repo="ticket_api", symbol="view_note"),
                        FILES["notes_app"]) is None
    assert replay.match(n2, _f(symbol="edit_note", title="edit_note is fine"),
                        FILES["notes_app"]) is None


def test_score_states_every_denominator():
    findings = [
        _f(id=1, symbol="view_note", n_survived=1, n_refuted=0),            # N2, kept
        _f(id=2, file="notes/admin.py", symbol="reset_password"),           # N1, refuted
        _f(id=3, file="notes/views.py", quote="nothing like it", quote_verified=0),
        _f(id=4, file="notes/views.py", symbol="list_notes", n_survived=1),  # off-plant
        _f(id=5, repo="ticket_api", file="controllers/admin.js", symbol="setRole",
           n_survived=1),                                                   # T2, kept
    ]
    s = replay.score(CORPUS, findings, FILES)
    assert s["plants"] == 7
    assert s["missed_at_hunt"] == {"n": 4, "of": 7, "ids": ["N3", "N4", "T1", "T3"]}
    assert s["missed_after_refute"]["n"] == 5 and "N1" in s["missed_after_refute"]["ids"]
    assert s["unsupported_claims"] == {"n": 1, "of": 5}
    assert s["survivors"] == {"n": 3, "of": 5}
    assert s["verified_claims_on_no_plant"] == {"n": 1, "of": 4}
    assert s["per_repo"]["notes_app"] == {"claims": 4, "unsupported": 1, "survivors": 2,
                                          "plants": 4, "found_at_hunt": 2,
                                          "found_after_refute": 1}
    assert s["per_plant"]["N1"]["hits"][0]["via"] == "symbol"


def _result(missed_hunt=2, missed_ref=4, unsupported=(3, 20), wall=600.0, **cfg):
    base = {"models": ["a:1", "b:2"], "model_digests": {"a:1": "x", "b:2": "y"},
            "ollama": "0.1", "budget": {"num_ctx": 1}, "sampling": {"seed": 42},
            "lenses": ["l"], "corpus_sha": "c", "quarry_commit": "abc",
            "layer2_sha": "s1", "route_intent": False, "quarry_dirty": False}
    return {"config": {**base, **cfg}, "wall_seconds": wall,
            "score": {"claims": unsupported[1],
                      "missed_at_hunt": {"n": missed_hunt, "of": 7, "ids": []},
                      "missed_after_refute": {"n": missed_ref, "of": 7, "ids": []},
                      "unsupported_claims": {"n": unsupported[0], "of": unsupported[1]}}}


def test_compare_calls_a_tie_a_tie_and_ignores_wall_time():
    a = _result()
    b = _result(wall=900.0, layer2_sha="s2", route_intent=True)
    d = replay.compare(a, b)
    assert d["verdict"] == "tie"
    assert set(d["what_changed"]) == {"layer2_sha", "route_intent"}


def test_compare_better_worse_and_mixed():
    a = _result()
    assert replay.compare(a, _result(missed_ref=3))["verdict"] == "better"
    assert replay.compare(a, _result(unsupported=(6, 20)))["verdict"] == "worse"
    assert replay.compare(a, _result(missed_hunt=1, unsupported=(6, 20)))[
        "verdict"] == "mixed"
    # The rate, not the count: twice the claims with twice the unsupported is no change.
    assert replay.compare(a, _result(unsupported=(6, 40)))["verdict"] == "tie"


def test_compare_refuses_when_a_fixed_thing_moved():
    a = _result()
    b = _result(model_digests={"a:1": "x", "b:2": "CHANGED"})
    d = replay.compare(a, b)
    assert d["verdict"] == "not comparable" and "model_digests" in d["fixed_differs"]


def test_run_drives_the_real_runner_and_scores_it(tmp_path, monkeypatch):
    """Two models of different families; the hunt 'finds' N2 with a real quote, makes
    one unsupported claim, and the refuter defends everything."""
    def fake_call(model, prompt, schema, *, num_ctx=0, num_predict=0):
        if "THE CLAIM" in prompt:
            return json.dumps({"verdict": "survives", "reason": "true"}), {}
        if "YOUR LENS: broken-authz-idor" in prompt and "notes/views.py" in prompt \
                and model == "qwen3-coder:30b":
            return json.dumps({"findings": [
                {"title": "Any user reads any note", "file": "notes/views.py",
                 "quote": "def view_note(note_id):\n    note = get_db().execute(",
                 "severity": "high", "reasoning": "no owner check",
                 "attacker_control": "note_id", "why_it_might_be_wrong": "w"},
                {"title": "Invented", "file": "notes/views.py",
                 "quote": "eval(request.args['code'])", "severity": "high",
                 "reasoning": "r", "attacker_control": "a",
                 "why_it_might_be_wrong": "w"}]}), {}
        return json.dumps({"findings": []}), {}

    monkeypatch.setattr(E, "call", fake_call)
    monkeypatch.setattr(E, "model_provenance",
                        lambda models: {"ollama": "test", "models": {m: "d" for m in models}})
    res = replay.run(CORPUS, ["qwen3-coder:30b", "devstral:24b"], workdir=tmp_path / "w",
                     progress=lambda *_: None)
    s = res["score"]
    assert s["missed_at_hunt"]["n"] == 6 and "N2" not in s["missed_at_hunt"]["ids"]
    assert s["missed_after_refute"]["n"] == 6
    assert s["unsupported_claims"] == {"n": 1, "of": 2}
    assert res["complete"] and res["config"]["route_intent"] is True
    assert res["repos"]["notes_app"]["lenses"] == ["broken-authz-idor", "injection",
                                                   "filesystem-and-path"]
    assert res["repos"]["ticket_api"]["lenses"] == ["broken-authz-idor"]
    assert res["repos"]["notes_app"]["units"] == 6
    assert res["config"]["budget"]["num_ctx"] == 65536
    assert res["config"]["models"] == ["qwen3-coder:30b", "devstral:24b"]
    # The answer key never reaches the copy a model reads.
    assert not list((tmp_path / "w").rglob("plants.json"))
    assert (tmp_path / "w" / "replay.db").is_file()
    json.dumps(res, default=str)                       # the CLI writes it as JSON


def test_run_refuses_one_family(tmp_path):
    with pytest.raises(ValueError, match="two families"):
        replay.run(CORPUS, ["qwen3-coder:30b", "qwen3.6:27b"], workdir=tmp_path)


def test_cli_compare_prints_the_verdict(tmp_path):
    from typer.testing import CliRunner
    from quarry import cli
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    a.write_text(json.dumps(_result()))
    b.write_text(json.dumps(_result(route_intent=True, wall=1.0)))
    r = CliRunner().invoke(cli.app, ["deep-replay-compare", str(a), str(b)],
                           env={"COLUMNS": "200"})
    assert r.exit_code == 0, r.output
    assert "tie" in r.output and "route_intent" in r.output
    c = copy.deepcopy(_result())
    c["config"]["corpus_sha"] = "other"
    b.write_text(json.dumps(c))
    r = CliRunner().invoke(cli.app, ["deep-replay-compare", str(a), str(b)],
                           env={"COLUMNS": "200"})
    assert "not comparable" in r.output and "corpus_sha" in r.output
