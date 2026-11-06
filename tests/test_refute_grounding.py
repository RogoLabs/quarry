"""A refutation has to quote the code that defeats the claim, on the claim's path
(IMPROVEMENT-PLAN decision F).

MEASURED on the planted-bug replay, three runs: the refute pass killed all 46 claims,
every plant included, with no counter_quote on any of them, citing guards that exist only
in a sibling of the planted code. These tests pin the check that answers that: what
grounds a refutation (`research.grounding`), how an ungrounded one is counted, the one
retry the refute pass gives it, and what the funnel gate and the digest do with a claim
no refuter could rebut.

No model and no network: `E.call` is monkeypatched.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quarry import db, funnel                                 # noqa: E402
from quarry.disclosure import report                          # noqa: E402
from quarry.research import ensemble as E                     # noqa: E402
from quarry.research import grounding, runner, verdicts       # noqa: E402
from quarry.research.grounding import ground                  # noqa: E402

REPLAY = Path(__file__).resolve().parent / "fixtures" / "replay"
NOTES, TICKETS = REPLAY / "notes_app", REPLAY / "ticket_api"
DOWNLOAD = "path = os.path.join(_user_dir(), name)"
ROLE_ROUTE = "router.post('/users/:id/role', auth.requireUser, admin.setRole)"
HISTORY_ROUTE = "router.get('/tickets/:id/history', tickets.history)"


def _g(root, claim_file, claim_quote, counter_quote, counter_file=None, guard=None):
    """`guard` defaults to the whole counter_quote, so a case about the quote's place is
    not decided by the guard rules; the guard cases pass one."""
    return ground(root, claim_file=claim_file, claim_quote=claim_quote, claim_line=None,
                  counter_quote=counter_quote, counter_file=counter_file,
                  guard=counter_quote if guard is None else guard)


# ------------------------------------------------------------------ the replay's cases

@pytest.mark.parametrize("root, claim_file, claim_quote, counter, counter_file, guard, where", [
    # N3: `remove` calls secure_filename; the planted `download` does not.
    (NOTES, "notes/files.py", DOWNLOAD,
     "path = os.path.join(_user_dir(), secure_filename(name))", None,
     "secure_filename(name)", "remove"),
    # T2: every other admin route carries auth.requireAdmin; the planted one does not.
    (TICKETS, "routes/admin.js", ROLE_ROUTE,
     "auth.requireUser, auth.requireAdmin", None, "auth.requireAdmin", "GET /users"),
    # T1: the other ticket controllers call visibleTicket; `history` does not.
    (TICKETS, "routes/tickets.js", HISTORY_ROUTE,
     "const ticket = visibleTicket(req, res)", "controllers/tickets.js", "visibleTicket",
     "show"),
], ids=["N3-sibling-sanitiser", "T2-sibling-route-guard", "T1-sibling-controller-check"])
def test_a_guard_that_exists_only_in_a_sibling_does_not_ground(root, claim_file,
                                                             claim_quote, counter,
                                                             counter_file, guard, where):
    g = _g(root, claim_file, claim_quote, counter, counter_file, guard)
    assert not g.ok
    assert "sibling" in g.why and where in g.why


# MEASURED on the first replays after the counter_quote rule: the refuter quoted the
# claimed code itself, which is real and on the path, beside a guard that is not in it.
@pytest.mark.parametrize("root, claim_file, claim_quote, counter, guard", [
    (NOTES, "notes/files.py", DOWNLOAD,
     '@bp.route("/<path:name>", methods=["GET"])\n@login_required\ndef download(name):\n'
     '    path = os.path.join(_user_dir(), name)', "secure_filename"),
    (TICKETS, "routes/admin.js", ROLE_ROUTE, ROLE_ROUTE, "auth.requireAdmin"),
], ids=["download-head", "role-route"])
def test_quoting_the_claimed_code_back_does_not_ground_a_guard_absent_from_it(
        root, claim_file, claim_quote, counter, guard):
    g = _g(root, claim_file, claim_quote, counter, guard=guard)
    assert not g.ok and "is not in the counter_quote" in g.why


def test_a_quote_that_runs_from_the_claim_into_a_sibling_is_judged_by_the_guard_line():
    counter = ("    if not os.path.isfile(path):\n        abort(404)\n"
               "    return send_file(path)\n\n\n"
               '@bp.route("/<path:name>", methods=["DELETE"])\n@login_required\n'
               "def remove(name):\n"
               "    path = os.path.join(_user_dir(), secure_filename(name))")
    g = _g(NOTES, "notes/files.py", DOWNLOAD, counter, guard="secure_filename(name)")
    assert not g.ok and "remove" in g.why


@pytest.mark.parametrize("guard, why", [
    ("", "no guard"),
    ("auth", "under 6"),
    ("auth.requireAdmin", "is not in the counter_quote"),
])
def test_the_guard_is_required_and_must_be_in_the_quote(guard, why):
    g = _g(TICKETS, "routes/admin.js", ROLE_ROUTE, ROLE_ROUTE, guard=guard)
    assert not g.ok and why in g.why


def test_an_import_is_not_a_check():
    g = _g(NOTES, "notes/files.py", DOWNLOAD, "from werkzeug.utils import secure_filename",
           guard="secure_filename")
    assert not g.ok and "import" in g.why


def test_code_inside_the_claimed_definition_grounds():
    # `remove` really does call secure_filename: a refutation of a claim about it holds.
    g = _g(NOTES, "notes/files.py",
           "path = os.path.join(_user_dir(), secure_filename(name))",
           "os.path.join(_user_dir(), secure_filename(name))", guard="secure_filename(name)")
    assert g.ok and "remove" in g.why


def test_the_handler_a_route_registers_is_on_its_path():
    g = _g(TICKETS, "routes/tickets.js", HISTORY_ROUTE,
           "store.history.filter(e => e.ticketId === Number(req.params.id))",
           "controllers/tickets.js")
    assert g.ok and "history" in g.why


def test_a_helper_the_claimed_function_calls_is_on_its_path():
    g = _g(TICKETS, "controllers/tickets.js",
           "const ticket = visibleTicket(req, res)\n  if (ticket) res.json(ticket)",
           "if (!ticket || ticket.orgId !== req.user.orgId) {")
    assert g.ok and "visibleTicket" in g.why


@pytest.mark.parametrize("counter, why", [
    ("", "no counter_quote"),
    ("   ", "no counter_quote"),
    ("@login_required", "under 16"),
    # The planted route as the refuter imagined it: not in the file.
    ("router.post('/users/:id/role', auth.requireUser, auth.requireAdmin", "not found"),
])
def test_missing_short_or_invented_evidence_does_not_ground(counter, why):
    g = _g(TICKETS, "routes/admin.js", ROLE_ROUTE, counter)
    assert not g.ok and why in g.why


# ------------------------------------------------------------------ a small tree

JS = """const express = require('express')
const router = express.Router()
router.use(requireUser)

function check (id) {
  if (!Number.isInteger(id)) throw new Error('bad id')
}

function show (req, res) {
  const x = 1
  check(req.params.id)
  res.json(x)
}

function other (req, res) {
  if (!req.user.isAdmin) return res.status(403).end()
}
"""


@pytest.fixture
def src(tmp_path):
    root = tmp_path / "src"
    root.mkdir()
    (root / "a.js").write_text(JS)
    # A link out of the clone. Ingest destroys symlinks; a scanner could plant one later.
    (tmp_path / "outside.js").write_text("if (!Number.isInteger(id)) throw\n")
    os.symlink(tmp_path / "outside.js", root / "link.js")
    return root


@pytest.mark.parametrize("counter, ok, word", [
    ("check(req.params.id)", True, "show"),
    ("if (!Number.isInteger(id)) throw new Error('bad id')", True, "check"),
    ("router.use(requireUser)\n", True, "module level"),
    ("if (!req.user.isAdmin) return res.status(403).end()", False, "sibling"),
    ("const express = require('express')", False, "import"),
])
def test_the_path_rule_on_a_small_tree(src, counter, ok, word):
    g = _g(src, "a.js", "const x = 1\n  check(req.params.id)", counter)
    assert g.ok is ok and word in g.why


@pytest.mark.parametrize("counter_file", ["/etc/hosts", "../outside.js", "link.js"])
def test_counter_file_is_model_output_and_stays_in_the_clone(src, counter_file):
    g = _g(src, "a.js", "const x = 1", "if (!Number.isInteger(id)) throw", counter_file,
           guard="Number.isInteger(id)")
    assert not g.ok and "not a file in the repository" in g.why


def test_a_multi_line_counter_quote_is_located(src):
    assert grounding.occurrences(JS.splitlines(),
                                 "function show (req, res) {\n  const x = 1") == [8]


# ------------------------------------------------------------------ counting

AUTHOR = "qwen3.6:27b"


def _finding(refs, verified=True) -> E.Finding:
    return E.Finding(lens="injection", model=AUTHOR, title="t", file="a.js",
                     quote="const x = 1", severity="high", reasoning="r",
                     attacker_control="a", why_it_might_be_wrong="w",
                     quote_verified=verified, refutations=list(refs))


BAD = {"model": "devstral:24b", "verdict": "refuted", "reason": "guarded",
       "grounding": {"ok": False, "why": "counter_quote occurs only in other"}}
GOOD = {"model": "granite4.2:30b", "verdict": "refuted", "reason": "guarded",
        "grounding": {"ok": True, "why": "in show"}}
LEGACY = {"model": "granite4.2:30b", "verdict": "refuted", "reason": "guarded"}


def test_an_ungrounded_refutation_is_unsupported_not_a_vote_and_not_an_error():
    f = _finding([BAD])
    assert (f.refuted, f.survived, f.unsupported, f.refuter_errors) == (0, 0, 1, 0)


def test_a_grounded_refutation_counts():
    f = _finding([BAD, GOOD])
    assert (f.refuted, f.unsupported, f.refuter_errors) == (1, 1, 0)


def test_uncertain_is_not_rebutted_rather_than_a_refuter_error():
    """`uncertain` was a refuter error, and `--resume` re-asks only failed calls, so the
    claim stayed deferred at the gate for good."""
    unsure = {"model": "devstral:24b", "verdict": "uncertain", "reason": "needs config"}
    f = _finding([unsure])
    assert (f.refuted, f.survived, f.unsupported, f.refuter_errors) == (0, 0, 1, 0)
    assert (_finding([unsure, GOOD]).refuted, _finding([unsure, GOOD]).unsupported) == (1, 1)
    assert _finding([unsure], verified=False).unsupported == 0


def test_an_uncertain_answer_reaches_the_gate_as_not_rebutted(con, src, monkeypatch):
    _answers(monkeypatch, {"verdict": "uncertain", "reason": "depends on deployment"})
    runner._refute_pass(con, 1, src, {"core": _Sub()}, MODELS, None, lambda *_: None)
    r = _row(con)
    assert (r["n_unsupported"], r["refuter_errors"]) == (1, 0) and E.kept(r)
    oid = _deep_occurrence(con)
    funnel.run(con, 1)
    ev = con.execute("SELECT action, reason FROM funnel_events WHERE occurrence_id=? AND "
                     "stage='layer2-gate'", (oid,)).fetchone()
    assert ev["action"] == "pass" and "uncertain" in ev["reason"]


def test_a_record_from_before_grounding_counts_as_it_did():
    assert (_finding([LEGACY]).refuted, _finding([LEGACY]).unsupported) == (1, 0)


def test_grounding_does_not_apply_to_a_claim_whose_own_quote_failed():
    # The gate kills an unverified claim on its quote; its refutations do not matter.
    f = _finding([BAD], verified=False)
    assert (f.refuted, f.unsupported) == (1, 0)


def test_a_model_cannot_write_its_own_grounding():
    rec = E.refutation_record("devstral:24b", json.dumps(
        {"verdict": "refuted", "reason": "r", "counter_file": "a.js",
         "counter_quote": "check(req.params.id)", "guard": "check(",
         "grounding": {"ok": True, "why": "me"}}))
    assert "grounding" not in rec and rec["counter_file"] == "a.js"
    assert rec["guard"] == "check("


def test_the_prompt_and_schema_ask_for_evidence():
    assert {"counter_file", "counter_quote", "guard"} <= set(E.REFUTE_SCHEMA["properties"])
    assert "`guard`" in E.REFUTE_SYSTEM
    assert "counter_quote" in E.REFUTE_SYSTEM and "sibling" in E.REFUTE_SYSTEM
    f = _finding([])
    retry = E.refute_prompt("body", f, "Qtag", rejected=BAD)
    assert "Qtag YOUR PREVIOUS ANSWER WAS NOT ACCEPTED" in retry
    assert "counter_quote occurs only in other" in retry
    assert "NOT ACCEPTED" not in E.refute_prompt("body", f, "Qtag")


# ------------------------------------------------------------------ the refute pass

MODELS = ["qwen3.6:27b", "devstral:24b"]


class _Sub:
    def render(self, tag: str = "") -> str:
        return JS


@pytest.fixture
def con(tmp_path):
    c = db.init(tmp_path / "t.db")
    c.execute("INSERT INTO runs (id,target,clone_url,status) VALUES (1,'o/r','x','done')")
    c.execute("INSERT INTO research_runs (id,run_id,status,models) VALUES (1,1,'running',?)",
              (json.dumps(MODELS),))
    c.execute(
        """INSERT INTO research_findings
           (id, research_id, subsystem, lens, model, family, title, file, quote,
            quote_verified, severity, reasoning, attacker_control, self_critique)
           VALUES (1,1,'core','injection',?,?,'t','a.js','const x = 1',1,'high','r',
                   'the `id` route parameter','w')""",
        (AUTHOR, E.family(AUTHOR)))
    return c


def _answers(monkeypatch, first, second=None):
    prompts: list[str] = []

    def fake(model, prompt, schema, *, num_ctx=0, num_predict=0):
        prompts.append(prompt)
        ans = second if (second and "NOT ACCEPTED" in prompt) else first
        return json.dumps(ans), {}

    monkeypatch.setattr(E, "call", fake)
    return prompts


def _row(con):
    return con.execute("SELECT * FROM research_findings WHERE id=1").fetchone()


def test_an_ungrounded_refutation_is_asked_once_more_then_counted_unsupported(con, src,
                                                                           monkeypatch):
    sibling = {"verdict": "refuted", "reason": "only admins reach it",
               "counter_file": "a.js",
               "counter_quote": "if (!req.user.isAdmin) return res.status(403).end()",
               "guard": "req.user.isAdmin"}
    prompts = _answers(monkeypatch, sibling)
    runner._refute_pass(con, 1, src, {"core": _Sub()}, MODELS, None, lambda *_: None)
    assert len(prompts) == 2 and "occurs only in other" in prompts[1]
    r = _row(con)
    assert (r["n_refuted"], r["n_survived"], r["n_unsupported"], r["refuter_errors"]) == (
        0, 0, 1, 0)
    rec = json.loads(r["refutations"])[0]
    assert rec["grounding"]["ok"] is False and len(rec["earlier_ungrounded"]) == 1


def test_a_refuter_that_backs_down_on_the_retry_is_a_defence(con, src, monkeypatch):
    _answers(monkeypatch, {"verdict": "refuted", "reason": "it is checked"},
             {"verdict": "survives", "reason": "no check on this path"})
    runner._refute_pass(con, 1, src, {"core": _Sub()}, MODELS, None, lambda *_: None)
    r = _row(con)
    assert (r["n_survived"], r["n_unsupported"]) == (1, 0)
    rec = json.loads(r["refutations"])[0]
    assert rec["earlier_ungrounded"][0]["grounding"]["why"].startswith("no counter_quote")


def test_a_grounded_refutation_is_not_asked_again(con, src, monkeypatch):
    prompts = _answers(monkeypatch, {"verdict": "refuted", "reason": "the id is checked",
                                     "counter_file": "a.js",
                                     "counter_quote": "check(req.params.id)",
                                     "guard": "check(req.params.id)"})
    runner._refute_pass(con, 1, src, {"core": _Sub()}, MODELS, None, lambda *_: None)
    assert len(prompts) == 1
    assert (_row(con)["n_refuted"], _row(con)["n_unsupported"]) == (1, 0)


# ------------------------------------------------------------------ gate, bar, digest

def _deep_occurrence(con) -> int:
    pid = db.upsert_producer(con, "deep", "injection")
    con.execute("INSERT INTO findings (id,target,path,producer_id,first_seen_run,"
                "last_seen_run) VALUES ('fd','o/r','a.js',?,1,1)", (pid,))
    oid = con.execute("INSERT INTO occurrences (run_id,finding_id,producer_id,path,message,"
                      "severity) VALUES (1,'fd',?,'a.js','t','high')", (pid,)).lastrowid
    con.execute("UPDATE research_findings SET occurrence_id=? WHERE id=1", (oid,))
    con.execute("UPDATE research_runs SET status='done' WHERE id=1")
    return oid


@pytest.mark.parametrize("counts, action, words", [
    ((0, 0, 1), "pass", "not rebutted"),
    ((1, 0, 1), "kill", "refuted by all 1"),
])
def test_the_gate_keeps_a_claim_no_refuter_could_rebut(con, counts, action, words):
    n_ref, n_surv, n_uns = counts
    con.execute("UPDATE research_findings SET n_refuted=?, n_survived=?, n_unsupported=?, "
                "refutations=? WHERE id=1", (n_ref, n_surv, n_uns, json.dumps([BAD])))
    oid = _deep_occurrence(con)
    funnel.run(con, 1)
    ev = con.execute("SELECT action, reason FROM funnel_events WHERE occurrence_id=? AND "
                     "stage='layer2-gate'", (oid,)).fetchone()
    assert ev["action"] == action and words in ev["reason"]


@pytest.mark.parametrize("counts, kept", [
    ((1, 0, 0, 0), False), ((0, 1, 0, 0), True), ((1, 1, 0, 0), True),
    ((0, 0, 1, 0), True), ((1, 0, 1, 0), False), ((0, 0, 0, 3), False),
])
def test_kept_and_the_sql_bar_agree(con, counts, kept):
    n_ref, n_surv, n_uns, errs = counts
    con.execute("UPDATE research_findings SET n_refuted=?, n_survived=?, n_unsupported=?, "
                "refuter_errors=? WHERE id=1", (n_ref, n_surv, n_uns, errs))
    sql = con.execute(f"SELECT {E.KEPT_SQL} FROM research_findings rf WHERE id=1"
                      ).fetchone()[0]
    assert bool(sql) is kept is E.kept(_row(con))
    assert bool(verdicts.survivors(con, 1)) is kept


def test_the_digest_says_not_rebutted_and_why(con, tmp_path):
    con.execute("UPDATE research_findings SET n_unsupported=1, refutations=? WHERE id=1",
                (json.dumps([BAD]),))
    d = report.draft_research_digest(con, 1, out_dir=tmp_path)
    text = Path(d.path).read_text() if hasattr(d, "path") else str(d)
    assert "not rebutted" in text
    assert "evidence did not hold" in text and "only in other" in text
