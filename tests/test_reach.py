"""Decision N: reach orders the Layer 2 review list and kills nothing.

A refutation that argues the attacker cannot reach the claimed code has no guard to
quote, so decision F keeps the claim for a human. On VulnLookup (2026-11-07) 127 of
429 kept findings carried one. Killing on reach was rejected because the code that
parses third-party feeds is attack surface no route touches; the list is ordered by
reach instead: defended first, then a file that declares a route, then one imported by
such a file, then the rest.

No model and no network: E.call is replaced where the runner is driven.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quarry import db                                        # noqa: E402
from quarry.research import ensemble as E                    # noqa: E402
from quarry.research import reach, runner, verdicts          # noqa: E402
from quarry.web import queries as q                          # noqa: E402


def _write(root: Path, rel: str, text: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def test_python_reach_follows_imports_from_a_routed_file(tmp_path):
    _write(tmp_path, "web/views.py",
           'from flask import Blueprint\nfrom core import helpers\nimport utils\n\n'
           'bp = Blueprint("notes", __name__, url_prefix="/notes")\n\n\n'
           '@bp.route("/public")\ndef public():\n    return helpers.go()\n')
    _write(tmp_path, "core/helpers.py", "from .deep import thing\n\ndef go():\n    return thing\n")
    _write(tmp_path, "core/deep.py", "thing = 1\n")
    _write(tmp_path, "feeders/feed.py", "import json\n")        # parses feeds, no route
    _write(tmp_path, "a/utils.py", "")                          # `import utils` is
    _write(tmp_path, "b/utils.py", "")                          # ambiguous: two match

    got = reach.classify(tmp_path)

    assert got["web/views.py"] == reach.ROUTE
    assert got["core/helpers.py"] == reach.IMPORTED
    assert got["core/deep.py"] == reach.IMPORTED                # through helpers' import
    assert "feeders/feed.py" not in got
    assert "a/utils.py" not in got and "b/utils.py" not in got


def test_javascript_reach_follows_relative_specifiers(tmp_path):
    _write(tmp_path, "src/routes/index.js",
           "const h = require('../lib/helper')\nconst ext = require('express')\n")
    _write(tmp_path, "src/lib/helper.js", "import x from './inner'\nexport * from './more'\n")
    _write(tmp_path, "src/lib/inner.ts", "export default 1\n")
    _write(tmp_path, "src/lib/more/index.js", "module.exports = {}\n")
    _write(tmp_path, "src/tools/cli.js", "require('../lib/helper')\n")   # imports, not imported
    _write(tmp_path, "node_modules/express/index.js", "")

    got = reach.classify(tmp_path, route_files={"src/routes/index.js"})

    assert got == {"src/routes/index.js": reach.ROUTE, "src/lib/helper.js": reach.IMPORTED,
                   "src/lib/inner.ts": reach.IMPORTED,
                   "src/lib/more/index.js": reach.IMPORTED}


def _kept(con, fid: int, file: str, reach_value, *, survived: int = 0) -> None:
    con.execute(
        """INSERT INTO research_findings
           (id, research_id, subsystem, lens, model, family, title, file, quote,
            quote_verified, n_survived, n_refuted, n_unsupported, reach)
           VALUES (?,1,'s','injection','devstral:24b','mistral',?,?,'q',1,?,0,?,?)""",
        (fid, f"finding {fid}", file, survived, 0 if survived else 1, reach_value))


def test_the_review_list_puts_defended_first_then_nearer_a_route(tmp_path):
    con = db.init(tmp_path / "t.db")
    con.execute("INSERT INTO runs (id,target,clone_url,status) VALUES (1,'o/r','x','done')")
    con.execute("INSERT INTO research_runs (id,run_id,status,models) VALUES (1,1,'done','[]')")
    _kept(con, 1, "feeders/feed.py", None)
    _kept(con, 2, "feeders/other.py", reach.NONE)
    _kept(con, 3, "core/helpers.py", reach.IMPORTED)
    _kept(con, 4, "web/views.py", reach.ROUTE)
    _kept(con, 5, "feeders/feed.py", reach.NONE, survived=1)     # defended beats reach

    assert [r["id"] for r in verdicts.survivors(con, 1)] == [5, 4, 3, 1, 2]
    labels = {r["id"]: r["reach_label"] for r in q.research_survivors(con, 1, 1)["rows"]}
    assert labels[4] == "declares a route" and labels[1] == "not ranked yet"
    assert reach.fill(con, 1, {"feeders/feed.py": reach.NONE}) == 1     # only the NULL one
    assert con.execute("SELECT reach FROM research_findings WHERE id=1").fetchone()[0] \
        == reach.NONE


EXPRESS = """\
const express = require('express')
const router = express.Router()
const helper = require('../lib/helper')
router.get('/x/:id', mw.optionallyValidateUser, controller.GET_ONE)
router.put('/x/:id', mw.validateUser, controller.PUT_ONE)
module.exports = router
"""


def _planned(tmp_path):
    src = tmp_path / "vol" / "src"
    _write(src, "routes/index.js", EXPRESS * 3)
    _write(src, "lib/helper.js", "module.exports = function helper (a) { return eval(a) }\n")
    _write(src, "tools/cli.js", "const fs = require('fs')\nfs.unlinkSync(process.argv[2])\n")
    _write(src, "package.json", '{"scripts": {"start": "node ."}, '
                                '"dependencies": {"express": "4"}}')
    con = db.init(tmp_path / "t.db")
    con.execute("INSERT INTO runs (id,target,clone_url,status) VALUES (1,'o/r','x','done')")
    rid, _, _ = runner.plan(con, 1, src, models=["qwen3.6:27b", "devstral:24b"],
                            lenses=["error-and-disclosure"])
    return con, rid, src


def _hunt_finds_two(monkeypatch):
    def fake_call(model, prompt, schema, *, num_ctx=0, num_predict=0):
        if "THE CLAIM" in prompt:
            return json.dumps({"verdict": "survives", "reason": "holds"}), {}
        return json.dumps({"findings": [
            {"title": "eval of input", "file": "lib/helper.js",
             "quote": "return eval(a)", "severity": "high", "reasoning": "r",
             "attacker_control": "a", "why_it_might_be_wrong": "w"},
            {"title": "unlink from argv", "file": "tools/cli.js",
             "quote": "fs.unlinkSync(process.argv[2])", "severity": "low",
             "reasoning": "r", "attacker_control": "a", "why_it_might_be_wrong": "w"}]}), {}
    monkeypatch.setattr(E, "call", fake_call)
    monkeypatch.setattr(E, "model_provenance", lambda models: {})


def test_the_runner_ranks_each_finding_as_it_lands(tmp_path, monkeypatch):
    con, rid, src = _planned(tmp_path)
    _hunt_finds_two(monkeypatch)

    runner.execute(con, rid, src, progress=lambda *_: None)

    got = {r["file"]: r["reach"] for r in
           con.execute("SELECT file, reach FROM research_findings WHERE research_id=?",
                       (rid,))}
    assert got == {"lib/helper.js": reach.IMPORTED, "tools/cli.js": reach.NONE}


def test_an_untimed_resume_clears_an_earlier_deadline(tmp_path, monkeypatch):
    """2026-11-07: a run resumed with no deadline kept the one an earlier call set, so
    the dashboard counted down to a stop that was never coming. (Here rather than in a
    file of its own because this harness already drives `execute`.)"""
    con, rid, src = _planned(tmp_path)
    _hunt_finds_two(monkeypatch)
    con.execute("UPDATE research_runs SET deadline='2026-11-07T15:24:57' WHERE id=?", (rid,))

    runner.execute(con, rid, src, deadline=None, progress=lambda *_: None)

    assert con.execute("SELECT deadline FROM research_runs WHERE id=?",
                       (rid,)).fetchone()[0] is None


def test_a_reach_failure_leaves_the_list_unranked_and_the_review_running(tmp_path,
                                                                         monkeypatch):
    con, rid, src = _planned(tmp_path)
    _hunt_finds_two(monkeypatch)

    def broken(src):
        raise RuntimeError("no route map")
    monkeypatch.setattr(reach, "classify", broken)
    lines: list[str] = []

    stats = runner.execute(con, rid, src, progress=lines.append)

    assert stats["findings"] > 0
    assert any("[reach] unavailable" in x for x in lines)
    assert {r[0] for r in con.execute("SELECT reach FROM research_findings")} == {None}
