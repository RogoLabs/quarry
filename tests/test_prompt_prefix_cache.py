"""IMPROVEMENT-PLAN item 28: prompts of one subsystem share one tag.

The tag sits ahead of the repository text in both the hunt and the refute prompt, so a
fresh tag per call made every call re-read the whole subsystem. MEASURED on run 7
(qwen3-coder:30b, a 41k-token subsystem, 5 findings): 102 to 123 s per refute call with
a fresh tag; with one shared, 111 s for the first and 9 to 11 s for each after it.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from quarry.research import ensemble as E, runner            # noqa: E402
from test_deep_intent import _planned                         # noqa: E402
from test_refute_pass import MODELS, con                      # noqa: E402,F401

TAG = re.compile(r"carries the tag (Q[0-9a-f]+)")


class _Sub:
    def __init__(self, name):
        self.name = name

    def render(self, tag: str = "") -> str:
        return f"===== {tag} {self.name} =====\nconst x = 1\n"


def _add(con, fid, model, subsystem):
    con.execute(
        """INSERT INTO research_findings
           (id, research_id, subsystem, lens, model, family, title, file, quote,
            quote_verified, severity, reasoning, attacker_control, self_critique)
           VALUES (?,1,?,'injection',?,?,?,'a.js','const x = 1',1,'high','r','a','w')""",
        (fid, subsystem, model, E.family(model), f"finding {fid}"))


def test_the_refute_pass_uses_one_tag_per_subsystem(con, monkeypatch):
    for fid, subsystem in enumerate(["core", "core", "web", "core", "web"], start=1):
        _add(con, fid, MODELS[0], subsystem)
    seen: list[tuple[str, str]] = []

    def fake_call(model, prompt, schema, *, num_ctx=0, num_predict=0):
        seen.append((TAG.search(prompt).group(1), prompt))
        return json.dumps({"verdict": "survives", "reason": "r"}), {}
    monkeypatch.setattr(E, "call", fake_call)
    runner._refute_pass(con, 1, Path("/x"), {"core": _Sub("core"), "web": _Sub("web")},
                        MODELS, None, lambda *_: None)
    by_sub: dict[str, set[str]] = {}
    for tag, prompt in seen:
        by_sub.setdefault("core" if " core =====" in prompt else "web", set()).add(tag)
    assert len(seen) == 10                       # 5 findings x 2 cross-family refuters
    assert all(len(tags) == 1 for tags in by_sub.values())
    assert by_sub["core"] != by_sub["web"], "each subsystem gets its own tag"
    # grouped, so consecutive calls of one model stay on one subsystem
    order = ["core" if " core =====" in p else "web" for _, p in seen[:5]]
    assert order == sorted(order)


def test_the_hunt_runs_a_subsystem_model_by_model_with_one_tag(tmp_path, monkeypatch):
    con, rid, src, chosen = _planned(tmp_path, ["broken-authz-idor", "error-and-disclosure"])
    calls: list[tuple[str, str, str]] = []

    def fake_call(model, prompt, schema, *, num_ctx=0, num_predict=0):
        if "YOUR LENS" in prompt:
            lens = prompt.split("YOUR LENS: ")[1].split(" ")[0]
            calls.append((model, lens, TAG.search(prompt).group(1)))
        return json.dumps({"findings": []}), {}
    monkeypatch.setattr(E, "call", fake_call)
    monkeypatch.setattr(E, "model_provenance", lambda models: {})
    runner.execute(con, rid, src, progress=lambda *_: None)
    models = [m for m, _, _ in calls]
    assert models == sorted(models, key=models.index), "one model at a time, not alternating"
    assert len({t for _, _, t in calls}) == 1, "one subsystem, one tag"
    assert len(calls) == 4
