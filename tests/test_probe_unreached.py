"""A probe that never reached the code must not reject the finding (IMPROVEMENT-PLAN P4;
item 3, "Rejection is easier than confirmation").

A rejected verdict kills the finding in every later run, so it needs a handler that
answered. A target that answers 404 or 405 to everything, or that nothing reached at
all, says only that the probe picked the wrong route or method. The existing tests pin
this for the timing probe and the rate-limit probe one case at a time. These sweep every
probe lens and every CWE class it handles against such a target, with a 404 page that
echoes the request HTML-encoded the way framework error pages do, and then run the whole
validate loop against it.
"""
from __future__ import annotations

import html
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quarry import db                                                  # noqa: E402
from quarry.dynamic import lenses                                      # noqa: E402
from quarry.dynamic.routes import Route                                # noqa: E402
from quarry.dynamic.validate import (                                  # noqa: E402
    Candidate, RuntimeSpec, RunningTarget, adjudicate_with_reason, run_validation)

RUNNING = RunningTarget(base_url="http://web:8080", stop=lambda: None, network="net")
# One of each shape a probe selects on: a declared-protected route, an auth-like route,
# and routes with a path parameter to inject into.
ROUTES = [
    Route("GET", "/api/users/{uid}", "app.py", "openapi", auth_required=True,
          params=("uid",)),
    Route("GET", "/login", "app.py", "static"),
    Route("GET", "/files/<name>", "app.py", "static", params=("name",)),
    Route("GET", "/fetch", "app.py", "static", params=("url",)),
]
CASES = [(lens, cwe) for lens in lenses.CATALOGUE for cwe in sorted(lens.cwes)]


def _target(statuses, *, rc=0):
    """A fake exec_fn for a target that never handles a request: every status probe
    gets the next of `statuses` (cycling), every timing probe the same status with a
    flat 20ms, and every body request an error page that echoes the path encoded."""
    n = {"i": 0}

    def status() -> str:
        s = statuses[n["i"] % len(statuses)]
        n["i"] += 1
        return s

    def run(argv):
        if rc:
            return rc, ""
        fmt = argv[argv.index("-w") + 1] if "-w" in argv else None
        if fmt == "%{http_code}":
            return 0, status()
        if fmt == "%{http_code} %{time_total}":
            return 0, f"{status()} 0.020000"
        path = argv[-1].split("://", 1)[-1].partition("/")[2]
        s = status()
        return 0, (f"<html><title>{s}</title><body><h1>{s}</h1>"
                   f"<p>Cannot GET /{html.escape(path)}</p></body></html>")
    return run


def _cand(cwe: str) -> Candidate:
    return Candidate("f1", 1, "o/r", "app.py", 3, "p", cwe, "finding")


@pytest.mark.parametrize("statuses", [["404"], ["405"], ["404", "405"]],
                         ids=["404", "405", "404-and-405"])
@pytest.mark.parametrize("lens, cwe", CASES,
                         ids=[f"{lens.key}-{cwe}" for lens, cwe in CASES])
def test_no_probe_rejects_on_404_or_405(lens, cwe, statuses):
    ev = lens.probe(RUNNING, _cand(cwe), ROUTES, _target(statuses))
    verdict, reason = adjudicate_with_reason(ev)
    assert verdict != "rejected", (lens.key, cwe, ev.summary)
    assert verdict == "needs-review", (lens.key, cwe, verdict, ev.summary)
    assert ev.handled is not True, ev.summary


@pytest.mark.parametrize("lens, cwe", CASES,
                         ids=[f"{lens.key}-{cwe}" for lens, cwe in CASES])
def test_no_probe_rejects_when_nothing_answered(lens, cwe):
    """curl exits 7 (could not connect) on every request: there is no response at all."""
    ev = lens.probe(RUNNING, _cand(cwe), ROUTES, _target(["000"], rc=7))
    assert adjudicate_with_reason(ev)[0] == "needs-review", (lens.key, cwe, ev.summary)


def test_the_sweep_can_see_a_rejection():
    """Guard against a vacuous sweep: with the same stub answering 200, the timing
    probe's equal medians are a handled control comparison, and that rejects."""
    timing = next(lens for lens in lenses.CATALOGUE if lens.key == "auth-timing-oracle")
    ev = timing.probe(RUNNING, _cand("CWE-208"), ROUTES, _target(["200"]))
    assert adjudicate_with_reason(ev) == ("rejected", "statistical")


class _NotFoundRuntime:
    """A stood-up target whose router answers 404 (or 405) to every request."""
    def __init__(self, statuses):
        self.exec = _target(statuses)
        self.stopped = False

    def detect(self, src):
        return RuntimeSpec("compose", "docker-compose.yml", base_url="http://web:8080")

    def start(self, spec, rundir):
        return RunningTarget("http://web:8080", stop=self._stop, network="net")

    def _stop(self):
        self.stopped = True

    def probe_exec(self, running, argv):
        return self.exec(argv)


# A Flask service whose source shows every capability a probe lens needs, so the
# profile selects all five lenses.
APP = """\
import subprocess
from flask import render_template

@app.get('/login')
@login_required
def login(): ...

@app.get('/api/users/<int:uid>')
def user(uid):
    return cursor.execute("SELECT * FROM users WHERE id = %s" % uid)

@app.get('/files/<name>')
def files(name):
    return open(name).read()

@app.get('/run/<cmd>')
def run(cmd):
    return subprocess.run(cmd, shell=True)

@app.get('/hello/<who>')
def hello(who):
    return render_template('hello.html', who=who)
"""


@pytest.mark.parametrize("statuses", [["404"], ["405"]], ids=["404", "405"])
def test_validate_against_a_target_that_only_404s_writes_no_rejection(tmp_path, statuses):
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text(APP)
    (src / "docker-compose.yml").write_text("services:\n  web:\n    image: x\n")
    con = db.init(tmp_path / "quarry.db")
    cwes = sorted({c for lens in lenses.CATALOGUE for c in lens.cwes})
    with db.tx(con):
        con.execute("INSERT INTO runs (id, target, clone_url) VALUES (1,'o/r','https://x')")
        for i, cwe in enumerate(cwes):
            con.execute("INSERT INTO producers (id,tool,rule_id,cwe) VALUES (?,?,?,?)",
                        (f"p{i}", "opengrep", f"rule{i}", cwe))
            con.execute("INSERT INTO findings (id,target,path,producer_id,first_seen_run,"
                        "last_seen_run) VALUES (?,'o/r','app.py',?,1,1)", (f"f{i}", f"p{i}"))
            con.execute("INSERT INTO occurrences (id,run_id,finding_id,producer_id,path,"
                        "start_line,message) VALUES (?,1,?,?,'app.py',3,'x')",
                        (10 + i, f"f{i}", f"p{i}"))
    runtime = _NotFoundRuntime(statuses)

    res = run_validation(con, 1, tmp_path, runtime)

    probed = {lens for _, lens, _ in res.verdicts}
    assert probed == {lens.key for lens in lenses.CATALOGUE}, probed   # every lens ran
    assert len(res.verdicts) == len(cwes)
    assert res.rejected == 0 and res.confirmed == 0
    rows = [dict(r) for r in con.execute("SELECT verdict, rationale FROM verdicts")]
    assert len(rows) == len(cwes)
    assert {r["verdict"] for r in rows} == {"needs-review"}
    assert not [r for r in rows if json.loads(r["rationale"])["handled"] is True]
    assert runtime.stopped is True
