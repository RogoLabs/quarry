"""Deep-review findings reach Layer 3 (validate.DEEP_LENS_CWE).

A deep finding's producer is its lens, with no CWE, and validate picks candidates by
CWE, so no deep-review finding was ever probed. Three lenses now map to the probe class
that covers them. The model rarely gives a line, and a probe decides only on the handler
enclosing the finding's line, so the line comes from the finding's verified quote. And
since a lens is a kind of question rather than a CWE, a probe that does not reproduce
the claim cannot reject it.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from quarry import db                                              # noqa: E402
from quarry.dynamic.validate import (                              # noqa: E402
    INFERRED_CWE, ProbeEvidence, final_verdict, run_validation, select_candidates)
from test_run_validation import (                                  # noqa: E402,F401
    FakeRuntime, _confirming, _with_control, scanned)


def _add_deep(con, fid, lens, path="app.py", quote="@app.get('/secret')", line=None):
    with db.tx(con):
        pid = db.upsert_producer(con, "deep", lens, name=f"deep review: {lens}")
        con.execute("INSERT INTO findings (id,target,path,producer_id,first_seen_run,"
                    "last_seen_run) VALUES (?,?,?,?,1,1)", (fid, "o/r", path, pid))
        con.execute("INSERT INTO occurrences (run_id,finding_id,producer_id,path,"
                    "start_line,message,raw_result) VALUES (1,?,?,?,?,'t',?)",
                    (fid, pid, path, line, json.dumps({"lens": lens, "quote": quote})))


def _cand(con, fid, src=None):
    return next(c for c in select_candidates(con, 1, src=src) if c.finding_id == fid)


def test_a_deep_finding_takes_its_lens_cwe_and_its_quotes_line(scanned):
    con, rundir = scanned
    _add_deep(con, "d-authz", "broken-authz-idor")
    _add_deep(con, "d-tenant", "multi-tenancy-isolation", quote="def users(): ...")
    _add_deep(con, "d-path", "filesystem-and-path", quote="def health(): ...")
    authz = _cand(con, "d-authz", rundir / "src")
    assert (authz.cwe, authz.cwe_from) == ("CWE-639", "deep lens broken-authz-idor")
    # The quote is the decorator on line 1; the handler it decorates starts on line 2.
    assert authz.start_line == 2
    assert _cand(con, "d-tenant", rundir / "src").cwe == "CWE-863"
    assert _cand(con, "d-tenant", rundir / "src").start_line == 6
    path = _cand(con, "d-path", rundir / "src")
    assert (path.cwe, path.start_line) == ("CWE-22", 4)
    assert _cand(con, "d-authz").start_line is None, "no source tree, no line"
    assert _cand(con, "f-secret").cwe_from == "", "a scanner's own CWE is not inferred"


def test_a_line_the_model_gave_is_kept(scanned):
    con, rundir = scanned
    _add_deep(con, "d-authz", "broken-authz-idor", line=8)
    assert _cand(con, "d-authz", rundir / "src").start_line == 8


def test_lenses_without_a_probe_stay_out(scanned):
    """Injection spans XSS, SQL, command injection and SSRF; which check to send would be
    a guess. The rest have no probe at all."""
    con, rundir = scanned
    for lens in ("injection", "secrets-and-crypto", "mass-assignment"):
        _add_deep(con, f"d-{lens}", lens)
    ids = {c.finding_id for c in select_candidates(con, 1, src=rundir / "src")}
    assert not ids & {"d-injection", "d-secrets-and-crypto", "d-mass-assignment"}


def test_a_quote_found_only_in_a_stand_in_file_gives_no_line(scanned):
    """Quote verification lets one same-named file stand in for a path that does not
    exist. A route matches a finding by its own path, so that file's line means
    nothing here."""
    con, rundir = scanned
    _add_deep(con, "d-moved", "broken-authz-idor", path="lib/app.py")
    assert _cand(con, "d-moved", rundir / "src").start_line is None


def test_a_quote_not_in_the_file_gives_no_line(scanned):
    con, rundir = scanned
    _add_deep(con, "d-gone", "broken-authz-idor", quote="def nowhere(): pass")
    assert _cand(con, "d-gone", rundir / "src").start_line is None


def test_an_inferred_cwe_is_never_rejected(scanned, monkeypatch):
    """The same controlled denial rejects the scanner's CWE-862 finding and holds the
    deep finding, whose CWE was only assumed from its lens."""
    con, rundir = scanned
    _add_deep(con, "d-authz", "broken-authz-idor")
    _with_control(monkeypatch)
    res = run_validation(con, 1, rundir, FakeRuntime({"/secret": "403"}))
    got = {fid: v for fid, _, v in res.verdicts}
    assert got == {"f-secret": "rejected", "d-authz": "needs-review"}
    row = dict(con.execute("SELECT * FROM verdicts WHERE finding_id='d-authz'").fetchone())
    assert row["reason"] == INFERRED_CWE and row["executed_score"] == 0
    assert row["cwe"] == "CWE-639"
    assert json.loads(row["rationale"])["cwe_from"] == "deep lens broken-authz-idor"


def test_an_inferred_cwe_can_be_confirmed_on_its_own_handler(scanned, monkeypatch):
    con, rundir = scanned
    _add_deep(con, "d-authz", "broken-authz-idor")
    _confirming(monkeypatch)
    res = run_validation(con, 1, rundir, FakeRuntime({"/secret": "200"}))
    assert ("d-authz", "broken-authz-idor", "confirmed") in res.verdicts
    row = dict(con.execute("SELECT * FROM verdicts WHERE finding_id='d-authz'").fetchone())
    assert row["verdict"] == "confirmed" and row["cwe"] == "CWE-639"
    assert json.loads(row["rationale"])["cwe_from"] == "deep lens broken-authz-idor"


def test_final_verdict_holds_only_a_rejection():
    reject = ProbeEvidence(reproduced=False, determinism="deterministic",
                           baseline="GET /health -> 200", differs_from_baseline=False,
                           handled=True, summary="s")
    assert final_verdict(reject)[0] == "rejected"
    assert final_verdict(reject, may_reject=False) == ("needs-review", INFERRED_CWE)
    confirm = ProbeEvidence(reproduced=True, determinism="deterministic",
                            baseline="GET /health -> 200", differs_from_baseline=True,
                            handled=True, summary="s")
    assert final_verdict(confirm, may_reject=False)[0] == "confirmed"
