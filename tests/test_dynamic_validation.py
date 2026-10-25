"""Layer 3 acceptance: the target-runtime containment and the validation plumbing.

Two halves, mirroring test_containment's philosophy that a profile with no test is a
comment. The containment half mounts a real sparse image and runs real sandbox-exec to
prove the one capability Layer 3 adds (loopback) and the one it must never add (egress).
The plumbing half is fast and hermetic: candidate selection obeys the funnel ledger, and
a verdict only carries a non-zero executed_score when a probe actually ran.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quarry import config, db                                       # noqa: E402
from quarry.ingest.volume import RunVolume                          # noqa: E402
from quarry.sandbox import tier1, PROFILE, TARGET_PROFILE           # noqa: E402
from quarry.dynamic import validate                                 # noqa: E402
from quarry.dynamic.validate import Candidate, ProbeEvidence        # noqa: E402

macos = pytest.mark.skipif(sys.platform != "darwin", reason="sandbox-exec is macOS-only")

RUN_ID = 99_998

LOOPBACK = (
    "import socket\n"
    "s=socket.socket(); s.bind(('127.0.0.1',0)); s.listen(1)\n"
    "port=s.getsockname()[1]\n"
    "c=socket.socket(); c.connect(('127.0.0.1',port))\n"
    "conn,_=s.accept(); c.sendall(b'x')\n"
    "assert conn.recv(1)==b'x'\n"
    "print('LOOPBACK-OK')\n"
)
EGRESS = (
    "import socket\n"
    "try:\n"
    "    socket.create_connection(('192.0.2.1',80),timeout=2); print('EGRESS-OPEN')\n"
    "except OSError as e: print('EGRESS-BLOCKED', e.errno)\n"
)


@pytest.fixture(scope="module")
def volume():
    paths = config.paths()
    (paths.runs / f"{RUN_ID}.sparseimage").unlink(missing_ok=True)
    vol = RunVolume.create(RUN_ID, paths.runs, size_gb=1)
    try:
        yield vol
    finally:
        vol.release()


def _run(volume, script, profile, name):
    r = tier1(volume.mount, ["/usr/bin/python3", "-c", script], name=name, profile=profile)
    return r.returncode, r.stdout_bytes(65536).decode("utf-8", "replace")


@macos
def test_target_profile_allows_loopback(volume):
    """A probe must be able to reach a target it just started on loopback."""
    rc, out = _run(volume, LOOPBACK, TARGET_PROFILE, "t-loop")
    assert rc == 0 and "LOOPBACK-OK" in out, out


@macos
def test_scanner_profile_denies_loopback(volume):
    """The capability is specific to the target profile: the scanner profile, which
    every tool that only reads bytes runs under, still denies all network."""
    rc, out = _run(volume, LOOPBACK, PROFILE, "s-loop")
    assert rc != 0 and "LOOPBACK-OK" not in out, out


@macos
def test_target_profile_denies_egress(volume):
    """Loopback in, nothing out: a target under the target profile cannot open a
    connection to any non-loopback host, so it cannot exfiltrate."""
    rc, out = _run(volume, EGRESS, TARGET_PROFILE, "t-egress")
    assert "EGRESS-OPEN" not in out and "EGRESS-BLOCKED" in out, out


# ------------------------------------------------------------------ plumbing (fast)

@pytest.fixture
def con(tmp_path):
    p = tmp_path / "quarry.db"
    db.init(p)
    c = db.connect(p)
    with db.tx(c):
        c.execute("INSERT INTO runs (id, target, clone_url) VALUES (1,'o/r','https://x')")
        # a producer with a dynamically-testable CWE and a measured precision,
        # and one with a non-testable CWE.
        c.execute("""INSERT INTO producers (id, tool, rule_id, cwe, n_adjudicated, n_confirmed)
                     VALUES ('t:auth','opengrep','auth','CWE-862',4,3),
                            ('t:style','opengrep','style','CWE-710',0,0)""")
        for fid, pid in (("f-live", "t:auth"), ("f-killed", "t:auth"), ("f-style", "t:style")):
            c.execute("""INSERT INTO findings (id,target,path,producer_id,first_seen_run,last_seen_run)
                         VALUES (?,?,?,?,1,1)""", (fid, "o/r", "app/x.py", pid))
        c.execute("""INSERT INTO occurrences (id,run_id,finding_id,producer_id,path,start_line,message)
                     VALUES (10,1,'f-live','t:auth','app/x.py',5,'missing authz'),
                            (11,1,'f-killed','t:auth','app/x.py',9,'dup'),
                            (12,1,'f-style','t:style','app/y.py',1,'style')""")
        # kill occurrence 11 via the ledger — it must drop out of live_occurrences.
        db.funnel(c, 1, stage="dedup", action="kill", reason="duplicate", deterministic=True,
                  occurrence_id=11)
    return c


def test_select_candidates_only_live_and_testable(con):
    cands = validate.select_candidates(con, 1)
    ids = {c.finding_id for c in cands}
    assert ids == {"f-live"}                       # killed dropped, non-testable CWE dropped
    assert cands[0].cwe == "CWE-862"


def test_record_verdict_writes_executed_score(con):
    cand = Candidate("f-live", 10, "o/r", "app/x.py", 5, "t:auth", "CWE-862", "missing authz")
    vid = validate.record_verdict(con, cand, 1,
                                  ProbeEvidence(True, "authz bypass reproduced",
                                                observed="200 without a session cookie",
                                                determinism="deterministic",
                                                baseline="401 with no session cookie on "
                                                         "the sibling route",
                                                differs_from_baseline=True))
    row = dict(con.execute("SELECT * FROM verdicts WHERE id=?", (vid,)).fetchone())
    assert row["verdict"] == "confirmed"
    assert row["executed_score"] == 100 and row["evidence_score"] == 0
    assert row["seat"] == "dynamic" and row["cwe"] == "CWE-862"
    stored = json.loads(row["rationale"])
    assert stored["baseline"].startswith("401") and stored["differs_from_baseline"] is True


def test_reproduction_without_baseline_is_held_for_review(con):
    # A probe that saw the predicted effect but recorded no control comparison has not
    # shown the effect is the finding. It must not reach "confirmed", and so never an
    # advisory.
    cand = Candidate("f-live", 10, "o/r", "app/x.py", 5, "t:auth", "CWE-862", "x")
    ev = ProbeEvidence(True, "authz bypass reproduced", observed="HTTP 200",
                       determinism="deterministic")
    assert validate.adjudicate(ev) == "needs-review"
    vid = validate.record_verdict(con, cand, 1, ev)
    row = dict(con.execute("SELECT * FROM verdicts WHERE id=?", (vid,)).fetchone())
    assert row["verdict"] == "needs-review"
    assert row["reason"] == "no baseline comparison recorded" == validate.NO_BASELINE
    assert row["executed_score"] == 50                 # the probe ran; it did not decide


def test_baseline_that_does_not_differ_is_not_a_confirmation():
    same = ProbeEvidence(True, "x", determinism="deterministic",
                         baseline="HTTP 200", differs_from_baseline=False)
    unset = ProbeEvidence(True, "x", determinism="deterministic", baseline="HTTP 200")
    empty = ProbeEvidence(True, "x", determinism="deterministic",
                          baseline="", differs_from_baseline=True)
    for ev in (same, unset, empty):
        assert validate.adjudicate(ev) == "needs-review"
    assert validate.adjudicate_with_reason(empty) == ("needs-review", validate.NO_BASELINE)


def test_rejected_probe_is_executed_but_not_confirmed(con):
    cand = Candidate("f-live", 10, "o/r", "app/x.py", 5, "t:auth", "CWE-862", "x")
    vid = validate.record_verdict(con, cand, 1,
                                  ProbeEvidence(False, "did not reproduce",
                                                determinism="deterministic"))
    row = dict(con.execute("SELECT * FROM verdicts WHERE id=?", (vid,)).fetchone())
    assert row["verdict"] == "rejected" and row["executed_score"] == 50


def test_plan_validation_is_honest_without_a_runtime(con, tmp_path):
    # tmp_path is an empty dir: profiles as a non-service, so no probe lens applies and
    # no runtime is registered. The plan says so rather than pretending.
    plan = validate.plan_validation(con, 1, tmp_path)
    assert [c.finding_id for c in plan.candidates] == ["f-live"]
    assert plan.runnable is False and "no registered runtime" in plan.runtime_reason
    assert plan.selected == []                     # nothing runs on a non-service
    assert plan.skipped                            # every lens reported a reason
    assert con.execute("SELECT COUNT(*) FROM verdicts").fetchone()[0] == 0
