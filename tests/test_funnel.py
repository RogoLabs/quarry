"""Funnel tests.

The funnel decides what a human never sees, so its failures are silent by
construction. Two classes of test here: the ledger semantics (nothing deleted, defer
is not kill), and regressions for recall bugs that actually happened.
"""
from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quarry import db, funnel, taint               # noqa: E402
from quarry.migrations import migrate              # noqa: E402


@pytest.fixture
def con(tmp_path):
    c = db.init(tmp_path / "t.db")
    migrate(c)
    c.execute("INSERT INTO runs (id,target,clone_url,git_sha,status) "
              "VALUES (1,'o/r','https://x','abc','done')")
    return c


def add(c: sqlite3.Connection, tool, rule, path, line=10, message="", raw=None,
        secret_prefix=None, redacted=0, blob=True, secret=None):
    """`secret` is the plaintext a test pretends Gitleaks saw; only its prefix and
    hash are stored, as the real writer does (D16)."""
    secret_sha = None
    if secret is not None:
        r = taint.redact_secret(secret)
        secret_prefix, secret_sha, redacted = r.prefix, r.sha256, 1
    pid = db.upsert_producer(c, tool, rule)
    fid = f"f{tool}{rule}{path}{line}"
    c.execute("INSERT OR IGNORE INTO findings (id,target,path,producer_id,"
              "first_seen_run,last_seen_run) VALUES (?,?,?,?,1,1)", (fid, "o/r", path, pid))
    sha = None
    if blob:
        sha = f"blob{tool}{rule}{path}{line}"
        c.execute("INSERT OR IGNORE INTO evidence_blobs "
                  "(sha,path,file_sha256,start_line,end_line,body,bytes) "
                  "VALUES (?,?,?,?,?,?,?)", (sha, path, "x", max(1, line - 40), line + 40, b"", 0))
    cur = c.execute(
        "INSERT INTO occurrences (run_id,finding_id,producer_id,path,start_line,message,"
        "severity,blob_sha,redacted,secret_prefix,secret_sha,raw_result) "
        "VALUES (1,?,?,?,?,?,'medium',?,?,?,?,?)",
        (fid, pid, path, line, message, sha, redacted, secret_prefix, secret_sha,
         json.dumps(raw or {})))
    return cur.lastrowid


# ---------------------------------------------------------------- regressions

def test_lockfile_sca_findings_survive_the_path_filter(con):
    """REGRESSION. The first run of `path-class` killed 107 findings on `poetry.lock`
    — 100% of the dependency-vulnerability output from both OSV-Scanner and Trivy —
    because a lockfile matches the "generated" pattern. A path filter that is not
    tool-aware silently deletes an entire detector class and still reports success."""
    sca = add(con, "osv-scanner", "PYSEC-2026-1", "poetry.lock", 1,
              "aiohttp 3.13.3: PYSEC-2026-1", {"aliases": ["CVE-2026-1"]})
    sast = add(con, "opengrep", "python.lang.x", "poetry.lock", 1)

    funnel.run(con, 1)
    alive = {r["id"] for r in con.execute("SELECT id FROM live_occurrences")}
    assert sca in alive, "SCA finding on a lockfile must survive — that is where they live"
    assert sast not in alive, "a SAST hit on a lockfile is still generated-file noise"


def test_sca_merge_resolves_aliases_across_tools(con):
    """REGRESSION. OSV reports PYSEC-…, Trivy reports the CVE it aliases to. Without
    alias resolution the merge finds nothing, both survive, and the duplicate then
    earns a corroboration boost — actively outranking genuine single-source findings."""
    a = add(con, "osv-scanner", "PYSEC-2026-2094", "poetry.lock", 1,
            "aiohttp 3.13.3: PYSEC-2026-2094",
            {"aliases": ["CVE-2026-22815", "GHSA-w2fm-2cpv-w7v5"],
             "package": {"name": "aiohttp"}})
    b = add(con, "trivy", "CVE-2026-22815", "poetry.lock", 1,
            "Package: aiohttp\nInstalled Version: 3.13.3\nVulnerability CVE-2026-22815")

    funnel.run(con, 1)
    alive = {r["id"] for r in con.execute("SELECT id FROM live_occurrences")}
    assert len(alive & {a, b}) == 1, "the same advisory from two tools must collapse to one"
    merged = con.execute("SELECT reason FROM funnel_events WHERE stage='sca-merge' "
                         "AND action='merge'").fetchone()
    assert merged and "CVE-2026-22815" in merged["reason"]


# ---------------------------------------------------------------- ledger semantics

def test_nothing_is_deleted_and_kills_are_reversible(con):
    oid = add(con, "bandit", "B101", "tests/test_x.py", 5)
    funnel.run(con, 1)
    assert con.execute("SELECT COUNT(*) c FROM occurrences").fetchone()["c"] == 1
    assert con.execute("SELECT COUNT(*) c FROM live_occurrences").fetchone()["c"] == 0

    db.funnel(con, 1, occurrence_id=oid, stage="operator", action="resurrect",
              reason="reviewed: this is production code despite the path",
              deterministic=False, actor="jerry")
    assert con.execute("SELECT COUNT(*) c FROM live_occurrences").fetchone()["c"] == 1


def test_defer_is_recorded_distinctly_from_kill(con):
    """A rate limiter running out is not evidence. Conflating the two destroys the
    only number that matters."""
    for i in range(5):
        add(con, "opengrep", f"rule.{i}", f"src/a{i}.py", 10)
    funnel.run(con, 1, budget_top_k=2)
    rows = {r["action"]: r["n"] for r in con.execute(
        "SELECT action, COUNT(*) n FROM funnel_events WHERE run_id=1 GROUP BY action")}
    assert rows.get("defer", 0) == 3
    assert rows.get("kill", 0) == 0, "the budget cut must never be recorded as a kill"


def test_every_suppression_carries_a_reason_and_a_determinism_flag(con):
    add(con, "bandit", "B101", "tests/test_x.py", 5)
    add(con, "opengrep", "r", "node_modules/x/y.js", 3)
    funnel.run(con, 1)
    for r in con.execute("SELECT stage,reason,deterministic FROM funnel_events "
                         "WHERE action IN ('kill','defer','merge')"):
        assert r["reason"].strip(), f"{r['stage']} suppressed something without a reason"
        assert r["deterministic"] in (0, 1)


# ---------------------------------------------------------------- specific stages

def test_local_dev_fixture_kills_compose_defaults_but_not_real_leaks(con):
    """Seat 3's reportability test. A credential authenticating to a database the same
    file started ninety seconds ago is not a leaked credential."""
    fixture = add(con, "gitleaks", "generic-api-key", "deploy/docker-compose.yml", 16,
                  "generic api key", secret="root_pg_password")
    real = add(con, "gitleaks", "aws-access-token", "nettacker/core/config.py", 12,
               "aws access token", secret="AKIAIOSFODNN7EXAMPLE")
    funnel.run(con, 1)
    alive = {r["id"] for r in con.execute("SELECT id FROM live_occurrences")}
    assert fixture not in alive
    assert real in alive, "a specific detector outside a dev path must never be suppressed here"
    det = con.execute("SELECT deterministic FROM funnel_events WHERE occurrence_id=? "
                      "AND stage='local-dev-fixture'", (fixture,)).fetchone()["deterministic"]
    assert det == 0, "a path-based guess about intent is a recall risk, not a determination"


@pytest.mark.parametrize("value", ["password", "Changeme", "123456", "postgres", "root"])
def test_local_dev_fixture_kills_known_placeholders(con, value):
    """REGRESSION. The old pattern was anchored and matched against the 4-character
    prefix, so `password`, `changeme` and `123456` could never match."""
    oid = add(con, "gitleaks", "generic-api-key", "docker-compose.yml", 5, secret=value)
    funnel.run(con, 1)
    assert oid not in {r["id"] for r in con.execute("SELECT id FROM live_occurrences")}


@pytest.mark.parametrize("path", ["deploy/k8s/secret.yaml", "docs/setup.md",
                                  "dev/config.env", "docker-compose.prod.yml"])
def test_random_key_on_a_dev_path_survives(con, path):
    """REGRESSION. Any `generic` detector on a dev path was killed, whatever the value:
    a real random key committed under deploy/ was suppressed as a fixture."""
    oid = add(con, "gitleaks", "generic-api-key", path, 5,
              secret="pa55_9fK2xQ7vLm3RtY8wZ1nB4cD6eH0jS")
    funnel.run(con, 1)
    assert oid in {r["id"] for r in con.execute("SELECT id FROM live_occurrences")}


def test_corroboration_is_boost_only_and_never_demotes_n_of_1(con):
    """The findings that justify the product — a missing authz decorator, a cross-file
    taint chain — have corroboration N=1 by construction."""
    solo = add(con, "zizmor", "zizmor/excessive-permissions", ".github/workflows/ci.yml", 4)
    a = add(con, "bandit", "B113", "src/net.py", 42)
    b = add(con, "opengrep", "python.requests.best-practice.use-timeout", "src/net.py", 42)
    funnel.run(con, 1)
    scores = {r["occurrence_id"]: r["score"] for r in con.execute(
        "SELECT occurrence_id, score FROM occurrence_rank")}
    assert scores[solo] > 0, "an N=1 finding must never be pushed negative by corroboration"
    assert scores[a] > scores[solo], "genuinely independent agreement is evidence"
    assert all(r["score_delta"] >= 0 for r in con.execute(
        "SELECT score_delta FROM funnel_events WHERE stage='independence-corroboration'"))


def test_quote_verify_kills_findings_with_no_capturable_evidence(con):
    ghost = add(con, "opengrep", "r", "src/gone.py", 10, blob=False)
    funnel.run(con, 1)
    alive = {r["id"] for r in con.execute("SELECT id FROM live_occurrences")}
    assert ghost not in alive


def test_dismissed_producer_is_disabled_not_deleted(con):
    oid = add(con, "bandit", "B101", "src/app.py", 5)
    con.execute("UPDATE producers SET enabled=0 WHERE id='bandit:B101'")
    funnel.run(con, 1)
    assert con.execute("SELECT COUNT(*) c FROM live_occurrences").fetchone()["c"] == 0
    assert con.execute("SELECT COUNT(*) c FROM producers WHERE id='bandit:B101'").fetchone()["c"] == 1
    reason = con.execute("SELECT reason FROM funnel_events WHERE occurrence_id=? "
                         "AND action='kill'", (oid,)).fetchone()["reason"]
    assert "dismissed" in reason


def test_independence_classes_collapse_shared_lineage():
    ic = funnel.independence_class
    assert ic("opengrep", "generic.secrets.gitleaks.generic-api-key") == ic("gitleaks", "generic-api-key")
    assert ic("osv-scanner", "CVE-1") == ic("grype", "CVE-1") == ic("trivy", "CVE-1")
    assert ic("bandit", "B303") == ic("opengrep", "python.lang.security.audit.md5-used")
    assert ic("zizmor", "zizmor/artipacked") != ic("opengrep", "javascript.x")


def test_funnel_refuses_to_run_twice_on_one_run(con):
    """REGRESSION. A second pass doubled every score in occurrence_rank and re-killed
    findings an operator had resurrected, because its kills land after the resurrect."""
    oid = add(con, "bandit", "B101", "tests/test_x.py", 5)
    add(con, "bandit", "B113", "src/net.py", 42)
    funnel.run(con, 1)
    db.funnel(con, 1, occurrence_id=oid, stage="operator", action="resurrect",
              reason="production code", deterministic=False, actor="jerry")
    scores = dict(con.execute("SELECT occurrence_id, score FROM occurrence_rank").fetchall())
    events = con.execute("SELECT COUNT(*) FROM funnel_events").fetchone()[0]

    with pytest.raises(funnel.FunnelAlreadyRan, match="already been through the funnel"):
        funnel.run(con, 1)
    assert dict(con.execute("SELECT occurrence_id, score FROM occurrence_rank").fetchall()) == scores
    assert con.execute("SELECT COUNT(*) FROM funnel_events").fetchone()[0] == events
    assert oid in {r["id"] for r in con.execute("SELECT id FROM live_occurrences")}


def test_operator_events_before_the_funnel_do_not_block_it(con):
    oid = add(con, "bandit", "B113", "src/net.py", 42)
    db.funnel(con, 1, occurrence_id=oid, stage="operator", action="kill",
              reason="dismissed", deterministic=False, actor="operator")
    funnel.run(con, 1)
