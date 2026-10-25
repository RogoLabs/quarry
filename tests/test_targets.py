"""Target-selection tests. Offline — the fetchers are stubbed, because a scorer whose
tests need the network is a scorer nobody runs."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quarry import targets                       # noqa: E402


def fake(monkeypatch, *, repo=None, eco=None, scorecard=None, workflows=None):
    """Stub the fetchers.

    They take a `ledger` now, and the stubs record into it exactly as the real ones
    do — so these tests also cover the egress accounting rather than merely tolerating
    its parameter. Scoring reached `repos.ecosyste.ms` and
    `api.securityscorecards.dev` without writing an `egress` row, which meant
    `quarry doctor` under-reported the product's own network destinations.
    """
    def _gh(path, timeout=20, ledger=None):
        targets._record(ledger, "api.github.com", 0)
        if path.startswith("repos/") and path.count("/") == 2:
            return repo
        if path.endswith("/contents/SECURITY.md"):
            return None
        if path.endswith("/contents/.github/workflows"):
            return workflows
        return None

    def _http(url, timeout=15, ledger=None):
        from urllib.parse import urlsplit
        targets._record(ledger, urlsplit(url).netloc, 0)
        return scorecard if "securityscorecards" in url else eco

    monkeypatch.setattr(targets, "_gh", _gh)
    monkeypatch.setattr(targets, "_http_json", _http)


APP = {"language": "Python", "stargazers_count": 5000, "pushed_at": "2026-08-20T00:00:00Z",
       "archived": False, "open_issues_count": 40, "size": 10000,
       "description": "A web API server with OAuth and file upload",
       "topics": ["api", "server", "auth"], "license": {"spdx_id": "MIT"}}
LIST = {"language": None, "stargazers_count": 300000, "pushed_at": "2026-08-22T00:00:00Z",
        "archived": False, "open_issues_count": 20, "size": 5000,
        "description": "An awesome curated list of resources", "topics": ["awesome", "list"],
        "license": {"spdx_id": "CC0-1.0"}}
ECO = {"dependent_repos_count": 900, "dependent_packages_count": 40,
       "commit_stats": {"total_committers": 50}}


def test_a_link_directory_scores_zero_however_popular(monkeypatch):
    """REGRESSION. An additive model put `sindresorhus/awesome` at 34 and a wordlist
    repo at 45, outranking real applications on stars and commit recency alone.
    Reach multiplies the value of a vulnerability; it cannot create one."""
    fake(monkeypatch, repo=LIST, eco=ECO, scorecard={"score": 3.9})
    ts = targets.score_target("sindresorhus/awesome")
    assert ts.surface == 0
    assert ts.score == 0, "no attack surface must be an absolute veto, not a deduction"


def test_a_real_application_outranks_a_more_popular_list(monkeypatch):
    fake(monkeypatch, repo=LIST, eco=ECO, scorecard=None)
    listy = targets.score_target("o/list")
    fake(monkeypatch, repo=APP, eco=ECO, scorecard=None)
    app = targets.score_target("o/app")
    assert app.score > listy.score
    assert app.surface > 20, "server + api + auth + upload is substantial surface"


def test_archived_repositories_are_zeroed(monkeypatch):
    fake(monkeypatch, repo={**APP, "archived": True}, eco=ECO)
    ts = targets.score_target("o/dead")
    assert ts.score == 0
    assert any("archived" in r for r in ts.reasons)


def test_audit_maturity_is_recorded_but_never_scored(monkeypatch):
    """Seat 6: selecting on 'no SECURITY.md, no CodeQL' begs the question the
    calibration run exists to answer, and guarantees the free-stack arm wins."""
    fake(monkeypatch, repo=APP, eco=ECO, scorecard={"score": 9.5},
         workflows=[{"name": "codeql-analysis.yml"}])
    hardened = targets.score_target("o/app")
    fake(monkeypatch, repo=APP, eco=ECO, scorecard={"score": 1.0}, workflows=[])
    soft = targets.score_target("o/app")

    assert hardened.score == soft.score, "covariates must not move the score"
    assert hardened.covariates["openssf_scorecard"] == 9.5
    assert hardened.covariates["has_codeql_workflow"] is True
    assert soft.covariates["has_codeql_workflow"] is False


def test_reach_scales_but_does_not_dominate(monkeypatch):
    fake(monkeypatch, repo=APP, eco={"dependent_repos_count": 0,
                                     "dependent_packages_count": 0,
                                     "commit_stats": {"total_committers": 1}})
    small = targets.score_target("o/app")
    fake(monkeypatch, repo=APP, eco=ECO)
    big = targets.score_target("o/app")
    assert big.score > small.score
    assert big.score < small.score * 2.5, "reach is a multiplier, capped, not a takeover"


def test_unreachable_metadata_is_an_error_not_a_zero(monkeypatch):
    """A private or rate-limited repo must not silently look like a bad target."""
    fake(monkeypatch, repo=None)
    ts = targets.score_target("o/private")
    assert not ts.ok and "unavailable" in ts.error


def test_every_score_carries_its_reasons(monkeypatch):
    fake(monkeypatch, repo=APP, eco=ECO)
    ts = targets.score_target("o/app")
    assert ts.reasons
    assert any("score = surface" in r for r in ts.reasons), "the formula must be legible"


def test_scoring_records_every_host_it_contacted(monkeypatch):
    """`quarry doctor` answers "which hosts has this tool contacted" from the
    `egress` table. Scoring reached two hosts that never wrote a row, so the answer was
    wrong on the one screen whose whole claim is that nothing leaves unrecorded.

    A failed request is still recorded: the packet left the machine either way.
    """
    import sqlite3
    from pathlib import Path
    fake(monkeypatch, repo=APP, eco=ECO, scorecard={"score": 5.0})
    ts = targets.score_target("owner/app")

    assert "api.github.com" in ts.hosts_contacted
    assert "repos.ecosyste.ms" in ts.hosts_contacted
    assert "api.securityscorecards.dev" in ts.hosts_contacted

    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    schema = Path(__file__).resolve().parents[1] / "quarry" / "schema.sql"
    con.executescript(schema.read_text())
    targets.log_egress(con, ts)
    dests = {r["destination"] for r in con.execute("SELECT destination FROM egress")}
    assert dests == set(ts.hosts_contacted)
    for r in con.execute("SELECT stage, note FROM egress"):
        assert r["stage"] == "targets-score"
        assert "owner/app" in r["note"]


def test_a_failed_fetch_is_still_recorded(monkeypatch):
    """The request happened. An error is not an absence of egress."""
    fake(monkeypatch, repo=None)
    ts = targets.score_target("owner/gone")
    assert not ts.ok
    assert "api.github.com" in ts.hosts_contacted
