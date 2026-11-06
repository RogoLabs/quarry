"""IMPROVEMENT-PLAN item 19: the HEAD re-check. Opt-in, one `git ls-remote <url> HEAD`
through ingest's hardened git and sandbox profile, on the egress ledger before it leaves,
and stated in every draft either way. No test here reaches the network: the runner is a
stand-in, and the default runner's argv is checked without running it.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quarry import db                                                   # noqa: E402
from quarry.disclosure import draft_reports, head                       # noqa: E402
from test_disclosure import _confirm, _db                               # noqa: E402

OBSERVED = "deadbee"          # what test_disclosure._db records as runs.git_sha
SAME = "d" * 40
NEW = "a" * 40


@pytest.fixture(autouse=True)
def _no_live_vulndb(tmp_path, monkeypatch):
    """draft_reports reads the local OSV copy; keep it off the operator's synced one."""
    monkeypatch.setenv("QUARRY_DBS", str(tmp_path / "no-vulndb"))


def _runs_at(con, sha):
    with db.tx(con):
        con.execute("UPDATE runs SET git_sha=? WHERE id=1", (sha,))


def _runner(out, rc=0, seen=None):
    def run(rundir, argv, timeout):
        if seen is not None:
            seen.append((rundir, argv, timeout))
        return rc, out
    return run


def _egress(con):
    return [dict(r) for r in con.execute("SELECT stage, destination, note FROM egress")]


def test_the_check_is_ledgered_before_it_leaves_and_uses_ingests_git(tmp_path):
    con, _ = _db(tmp_path)
    _runs_at(con, SAME)
    seen = []

    def run(rundir, argv, timeout):
        # The ledger row exists before the request is made.
        assert [e["stage"] for e in _egress(con)] == [head.STAGE]
        return _runner(f"{SAME}\tHEAD\n", seen=seen)(rundir, argv, timeout)
    hc = head.check_head(con, 1, tmp_path, runner=run)
    assert hc.checked and hc.moved is False and hc.head == SAME and hc.host == "github.com"
    [(rundir, argv, timeout)] = seen
    assert argv == ["/usr/bin/git", "-c", "core.hooksPath=/dev/null",
                    "-c", "protocol.file.allow=never", "-c", "protocol.ext.allow=never",
                    "-c", "credential.helper=", "ls-remote",
                    "https://github.com/acme/widgets", "HEAD"]
    assert _egress(con) == [{"stage": "report-head-check", "destination": "github.com",
                             "note": "git ls-remote HEAD for the advisory draft; "
                                     "anonymous https, no credential"}]
    rec = db.read_manifest(con, 1)["report"]["head_check"]
    assert rec["checked"] is True and rec["moved"] is False and rec["head"] == SAME


def test_the_default_runner_is_the_clone_sandbox(tmp_path, monkeypatch):
    import quarry.sandbox as sandbox
    calls = []

    class Res:
        returncode = 0

        def stdout_bytes(self, cap):
            return f"{NEW}\tHEAD\n".encode()

    def fake_tier1(rundir, argv, **kw):
        calls.append((rundir, argv, kw))
        return Res()
    monkeypatch.setattr(sandbox, "tier1", fake_tier1)
    con, _ = _db(tmp_path)
    _runs_at(con, SAME)
    hc = head.check_head(con, 1, tmp_path)
    assert hc.moved is True and hc.head == NEW
    [(rundir, argv, kw)] = calls
    assert kw["profile"] == sandbox.CLONE_PROFILE and kw["name"] == "head-check"
    assert kw["env"] == {"GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "/usr/bin/true"}


@pytest.mark.parametrize("url, sha, why", [
    ("https://github.com/acme/widgets", None, "the run recorded no commit to compare"),
    ("https://user:pw@git.example.test/x/y", SAME, "not a plain https URL"),
    ("ssh://git.test/x/y", SAME, "not a plain https URL"),
], ids=["no-commit", "credential-in-url", "not-https"])
def test_nothing_leaves_when_there_is_nothing_honest_to_ask(tmp_path, url, sha, why):
    con, _ = _db(tmp_path)
    with db.tx(con):
        con.execute("UPDATE runs SET clone_url=?, git_sha=? WHERE id=1", (url, sha))
    hc = head.check_head(con, 1, tmp_path, runner=_runner("x", rc=99))
    assert not hc.checked and why in hc.reason
    assert _egress(con) == []                       # no request, so no ledger row


@pytest.mark.parametrize("out, rc, why", [
    ("", 128, "git ls-remote failed (exit 128)"),
    ("not a sha\tHEAD\n", 0, "git ls-remote returned no HEAD"),
], ids=["git-failed", "no-head"])
def test_a_failed_check_is_a_stated_reason_and_still_ledgered(tmp_path, out, rc, why):
    con, _ = _db(tmp_path)
    _runs_at(con, SAME)
    hc = head.check_head(con, 1, tmp_path, runner=_runner(out, rc=rc))
    assert not hc.checked and hc.reason == why and hc.moved is None
    assert len(_egress(con)) == 1                   # the attempt left the machine


def _section(md, title):
    return md.split(f"\n## {title}\n", 1)[1].split("\n## ", 1)[0].strip()


def test_drafts_say_what_the_check_found(tmp_path):
    con, src = _db(tmp_path)
    _confirm(con, "f1")
    _confirm(con, "f2")
    _runs_at(con, SAME)
    calls = []

    def check():
        calls.append(1)
        return head.check_head(con, 1, tmp_path, runner=_runner(f"{NEW}\tHEAD\n"))
    drafts = draft_reports(con, 1, src, out_dir=tmp_path / "r", check_head=check)
    assert len(drafts) == 2 and calls == [1]        # one request for the whole report
    text = drafts[0].path.read_text()
    versions = _section(text, "Affected versions")
    assert f"and is now `{NEW}`, not the observed commit" in versions
    assert "The issue was not re-tested there" in versions
    assert f"HEAD has since moved to `{NEW}`, where it was not re-tested." in text
    _runs_at(con, NEW)
    same = draft_reports(con, 1, src, out_dir=tmp_path / "s", check_head=lambda: head
                         .check_head(con, 1, tmp_path, runner=_runner(f"{NEW}\tHEAD\n")))
    versions = _section(same[0].path.read_text(), "Affected versions")
    assert "is still the observed commit. Only the commit was compared" in versions


def test_without_the_flag_nothing_is_asked_and_the_draft_says_why(tmp_path):
    con, src = _db(tmp_path)
    _confirm(con, "f1")
    text = draft_reports(con, 1, src, out_dir=tmp_path / "r")[0].path.read_text()
    assert ("Current HEAD was not re-checked: report drafting makes no network request "
            "unless run with --check-head.") in text
    assert "current HEAD was not re-checked (report drafting makes no network" in text
    assert _egress(con) == [] and "report" not in db.read_manifest(con, 1)


def test_no_draft_means_no_request(tmp_path):
    con, src = _db(tmp_path)
    calls = []
    assert draft_reports(con, 1, src, out_dir=tmp_path / "r",
                         check_head=lambda: calls.append(1)) == []
    assert calls == []


def test_a_failed_check_reads_as_not_re_checked_with_its_reason(tmp_path):
    con, src = _db(tmp_path)
    _confirm(con, "f1")
    _runs_at(con, SAME)
    text = draft_reports(con, 1, src, out_dir=tmp_path / "r", check_head=lambda: head
                         .check_head(con, 1, tmp_path, runner=_runner("", rc=128))
                         )[0].path.read_text()
    assert "Current HEAD was not re-checked: git ls-remote failed (exit 128)." in text
    rec = json.loads(json.dumps(db.read_manifest(con, 1)["report"]["head_check"]))
    assert rec["checked"] is False and rec["reason"] == "git ls-remote failed (exit 128)"


def test_the_cli_asks_only_with_check_head(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from typer.testing import CliRunner
    import quarry.disclosure as disclosure
    from quarry import cli
    from quarry.ingest import RunVolume
    monkeypatch.setattr(RunVolume, "attach_existing", classmethod(
        lambda cls, run_id, images_dir: SimpleNamespace(src=tmp_path / "src",
                                                        mount=tmp_path)))
    seen: list = []

    def drafts(con, run_id, src, *, out_dir, check_head=None):
        seen.append(check_head)
        if check_head is not None:
            check_head()
        return []
    monkeypatch.setattr(disclosure, "draft_reports", drafts)
    monkeypatch.setattr(disclosure, "draft_research_digest",
                        lambda con, run_id, out_dir: None)
    monkeypatch.setattr(head, "check_head", lambda con, run_id, rundir: head.HeadCheck(
        True, observed=SAME, head=NEW, host="github.com", at="2026-11-06T00:00:00+00:00"))
    plain = CliRunner().invoke(cli.app, ["report", "1"], env={"COLUMNS": "200"})
    asked = CliRunner().invoke(cli.app, ["report", "1", "--check-head"],
                               env={"COLUMNS": "200"})
    assert plain.exit_code == 0 and asked.exit_code == 0, (plain.output, asked.output)
    assert seen[0] is None and callable(seen[1])
    assert "HEAD re-check" not in plain.output
    assert "HEAD re-check: moved to aaaaaaaaaaaa since the run's dddddddddddd" in asked.output
