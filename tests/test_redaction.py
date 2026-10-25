"""Secret redaction across the whole run, not just a record's own secret.

D16 says secret material never reaches the database in plaintext. Each test here is a
path by which it did: a window built by another tool before Gitleaks ran, a
neighbouring Gitleaks hit inside the same window, a CRLF key or a zero-width
character that stopped the match, and a tool's own quote of the line in raw_result.
"""
from __future__ import annotations

import gzip
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quarry import db, orchestrator, taint                 # noqa: E402
from quarry.scanners import base, tools                     # noqa: E402
from quarry.scanners.base import Record, ScanOutcome        # noqa: E402

KEY_A = "ghp_AAAAbbbbCCCCddddEEEEffffGGGGhhhh1234"
KEY_B = "xoxb-1111-2222-ZZZZyyyyXXXXwwww"


@pytest.fixture
def volume(tmp_path: Path) -> Path:
    """A run volume as the orchestrator sees it: src/ for the clone, out/ for tools."""
    (tmp_path / "src").mkdir()
    (tmp_path / "out").mkdir()
    lines = [f"x{i} = {i}" for i in range(1, 30)]
    lines[9] = f"TOKEN = '{KEY_A}'"           # line 10
    lines[11] = f"SLACK = '{KEY_B}'"          # line 12
    lines[13] = "eval(user_input)"            # line 14: a SAST hit near both
    (tmp_path / "src" / "app.py").write_text("\n".join(lines) + "\n")
    return tmp_path


def _gitleaks_report(vol: Path, *hits: tuple[str, int]) -> None:
    (vol / "out" / "gitleaks.json").write_text(json.dumps([
        {"RuleID": "generic-api-key", "File": str(vol / "src" / "app.py"),
         "StartLine": ln, "EndLine": ln, "Secret": s, "Match": f"'{s}'",
         "Line": f"X = '{s}'", "Description": "key", "Fingerprint": f"app.py:x:{ln}"}
        for s, ln in hits]))


def _body(ev: taint.Evidence) -> str:
    return gzip.decompress(ev.body).decode()


def test_window_of_another_tool_is_redacted_from_the_run_report(volume):
    """A bandit/opengrep/deep window on the same lines as a Gitleaks hit carried the
    plaintext, because only a record's own secret was redacted."""
    _gitleaks_report(volume, (KEY_A, 10), (KEY_B, 12))
    ev = taint.extract_evidence(volume / "src", Path("app.py"), 14)      # no secrets passed
    body = _body(ev)
    assert KEY_A not in body and KEY_B not in body
    assert "«redacted:ghp_" in body and "«redacted:xoxb" in body


def test_neighbouring_gitleaks_hit_is_redacted_in_the_window(volume):
    """Gitleaks hit A's window contains hit B two lines down."""
    ev = taint.extract_evidence(volume / "src", Path("app.py"), 10, secrets=[KEY_A, KEY_B])
    body = _body(ev)
    assert KEY_A not in body and KEY_B not in body


def test_crlf_pem_key_is_redacted(tmp_path):
    """REGRESSION. splitlines/join dropped the \\r of a CRLF key before redaction ran,
    so the Gitleaks match (which keeps \\r\\n) never matched the window."""
    key = ("-----BEGIN RSA PRIVATE KEY-----\r\n"
           "MIIEowIBAAKCAQEAsecretsecretsecretsecretsecret\r\n"
           "-----END RSA PRIVATE KEY-----")
    (tmp_path / "k.pem").write_bytes(f"before\r\n{key}\r\nafter-line-5\r\n".encode())
    ev = taint.extract_evidence(tmp_path, Path("k.pem"), 2, secrets=[key])
    body = _body(ev)
    assert "MIIEowIBAAKCAQEA" not in body
    # The placeholder keeps the key's line breaks, so later lines keep their numbers.
    assert body.split("\n")[4] == "after-line-5"


def test_secret_containing_zero_width_characters_is_redacted(tmp_path):
    """REGRESSION. The scrub removed the zero-width character before redaction, so the
    raw secret no longer matched and its scrubbed form went into the DB."""
    secret = "sk_live_​ABCDEFGHIJKLMNOP"
    (tmp_path / "c.py").write_text(f"a = 1\nKEY = '{secret}'\nb = 2\n")
    ev = taint.extract_evidence(tmp_path, Path("c.py"), 2, secrets=[secret])
    body = _body(ev)
    assert "ABCDEFGHIJKLMNOP" not in body
    # Text that was already scrubbed (a tool message) is caught too.
    assert "ABCDEFGHIJKLMNOP" not in taint.redact_in(taint.scrub_text(f"x {secret}"), [secret])


def test_bandit_code_and_sarif_snippet_do_not_reach_raw_result(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text("x = 1\n")
    out = tmp_path / "bandit.json"
    out.write_text(json.dumps({"results": [{
        "filename": str(src / "a.py"), "test_id": "B105", "line_number": 1,
        "issue_text": "hardcoded password", "issue_severity": "LOW",
        "code": f"1 PASSWORD = '{KEY_A}'\n"}]}))
    rec = next(iter(tools.Bandit().parse(out, src)))
    assert "code" not in rec.raw and KEY_A not in json.dumps(rec.raw)

    sarif = {"runs": [{"tool": {"driver": {"rules": []}}, "results": [{
        "ruleId": "r", "message": {"text": "m"},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "a.py"},
            "region": {"startLine": 1, "snippet": {"text": KEY_A}},
            "contextRegion": {"startLine": 1, "snippet": {"text": KEY_A}}}}]}]}]}
    rec = next(iter(base.sarif_records(sarif, src, "opengrep")))
    assert KEY_A not in json.dumps(rec.raw)
    assert rec.raw["locations"][0]["physicalLocation"]["region"]["startLine"] == 1


def test_gitleaks_runs_first():
    assert tools.ALL[0] is tools.Gitleaks


class _Fake:
    def __init__(self, name, records):
        self.name, self._records = name, records

    def run(self, rundir, src, *, timeout=1800):
        if self.name == "gitleaks":
            _gitleaks_report(rundir, (KEY_A, 10), (KEY_B, 12))
        return ScanOutcome(self.name, True, 0, 0.1, list(self._records))


def test_scan_redacts_every_run_secret_whatever_the_tool_order(volume, tmp_path, monkeypatch):
    """End to end through orchestrator.scan. The registry lists bandit before
    gitleaks; the scan must still know both secrets before bandit's window is built,
    and must keep them out of the message and raw_result too."""
    con = db.init(tmp_path / "t.db")
    con.execute("INSERT INTO runs (id,target,clone_url,git_sha,status) "
                "VALUES (1,'o/r','https://x','abc','done')")
    bandit = Record(tool="bandit", rule_id="B307", path="app.py", start_line=14,
                    message=f"eval near {KEY_B}", raw={"code": "x", "quote": KEY_A})
    leak = Record(tool="gitleaks", rule_id="generic-api-key", path="app.py",
                  start_line=10, secret=KEY_A, raw={})
    fakes = {"bandit": _Fake("bandit", [bandit]), "gitleaks": _Fake("gitleaks", [leak])}
    monkeypatch.setattr("quarry.scanners.registry", lambda: fakes)
    monkeypatch.setattr(orchestrator.RunVolume, "attach_existing",
                        classmethod(lambda cls, rid, runs: SimpleNamespace(
                            mount=volume, src=volume / "src")))

    orchestrator.scan(SimpleNamespace(runs=tmp_path), con, 1)

    for row in con.execute("SELECT body FROM evidence_blobs"):
        body = gzip.decompress(row["body"]).decode()
        assert KEY_A not in body and KEY_B not in body
    for row in con.execute("SELECT message, raw_result FROM occurrences"):
        for text in (row["message"] or "", row["raw_result"]):
            assert KEY_A not in text and KEY_B not in text
