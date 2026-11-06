"""Regression tests for the hermetic half of the sandbox-hardening pass.

Three classes of defect, each proven by a reviewer before it was fixed:

  * model output naming a host path (`/etc/hosts`, `../../../../etc/hosts`) was read
    UNSANDBOXED by the research layer and stored as evidence;
  * an ollama model name ending in `-cloud` or tagged `:cloud` sends the prompt, i.e.
    the target's source, to ollama.com with no egress record;
  * `hdiutil detach` had no timeout, so a held volume could hang the orchestrator.

No sandbox, no network, no model: everything external is either a temp file or a
monkeypatched subprocess.run that fails the test if it is reached when it must not be.
"""
from __future__ import annotations

import gzip
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quarry import db, targets                              # noqa: E402
from quarry.ingest import volume as V                       # noqa: E402
from quarry.research import ensemble as E                   # noqa: E402
from quarry.research import runner                          # noqa: E402

HOSTS = Path("/etc/hosts")
# The deep `../` form is the one that bites at pytest's tmp_path depth: `..` at `/`
# stays at `/`, so enough of them always land on /etc/hosts.
ESCAPES = ["/etc/hosts", "../../../../etc/hosts", "../" * 24 + "etc/hosts",
           "file:///etc/hosts", "pkg/" + "../" * 24 + "etc/hosts"]


def _hosts_line() -> str:
    """A real line from /etc/hosts, so a quote check that reached the file WOULD pass.
    Without that the escape tests could not tell a fix from a miss."""
    if not HOSTS.is_file():
        pytest.skip("/etc/hosts not present")
    for line in HOSTS.read_text(errors="replace").splitlines():
        if line.strip() and not line.lstrip().startswith("#"):
            return line
    pytest.skip("/etc/hosts has no non-comment line")


@pytest.fixture
def src(tmp_path):
    root = tmp_path / "src"
    (root / "pkg").mkdir(parents=True)
    (root / "pkg" / "a.py").write_text("import os\nx = os.getenv('X')\n")
    return root


def _finding(file: str, quote: str) -> E.Finding:
    return E.Finding(lens="injection", model="qwen3-coder:30b", title="t", file=file,
                     quote=quote, severity="high", reasoning="r", attacker_control="a",
                     why_it_might_be_wrong="w", line=1)


# ------------------------------------------------------------------ verify_quote

@pytest.mark.parametrize("path", ESCAPES)
def test_verify_quote_never_reads_outside_the_clone(src, path):
    line = _hosts_line()
    assert " ".join(line.split()) in " ".join(HOSTS.read_text().split())   # it would match
    assert E.verify_quote(_finding(path, line), src) is False


def test_verify_quote_does_not_read_through_a_symlink(src):
    line = _hosts_line()
    (src / "pkg" / "hosts").symlink_to(HOSTS)
    assert E.verify_quote(_finding("pkg/hosts", line), src) is False


def test_verify_quote_glob_characters_are_literal(src):
    """A model-supplied `*` must not become a walk of the whole tree."""
    assert E.verify_quote(_finding("*", "x = os.getenv('X')"), src) is False


def test_verify_quote_still_verifies_a_real_quote(src):
    assert E.verify_quote(_finding("pkg/a.py", "x = os.getenv('X')"), src) is True
    # basename fallback, which models rely on when they drop the directory
    assert E.verify_quote(_finding("a.py", "x = os.getenv('X')"), src) is True


# ------------------------------------------------------------------ _persist

@pytest.fixture
def con(tmp_path):
    p = tmp_path / "quarry.db"
    db.init(p)
    c = db.connect(p)
    with db.tx(c):
        c.execute("INSERT INTO runs (id, target, clone_url, git_sha) "
                  "VALUES (1,'o/r','https://x','abc')")
        c.execute("INSERT INTO research_runs (id, run_id) VALUES (1, 1)")
    return c


def test_persist_drops_findings_whose_path_escapes_the_clone(con, src):
    line = _hosts_line()
    found = [_finding(p, line) for p in ESCAPES]
    found.append(_finding("pkg/a.py", "x = os.getenv('X')"))
    runner._persist(con, 1, 1, {"subsystem": "core"}, found, src)

    files = [r["file"] for r in con.execute("SELECT file FROM research_findings")]
    assert files == ["pkg/a.py"]
    paths = [r["path"] for r in con.execute("SELECT path FROM occurrences")]
    assert paths == ["pkg/a.py"]
    blobs = con.execute("SELECT path, body FROM evidence_blobs").fetchall()
    assert [b["path"] for b in blobs] == ["pkg/a.py"]
    for b in blobs:
        assert line.encode() not in gzip.decompress(b["body"]), "host file stored as evidence"


# ------------------------------------------------------------------ cloud models

CLOUD = ["gpt-oss:120b-cloud", "qwen3-coder:480b-cloud", "deepseek-v3.1:671b-cloud",
         "kimi-k2:cloud", "glm-4.6:cloud", "Some-CLOUD-Model:latest"]


@pytest.mark.parametrize("model", CLOUD)
def test_cloud_models_are_refused_before_any_request(model, monkeypatch):
    def no_request(*a, **k):
        raise AssertionError("a request was made for a cloud model")
    monkeypatch.setattr(E.subprocess, "run", no_request)
    with pytest.raises(E.CloudModelRefused, match="ollama.com"):
        E.call(model, "prompt", None)


@pytest.mark.parametrize("model", ["qwen3-coder:30b", "gpt-oss:20b", "devstral:24b"])
def test_local_models_pass_the_guard(model):
    assert E.check_local_model(model) == model


# ------------------------------------------------------------------ curl hygiene

def _fake_run(seen: list, stdout: str):
    def run(argv, **kw):
        seen.append(argv)
        return subprocess.CompletedProcess(argv, 0, stdout=stdout, stderr="")
    return run


def test_ollama_curl_ignores_curlrc_and_proxies(monkeypatch):
    seen: list = []
    monkeypatch.setattr(E.subprocess, "run", _fake_run(
        seen, json.dumps({"response": '{"findings": []}', "done_reason": "stop"})))
    E.call("qwen3-coder:30b", "prompt", None)
    # call() may probe `ollama show <model>` for the thinking capability first; the curl
    # hygiene we are asserting is on the generate request, so find that call.
    argv = next(a for a in seen if a and a[0] == "curl")
    assert argv[:2] == ["curl", "-q"], "-q only works as the FIRST argument"
    i = argv.index("--noproxy")
    assert argv[i + 1] == "*"
    assert E.OLLAMA in argv


def test_public_json_curl_ignores_curlrc(monkeypatch):
    seen: list = []
    monkeypatch.setattr(targets.subprocess, "run", _fake_run(seen, "{}"))
    targets._http_json("https://example.invalid/x.json")
    assert seen[0][:2] == ["curl", "-q"]
    # a public host: a configured proxy is the operator's call, so it is NOT bypassed
    assert "--noproxy" not in seen[0]


def test_length_truncation_is_retried_with_a_bigger_budget(monkeypatch):
    # A thinking model that ignores think:false spends its whole budget on a reasoning
    # trace and truncates (done_reason=length) before the JSON. call() must retry once
    # with room for trace+answer and recover the result, not error the unit. Regression:
    # qwen3.6:27b failed 42 units this exact way on run 3.
    monkeypatch.setattr(E, "supports_thinking", lambda m: False)  # keep to generate calls
    budgets: list = []
    answer = json.dumps({"findings": []})

    def run(argv, **kw):
        body = json.loads(argv[argv.index("-d") + 1])
        budgets.append(body["options"]["num_predict"])
        done = "length" if len(budgets) == 1 else "stop"      # first truncates, retry ok
        resp = "" if done == "length" else answer
        out = json.dumps({"response": resp, "done_reason": done})
        return subprocess.CompletedProcess(argv, 0, stdout=out, stderr="")

    monkeypatch.setattr(E.subprocess, "run", run)
    resp, meta = E.call("qwen3-coder:30b", "prompt", E.FINDING_SCHEMA, num_predict=2200)
    assert len(budgets) == 2, "a length truncation must trigger exactly one retry"
    assert budgets[0] == 2200 and budgets[1] >= 8192 and budgets[1] > budgets[0]
    assert resp == answer                          # the unit recovers instead of erroring
    assert meta.get("length_retry_num_predict") == budgets[1]


def test_a_clean_first_response_makes_no_length_retry(monkeypatch):
    # The retry must fire only on truncation: a model that answers cleanly is called once.
    monkeypatch.setattr(E, "supports_thinking", lambda m: False)
    calls: list = []

    def run(argv, **kw):
        calls.append(argv)
        out = json.dumps({"response": json.dumps({"findings": []}), "done_reason": "stop"})
        return subprocess.CompletedProcess(argv, 0, stdout=out, stderr="")

    monkeypatch.setattr(E.subprocess, "run", run)
    _, meta = E.call("qwen3-coder:30b", "prompt", E.FINDING_SCHEMA, num_predict=2200)
    assert len(calls) == 1
    assert "length_retry_num_predict" not in meta


# ------------------------------------------------------------------ hdiutil detach

class _FakeMount:
    """Stands in for a mounted Path so no real volume is ever detached."""
    def is_mount(self) -> bool:
        return True

    def __str__(self) -> str:
        return "/private/tmp/quarry/run-fake"


def test_detach_is_bounded_and_escalates_to_force(monkeypatch):
    calls: list = []

    def run(argv, **kw):
        calls.append((argv, kw.get("timeout")))
        if len(calls) == 1:
            raise subprocess.TimeoutExpired(argv, kw.get("timeout"))
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(V.subprocess, "run", run)
    vol = V.RunVolume(1, Path(os.devnull), _FakeMount())         # type: ignore[arg-type]
    vol.detach()
    assert len(calls) == 2, "a hung detach was not retried"
    assert all(t is not None and t > 0 for _, t in calls), "an hdiutil call had no timeout"
    assert "-force" not in calls[0][0]
    assert "-force" in calls[1][0]


# A detached volume left its empty mount point behind: test runs had left 89 empty
# /private/tmp/quarry/run-9* directories when they were cleared on 2026-11-06
# (IMPROVEMENT-PLAN item 26).

def _hdiutil_ok(calls):
    def run(argv, **kw):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")
    return run


def test_detach_removes_its_own_empty_mount_point(tmp_path, monkeypatch):
    calls: list = []
    monkeypatch.setattr(V.subprocess, "run", _hdiutil_ok(calls))
    mount = tmp_path / "run-1"
    mount.mkdir()
    V.RunVolume(1, tmp_path / "1.sparseimage", mount).detach()
    assert not mount.exists()
    assert calls == []                       # not a mount, so hdiutil was not asked


def test_detach_removes_only_an_empty_unmounted_directory(tmp_path, monkeypatch):
    """rmdir only, never recursive: a mount point with anything in it, one still
    mounted after hdiutil returned, and a link planted at the path all stay."""
    monkeypatch.setattr(V.subprocess, "run", _hdiutil_ok([]))
    full = tmp_path / "run-2"
    (full / "src").mkdir(parents=True)
    (full / "src" / "a.py").write_text("x\n")
    V.RunVolume(2, tmp_path / "2.sparseimage", full).detach()
    assert (full / "src" / "a.py").is_file()

    held = tmp_path / "run-3"
    held.mkdir()
    monkeypatch.setattr(V.Path, "is_mount", lambda self: self == held)
    V.RunVolume(3, tmp_path / "3.sparseimage", held).detach()
    assert held.is_dir()
    monkeypatch.undo()

    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    link = tmp_path / "run-4"
    link.symlink_to(elsewhere)
    V.RunVolume(4, tmp_path / "4.sparseimage", link).detach()
    assert link.is_symlink() and elsewhere.is_dir()


@pytest.mark.parametrize("how", ["create", "attach_existing"])
def test_a_failed_attach_leaves_no_mount_point(tmp_path, monkeypatch, how):
    monkeypatch.setattr(V, "MOUNT_BASE", tmp_path / "mnt")

    def run(argv, **kw):
        rc = 1 if argv[1] == "attach" else 0
        return subprocess.CompletedProcess(argv, rc, "", "attach failed" if rc else "")

    monkeypatch.setattr(V.subprocess, "run", run)
    images = tmp_path / "images"
    if how == "attach_existing":
        images.mkdir()
        (images / "5.sparseimage").write_bytes(b"")
    with pytest.raises(V.VolumeError, match="attach failed"):
        getattr(V.RunVolume, how)(5, images)
    assert not (tmp_path / "mnt" / "run-5").exists()
