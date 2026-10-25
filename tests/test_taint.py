"""Taint-boundary tests.

Everything a tool writes is target-influenced. These assert the four refusals that
stop a malformed or malicious tool result from becoming a filesystem read, a terminal
escape sequence, or a plaintext secret in the database.
"""
from __future__ import annotations

import gzip
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quarry import taint                                  # noqa: E402
from quarry.scanners.base import rel_or_none              # noqa: E402


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "x.py").write_text("\n".join(f"line {i}" for i in range(1, 120)))
    return tmp_path


@pytest.mark.parametrize("uri", [
    "/etc/passwd",                 # absolute
    "../../etc/passwd",            # traversal
    "file:///etc/shadow",          # scheme + absolute
    "https://evil.example/x",      # remote scheme
    "app/\x1b[31mevil.py",         # ANSI in a path
    "app/x\x00.py",                # NUL
])
def test_hostile_paths_are_refused(tree, uri):
    with pytest.raises(taint.TaintError):
        taint.safe_relpath(uri, tree)


def test_legitimate_paths_survive(tree):
    assert str(taint.safe_relpath("app/x.py", tree)) == "app/x.py"
    assert str(taint.safe_relpath("app/../app/x.py", tree)) == "app/x.py"


def test_absolute_paths_under_the_root_are_relativised(tree):
    """Tools handed an absolute scan root report absolute paths; that is normal and
    must not cost us the finding. Anything absolute *outside* the root still dies."""
    assert rel_or_none(str(tree / "app" / "x.py"), tree) == "app/x.py"
    assert rel_or_none("/etc/passwd", tree) is None
    assert rel_or_none(f"file://{tree}/app/x.py", tree) == "app/x.py"


def test_control_characters_are_stripped():
    out = taint.scrub_text("safe\x1b[31mred\x00nul\x07bell\ttab\nnewline")
    assert "\x1b" not in out and "\x00" not in out and "\x07" not in out
    assert "\t" in out and "\n" in out      # real whitespace survives


@pytest.mark.parametrize("label,raw", [
    ("zero-width space", "a\u200bb"),
    ("RTL override (Trojan Source)", "a\u202eb"),
    ("BOM / ZWNBSP", "a\ufeffb"),
    ("Unicode tag block", "a\U000e0001b"),
    ("bidi isolate", "a\u2066b"),
    ("word joiner", "a\u2060b"),
])
def test_invisible_and_bidi_characters_are_stripped(label, raw):
    """REGRESSION. The scrubber originally covered only C0/C1, so every one of these
    survived. U+202E is Trojan Source (CVE-2021-42574) — it reorders rendered text so
    the code a reviewer reads is not the code that runs. The zero-width and tag-block
    ranges hide text from every renderer. This matters most for Layer 2R, where an
    agentic model reads the text and acts on it."""
    assert taint.scrub_text(raw) == "ab", f"{label} survived the scrubber"


def test_ordinary_unicode_is_not_mangled():
    """The scrubber must not eat legitimate non-ASCII — accented identifiers, CJK
    comments and emoji in source are all normal."""
    for s in ("café", "変数名", "naïve_impl", "# 🚀 fast path", "Ω = 1"):
        assert taint.scrub_text(s) == __import__("unicodedata").normalize("NFC", s)


def test_long_fields_are_truncated_visibly():
    out = taint.scrub_text("A" * 20_000, limit=100)
    assert len(out) < 200 and out.endswith("chars]")


def test_secret_is_never_stored_whole():
    s = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    r = taint.redact_secret(s)
    assert r.prefix == "ghp_" and len(r.prefix) == 4
    assert s not in r.placeholder
    assert r.sha256 == __import__("hashlib").sha256(s.encode()).hexdigest()


def test_evidence_window_is_redacted(tmp_path):
    """D16 + Seat 4's catch: a ±40-line window around a Gitleaks hit contains the
    secret, so redaction must run at the same boundary as extraction."""
    secret = "AKIAIOSFODNN7EXAMPLE"
    (tmp_path / "conf.py").write_text(f"pre\nAWS_KEY = '{secret}'\npost\n")
    ev = taint.extract_evidence(tmp_path, Path("conf.py"), 2, secrets=[secret])
    body = gzip.decompress(ev.body).decode()
    assert secret not in body
    assert "«redacted:AKIA" in body


def test_finding_id_is_line_number_free_and_symbol_sensitive():
    a = taint.finding_id("o/r", "a.py", "bandit:B311", "sym-hash-1")
    b = taint.finding_id("o/r", "a.py", "bandit:B311", "sym-hash-1")
    c = taint.finding_id("o/r", "a.py", "bandit:B311", "sym-hash-2")
    assert a == b, "same symbol content must yield the same finding_id across runs"
    assert a != c, "changed symbol content must yield a new finding_id"


def test_oversized_tool_output_is_refused(tmp_path):
    big = tmp_path / "huge.json"
    big.write_bytes(b"x" * 2048)
    with pytest.raises(taint.TaintError):
        taint.read_capped(big, cap=1024)


def test_malformed_json_is_refused_not_crashed(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    with pytest.raises(taint.TaintError):
        taint.load_json(bad)


@pytest.mark.parametrize("label,raw", [
    ("Arabic letter mark", "a؜b"),
    ("line separator", "a b"),
    ("paragraph separator", "a b"),
    ("soft hyphen", "a­b"),
    ("Mongolian vowel separator", "a᠎b"),
    ("Hangul filler", "aㅤb"),
])
def test_remaining_invisible_characters_are_stripped(label, raw):
    """REGRESSION. These survived the scrubber: each renders as nothing (or as a line
    break only some parsers honour), and U+3164 is a valid JavaScript identifier."""
    assert taint.scrub_text(raw) == "ab", f"{label} survived the scrubber"
    with pytest.raises(taint.TaintError):
        taint.safe_relpath(f"app/{raw}.py", Path("/nonexistent"))


def test_tool_output_is_never_read_through_a_symlink(tmp_path):
    """A sandboxed child can swap out/<tool>.json for a link to a host file; the
    unsandboxed parent must refuse it rather than parse the host file."""
    from quarry.taint import TaintError, load_json
    host = tmp_path / "host-secret.json"
    host.write_text('{"secret": "host"}')
    out = tmp_path / "out"
    out.mkdir()
    (out / "tool.json").symlink_to(host)
    with pytest.raises(TaintError):
        load_json(out / "tool.json")
    (out / "real.json").write_text('{"ok": 1}')
    assert load_json(out / "real.json") == {"ok": 1}
