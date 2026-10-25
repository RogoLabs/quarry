"""The taint boundary.

Everything a tool wrote to the run volume passes through here exactly once on its way
into the database. Upstream of this function, bytes are target-controlled. Downstream,
they are data with known shape. Seat 5, P0 step 7; Seat 4's redaction note; D15/D16.

Five jobs, in order:

1. **Cap.** The volume quota already bounds this, but a 900 MB SARIF file should fail
   loudly rather than be parsed.
2. **Sanitise.** Strip C0/C1 control characters and ESC. A tool's ``message`` field is
   target-controlled text that will be rendered in a terminal and a browser; an ANSI
   sequence there is a real attack on the operator, not a theoretical one.
3. **Validate every path.** A SARIF ``uri`` is written by a tool the target could
   influence. Reject absolute paths, reject ``..`` after normalisation, reject control
   characters, then join → resolve → prefix-check → ``lstat``. A path that resolves
   outside the run volume is discarded and recorded, never followed.
4. **Redact.** Secret material is stored as ``(prefix[:4], sha256)`` and never in
   plaintext — including inside the evidence window, because a ±40-line window around a
   Gitleaks hit contains the secret. Redaction runs at the same boundary as extraction.
5. **Extract evidence.** The enclosing ±40 lines, content-addressed and gzipped, for
   every occurrence including ones the funnel will kill.
"""
from __future__ import annotations

import functools
import gzip
import hashlib
import json
import os
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

MAX_TOOL_OUTPUT = 256 * 1024 * 1024      # a tool that writes more than this is broken
MAX_FIELD_CHARS = 8_000                  # message/snippet fields
EVIDENCE_CONTEXT = 40                    # lines either side (D15)

# C0 minus \t\n\r, plus DEL and the C1 block. ESC is in C0 and is the one that matters
# for a terminal. But a terminal is not the only renderer, and C0/C1 is not the only
# way to lie about what a line of code says:
#
#   U+202E RIGHT-TO-LEFT OVERRIDE and friends are Trojan Source (CVE-2021-42574) —
#     they reorder rendered text so the code a reviewer reads is not the code that runs;
#   U+200B..U+200F, U+FEFF are zero-width — invisible in every renderer, and enough to
#     smuggle an instruction past a human skimming an evidence window;
#   U+E0000..U+E007F is the Unicode tag block, the standard way to hide a payload in
#     text that displays as nothing at all;
#   U+00AD soft hyphen, U+061C Arabic letter mark, U+180E Mongolian vowel separator and
#     U+3164 Hangul filler render as nothing or as a blank that is not whitespace;
#     U+3164 is also a legal JavaScript identifier, the "invisible backdoor" trick;
#   U+2028/U+2029 are line and paragraph separators: JavaScript treats them as line
#     terminators, most viewers do not, so a line can say one thing and parse as two.
#
# Layer 2R makes this urgent rather than theoretical: an agentic model will read this
# text and act on it. Caught by Seat 5 in round 3 against shipped code.
_CONTROL = re.compile(
    "["
    "\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f"      # C0 (less \t\n\r), DEL, C1
    "\u00ad\u061c\u180e\u3164"                      # soft hyphen, ALM, MVS, Hangul filler
    "\u2028\u2029"                                  # line/paragraph separator
    "\u200b-\u200f"                                 # zero-width space/joiners, LRM/RLM
    "\u202a-\u202e"                                 # bidi embedding and overrides
    "\u2060-\u2064"                                 # word joiner, invisible operators
    "\u2066-\u2069"                                 # bidi isolates
    "\ufeff"                                        # BOM / zero-width no-break space
    "\U000e0000-\U000e007f"                         # Unicode tag block
    "]")


class TaintError(ValueError):
    """A tool emitted something that will not be trusted."""


# ------------------------------------------------------------------ 1 & 2

# Tool output lives on the run volume, which every sandboxed child can write. A child
# that swaps out/<tool>.json for a symlink would have the unsandboxed parent read a host
# file. O_NOFOLLOW_ANY refuses a link in any component; O_NOFOLLOW is the fallback.
_NOFOLLOW = getattr(os, "O_NOFOLLOW_ANY", 0) or os.O_NOFOLLOW


def read_capped(path: Path, cap: int = MAX_TOOL_OUTPUT) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | _NOFOLLOW)
    except OSError as e:
        raise TaintError(f"{path.name}: refused to open ({e.strerror})") from e
    with os.fdopen(fd, "rb") as f:
        size = os.fstat(f.fileno()).st_size
        if size > cap:
            raise TaintError(f"{path.name} is {size} bytes, over the {cap} cap")
        return f.read(cap + 1)


def scrub_text(value: Any, limit: int = MAX_FIELD_CHARS) -> str:
    """Make target-controlled text safe to store, log, and render."""
    if value is None:
        return ""
    s = value if isinstance(value, str) else str(value)
    s = unicodedata.normalize("NFC", s)
    s = _CONTROL.sub("", s)
    if len(s) > limit:
        s = s[:limit] + f"… [+{len(s) - limit} chars]"
    return s


def load_json(path: Path) -> Any:
    raw = read_capped(path)
    if not raw.strip():
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        raise TaintError(f"{path.name}: {e}") from e


# ------------------------------------------------------------------ 3

def safe_relpath(uri: str, root: Path) -> Path:
    """Resolve a tool-emitted path against the run volume, or refuse.

    Refuses absolute paths, URI schemes, control characters, and anything that escapes
    `root` after normalisation. Returns a path relative to `root`.
    """
    if not isinstance(uri, str) or not uri:
        raise TaintError("empty path")
    if _CONTROL.search(uri):
        raise TaintError("control characters in path")
    if uri.startswith("file://"):
        uri = uri[len("file://"):]
    if "://" in uri:
        raise TaintError(f"unsupported scheme in path: {uri[:40]!r}")
    if uri.startswith("/") or (len(uri) > 1 and uri[1] == ":"):
        raise TaintError(f"absolute path refused: {uri[:60]!r}")
    if "\x00" in uri:
        raise TaintError("NUL in path")

    root = root.resolve()
    candidate = (root / uri).resolve()
    try:
        rel = candidate.relative_to(root)
    except ValueError as e:
        raise TaintError(f"path escapes the run volume: {uri[:60]!r}") from e
    # resolve() follows symlinks; the scrub removed them, but check anyway — this is the
    # last gate before a filesystem read, and defence in depth is the whole point.
    if candidate.is_symlink() or candidate.parent.is_symlink():
        raise TaintError(f"symlink in path: {uri[:60]!r}")
    return rel


# ------------------------------------------------------------------ 4

@dataclass(frozen=True)
class Redaction:
    prefix: str
    sha256: str
    length: int

    @property
    def placeholder(self) -> str:
        return f"«redacted:{self.prefix}…{self.sha256[:12]} len={self.length}»"


def redact_secret(secret: str) -> Redaction:
    """D16. A secret is stored as its first four characters and a hash, never whole."""
    b = secret.encode("utf-8", "surrogateescape")
    return Redaction(secret[:4], hashlib.sha256(b).hexdigest(), len(secret))


# Values that are self-evidently not a live credential. The funnel cannot see a
# secret (D16), so it compares the stored hash against these, hashed the same way at
# this same boundary. A case variant of each is included; anything else is a value
# nobody has shown to be a placeholder, and survives.
PLACEHOLDER_SECRETS = (
    "password", "passwd", "pass", "changeme", "change_me", "changeit", "admin",
    "administrator", "root", "toor", "secret", "example", "sample", "test", "testing",
    "dummy", "placeholder", "default", "demo", "guest", "postgres", "mysql", "redis",
    "123456", "12345678", "123456789", "qwerty", "letmein", "hunter2", "s3cr3t",
    "abc123", "foo", "bar", "foobar", "xxx", "xxxxxx", "xxxxxxxx",
    "root_pg_password", "rootpassword", "your_password", "your-password", "yourpassword",
    "mysecretpassword", "supersecret",
)
PLACEHOLDER_SHAS = frozenset(
    redact_secret(v).sha256
    for p in PLACEHOLDER_SECRETS for v in {p, p.lower(), p.upper(), p.capitalize()})


def _line_breaks(s: str) -> int:
    """Line breaks in `s`, counted the way str.splitlines() counts them."""
    return len(("x" + s + "x").splitlines()) - 1


def _variants(secret: str) -> set[str]:
    """Every form a secret can take in text that has already been reshaped: the raw
    match, LF-only (a CRLF PEM key after a splitlines/join) and scrubbed (zero-width
    and control characters gone). Redacting only the raw form missed the other two."""
    lf = secret.replace("\r\n", "\n").replace("\r", "\n")
    out = {secret, lf}
    out |= {_CONTROL.sub("", unicodedata.normalize("NFC", v)) for v in tuple(out)}
    return {v for v in out if len(v) >= 6}


def redact_in(text: str, secrets: Iterable[str]) -> str:
    """Replace every known secret inside a body of text. Used on evidence windows so a
    ±40-line window around a Gitleaks hit does not smuggle the secret into the DB.

    The placeholder keeps the secret's line breaks, so a redacted multi-line key does
    not shift the line numbers of everything after it."""
    pairs: dict[str, str] = {}
    for s in {s for s in secrets if s and len(s) >= 6}:
        ph = redact_secret(s).placeholder
        for v in _variants(s):
            pairs.setdefault(v, ph + "\n" * _line_breaks(v))
    out = text
    for v in sorted(pairs, key=len, reverse=True):
        out = out.replace(v, pairs[v])
    return out


def redact_obj(obj: Any, secrets: Iterable[str]) -> Any:
    """redact_in over every string inside a decoded JSON value. Used on raw_result,
    which is stored verbatim (D9) and so carries whatever the tool quoted."""
    secrets = frozenset(secrets)
    if not secrets:
        return obj
    if isinstance(obj, str):
        return redact_in(obj, secrets)
    if isinstance(obj, dict):
        return {k: redact_obj(v, secrets) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [redact_obj(v, secrets) for v in obj]
    return obj


def run_secrets(rundir: Path) -> frozenset[str]:
    """Every secret the run's Gitleaks report names, read from the run volume.

    Redaction has to cover every window built in the run, not only a Gitleaks
    record's own: a bandit hit two lines below a key captures the same 81 lines. The
    report on the volume is the one source every writer (scan, deep review) can reach.
    """
    report = rundir / "out" / "gitleaks.json"
    try:
        st = report.stat()
    except OSError:
        return frozenset()
    return _report_secrets(str(report), st.st_mtime_ns, st.st_size)


@functools.lru_cache(maxsize=8)
def _report_secrets(path: str, _mtime: int, _size: int) -> frozenset[str]:
    try:
        doc = load_json(Path(path))
    except (TaintError, OSError):
        return frozenset()
    out: set[str] = set()
    for r in doc if isinstance(doc, list) else []:
        if not isinstance(r, dict):
            continue
        # Same choice as the Gitleaks adapter: Match only when there is no Secret, so
        # the placeholder's hash is the one stored on the occurrence.
        s = r.get("Secret") or r.get("Match")
        if isinstance(s, str) and s:
            out.add(s)
    return frozenset(out)


# ------------------------------------------------------------------ 5

@dataclass
class Evidence:
    sha: str
    path: str
    file_sha256: str
    start_line: int
    end_line: int
    body: bytes          # gzipped, redacted
    bytes_raw: int
    match_sha: str | None = None    # content_key of the flagged line(s); see finding_id


def extract_evidence(root: Path, rel: Path, line: int | None, *,
                     end_line: int | None = None,
                     context: int = EVIDENCE_CONTEXT,
                     secrets: Iterable[str] = ()) -> Evidence | None:
    """Capture the window around `line`, redacted and gzipped, content-addressed.

    Evidence scales with finding count, not repo size: ~8k unique windows per 18k
    occurrences is ~32 MB raw / ~9 MB gzipped, so a 2 GB target costs the same as a
    2 MB one (Seats 4 + 5).

    `secrets` is unioned with every secret in the run's Gitleaks report (when `root`
    is a run volume's src/), so no caller can build a window that skips one.
    """
    full = (root / rel)
    try:
        raw = full.read_bytes()
    except (OSError, ValueError):
        return None
    if len(raw) > 8 * 1024 * 1024:      # a minified bundle is not evidence
        return None
    file_sha = hashlib.sha256(raw).hexdigest()
    # Redact the whole file as decoded, before anything reshapes it: splitlines drops
    # the \r of a CRLF PEM key and the scrub drops zero-width characters, and either
    # one stops the secret matching.
    text = redact_in(raw.decode("utf-8", "replace"),
                     set(secrets) | run_secrets(root.parent))
    lines = text.splitlines()
    if not lines:
        return None

    centre = (line or 1) - 1
    start = max(0, centre - context)
    end = min(len(lines), centre + context + 1)
    window = "\n".join(lines[start:end])
    window = scrub_text(window, limit=200_000)
    body = window.encode("utf-8", "replace")
    match_sha = None
    if line and 0 <= centre < len(lines):
        last = min(len(lines), max(line, end_line or line), centre + 200)
        match_sha = content_key("\n".join(lines[centre:last]))
    return Evidence(
        sha=hashlib.sha256(body).hexdigest(),
        path=str(rel),
        file_sha256=file_sha,
        start_line=start + 1,
        end_line=end,
        body=gzip.compress(body, 6),
        bytes_raw=len(body),
        match_sha=match_sha,
    )


# ------------------------------------------------------------------ identity

def content_key(text: str) -> str:
    """Hash of text with all whitespace removed, per line. Re-indenting or re-spacing
    does not change it; changing a token does."""
    s = _CONTROL.sub("", unicodedata.normalize("NFC", text))
    norm = "\n".join("".join(ln.split()) for ln in s.splitlines())
    return hashlib.sha256(norm.encode("utf-8", "surrogateescape")).hexdigest()


def finding_id(target: str, path: str, producer_id: str, content_sha: str | None,
               fallback: str | None = None) -> str:
    """D8: line-number-free. Keyed on (relative path, producer = tool + rule, content
    of the flagged line(s) with whitespace stripped), so a finding that moves down the
    file keeps its id and a verdict carries forward.

    It used to key on the whole file's hash, which gave every same-rule finding in a
    file one id (a rejected verdict on one then killed its siblings) and reset every
    verdict in the file on any byte change.

    With no line to key on, `fallback` (a message or quote, already redacted) stands
    in, so two packages hitting one advisory in one lockfile stay two findings. With
    neither, the id is path + producer."""
    if not content_sha and fallback:
        content_sha = "text:" + content_key(fallback)
    basis = "\x1f".join([target, path, producer_id, content_sha or "-"])
    return hashlib.sha256(basis.encode()).hexdigest()[:32]
