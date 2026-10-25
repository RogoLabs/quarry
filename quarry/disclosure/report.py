"""Render a confirmed verdict as a GHSA-shaped Markdown advisory.

The report states only what was verified. Severity is offered as a proposal for the
reporter to confirm, never a computed CVSS the tool invented; affected versions are given
as the exact commit the probe ran against, with the range left for the maintainer, since
the probe observed one revision and inventing a range would be a guess.

Most of what fills the template is target-controlled: route paths from the repo's source
or the OpenAPI document the running target served, the target and file names, response
excerpts. A string that closes the PoC fence could append its own headings, links or a
remote image to a document a human is about to send under their own name. So nothing is
interpolated raw. Every target string passes the taint boundary's control/bidi scrub;
verbatim evidence goes in a code fence longer than any backtick run inside it; names and
paths go in code spans built the same way; and prose is held to one inert paragraph with
images dropped and the characters that open links, code or HTML escaped.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..taint import TaintError, safe_relpath, scrub_text

CWE_TITLE = {
    "CWE-862": "Missing Authorization",
    "CWE-863": "Incorrect Authorization",
    "CWE-639": "Insecure Direct Object Reference (IDOR)",
    "CWE-307": "Improper Restriction of Excessive Authentication Attempts",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-208": "Observable Timing Discrepancy",
    "CWE-89": "SQL Injection",
    "CWE-77": "Command Injection",
    "CWE-79": "Cross-site Scripting (Reflected)",
    "CWE-22": "Path Traversal",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
}

# A starting point for the reporter, clearly proposed, never a computed score.
CWE_SEVERITY = {
    "CWE-862": "High", "CWE-863": "High", "CWE-639": "High",
    "CWE-307": "Moderate", "CWE-400": "Moderate", "CWE-208": "Low",
    "CWE-89": "Critical", "CWE-77": "Critical", "CWE-79": "Moderate",
    "CWE-22": "High", "CWE-918": "High",
}

CWE_FIX = {
    "CWE-862": "Enforce an authorization check on this route, consistent with its "
               "siblings, before the handler runs.",
    "CWE-863": "Correct the authorization predicate so it denies the caller who should "
               "not reach this object or action.",
    "CWE-639": "Scope the object lookup to the authenticated principal; do not trust a "
               "caller-supplied identifier without an ownership check.",
    "CWE-307": "Rate-limit this endpoint (per account and per source) and add backoff or "
               "lockout on repeated failures.",
    "CWE-400": "Bound the work this endpoint can be made to do: limit input size, "
               "iterations, and concurrency.",
    "CWE-208": "Make the response time independent of whether the account exists, for "
               "example by always performing the password hash comparison.",
    "CWE-89": "Use parameterised queries or an ORM binding; never build SQL by string "
              "interpolation of caller input.",
    "CWE-77": "Avoid passing caller input to a shell; use an argument vector with no shell, "
              "and validate against an allowlist.",
    "CWE-79": "Contextually encode output, or sanitise with a vetted library; do not emit "
              "caller input into HTML unescaped.",
    "CWE-22": "Resolve the path and confirm it stays within the intended directory; reject "
              "absolute paths and `..` sequences.",
    "CWE-918": "Validate and allowlist outbound destinations; block internal address "
               "ranges and do not let callers choose the host.",
}

_ECOSYSTEM = {
    "Python": "PyPI", "JavaScript": "npm", "TypeScript": "npm", "Ruby": "RubyGems",
    "Go": "Go", "PHP": "Packagist", "Java": "Maven", "Rust": "crates.io",
}

@dataclass(frozen=True)
class SecurityContact:
    """One reporting channel the target declares. The advisory lists every one found, in
    order, for the reporter to choose; Quarry never picks for them."""
    kind: str                    # "ghsa" | "email" | "url"
    value: str                   # address or URL; "" for a GHSA instruction with no link
    source: str                  # where it was found, e.g. "SECURITY.md, mailto link"


@dataclass
class DisclosureContext:
    target: str
    clone_url: str
    git_sha: str | None
    cwe: str | None
    file: str
    symbol: str | None
    line: int | None
    summary: str
    request: str
    observed: str
    determinism: str
    ecosystem: str
    package: str
    security_contacts: tuple[SecurityContact, ...]
    run_id: int
    verdict_time: str
    baseline: str = ""           # the control result the probe's effect differed from


def guess_ecosystem(primary_language: str) -> str:
    return _ECOSYSTEM.get(primary_language, "(unknown)")


# Where a project declares how to report: a SECURITY.md policy, or an RFC 9116
# security.txt. All are read; on a case-insensitive filesystem two names can be one file.
_CONTACT_FILES = ("SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md",
                  ".well-known/security.txt", "security.txt", "SECURITY.txt")
_CONTACT_READ_CAP = 64 * 1024

# GitHub private vulnerability reporting: the advisories URL, or the instruction in words.
_GHSA_URL = re.compile(
    r"https?://github\.com/[\w.-]+/[\w.-]+/security/advisories(?:/new)?", re.I)
_GHSA_TEXT = re.compile(
    r"security/advisories|private vulnerability report|report a vulnerability|"
    r"github\b[^.\n]{0,40}\bsecurity advisor|security advisor[^.\n]{0,40}\bgithub", re.I)
# RFC 9116: "Contact:" lines, one channel each, in the maintainer's order of preference.
_CONTACT_LINE = re.compile(r"^[ \t>*-]*Contact:[ \t]*(\S+)", re.I | re.M)
_MAILTO = re.compile(r"mailto:([^\s)>\]\"'?]+)", re.I)
# An address needs a real domain: dot-separated labels ending in an alphabetic TLD.
_EMAIL = re.compile(
    r"(?<![\w.%+-])([A-Za-z0-9][A-Za-z0-9._%+-]*@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+([A-Za-z]{2,24}))(?![A-Za-z0-9-])")
# "TLDs" that are file extensions: ![logo](img/logo@2x.png) is not an address.
_FILE_EXTS = frozenset({
    "png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "bmp", "tif", "tiff", "avif",
    "md", "txt", "rst", "html", "htm", "js", "mjs", "ts", "css", "scss", "json", "yml",
    "yaml", "xml", "toml", "lock", "pdf", "zip", "gz", "tgz", "tar", "py", "rb", "php",
    "mp4", "mov", "webm", "woff", "woff2", "ttf"})
_IMAGE_ANY = re.compile(r"!\[[^\]]*\]\([^)]*\)|<img\b[^>]*>", re.I)
# "Do not email x", "please don't use x": the address is named to be avoided.
_NEGATED = re.compile(r"\b(?:do\s+not|don'?t|never|not)\b[^.,;:!?\n]*$", re.I)


def _email(addr: str) -> str | None:
    m = _EMAIL.fullmatch(addr.strip())
    if not m or m.group(2).lower() in _FILE_EXTS:
        return None
    return m.group(1)


def _negated(text: str, start: int) -> bool:
    return bool(_NEGATED.search(text[max(0, start - 80):start]))


def _contacts_in(text: str, source: str) -> dict[str, list[SecurityContact]]:
    found: dict[str, list[SecurityContact]] = {
        "ghsa": [], "contact": [], "mailto": [], "email": []}
    urls = _GHSA_URL.findall(text)
    if urls:
        found["ghsa"] += [SecurityContact("ghsa", u, f"{source}, reporting link") for u in urls]
    elif _GHSA_TEXT.search(text):
        found["ghsa"].append(SecurityContact("ghsa", "", f"{source}, reporting instruction"))
    for m in _CONTACT_LINE.finditer(text):
        value = m.group(1).rstrip(".,;")
        if value.lower().startswith("mailto:"):
            addr = _email(value[len("mailto:"):])
            if addr:
                found["contact"].append(SecurityContact("email", addr, f"{source}, Contact: line"))
        elif value.lower().startswith("https://"):
            found["contact"].append(SecurityContact("url", value, f"{source}, Contact: line"))
        elif _email(value):
            found["contact"].append(SecurityContact("email", _email(value),
                                                    f"{source}, Contact: line"))
    for m in _MAILTO.finditer(text):
        addr = _email(m.group(1))
        if addr and not _negated(text, m.start()):
            found["mailto"].append(SecurityContact("email", addr, f"{source}, mailto link"))
    bare = _IMAGE_ANY.sub(lambda m: " " * len(m.group(0)), text)
    for m in _EMAIL.finditer(bare):
        addr = _email(m.group(1))
        if addr and not _negated(bare, m.start()):
            found["email"].append(SecurityContact("email", addr, source))
    return found


def extract_security_contacts(src: Path) -> list[SecurityContact]:
    """Every reporting channel the target declares, in order: the GitHub private-reporting
    instruction first (a policy that says "use GitHub, not email" must not yield the email
    it warns against), then RFC 9116 Contact: lines, then mailto: links, then addresses in
    the text. An address needs a real domain, not a file extension, and one named in a
    "do not" clause is skipped. Empty when none is declared, so the report says to use
    GHSA. Files are read through the taint boundary's path check, never via a symlink."""
    buckets: dict[str, list[SecurityContact]] = {
        "ghsa": [], "contact": [], "mailto": [], "email": []}
    seen_files: set[tuple[int, int]] = set()
    for name in _CONTACT_FILES:
        try:
            p = src.resolve() / safe_relpath(name, src)
        except TaintError:
            continue
        if not p.is_file():
            continue
        st = p.stat()
        if (st.st_dev, st.st_ino) in seen_files:
            continue
        seen_files.add((st.st_dev, st.st_ino))
        with p.open("rb") as fh:
            text = scrub_text(fh.read(_CONTACT_READ_CAP).decode("utf-8", "replace"),
                              limit=_CONTACT_READ_CAP)
        for k, v in _contacts_in(text, name).items():
            buckets[k] += v
    out: list[SecurityContact] = []
    seen: set[tuple[str, str]] = set()
    for c in buckets["ghsa"] + buckets["contact"] + buckets["mailto"] + buckets["email"]:
        key = (c.kind, c.value.lower())
        if key not in seen:
            seen.add(key)
            out.append(c)
    return out


def _title(cwe: str | None) -> str:
    return CWE_TITLE.get(cwe or "", "Security vulnerability")


# ------------------------------------------------------------------ Markdown safety

_TICKS = re.compile(r"`+")
_IMAGE = re.compile(r"!\[[^\]]*\]\([^)]*\)")
# Characters that open a link or image ([ ]), a code span (`), inline or block HTML and
# autolinks (< >), plus the backslash itself so an escape cannot be undone.
_INLINE_ACTIVE = re.compile(r"([\\`\[\]<>])")
# A paragraph that starts with one of these becomes a heading, quote, list or rule.
_BLOCK_START = re.compile(r"^(?:[#>+\-*=|~_]|\d+[.)])")


def _longest_tick_run(s: str) -> int:
    return max((len(m) for m in _TICKS.findall(s)), default=0)


def _one_line(value: Any) -> str:
    """Scrubbed through the taint boundary and collapsed to one line, so nothing in it can
    start a new Markdown block."""
    return " ".join(scrub_text(value).split())


def _code(value: Any, empty: str = "(none)") -> str:
    """An inline code span the value cannot close: the delimiter is one backtick longer
    than the longest run inside, padded when the value itself starts or ends with one."""
    s = _one_line(value) or empty
    fence = "`" * (_longest_tick_run(s) + 1)
    pad = " " if s.startswith("`") or s.endswith("`") else ""
    return f"{fence}{pad}{s}{pad}{fence}"


def _code_block(value: Any) -> str:
    """Verbatim evidence in a fence at least three backticks long and longer than any run
    inside, so no line of the evidence can close it. Line breaks are kept."""
    s = scrub_text(value).replace("\r\n", "\n").replace("\r", "\n")
    fence = "`" * max(3, _longest_tick_run(s) + 1)
    return f"{fence}\n{s}\n{fence}"


def _text(value: Any) -> str:
    """Prose that may carry target strings (a probe summary quotes the route path), made
    inert: one paragraph, Markdown images dropped, link/code/HTML openers escaped, and no
    leading character that would turn it into a heading, quote or list. Em dashes become
    hyphens, since this is prose."""
    s = _IMAGE.sub("(image removed)", _one_line(value)).replace("\u2014", "-")
    s = _INLINE_ACTIVE.sub(r"\\\1", s)
    m = _BLOCK_START.match(s)
    if m:
        tok = m.group(0)
        s = (tok[:-1] + "\\" + tok[-1] if tok[0].isdigit() else "\\" + tok) + s[len(tok):]
    return s


_CONTACT_KIND = {"ghsa": "GitHub private vulnerability reporting", "email": "Email",
                 "url": "Web page"}


def _render_contacts(contacts) -> str:
    """Every declared channel, for the reporter to choose; none is preferred silently."""
    if not contacts:
        return ("No security contact was declared. Use the project's GitHub \"Report a "
                "vulnerability\" (GHSA) form.")
    lines = [f"- {_CONTACT_KIND.get(c.kind, 'Contact')}: "
             + (_code(c.value) if c.value else
                "the project's Security tab, \"Report a vulnerability\"")
             + f" (from {_code(c.source)})" for c in contacts]
    head = ("The project declares this reporting channel:" if len(contacts) == 1 else
            "The project declares these reporting channels, in the order found. Choose "
            "one before sending:")
    return head + "\n\n" + "\n".join(lines)


def render_report(ctx: DisclosureContext) -> str:
    cwe = _text(ctx.cwe or "(unclassified)")
    klass = _title(ctx.cwe)
    severity = CWE_SEVERITY.get(ctx.cwe or "", "To be assessed")
    fix = CWE_FIX.get(ctx.cwe or "", "Review and remediate the issue described above.")
    where = _code(ctx.file + (f" ({ctx.symbol})" if ctx.symbol else "")
                  + (f":{int(ctx.line)}" if ctx.line else ""))
    sha = _code(ctx.git_sha or "(working tree)")
    contacts = _render_contacts(ctx.security_contacts)
    summary = _text(ctx.summary) or "(no summary recorded)"
    request = _code_block(ctx.request) if ctx.request.strip() else \
        "(No request was recorded; see the observation below.)"
    observed = _code_block(ctx.observed) if ctx.observed.strip() else summary
    baseline = (f"\n\nBaseline (the control request the observation differs from):\n\n"
                f"{_code_block(ctx.baseline)}") if ctx.baseline.strip() else ""

    return f"""# {klass} in {_text(ctx.package)}

## Summary

{summary}

## Package

- Ecosystem: {_text(ctx.ecosystem)}
- Package / project: {_code(ctx.package)} ({_code(ctx.target)})
- Source: {_code(ctx.clone_url)}

## Affected versions

Observed at commit {sha}. The affected version range is for the maintainer to confirm;
this report records the single revision the probe ran against, and does not infer a range.

## Severity

Proposed: **{severity}** (reporter to confirm with a CVSS vector). Weakness: {cwe}
({klass}).

## Location

{where}

## Description

{summary}

This was confirmed dynamically against a running instance of the project, in an isolated
environment with no network egress. The verdict is based on a measured, reproducible
observation rather than static inference ({_text(ctx.determinism)} signal).

## Proof of concept

{request}

Observed:

{observed}{baseline}

## Suggested remediation

{fix}

## Disclosure

Please treat this as a coordinated disclosure.

{contacts}

---

Found with Quarry (run {int(ctx.run_id)}, {_text(ctx.verdict_time)}). This is a reporter's draft to
review before sending, not a published advisory.
"""


def _has_baseline(ev: dict) -> bool:
    """The stored evidence carries the control comparison a confirmation requires."""
    return bool(ev.get("baseline")) and ev.get("differs_from_baseline") is True


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "finding"


@dataclass(frozen=True)
class Draft:
    """One advisory file as written: where, from which verdict, and the hash of the
    exact bytes, so `quarry report` can record it in the `advisories` table."""
    path: Path
    finding_id: str
    verdict_id: int
    sha256: str


def build_reports(con: sqlite3.Connection, run_id: int, src: Path, *,
                  out_dir: Path) -> list[Path]:
    """The paths `draft_reports` wrote. Kept for callers that only need the files."""
    return [d.path for d in draft_reports(con, run_id, src, out_dir=out_dir)]


def draft_reports(con: sqlite3.Connection, run_id: int, src: Path, *,
                  out_dir: Path) -> list[Draft]:
    """Write a Markdown advisory for every finding whose latest dynamic verdict in the run
    is confirmed. Returns one Draft per file. Reproducible from the DB: the probe evidence was
    stored on the verdict as JSON.

    Three filters, because the template says "confirmed dynamically" and a human may send
    it. Only seat='dynamic' verdicts count; a model seat's opinion is not a probe. Only the
    latest such verdict per finding counts, so a re-run of validate that rejected or held a
    finding withdraws the earlier confirmation. And the stored evidence must carry the
    baseline comparison that confirmation requires (validate.adjudicate), so a verdict
    written before that rule, or by hand, is not drafted. needs-review is never drafted."""
    from ..research.profile import profile_repo

    prof = profile_repo(src)
    ecosystem = guess_ecosystem(prof.primary_language)
    contacts = tuple(extract_security_contacts(src))
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    rows = con.execute(
        """SELECT v.id AS verdict_id, v.finding_id, v.cwe, v.rationale, v.created_at,
                  f.path, f.symbol, r.target, r.clone_url, r.git_sha,
                  (SELECT o.start_line FROM occurrences o
                    WHERE o.finding_id = v.finding_id AND o.run_id = v.run_id
                    LIMIT 1) AS start_line
             FROM verdicts v
             JOIN (SELECT finding_id, MAX(id) AS id FROM verdicts
                    WHERE run_id = ? AND seat = 'dynamic'
                    GROUP BY finding_id) latest ON latest.id = v.id
             JOIN findings f ON f.id = v.finding_id
             JOIN runs r     ON r.id = v.run_id
            WHERE v.verdict = 'confirmed'
            ORDER BY v.id""", (run_id,)).fetchall()

    package = ""
    written: list[Draft] = []
    for row in rows:
        d: dict[str, Any] = dict(row)
        package = d["target"].split("/")[-1]
        try:
            ev = json.loads(d["rationale"] or "{}")
        except ValueError:
            ev = {}
        if not isinstance(ev, dict) or not _has_baseline(ev):
            continue

        def field(key: str, default: str = "") -> str:
            return scrub_text(ev.get(key) or default)
        ctx = DisclosureContext(
            target=d["target"], clone_url=d["clone_url"], git_sha=d["git_sha"],
            cwe=d["cwe"], file=d["path"], symbol=d["symbol"], line=d["start_line"],
            summary=field("summary"), request=field("request"),
            observed=field("observed"), determinism=field("determinism", "unknown"),
            baseline=field("baseline"),
            ecosystem=ecosystem, package=package, security_contacts=contacts,
            run_id=run_id, verdict_time=d["created_at"])
        path = out_dir / f"{run_id}-{_slug(d['cwe'] or 'finding')}-{d['finding_id'][:8]}.md"
        body = render_report(ctx).encode("utf-8")
        path.write_bytes(body)
        written.append(Draft(path=path, finding_id=d["finding_id"],
                             verdict_id=int(d["verdict_id"]),
                             sha256=hashlib.sha256(body).hexdigest()))
    return written
