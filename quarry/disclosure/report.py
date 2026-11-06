"""Render a confirmed verdict as a GHSA-shaped Markdown advisory.

The report states only what was verified. Severity is offered as a proposal for the
reporter to confirm, never a computed CVSS the tool invented; affected versions are given
as the exact commit the probe ran against, with the range left for the maintainer, since
the probe observed one revision and inventing a range would be a guess.

It also states the limits of what was verified. Severity is labelled a class default and
kept apart from Confidence, which comes from the verdict and its replays. Conditions lists
what had to be true for the observation (commit, route, seed recipe, auth role, `--env`
names) from the verdict's rationale and the run manifest, and says "not recorded" for
anything missing. Limitations names the single weakest link. Nothing is fetched by
default: the prior-advisory check reads the local OSV copy, and current HEAD is
re-checked only when the reporter asks (`quarry report --check-head`, disclosure.head),
which the draft says either way. `--env` values and a seed recipe's keys and password are never stored,
so the draft can only name them; it also redacts credential headers and
credential-shaped query values in the evidence, in case a probe sent one.

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
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .. import db
from ..cwe import probe_class
from ..research import verdicts
from ..research.ensemble import KEPT_SQL
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
    # What had to be true for the observation, and how far the evidence goes. Each is
    # optional: a verdict written before a key existed renders "not recorded", never a
    # guess. replay/probe/conditions are the rationale keys of the same names;
    # `validate` is the run manifest's validate block (provisioning, seed, service).
    verdict: str = "confirmed"
    verdict_reason: str = ""
    replay: Any = None
    probe: Any = None
    conditions: Any = None
    validate: Any = None
    seed_notes: tuple[str, ...] = ()
    prior: Any = None            # vulndb.PriorCheck; None when no lookup ran
    security_policy: tuple[str, ...] | None = None   # SECURITY.md paths; None: not checked
    # The names the clone's manifests declare (packages.PackageName); () when none
    # declares one, so the repository name stood in; None when they were not read.
    packages: Any = None
    head: Any = None             # head.HeadCheck; None when no re-check was asked for


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


_POLICY_FILES = ("SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md")


def find_security_policy(src: Path) -> tuple[str, ...] | None:
    """The SECURITY.md files the clone holds, by Quarry's fixed list of names, read
    through the taint boundary's path check so a symlink out of the clone does not
    count. None when the clone is not there to look in, so the draft says "not
    checked" rather than "absent"."""
    try:
        if not Path(src).is_dir():
            return None
    except OSError:
        return None
    found: list[str] = []
    for name in _POLICY_FILES:
        try:
            p = Path(src).resolve() / safe_relpath(name, Path(src))
        except TaintError:
            continue
        if p.is_file():
            found.append(name)
    return tuple(found)


def _title(cwe: str | None) -> str:
    return CWE_TITLE.get(probe_class(cwe) or "", "Security vulnerability")


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


# ------------------------------------------------------------ conditions and limits
# A maintainer who cannot reproduce a report closes it, and a reporter who overstates
# one loses the next. So the draft says what had to be true for the observation, how far
# the evidence goes, and its single weakest link, from what Quarry recorded. Anything not
# recorded is said to be not recorded; nothing is filled in from what usually happens.

NOT_RECORDED = "not recorded"
_MISSING = object()


def _count(v: Any) -> int | None:
    """A non-negative int, and not a bool (True is an int in Python)."""
    return v if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else None


def _dict(v: Any) -> dict:
    return v if isinstance(v, dict) else {}


@dataclass(frozen=True)
class _Replay:
    state: str                   # absent | unreadable | empty | agreed | disagreed
    attempts: int = 0
    reproduced: int = 0
    control_held: int = 0
    after_restart: bool | None = None


def _replay(raw: Any) -> _Replay:
    """rationale["replay"], read strictly. A record whose counts do not add up is
    "unreadable" and counts as no replay, because a reproducibility claim rests on
    them. A replay that failed after a restart is a disagreement."""
    if raw is None:
        return _Replay("absent")
    if not isinstance(raw, dict):
        return _Replay("unreadable")
    n, r, c = (_count(raw.get(k)) for k in ("attempts", "reproduced", "control_held"))
    restart = raw.get("after_restart")
    if (n is None or r is None or c is None or r > n or c > n
            or not (restart is None or isinstance(restart, bool))):
        return _Replay("unreadable")
    if n == 0:
        return _Replay("empty")
    agreed = r == n and c == n and restart is not False
    return _Replay("agreed" if agreed else "disagreed", n, r, c, restart)


# A recorded override is shown by name only. Anything that is not a plain variable name
# is withheld, in case it is a value. A role is a short word (admin, user, quarry_admin);
# one with a digit or over 24 characters is withheld, because that is what a key looks
# like (the vulnlookup recipe captures keys as 16 or more letters and digits).
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
_ROLE = re.compile(r"[A-Za-z][A-Za-z_-]{0,23}")


def _env_names(raw: Any) -> tuple[list[str], int] | None:
    """Variable names from a recorded override list, and how many entries were
    withheld. A dict's values are never read; a `KEY=VALUE` entry keeps only KEY. None
    when the record is not a list or dict."""
    if isinstance(raw, dict):
        items = list(raw)
    elif isinstance(raw, (list, tuple)):
        items = list(raw)
    else:
        return None
    names: list[str] = []
    withheld = 0
    for it in items:
        name = it.split("=", 1)[0].strip() if isinstance(it, str) else ""
        if _ENV_NAME.fullmatch(name):
            names.append(name)
        else:
            withheld += 1
    return names, withheld


@dataclass
class _Facts:
    """The conditions, gathered once for the Conditions and Limitations sections. The
    verdict's own rationale is preferred. The run manifest is the fallback, and it holds
    the run's latest validation, which may not be the one that wrote this verdict, so a
    value taken from it is labelled. `missing` is filled while Conditions renders."""
    seed: Any = _MISSING         # str | None (not seeded) | _MISSING
    seed_from_run: bool = False
    auth: Any = _MISSING         # "anonymous" | role | _MISSING
    env: tuple[list[str], int] | None = None
    env_from_run: bool = False
    prov: dict = field(default_factory=dict)
    service: Any = None
    missing: list[str] = field(default_factory=list)


_FROM_RUN = " (recorded for the run)"


def _facts(ctx: DisclosureContext) -> _Facts:
    cond, val = _dict(ctx.conditions), _dict(ctx.validate)
    f = _Facts(prov=_dict(val.get("provisioning")), service=val.get("service"))
    if "seed" in cond:
        f.seed = cond["seed"]
    elif "seed" in val:
        f.seed, f.seed_from_run = val["seed"], True
    if f.seed is not None and f.seed is not _MISSING and not (
            isinstance(f.seed, str) and f.seed):
        f.seed = _MISSING
    if isinstance(cond.get("auth"), str) and cond["auth"]:
        f.auth = cond["auth"]
    if "env_keys" in cond:
        f.env = _env_names(cond["env_keys"])
    elif "env_overrides" in f.prov:
        f.env, f.env_from_run = _env_names(f.prov["env_overrides"]), True
    return f


def _render_conditions(ctx: DisclosureContext, f: _Facts) -> str:
    probe = _dict(ctx.probe)

    def nr(what: str) -> str:
        f.missing.append(what)
        return NOT_RECORDED

    lines = [f"- Commit observed: {_code(ctx.git_sha) if ctx.git_sha else nr('commit')}"]
    method, route = probe.get("method"), probe.get("route")
    if isinstance(method, str) and method and isinstance(route, str) and route:
        lines.append(f"- Route and method: {_code(method.upper())} {_code(route)}")
    else:
        lines.append(f"- Route and method: {nr('route and method')} as a field; the "
                     f"request under Proof of concept is what was sent")
    pid, psha = probe.get("id"), probe.get("source_sha")
    if isinstance(pid, str) and pid:
        lines.append(f"- Probe: {_code(pid)}, source hash "
                     + (_code(psha[:12]) if isinstance(psha, str) and psha
                        else NOT_RECORDED))
    else:
        lines.append(f"- Probe: {nr('probe identity')}")

    if f.auth is _MISSING:
        auth = nr("authentication")
    elif f.auth == "anonymous":
        auth = "anonymous (the probe sent no credentials)"
    elif _ROLE.fullmatch(f.auth):
        auth = (f"a seeded test account with role {_code(f.auth)}"
                + (f" from recipe {_code(f.seed)}" if isinstance(f.seed, str) else "")
                + "; its key and password are not in this draft")
    else:
        auth = "recorded, but withheld (not a plain role name)"
    lines.append(f"- Authentication: {auth}")

    if f.seed is _MISSING:
        seed = nr("seed recipe")
    elif f.seed is None:
        seed = "none (the instance was not seeded)"
    else:
        seed = (f"{_code(f.seed)} (the project's own setup commands, run by Quarry inside "
                f"the contained instance)")
        notes = [_text(n) for n in ctx.seed_notes[:8] if _text(n)]
        if notes:
            seed += "; notes recorded on the run: " + "; ".join(notes)
    if f.seed is not _MISSING and f.seed_from_run:
        seed += _FROM_RUN
    lines.append(f"- Seed recipe: {seed}")

    if f.env is None:
        env = nr("environment overrides")
    elif not f.env[0] and not f.env[1]:
        env = "none"
    else:
        names, withheld = f.env
        env = ", ".join(_code(n) for n in names)
        if withheld:
            env += ((" and " if names else "")
                    + f"{withheld} entr{'y' if withheld == 1 else 'ies'} withheld (not a "
                      f"plain variable name)")
        env += " (names only; the values are not in this draft)"
    if f.env is not None and f.env_from_run:
        env += _FROM_RUN
    lines.append(f"- Environment overrides used to boot: {env}")

    if not f.prov:
        lines.append(f"- Build network, memory limit and .env source: "
                     f"{nr('build settings')}")
    else:
        bn = f.prov.get("build_network")
        lines.append("- Build network: " + (
            "none (the image was built offline)" if bn == "none" else
            "default (Dockerfile RUN steps could reach the network while the image was "
            "built; the running instance could not)" if bn == "default" else
            _code(bn) if isinstance(bn, str) and bn else nr("build network")))
        mem = f.prov.get("mem_limit")
        lines.append("- Memory limit per service: "
                     + (_code(mem) if isinstance(mem, str) and mem else nr("memory limit")))
        if "dotenv" in f.prov:
            de = f.prov["dotenv"]
            dotenv = (_code(de) if isinstance(de, str) and de else
                      "none (no .env or sample file in the clone)")
        else:
            dotenv = nr(".env source")
        lines.append(f"- .env file used for interpolation: {dotenv}")
    svc = f.service
    lines.append("- Compose service probed: "
                 + (_code(svc) if isinstance(svc, str) and svc else nr("compose service")))
    return "\n".join(lines)


def _head_reason(head: Any) -> str:
    from .head import NOT_REQUESTED
    return _text(getattr(head, "reason", "") or NOT_REQUESTED)


def _head_versions(head: Any) -> str:
    """The Affected versions lines about current HEAD (disclosure.head)."""
    if head is None or not getattr(head, "checked", False):
        return (f"Current HEAD was not re-checked: {_head_reason(head)}. Confirm the issue "
                "reproduces on the latest commit before sending.")
    when = _text(head.at) or "an unrecorded time"
    if head.moved:
        return (f"Current HEAD was re-checked with `git ls-remote` at {when} and is now "
                f"{_code(head.head)}, not the observed commit. The issue was not "
                "re-tested there; confirm it reproduces on the latest commit before "
                "sending.")
    return (f"Current HEAD was re-checked with `git ls-remote` at {when} and is still the "
            "observed commit. Only the commit was compared; the issue was not re-tested.")


def _head_limit(head: Any) -> str:
    if head is None or not getattr(head, "checked", False):
        return (f"It was observed at one commit, and current HEAD was not re-checked "
                f"({_head_reason(head)}).")
    if head.moved:
        return (f"It was observed at one commit. HEAD has since moved to "
                f"{_code(head.head)}, where it was not re-tested.")
    return (f"It was observed at one commit, still HEAD when re-checked at "
            f"{_text(head.at) or 'an unrecorded time'}; the issue itself was not "
            "re-tested.")


_ROUTE_LINK = ("Quarry matched the flagged file to the route it probed and did not trace "
               "whether the flagged code ran for this request. The response could have "
               "come from other code on the same route.")


def _render_limits(ctx: DisclosureContext, f: _Facts, rp: _Replay) -> str:
    """The single weakest link first, then every other limit that applies. The order of
    the checks is the order of how badly each gap undercuts a confirmation: a verdict
    that is not a confirmation, replays that disagree, no replay at all, no replay
    after a restart, and last the link every probe has today, file to route."""
    if ctx.verdict != "confirmed":
        weakest = (f"The verdict is {_text(ctx.verdict)}, not confirmed "
                   f"({_text(ctx.verdict_reason) or 'no reason recorded'}).")
    elif rp.state == "disagreed":
        weakest = (f"Replays disagreed with the first observation: the effect reproduced "
                   f"{rp.reproduced} of {rp.attempts} times and the control held "
                   f"{rp.control_held} of {rp.attempts} times"
                   + ("; after a restart of the target service it did not reproduce"
                      if rp.after_restart is False else "") + ".")
    elif rp.state != "agreed":
        weakest = ("The result was observed once and was not replayed. One observation "
                   "can come from instance state, timing or a transient error rather than "
                   "the flaw.")
    elif rp.after_restart is None:
        weakest = ("Every replay ran in the same running instance. None ran after a "
                   "restart of the target service, so state left by an earlier request "
                   "was not ruled out.")
    else:
        weakest = _ROUTE_LINK
    others = [] if weakest is _ROUTE_LINK else [_ROUTE_LINK]
    others.append(_head_limit(ctx.head))
    if f.missing:
        others.append("Not recorded for this verdict: " + ", ".join(f.missing)
                      + ". A maintainer may need these to reproduce it.")
    if isinstance(f.seed, str):
        others.append(f"The instance was seeded with recipe {_code(f.seed)}. A deployment "
                      f"holding other data or accounts may answer differently.")
    elif f.seed is None:
        others.append("The instance was not seeded. A deployment holding data and "
                      "accounts may answer differently.")
    if f.env and f.env[0]:
        others.append("The target was booted with operator overrides for "
                      + ", ".join(_code(n) for n in f.env[0])
                      + ". A deployment with other values may behave differently.")
    others.append("The instance ran in Quarry's contained environment. Anything a "
                  "deployment puts in front of the application, such as a reverse proxy or "
                  "gateway that enforces authentication, was not present.")
    others.append("Severity is the class default for the weakness, not an impact the "
                  "probe demonstrated (see Severity).")
    return (f"Weakest link: {weakest}\n\nOther limits:\n\n"
            + "\n".join(f"- {o}" for o in others))


def _confidence(ctx: DisclosureContext, rp: _Replay) -> str:
    """How sure the evidence lets a reader be, kept apart from Severity so a class
    default is never read as a measured result."""
    det = _text(ctx.determinism) or "unknown"
    if ctx.verdict != "confirmed":
        return (f"**Needs review** ({_text(ctx.verdict_reason) or 'no reason recorded'}). "
                f"The probe did not confirm this finding. Do not send it as a confirmation.")
    restart = {True: "After a restart of the target service it reproduced again.",
               False: "After a restart of the target service it did not reproduce.",
               None: "No replay ran after a restart of the target service."}
    if rp.state == "agreed":
        return (f"**Confirmed against a control, and replayed.** The confirming request "
                f"and its control were replayed {rp.attempts} times: the effect reproduced "
                f"{rp.reproduced} of {rp.attempts} times and the control held "
                f"{rp.control_held} of {rp.attempts} times. {restart[rp.after_restart]} "
                f"Signal: {det}.")
    if rp.state == "disagreed":
        return (f"**Confirmed once, but replays disagreed.** The effect reproduced "
                f"{rp.reproduced} of {rp.attempts} times and the control held "
                f"{rp.control_held} of {rp.attempts} times. {restart[rp.after_restart]} "
                f"Treat this as needs-review, and do not send it until a human has re-run "
                f"the request.")
    out = (f"**Confirmed against a control, on a single observation.** The probe's "
           f"response differed from a control request ({det} signal). The result was "
           f"observed once and was not replayed.")
    if rp.state == "unreadable":
        out += " A replay record exists but its counts could not be read, so it is not counted."
    elif rp.state == "empty":
        out += " The replay record shows no attempts."
    return out


def _how_confirmed(ctx: DisclosureContext, rp: _Replay) -> str:
    if ctx.verdict != "confirmed":
        return ("This was probed dynamically against a running instance of the project, "
                "in an isolated environment with no network egress, and was not confirmed "
                "(see Confidence).")
    out = ("This was confirmed dynamically against a running instance of the project, in "
           "an isolated environment with no network egress. The verdict rests on a "
           "measured difference between the probe's response and a control request, not "
           f"on static inference ({_text(ctx.determinism) or 'unknown'} signal).")
    if rp.state == "agreed":
        return out + (f" The effect reproduced on {rp.reproduced} of {rp.attempts} "
                      f"replays.")
    if rp.state == "disagreed":
        return out + " Replays of the request did not all agree (see Confidence)."
    return out + " The result was observed once and was not replayed."


_PRIOR_LISTED = 10


def _searched_names(prior: Any, packages: Any) -> str:
    """The package names the lookup searched, each with the manifest it came from, or ""
    when it searched none. A check made before names were read from manifests says only
    the one name it was given."""
    names = [(e, n) for e, n, ok in getattr(prior, "names", ()) or () if ok]
    if not names:
        if getattr(prior, "names", ()) or not prior.package_ecosystem:
            return ""
        return (f"package name {_code(prior.package)} in "
                f"{_text(prior.package_ecosystem)}")
    where = {(p.ecosystem, p.name): p.source for p in packages or ()}
    parts = [f"{_code(n)} in {_text(e)}"
             + (f" (from {_code(where[(e, n)])})" if (e, n) in where else
                " (the repository name)" if packages == () else "")
             for e, n in names]
    return ("package name " if len(parts) == 1 else "package names ") + ", ".join(parts)


def _unsearched_names(prior: Any, packages: Any) -> str:
    """A bullet naming every declared name that was not searched, and why."""
    gaps: list[str] = []
    for p in packages or ():
        if p.skip:
            gaps.append(f"{_code(p.name)} ({_text(p.ecosystem)}, {_code(p.source)}): "
                        f"{_text(p.skip)}")
    where = {(p.ecosystem, p.name): p.source for p in packages or ()}
    for e, n, ok in getattr(prior, "names", ()) or ():
        if not ok:
            src = f", {_code(where[(e, n)])}" if (e, n) in where else ""
            gaps.append(f"{_code(n)} ({_text(e)}{src}): no local OSV copy for "
                        f"{_text(e)}")
    return ("- Not searched by package name: " + "; ".join(gaps) + ".") if gaps else ""


def _render_prior(prior: Any, cwe: str | None, policy: tuple[str, ...] | None,
                  packages: Any = None) -> str:
    """What the local, offline prior-advisory check searched and found, and whether the
    clone carries a SECURITY.md. Quarry does not reach the network here, so anything it
    could not search locally is stated as not checked. `packages` are the names the
    clone's manifests declare (None when they were not read); the draft names each one
    searched and each one that was not."""
    from ..vulndb import BASES
    lines: list[str] = []
    if packages == ():
        from .packages import MANIFESTS
        lines.append("- Package names: no manifest in the clone declares one (looked "
                     "for " + ", ".join(_code(m) for m in MANIFESTS)
                     + "), so the repository name stood in.")
    if prior is None or not getattr(prior, "checked", False):
        why = _text(getattr(prior, "reason", "")) if prior is not None else ""
        lines.append("- Prior advisories: not checked (offline"
                     + (f"; {why}" if why else "") + ").")
    else:
        klass = probe_class(cwe)
        matches = sorted(prior.matches, key=lambda m: m.modified, reverse=True)
        matches.sort(key=lambda m: (klass not in {probe_class(c) for c in m.cwes},
                                    BASES.index(m.basis) if m.basis in BASES else 9))
        by = []
        if (names := _searched_names(prior, packages)):
            by.append(names)
        if prior.repo:
            by.append(f"repository {_code(prior.repo)}")
        searched = (f"{prior.entries_read:,} records in the local OSV copies for "
                    f"{', '.join(_text(e) for e in prior.ecosystems)}"
                    + (f" (oldest copy downloaded {_text(prior.downloaded)})"
                       if prior.downloaded else "")
                    + (", by " + " and by ".join(by) if by else ""))
        if not matches:
            lines.append(f"- Prior advisories: none found. Searched {searched}.")
        else:
            same = sum(1 for m in matches if klass in {probe_class(c) for c in m.cwes})
            lines.append(f"- Prior advisories: {len(matches)} found, {same} of them "
                         f"recorded with {_text(cwe or 'this weakness')}. Read each before "
                         f"sending. Searched {searched}.")
            for m in matches[:_PRIOR_LISTED]:
                extra = []
                if m.aliases:
                    extra.append("aliases " + ", ".join(_code(a) for a in m.aliases[:3]))
                if m.cwes:
                    extra.append(", ".join(_text(c) for c in m.cwes[:3]))
                extra.append(f"matched by {_text(m.basis)}")
                summ = _text(m.summary[:160]) if m.summary else ""
                lines.append(f"  - {_code(m.id)} ({'; '.join(extra)})"
                             + (f": {summ}" if summ else ""))
            if len(matches) > _PRIOR_LISTED:
                lines.append(f"  - and {len(matches) - _PRIOR_LISTED} more not listed here")
    if (gaps := _unsearched_names(prior, packages)):
        lines.append(gaps)
    if policy is None:
        sec = "not checked (the clone was not available)"
    elif not policy:
        sec = ("absent (looked for " + ", ".join(_code(p) for p in _POLICY_FILES) + ")")
    else:
        sec = (", ".join(_code(p) for p in policy)
               + " present; read its reporting policy before sending")
    lines.append(f"- SECURITY.md in the clone: {sec}")
    lines.append("")
    if prior is not None and getattr(prior, "checked", False):
        names = ("the names searched are the ones the clone's manifests declare, which "
                 "may not be every name the project publishes under" if packages else
                 "the repository name may not be the published package name")
        lines.append("A miss here does not show the issue is new. The local OSV copy is a "
                     f"snapshot, {names}, and reports outside OSV, such as the project's "
                     "issue tracker or changelog, were not searched.")
    else:
        lines.append("Nothing was searched for an earlier report of this issue. Search OSV, "
                     "GitHub's advisory database and the project's issue tracker before "
                     "sending.")
    return "\n".join(lines)


# Credentials a request or response can carry: auth headers (and the same names as JSON
# keys), and secret-looking query parameters. A seeded account's key must never reach a
# draft a human sends, so the value goes and the name stays, so the maintainer can see a
# credential was used. A query value is redacted only when it looks like a credential (8
# or more URL-safe characters with no escape): a `password=` or `token=` parameter is
# also where an injection probe puts its payload, and the PoC needs that payload intact.
_CRED_HEADER = re.compile(
    r"(?i)\b(authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key|apikey|"
    r"x-auth-token|x-access-token|private-token)([\"']?[ \t]*:[ \t]*[\"']?)"
    r"([^\r\n\"']*[^\s\"'])")
_AUTH_SCHEME = re.compile(r"(?i)^(?:basic|bearer|token|digest)[ \t]+")
_CRED_QUERY = re.compile(
    r"(?i)([?&;](?:api[_-]?key|access[_-]?token|auth[_-]?token|token|password|passwd|"
    r"secret|client[_-]?secret)=)([A-Za-z0-9._~-]{8,})(?=[&#\s\"']|$)")
REDACTED = "<redacted>"


def _redact(value: Any) -> tuple[str, int]:
    """The text with credential values replaced by REDACTED, and how many were."""
    s = scrub_text(value)
    n = 0

    def header(m: re.Match) -> str:
        nonlocal n
        n += 1
        scheme = _AUTH_SCHEME.match(m.group(3))
        return m.group(1) + m.group(2) + (scheme.group(0) if scheme else "") + REDACTED

    def query(m: re.Match) -> str:
        nonlocal n
        n += 1
        return m.group(1) + REDACTED

    s = _CRED_QUERY.sub(query, _CRED_HEADER.sub(header, s))
    return s, n


def render_report(ctx: DisclosureContext) -> str:
    cwe = _text(ctx.cwe or "(unclassified)")
    klass = _title(ctx.cwe)
    severity = CWE_SEVERITY.get(probe_class(ctx.cwe) or "")
    fix = CWE_FIX.get(probe_class(ctx.cwe) or "",
                      "Review and remediate the issue described above.")
    where = _code(ctx.file + (f" ({ctx.symbol})" if ctx.symbol else "")
                  + (f":{int(ctx.line)}" if ctx.line else ""))
    sha = _code(ctx.git_sha or "(working tree)")
    contacts = _render_contacts(ctx.security_contacts)
    summary_raw, n_sum = _redact(ctx.summary)
    summary = _text(summary_raw) or "(no summary recorded)"
    req, n_req = _redact(ctx.request)
    obs, n_obs = _redact(ctx.observed)
    base, n_base = _redact(ctx.baseline)
    request = _code_block(req) if req.strip() else \
        "(No request was recorded; see the observation below.)"
    observed = _code_block(obs) if obs.strip() else summary
    baseline = (f"\n\nBaseline (the control request the observation differs from):\n\n"
                f"{_code_block(base)}") if base.strip() else ""
    redacted = ("\n\nCredential values in this evidence were replaced with "
                f"{_code(REDACTED)}. The redaction matches credential headers and "
                "credential-shaped query values only; check the evidence for any other "
                "secret before sending.") if n_sum + n_req + n_obs + n_base else ""
    rp = _replay(ctx.replay)
    facts = _facts(ctx)
    conditions = _render_conditions(ctx, facts)
    limits = _render_limits(ctx, facts, rp)
    if severity:
        sev = (f"Class default: **{severity}** for {cwe} ({klass}), reporter to confirm "
               f"with a CVSS vector. Quarry proposes this for every finding of this "
               f"weakness class; it is not an impact the probe demonstrated.")
    else:
        sev = (f"No class default for {cwe} ({klass}). The reporter sets the severity "
               f"with a CVSS vector before sending.")

    return f"""# {klass} in {_text(ctx.package)}

## Summary

{summary}

## Package

- Ecosystem: {_text(ctx.ecosystem)}
- Package / project: {_code(ctx.package)} ({_code(ctx.target)})
- Source: {_code(ctx.clone_url)}

## Affected versions

Observed at commit {sha}.
{_head_versions(ctx.head)}
The affected version range is for the maintainer to confirm;
this report records the single revision the probe ran against, and does not infer a range.

## Severity

{sev}

## Confidence

{_confidence(ctx, rp)}

## Location

{where}

## Description

{summary}

{_how_confirmed(ctx, rp)}

## Conditions

What had to be true for the observation, as Quarry recorded it.
A field marked "{NOT_RECORDED}" was not recorded for this verdict; nothing here is inferred.
Build settings, the service, and anything marked "recorded for the run" come from the
run's latest validation rather than from this verdict's own record.

{conditions}

## Proof of concept

{request}

Observed:

{observed}{baseline}{redacted}

## Limitations and weakest link

{limits}

## Prior advisories checked

{_render_prior(ctx.prior, ctx.cwe, ctx.security_policy, ctx.packages)}

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
    """The stored evidence carries the control comparison a confirmation requires. A
    probe whose finding is a missing defence records `reproduces_when: same` and confirms
    on sameness (validate.ProbeEvidence), so for it the supporting value is False."""
    supporting = ev.get("reproduces_when", "differs") != "same"
    return bool(ev.get("baseline")) and ev.get("differs_from_baseline") is supporting


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
                  out_dir: Path, vulndb_root: Path | None = None) -> list[Path]:
    """The paths `draft_reports` wrote. Kept for callers that only need the files."""
    return [d.path for d in draft_reports(con, run_id, src, out_dir=out_dir,
                                          vulndb_root=vulndb_root)]


# ------------------------------------------------------------ Layer 2 -> report bridge

@dataclass(frozen=True)
class ResearchDigest:
    """The single Markdown digest of Layer 2 survivors written for a run: where, how many
    findings it holds, and the hash of the exact bytes, so `quarry report` can record it."""
    path: Path
    n_findings: int
    sha256: str


_VERDICT_WORD = {"survives": "defended", "refuted": "refuted",
                 "uncertain": "uncertain", "error": "error"}


def _render_human_verdicts(rf_id: int, h: dict[str, Any]) -> list[str]:
    """List items for what humans have said about one finding (`verdicts.standing`):
    its own newest verdict, or how to record one, and the earlier verdict a deep run
    matched it to. A reader of the digest otherwise met a finding a human had already
    judged intended as if it were new. Notes are human prose and the matched title and
    file are model and target text, so all of it is made inert."""
    def said(v: dict[str, Any]) -> str:
        note = _text(v.get("note") or "")
        return (f"{_text(v['verdict'])}, by {_code(v.get('actor'))}, "
                f"{_text(v.get('created_at'))} UTC" + (f". Note: {note}" if note else ""))

    own, prior = h.get("own"), h.get("prior")
    out = [f"- Research finding: #{rf_id}"]
    out.append(f"- Human verdict: {said(own)}" if own else
               f"- Human verdict: none recorded. Record one with "
               f"`quarry deep-verdict {rf_id} intended|real|unclear --note \"...\"`")
    if prior:
        line = (f"- Matched an earlier finding: #{int(prior['rf_id'])} (run "
                f"{int(prior['run_id'])}, {_text(prior.get('basis') or 'matched')}), "
                f"{_text(prior.get('title') or 'untitled')} in {_code(prior.get('file'))}, "
                f"judged {said(prior)}")
        if prior.get("now"):
            line += f". That finding's verdict has since changed to {said(prior['now'])}"
        out.append(line)
    else:
        out.append("- Matched an earlier finding: none; new to human review")
    return out


def _render_research_finding(d: dict[str, Any]) -> str:
    """One deep-review finding as a Markdown section. Every target-derived string is made
    inert: the quote is verbatim source, so it goes in a fence it cannot close; the model's
    prose may echo target strings, so it is escaped to one inert paragraph; names and paths
    go in code spans. The refuters' reasons are model prose and are treated the same."""
    where = _code(d["file"] + (f":{int(d['line'])}" if d.get("line") else "")
                  if d.get("file") else "(no file recorded)")
    lines = [
        f"### {_text(d['title']) or 'Untitled finding'}",
        "",
        f"- Subsystem: {_code(d['subsystem'])}",
        f"- Lens: {_code(d['lens'])}",
        f"- Location: {where}",
        f"- Found by: {_code(d['model'])} (family {_code(d['family'])})",
        f"- Severity (model-claimed, not computed): {_text(d['severity'] or 'unstated')}",
        f"- Cross-family vote: {int(d['n_survived'])} defended, "
        f"{int(d['n_refuted'])} refuted"
        + (f", {int(d['n_unsupported'])} not rebutted (uncertain, or refuted without "
           f"evidence on the claim's path)" if d.get("n_unsupported") else ""),
        *_render_human_verdicts(int(d["id"]), d.get("human") or {}),
        "",
        "Claimed code:",
        "",
        _code_block(d["quote"] or "(no quote recorded)"),
        "",
        "Reasoning:",
        "",
        _text(d["reasoning"]) or "(none recorded)",
        "",
        "Attacker control:",
        "",
        _text(d["attacker_control"]) or "(none recorded)",
    ]
    critique = _text(d.get("self_critique") or "")
    if critique:
        lines += ["", "The model's own caveat:", "", critique]
    refs = []
    try:
        refs = json.loads(d.get("refutations") or "[]")
    except ValueError:
        refs = []
    if refs:
        lines += ["", "Cross-family review:"]
        for r in refs:
            if r.get("discarded"):
                continue
            word = _VERDICT_WORD.get(r.get("verdict", ""), _text(r.get("verdict", "?")))
            reason = _text(r.get("reason") or r.get("rationale") or "")
            g = r.get("grounding") if isinstance(r.get("grounding"), dict) else None
            if g and g.get("ok") is False:
                # The why names files and symbols from the target, so it is escaped too.
                word = (f"refuted, discarded because its evidence did not hold "
                        f"({_text(str(g.get('why', '')))})")
            lines.append(f"- {_code(r.get('model', '?'))}: {word}."
                         + (f" {reason}" if reason else ""))
    return "\n".join(lines)


def draft_research_digest(con: sqlite3.Connection, run_id: int, *,
                          out_dir: Path) -> ResearchDigest | None:
    """Write one Markdown digest of this run's Layer 2 deep-review survivors.

    A survivor is a finding whose quote verified against the source and that at least one
    cross-family model still defended after being told to kill it (`n_survived > 0`), or
    that every refuter tried to kill without quoting code on the claim's path that defeats
    it (decision F: "not rebutted"). The bar is `ensemble.KEPT_SQL`, shared with the funnel
    gate and the dashboard, and the order is the dashboard's, defended first.

    These are model-found candidates for human triage. They were NOT confirmed dynamically:
    no probe stood the target up and reproduced them, which is what the advisory drafts in
    the same directory record. The digest says so in its own words, because a human may read
    it next to those advisories. Returns None when the run has no such survivor."""
    rows = con.execute(
        f"""SELECT rf.id, rf.subsystem, rf.lens, rf.model, rf.family, rf.title,
                  rf.file, rf.quote, rf.severity, rf.reasoning,
                  rf.attacker_control, rf.self_critique, rf.refutations,
                  rf.n_refuted, rf.n_survived, rf.n_unsupported, r.target
             FROM research_findings rf
             JOIN research_runs rr ON rr.id = rf.research_id
             JOIN runs r          ON r.id = rr.run_id
            WHERE rr.run_id = ? AND {KEPT_SQL}
            ORDER BY rf.quote_verified DESC, rf.n_survived DESC, rf.n_refuted ASC,
                     rf.subsystem, rf.id""", (run_id,)).fetchall()
    if not rows:
        return None

    target = rows[0]["target"]
    body = [
        f"# Deep-review candidates for {_text(target.split('/')[-1])}",
        "",
        f"Quarry's Layer 2 multi-model review (run {int(run_id)}) produced "
        f"{len(rows)} finding(s) that cleared the cross-family gate: the quote verified "
        f"against the source, and at least one model from a different family defended the "
        f"claim after being instructed to refute it.",
        "",
        "These are candidates for human triage, not confirmed vulnerabilities. No probe "
        "stood the target up and reproduced them. Treat each as a lead to read, confirm, "
        "and only then report. Severity is the finding model's own label, never a computed "
        "score. Any confirmed-dynamic advisories for this run are separate files in this "
        "directory.",
        "",
        f"- Target: {_code(target)}",
        f"- Survivors: {len(rows)}",
        "",
        "---",
        "",
    ]
    body.append(("\n\n---\n\n").join(
        _render_research_finding({**dict(r), "human": verdicts.standing(con, r["id"])})
        for r in rows))
    body.append("")
    body.append("---")
    body.append("")
    body.append(f"Found with Quarry (Layer 2, run {int(run_id)}). A triage list to review, "
                "not a published advisory.")
    text = ("\n".join(body)).encode("utf-8")

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / digest_name(run_id)
    path.write_bytes(text)
    return ResearchDigest(path=path, n_findings=len(rows),
                          sha256=hashlib.sha256(text).hexdigest())


def _prior_check(ecosystem: str, package: str, clone_url: str, root: Path | None,
                 packages: list[tuple[str, str]] | None = None):
    """The local OSV lookup, or a PriorCheck saying why it did not run. A failure here
    must not stop a draft: the section then says "not checked". `packages` are the
    (ecosystem, name) pairs to search by name in place of (ecosystem, package)."""
    from .. import vulndb
    try:
        return vulndb.local_prior_advisories(ecosystem, package, clone_url, root=root,
                                             packages=packages)
    except Exception as e:                       # noqa: BLE001 - a gap, stated in the draft
        return vulndb.PriorCheck(False, f"lookup failed: {type(e).__name__}")


def _names_to_search(ecosystem: str, package: str,
                     declared: list) -> list[tuple[str, str]]:
    """What the prior lookup searches by name: every name a manifest declares and that
    is published (a private npm package is not), or the repository name in the guessed
    ecosystem when no manifest declares one (IMPROVEMENT-PLAN item 19)."""
    if not declared:
        return [(ecosystem, package)]
    return [(p.ecosystem, p.name) for p in declared if not p.skip]


def digest_name(run_id: int) -> str:
    """The digest's file name inside a run's report directory."""
    return f"{int(run_id)}-deep-review-candidates.md"


def record_digest(con: sqlite3.Connection, run_id: int, digest: ResearchDigest) -> None:
    """Note a written digest in the run manifest, so the dashboard can list it.

    The digest was written to disk and recorded nowhere, so the advisories page said
    "0 drafts" beside a file the report command had just named. It is not an
    `advisories` row: that table keys each row to one finding and one verdict, and the
    digest is many findings with no dynamic verdict. The manifest needs no schema
    change and holds what the page needs: where the file is, how many findings it
    holds, and the hash of the bytes written, so a later edit shows as a mismatch."""
    from datetime import datetime, timezone
    from .. import db
    rec = {"path": str(Path(digest.path).resolve()), "sha256": digest.sha256,
           "n_findings": digest.n_findings,
           "written_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}

    def change(m: dict[str, Any]) -> None:
        report = m.get("report") if isinstance(m.get("report"), dict) else {}
        report["digest"] = rec
        m["report"] = report
    db.update_manifest(con, run_id, change)


def draft_reports(con: sqlite3.Connection, run_id: int, src: Path, *,
                  out_dir: Path, vulndb_root: Path | None = None,
                  check_head: Any = None) -> list[Draft]:
    """Write a Markdown advisory for every finding whose latest dynamic verdict in the run
    is confirmed. Returns one Draft per file. Reproducible from the DB: the probe evidence was
    stored on the verdict as JSON.

    Three filters, because the template says "confirmed dynamically" and a human may send
    it. Only seat='dynamic' verdicts count; a model seat's opinion is not a probe. Only the
    latest such verdict per finding counts, so a re-run of validate that rejected or held a
    finding withdraws the earlier confirmation. And the stored evidence must carry the
    baseline comparison that confirmation requires (validate.adjudicate), so a verdict
    written before that rule, or by hand, is not drafted. needs-review is never drafted.

    The conditions come from the verdict's rationale (replay, probe, conditions, when
    the probe recorded them) and the run manifest's validate block. The prior-advisory
    lookup reads the local OSV copy under `vulndb_root` (default: `quarry db sync`'s
    directory) only when there is a draft to write, by the package names the manifests
    nearest the finding's file declare, once per distinct set of names.

    `check_head`, when given, is called once, before the first draft is written, and
    returns the head.HeadCheck every draft states. It is the only network request this
    function can cause, and only the CLI's --check-head passes one; without it each
    draft says HEAD was not re-checked and why."""
    from ..research.profile import profile_repo
    from .packages import declared_packages
    head: Any = None
    asked = check_head is None

    prof = profile_repo(src)
    ecosystem = guess_ecosystem(prof.primary_language)
    contacts = tuple(extract_security_contacts(src))
    policy = find_security_policy(src)
    manifest = db.read_manifest(con, run_id)
    validate = _dict(manifest.get("validate"))
    seed_notes = tuple(n for n in _dict(_dict(manifest.get("health")).get("validate"))
                       .get("seed") or [] if isinstance(n, str))
    priors: dict[tuple, Any] = {}
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    rows = con.execute(
        """SELECT v.id AS verdict_id, v.finding_id, v.cwe, v.rationale, v.created_at,
                  v.reason, f.path, f.symbol, r.target, r.clone_url, r.git_sha,
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
        declared = tuple(declared_packages(src, d["path"]))
        search = _names_to_search(ecosystem, package, list(declared))
        if (key := tuple(search)) not in priors:
            priors[key] = _prior_check(ecosystem, package, d["clone_url"], vulndb_root,
                                       packages=search)
        prior = priors[key]
        if not asked:
            head, asked = check_head(), True

        def ev_text(key: str, default: str = "") -> str:
            return scrub_text(ev.get(key) or default)
        ctx = DisclosureContext(
            target=d["target"], clone_url=d["clone_url"], git_sha=d["git_sha"],
            cwe=d["cwe"], file=d["path"], symbol=d["symbol"], line=d["start_line"],
            summary=ev_text("summary"), request=ev_text("request"),
            observed=ev_text("observed"), determinism=ev_text("determinism", "unknown"),
            baseline=ev_text("baseline"),
            ecosystem=ecosystem, package=package, security_contacts=contacts,
            run_id=run_id, verdict_time=d["created_at"],
            verdict="confirmed", verdict_reason=scrub_text(d["reason"] or ""),
            replay=ev.get("replay"), probe=ev.get("probe"),
            conditions=ev.get("conditions"), validate=validate, seed_notes=seed_notes,
            prior=prior, security_policy=policy, packages=declared, head=head)
        path = out_dir / f"{run_id}-{_slug(d['cwe'] or 'finding')}-{d['finding_id'][:8]}.md"
        body = render_report(ctx).encode("utf-8")
        path.write_bytes(body)
        written.append(Draft(path=path, finding_id=d["finding_id"],
                             verdict_id=int(d["verdict_id"]),
                             sha256=hashlib.sha256(body).hexdigest()))
    return written
