"""Run orchestration. Tier 0: holds the DB, never opens a clone.

The orchestrator reads target bytes only as data that has already crossed the taint
boundary. It never interprets target content as a path, a command, or a config — that
is the invariant from docs/PLAN.md §4.1, stated in its testable form.
"""
from __future__ import annotations

import json
import os
import platform
import shutil
import sqlite3
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import db, taint
from .config import Paths
from .ingest import RunVolume, clone_target
from .ingest.clone import canonical_target

# OSI-approved identifiers we recognise for the CodeQL gate (docs/PLAN.md §5).
# Conservative on purpose: an unknown license means "not OSI", which means no CodeQL.
OSI_SPDX = {
    "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "MPL-2.0",
    "GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0", "GPL-3.0-only",
    "GPL-3.0-or-later", "LGPL-2.1", "LGPL-2.1-only", "LGPL-2.1-or-later",
    "LGPL-3.0", "LGPL-3.0-only", "LGPL-3.0-or-later", "AGPL-3.0", "AGPL-3.0-only",
    "AGPL-3.0-or-later", "EPL-2.0", "Unlicense", "Zlib", "PostgreSQL", "Artistic-2.0",
    "BSL-1.0", "CDDL-1.0", "EUPL-1.2", "NCSA", "OSL-3.0", "Python-2.0",
}

LICENSE_FILES = ("LICENSE", "LICENSE.txt", "LICENSE.md", "LICENCE", "LICENCE.txt",
                 "COPYING", "COPYING.txt", "LICENSE-MIT", "LICENSE-APACHE")

# Cheap, deterministic license identification. Not a replacement for a real scanner —
# it exists to answer one question: may we legally run CodeQL here?
_LICENSE_MARKERS = (
    ("Apache-2.0",   ("Apache License", "Version 2.0")),
    ("MIT",          ('Permission is hereby granted, free of charge',)),
    ("BSD-3-Clause", ("Redistribution and use in source and binary forms",
                      "Neither the name of")),
    ("BSD-2-Clause", ("Redistribution and use in source and binary forms",)),
    ("AGPL-3.0",     ("GNU AFFERO GENERAL PUBLIC LICENSE",)),
    ("LGPL-3.0",     ("GNU LESSER GENERAL PUBLIC LICENSE", "Version 3")),
    ("LGPL-2.1",     ("GNU LESSER GENERAL PUBLIC LICENSE", "Version 2.1")),
    ("GPL-3.0",      ("GNU GENERAL PUBLIC LICENSE", "Version 3")),
    ("GPL-2.0",      ("GNU GENERAL PUBLIC LICENSE", "Version 2")),
    ("MPL-2.0",      ("Mozilla Public License Version 2.0",)),
    ("ISC",          ("ISC License",)),
    ("Unlicense",    ("This is free and unencumbered software released into the public domain",)),
)


def detect_license(src: Path) -> tuple[str | None, bool]:
    """-> (spdx_or_None, is_osi). Unknown is treated as not-OSI, deliberately."""
    for name in LICENSE_FILES:
        p = src / name
        if not p.is_file():
            continue
        try:
            head = p.read_text(errors="replace")[:8000]
        except OSError:
            continue
        for spdx, markers in _LICENSE_MARKERS:
            if all(m.lower() in head.lower() for m in markers):
                return spdx, spdx in OSI_SPDX
        return "UNKNOWN", False
    return None, False


def _version(binary: str, *args: str) -> str | None:
    """Resolve on the same PATH a sandboxed scanner gets, or `doctor` reports tools as
    absent that the scan will happily find — the two must never disagree."""
    from .sandbox.spawn import BASE_ENV, tools_dir
    path = shutil.which(binary, path=f"{tools_dir() / 'bin'}:{BASE_ENV['PATH']}")
    if not path:
        return None
    try:
        out = subprocess.run([path, *(args or ("--version",))], capture_output=True,
                             text=True, timeout=20, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return (out.stdout or out.stderr).strip().splitlines()[0][:120] if (out.stdout or out.stderr) else None


def tool_manifest() -> dict[str, str | None]:
    """Reproducibility manifest (Visa's pattern, adopted in RESEARCH §6).
    Without it you cannot compare two runs, and comparing runs is the point."""
    return {
        "platform": f"{platform.system()} {platform.release()} {platform.machine()}",
        "git": _version("git"),
        "opengrep": _version("opengrep"),
        "semgrep": _version("semgrep"),
        "trivy": _version("trivy"),
        "grype": _version("grype"),
        "syft": _version("syft"),
        "osv-scanner": _version("osv-scanner"),
        "gitleaks": _version("gitleaks", "version"),
        "bandit": _version("bandit"),
        "checkov": _version("checkov"),
        "zizmor": _version("zizmor"),
    }


@dataclass
class IngestResult:
    run_id: int
    target: str
    git_sha: str | None
    license_spdx: str | None
    license_osi: bool
    files: int
    symlinks_removed: int
    configs_quarantined: int
    volume: RunVolume | None = None
    notes: list[str] = field(default_factory=list)


def ingest(paths: Paths, con: sqlite3.Connection, target: str, *,
           size_gb: int = 20, keep_volume: bool = True) -> IngestResult:
    """P0 ingest: volume -> hardened clone -> scrub -> quarantine -> record.

    Nothing here interprets target content. The clone runs under the clone profile with
    an empty credential helper; the scrub and quarantine run in Tier 0 but only ever
    call lstat/unlink/move on paths derived from os.walk, never from file *contents*.
    """
    target = canonical_target(target)
    clone_url = target if "://" in target else f"https://github.com/{target}"
    manifest = tool_manifest()
    run_id = db.start_run(con, target, clone_url, manifest)
    db.egress(con, run_id, "clone", "github.com", note="anonymous https, no credential")

    notes: list[str] = []
    vol: RunVolume | None = None
    try:
        # Inside the try: a volume that fails to create must still mark the run
        # failed, or the row says "running" forever.
        vol = RunVolume.create(run_id, paths.runs, size_gb=size_gb)
        res = clone_target(target, vol.mount)
        if not res.ok:
            db.finish_run(con, run_id, "failed", volume_path=str(vol.mount))
            raise RuntimeError(f"clone failed ({res.returncode}): {res.stderr_tail.strip()[:300]}")

        with db.tx(con):
            for e in res.quarantined:
                con.execute(
                    """INSERT INTO quarantined (run_id, original_path, kind, detail, sha256)
                       VALUES (?,?,?,?,?)""",
                    (run_id, taint.scrub_text(e.original_path, 1024), e.kind,
                     taint.scrub_text(e.detail, 512), e.sha256))

        spdx, osi = detect_license(res.src)
        if not osi:
            notes.append(f"license {spdx or 'absent'} is not OSI-approved — CodeQL is gated off")

        files = sum(1 for p in res.src.rglob("*") if p.is_file() and ".git" not in p.parts)
        symlinks = sum(1 for e in res.quarantined if e.kind == "symlink")
        configs = len(res.quarantined) - symlinks

        db.finish_run(con, run_id, "done", git_sha=res.git_sha, license_spdx=spdx,
                      license_osi=int(osi), volume_path=str(vol.mount),
                      manifest={**manifest, "files": files})

        return IngestResult(run_id, target, res.git_sha, spdx, osi, files,
                            symlinks, configs, vol if keep_volume else None, notes)
    except Exception:
        db.finish_run(con, run_id, "failed",
                      volume_path=str(vol.mount) if vol is not None else None)
        if vol is not None:
            vol.detach()
        raise
    finally:
        if vol is not None and not keep_volume:
            vol.release()


# ==================================================================== Layer 1

@dataclass
class ScanSummary:
    run_id: int
    per_tool: dict[str, dict[str, Any]] = field(default_factory=dict)
    occurrences: int = 0
    findings: int = 0
    dropped_paths: int = 0
    evidence_blobs: int = 0
    evidence_bytes: int = 0
    finding_ids: set[str] = field(default_factory=set, repr=False)
    health: dict[str, list[str]] = field(default_factory=dict)


class AlreadyScanned(RuntimeError):
    """A tool already returned results for this run."""


# Lockfiles osv-scanner reads. Used only to ask whether "0 vulnerabilities" was a scan.
LOCKFILES = frozenset({
    "poetry.lock", "Pipfile.lock", "pdm.lock", "uv.lock", "requirements.txt",
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
    "go.sum", "Cargo.lock", "Gemfile.lock", "composer.lock", "mix.lock",
    "pubspec.lock", "gradle.lockfile", "packages.lock.json", "conan.lock",
})
_SKIP_WALK = {".git", "node_modules", "vendor", ".venv", "venv"}


def _lockfiles(src: Path) -> int:
    n = 0
    for root, dirs, files in os.walk(src):
        dirs[:] = [d for d in dirs if d not in _SKIP_WALK]
        n += sum(1 for f in files if f in LOCKFILES)
    return n


_TRIVY_IGNORE = b"trivy:ignore"


def trivy_inline_ignores(src: Path, *, cap: int = 1024 * 1024) -> list[str]:
    """Files in the clone that carry a `trivy:ignore` comment. Trivy obeys these for
    misconfiguration results and drops the result from its output with no trace;
    `--show-suppressed` does not bring it back and no flag turns it off (MEASURED,
    trivy 0.76.1: `#trivy:ignore:AVD-DS-0001` above FROM removed DS-0001). The clone is
    read-only to scanners, so the comment cannot be stripped; it is reported instead.
    A substring match, read without following links, nothing interpreted. Vendored
    trees are walked too, because Trivy scans them."""
    hits: list[str] = []
    for root, dirs, files in os.walk(src):
        dirs[:] = [d for d in dirs if d != ".git"]
        for name in files:
            p = Path(root) / name
            try:
                if _TRIVY_IGNORE in taint.read_capped(p, cap):
                    hits.append(p.relative_to(src).as_posix())
            except (taint.TaintError, OSError):
                continue
    return sorted(hits)


# Source extensions every opengrep rule pack run is expected to read. MEASURED with the
# installed pack (opengrep 1.27.1, all 25 trees): one file of each extension below was
# in `paths.scanned`. The `generic` tree targets every file, .md and .txt included, so
# this list undercounts on purpose; it is a denominator, not a language map.
SOURCE_EXTS = frozenset({
    ".py", ".pyi", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts",
    ".go", ".java", ".rb", ".php", ".rs", ".scala", ".kt", ".kts", ".cs", ".c", ".h",
    ".cpp", ".swift", ".sol", ".ex", ".exs", ".clj", ".cljs", ".ml", ".mli", ".sh",
    ".bash", ".tf", ".hcl",
})
_EXAMPLES = 10


def source_files(src: Path) -> set[str]:
    """Clone-relative paths of every source file in the tree, by extension. Walks the
    tree without following links and reads no content. Everything but .git counts:
    a vendored or test file is still code a scanner was supposed to read."""
    found: set[str] = set()
    for root, dirs, files in os.walk(src, followlinks=False):
        dirs[:] = [d for d in dirs if d != ".git"]
        for name in files:
            if os.path.splitext(name)[1].lower() in SOURCE_EXTS:
                found.add((Path(root) / name).relative_to(src).as_posix())
    return found


def coverage_summary(cov: Any, expected: set[str]) -> dict[str, Any]:
    """The manifest form of a tool's Coverage: counts, plus a few example paths for
    each gap so the run page can name them. `unexplained` is a source file the tool
    neither scanned nor reported skipping, which is the silent kind of loss."""
    # A skip can name a directory: opengrep reports an ignored tree as `vendor`, not
    # file by file. A file under a reported directory is explained.
    reported = set().union(*cov.skipped.values()) if cov.skipped else set()
    unexplained = sorted(
        f for f in expected - cov.scanned
        if f not in reported
        and not any(p.as_posix() in reported for p in Path(f).parents))
    return {
        "scanned": len(cov.scanned),
        "expected": len(expected),
        "skipped": {r: {"n": len(ps), "examples": sorted(ps)[:_EXAMPLES]}
                    for r, ps in sorted(cov.skipped.items())},
        "errors": dict(sorted(cov.errors.items())),
        "unexplained": {"n": len(unexplained), "examples": unexplained[:_EXAMPLES]},
        "unreported": list(cov.unreported),
    }


# How each opengrep skip reason reads in a health warning. An unknown reason is shown
# as the tool wrote it.
_SKIP_WORDS = {
    "semgrepignore_patterns_match": "skipped by an ignore list",
    "exceeded_size_limit": "skipped as larger than --max-target-bytes",
    "analysis_failed_parser_or_internal_error":
        "only partly analyzed (parse error, or a per-file timeout that stops the "
        "remaining rules on that file)",
}


def coverage_health(cov: dict[str, Any]) -> list[str]:
    msgs: list[str] = []
    if cov.get("unreported"):
        msgs.append(f"no target report from {len(cov['unreported'])} invocation(s) "
                    f"({', '.join(cov['unreported'][:5])}); what they scanned is unknown.")
    for reason, s in (cov.get("skipped") or {}).items():
        eg = ", ".join(s["examples"][:3])
        msgs.append(f"{s['n']} path(s) {_SKIP_WORDS.get(reason, f'skipped ({reason})')}"
                    f", e.g. {eg}")
    if errs := cov.get("errors"):
        msgs.append("rule errors on scanned files: "
                    + ", ".join(f"{k} {v}" for k, v in errs.items()))
    un = cov.get("unexplained") or {}
    if un.get("n"):
        msgs.append(f"{un['n']} of {cov.get('expected', '?')} source file(s) were neither "
                    f"scanned nor reported skipped, e.g. {', '.join(un['examples'][:3])}")
    return msgs


def scan_health(per_tool: dict[str, dict[str, Any]], lockfiles: int) -> dict[str, list[str]]:
    """Ways a tool can lose its output while the run still reports success. Each one
    has happened: Checkov's paths left every finding without an evidence window (21 of
    21 killed), osv-scanner returned nothing for a whole run because one GIT
    dependency aborted it, and opengrep's built-in ignore list skipped every test/,
    vendor/, build/ and dist/ file. A warning here is a question to answer, not a
    verdict."""
    out: dict[str, list[str]] = {}
    for tool, info in per_tool.items():
        msgs = []
        if info.get("error"):
            msgs.append(f"failed: {info['error']}")
        if isinstance(info.get("coverage"), dict):
            msgs += coverage_health(info["coverage"])
        if dropped := info.get("dropped"):
            msgs.append(f"{sum(dropped.values())} result(s) dropped from the report: "
                        + ", ".join(f"{k} {v}" for k, v in sorted(dropped.items())))
        if bad := info.get("bad_lines"):
            msgs.append(f"{bad} result(s) had a line number that is not a positive "
                        f"integer and were stored without a line")
        lined, got = info.get("lined", 0), info.get("captured", 0)
        if lined and got / lined < 0.5:
            msgs.append(f"evidence captured for {got} of {lined} located finding(s); "
                        f"the rest will be killed by quote-verify. Check the tool's paths.")
        if (tool == "osv-scanner" and info.get("ok") and not info.get("note")
                and not info.get("records") and lockfiles):
            msgs.append(f"0 vulnerabilities across {lockfiles} lockfile(s). A clean "
                        f"result is possible; confirm it parsed them.")
        out[tool] = msgs
    return out


def scan(paths: Paths, con: sqlite3.Connection, run_id: int, *,
         only: list[str] | None = None, timeout: int = 1800) -> ScanSummary:
    """Run the deterministic layer over an already-ingested run.

    Every tool runs under Tier 1; every result crosses the taint boundary before it
    becomes a row. Nothing is filtered here — suppression is the funnel's job and it
    happens as ledger events, never as a dropped row (D8).
    """
    from .scanners import registry

    row = con.execute("SELECT target, git_sha, volume_path, status FROM runs WHERE id=?",
                      (run_id,)).fetchone()
    if row is None:
        raise RuntimeError(f"no run {run_id}")
    if row["status"] != "done":
        raise RuntimeError(f"run {run_id} is {row['status']}, not a completed ingest")
    target, git_sha = row["target"], row["git_sha"]

    summary = ScanSummary(run_id)
    scanners = registry()
    chosen = [s for n, s in scanners.items() if not only or n in only]
    if again := sorted(_already_scanned(con, run_id) & {s.name for s in chosen}):
        raise AlreadyScanned(
            f"run {run_id} already has results from {', '.join(again)}. A second scan "
            f"would add a second copy of every finding. Re-run only a tool that failed or "
            f"was skipped (--only), or ingest the target into a new run.")
    vol = RunVolume.attach_existing(run_id, paths.runs)
    src = vol.src
    # A scan that quietly reports "0 findings" against an empty tree is worse than a
    # failure: it looks like a clean repo. Fail loudly instead.
    if not src.is_dir() or not any(src.iterdir()):
        raise RuntimeError(f"run {run_id}: source tree at {src} is empty — "
                           f"re-ingest, or the volume was released")
    # Gitleaks first, whatever the registry order: every window built after it is
    # redacted with every secret it found. A scan that skips gitleaks still redacts
    # with the report an earlier scan left on the volume.
    chosen.sort(key=lambda s: s.name != "gitleaks")
    secrets: set[str] = set(taint.run_secrets(vol.mount))
    expected: set[str] | None = None

    for sc in chosen:
        outcome = sc.run(vol.mount, src, timeout=timeout)
        if sc.name == "gitleaks" and outcome.ok:
            secrets |= {r.secret for r in outcome.records if r.secret}
            secrets |= taint.run_secrets(vol.mount)
        summary.per_tool[sc.name] = {
            "ok": outcome.ok, "rc": outcome.returncode,
            "seconds": round(outcome.duration_s, 1),
            "records": len(outcome.records),
            "skipped": outcome.skipped, "error": outcome.error, "note": outcome.note,
            "nothing_to_scan": outcome.nothing_to_scan,
            "lined": 0, "captured": 0,
            "dropped": dict(outcome.dropped), "bad_lines": 0,
        }
        if outcome.coverage is not None:
            if expected is None:
                expected = source_files(src)
            summary.per_tool[sc.name]["coverage"] = coverage_summary(outcome.coverage,
                                                                     expected)
        if outcome.ok:
            _persist(con, run_id, target, git_sha, src, sc.name, outcome.records, summary,
                     secrets=frozenset(secrets))
        # Per tool, so a scan interrupted part way still records what did run.
        with db.tx(con):
            _record_tool(con, run_id, sc.name, summary.per_tool[sc.name])

    summary.health = scan_health(summary.per_tool, _lockfiles(src))
    if "opengrep" in summary.per_tool and not summary.per_tool["opengrep"].get("skipped"):
        from .scanners.tools import Opengrep
        have = db.read_manifest(con, run_id).get("opengrep")
        if have and have.strip() != Opengrep.MEASURED_VERSION:
            summary.health.setdefault("opengrep", []).append(
                f"opengrep {have.strip()} is not {Opengrep.MEASURED_VERSION}, the version "
                f"its internal ignore flag and target report were measured on; check "
                f"coverage before trusting a clean result")
    if "trivy" in summary.per_tool and (ignored := trivy_inline_ignores(src)):
        shown = ", ".join(ignored[:5])
        if len(ignored) > 5:
            shown += f" and {len(ignored) - 5} more"
        summary.health.setdefault("trivy", []).append(
            f"{len(ignored)} file(s) carry trivy:ignore comments, which Trivy obeys and "
            f"drops without a trace: {shown}")
    # What the SCA tools scanned against. A clean result from a months-old database
    # looks the same as a clean result from today's, so the age is kept with the run.
    from . import vulndb
    used = [t for t in summary.per_tool if t in vulndb.DB_OF_TOOL]
    ages = vulndb.ages()
    with db.tx(con):
        db.set_health(con, run_id, "scan", summary.health)
        if used:
            db.update_manifest(con, run_id, lambda m: m.setdefault("vulndb", {}).update(
                {vulndb.DB_OF_TOOL[t]: ages[vulndb.DB_OF_TOOL[t]] for t in used}))
            db.set_health(con, run_id, "vulndb", vulndb.stale_warnings(ages, used))
    db.bump_producer_counts(con)
    return summary


def _already_scanned(con: sqlite3.Connection, run_id: int) -> set[str]:
    """Tools that returned results for this run: a recorded clean outcome, or any
    occurrence at all (a run scanned before outcomes were recorded). A tool that failed
    or was skipped is not in the set, so it can be re-run."""
    tools = (db.read_manifest(con, run_id).get("scan") or {}).get("tools") or {}
    done = {t for t, info in tools.items() if isinstance(info, dict) and info.get("ok")}
    done |= {r["tool"] for r in con.execute(
        "SELECT DISTINCT p.tool FROM occurrences o JOIN producers p ON p.id = o.producer_id "
        "WHERE o.run_id = ? AND p.tool != 'deep'", (run_id,))}
    return done


def _record_tool(con: sqlite3.Connection, run_id: int, tool: str,
                 info: dict[str, Any]) -> None:
    """Keep each tool's outcome in the manifest. It was printed and thrown away, so a
    run where Trivy timed out looked the same as one where Trivy found nothing."""
    from datetime import datetime, timezone
    entry = {**info, "at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    db.update_manifest(con, run_id, lambda m: m.setdefault("scan", {})
                       .setdefault("tools", {}).__setitem__(tool, entry))


def _persist(con: sqlite3.Connection, run_id: int, target: str, git_sha: str | None,
             src: Path, tool: str, records: list, summary: ScanSummary, *,
             secrets: frozenset[str] = frozenset()) -> None:
    """Write one tool's records. Single writer; one transaction per tool so a crash
    mid-scan loses at most one tool's output.

    `secrets` is every secret known for the run. All of them are redacted from every
    window, message and raw result, whichever tool produced the record: a bandit hit
    two lines below a key captures the same window the Gitleaks hit does."""
    from .taint import (Evidence, extract_evidence, finding_id, line_number, redact_in,
                        redact_obj, redact_secret)

    with db.tx(con):
        for rec in records:
            pid = db.upsert_producer(con, tool, rec.rule_id, cwe=rec.cwe,
                                     default_severity=rec.severity)
            known = (secrets | {rec.secret}) if rec.secret else secrets

            # A line is the tool's word, and a tool can write "12", 12.5 or -4. The
            # first two raised in extract_evidence, which rolled back this tool's rows
            # and ended the scan before the tools after it (IMPROVEMENT-PLAN P4 side
            # finding). Anything but a positive integer is stored as no line, and
            # counted so the loss shows in the run's health.
            start, end = line_number(rec.start_line), line_number(rec.end_line)
            if ((start is None and rec.start_line is not None)
                    or (end is None and rec.end_line is not None)):
                if tool in summary.per_tool:
                    summary.per_tool[tool]["bad_lines"] = \
                        summary.per_tool[tool].get("bad_lines", 0) + 1
            rec.start_line, rec.end_line = start, end

            # Evidence first, redacted with every known secret (Seat 4).
            ev: Evidence | None = extract_evidence(
                src, Path(rec.path), rec.start_line, end_line=rec.end_line, secrets=known)
            if rec.start_line and tool in summary.per_tool:
                summary.per_tool[tool]["lined"] += 1
                summary.per_tool[tool]["captured"] += ev is not None
            blob_sha = None
            if ev is not None:
                blob_sha = ev.sha
                cur = con.execute("SELECT 1 FROM evidence_blobs WHERE sha=?", (ev.sha,))
                if cur.fetchone() is None:
                    con.execute(
                        """INSERT INTO evidence_blobs
                             (sha,path,file_sha256,git_sha,start_line,end_line,body,bytes)
                           VALUES (?,?,?,?,?,?,?,?)""",
                        (ev.sha, ev.path, ev.file_sha256, git_sha,
                         ev.start_line, ev.end_line, ev.body, ev.bytes_raw))
                    summary.evidence_blobs += 1
                    summary.evidence_bytes += len(ev.body)

            # finding_id is line-number-free: keyed on the flagged line(s) with
            # whitespace stripped, or on the message when there is no line.
            content = ev.match_sha if ev else None
            fid = finding_id(target, rec.path, pid, content,
                             fallback=redact_in(rec.message, known))
            con.execute(
                """INSERT INTO findings (id,target,path,symbol_sha,producer_id,
                                         first_seen_run,last_seen_run)
                   VALUES (?,?,?,?,?,?,?)
                   ON CONFLICT(id) DO UPDATE SET last_seen_run = excluded.last_seen_run""",
                (fid, target, rec.path, content, pid, run_id, run_id))
            # total_changes is cumulative for the connection, so it was always truthy
            # and this counted occurrences. Count distinct ids instead.
            summary.finding_ids.add(fid)
            summary.findings = len(summary.finding_ids)

            red = redact_secret(rec.secret) if rec.secret else None
            con.execute(
                """INSERT INTO occurrences
                     (run_id,finding_id,producer_id,path,start_line,end_line,message,
                      severity,fingerprint,blob_sha,redacted,secret_prefix,secret_sha,raw_result)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (run_id, fid, pid, rec.path, rec.start_line, rec.end_line,
                 redact_in(rec.message, known), rec.severity, rec.fingerprint, blob_sha,
                 1 if red else 0, red.prefix if red else None,
                 red.sha256 if red else None,
                 json.dumps(redact_obj(rec.raw, known), default=str,
                            sort_keys=True)[:200_000]))
            summary.occurrences += 1
