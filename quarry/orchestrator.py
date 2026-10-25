"""Run orchestration. Tier 0: holds the DB, never opens a clone.

The orchestrator reads target bytes only as data that has already crossed the taint
boundary. It never interprets target content as a path, a command, or a config — that
is the invariant from docs/PLAN.md §4.1, stated in its testable form.
"""
from __future__ import annotations

import json
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
    manifest = tool_manifest()
    run_id = db.start_run(con, target, f"https://github.com/{target}", manifest)
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
    vol = RunVolume.attach_existing(run_id, paths.runs)
    src = vol.src
    # A scan that quietly reports "0 findings" against an empty tree is worse than a
    # failure: it looks like a clean repo. Fail loudly instead.
    if not src.is_dir() or not any(src.iterdir()):
        raise RuntimeError(f"run {run_id}: source tree at {src} is empty — "
                           f"re-ingest, or the volume was released")
    target, git_sha = row["target"], row["git_sha"]

    summary = ScanSummary(run_id)
    scanners = registry()
    chosen = [s for n, s in scanners.items() if not only or n in only]
    # Gitleaks first, whatever the registry order: every window built after it is
    # redacted with every secret it found. A scan that skips gitleaks still redacts
    # with the report an earlier scan left on the volume.
    chosen.sort(key=lambda s: s.name != "gitleaks")
    secrets: set[str] = set(taint.run_secrets(vol.mount))

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
        }
        if not outcome.ok:
            continue
        _persist(con, run_id, target, git_sha, src, sc.name, outcome.records, summary,
                 secrets=frozenset(secrets))

    db.bump_producer_counts(con)
    return summary


def _persist(con: sqlite3.Connection, run_id: int, target: str, git_sha: str | None,
             src: Path, tool: str, records: list, summary: ScanSummary, *,
             secrets: frozenset[str] = frozenset()) -> None:
    """Write one tool's records. Single writer; one transaction per tool so a crash
    mid-scan loses at most one tool's output.

    `secrets` is every secret known for the run. All of them are redacted from every
    window, message and raw result, whichever tool produced the record: a bandit hit
    two lines below a key captures the same window the Gitleaks hit does."""
    from .taint import (Evidence, extract_evidence, finding_id, redact_in, redact_obj,
                        redact_secret)

    with db.tx(con):
        for rec in records:
            pid = db.upsert_producer(con, tool, rec.rule_id, cwe=rec.cwe,
                                     default_severity=rec.severity)
            known = (secrets | {rec.secret}) if rec.secret else secrets

            # Evidence first, redacted with every known secret (Seat 4).
            ev: Evidence | None = extract_evidence(
                src, Path(rec.path), rec.start_line, end_line=rec.end_line, secrets=known)
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
