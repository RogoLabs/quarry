"""Is the commit an advisory was observed at still the target's HEAD? (IMPROVEMENT-PLAN
item 19.)

The clone is depth 1 and report drafting is offline, so the honest check is the smallest
one: ask the remote for its HEAD with `git ls-remote <clone url> HEAD` and compare it with
the commit the run cloned. Only the commit is compared. Nothing is fetched and nothing is
re-tested, so a HEAD that moved says the observation may be stale, and a HEAD that did not
move says only that no newer commit exists on the default branch.

It goes out the way ingest's clone does: the same git with hooks off, file and ext
protocols refused and an empty credential helper, under the same sandbox profile, with no
terminal prompt and an askpass that answers nothing. The egress ledger gets its row
before the request leaves, as ingest's does.

Opt-in (`quarry report --check-head`), not automatic. Drafting has been offline, and the
reporter decides when Quarry reaches the network: this request goes to the target's own
git host at the moment someone drafts an unpublished advisory about it, and on a
self-hosted forge that shows in the maintainer's logs. Without the flag the draft says
"not re-checked" and why, and re-drafting gives the same bytes.
"""
from __future__ import annotations

import re
import sqlite3
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

from .. import db

NOT_REQUESTED = ("report drafting makes no network request unless run with "
                 "--check-head")
STAGE = "report-head-check"
_SHA = re.compile(r"^([0-9a-f]{40}|[0-9a-f]{64})\tHEAD$", re.M)
_URL = re.compile(r"https://[A-Za-z0-9.-]+(?::\d+)?/[A-Za-z0-9._~/%-]+")

# (rundir, argv, timeout) -> (returncode, stdout)
Runner = Callable[[Path, list[str], int], tuple[int, str]]


@dataclass(frozen=True)
class HeadCheck:
    checked: bool
    reason: str = ""             # why it was not checked, when checked is False
    observed: str | None = None  # the commit the run cloned
    head: str | None = None      # the remote's HEAD when it was checked
    host: str = ""
    at: str = ""                 # UTC, ISO seconds

    @property
    def moved(self) -> bool | None:
        if not (self.checked and self.observed and self.head):
            return None
        return self.head != self.observed


def ls_remote_argv(url: str) -> list[str]:
    """The ingest clone's git hardening, for ls-remote."""
    return ["/usr/bin/git",
            "-c", "core.hooksPath=/dev/null",
            "-c", "protocol.file.allow=never",
            "-c", "protocol.ext.allow=never",
            "-c", "credential.helper=",
            "ls-remote", url, "HEAD"]


def _sandboxed(rundir: Path, argv: list[str], timeout: int) -> tuple[int, str]:
    from ..sandbox import CLONE_PROFILE, tier1
    res = tier1(rundir, argv, name="head-check", cwd=rundir / "out", timeout=timeout,
                profile=CLONE_PROFILE,
                env={"GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "/usr/bin/true"})
    return res.returncode, res.stdout_bytes(64 * 1024).decode("utf-8", "replace")


def check_head(con: sqlite3.Connection, run_id: int, rundir: Path, *,
               runner: Runner | None = None, timeout: int = 60) -> HeadCheck:
    """Compare the run's cloned commit with the remote's HEAD, and record the result in
    the run manifest (`report.head_check`). Every outcome is a HeadCheck; a failure is a
    reason the draft states, never an exception."""
    from ..ingest.clone import _https_url
    row = con.execute("SELECT clone_url, git_sha FROM runs WHERE id=?",
                      (run_id,)).fetchone()
    if row is None:
        return HeadCheck(False, f"no run {run_id}")
    observed = row["git_sha"]
    url = _https_url(row["clone_url"] or "")
    host = (urlsplit(url).hostname or "") if url.startswith("https://") else ""
    if not observed:
        hc = HeadCheck(False, "the run recorded no commit to compare with")
    elif not host or not _URL.fullmatch(url):
        hc = HeadCheck(False, "the clone URL is not a plain https URL", observed)
    else:
        at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with db.tx(con):
            db.egress(con, run_id, STAGE, host,
                      note="git ls-remote HEAD for the advisory draft; anonymous https, "
                           "no credential")
        try:
            rc, out = (runner or _sandboxed)(Path(rundir), ls_remote_argv(url), timeout)
        except Exception as e:                   # noqa: BLE001 - a reason, not a crash
            rc, out = -1, f"{type(e).__name__}"
        m = _SHA.search(out or "") if rc == 0 else None
        if rc != 0:
            hc = HeadCheck(False, f"git ls-remote failed (exit {rc})", observed,
                           host=host, at=at)
        elif m is None:
            hc = HeadCheck(False, "git ls-remote returned no HEAD", observed, host=host,
                           at=at)
        else:
            hc = HeadCheck(True, observed=observed, head=m.group(1), host=host, at=at)
    def change(mf: dict) -> None:
        report = mf.get("report") if isinstance(mf.get("report"), dict) else {}
        report["head_check"] = {**asdict(hc), "moved": hc.moved}
        mf["report"] = report
    with db.tx(con):
        db.update_manifest(con, run_id, change)
    return hc
