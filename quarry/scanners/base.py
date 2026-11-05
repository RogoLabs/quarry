"""Scanner adapters.

Every adapter is the same shape: build an argv, run it under Tier 1 containment, and
turn its native output into normalised records. Three rules hold for all of them:

  * the tool never sees a credential and never reaches the network (the profile);
  * the tool's native output is preserved verbatim in `raw` (D9) — SARIF is an export
    projection, and OSV-Scanner's SARIF in particular destroys the `purl` and
    fixed-version that the advisory composer needs;
  * paths and messages cross the taint boundary before they become rows.

`producer_id` is assigned from run one so the cross-repo precision ledger starts
accumulating immediately — that is the mechanism by which the deterministic layer
improves, and Seat 1 made it a condition of endorsement.
"""
from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

from .. import taint
from ..sandbox import tier1
from ..sandbox.spawn import BASE_ENV, tools_dir


@dataclass
class Record:
    """One normalised finding, pre-database."""
    tool: str
    rule_id: str
    path: str                       # relative to the clone, already validated
    start_line: int | None = None
    end_line: int | None = None
    message: str = ""
    severity: str = "info"          # the tool's claim. Never a sort key (§2.3).
    cwe: str | None = None
    fingerprint: str | None = None
    secret: str | None = None       # plaintext, redacted before it reaches the DB
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class Coverage:
    """What a tool says it looked at, read from the tool's own report.

    Zero findings from a tool is not evidence that it read a file: Opengrep's built-in
    ignore list dropped every test/, vendor/, build/ and dist/ file without a word
    (IMPROVEMENT-PLAN item 15). A tool that can say which files it scanned and which it
    skipped carries that here, so the orchestrator can compare it with the tree."""
    scanned: set[str] = field(default_factory=set)            # clone-relative paths
    skipped: dict[str, set[str]] = field(default_factory=dict)  # reason -> paths
    errors: dict[str, int] = field(default_factory=dict)        # error type -> count
    unreported: list[str] = field(default_factory=list)         # invocations with no report

    def merge(self, other: "Coverage") -> None:
        self.scanned |= other.scanned
        for reason, ps in other.skipped.items():
            self.skipped.setdefault(reason, set()).update(ps)
        for kind, n in other.errors.items():
            self.errors[kind] = self.errors.get(kind, 0) + n
        self.unreported += other.unreported


@dataclass
class ScanOutcome:
    tool: str
    ok: bool
    returncode: int
    duration_s: float
    records: list[Record] = field(default_factory=list)
    error: str = ""
    skipped: str = ""               # non-empty => the tool did not run, and why
    note: str = ""                  # ran cleanly, but say something (e.g. nothing to scan)
    coverage: Coverage | None = None  # None => the tool cannot report what it scanned
    # The note means the target had nothing this tool reads. Kept apart from `note`,
    # which the run page read as "nothing to scan" for any note at all, including
    # opengrep's "recovered per tree" on a run with hundreds of findings.
    nothing_to_scan: bool = False


class Scanner:
    name: str = "?"
    binary: str = "?"
    # A tool that only makes sense for some targets declares it here.
    needs_network: bool = False

    def available(self) -> str | None:
        """-> absolute path, or None. Searches the same PATH the sandboxed child gets,
        so `available()` and the child can never disagree about which binary runs."""
        return shutil.which(self.binary,
                            path=f"{tools_dir() / 'bin'}:{BASE_ENV['PATH']}")

    def argv(self, src: Path, out: Path) -> list[str]:
        raise NotImplementedError

    def parse(self, out: Path, src: Path) -> Iterable[Record]:
        raise NotImplementedError

    def outputs(self, out: Path) -> list[Path]:
        """Every file parse() may read. Deleted before each run so a tool that writes
        nothing cannot hand back the previous scan's results."""
        return [out]

    def workdir(self, rundir: Path, src: Path) -> Path:
        """The child's cwd. Must be inside the run volume or the profile denies getcwd()."""
        return rundir / "out"

    def env(self) -> dict[str, str]:
        """Extra environment for the child, on top of the sandbox's own. Used for
        tools whose directory skips are switched by environment variable only."""
        return {}

    def nothing_to_scan(self, returncode: int, out: Path, stderr: bytes) -> str:
        """Non-empty when the tool exited non-zero only because the target has
        nothing it can read. Without this, an absent output file reads as refused output."""
        return ""

    # -- shared runner ------------------------------------------------------
    def run(self, rundir: Path, src: Path, *, timeout: int = 1800) -> ScanOutcome:
        binpath = self.available()
        if not binpath:
            return ScanOutcome(self.name, False, -1, 0.0,
                               skipped=f"{self.binary} not installed")
        if self.needs_network:
            return ScanOutcome(self.name, False, -1, 0.0,
                               skipped="requires network; Tier 1 denies it "
                                       "(run `quarry db sync` first)")

        out = rundir / "out" / f"{self.name}.json"
        for stale in self.outputs(out):
            stale.unlink(missing_ok=True)
        argv = [binpath, *self.argv(src, out)[1:]]
        # Only pass env when there is some: the test doubles for tier1 predate it.
        extra = {"env": e} if (e := self.env()) else {}
        res = tier1(rundir, argv, name=self.name, cwd=self.workdir(rundir, src),
                    timeout=timeout, **extra)
        # A negative code is a signal; tier1 reports its own timeout as -9. Either way
        # the output is partial, and partial output parses as a clean result.
        if res.returncode < 0:
            why = (f"timed out after {timeout}s" if res.returncode == -9
                   else f"killed by signal {-res.returncode}")
            return ScanOutcome(self.name, False, res.returncode, res.duration_s, error=why)

        try:
            stderr = res.stderr_bytes() if res.returncode else b""
        except Exception:                   # noqa: BLE001 - a missing log is not a verdict
            stderr = b""
        if why := self.nothing_to_scan(res.returncode, out, stderr):
            return ScanOutcome(self.name, True, res.returncode, res.duration_s, note=why,
                               nothing_to_scan=True)

        try:
            records = list(self.parse(out, src))
        except taint.TaintError as e:
            return ScanOutcome(self.name, False, res.returncode, res.duration_s,
                               error=f"untrusted output refused: {e}")
        except Exception as e:                      # noqa: BLE001 - a broken parser is data
            return ScanOutcome(self.name, False, res.returncode, res.duration_s,
                               error=f"{type(e).__name__}: {e}")
        return ScanOutcome(self.name, True, res.returncode, res.duration_s, records)


# ---------------------------------------------------------------- helpers

def write_tool_config(rundir: Path, name: str, text: str) -> Path:
    """Write a Quarry-owned config into the run's out/ dir for a sandboxed tool to read.

    Tier 0 writes here, into a directory every earlier sandboxed tool could write to.
    A plain write_text follows a symlink a child left at the path, which would turn a
    compromised scanner into a write anywhere the operator can write. So the file is
    created the way logs are: unlinked first, then O_EXCL and never through a link."""
    from ..sandbox.spawn import _create_log
    out = rundir / "out"
    if out.is_symlink():
        out.unlink()
    out.mkdir(parents=True, exist_ok=True)
    path = out / name
    with os.fdopen(_create_log(path), "w") as fh:
        fh.write(text)
    return path


def rel_or_none(uri: str | None, src: Path) -> str | None:
    """Validate a tool-emitted path against the clone root, or drop the finding.

    Tools handed an absolute scan root report absolute paths, so strip the known
    prefix first — but only that exact prefix, and only after resolving it. Anything
    still absolute afterwards points outside the clone and is refused, which is the
    behaviour we want: `/etc/passwd` in a SARIF `uri` is not a finding, it is an attack.

    Returning None rather than raising is deliberate: one malformed path in a 5,000
    result file should cost one finding, not the whole scan.
    """
    if not isinstance(uri, str) or not uri:
        return None
    if uri.startswith("file://"):
        uri = uri[len("file://"):]
    src_s = str(src.resolve())
    if uri.startswith(src_s + "/"):
        uri = uri[len(src_s) + 1:]
    elif uri == src_s:
        return "."
    try:
        return str(taint.safe_relpath(uri, src))
    except taint.TaintError:
        return None


def sarif_records(doc: dict[str, Any], src: Path, tool: str,
                  severity_of: Callable[[dict, dict], str] | None = None
                  ) -> Iterable[Record]:
    """Parse a SARIF 2.1.0 log. Shared by every tool that speaks it."""
    for run in doc.get("runs", []):
        driver = (run.get("tool") or {}).get("driver") or {}
        rules = {r.get("id"): r for r in driver.get("rules") or [] if isinstance(r, dict)}
        for result in run.get("results") or []:
            if not isinstance(result, dict):
                continue
            rule_id = result.get("ruleId") or "unknown"
            rule = rules.get(rule_id, {})
            locs = result.get("locations") or []
            phys = (locs[0].get("physicalLocation") if locs else None) or {}
            uri = ((phys.get("artifactLocation") or {}).get("uri"))
            path = rel_or_none(uri, src)
            if path is None:
                continue
            region = phys.get("region") or {}
            props = {**(rule.get("properties") or {}), **(result.get("properties") or {})}
            tags = props.get("tags") or []
            cwe = next((t for t in tags if isinstance(t, str) and t.upper().startswith("CWE")), None)

            sev = severity_of(result, rule) if severity_of else _sarif_severity(result, props)
            fp = (result.get("partialFingerprints") or {}).get("primaryLocationLineHash")

            yield Record(
                tool=tool, rule_id=rule_id, path=path,
                start_line=region.get("startLine"), end_line=region.get("endLine"),
                message=taint.scrub_text((result.get("message") or {}).get("text")),
                severity=sev, cwe=cwe, fingerprint=fp, raw=strip_source(result),
            )


def strip_source(obj: Any, keys: tuple[str, ...] = ("snippet",)) -> Any:
    """Copy of a tool result without the source text it quotes. SARIF
    `region.snippet` and bandit's `code` are verbatim lines from the target, so a
    secret on or near a flagged line would otherwise reach raw_result in plaintext.
    The redacted evidence window already holds the same lines."""
    if isinstance(obj, dict):
        return {k: strip_source(v, keys) for k, v in obj.items() if k not in keys}
    if isinstance(obj, list):
        return [strip_source(v, keys) for v in obj]
    return obj


def score_band(score: float) -> str:
    """CVSS qualitative bands, which GitHub's security-severity mapping also uses."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low" if score > 0 else "none"


def _sarif_severity(result: dict, props: dict) -> str:
    """GitHub's mapping (docs/PLAN §5): security-severity numeric wins, else level."""
    try:
        ss = float(props.get("security-severity"))
    except (TypeError, ValueError):
        ss = None
    if ss is not None:
        return score_band(ss)
    return {"error": "high", "warning": "medium", "note": "low",
            "none": "info"}.get(result.get("level", "warning"), "medium")
