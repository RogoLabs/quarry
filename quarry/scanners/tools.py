"""Concrete adapters. One class per tool, all identical in shape."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable

from .. import taint
from ..sandbox.spawn import rules_dir as _sandbox_rules_dir, tier1
from .base import (Coverage, Record, ScanOutcome, Scanner, rel_or_none, sarif_records,
                   score_band, strip_source, write_tool_config)

RULES_ENV = "QUARRY_RULES"


def rules_dir() -> Path:
    """Single source of truth — the same path the sandbox profile allowlists."""
    return _sandbox_rules_dir()


class Opengrep(Scanner):
    """LGPL-2.1 engine, community rules. `--taint-intrafile` is on: cross-function taint
    within a file is stable in 1.27.1, and it is the reason four of the six CWE lenses
    were cut from Layer 2 (PLAN §6.2)."""
    name = "opengrep"
    binary = "opengrep"
    # The version --x-ignore-semgrepignore-files, the --json-output target report and
    # the --verbose skip list were measured on (IMPROVEMENT-PLAN items 15 and 24).
    # `--x-` options are internal and may change; another version gets a health warning
    # until the same checks are run against it (`quarry doctor --coverage`).
    MEASURED_VERSION = "1.27.1"

    # The pack's root holds template.yaml and CI config, which fail rule-schema
    # validation and abort the whole scan (exit 7). Point --config at the language
    # trees instead. `scripts`, `stats`, `libsonnet` and `ai` are not rule trees.
    RULE_TREES = ("bash", "c", "clojure", "csharp", "dockerfile", "elixir", "generic",
                  "go", "html", "java", "javascript", "json", "kotlin", "ocaml", "php",
                  "python", "ruby", "rust", "scala", "solidity", "swift", "terraform",
                  "typescript", "apex", "problem-based-packs")

    def config_paths(self) -> list[Path]:
        pack = rules_dir() / "opengrep_opengrep-rules"
        return [pack / t for t in self.RULE_TREES if (pack / t).is_dir()]

    def argv(self, src: Path, out: Path) -> list[str]:
        return self._argv(src, out, self.config_paths())

    @staticmethod
    def targets_path(out: Path) -> Path:
        return out.with_name(f"{out.stem}.targets.json")

    def outputs(self, out: Path) -> list[Path]:
        return [out, self.targets_path(out)]

    def _argv(self, src: Path, out: Path, configs: list[Path]) -> list[str]:
        flags: list[str] = []
        for c in configs:
            flags += ["--config", str(c)]
        return [self.binary, "scan", *flags,
                "--sarif-output", str(out),
                # The same run writes a second report. Its `paths` block lists every
                # file scanned and, with --verbose, every file skipped and why. SARIF
                # carries neither, so coverage is read from here (base.Coverage).
                "--json-output", str(self.targets_path(out)),
                "--disable-version-check",
                # D14: suppressions are parsed, never obeyed.
                "--disable-nosem",
                # IMPROVEMENT-PLAN item 15. Ingest quarantines the target's
                # .semgrepignore (D14), and with none present opengrep applies a
                # built-in list: test/, tests/, vendor/, build/, dist/, node_modules/,
                # *.min.js, *_test.go and more. Those files were skipped without a word.
                # MEASURED, opengrep 1.27.1: 1 of 5 fixture files scanned without this
                # flag, 5 of 5 with it; across runs 1 to 3, 0 of 904 opengrep hits sat
                # under test/ or tests/ while bandit had 687, 250 and 4,982 there. An
                # empty .semgrepignore did not help. `--x-` options are internal and
                # may be removed, so the target report below is also the canary: if
                # the flag stops working, the skips show up as health warnings.
                "--x-ignore-semgrepignore-files",
                "--taint-intrafile",
                "--timeout", "20", "--max-target-bytes", "2000000",
                # Not --quiet: without --verbose the JSON report omits `skipped`, and
                # stderr (a file on the run volume) is the only record of why a run
                # crashed. Its skip lists are capped at 100 entries by opengrep.
                "--verbose", str(src)]

    def run(self, rundir: Path, src: Path, *, timeout: int = 1800) -> ScanOutcome:
        """One combined invocation is the fast normal path. But opengrep-core can abort a
        whole run ("exited with unexpected output") on a single ruleset or a single file
        it cannot parse, and in a combined run that one crash writes an empty SARIF and
        zeros every finding from every tree. MEASURED on VulnLookup: the `generic` tree
        crashed and took the other 24 trees' 645 findings with it, and `--quiet` hid why
        while the run still reported success. So when the combined run comes back failed
        with nothing, fall back to one invocation per rule tree, where a crashing tree
        costs only its own findings and is recorded, not the whole tool's output."""
        outcome = super().run(rundir, src, timeout=timeout)
        if outcome.skipped:
            return outcome
        if outcome.records or outcome.returncode == 0:
            outcome.coverage = self.coverage(rundir / "out" / f"{self.name}.json", src,
                                             label="combined")
            return outcome
        return self._per_tree(rundir, src, timeout)

    def coverage(self, out: Path, src: Path, *, label: str) -> Coverage:
        """Read the target report one invocation wrote. A missing or unreadable report
        is recorded under `unreported`, never read as "scanned nothing"."""
        try:
            doc = taint.load_json(self.targets_path(out))
        except (taint.TaintError, OSError):
            doc = None
        paths = doc.get("paths") if isinstance(doc, dict) else None
        if not isinstance(paths, dict):
            return Coverage(unreported=[label])
        cov = Coverage()
        for uri in paths.get("scanned") or []:
            if isinstance(uri, str) and (p := rel_or_none(uri, src)):
                cov.scanned.add(p)
        for s in paths.get("skipped") or []:
            if not isinstance(s, dict):
                continue
            p = rel_or_none(s.get("path"), src) if isinstance(s.get("path"), str) else None
            if p:
                reason = taint.scrub_text(s.get("reason") or "unknown", 80)
                cov.skipped.setdefault(reason, set()).add(p)
        for e in doc.get("errors") or []:
            if not isinstance(e, dict):
                continue
            # `type` is a string ("Timeout") or a list (["PartialParsing", [spans]]).
            t = e.get("type")
            t = t[0] if isinstance(t, list) and t else t
            kind = taint.scrub_text(t if isinstance(t, str) else "unknown", 80)
            cov.errors[kind] = cov.errors.get(kind, 0) + 1
        return cov

    def _per_tree(self, rundir: Path, src: Path, timeout: int) -> ScanOutcome:
        """One invocation per rule tree, in two passes.

        Pass one gives every tree an equal slice of the budget, which bounds a hung
        tree. Pass two reruns the trees that ran out of their slice, sharing whatever
        the fast trees left. MEASURED on VulnLookup (run 4, 2026-11-05): once item 15
        stopped opengrep skipping test/, vendor/ and minified files, the python,
        javascript, typescript and generic trees each needed more than the 72 s slice
        (1800 s over 25 trees) and were killed with no output, so opengrep reported 43
        findings against run 3's 656 while about 1500 s of its budget went unused."""
        import time
        binpath = self.available()
        outdir = rundir / "out"
        trees = self.config_paths()
        per = max(60, timeout // max(1, len(trees)))   # bound a single hung tree
        t0 = time.time()

        def attempt(c: Path, budget: int) -> tuple[str, list[Record], Coverage]:
            out = outdir / f"{self.name}-{c.name}.json"
            for stale in self.outputs(out):
                stale.unlink(missing_ok=True)
            argv = [binpath, *self._argv(src, out, [c])[1:]]
            # Own log per tree: one shared name was unlinked and recreated by every
            # tree, so the combined run's crash log and all but the last tree's were
            # gone by the time anyone looked (IMPROVEMENT-PLAN item 24).
            res = tier1(rundir, argv, name=f"{self.name}-{c.name}",
                        cwd=self.workdir(rundir, src), timeout=budget)
            got = self.coverage(out, src, label=c.name)
            # tier1 reports its own kill as -9 after the whole budget.
            if res.returncode == -9 and res.duration_s >= budget - 1:
                return "timeout", [], got
            if res.returncode < 0 or not out.exists():
                return "failed", [], got
            try:
                recs = list(self.parse(out, src))
            except Exception:                           # noqa: BLE001 - a bad tree is data
                return "failed", [], got
            if res.returncode and not recs:             # crashed: no usable output
                return "failed", [], got
            return "ok", recs, got

        status: dict[str, str] = {}
        found: dict[str, list[Record]] = {}
        covs: dict[str, Coverage] = {}
        for c in trees:
            status[c.name], found[c.name], covs[c.name] = attempt(c, per)
        retried: list[str] = []
        slow = [c for c in trees if status[c.name] == "timeout"]
        for i, c in enumerate(slow):
            share = int((timeout - (time.time() - t0)) // (len(slow) - i))
            if share <= per:
                break                                   # nothing left worth a rerun
            retried.append(c.name)
            status[c.name], found[c.name], covs[c.name] = attempt(c, share)

        records = [r for c in trees for r in found[c.name]]
        failed = [c.name for c in trees if status[c.name] != "ok"]
        cov = Coverage()
        for c in trees:
            cov.merge(covs[c.name])
        if trees and len(failed) == len(trees):
            # Every tree failed, so nothing was scanned. MEASURED: an option opengrep
            # 1.27.1 rejects made every invocation exit 2 with no output, and this
            # returned ok with a note, which reads as a clean scan.
            return ScanOutcome(self.name, False, 2, round(time.time() - t0, 1),
                               error=f"every rule tree failed ({len(trees)} of "
                                     f"{len(trees)}); see logs/{self.name}.stderr and "
                                     f"logs/{self.name}-<tree>.stderr",
                               coverage=cov)
        note = ""
        if failed or retried:
            note = "combined run crashed; recovered per tree."
        if retried:
            note += (f" {len(retried)} tree(s) outran the {per} s slice and were rerun "
                     f"with the time the others left: {', '.join(retried)}.")
        if failed:
            timed = sorted(n for n in failed if status[n] == "timeout")
            note += (f" {len(failed)} of {len(trees)} rule tree(s) produced no usable "
                     f"output and were skipped: {', '.join(sorted(failed))}"
                     + (f" (out of time: {', '.join(timed)})" if timed else ""))
        # A tree that crashes is a recorded gap, not a zeroed tool: ok as long as the
        # per-tree pass recovered findings or nothing actually failed.
        return ScanOutcome(self.name, True, 0 if records or not failed else 2,
                           round(time.time() - t0, 1), records, note=note, coverage=cov)

    # Opengrep derives a rule id from the --config path, so an absolute config path
    # produces machine-specific ids like
    #   Users.<you>.Library.ApplicationSupport.Quarry.rules.<pack>.python.lang.x
    # That would make producer_id host-dependent and destroy the cross-repo precision
    # ledger, which is the whole point of the ledger (Seat 1). Strip the prefix.
    _PACK_MARK = "opengrep_opengrep-rules."

    @classmethod
    def normalise_rule_id(cls, rule_id: str) -> str:
        if cls._PACK_MARK in rule_id:
            return rule_id.split(cls._PACK_MARK, 1)[1]
        return rule_id

    def parse(self, out: Path, src: Path) -> Iterable[Record]:
        doc = taint.load_json(out)
        if not doc:
            return
        for rec in sarif_records(doc, src, self.name):
            rec.rule_id = self.normalise_rule_id(rec.rule_id)
            yield rec


class Bandit(Scanner):
    """AST-only — it does not import target code, so Tier 1 is sufficient.
    Earned its place empirically: it recovers the Qwythos corpus's headline finding
    (a weak Flask SECRET_KEY, B311/CWE-330) in under a second for $0."""
    name = "bandit"
    binary = "bandit"

    def argv(self, src: Path, out: Path) -> list[str]:
        # --ignore-nosec: D14 — suppressions are parsed, never obeyed.
        # -x: IMPROVEMENT-PLAN item 23. Bandit's default exclude list is the bare
        # strings .svn, CVS, .bzr, .hg, .git, __pycache__, .tox, .eggs, *.egg. Each
        # becomes a `<name>/*` glob only if ./<name> is a directory in the *cwd*;
        # otherwise it is matched as a substring of every path. Quarry's cwd is the
        # run's out/ dir, so `.git` matched `.github/` and `CVS` matched `CVSS.py`.
        # MEASURED, bandit 1.9.4: .github/scripts/x.py, lib/CVSS.py and .gitlab/ci.py
        # were skipped without a word. An explicit -x replaces that list. The trailing
        # `/*` keeps this one a glob: bandit never sees it as a directory, and the
        # literal `*` cannot occur in a real path, so the substring test never fires.
        return [self.binary, "-r", str(src), "-f", "json", "-o", str(out),
                "-x", f"{src}/.git/*", "--ignore-nosec", "-q"]

    def parse(self, out: Path, src: Path) -> Iterable[Record]:
        doc = taint.load_json(out)
        for r in (doc or {}).get("results", []):
            path = rel_or_none(r.get("filename"), src)
            if path is None:
                continue
            yield Record(
                tool=self.name, rule_id=r.get("test_id", "?"), path=path,
                start_line=r.get("line_number"),
                message=taint.scrub_text(r.get("issue_text")),
                severity=str(r.get("issue_severity", "low")).lower(),
                cwe=f"CWE-{(r.get('issue_cwe') or {}).get('id')}"
                    if (r.get("issue_cwe") or {}).get("id") else None,
                raw=strip_source(r, ("code",)),
            )


GITLEAKS_CONFIG_NAME = "gitleaks-config.toml"


class Gitleaks(Scanner):
    """Secrets. D16: the match never reaches the database in plaintext — the adapter
    hands it over on `Record.secret` and the writer stores (prefix, sha256)."""
    name = "gitleaks"
    binary = "gitleaks"

    def run(self, rundir: Path, src: Path, *, timeout: int = 1800) -> "ScanOutcome":
        # IMPROVEMENT-PLAN item 23: Gitleaks' default rules without its global path
        # allowlist (node_modules/, lockfiles, vendored trees, virtualenvs). See
        # gitleaks_config.py. Copied into out/, which Tier 1 can read, like OSV's.
        from .gitleaks_config import CONFIG
        write_tool_config(rundir, GITLEAKS_CONFIG_NAME, CONFIG.read_text())
        return super().run(rundir, src, timeout=timeout)

    def argv(self, src: Path, out: Path) -> list[str]:
        # --ignore-gitleaks-allow: D14, an inline `gitleaks:allow` is the target
        # telling the scanner what not to report.
        return [self.binary, "detect", "--source", str(src), "--no-git",
                "--config", str(out.parent / GITLEAKS_CONFIG_NAME),
                "--report-format", "json", "--report-path", str(out),
                "--redact=0", "--exit-code", "0", "--no-banner",
                "--ignore-gitleaks-allow"]

    def parse(self, out: Path, src: Path) -> Iterable[Record]:
        doc = taint.load_json(out)
        for r in (doc or []):
            path = rel_or_none(r.get("File"), src)
            if path is None:
                continue
            secret = r.get("Secret") or r.get("Match") or ""
            scrubbed = dict(r)
            for k in ("Secret", "Match", "Line"):
                scrubbed.pop(k, None)          # never persist plaintext in raw_result
            yield Record(
                tool=self.name, rule_id=r.get("RuleID", "?"), path=path,
                start_line=r.get("StartLine"), end_line=r.get("EndLine"),
                message=taint.scrub_text(r.get("Description")),
                severity="high", cwe="CWE-798", secret=secret,
                fingerprint=r.get("Fingerprint"), raw=scrubbed,
            )


class Zizmor(Scanner):
    """GitHub Actions. Seat 1's P1c condition — workflow injection is a real, common,
    high-impact class that no other tool in the stack covers."""
    name = "zizmor"
    binary = "zizmor"

    def argv(self, src: Path, out: Path) -> list[str]:
        # D14. zizmor discovers zizmor.yml / .github/zizmor.yml in the input tree, and
        # that file can disable audits or ignore findings; --no-config stops the
        # discovery and --no-ignores stops inline `# zizmor: ignore[...]` comments.
        # Both exist in zizmor 1.31.1, the version this was checked against.
        return [self.binary, "--format", "sarif", "--no-progress",
                "--persona", "regular", "--no-config", "--no-ignores", str(src)]

    def parse(self, out: Path, src: Path) -> Iterable[Record]:
        # zizmor writes SARIF to stdout; the runner captured it in logs/.
        stdout = out.parent.parent / "logs" / f"{self.name}.stdout"
        doc = taint.load_json(stdout if stdout.exists() else out)
        return sarif_records(doc, src, self.name) if doc else []


# osv-scanner aborts the whole offline scan (exit 127, no output) if any ecosystem it
# detects has no downloadable OSV database. The GIT ecosystem (a commit-pinned
# dependency, e.g. a `git+ssh://...#<sha>` entry in a lockfile) has none, so a single
# such dependency would suppress every npm/PyPI/etc. finding beside it. OSV publishes no
# offline GIT database, so there is nothing to sync: filter the ecosystem out by config
# and scan the rest. MEASURED on cve-services, whose lockfile pins one git dependency.
OSV_CONFIG_TOML = (
    "[[PackageOverrides]]\n"
    'ecosystem = "GIT"\n'
    "ignore = true\n"
    'reason = "offline scan: OSV publishes no downloadable GIT-ecosystem database"\n'
)
OSV_CONFIG_NAME = "osv-config.toml"


class OSVScanner(Scanner):
    """SCA. `--offline-vulnerabilities` keeps it inside Tier 1; `--no-resolve` stops it
    leaking manifests to package registries (Seat 5's measurement)."""
    name = "osv-scanner"
    binary = "osv-scanner"

    def run(self, rundir: Path, src: Path, *, timeout: int = 1800) -> "ScanOutcome":
        # Written into the per-run out/ dir, which is readable inside Tier 1; see argv.
        write_tool_config(rundir, OSV_CONFIG_NAME, OSV_CONFIG_TOML)
        return super().run(rundir, src, timeout=timeout)

    def argv(self, src: Path, out: Path) -> list[str]:
        return [self.binary, "scan", "source", "--recursive",
                "--offline-vulnerabilities", "--no-resolve",
                "--config", str(out.parent / OSV_CONFIG_NAME),
                "--format", "json", "--output", str(out), str(src)]

    def nothing_to_scan(self, returncode: int, out: Path, stderr: bytes) -> str:
        # 128 is osv-scanner's "no package sources found": a repo with no manifests.
        if returncode == 128 and not out.exists() and b"No package sources found" in stderr:
            return "no package manifests to scan"
        return ""

    def parse(self, out: Path, src: Path) -> Iterable[Record]:
        doc = taint.load_json(out)
        for res in (doc or {}).get("results", []):
            # A manifest path that does not resolve inside the clone is dropped, as in
            # every other adapter. It used to become ".", a finding on the repo root.
            src_path = rel_or_none((res.get("source") or {}).get("path"), src)
            if src_path is None:
                continue
            for pkg in res.get("packages", []):
                info = pkg.get("package") or {}
                scores = _osv_group_scores(pkg)
                for v in pkg.get("vulnerabilities", []):
                    # osv-scanner's own max_severity for the alias group, a CVSS base
                    # score. Any CVSS v3 vector used to read as "high", so an A:L-only
                    # 5.3 sat beside a 9.8.
                    score = scores.get(v.get("id"))
                    sev = score_band(score) if score is not None else "unscored"
                    yield Record(
                        tool=self.name, rule_id=v.get("id", "?"), path=src_path,
                        message=taint.scrub_text(
                            f"{info.get('name')} {info.get('version')}: {v.get('summary') or v.get('id')}"),
                        severity=sev,
                        cwe=next((c for c in (v.get("database_specific") or {}).get("cwe_ids", [])), None),
                        raw={"package": info, "vuln_id": v.get("id"),
                             "aliases": v.get("aliases"), "purl": info.get("purl")},
                    )


def _osv_group_scores(pkg: dict) -> dict[str, float]:
    out: dict[str, float] = {}
    for g in pkg.get("groups") or []:
        try:
            score = float(g.get("max_severity"))
        except (TypeError, ValueError):
            continue
        for vid in g.get("ids") or []:
            out[vid] = max(score, out.get(vid, 0.0))
    return out


class TrivyFS(Scanner):
    """Breadth sweep: misconfig + license + vuln over the filesystem.
    Trivy cannot run offline before a DB sync — that is a provisioning step
    (`quarry db sync`), not a flag."""
    name = "trivy"
    binary = "trivy"

    def argv(self, src: Path, out: Path) -> list[str]:
        return [self.binary, "fs", "--scanners", "vuln,misconfig",
                "--format", "sarif", "--output", str(out),
                "--skip-db-update", "--skip-java-db-update", "--offline-scan",
                "--quiet", str(src)]

    def parse(self, out: Path, src: Path) -> Iterable[Record]:
        doc = taint.load_json(out)
        return sarif_records(doc, src, self.name) if doc else []


class Checkov(Scanner):
    """IaC. Tier 1 ONLY with external modules and custom policies off — Seat 5's
    ruling, granted by the chair. With those off it is a parser; with either on it
    moves to Tier 2 behind Colima."""
    name = "checkov"
    binary = "checkov"

    # Handed `-d <rundir>/src`, checkov reports every uri as `src/<path>`: it prefixes
    # the scan directory's own name. That path does not exist in the clone, so every
    # finding lost its evidence window and quote-verify killed all of them (21 of 21
    # on runs 1 and 2). From inside the clone with `-d .` the uris are plain relative
    # paths. This opens no new config path: checkov already reads .checkov.y*ml from
    # the -d directory, and ingest quarantines both. MEASURED with checkov in .venv.
    def workdir(self, rundir: Path, src: Path) -> Path:
        return src

    def argv(self, src: Path, out: Path) -> list[str]:
        return [self.binary, "-d", ".", "-o", "sarif",
                "--output-file-path", str(out.parent),
                "--download-external-modules", "false",
                "--skip-download", "--compact", "--quiet"]

    def env(self) -> dict[str, str]:
        # IMPROVEMENT-PLAN item 23. Checkov drops directories named node_modules,
        # .terraform or .serverless, and every directory whose name starts with a
        # dot, so a Docker container action's .github/actions/<name>/Dockerfile was
        # never read. Both rules are set only by environment variable. MEASURED: a
        # Dockerfile under node_modules/, .venv/ or .github/ produced nothing; with
        # these values, all three produce findings. (A root .gitlab-ci.yml is read
        # either way.) Keep only .git out; the match is on the exact directory name.
        return {"CKV_IGNORED_DIRECTORIES": ".git",
                "CKV_IGNORE_HIDDEN_DIRECTORIES": "false"}

    def outputs(self, out: Path) -> list[Path]:
        return [out, out.parent / "results_sarif.sarif"]

    def parse(self, out: Path, src: Path) -> Iterable[Record]:
        # checkov writes results.sarif into the directory it is given.
        sarif = out.parent / "results_sarif.sarif"
        doc = taint.load_json(sarif) if sarif.exists() else None
        return sarif_records(doc, src, self.name) if doc else []


# Gitleaks runs first: every later tool's evidence window is redacted with the
# secrets it found, so they have to be known before any other window is built.
ALL: tuple[type[Scanner], ...] = (
    Gitleaks, Opengrep, Bandit, Zizmor, OSVScanner, TrivyFS, Checkov,
)


def registry() -> dict[str, Scanner]:
    return {cls.name: cls() for cls in ALL}
