"""Concrete adapters. One class per tool, all identical in shape."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable

from .. import taint
from ..sandbox.spawn import rules_dir as _sandbox_rules_dir
from .base import Record, Scanner, rel_or_none, sarif_records, strip_source

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
        configs: list[str] = []
        for c in self.config_paths():
            configs += ["--config", str(c)]
        return [self.binary, "scan", *configs,
                "--sarif-output", str(out),
                "--disable-version-check",
                # D14: suppressions are parsed, never obeyed.
                "--disable-nosem",
                "--taint-intrafile",
                "--timeout", "20", "--max-target-bytes", "2000000",
                "--quiet", str(src)]

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
        return [self.binary, "-r", str(src), "-f", "json", "-o", str(out),
                "--ignore-nosec", "-q"]

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


class Gitleaks(Scanner):
    """Secrets. D16: the match never reaches the database in plaintext — the adapter
    hands it over on `Record.secret` and the writer stores (prefix, sha256)."""
    name = "gitleaks"
    binary = "gitleaks"

    def argv(self, src: Path, out: Path) -> list[str]:
        # --ignore-gitleaks-allow: D14, an inline `gitleaks:allow` is the target
        # telling the scanner what not to report.
        return [self.binary, "detect", "--source", str(src), "--no-git",
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
        (rundir / "out" / OSV_CONFIG_NAME).write_text(OSV_CONFIG_TOML)
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
            for pkg in res.get("packages", []):
                info = pkg.get("package") or {}
                src_path = rel_or_none((res.get("source") or {}).get("path"), src) or "."
                for v in pkg.get("vulnerabilities", []):
                    sev = "medium"
                    for s in v.get("severity", []):
                        if s.get("type") == "CVSS_V3":
                            sev = "high"
                    yield Record(
                        tool=self.name, rule_id=v.get("id", "?"), path=src_path,
                        message=taint.scrub_text(
                            f"{info.get('name')} {info.get('version')}: {v.get('summary') or v.get('id')}"),
                        severity=sev,
                        cwe=next((c for c in (v.get("database_specific") or {}).get("cwe_ids", [])), None),
                        raw={"package": info, "vuln_id": v.get("id"),
                             "aliases": v.get("aliases"), "purl": info.get("purl")},
                    )


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

    def argv(self, src: Path, out: Path) -> list[str]:
        return [self.binary, "-d", str(src), "-o", "sarif",
                "--output-file-path", str(out.parent),
                "--download-external-modules", "false",
                "--skip-download", "--compact", "--quiet"]

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
