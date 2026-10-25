# Chair's Synthesis — Draft 1, for panel review

**To:** Seats 1–6  **From:** Chair  **Re:** `docs/RESEARCH.md` after first-round review

---

## 0. Chair's independent verification

Before synthesizing I re-ran the load-bearing claims myself rather than accepting them. All four
material factual challenges to the research doc are **upheld**:

| Claim | Seat | Chair's verification | Status |
|---|---|---|---|
| No container runtime on this host | 5 | `docker info` → daemon unavailable; no Docker Desktop, OrbStack, Colima, Lima, Podman, or `container(1)` present | **UPHELD** — §10's only named control does not exist |
| `gh` token is broad and ambient | 5 | `gh auth status` → scopes `admin:org, gist, repo, workflow` | **UPHELD** |
| Real corpus is 14 repos / 162 verdicts / $27.99 / **4 confirmed** | 6 | Parsed all `work/*/verified/qwythos/*.json` — exactly 14 repos, 162 verdicts, $27.99, 4 confirmed. Rejection reasons: false-premise 48, not-a-vulnerability 40, already-mitigated 40, duplicate 11, test-or-example 10, not-reachable 9 | **UPHELD** (research doc cited only the 6-repo subset) |
| 3 of the 4 confirmed findings are free-tool-findable | 6 | `bandit -t B311` finds the SECRET_KEY finding (B311, CWE-330), exact line, <1s, $0. `grep` finds all four hardcoded database password locations in ~9ms, including one the model did not report | **UPHELD** |

**The last row is the most important finding of this entire review.** The pipeline's headline result —
the one that justified $24.94 of Opus 5 — is reproduced by a 1.9.4 Bandit rule in under a second. The
only genuinely LLM-only finding across 14 repositories is one cross-file missing-authorization bug.

I also checked Seat 1's Opengrep claim: `--taint-intrafile` (cross-function taint within a file) is
real and shipped; interfile taint is announced but **still in development** as of the sources I can
see. Seat 1 — please downgrade the "interfile alpha landed 2026-08-19" claim unless you can cite the
release. Everything else in your report stands.

**One correction the research doc owes the panel:** §2.3 quoted the 6-repo, 115-finding subset from
`prompts/README.md` as if it were the whole corpus. The real denominator is 162 across 14 repos, and
precision is 4/162 = **2.5%**, not 1.7%. Marginally better, same conclusion.

---

## 1. What the panel changed

The plan I circulated was structurally right and strategically wrong. Six seats converged
independently on the same underlying error, from six directions:

> **The plan spends its entire design budget on suppressing false positives, and almost none on
> generating true positives.**

- Seat 6 stated it directly: "a filter's maximum possible contribution to true bugs surfaced is zero."
- Seat 1 reached it from recall: the funnel is a set with no ordering and no recall instrument.
- Seat 2 reached it from measurement: seven seats, zero ablations, after criticizing Refute-or-Promote for having no ablations.
- Seat 4 reached it from the UI: the funnel is the trust anchor and it was a bullet point.
- Seat 3 reached it from the output: a 2.5% base rate does not earn access to a volunteer's inbox.
- Seat 5 reached it from the input: the pipeline's first act is downloading hostile code next to a `repo`-scoped token.

I accept the correction. **The revised plan inverts the emphasis.**

## 2. Decisions (chair's rulings on the contested points)

**D1 — The deterministic layer is the product; the LLM layers are a measured experiment on top.**
Ruling for Seats 1 and 6. P1 ships a tool that is useful with zero model calls. Bandit found in 0.33s
what cost $24.94. That is not an argument against LLMs; it is an argument that the free layer was
never actually run, and the LLM was doing a rule engine's job badly.

**D2 — Target selection is promoted to a first-class feature, ahead of the panel redesign.**
Ruling for Seat 6. Qwythos hunted OWASP Nettacker, DefectDojo, IntelOwl — repos with years of
professional attention. Finding nothing there is the correct answer. A target-selection scorer
(dependents, attack surface, prior audit evidence, contributor count, security-tooling maturity,
last-audit signals) plausibly outperforms every §5 change at ~1% of the cost.

**D3 — The panel starts at ONE seat and grows only on measured evidence.**
Ruling for Seats 2 and 6 jointly, against my own §5.3. The incumbent `verify.py` single Opus 5 call
with repo tools is the baseline at a measured $0.0744/finding. Seat 2's chair-replay ablation is the
mechanism for adding seats; Seat 6's power analysis is the honest caveat that at 162 findings we
cannot detect small effects. **A seat that cannot be shown to change a verdict does not ship.**
The "6-persona panel" survives as an architecture the code supports and the evidence must earn.
Seat 6's finding that `debate.py` already ran — 39 disputes, 0 rebuttals, 0 flips — is the precedent.

**D4 — Egress: Quarry never performs a network write against a repository the operator does not
administer.** Ruling for Seat 3, seconded by Seat 5. §7 becomes an **export-only composer**. The
deliverable is a document on disk plus a `gh` command the operator runs themselves. This costs eight
seconds per report and makes an entire class of bug — loop errors, prompt injection, misparsed API
responses — structurally unable to transmit.

**D5 — "Always request a CVE" is retired as a default and replaced with `not_ours_to_request` +
a CNA-ready appendix.** Ruling for Seat 3, whose verification of GitHub's CNA scope (CNA-2019-0009
covers "CVEs requested by code owners") shows the brief's requirement is not merely unwise but
*mechanically impossible* for the third-party case. The user's intent — "make it easy to get a CVE
when one is warranted" — is served better by a complete, correct CNA packet than by an API call that
does not exist.

**D6 — Sandboxing: `sandbox-exec` per-run profile for all of Layer 1, plus install a real container
runtime for anything that resolves dependencies or executes.** Ruling for Seat 5. Their measured
twelve-line profile (network denied, reads confined to a per-run APFS sparse image, `~/.ssh` denied,
keychain denied, zero overhead) is available today; the container runtime is not installed and must
be. Credential separation — no process that reads target bytes holds a credential — is adopted as a
hard invariant.

**D7 — UI: FastAPI + Jinja + HTMX + Alpine + CodeMirror 6. Three routes, two overlays.**
Ruling for Seat 4. The argument that wins is not taste, it is that four of the twelve React days
produce nothing visible during the exact week P1 must ship and stand alone. `/triage`, `/runs/:id`
(the funnel, which *is* the progress view), `/runs`. Seat 4's rule that **every number in the funnel
is a link to the set it killed** is adopted as a build constraint, not a nice-to-have.

**D8 — Finding identity is three concepts, and nothing is ever deleted.**
Ruling for Seat 1. `occurrence_id` / `finding_id` (line-number-free, symbol-content-hashed) /
`issue_id` (cross-tool equivalence class). A `funnel_events` ledger records every suppression as a
reversible, attributed event; `defer` ≠ `kill`. Verdicts carry forward across runs keyed on
`finding_id`, so a re-scan does not re-pay to re-reject the same 158 findings.

**D9 — SARIF is the export projection, not the internal store.** Ruling for Seat 1. Relational SQLite
core; each tool's native JSON kept verbatim in `raw_results` (OSV-Scanner's SARIF destroys the `purl`
and fixed-version that the advisory composer needs).

**D10 — Layer 2 defaults to the MoE.** Ruling for Seat 2. Their scaling from the measured 9.2 s/call
baseline puts a dense 27B at ~52 h/repo. Qwen3.6-35B-A3B, thinking off, JSON-schema-constrained. And
a pre-funnel *in front of* Layer 2, since §6 only gated dollars and Layer 2's cost is hours.

**D11 — Sampling parameters are removed on Opus 5 / Sonnet 5 / Fable 5** (400 error), so Visa's
majority-vote-at-T>0 is unportable. Ruling for Seat 2: replace with verdict-flip-rate across two
identical runs as a week-one gate. Also noted: `effort` is unsupported on Haiku 4.5, and **Sonnet 5
intro pricing ends 2026-08-31** — eight days out — so every cost figure in §5.3 is ~50% low from
September.

## 3. What survived unchallenged

Worth recording, because six adversarial seats failing to kill something is evidence:

- The three-family taxonomy and the judgment that Quarry is Family C.
- The Qwythos rejection taxonomy as the requirements document for the funnel (all six seats built on it).
- "Never sort or gate by model-claimed severity" — Seat 4 called §2.3 sufficient to earn this outright.
- Prompt caching on the whole conversation (~3x/turn).
- The reproducibility manifest.
- The finder/verifier isolation principle from `defending-code-harness`.

## 4. The revised shape

```
P0  schema + ingest + sandbox profile + credential separation   (nothing runs unsandboxed, ever)
P1  deterministic layer + funnel ledger + /triage + /runs        ← ships standalone, zero model calls
P1b target selection scorer                                      ← Seat 6's highest-ROI item
P2  falsification experiment (Seat 6's 2x2, ~$48, 5.6 machine-h) ← GO/NO-GO GATE on everything below
P3  local sweep, gated on P2                                     ← only the lenses P2 shows work
P4  single-seat adjudicator (port verify.py), then ablate        ← seats added one at a time, on evidence
P5  export-only disclosure composer + CNA packet
```

**P2 is a gate, not a phase.** Seat 6's abandon thresholds are adopted verbatim: if the free stack
recalls ≥2 of 3 known issues, the LLM layers do not proceed as designed; if the panel flips <10% of
single-seat verdicts, the panel does not proceed; if the unaudited target stratum beats the popular
stratum by ≥4x, work stops and moves to target selection.

---

## 5. Questions back to the panel — please respond

1. **All seats:** D1 and D3 together mean the thing Jerry asked for — "multiple LLMs and a 6-persona
   critical review panel" — is now gated behind a measurement that might kill it. Is that the right
   call, or is the chair over-correcting from a 4-finding sample? **Seat 6 in particular: argue the
   other side.** You are the seat that most wants this outcome; tell me where your own case is weakest.
2. **Seat 1 & Seat 6:** you disagree about Layer 2. Seat 1 says Opengrep `--taint-intrafile` partly
   obsoletes it; Seat 6 says 4 of 6 lenses are 0-for-72. Both point at cutting, but to *different*
   remainders. What is the minimum LLM sweep that survives both of your arguments?
3. **Seat 2 & Seat 6:** Seat 2 wants a 9-arm chair-replay ablation at $153; Seat 6's power analysis
   says 162 findings cannot detect the effects being tested. Reconcile. Is Seat 2's ablation
   underpowered theater, or is Seat 6's power bar too high for a decision this cheap to reverse?
4. **Seat 3 & Seat 4:** D4 makes the composer export-only. Seat 4's three-free-text-fields
   reproduction gate was designed to gate *egress*. With no egress, what is it gating — and does the
   friction still earn its place?
5. **Seat 5 & Seat 4:** the sandbox confines Layer 1 reads to a per-run sparse image. Does that break
   the code pane in `/triage`, which must render source for findings weeks after the run?
6. **Seat 1 & Seat 5:** who owns the target's own config files (`.semgrep.yml`, `.trivyignore`,
   `.checkov.yaml`)? Seat 5 treats them as an injection vector; a scanner that ignores them will
   produce findings the maintainer already triaged. Ruling requested.
7. **All seats:** name the one thing in this synthesis you think is still wrong.

Please reply with: **(a)** anything in §0–§4 you dispute, with evidence; **(b)** your answers to the
questions addressed to you; **(c)** your single highest-priority change to the revised shape in §4;
**(d)** whether you now **endorse**, **endorse-with-conditions**, or **dissent**. State conditions
explicitly — I will record dissents in the final plan rather than smoothing them over.
