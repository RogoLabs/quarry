# Quarry — Final Plan

**Status:** ratified by the review panel 2026-08-23 — 6 of 6 endorse with conditions, 0 dissents,
3 dissent triggers recorded in §9.
**Inputs:** [`docs/RESEARCH.md`](RESEARCH.md) · six seat reports in [`docs/panel/`](panel/) ·
[`docs/panel/TALLY.md`](panel/TALLY.md)

---

## 1. What changed, and why

The plan that went into review was a nine-tool scanner feeding a six-seat adversarial LLM panel that
would file GitHub advisories. Six seats attacked it independently and converged on one error:

> **It spent its entire design budget on suppressing false positives and almost none on generating
> true positives. A filter's maximum possible contribution to "true bugs surfaced" is zero.**

Then the panel went and measured the prior tool instead of arguing about it. The full Qwythos corpus —
which the research doc had under-reported — is **14 repos, 162 verdicts, $27.99, 4 confirmed (2.5%)**.
I verified every number myself. Of those four:

| Finding | Free-tool recoverable? | Reportable? |
|---|---|---|
| Non-CSPRNG `SECRET_KEY` in a Python web app | **Yes**: `bandit -t B311`, CWE-330, <1 s, $0 | Yes |
| Postgres password in a docker-compose file | **Yes** — `grep`, ~9 ms, found 4 sites incl. one the model missed | **No** — local dev fixture (§7.3) |
| Postgres password in a reset script | **Yes** — same grep | **No** — same |
| Cross-file missing authorization check in a web app | **No**: cross-file missing-authz | Yes |

**Net yield of the entire $27.99 LLM program across 14 repositories: two reportable findings, one of
which a free rule engine finds in under a second.** (Seat 6's caveat, which I owe them: n=4,
95% CI [30%, 95%]. The direction is solid; the point estimate is not.)

That is not an argument against LLMs. It is an argument that **the free layer was never actually run**,
and a 9B model was doing a rule engine's job badly. The plan below inverts the emphasis accordingly.

**But the panel also caught me over-correcting.** Seat 6 — the seat that won hardest — spent round two
attacking its own victory and found the flaw: all 162 verdicts come from a *single Opus call*, and
`debate.py`'s "0 flips in 39 disputes" was *same-model self-review*, the configuration the literature
already reports as failing. **The corpus therefore contains zero observations of a panel.** Seat 6
withdrew "the panel must not be built" and kept "the panel must not be believed." That distinction is
now D3.

---

## 2. What Quarry is

**A local-first repository audit dashboard whose product is the deterministic layer, whose LLM layers
are an explicitly unmeasured experiment on top, and which never writes to a repository you do not
administer.**

Three properties, in priority order:

1. **Throughput.** At a ~7% hit rate, throughput *is* the strategy. Layer 1 runs ~2,400 repos/day;
   Layer 2 as originally scoped ran 1–4. The 617–5,349× gap means anything that sits behind Layer 2
   is functionally unimplementable.
2. **Auditability.** Nothing is ever deleted. Every suppression is a reversible, attributed event.
   Every number in the UI links to the set it killed.
3. **Containment.** Nothing that reads target bytes runs unsandboxed, and no process that reads
   target bytes holds a credential.

---

## 3. The sixteen ratified decisions

| # | Decision | Ruling for |
|---|---|---|
| **D1** | The deterministic layer is the product. P1 ships useful with zero model calls. | 1, 6 (unanimous) |
| **D2** | Target selection is a first-class feature, promoted to **P1a**, and must not sit behind Layer 2. | 6 |
| **D3** | The adjudicator starts at **one seat**. The panel ships behind a flag labelled `unmeasured, 3–8× cost`, and **no measurement is claimed in either direction**. The seat-screen can only **cut** seats, never promote them. | 2, 6 |
| **D4** | **No network write to any repository the operator does not administer.** The composer emits a document plus a `gh` command the operator runs. | 3, 5 |
| **D5** | "Always request a CVE" retired. Default `not_ours_to_request` + a CNA-ready appendix. GitHub's CNA scope (CNA-2019-0009) covers only CVEs requested by code owners. | 3 |
| **D6** | Containment is **~1 developer-day in P0** via `sandbox-exec`, not a runtime install. Colima is a **P3/P5** dependency. Invariant: *nothing that reads target bytes runs unsandboxed.* | 5 |
| **D7** | FastAPI + Jinja + HTMX + Alpine + CodeMirror 6. Three routes: `/triage`, `/runs/:id`, `/runs`. | 4 |
| **D8** | Three-level identity (`occurrence_id` / `finding_id` / `issue_id`); `funnel_events` ledger; `defer ≠ kill`; **nothing is ever deleted** — extends to rules (dismissal sets `enabled:false`). | 1 |
| **D9** | SARIF 2.1.0 is the **export projection**; relational SQLite is the store; each tool's native JSON kept verbatim in `raw_results`. | 1 |
| **D10** | Layer 2 collapses to **one gated lens** + one per-finding lens (§6.2). MoE budget **24–28 GB**. | 1, 6 |
| **D11** | Sampling params are removed on Opus 5 / Sonnet 5 / Fable 5 (400). Flip-rate gates are relative to the **measured self-flip floor**, never a fixed 10%. | 2 |
| **D12** | The GO/NO-GO gate is retired for a **calibration run** plus a **throughput target: P1 scans 100 repos overnight.** | 6 |
| **D13** | `local-dev-fixture` becomes a seventh free funnel class. A **render guard** strips exploitation-status language from every outbound artifact. | 3 |
| **D14** | Target config: loader-capable files **quarantined and never loaded**; suppressions **parsed, never obeyed**; suppression reason strings **never reach a model**. | 1, 5 |
| **D15** | **Evidence blobs at ingest** — enclosing symbol ±40 lines, content-addressed, for every occurrence including killed ones. The code pane never depends on the clone surviving. | 4, 5 |
| **D16** | Secret findings stored as **prefix + hash**, never plaintext. Redaction runs at the same boundary as snippet extraction. | 5, 4 |
| **D17** | **Private repos: option (C) ships now — out-of-band clone.** A credential broker (B) is approved *in principle* for P2+ but **only as a GitHub App** issuing 1-hour per-repo installation tokens; (B) via the ambient `gh` token is **permanently forbidden**. | 5 |

---

## 4. Architecture

```
P0  CONTAINMENT + SCHEMA                                   ~1 dev-day, before any real target
    sandbox-exec profile · spawn wrapper · credential broker
    SQLite: runs, producers, occurrences, findings, issues,
            funnel_events, evidence_blobs, verdicts, manifest

P1  DETERMINISTIC LAYER            ← the product. zero model calls. 100 repos/night.
    Opengrep 1.27.1 (+1.28.0-interfile.alpha.2 opt-in) · OSV-Scanner · Trivy ·
    Grype/Syft · Gitleaks · Checkov (Tier 1, ext modules OFF) · Bandit/gosec/njsscan
    P1c: zizmor · OpenSSF Scorecard · dependency-confusion      [Seat 1 dissent trigger]
    enrichment: OSV · EPSS · KEV · CWE      normalization: SARIF projection
    UI: /triage grouped by PRODUCER · /runs/:id (the funnel) · /runs

P1a TARGET SELECTION SCORER        ← highest-ROI item in the whole plan
    attack surface · dependents · responsiveness · prior-audit covariates

P2  CALIBRATION RUN (not a gate)   ~$48-64, 5.6 machine-h
    20 repos, 2x2 stratified, planted-bug control in 5, blind pooled adjudication,
    thresholds committed to git before the first clone   [Seat 1 + 6 dissent trigger]

P3  LOCAL SWEEP — one gated lens   gated on P1a + the repo C replay
P4  SINGLE-SEAT ADJUDICATOR        port verify.py; panel behind an `unmeasured` flag
P5  EXPORT-ONLY COMPOSER           render guard + self-labelling + withheld gh command
                                                            [Seat 3 dissent trigger]
```

### 4.1 Containment (P0)

Four tiers, per Seat 5:

| Tier | What runs there | Mechanism |
|---|---|---|
| 0 | Orchestrator, web server, DB | Native. **Never opens a clone.** Holds credentials. |
| 1 | All P1 scanners, tree-sitter, snippet extraction | `sandbox-exec`: `(deny network*)`, reads confined to a per-run APFS sparse image, `~/.ssh` / keychain / `gh` config denied. **Zero credentials in the process.** |
| 2 | Dependency resolution, Checkov w/ external modules, CodeQL | Colima VM (P3+). |
| 3 | PoC execution | Snapshot-reverted VM (P5, deferred). |

Metal inference cannot be sandboxed, which is why the invariant is *"nothing that reads target bytes
runs unsandboxed"* rather than *"nothing runs unsandboxed."* The local model reads **evidence blobs**,
never the clone.

### 4.2 Data model (P0)

Three identities, because conflating them breaks the funnel, the cost model, and the eval harness:

- `occurrence_id` — this result, this run, this line.
- `finding_id` — the same claim across runs. **Line-number-free**, hashed over
  `(repo, path, enclosing_symbol_content_sha, rule_id)`. Verdicts key on this, so a re-scan does not
  re-pay to re-reject the same 158 findings.
- `issue_id` — cross-tool equivalence class, assigned by clustering into a table, **never by deletion**.

Plus `producer_id` (tool + rule) carrying a **cross-repo precision ledger** — this is the mechanism by
which the deterministic layer improves over time, and it is what makes `/triage` more than a SARIF
viewer.

---

## 5. Tool stack (P1)

| Tool | Version | Install | Notes |
|---|---|---|---|
| Opengrep | 1.27.1 stable | `install.sh` (**not in homebrew-core**) | `--taint-intrafile` on. `1.28.0-interfile.alpha.2` (`--taint-interfile`) behind an opt-in flag. |
| OSV-Scanner | installed | — | `--no-resolve` by default (leaks manifests to registries otherwise). |
| Trivy | installed | — | **Cannot run offline before a DB sync** — provisioning step, not a flag. |
| Grype / Syft | installed | — | Syft phones home each run; pin `SYFT_CHECK_FOR_APP_UPDATE=false`. |
| Gitleaks | 8.30.1 | brew | Findings stored **prefix+hash** (D16). |
| Checkov | 3.3.10 | brew | Tier 1 **only** with external modules + custom policies off. |
| Bandit / gosec / njsscan | | | Bandit already proved its worth on this corpus. |
| zizmor | 1.29.0 | brew | GitHub Actions injection. **P1c, Seat 1 dissent trigger.** |
| OpenSSF Scorecard | | | P1c. Also feeds the P1a target scorer. |
| CodeQL | opt-in | | **Hard license gate: OSI-licensed targets only.** Refuse otherwise. |

**Rule sourcing**, given `opengrep/opengrep-rules` was archived 2025-11-28: pin the archived fork as a
baseline, layer `AikidoSec/opengrep-rules`, and author rules from confirmed findings. Every rule
carries a `producer_id` from run one so the precision ledger starts accumulating immediately.

**Excluded by ruling:** Semgrep's own rule packs (Semgrep Rules License v1.0 — internal, non-competing,
non-SaaS; shipping them in an open-source repo is a licensing problem). Engine swap is a binary swap.

---

## 6. Model stack

### 6.1 Local (already on disk — verified)

`ollama list` shows the local tier largely exists:

| Model | Size | Role |
|---|---|---|
| `Foundation-Sec-8B-Instruct-Q8` | 8.5 GB | CWE mapping, security-relevance classification, advisory summarization |
| `gpt-oss:20b` | 13 GB | **The cross-family critic** — genuinely different family, $0 |
| `qwen3-coder:30b` | 18 GB | Layer 2 sweep candidate |
| `codestral:22b`, `deepseek-coder-v2:16b` | | alternates |

Budget Layer 2 at **24–28 GB** (Seat 5: the MoE is faster, not smaller).

### 6.2 Layer 2 collapses to two lenses

Seat 1's ruling, agreeing with Seat 6's 0-for-72 measurement from a second direction: `injection`,
`path-file`, `ssrf-network`, and `deserialization` all ask a **source → sink → path** question, which
is *the definition of what a taint engine computes* — cross-function on stable Opengrep, cross-file in
the alpha. Those four lenses were asking a quantized model to approximate dataflow analysis by reading.

What survives are the two questions with **no source and no sink**:

1. **"Does this route need authorization?"** — the *absence* of a call that ought to be there is
   outside the taint formalism entirely. No engine maturity closes it. It produced the single LLM-only
   confirmation in 14 repos.
   **Deterministic gate:** an entry point whose sibling routes are ≥80% auth-guarded and which carries
   none. That is a `GROUP BY`. 5–30 anomalies on a 200-route repo, ~10 min — not 6–20 h.
2. **"Is this node on a proven path actually a sanitizer?"** — the engine believes `escape_html()`
   sanitizes because a rule author said so, and cannot tell that *this* repo's `sanitize()` just calls
   `.strip()`.

> **Action before P3:** replay gate (1) against repo C. One afternoon, $0. It either
> validates the last surviving lens or kills it.

### 6.3 The single seat (P4)

`claude-opus-5`, effort `high`, adaptive thinking. Tools: read/grep/glob rooted at the clone —
**no bash, no write, no network**. 24 iterations. Four cache breakpoints: tools (sorted-key JSON) →
system (1 h TTL) → **new per-repo preamble, 3–8 k tokens, identical for every finding in that repo** →
rolling conversation.

Measured today: **$0.1728/finding** actual corpus cost; $0.0744 is the post-caching *marginal* figure.
Post-caching the spend is 54% cache writes / 36% output / 10% reads; uncached input fell 2.17 M → 180
tokens; hit ratio **69.9%**. Projected with the preamble breakpoint: **$0.051–0.061/finding**.

Gate: two identical runs, flip rate **>15% stop / 5–15% record as the floor / <5% proceed** (~$16).

**Break-even, from Seat 6's corrected arithmetic:** at 0.071 authz findings/repo, break-even LLM spend
is **$7.14/repo even at V=$100**, against a measured **$2.00/repo**. *The single call is a good trade.
The panel at $12–36/repo is not — which is why it ships behind a flag and claims nothing.*

---

## 7. Reporting

### 7.1 Export-only (D4)

The composer produces a **document on disk plus a `gh` command the operator runs themselves.** No
outbound write to a repo the operator does not administer, ever. This costs eight seconds per report
and makes loop bugs, prompt injection, and misparsed API responses **structurally unable to transmit**.

### 7.2 CVEs (D5)

Default is `not_ours_to_request`, plus a CNA-ready appendix (affected/fixed versions, CWE, CVSS 3.1
vector, PoC, references). Your repos: the advisory API path works and a CVE can be requested. Third
party: you cannot request it — the maintainer or their CNA does. `cveform.mitre.org` (CNA-LR) is a
generated, copy-pasteable packet, never auto-submitted.

### 7.3 The reportability test (D13)

All three must be **yes**, or the finding is deterministically suppressed with reason
`local-dev-fixture` (a seventh free funnel class, ~20 lines, pre-LLM):

1. Does it authenticate to a system the reporter did not instantiate?
2. Is the artifact on a distribution path — published package, tagged release, pushed image?
3. Does the value work anywhere the reporter does not control?

This rule alone removes two of the four "confirmed" findings in the existing corpus.

### 7.4 The render guard (D13)

Applies when `finding.owner != operator`, runs on final rendered bytes + filename + the `gh` command,
**fails closed**. Banned strings: `actively exploited`, `exploited in the wild`, `in.the.wild`,
`under active attack`, `0-?day`, `zero.?day`, `\bKEV\b`, `Known Exploited Vulnerabilit`, `\bEPSS\b`,
`weaponized`, `public exploit available`, `ransomware`. Banned fields: `enrichment.kev.*`,
`enrichment.epss.*`, `exploit_refs[]`, `nvd.cisa_*`. Substitute: silence, plus CVE ID and upstream
advisory URL only — the maintainer looks KEV up themselves and controls when they became "aware."
One fixed line: *"We have not assessed whether this is being exploited and make no claim either way."*

**Why:** EU CRA Article 14 applies **2026-09-11**. Pasting KEV/EPSS into a report can start a 24-hour
statutory clock for a volunteer maintainer.

---

## 8. UI

Three routes, two overlays. `/triage` · `/runs/:id` (the funnel, which *is* the live progress view) ·
`/runs`. Overlays: New Scan, Disclosure drawer.

**The P1 triage unit is the RULE, not the finding.** At ~458 verdict-less findings per repo, a
60-second per-finding decision is the wrong operation — the decision does not vary within a rule. The
operator's job is *"which producers do I ever want to hear from again."*

Default grouping: producer. Three bands, **never severity**:

- **known-good** — `rule_precision.confirmed > 0`
- **unmeasured** — `n < 5`, ordered by corroboration then occurrence count **ascending**
  (cheapest-measurement-first: a rule that fired 3 times is a cheaper measurement than one that fired 61)
- **known-bad** — `confirmed == 0, n ≥ 5`, collapsed

`D` dismisses a producer corpus-wide and writes the ledger; `d` is repo-local. DefectDojo's 458
occurrences collapse to ~60–90 producer ids: ~20–30 min on repo #1, under 10 min by repo #3.

**Build constraint:** every number in the funnel is a link to the set it killed, and it renders **code**
(from evidence blobs, D15), not paths. Heuristic killers flagged `⚠ RECALL RISK`; deterministic ones not.

Evidence blobs: ~8,000 unique windows per 18,431 occurrences ≈ **32 MB raw / 9 MB gzipped**. A 2 GB
target produces the same ~40 MB, because evidence scales with finding count, not repo size.

---

## 9. Recorded dissent triggers

Ratification is conditional. These are recorded verbatim rather than smoothed over:

- **Seat 1 (Detection Architect)** dissents unless (a) P2 thresholds are computed against a **blind
  human-adjudicated union of all arms**, not the LLM-generated confirmations — *"as written, the gate
  cannot fail"*; and (b) **P1c ships in P1** — *"without new detectors the plan measures a filter and
  calls it a finder."*
- **Seat 3 (Disclosure Ethicist)** dissents from P5 shipping unless the **render guard** lands before
  the first document, and documents **self-label `NOT REPRODUCED`** with the `gh` command withheld
  until the reproduction fields are filled.
- **Seat 6 (Adversarial Economist)** dissents if the calibration run is **presented as a measurement**:
  *"a false measurement is worse than an honest unknown."* P2 yields ~222 findings — less power than
  the 162-finding corpus Seat 6 itself disqualified; P(fewer than 3 confirmed) = 20%.

---

## 9a. D17 in full — private repository ingest

Ruled after P0 was built, when anonymous clone turned out to make private repos
unreachable. Seat 5's ruling, adopted verbatim, including the amendment to their own
invariant:

> **Clause (iv):** no credential-holding process may parse a byte stream controlled by
> the party that credential authenticates against, unless the credential's blast radius
> is a subset of what that party already controls.

Clone is not passive — git parses an attacker-controlled protocol stream and then
checks out, interpreting in-tree `.gitattributes`. The attacker controls the *input*,
which the original three clauses did not name. Clause (iv) settles it both ways: a
one-repo `Contents: Read` token held while talking to that repo's own owner has zero
marginal value to them, and passes; the same clone carrying the ambient `gh` token
(`admin:org, repo, workflow`) fails by orders of magnitude. Prohibition rather than
caution, because **(B) with the wrong token is the only (B) anyone builds under
schedule pressure.**

(B) cannot ship today regardless: there is no API to mint a fine-grained PAT, so
"per-run" would mean a browser form — *more* friction than (C).

**Implementation warning, measured by Seat 5: do not use `git archive` for (C).**
A `.gitattributes` containing `hidden.py export-ignore` made `hidden.py` silently
vanish from the import — a one-line evasion aimed squarely at the importer. Use
`git clone --no-local file://` and **assert the tree hash matches
`rev-parse HEAD^{tree}`**, which is cryptographic proof nothing was hidden. Then
`rm -rf .git` and run the identical scrub. Guardrails: no silent fallback to
credentials; refuse a dirty worktree; `run.visibility='private'` hard-blocks every
public output path.

---

## 10. Build order

1. **P0** — schema, `sandbox-exec` profile + spawn wrapper, credential broker, ingest with hooks
   disabled + config quarantine + license detection. *Nothing touches a real target until this lands.*
2. **P1** — scanners → SARIF projection → funnel ledger → `/triage` (producer-grouped) → `/runs/:id`.
3. **P1a** — target selection scorer.
4. **P1c** — zizmor, Scorecard, dependency confusion.
5. **Throughput target: 100 repos overnight.** This does the old gate's work as arithmetic.
6. **repo C replay** of the missing-authz gate. $0, one afternoon.
7. **P2** calibration run, thresholds committed to git first.
8. **P3/P4/P5** as the evidence warrants.
