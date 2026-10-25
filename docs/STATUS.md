# Build status — 2026-08-23

Plan: [`PLAN.md`](PLAN.md) · Research: [`RESEARCH.md`](RESEARCH.md) · Panel: [`panel/`](panel/)

**449 tests green.** `quarry doctor · db sync · targets score · ingest · scan · funnel · killed · validate · report · serve`

---

## Built

### P0 — containment and schema

Seat 5's non-tradeable precondition: nothing touches a real target until this is in place.

| Piece | Verified how |
|---|---|
| Data-root refusal check | refuses `~/Documents`, sync xattrs, network mounts |
| Per-run APFS sparse image | 20 GB quota, case-sensitive, released as one `rm` |
| `sandbox-exec` Tier 1 | `~/.ssh`, `~/.config/gh`, keychain, `~/Documents` **denied**; network → `HTTP:000`; `$HOME` write **denied** |
| Tier 1-net clone profile | separate profile — network allowed, credentials still denied |
| Hardened clone | hooks off, no submodules, no LFS smudge, `protocol.file.allow=never`, empty `credential.helper` |
| Symlink scrub | **fired on the first real repo** |
| Config quarantine (D14) | loader-capable vs suppression, moved not deleted, sha256 recorded |
| Credential isolation | `env -i` + fixed allowlist; a planted `ANTHROPIC_API_KEY` canary never reaches a child |
| Taint boundary | absolute / `..` / `file://` / `https://` / ANSI / NUL paths refused; C0-C1 stripped |
| Secret redaction (D16) | prefix + SHA-256; 13/13 evidence windows carried a redaction marker, 0 leaked |
| Evidence blobs (D15) | ±40 lines, content-addressed, captured for killed occurrences too |
| Schema (D8/D9) | three-level identity, `funnel_events` ledger, `live_occurrences` view |

### P1 — deterministic layer

Seven scanners under Tier 1 containment. Zero model calls, zero dollars.
On `OWASP/Nettacker` (860 files): **616 findings in ~38 s** — opengrep 105, bandit 355,
gitleaks 13, zizmor 23, osv-scanner 71, trivy 39, checkov 10.

`quarry db sync` provisions Trivy (1.3 GB), Grype (2.1 GB) and OSV (48 MB) *outside*
the sandbox — the one deliberate network step — and writes every fetch to the egress ledger.

### The funnel — Seat 1's twelve canonical stages

Ordered, because order changes the answer. Every stage writes `funnel_events`; nothing
is deleted; `defer` (a rate limiter) and `kill` (evidence) are different actions.

```
616 → 191 survive (31%)
  1 quote-verify              kill  10
  2 symbol-containment          ·
  3 path-class  ⚠ RECALL RISK  kill 319
  4 local-dev-fixture          kill  26
  5 exact-dedup                  ·
  6 sca-merge                  merge 70
  7 cross-tool-cluster         pass  15
  8 rejected-carry-forward       ·
  9 rule-precision-prior       boost 191
 10 independence-corroboration boost  15
 11 novelty-rank               boost 122
```

Rank is derived, never stored — the sum of every `score_delta` a finding was granted, so
you can always ask *which stage* put a finding where it is.

### P1a — target selection (D2)

Scored on **attack surface × reach** (blast radius + maintainer responsiveness). Audit
maturity — OpenSSF Scorecard, `SECURITY.md`, CodeQL workflow — is recorded as a
**covariate and never scored**, because selecting on it begs the calibration run's question.

| target | score | surface | blast | resp |
|---|---:|---:|---:|---:|
| repo C | **45** | 29 | 8 | 23 |
| OWASP/Nettacker | 39 | 24 | 10 | 23 |
| DefectDojo/django-DefectDojo | 24 | 15 | 10 | 24 |
| danielmiessler/SecLists | **0** | 0 | 10 | 24 |
| sindresorhus/awesome | **0** | 0 | 10 | 24 |

repo C ranking first is a weak signal at best. n=1.

### Second full run — `repo C`, the scorer's top pick

**2,456 findings in 2m31s** (opengrep alone 2,316 in 145s).
The funnel kills only 7% here versus 69% on Nettacker — this repo has no test tree
matching the path patterns, and the funnel does not suppress what it cannot justify.
That is the honest behaviour, and it is why grouping carries the load:

```
2,277 live findings  →  89 producer decisions   (25.6× collapse)
  920  opengrep:javascript.express…xss.mustache.var-in-href
  282  opengrep:bash.lang.correctness.unquoted-variable-expansion
  179  opengrep:python.flask.security.open-redirect
  …top 8 producers = 1,762 / 2,277 = 77% of the queue
```

Seat 4's producer thesis gets *stronger* with repo size: 3.5× collapse on Nettacker,
25.6× here. Per-finding triage would be 2,277 decisions; per-rule triage is 89.

### The UI — three routes, Seat 4's design

`/triage` · `/runs/{id}` · `/runs`. FastAPI + Jinja + HTMX + Alpine, vendored locally,
loopback only, holds no credentials.

**The triage unit is the rule, not the finding.** 2,277 live findings collapse to 89
producer decisions (25.6×); on a smaller repo, 191 to 92. Banded known-good / unmeasured / known-bad, ordered
cheapest-information-first, **never by severity**. `d` dismisses for this repo, `D`
corpus-wide — both reversible, both write an attributed ledger event, neither deletes anything.

`/runs/{id}` is the funnel, and **every number is a link to the set it killed**, rendering
code from evidence blobs rather than paths. Heuristic stages are flagged `RECALL RISK`.

---

## Bugs the build caught in its own design

Five, all found by running the thing rather than by reading it:

1. **The path filter destroyed 100% of SCA recall.** `poetry.lock` matches "generated", so
   `path-class` killed all 107 dependency findings from OSV-Scanner and Trivy — and the run
   still reported success. A path filter that is not tool-aware silently deletes an entire
   detector class. Now exempt for the `sca-db` class, with a regression test.
2. **SCA merge found nothing because it did not resolve aliases.** OSV reports
   `PYSEC-2026-2094`, Trivy reports the `CVE-2026-22815` it aliases to. Every dependency
   vulnerability was counted twice — and the duplicate then earned a corroboration boost,
   actively outranking genuine single-source findings. Now 70 duplicates collapse.
3. **The target scorer ranked a wordlist above real applications.** Additive scoring put
   `SecLists` at 45 and `awesome` at 34 on stars and commit recency alone. Surface is now a
   multiplicative gate: no attacker-reachable code, no score.
4. **Restore overrode the deterministic funnel.** Withdrawing an operator dismissal also
   resurrected findings the funnel had killed for unrelated reasons. Now scoped to
   occurrences whose *only* suppression came from the operator.
5. **Opengrep rule IDs embedded the absolute config path**, making `producer_id`
   machine-specific so the cross-repo precision ledger — Seat 1's condition of endorsement —
   would silently never accumulate.

Plus: a scan against an empty tree silently reported "0 findings" (now a loud failure), and
`ALTER TABLE RENAME` silently repointed a view at a table the same migration dropped.

---

## Next: Layer 2R — autonomous local research

Ratified 2026-08-23 (6/6 endorse with conditions). The operator directed a reversal of D3
and D10: local models reading and reasoning over the codebase overnight rather than
validating tool output. **Build plan: [`LAYER2-PLAN.md`](LAYER2-PLAN.md)** · rulings:
[`panel/00-chair-layer2r.md`](panel/00-chair-layer2r.md) · proposal (annotated where wrong):
[`LAYER2-RESEARCH.md`](LAYER2-RESEARCH.md).

The shape: **one mechanism, four deterministic detectors.** A `GROUP BY` over the tree-sitter
index emits a small anomaly cohort; the model answers one bounded question — *"is this absence
intended?"* The detectors keep working if the model is cut. Two free prerequisites block the
first night: enable Opengrep interfile taint (it defines the control arm) and measure cohort
size on the repo C replay (if cohorts are 1:1 there is no triage model).

## Not built yet

- **Layer 2** — the single gated authorization lens, and the free repo C replay
  that decides whether it lives at all.
- **P4 adjudicator** — the single Opus 5 seat, gated behind the calibration run.
- **P5 composer** — export-only, render guard, CNA packet.
- **P1c** — OpenSSF Scorecard as a detector, dependency confusion. *(Scorecard is already
  consumed as a target covariate, but not as a finding source — Seat 1's dissent trigger is
  not yet satisfied.)*
- **P2 calibration run.**

## Cost posture — verified, and guarded

**Quarry spends nothing today, and cannot.** Verified by inspection and now enforced
by `tests/test_no_paid_models.py` (7 assertions):

| check | result |
|---|---|
| Model-provider SDK imported | none |
| Model-provider SDK declared in `pyproject.toml` | **none, not even as an extra** |
| Paid-model endpoint in source | none |
| Local model endpoint in source | none (Layer 2 is gated) |
| Credential read in source | none — ingest clones anonymously (D17) |
| Outbound hosts | `github.com`, `repos.ecosyste.ms`, `api.securityscorecards.dev` — all free, no key |
| Recorded spend | **$0.0000** across 0 verdicts |

`quarry doctor` reports this posture on every run, so it is visible rather than
buried in a test.

Two latent paths were removed rather than left dormant: the `[llm]` extra declaring
`anthropic>=1.0.0`, and an unused required `httpx` dependency. An unused optional
dependency is an invitation to write the code path before the calibration run has
justified it — the SDK gets added in the same commit as the adjudicator, never before.

**The guard is a tripwire, not a prohibition.** When P4 is built these tests should fail
loudly and be amended in the same commit, alongside the cost accounting and the budget
ceiling.

## Known limitations

- **Private repositories are unreachable** by design (D17); out-of-band clone is ruled but
  unimplemented.
- **Rule rot.** `opengrep/opengrep-rules` was archived 2025-11-28 and is the only substantial
  free pack (1,942 rule files); `AikidoSec/opengrep-rules` holds **two**.
- **Grype's 2.1 GB database** is the largest disk cost and grype is not yet in the scan path.
- **Cross-tool clustering is coarse** — same file, same ten-line window, different detector
  classes. It has not been tuned.
- No container runtime installed; not needed for P1 (Seat 5's ruling). Colima is P3/P5.
