# Chair's Synthesis — Layer 2R, round 3

**To:** Seats 1–6  **Re:** `docs/LAYER2-RESEARCH.md`
**Outcome: 6 of 6 endorse with conditions. 0 dissents.** Five dissent *triggers* recorded.

> This file is the **ruling record** — what was decided and why. The buildable design that
> came out of it is [`../LAYER2-PLAN.md`](../LAYER2-PLAN.md).

---

## 0. Corrections the chair owes, before anything else

The panel found three errors in my proposal. I verified each myself. All three stand.

### 0.1 I cited a number backwards — Seat 1

§1 cites GPT-4's **5.17% I-Score** against Bandit's 0% and CodeQL's 0.39% as counter-evidence
to the panel's "free tools recover it anyway." Seat 1 points out that the same section
contains the refutation: **the exact one-sided 95% upper bound for 0-for-72 is 4.08%**
(Seat 6's two-sided figure was 5.1%). GPT-4's best published result is not evidence that
LLMs clear the bar — *it is the bar*. 5.17% "fully accurate detections" is a ceiling, and
I presented it as a floor. Correction accepted; §1's row is inverted.

### 0.2 My throughput headline was the zero-output limit — Seat 2

The measurement was right and the unit was wrong. Prefill runs at 351 tok/s and generation
at 35 tok/s, so **one output token costs 10.0 prefill-token-equivalents**. "15.2M tokens of
reading per night" is what you get if the model never writes anything. In prefill-token-
equivalents, and with Layer 2R being output-heavy, **repo C is ~1.4 passes per
night, not 6.7.** Every figure in §0.2 must be re-denominated in PTE. This does not sink
the proposal — Seat 2's own allocation still lands ~100 investigated candidates a night —
but the headline was flattering and I wrote it.

### 0.3 My recall argument was a filter statistic — Seat 6

§0.3 argues "at least 89 of 162 rejections (55%) are consequences of single-file blindness."
Seat 6: that is a statement about the *denominator*. Remove all 89 and the numerator is
still 4. The real argument was sitting in `config.sh` and I missed it:

| repo | code files | files actually read | **fraction of the repo seen** |
|---|---:|---:|---:|
| cve-search | 119 | 30 | 25.2% |
| OWASP/Nettacker | 268 | 30 | 11.2% |
| **repo C** | **596** | **30** | **5.0%** |
| DefectDojo | 2,676 | 30 | **1.1%** |

The predecessor found its one novel finding while reading **5% of that repository**. That is
the recall case. It is much stronger than the one I made, and it is Seat 6's, not mine.

---

## 1. A live bug in shipped code, found by this round

Seat 5 checked `taint.scrub_text` against the code I committed this morning and found it
covers C0/C1 only. Verified: **U+200B, U+202E, U+FEFF, U+2066 and the U+E0000 tag block all
survived the scrubber.** U+202E is Trojan Source (CVE-2021-42574) — rendered text reorders
so the code a reviewer reads is not the code that runs.

This was survivable when only humans read evidence windows. Layer 2R makes an agentic model
read them and act on them. **Fixed and tested before writing this synthesis** — six new
regression cases, plus one asserting legitimate `café / 変数 / 🚀` still round-trips.

---

## 2. Rulings

**L1 — Layer 2R proceeds.** Unanimous endorsement, conditional. The operator's direction
stands and the panel's cost objections are formally retired: Seat 6 reproduced the benchmark
independently (354.54 tok/s) and withdrew their dollar economics; Seats 1 and 2 both withdrew
their wall-clock objections.

**L2 — But the scarce resource moved, and nothing was re-denominated.** Ruling for Seat 6,
whose sharpest round-3 point is not about tokens: *"the scarce resource moved from dollars to
operator-adjudication-hours, and the proposal re-denominated nothing."* Every threshold in
§5–§6 is counted in repos and nights, which are now free. **The binding budget is Jerry's
attention.** Seat 6's cap — 40 operator-hours — is adopted as the real ceiling.

**L3 — Budget in prefill-token-equivalents, not tokens.** Ruling for Seat 2. Their
allocation is adopted as the planning baseline: R0 0.18M PTE cached to SHA · R1 sweep 2.84M ·
R1 escalation 1.70M · R2 investigate 1.30M · R3+R3b 0.26 h → **~6.0M PTE, ~5.0 h per wave,
two waves a night, ~100 candidates investigated, ~35 surviving refutation.** Their conclusion
is the important one: **the constraint is candidate yield, not tokens** — 76% of the night is
spent generating 50 candidates. That is the same bottleneck the ratified plan hit from cost.

**L4 — Every lens needs a deterministic gate, including the two new ones.** Ruling for
Seat 1, who granted the new lenses admissible but only gated. `business-logic/state-machine`:
`GROUP BY (model)` on transaction/lock/idempotency coverage, ≥60% sibling threshold, zeroed
on repos without persistence. `trust-boundary/multi-tenancy`: a discriminator on ≥3 models or
the lens does not run, then ≥80% sibling scoping — and Seat 1's reframe is adopted: **it is
authz at row granularity, not a new lens.** An ungated lens is the broad sweep already killed.

**L5 — The re-entry test is the right shape and the wrong instrument.** Ruling for Seats 1
and 6 jointly, against my §3. Wrong control (Opengrep's taint alone rather than the Layer 1
union), wrong criterion (novelty is maximised by hallucinating), and it grades its own
homework because R3/R4 sit inside the arm. **Replaced with planted-bug recall**, per-lens,
pre-registered at 5%, n≥60 per lens, precision computed *before* R3, blind adjudication
against pooled arms with `false-premise` decoys.

**L6 — Turn on Opengrep interfile taint first.** Unanimous across Seats 1, 2 and 6. It is
free, already on disk (`1.28.0-interfile.alpha.2`), and **it defines the control** — every
novelty number computed before it lands is inflated. Opt-in flag, Layer 1, this week.

**L7 — The triage unit for novel findings is the anomaly cohort.** Ruling for Seat 4, who
retracted their own thesis where it did not reach. Two seats independently found the same
mechanical defect: `producers.id` is `tool:rule_id`, so **Layer 2R is one row, and by repo #2
it satisfies `n_confirmed == 0, n_adjudicated ≥ 5` and self-suppresses into the collapsed
known-bad band.** Confirmed against `queries.py:44`. The cohort is the `GROUP BY` key of the
gate that produced the candidate — `(blueprint, sibling guard rate)`, `(model, discriminator)`,
`(table, lock posture)`. **A candidate with no deterministic parent gets no cohort, no ledger
and no queue.** Producer id becomes `r2r:{lens}:{epoch}@{digest}`.

**L8 — The morning queue is a separate route that leads with refutation.** Ruling for Seat 4.
`/nights/:date`, hard-capped at ten, leading with `96 → 61 → 35 → 6` and every arrow opening
its killed set. Zero is the default aesthetic, because most mornings are zero. The detail view
renders Seat 1's typed resolution record, not the agent transcript. Only machine-checked
fields set the evidence bar's length; model assertions render hollow.

**L9 — Containment: three processes, a closed verb set, and a nonce envelope.** Ruling for
Seat 5. `omni-r2-exec` under Tier 1 with reads confined to `RUNDIR/src` — **not `RUNDIR`,
because `quarantine/` holds the suppression reason strings D14 says no model may see**, which
is a gap in my own design. `omni-infer` holds the ollama socket and never opens a path. A
broker validates every tool call against a closed verb set (`read`/`grep`/`glob`/`done`) reusing
the shipped `taint.safe_relpath`. Tool results return inside a per-invocation random nonce
envelope, stripped from the data and verified in the output. **No `11434` in any sandbox
profile — inference is brokered over an inherited fd.**

**L10 — Clause (v).** Seat 5 amends their own invariant again, and it is the right amendment:
*no process may both **select** an operation from target content and **hold** the authority it
exercises.* Clause (i) passes even if the three processes are collapsed into one, which would
be unsafe; (v) does not.

**L11 — Model-generated logic findings need a structural floor before they may be drafted.**
Ruling for Seat 3: five slots, all filled from resolved symbols in the R0 index and never from
model prose — entry point; a named second principal; a path with zero unresolved hops; the
absent guard absent everywhere on that path (grepped **without** a model, because R2's output
is the thing under suspicion); an in-repo counterexample. Their formulation is adopted
verbatim: **"a model-generated logic finding may be drafted only if a program that cannot read
English can verify every structural claim in it."**

**L12 — The channel gates the composer.** Ruling for Seat 3, on measurement: of 36 repos
matching the shipped scorer's profile, **26 (72%) have neither `SECURITY.md` nor private
vulnerability reporting** — versus 2 of 10 in the Qwythos-like stratum. Under their tree
"neither" routes to a *public issue*. So: when the producer is a Layer 2R lens and the only
channel is a public issue, **no document is generated at all.** D2 stands untouched — scoring
targets on channel would beg the question in the other direction — but the composer closes for
roughly three targets in four. Seat 3 also corrected my premise: `targets.py` does not select
for few maintainers; `responsiveness` rewards *more* committers.

**L13 — No self-refinement, enforced by a tripwire.** Ruling for Seat 2. `tests/test_no_self_refinement.py`
in the shape of the paid-model guard: every configured pipeline crosses model families (not
just today's default); every model id declares a family or the build fails; no hunter-family
literal in `r3.py` and **no fallback** — an unavailable refuter yields `defer`, never a
same-family review; no nudge strings in the prompt corpus; a prose-only turn terminates the R2
loop; wave-2 seeds and the few-shot bank admit only `r4_deterministic` / `r3_crossfamily` /
`human` provenance.

**L14 — JSON reliability is a stack, not a flag.** Ruling for Seat 2, who measured that
grammar-constrained output still returns a valid JSON *prefix* with `done_reason: "length"`.
Assert `done_reason == "stop"`; bound every string with `maxLength`; set
`num_predict ≥ 1.4 ×` max serialisation so truncation is impossible by construction; split
reasoning from grammar-constrained transcription; retry once then `defer` with a ledger row;
CI gate at 2%. **Grammar buys syntax, never semantics** — it emitted `CWE-521` for a textbook
IDOR, so CWE assignment goes to Foundation-Sec.

**L15 — The free-model guard covers the product, not the eval harness.** Ruling for Seat 6,
who raised the sharpest unresolved tension: `novel_confirmed` has no instrument if every
adjudicator must also be free, and *"if measurement must also be free, Layer 2R is
unmeasurable by construction."* The chair's position: **`tests/test_no_paid_models.py` guards
the shipped pipeline.** A paid second rater used once, offline, to score a pre-registered
experiment is a different thing and should be permitted — **but it is the operator's call, not
the panel's, and it is flagged for decision rather than assumed.**

---

## 3. The two things that must happen before any night runs

Both are cheap, both are gating, and both came from the panel rather than from me:

1. **Opengrep interfile taint on** (L6). It defines the control arm. Any novelty number
   computed before it lands is inflated.
2. **Cohort size measured on the R-1 repo C replay** (Seat 4's non-blocking
   reservation, which the chair is promoting to blocking). *"If cohorts are 1:1, Layer 2R has
   no triage model and the honest product is a digest the operator reads and closes."* That is
   a one-afternoon, zero-dollar measurement that determines whether L7 and L8 are worth
   building at all.

## 4. Recorded dissent triggers

- **Seat 1** — if the new lenses ship ungated, or thresholds are not in git before the first clone.
- **Seat 3** — C1 render guard, C4 self-labelling, **C6 channel prerequisite**, **C8 provenance block**.
- **Seat 5** — if the three-process split and its fixture test do not land before R2 reads a real target, or if `11434` appears in a sandbox profile.
- **Seat 6** — if the calibration is again presented as a measurement; or if the free-only guard is read to forbid a paid rater for the experiment.
- **Seat 2** — if any seat or lens ships on argument rather than measurement.

## 5. Three measured facts the plan must absorb

From Seat 5, verified against the machine rather than asserted:

- **`pmset` shows `sleep 1` on AC with no assertion held** — the 12-hour night is fiction as
  currently scheduled. The daemon must hold a power assertion (`caffeinate -is`) or it will
  simply stop.
- **`RunVolume` never re-checks its mount**, so a sleep/wake detach silently writes to the
  boot volume — directly relevant to overnight runs.
- **KV prefix reuse measured 83.3 s → 0.035 s (2,398×)** — and R3's model swap evicts it.
  Wave scheduling must batch by model, not by candidate.
