# Layer 2R — Autonomous Research

**Status: RATIFIED 2026-08-23** — 6 of 6 endorse with conditions, 0 dissents, 5 dissent
triggers. **Reverses D3 and D10.** Read
[`panel/00-chair-layer2r.md`](panel/00-chair-layer2r.md) **first** — it carries fifteen
rulings and three corrections to this document that have NOT been edited into the text
below, so §0.2, §1 and §3 as written are known to be wrong in the ways recorded there.
**To build from, use [`LAYER2-PLAN.md`](LAYER2-PLAN.md)** — it supersedes this document and the ruling record.
**Date:** 2026-08-23
**Constraint:** must remain free — local inference only, no paid model path (enforced by
`tests/test_no_paid_models.py`).

---

## 0. What is being proposed, and what it overturns

The ratified plan says the deterministic layer is the product (D1), that Layer 2 collapses
to a single gated lens (D10), and that the adjudicator starts at one seat (D3). The
operator now wants the opposite emphasis: **models that read and reason over the codebase
on their own, overnight, hunting for things no rule can express.**

That is a reversal, and it should be argued rather than assumed. Here is the argument.

### 0.1 The panel's economics were about paid inference, and they no longer apply

Every cost objection in the review was denominated in Opus dollars:

| Panel finding | Denominated in | Still true locally? |
|---|---|---|
| "break-even LLM spend is $7.14/repo even at V=$100, against a measured $2.00/repo" | USD | **No** — marginal cost is electricity |
| "the panel at $12–36/repo is not a good trade" | USD | **No** |
| "a 9-arm ablation costs $153" | USD | **No** — it costs a night |
| "dense 27B is ~52 h/repo, which is unaffordable" | wall-clock | **Partly** — see §0.2 |

Seat 6's central theorem — *a filter's maximum contribution to true bugs surfaced is
zero* — is not weakened by this. It is **the argument for doing this.** Novel finding is
the numerator. The panel optimised the denominator because the numerator was expensive.
It isn't any more.

### 0.2 Measured: reading is abundant overnight

Benchmarked on this machine (M5 Pro, 64 GB), `qwen3-coder:30b` on a realistic 29 k-token
code context:

```
prompt eval (reading code) : 351 tok/s     ← the binding rate
generation                 :  35 tok/s
one 12-hour night          : 15.2M tokens of reading
```

Against real repositories:

| repo | files | source tokens | one full read | full reads per night ¹ |
|---|---:|---:|---:|---:|
| OWASP/Nettacker | 268 | 0.86 M | 0.7 h | **17.7×** |
| repo C | 596 | 2.26 M | 1.8 h | **6.7×** |
| cve-search | 119 | 0.60 M | 0.5 h | **25.3×** |
| DefectDojo | 2,676 | 8.03 M | 6.4 h | 1.9× |

> ¹ **Corrected by Seat 2 (see chair ruling L3).** This column is the *zero-output* limit.
> Generation runs at 35 tok/s against prefill's 351, so one output token costs **10
> prefill-token-equivalents**, and Layer 2R is output-heavy. Re-denominated in PTE,
> repo C is **~1.4 passes per night, not 6.7**. The headline above is flattering
> and should not be quoted.

**The predecessor read each file exactly once, in isolation, and never re-read anything.**
That was not a capability ceiling — it was a budget assumption inherited from thinking of
inference as scarce. Locally and overnight it is false by an order of magnitude. We can
afford to read a mid-size repository six to eighteen times with a different question each
time, and to re-read any file as often as an investigation demands.

### 0.3 The predecessor's defect was blindness, not stupidity

Its own rejection taxonomy, across 162 adjudicated findings:

| reason | n | cause |
|---|---:|---|
| `already-mitigated` | 40 | validation lived in a file the scanner never saw |
| `false-premise` | 48 | hallucination under a single-file, no-tools prompt |
| `not-a-vulnerability` | 40 | no capability filter |
| `not-reachable` | 9 | could not trace callers |

~~**At least 89 of 162 rejections (55%) are direct consequences of the finder seeing one
file at a time with no tools.**~~ **Withdrawn (ruling L2/§0.3).** Seat 6: that is a
statement about the denominator. Remove all 89 and the numerator is still 4. The real
argument is coverage — `MAX_FILES_PER_REPO` was 25–30, so the predecessor read
**25.2% of cve-search, 11.2% of Nettacker, 5.0% of repo C, 1.1% of DefectDojo.**
It found its one novel finding while reading **5% of that repository.** Meanwhile the *validator* had repo-wide `read`/`grep`/`glob`
and ingested 4.6 M tokens across 80 calls — and was forbidden by its own prompt from
reporting anything.

> The predecessor gave the validator the whole repository and the finder a single file.
> **Layer 2R inverts that.**

---

## 1. What the literature says, and what it forbids

Sources are listed in §8; these are the load-bearing results.

| Result | Source | Consequence for the design |
|---|---|---|
| **LLM-only vulnerability detection: 14% true-positive rate** | Elliot Belt (2026) | Autonomous hunting *must* be paired with adversarial refutation and deterministic validation. It cannot ship raw. |
| **Iterative self-refinement without external feedback degrades findings by 37.6%** | Elliot Belt (2026) | **No self-critique loops.** Every refinement must come from a different model, a tool result, or execution. This is the single sharpest constraint. |
| Claude + Semgrep hybrid: 90% better recall, 61% precision on IDOR | Elliot Belt (2026) | Keep Layer 1. Hybrid beats either alone. |
| "Think and Verify" prompting: **+21.24 pp** | Elliot Belt (2026) | Detection and verification are separate phases, in that order. |
| Filtering can take a 92% FP rate to 6.3% | *Sifting the Noise* | The funnel is what makes autonomous hunting affordable in attention. |
| Single-shot degrades past ~3,000 tokens; fewer tokens improves detection (OR 0.92/token) | Elliot Belt; arXiv 2401.16310 | **Many small focused reads, not one giant context.** Budget abundance buys passes, not context length. |
| CWE-specialised prompting beats generic "find vulnerabilities" | arXiv 2401.16310; ZeroFalse; Qwythos' own measurement | Keep per-CWE lenses — but gate them (§3). |
| Generic personas: small-to-negative effect | Elliot Belt | Role text is cheap and near-worthless. Spend the tokens on context and examples. |
| Few-shot with 3–5 real input/output pairs is "the most powerful technique" | Crash Override | We have 162 adjudicated findings with reasons. Build the example bank from them. |
| GPT-4 I-Score 5.17% vs Bandit 0%, CodeQL 0.39% on the same corpus | arXiv 2401.16310 | ~~Counter-evidence that free tools recover it anyway.~~ **INVERTED by Seat 1 (ruling L5).** The exact one-sided 95% upper bound for 0-for-72 is **4.08%**. GPT-4's best published result is not evidence that LLMs clear the bar — *it is the bar*. Cited here as a floor; it is a ceiling. |
| High output entropy (0.94) even on the best model | arXiv 2401.16310 | Run the same lens more than once; disagreement between runs is signal, and it is free. |

### 1.1 Prompt corpora worth vendoring

| Source | License | What it gives us |
|---|---|---|
| [`dcarrero/awesome-code-review-prompts`](https://github.com/dcarrero/awesome-code-review-prompts) | MIT | Role / Scope / Method / Output-contract skeleton, 8 dimensions, 14 languages, 16 frameworks |
| [`baz-scm/awesome-reviewers`](https://github.com/baz-scm/awesome-reviewers) | Apache-2.0 | ~142 instructions **distilled from real review discussions in production OSS repos** — the closest thing to mined human reviewer judgment |
| [`trailofbits/skills`](https://github.com/trailofbits/skills) | see repo | Audit methodology from people who audit for a living |
| [`Sw4mpf0x/code-review-prompts`](https://github.com/Sw4mpf0x/code-review-prompts) | see repo | Security-oriented review system prompts |

These are **raw material, not a drop-in**. Every one is written for a frontier model with a
human in the loop; ours runs unattended on a 30B. They get adapted and then measured.

---

## 2. Architecture

Layer 2R sits between Layer 1 and the funnel, and emits findings as ordinary producers so
the ledger, the precision tracking and the triage UI need no changes.

```
┌── R0  COMPREHEND ─────────────────────────────── once per repo, cached ────┐
│ tree-sitter index → entry points, routes, auth decorators, sinks,          │
│                     trust boundaries, framework detection                  │
│ LLM architecture note: what is this, who talks to it, what is trusted      │
│ ~1 full read (0.5–2 h).  Reused by every later stage — this is the         │
│ "rich context" the literature says matters more than prompt wording.       │
└───────────────────────────────┬────────────────────────────────────────────┘
┌── R1  HYPOTHESISE ────────────┴──────── stratified, parallel, no tools ────┐
│ Stratified Context Hunting (Refute-or-Promote): hunters differ along       │
│   source  — architecture note / git hotspots / prior CVEs / a bug archetype│
│   scope   — non-overlapping subsystems                                     │
│   wave    — re-seeded with what earlier waves learned                      │
│ Each hunter emits candidates AND, for each, why it might NOT be exploitable│
│ Small windows (≤3k tokens) — detection degrades past that.                 │
└───────────────────────────────┬────────────────────────────────────────────┘
┌── R2  INVESTIGATE ────────────┴──── agentic, repo-wide tools, THE GRIND ───┐
│ Each candidate gets a read/grep/glob loop over the WHOLE repo.             │
│ Resolve: who calls this? is there a decorator? does middleware cover it?   │
│          is the sink's own implementation visible? is this test code?      │
│ This is the stage that kills `already-mitigated` and `not-reachable`       │
│ — 49 of 162 rejections — before anything is reported.                      │
│ Budget: N turns per candidate, capped. Re-reading is cheap.                │
└───────────────────────────────┬────────────────────────────────────────────┘
┌── R3  REFUTE ─────────────────┴──── DIFFERENT MODEL FAMILY, claim-only ────┐
│ gpt-oss:20b (different lineage from qwen3-coder) with a kill mandate and   │
│ context asymmetry: it sees the claim, never the hunter's reasoning.        │
│ Refute-or-Promote's Stage D, at $0. NOT self-critique — that is the        │
│ configuration measured to degrade findings by 37.6%.                       │
└───────────────────────────────┬────────────────────────────────────────────┘
┌── R4  VALIDATE ───────────────┴──── deterministic, no model, free ─────────┐
│ verbatim sink quote check · path/line resolution · sibling-authz anomaly   │
│ confirmation · route resolution · PoC execution where a harness exists     │
│ "80+ agents unanimously endorsed a vulnerability that did not exist —      │
│  killed by one test." Unanimity among models is not evidence.              │
└───────────────────────────────┬────────────────────────────────────────────┘
                    findings enter the existing funnel as producers
```

### 2.1 Model assignment

| Stage | Model | Why | Cost |
|---|---|---|---|
| R0 comprehend | `qwen3-coder:30b` | best local code comprehension on disk | $0 |
| R1 hypothesise | `qwen3-coder:30b` | | $0 |
| R2 investigate | `qwen3-coder:30b` + tools | needs tool-calling and long horizon | $0 |
| R3 refute | **`gpt-oss:20b`** | **different family** — correlated-error catcher | $0 |
| R3b classify | `Foundation-Sec-8B-Instruct` | CWE mapping, security-relevance; SOTA on CVE→CWE | $0 |
| R4 validate | none — Python + the sandbox | execution beats argument | $0 |

All four are already pulled. Total marginal cost: electricity.

### 2.2 Overnight scheduling

A `research` queue plus an idle daemon. Work is chunked at the *candidate* level so a run
is interruptible and resumable — the laptop closing must cost one candidate, not one night.

```
quarry research enqueue <run_id> --waves 3 --until 07:00
quarry research run --budget-hours 12        # foreground, resumable
quarry research status
```

Wave scheduling matters: wave 2 is re-seeded with what wave 1 confirmed *and* what it got
wrong, which is external feedback rather than self-refinement.

---

## 3. Which lenses run — and the honest problem with cutting four

Seat 1 cut `injection`, `path-file`, `ssrf-network` and `deserialization` on two grounds:
Seat 6's empirical 0-for-72, and the formal argument that all four ask a source→sink→path
question, which is definitionally what a taint engine computes.

**The formal argument survives Layer 2R. The empirical one does not, and I want to be
straight about why.** Those lenses were measured on a 9B, reading one file, with no tools,
no repo context, and a 25% think-truncation rate. That is not a fair test of the *question*;
it is a test of a broken configuration. 0-for-72 with 95% CI [0%, 5.1%] tells us that setup
does not work. It does not tell us a 30B with repo-wide tools cannot answer the same
question.

Proposed resolution — **re-earn, do not resurrect**:

| Lens | Status | Rationale |
|---|---|---|
| `missing-authz` (sibling anomaly) | **Ships.** | Outside the taint formalism; produced the only LLM-only confirmation |
| `sanitizer-validity` | **Ships.** | Only on flows Opengrep already proved; the engine cannot know if `sanitize()` really sanitises |
| `business-logic` / `state-machine` | **Ships (new).** | No engine expresses "this refund path can run twice". Highest-value class no rule can reach. |
| `trust-boundary` / `multi-tenancy` | **Ships (new).** | Cross-tenant data exposure is structural, not syntactic |
| `injection`, `path-file`, `ssrf`, `deser` | **Deferred, with a re-entry test.** | Run once against Opengrep's own taint output on the same repo. If Layer 2R finds nothing Opengrep did not, they stay dead — permanently, with a number. |

The re-entry test costs one night and settles the question with evidence instead of
inheriting a verdict from a broken configuration.

---

## 4. Few-shot from our own ground truth

Crash Override's strongest claim is that 3–5 real input/output pairs beat any amount of
instruction. **We have 162 adjudicated findings with verdicts and reasons** — a local,
ground-truthed example bank in exactly the shape a few-shot prompt needs:

- 4 `confirmed` (with the adjudicator's exploit path)
- 48 `false-premise` — what hallucinated code looks like
- 40 `already-mitigated` — what "the validation is elsewhere" looks like
- 40 `not-a-vulnerability` — what "real construct, no attacker benefit" looks like

Every wave adds to it. Nobody else building this has that corpus, and it grows for free.

---

## 5. Measurement — what keeps this honest

Seat 6's objection to the panel was that it could never be shown to work. Layer 2R must not
inherit that, and free inference makes rigour affordable rather than aspirational:

- **Every hypothesis is logged**, including the ones killed at R3 and R4. Per-stage kill
  rates land in the same `funnel_events` ledger as everything else.
- **Per-lens yield is tracked from run one.** The 0-for-72 problem must be visible after ten
  repos, not after a year.
- **Determinism gate:** run the same lens twice on the same SHA. The literature reports
  entropy 0.94 on frontier models; if our flip rate is high, every downstream number is
  uninterpretable, and this costs a night to learn.
- **Free tools as the control arm, always.** Every Layer 2R finding is checked against
  whether Layer 1 already had it. **The metric that matters is not precision — it is
  `novel_confirmed`: findings no deterministic tool produced.** That is the numerator the
  whole proposal exists to raise, and it is one SQL query.
- **The corpus reaches n=285** — Seat 2's threshold for a powered comparison — by running,
  not by budgeting.

---

## 6. Honest risks

| Risk | Severity | Mitigation |
|---|---|---|
| **14% TP rate produces a flood the operator drowns in** | High | R3 + R4 + the funnel + producer-level triage. If `novel_confirmed` stays 0 after 20 repos, stop. |
| **Self-refinement creeps in** and silently costs 37.6% | High | Architectural ban. R3 must be a different model family; no stage may critique its own output. Enforce in a test. |
| **We re-derive what Opengrep already computes**, expensively | Medium | §3's deferral plus the Layer 1 control arm |
| **Overnight runs on unaudited targets** — exactly where a hostile repo sits (Seat 5) | High | Everything runs under Tier 1; the model reads **evidence blobs and sandboxed files**, never with credentials in scope |
| **Prompt injection from target source into an agentic loop with tools** | High | R2 is the first stage where a tool-using model reads attacker-controlled text. Needs a real trust boundary, not a delimiter convention. **Open question for Seat 5.** |
| **Wall-clock optimism** — DefectDojo is 1.9 reads/night | Medium | Target selection (P1a) already prefers tractable repos; cap by token budget, not file count |
| **It simply does not find anything** | Medium | That is a valid outcome, cheaply learned, and worth publishing |

---

## 7. Phasing

| Phase | Work | Cost |
|---|---|---|
| **R-0** | Prompt corpus vendored + adapted; few-shot bank built from the 162 verdicts | 1 day, $0 |
| **R-1** | R0 comprehension pass + repo map; `missing-authz` sibling gate replayed on repo C — the free experiment already agreed | 1 day, $0 |
| **R-2** | R1+R2 agentic hunting for the two shipping lenses; determinism gate | 2 days, then nights |
| **R-3** | R3 cross-family refutation + R4 deterministic validation | 1 day |
| **R-4** | Overnight daemon, wave scheduling, resumability | 1 day |
| **R-5** | Re-entry test for the four deferred lenses | 1 night, $0 |

**The gating experiment is R-1**, and it was already ratified as free: replay the
missing-authz sibling anomaly against repo C and see whether the known LLM-only
finding falls out. Confirmed today: no deterministic scanner produces it.
If the gate does, the lens is real. If it does not, Layer 2R starts one lens poorer and we
learned it in an afternoon.

---

## 8. Sources

- [Prompting for Security Research](https://felixbillieres.github.io/posts/prompting-for-cybersecurity-2026/) — 14% LLM-only TP; **-37.6% self-refinement**; +21.24 pp Think-and-Verify; hybrid 61% precision on IDOR
- [Crash Override — How to Prompt LLMs for Better, Faster Security Reviews](https://crashoverride.com/blog/prompting-llm-security-reviews) — persona/context/few-shot/instructions/output-format; few-shot as the strongest lever
- [An Insight into Security Code Review with LLMs (arXiv 2401.16310)](https://arxiv.org/html/2401.16310v3) — GPT-4 5.17% I-Score vs **Bandit 0%, CodeQL 0.39%**; CWE-list prompting wins; token count dominates; entropy 0.94
- [Refute-or-Promote (arXiv 2604.19049)](https://arxiv.org/html/2604.19049v1) — stratified context hunting, kill mandate, context asymmetry, cross-model critic
- [dcarrero/awesome-code-review-prompts](https://github.com/dcarrero/awesome-code-review-prompts) (MIT) · [baz-scm/awesome-reviewers](https://github.com/baz-scm/awesome-reviewers) (Apache-2.0) · [trailofbits/skills](https://github.com/trailofbits/skills) · [Sw4mpf0x/code-review-prompts](https://github.com/Sw4mpf0x/code-review-prompts)
- Local measurements: `qwen3-coder:30b` 351 tok/s prompt eval @ 29 k ctx; repo token counts above; `Qwythos/work/*/verified/` (162 verdicts, 14 repos)
