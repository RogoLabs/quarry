# Layer 2R — Build Plan

**What this is:** the design that came out of the panel, written as something you can build
from. The proposal is [`LAYER2-RESEARCH.md`](LAYER2-RESEARCH.md) (annotated where it is
wrong); the ruling record is [`panel/00-chair-layer2r.md`](panel/00-chair-layer2r.md). This
file supersedes both as the thing to implement.

**Status:** ratified 2026-08-23, 6/6 endorse with conditions, 0 dissents.
**Constraint:** local inference only — **and per amendment A1, that now covers the eval
harness too, not just the shipped pipeline.** Principal's decisions on ratified rulings are
recorded in [`panel/AMENDMENTS.md`](panel/AMENDMENTS.md); §11 below reflects them.

---

## 1. The one idea the panel converged on

The proposal described four LLM "lenses." Seat 1 reframed them, Seat 4 built the triage
model on the reframe, and Seat 3 made it the disclosure gate. It is now the spine:

> **It is not four lenses. It is one mechanism with four deterministic detectors.**
> A detector emits a small anomaly set. The model answers one bounded question about each:
> **"is this absence intended?"**

Everything follows from that:

- **The detectors keep working if the model is cut.** They are `GROUP BY` queries over a
  tree-sitter index. That makes the index a Layer 1 deliverable that earns its keep even if
  every lens dies (Seat 1, condition 6).
- **The anomaly cohort is the triage unit** — `(blueprint, sibling guard rate)`,
  `(model, discriminator)`, `(table, lock posture)`. A cohort has a population and one
  uniform decision: *"this blueprint is an internal admin surface, all 14 are intended"* is
  one decision, not fourteen (Seat 4).
- **A candidate with no deterministic parent gets no cohort, no ledger, no queue, and no
  composer.** Ungated hunting writes to a file. It does not get a screen, because a screen
  legitimises output (Seat 4); and it never reaches a maintainer (Seat 3).

The model's job is narrow and it is the job no engine can do: **judge whether an absence is
deliberate.** That is outside the taint formalism, and it is what produced the only
LLM-only finding in the 14-repo corpus.

---

## 2. Corrected numbers to build against

Three figures in the proposal were wrong. Use these.

| | proposal said | actually |
|---|---|---|
| Overnight budget | 15.2M tokens of reading | **15.16M prefill-token-equivalents.** Generation costs **10 PTE per token** (7.3 on gpt-oss). repo C is **~1.4 passes/night, not 6.7.** |
| Published LLM ceiling | GPT-4 5.17% beats Bandit 0% | **4.08%** is the exact 95% upper bound on 0-for-72. 5.17% *is the ceiling*. Pre-register 5%, do not expect to beat it. |
| Why the predecessor missed things | 55% of rejections were blindness | It read **30 files**: 25.2% of cve-search, 11.2% of Nettacker, **5.0% of repo C**, 1.1% of DefectDojo. It found its one novel finding inside that 5%. |

**Position in the pipeline — one word, ruled by Seat 6:** Layer 2R is a **side-car
producer, never a pipeline stage.** As a stage it serialises behind Layer 1 and kills the
100-repos-overnight target; as a side-car it runs on GPU while the CPU-bound scanners run,
and they coexist.

---

## 3. Architecture

```
                    ┌──────────── Layer 1 (CPU, ~38s/repo) ───────────┐
   ingest ─────────►│ 7 scanners → funnel → /triage                   │──► findings
      │             └──────────────────────────────────────────────────┘
      │                                    ▲
      │  tree-sitter index (shared)        │ control arm: every 2R candidate
      ▼                                    │ is joined against Layer 1 at emission
   ┌──── Layer 2R side-car (GPU, overnight) ──────────────────────────────────┐
   │ R0  comprehend    repo card, cached to SHA                    0.18M PTE  │
   │ D   detect        4 deterministic gates → anomaly cohorts     free, SQL  │
   │ R1  hypothesise   one bounded question per anomaly            4.54M PTE  │
   │ R2  investigate   agentic, 3 read-only verbs, typed record    1.30M PTE  │
   │ R3  refute        gpt-oss:20b, kill mandate, no fallback      0.26 h     │
   │ R4  validate      deterministic; no model                     free       │
   └──────────────────────────────┬───────────────────────────────────────────┘
                                  ▼
              /nights/:date  →  cohort triage  →  composer (channel-gated)
```

### 3.1 Night budget (Seat 2's allocation, repo C, 200 entry points × 4 lenses)

| stage | PTE | wall |
|---|---:|---:|
| R0 comprehend (once, cached to SHA) | 0.18 M | 8 min |
| R1 sweep, 660 units at k=1 | 2.84 M | 2.25 h |
| R1 escalation, k=4 on the ~15% returning a candidate | 1.70 M | 1.35 h |
| R2 investigate, 50 candidates × 26 k | 1.30 M | 1.03 h |
| R3 refute + R3b CWE classify | — | 0.26 h |
| **one wave** | **~6.0 M** | **~5.0 h** |

**Two waves per night → ~100 candidates investigated, ~35 surviving refutation.**
The binding constraint is **candidate yield, not tokens**: 76% of the night produces 50
candidates. R1's gate is the bottleneck.

---

## 4. The four detectors

Deterministic, model-free, over the tree-sitter index. Each emits cohorts, not findings.

| # | detector | gate | preconditions (or the lens does not run) |
|---|---|---|---|
| **1** | **missing-authz** | `GROUP BY (blueprint/router)`; sibling routes **≥80%** carrying an auth decorator or covered by a `before_request`/middleware binding, this one carrying none | ≥2 sibling handlers |
| **2** | **unscoped-query** (multi-tenancy) | **Discriminator predicate first:** a `tenant_id\|org_id\|account_id\|workspace_id\|owner_id\|team_id\|project_id` field on **≥3 models**, a base class carrying one, or an RLS policy in migrations. No discriminator ⇒ **not multi-tenant ⇒ lens does not run.** Then `GROUP BY (model)`, siblings **≥80%** scoped | ≥3 models with a discriminator |
| **3** | **non-idempotent-mutation** (state machine) | `mutations` table: ORM/SQL writes and in-place updates of fields matching `balance\|amount\|quantity\|stock\|refund\|status\|role\|quota\|remaining\|attempts`, reachable from a **non-GET** entry point, with a **read-then-write** AST shape. `GROUP BY (model_or_table)` on `select_for_update` / `transaction.atomic` / `FOR UPDATE` / advisory or Redis lock / idempotency-key unique constraint / conditional `UPDATE … WHERE status='pending'`. Siblings **≥60%** guarded | persistence detected; ≥1 mutating non-GET entry point; ≥2 sibling handlers on the same model |
| **4** | **sanitizer-validity** | Only on flows **Opengrep already proved**. No population needed — the engine supplies the path; the model judges whether the node on it actually sanitises | interfile/intrafile taint output present |

**Ship-first freebie:** detector 2 has a sub-gate needing no population and no model —
*filter is exactly the primary key, key derives from a request parameter, model carries a
discriminator, discriminator absent*. Textbook IDOR, pure AST.

**60% not 80% for detector 3**, because transaction usage is more heterogeneous than auth
decoration, and it should be calibrated rather than asserted.

**Scored prediction, on record (Seat 1):** `business-logic` yields <5 candidates and 0
confirmations on the current target population; `trust-boundary` fires only on the 2–4
genuinely multi-tenant repos. If either gate fires broadly on security tooling, it is a
sweep in a gate's clothing and it dies.

---

## 5. R1 — hypothesise

**Prompt block layout, ordered for llama.cpp prefix reuse** (measured: 0.919 s → 0.044 s,
**21×**, warm output bit-identical to cold):

| block | tokens | varies |
|---|---:|---|
| 0 system + lens mandate + output schema | ~800 | never |
| 1 repo card from R0 (framework, auth mechanism, entry-point table, known sanitizers) | ~2,000 | per repo |
| 2 few-shot, 3 exemplars for this lens | ~1,200 | per (lens, repo) |
| — **cache boundary** — | | |
| 3 unit under judgement: one symbol + decorators + imports + enclosing header chain | ≤1,800 | every call |
| 4 question + schema reminder | ~150 | never |

**Queue ordering is the mechanism, not the prompt.** ollama reuse is longest-common-prefix
against *that slot's previous prompt* — no TTL, no `cache_control`, as many live prefixes as
`OLLAMA_NUM_PARALLEL`. So: **sort the queue so calls sharing a prefix run consecutively;
one lens per slot; never interleave lenses or repos.** One `{run_id}` in the system block
costs 4k × 20k calls = 80M PTE = **63 hours**. There is no 90% cache discount locally — a
miss is a 100% recharge.

Overlap between units is **structural, not lexical**: carry imports and the header chain,
never a 20% token window. Never split a symbol; oversize bodies go to a separate 6k pass
tagged `long_context` so degradation is measurable per bucket. Never batch small symbols —
the cached prefix is what makes one call per symbol affordable, and that *is* "passes, not
context."

**Run `quote-verify` at R1's output**, not after twenty wasted R2 turns.

---

## 6. R2 — investigate

**Tool surface: three read-only verbs, and nothing else exists.**

```python
ROOT   = RUNDIR / "src"      # NOT RUNDIR — quarantine/ holds the suppression reason
                             # strings D14 says no model may ever see
VERBS  = {"read_symbol", "grep", "list_symbols", "done"}
LIMITS = dict(turns=10, soft_turns=6, tool_bytes=120_000, turn_bytes=32_768,
              span=400, pattern=200, grep_hits=200, ctx=24_576, wall_s=180)
```

`read_symbol` reads **D15 evidence blobs, not the clone**. **596 files fit in 32k because R2
never sees files** — it navigates an index that lives in the cached prefix and reads
±40-line windows.

**Stop conditions:** terminal verdict · budget exhausted (⇒ `unresolved`, **never**
`exploitable`) · no tool call · two identical consecutive calls · context ceiling · wall
clock. **Never compact** — compaction rewrites the prefix and forfeits the 21×; terminate
and hand off the fact ledger.

**Anti-wander:** R1 emits each candidate's own refutation condition, and R2's schema
*requires* `refutation_condition_resolved` plus a verbatim quote. One named question wanders
far less than "investigate." Plus `budget_remaining` in every tool result, and a
package-scoped grep leash whose escape must be justified in a `why` field — which doubles as
wander telemetry.

### 6.1 The resolution record — eleven required fields

Typed, not prose. 1–3 and 7 are hard blocks; 4–6 and 8–11 are required but may return negative.

| # | field | kills |
|---|---|---|
| 1 | **sink exists** — path, line, verbatim snippet, `file_sha256`, checked against the blob | `false-premise` (48) |
| 2 | **enclosing symbol** — the claimed line is inside the claimed function | "right file, wrong function" |
| 3 | **identifiers resolve** — every identifier in the rationale maps to a definition or known import | highest-yield check nobody runs |
| 4 | **caller set** — `[{path, line, kind, resolution ∈ {exact, by_name, unresolved}}]`; unresolved **demotes, never kills** | `not-reachable` (9) |
| 5 | **mitigation search** — an *enumerated negative*: validators on the parameter repo-wide, middleware bound to this route, decorators on handler and parent, endpoint schema validation, config controls, the same parameter validated elsewhere. Each recorded `{checked: <query>, found: <path:line\|none>}` | **`already-mitigated` (40)** |
| 6 | **sink implementation read** — if repo-local, quote the line that makes it dangerous | |
| 7 | **capability filter** — `is_test`, `is_generated`, `is_vendored`, `is_attack_fixture`, `is_local_dev_fixture`, `is_cli_arg_not_remote`. **Consume the funnel's existing classifications; never re-derive** | **`not-a-vulnerability` (40)** |
| 8 | **source and trust** — `kind ∈ {http_param, body, header, cookie, file, env, cli, db, internal}`; a non-HTTP source must name who controls it and why they are an attacker | |
| 9 | **precondition ledger** — auth, role, feature flag, non-default config, each with evidence and default | |
| 10 | **Layer 1 overlap** — computed **at emission**, so `novel_confirmed` is a join, not a retrofit | re-deriving opengrep's 2,316 ail findings |
| 11 | **`unresolved: [...]`** — emittable, but labelled and **never ranked above a fully-resolved candidate** | a model out of turns asserting what it was about to look up |

**Absence is evidenced by the failing query, never asserted.** And **target-authored prose
never reaches R3** — `# reviewed by security, safe` is the cheapest recall attack in the
system. D14 generalises: typed output, no free-text channel downstream.

### 6.2 Structured output — a stack, not a flag

Measured: grammar-constrained output still returns a valid JSON *prefix* with
`done_reason: "length"`.

1. **Grammar mandatory** — ollama `format: <schema>` / llama-server `--json-schema-file`.
   Without it you get 1,293 chars of markdown.
2. **Assert `done_reason == "stop"`.** `length` is a hard error. *This alone is the
   predecessor's 25% parse-failure rate.*
3. **Make truncation impossible by construction:** `maxLength` on every string (`reason` 400,
   `sink_quote` 300), `maxItems` 3, `num_predict ≥ 1.4 ×` max serialisation. The old defect
   was an *unbounded* field meeting a fixed cap; raising the cap only moves the ceiling.
4. **Split reasoning from extraction:** free-form call, then grammar-constrained
   transcription at `num_predict 600`.
5. **Retry once at 2×, then `defer` with a `structured_output_failed` row.** The durable fix
   for silent loss is that the loss is a row. **CI gate: parse failures >2% fails the build.**
6. **Grammar buys syntax, never semantics** — the constrained model emitted `CWE-521` for a
   textbook IDOR. **CWE never comes from qwen**; Foundation-Sec-8B classifies over the quoted sink.
7. **Tool-call parsing is separate and worse** — ollama scrapes qwen3-coder tool calls by
   template, not grammar, so a malformed call degrades to prose and the no-tool-call stop
   catches it *safely but silently*. Count `malformed_tool_call`; above 5%, drop tools for
   scripted three-step retrieval (grep symbol → read definition → read caller), also 3× faster.

**Sampling defaults are not neutral:** `qwen3-coder:30b` ships `temperature 0.7, top_k 20,
top_p 0.8`; `gpt-oss:20b` ships `temperature 1`. Omitted options silently use these.

---

## 7. R3 — refute, and the self-refinement ban

The invariant, stated precisely: **no model output re-enters the same family without an
intervening external observation.** R2's tool loop is legal — tool results are observations.
Four things are not, and each gets a test:

1. **Nudge turns.** A turn with no tool call, answered by a harness "continue," *is* the
   banned loop. R2 must be tool-forced.
2. **Wave re-seeding** is external feedback only if seed rows carry provenance
   `r4_deterministic`, `r3_crossfamily`, or `human`. Reseeding on wave 1's own hypotheses is
   self-refinement with a 24-hour delay; **latency launders nothing.**
3. **The few-shot bank.** The 162 Opus verdicts are external. The proposal's "reaches n=285
   by running" closes the loop the moment Layer 2R's own outputs are appended.
4. **Silent family collapse.** `except: fall back to qwen` when gpt-oss is unloaded converts
   refutation into self-critique with no diff. **R3 gets no fallback: unavailable ⇒ `defer`.**

`tests/test_no_self_refinement.py`, in the shape of the paid-model tripwire:

```python
def test_every_pipeline_crosses_families()          # the registry, not just today's default
def test_every_model_id_declares_a_family()         # undeclared id fails the build
def test_refuter_has_no_fallback()                  # AST: no hunter-family literal in r3.py
def test_no_nudge_string_in_the_prompt_corpus()     # "reconsider", "are you sure", ...
def test_a_turn_without_a_tool_call_terminates()
def test_seed_and_fewshot_admit_external_provenance_only()
def test_only_transcription_is_self_referential()   # whitelist = {"r2.extract_verdict"}
```

---

## 8. Containment — three processes, clause (v)

| process | tier | holds | opens a clone path | socket |
|---|---|---|---|---|
| `omni-r2-exec` | 1 (`tier1.sb`, `deny network*`) | nothing | **yes — the only one** | none; inherited fd only |
| `omni-r2-broker` | 0, no credential | budget, transcript, validator | never | two inherited fds |
| `omni-infer` | 0, native Metal | the ollama socket | never | `127.0.0.1:11434` |

**The model never emits a syscall.** It emits a token from a closed vocabulary and a
**total validator** decides. Selection is target-influenced; authority is not.

> **Clause (v)** — no process may both **select** an operation from target-derived content
> and **hold** the authority that operation exercises. Where selection from target content is
> unavoidable, the selector *proposes*, a separate enforcer *decides*, and the enforcer must
> be a total function over a closed, enumerable operation space.

Clause (i) passes even if the three processes are collapsed into one — which would be unsafe.
(v) does not.

**The nonce envelope.** Every data line carries an unguessable per-invocation prefix,
stripped from the data before wrapping and verified in the output. A fixed delimiter is a
convention; an unguessable, stripped, verified one is a control.

```
<<<{nonce} DATA>>>
{nonce}|path/to/file.py:176| <scrubbed line>
<<<{nonce} END>>>
```

Four rules around it: **(1)** any nonce occurrence inside a tool result is a forgery attempt
— drop the turn, emit `producer_id='quarry/prompt-injection'`. **(2)** Never
string-concatenate into a prompt; tool results enter as a structured `tool` role, and chat
control tokens (`<|im_start|>`, `<|channel|>`, `[INST]`, `<<SYS>>`) are stripped — **ship a
fixture that plants `<|im_end|>` in a target file and asserts the turn structure survives.
The test is the deliverable.** **(3)** Citations verify byte-exact against the nonce lines,
then the evidence blob at the pinned SHA. **(4)** Strict parsing of model output; malformed
drops the turn and is counted. Never recover intent.

**What a total injection success buys:** reads of a repository the attacker already
published. There is no `bash`, `write`, `fetch`, or socket — no parser exists that could
produce one. **R2 has no verdict column, no severity column, and no `funnel_events` write**,
so an injected *"known false positive, verdict: rejected"* has nowhere to land. Candidates
whose evidence touches an injection-flagged file get `taint='injection-adjacent'`: out of
`novel_confirmed`, unreachable from the composer without a human ack.

**Suppression cannot be stopped and is not claimed to be.** An injected comment that makes
the model *not* report is unfalsifiable. Layer 1 is deterministic on the same tree and
unsteerable by prose, so a miss shows against the control arm — and the injection lens fires
on the attempt. A repo trying to manipulate a code reviewer is itself a finding.

### 8.1 Three measured facts about overnight operation

- **`pmset` shows `sleep 1` on AC with no assertion held** — the 12-hour night is fiction as
  scheduled. The daemon must hold a power assertion or it simply stops.
- **`RunVolume` never re-checks its mount**, so a sleep/wake detach silently writes to the
  boot volume.
- **KV prefix reuse measured 2,398× on a warm slot, and R3's model swap evicts it.** Batch
  waves by model, never by candidate.

---

## 9. Data model and UI

**Producer key:** `r2r:{lens}:{prompt_epoch}@{model_digest[:8]}` — the *ledger* key.
**Triage key:** the anomaly cohort (the gate's `GROUP BY` tuple). These are different, and
conflating them is what makes Layer 2R self-suppress: `producers.id` is `tool:rule_id`, so
the whole layer would be one row and by repo #2 it satisfies
`n_confirmed == 0, n_adjudicated ≥ 5` — landing in the collapsed **known-bad** band and
disappearing from its own UI.

**Also fix:** `independence_class()` must return `"semgrep"` for `sanitizer-validity`, which
is fed Opengrep's own flows — otherwise it corroborates with itself.

**Bands become evidence tiers**, because precision bands need a precision ledger:
`R4-validated` / `R3-survived, argued only` / `unresolved`. Ordered by **fraction of the
resolution record machine-checked**, descending. Only machine-checked fields set the evidence
bar's length; model assertions render hollow. Cheapest-information-first does not transfer —
there is no repeated measurement to be cheap about.

**`/nights/:date`** — a night's report, not a session. Capped at ten. Leads with
**refutation**: `96 → 61 → 35 → 6`, every arrow opening its killed set. "35 survived" alone
is a laundering headline. Operator-minutes appear *before* the work as an offer and after as
the actual. **Zero is a first-class, non-apologetic screen** — most mornings are zero, and a
zero reads as "no result," never a kill or a pass. One notification, at wake. Never at 3am.

**Queue length is a bug report, not a workload.** Overflow renders as an incident:
*"29 held. R3 and R4 did not reduce this to a coffee. That is a defect in the filters."*

The detail view renders the **eleven-field resolution record, not the agent transcript** —
twenty turns is the "seven essays" problem with twenty essays. The mitigation row shows its
six queries, because an enumerated negative is evidence and a conclusion is not.

---

## 10. Disclosure gating

**The floor for a model-generated logic finding — five slots, all filled from resolved
symbols in the R0 index, never from model prose:**

1. **Entry point** reachable from an untrusted source, resolved in the index
2. **Principal** — a named authorization subject the code compares or fails to. A "leak" with
   no second principal is a feature.
3. **Path** — every hop resolves to a real symbol at a real line at the pinned SHA. **Zero
   unresolved hops.**
4. **Absent control, absent everywhere** — grep for the guard's identifiers, zero hits on the
   path. **Run without a model, because R2's output is the thing under suspicion.**
5. **In-repo counterexample** — the codebase does it right elsewhere. A logic claim with no
   counterexample in the project's own code is a design opinion, and design opinions are not
   security reports.

> **A model-generated logic finding may be drafted only if a program that cannot read English
> can verify every structural claim in it.** Any slot unfilled ⇒ local lead.

**The channel gates the composer.** Measured: of 36 repos matching the shipped scorer's
profile, **26 (72%) have neither `SECURITY.md` nor PVR** — versus 2 of 10 in the
Qwythos-like stratum. Therefore:

> When the producer is a Layer 2R lens and the resolved channel is `CONTACT_REQUEST_ISSUE`
> or `COORDINATOR`, **no document is generated. Local lead only. No flag, no override.**

D2 stands untouched — scoring targets on channel begs the question in the other direction.
Layer 1 keeps its patch-note path there: a deterministic rule with a ledger and a twenty-line
diff belongs in a PR, and a PR needs no channel. **The higher a producer's base error rate,
the higher its bar for the channel.**

**Drafts auto-expire at 30 days.** Thirty well-written, mostly-wrong reports about strangers'
projects are one `git add .` from publication.

**Required provenance**, beyond Layer 1's `Detected by <tool> <version> rule <rule-id>`: a
fixed unattended-model opening line; model + quant per stage; **the 14% literature base rate
stated before the finding is argued**; and "did not execute, did not stand up, did not test."
**New banned strings:** `AI-verified`, `consensus`, `multi-agent`, `high confidence`, any
`confidence: 0.87`-style number — and **`novel`**.

**Ship the null report.** Nobody has ever sent a two-person project *"we read all 596 files
overnight; the authorization surface is clean; here are the 12 routes we checked and the 3 we
could not resolve."* Free, harmless, needs no channel, impossible for Layer 1, and the best
disclosure-side use of free overnight inference.

---

## 11. Measurement — pre-registered, committed before the first night

**Per amendment A5, Leg B is deferred entirely until Leg A reports** — if Layer 2R recovers
0 of 20 plants there is nothing to adjudicate. That defers the whole calibration apparatus
with it, so **operator-hours to first result are zero.** The Leg A corpus is ten curated OSS
applications, selected by measuring the detector preconditions: [`LEGA-CORPUS.md`](LEGA-CORPUS.md).

```
LEG A — planted control (free, no human, runs first)
  10 repos × (1 reverted CVE fix + 1 injected cross-file authz bug) = 20 plants.
  ABANDON if Layer 2R recovers 0 of 20.        P(0 | recall 15%) = 3.9%
  Cost: 10 nights, 0 operator-hours.

LEG B — the wild question
  METRIC  novel_reproduced := (i) no Layer 1 producer emitted the same finding_id
          AND (ii) survived R3+R4 AND (iii) Jerry reproduced it against a running
          instance and wrote the deciding fact in free text.
          Model agreement is never a confirmation.
  N       40 completed repos.                  P(0 | λ=0.071) = 5.8%
  ABANDON novel_reproduced == 0 at N=40.
  BUDGET  hard cap 40 operator-adjudication-hours, from night 1, in the ledger.
  NO RESULT if <40 repos completed or <25 candidates adjudicated — never a kill,
          never a pass.
  TRIPWIRE after 10 repos, if candidates reaching adjudication >25/repo, halt and
          fix R3/R4.
  ADJUDICATOR Jerry, blind to stage and lens, pooled and randomised against Layer 1
          candidates, deciding fact required, abstention recorded.
          gpt-oss:20b is INELIGIBLE as second rater — it is R3.
  OVERRIDE permitted only as a written, dated amendment in the panel file.
```

**N=20 was wrong:** P(0 in 20 | λ = 0.071, the predecessor's own rate) = **24.2%** — a
one-in-four chance of killing a Layer 2R that merely matches what it replaces.

**Report a triple, always:** `(novel_confirmed_reportable, candidates_emitted,
operator_minutes)`. `novel_confirmed` alone has no denominator and is gamed upward by volume.
Add **`recall_on_planted` per arm per lens every run** — the precision family structurally
cannot see a false negative. Add **`candidates_per_confirmed` per lens with a pre-committed
disable rule: 0 in 60 disables that lens**, reversibly, with a ledger row. "0 after 20 repos,
stop" kills the whole layer and lets one good lens die with three bad ones.

**Measure R3's false-kill rate before believing its true-kill rate.**

**Two determinism gates**, because "run the same lens twice" returns 0 by construction at
`T=0` (measured: bit-identical across 3 serial runs, 8 concurrent, cold vs warm cache):

- **G1 — harness reproducibility. Required flip rate: exactly 0.** Same SHA, index hash,
  model digest, ollama version, `T=0, top_k=1, fixed seed, explicit num_ctx`. Any flip is
  *our* bug. ~40 min, nightly. Likeliest culprit: ollama's default `num_ctx` is chosen from
  available VRAM, so the same prompt truncates differently depending on what else is loaded.
  Pin it and assert `prompt_eval_count < num_ctx` — a prompt that hit the ceiling is a
  dropped-evidence event, not a verdict.
- **G2 — semantic stability.** Perturb what should not matter: 5 seeds at `T=0.2`, permuted
  entry-point and exemplar order. Thresholds >15% stop / 5–15% record as floor / <5% proceed.

### 11.1 Under free-only (amendment A1) — resolved

The principal ruled free-only everywhere, including the harness. Seat 6 **withdrew the
dissent** and withdrew "unmeasurable" as their own error: *"that conflated no second rater
with no instrument. Leg A has no rater at all. Leg B is measurable single-rater."* They also
withdrew their own second-rater condition — *"a κ says two raters agree, not that they are
right; a confusion matrix against known items is better evidence and it is free."*

**Leg A is promoted to the headline instrument** (zero raters, ground truth by construction).
It may never report bare recall — always paired with candidates/repo, or a lens that flags
everything scores 20/20. Floor 20 plants, target 60. Prefer guard *deletion* to injection,
pre-flight every plant by program, and **scrub the git history — the commit message is the
answer key.**

**Leg B survives single-rater**, with the decoy bank as the free substitute for independent
calibration. Measured on disk: **124 usable decoys, not 48** (`false-premise` 46,
`not-a-vulnerability` 39, `already-mitigated` 39) — three types, because false-premise only
catches not-reading. **k = 18 (6/6/6)** gives 85/95/98% power against a 10/15/20%
false-confirm rate. **"Nonzero voids" is withdrawn** — at k=18 a 2%-accurate rater trips it
30% of the time. Graduated: any false-premise confirmation voids; two mitigation/capability
confirmations void; one is reported as the measured floor. **8 repeat pairs** catch
within-study drift; **6 Leg A plants routed in as known positives** guard against
over-rejection. Total calibration load **32 items, ~4.3 h, 10.7% of the cap**, billed to the
ledger.

**Known limitation, stated plainly:** there is no independent calibration of the adjudicator
on *natural* findings. The decoys measure accuracy against items whose ground truth was
established by a paid model in a prior campaign; the repeat pairs measure consistency. Neither
measures whether the adjudicator is systematically wrong in the same direction on findings
nobody has labelled. That is the price of free-only, and it is the whole price.

**Report `N_eligible`, never bare `N`** — see A4.

---

## 12. Build order

**Two blocking prerequisites, both free, both before any night runs:**

| # | task | why it blocks |
|---|---|---|
| **P1** | **Enable Opengrep `--taint-interfile`** (`1.28.0-interfile.alpha.2`, opt-in, recorded in `tools.lock.json`, never default, runs labelled) | **It defines the control arm.** Every novelty number computed before it lands is inflated by construction. Two hours on Nettacker and repo C, both already scanned. |
| **P2** | **Measure anomaly-cohort size on the repo C replay** | *"If cohorts are 1:1, Layer 2R has no triage model and the honest product is a digest the operator reads and closes."* One afternoon, $0, and it decides whether §9's UI is worth building. |

Then:

| phase | work |
|---|---|
| **R-0** | tree-sitter index promoted to a **Layer 1 deliverable** (every gate depends on it, and it earns its keep even if all four lenses die). Detector 1 + detector 2's no-population IDOR sub-gate. Both model-free. |
| **R-1** | R0 comprehension pass + repo card. Prompt corpus vendored and adapted; few-shot bank from the 162 Opus verdicts (**note: 2 usable positives, not 4** — two of the "confirmed" are the non-reportable dev fixtures). |
| **R-2** | R1 sweep with the block layout and queue ordering. G1 determinism gate — **flip rate must be 0 before any G2 number is believed.** |
| **R-3** | R2 agentic loop, three-process split, nonce envelope, `<\|im_end\|>` fixture test. **This lands before R2 reads a real target.** |
| **R-4** | R3 cross-family refutation + `test_no_self_refinement.py`. R4 deterministic validation. |
| **R-5** | Overnight daemon with a power assertion and mount re-check. `/nights/:date`. |
| **R-6** | Leg A planted-bug control over [`LEGA-CORPUS.md`](LEGA-CORPUS.md) — 10 nights, zero operator-hours. **Fix detector 3's `DeclarativeBase` gap first** — the current pattern set silently disables the lens on every modern SQLAlchemy codebase. |
| **R-7** | Detectors 3 and 4, if Leg A cleared. Re-entry test for the four deferred lenses, as **planted-bug recall**, not a novel-finding hunt. |

**Cheaper than the whole re-entry test and worth more (Seat 1):** run the two surviving
lenses **with and without R2**. If R2 grounding is the lift, that is the finding, and it
generalises.

---

## 13. What we are deliberately not building

- **Ungated hunting.** No cohort ⇒ no queue, no ledger, no composer. It writes to a file.
- **A self-critique loop.** Banned architecturally and by test.
- **Model-assigned CWE.** Foundation-Sec-8B over the quoted sink, or nothing.
- **A confidence score.** A self-report from a 14%-TP instrument. Banned from the UI outright.
- **An agent transcript view.** The typed resolution record instead.
- **A composer path for Layer 2R on channel-less targets.** Three targets in four.
- **Compaction in R2.** Terminate and hand off a fact ledger.
- **Layer 2R as a pipeline stage.** Side-car, or D12's throughput target dies.
