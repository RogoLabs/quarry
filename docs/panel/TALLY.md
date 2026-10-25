# Round 2 tally — endorsements and binding conditions

| Seat | Status | Conditions / key round-2 output |
|---|---|---|
| 1 Detection Architect | **Endorse with conditions** | 5 conditions. **Dissents without #1 and #2:** (1) P2 thresholds computed against the blind human-adjudicated **union of all arms**, not the LLM-generated confirmations — as written the gate cannot fail; (2) P1c (zizmor, Scorecard, dependency-confusion) ships in P1 with `producer_id` from run one. |
| 2 LLM Systems Engineer | **Endorse with conditions** | 5 conditions. **Withdrew** the 9-arm $153 ablation and **conceded three seats down to one**. Dissent trigger: any seat shipping on argument rather than the $14 paired screen. |
| 3 Disclosure Ethicist | **Endorse with conditions** | C1 render guard before first document; C2 `local-dev-fixture` becomes a 7th free funnel class; C3 P5 default artifact is a patch note, not an advisory; C4 documents self-label `NOT REPRODUCED` and the `gh` command is withheld until reproduction fields are filled; C5 composer holds zero GitHub credentials. **Dissents from P5 shipping if C1 or C4 slip.** |
| 4 Product & UX | **Endorse with conditions** | 6 conditions; load-bearing two: (a) the cross-repo **rule-precision ledger** is named in P1, (b) **snippets land in P1** so every funnel number links to rendered code, not paths. Reverses round 1 on the reproduction gate: it now gates *generation*, and the 60s cooling period is cut. |
| 5 Platform Security | **Endorse with conditions** | 7 conditions; **no dissent**. Two non-tradeable: (1) the P0 sandbox lands *before* any scanner touches a real target; (2) secret findings stored as **prefix+hash** in the P0 schema. |
| 6 Adversarial Economist | **Endorse with conditions** | 8 conditions. **Withdrew** "the panel must not be built"; **keeps** "the panel must not be believed." **Dissents if conditions 1-2 declined:** a false measurement is worse than an honest unknown. |

## Material findings added in round 2

- **Seat 3:** verified the credential-finding repo directly. Both "confirmed" credential findings are
  **local dev fixtures** — `docker-compose.yml` sets `POSTGRES_PASSWORD` on a postgres service the same
  file starts, then reuses the string in `PG_URL`. Repo has 0 stars, 0 releases, no license, no
  SECURITY.md, PVR disabled, not published anywhere. **Not reportable.**
  → Revised true yield of the entire $27.99 / 14-repo LLM program: **2 reportable findings**
    (one missing-authz bug, one weak SECRET_KEY), of which **1 is recovered by Bandit for free**.
  → Net LLM-only, reportable yield across 14 repos: **1 finding.**
- **Seat 3's reportability test** (all three must be yes): (1) authenticates to a system the reporter
  did not instantiate; (2) artifact is on a distribution path — published package, tagged release,
  pushed image; (3) the value works somewhere the reporter does not control.

- **Seat 4 (round 2): the P1 triage unit is the RULE, not the finding.** At ~458 verdict-less
  findings per repo, a 60-second per-finding decision is the wrong operation — the decision does not
  vary within a rule. `/triage` groups by producer by default. Sort into three bands:
  **known-good** (`rule_precision.confirmed > 0`) / **unmeasured** (`n < 5`, ordered by corroboration
  then occurrence count *ascending* — cheapest-measurement-first) / **known-bad**
  (`confirmed == 0, n >= 5`, collapsed). Never severity. `D` dismisses a producer corpus-wide and
  writes the ledger; `d` is repo-local. DefectDojo's 458 occurrences collapse to ~60-90 producer ids:
  ~20-30 min on repo #1, under 10 min by repo #3.
  → This is the mechanism by which the deterministic layer *improves over time*, and it is the answer
    to "why is this better than a SARIF viewer": a viewer has no memory across runs.
- **Seat 4 + Seat 5 resolved on the code pane:** extract a +/-40-line snippet at ingest inside the
  sandbox, for every occurrence including suppressed ones. zstd ~1.2 KB each -> ~550 KB per repo,
  ~22 MB at 18,431 findings. Volume scales with finding count, not repo size, so a 2 GB target costs
  single-digit MB. Re-hydrate from the pinned SHA when the clone is gone; fail loudly on
  `file_sha256` mismatch. **Seat 4 closes a hole in Seat 5's own control:** a snippet window around a
  Gitleaks hit contains the secret, so the extractor must run the redactor at the same boundary.

- **Seat 2 (round 2): the seat-screen can only CUT seats, never promote them.** Reconciles with
  Seat 6's power analysis by noting they answer different questions: Seat 6 computes a *between-arms
  two-proportion test on precision* (n~869 for a doubling at a 2.56% base rate, correct); a
  chair-replay measures *within-subject paired verdict flip rate*, where n=162 gives ~24 discordant
  pairs and power ~1.0 against H0 "<=2% of verdicts move". The clinching argument is Seat 6's own:
  `debate.py`'s **0 flips at n=39 was treated as conclusive, and it was** — you cannot hold both
  "n=39 proved a round inert" and "n=162 cannot measure a seat."
  → Asymmetric rule adopted: **flip ~= 0 -> provably inert -> cut** (decisive, $13.77/candidate).
    **flip > 0 -> does something, but whether it is *correct* needs n>=285 -> unaffordable -> does not
    ship**, and enters a deferred precision queue.
  → The naive-skeptic seat is **withdrawn by its own author**: with sampling parameters removed on
    Opus 5 / Sonnet 5, a claim-only seat is the same model with strictly less information.
- **Seat 2 (round 2): corrected cost accounting, recomputed from disk.** The corpus actually cost
  **$0.1728/finding**; Seat 6's $0.0744 is the *post-caching marginal* figure (correct
  forward-looking, but must be labelled as such). Post-caching the spend is **54% cache writes /
  36% output / 10% reads** — uncached input fell 2.17M -> **180 tokens**. Cache hit ratio **69.9%**.
- **Seat 2 (round 2): the single seat, specified.** `claude-opus-5`, effort `high`, adaptive thinking,
  read/grep/glob rooted at the clone, **no bash/write/network**, 24 iterations. **Four** cache
  breakpoints: tools (sorted-key JSON) -> system (1h TTL) -> **new per-repo preamble block (3-8k
  tokens, identical for every finding in the repo)** -> rolling conversation. Keep
  `output_format=FileVerdicts`; add `stop_reason` logging and a typed retry on
  `parsed_output is None`. Projected **$0.051-0.061/finding** with the preamble breakpoint.
  Two-run flip gate: >15% stop / 5-15% record as the floor / <5% proceed (~$16).
- **Seat 2 (round 2): P2 needs an A1' arm** — a second identical single-seat run (+$8-16) — because
  Seat 6's "<10% flip" threshold assumes the incumbent is deterministic and it is not. Every flip
  threshold must be relative to the *measured* self-flip floor.

- **Seat 1 (round 2): the minimum LLM sweep is ONE gated lens.** The four dead lenses
  (`injection`, `path-file`, `ssrf-network`, `deserialization`) all ask a **source -> sink -> path**
  question, which is the definition of what a taint engine computes — cross-function on stable
  Opengrep `1.27.1`, cross-file in the `1.28.0-interfile.alpha.2` pre-release. Condemned from two
  independent directions: Seat 6's empirical 0-for-72 and the formalism itself. They were asking a
  quantized model to approximate dataflow analysis by reading.
  What survives are the two questions with **no source and no sink**:
  1. **"Does this route need authorization?"** — the *absence* of a call that ought to be there is
     outside the taint formalism entirely; no engine maturity closes it; and it is the class that
     produced the single LLM-only confirmation in 14 repos.
  2. **"Is this node on a proven path actually a sanitizer?"** — the engine believes `escape_html()`
     sanitizes because a rule author said so, and cannot tell that *this* repo's `sanitize()` just
     calls `.strip()`.
  Gate for lens 1 is deterministic and cheap: an entry point whose sibling routes are >=80%
  auth-guarded and which carries none. That is a `GROUP BY`; it yields **5-30 anomalies on a
  200-route repo (~10 min, not 6-20 h)**, and it is the shape of the corpus's one LLM-only finding.
  → **Action: replay that gate against repo C before P3.** One afternoon, $0. It either
    validates the last surviving lens or kills it.
  → Second-order effect: interfile taint cannibalizes the *reachability attacker seat*, not just a lens.
- **Seat 1 (round 2): ruling on the target's own config — three classes.**
  1. **Loader-capable config** (`.checkov.y*ml`, `.semgrep*`, `.trivy.yaml`, `.gitleaks.toml`,
     `.bandit`): **quarantined, never loaded**, enforced in the spawn wrapper — every one of these
     auto-discovers from cwd.
  2. **Non-executable suppressions** (`# nosec`, `.trivyignore`, `.semgrepignore`): **parsed, never
     obeyed.** Scan as if absent, attach as metadata. Reason present and >90 days old -> `defer`
     (never kill, per D8). No reason / blanket path scope / **added in the same commit as the code it
     suppresses** -> rank **up**.
  3. **Suppression reason strings never reach a model** — that is the cheapest verdict-suppression
     attack in Seat 5's table.
  Ruled **against** `suppression-present` as a finding class: one `suppression-posture` row per run
  with drill-down. Django and Ansible carry hundreds of legitimate `# noqa`.
- **Seat 6 (round 2): the chair was over-correcting, by Seat 6's own admission.**
  P2 as adopted yields ~222 findings — **less power than the 162-finding corpus Seat 6 disqualified.**
  Expected yield 4.3 confirmed; **P(fewer than 3) = 20%**, so one run in five kills the LLM layer
  through sampling noise alone. "Flips <10%" is not a significance test.
  More important: **`debate.py` is same-model self-review** — the configuration Refute-or-Promote
  already reports as failing. All 162 verdicts come from one Opus call, so **the corpus contains zero
  observations of a panel**, and correlated error is by construction invisible to the model that made
  it. Seat 6: "I used evidence against the weakest form to kill the strongest."
  → **Revised D3:** one seat is the default; the panel ships **behind a flag labelled
    `unmeasured, 3-8x cost`**, and **no measurement is claimed in either direction.**
  → Seat 6 also flags the confidence interval the chair omitted: "free tools recover 3 of 4" is
    **n=4, 95% CI [30%, 95%]**. The headline must carry the interval.
  → And corrects its own under-pricing of that finding: at 0.071 authz findings/repo, break-even
    LLM spend is **$7.14/repo even at V=$100**, against a **measured $2.00/repo**. *The single Opus
    call is a good trade. The panel at $12-36/repo is not.*
- **Seat 6 (round 2): throughput is the strategy.** At a ~7% hit rate, Layer 1 runs **~2,400
  repos/day**; Layer 2 as scoped runs **1-4**. That is **617-5,349x**, and it makes D2 (target
  selection) unimplementable if it sits behind Layer 2.
  → **Replace the binary GO/NO-GO gate with a throughput target: P1 scans 100 repos overnight.**
    That does the gate's work as arithmetic rather than as an underpowered hypothesis test.
  → Promote **P1b -> P1a**. Retire the phrase "GO/NO-GO gate" for **"calibration run."**
- **Seat 6 (round 2): hardened P2 protocol.** Planted-bug control in 5 repos (the only arm-independent
  recall denominator); A2 = Opus + a **cross-family** critic or drop it, since three same-family seats
  is the pre-refuted configuration; U-stratum selected on attack surface / dependents / responsiveness
  **only** — "no SECURITY.md, no CodeQL" begs the question and guarantees A0 wins, so record scanning
  presence as a **covariate**; replace the 6 P-stratum repos Jerry has already read; pool and randomize
  across all 20, strip arm labels, require a free-text deciding fact; **commit thresholds to git before
  the first clone**; 20% second rater for inter-rater agreement.

- **Seat 5 (round 2): container runtime = Colima, and it is NOT a P0 blocker.** Revised from their
  round-1 lean toward Apple `container(1)`: more elegant on macOS 26 (per-container VM, sub-second
  start) but not installed, untestable here, narrow OCI ecosystem, and the stage that needs it
  (CodeQL, P3+) is the worst place to run a research project. `docker` 29.7.2 is already present, so
  `brew install colima && colima start --vm-type=vz --cpu 4 --memory 8 --disk 60` works with zero code
  change. Cost: 8 GB reserved *while running* (stop it after the stage), 60 GB sparse, ~25 s cold
  start, 2-5x small-file IO in-guest.
  → **Every P1 tool is covered by `sandbox-exec`.** Colima is a P3/P5 dependency only.
  → Ruling requested and granted: **Checkov ships in P1 under Tier 1 with external modules and custom
    policies OFF** — with those off it is a parser; with either on it moves to P3.
- **Seat 5 (round 2): D6 corrected — containment is ~1 developer-day in P0**, not a runtime install.
  This preserves Seat 6's ~333-repo break-even. Also: **§4's "nothing runs unsandboxed, ever" is
  unachievable** (Metal inference cannot be sandboxed); the correct invariant is
  **"nothing that *reads target bytes* runs unsandboxed."**
- **Seat 5 (round 2): D10's MoE is faster, not smaller** — budget Layer 2 at **24-28 GB**, more than
  a dense 27B.
- **Seat 5 (round 2): new threat created by the chair's own D2** — target selection points the tool at
  unaudited, low-attention repositories, which is precisely where a deliberately hostile repo sits.
  Adversarial-input risk goes *up* as a direct consequence of the highest-ROI product decision.
- **Seat 5 + Seat 4 resolved on the code pane: evidence blobs, not clones.** At the taint boundary,
  persist per occurrence (killed ones included, per D8) the enclosing symbol +/-40 lines,
  content-addressed and deduped, plus file and commit SHAs. Seat 4's 18,431-occurrence run ->
  ~8,000 unique windows -> **~32 MB raw / ~9 MB gzipped**; a 2 GB target produces the same ~40 MB,
  because evidence scales with finding count, not repo size. Three pane states, never blank:
  live file -> stored window with `clone released - sha256 verified` + re-materialise button ->
  honest failure. The verbatim quote check keeps working against the blob, so evidence-weight zeroing
  and the sink marker survive deletion of the clone.

---

## Outcome

**6 of 6 endorse with conditions. 0 dissents. 3 dissent triggers, all recorded in the final plan:**

- **Seat 1** dissents if P2 thresholds are not computed against a blind human-adjudicated union of all
  arms, or if P1c (zizmor, Scorecard, dependency-confusion) does not ship in P1.
- **Seat 3** dissents from P5 shipping if the render guard (C1) or the self-labelling +
  withheld-`gh`-command rule (C4) slips.
- **Seat 6** dissents if the calibration run is presented as a measurement.
