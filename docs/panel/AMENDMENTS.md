# Amendments — principal's decisions on ratified rulings

Seat 6, round 3: *"The principal may overrule the rule; he may not overrule it silently."*
This file is the non-silent form. Dated, written, and linked from the plan.

---

## A1 — 2026-08-23 · Free-only applies to the eval harness as well as the product

**Ruled by:** Jerry Gamblin (principal)
**Overrules:** the chair's position in `00-chair-layer2r.md` §L15, that
`tests/test_no_paid_models.py` guards the shipped pipeline only and a paid second rater
would be permissible offline for a pre-registered experiment.

**The decision:** no paid model, anywhere. Not in a run, not in a report, not in the
measurement harness.

**Seat 6 said they would dissent on day one.** Asked to specify the best protocol
achievable under the constraint instead, they **withdrew the dissent** and withdrew the
word "unmeasurable" as their own error:

> *"'Unmeasurable' conflated no second rater with no instrument. Leg A has no rater at
> all. Leg B is measurable single-rater. The loss is narrower and nameable: independent
> calibration of the adjudicator on natural findings."*

They also withdrew their own round-2 second-rater condition as the wrong ask:

> *"A κ says two raters agree, not that they are right, and this panel's own OpenSSL
> precedent settles that. A confusion matrix against known items is better evidence and
> it is free."*

**Consequences, all adopted:**

1. **Leg A (planted bugs) is promoted to the headline instrument.** Zero raters, zero
   dollars, ground truth by construction. Condition: it may never report bare recall —
   always paired with candidates/repo, or a lens that flags everything scores 20/20.
   Floor 20 plants, target 60. Prefer guard *deletion* to injection; harvest one class
   from OSV; pre-flight every plant by program; **scrub the git history, because the
   commit message is the answer key.**
2. **Leg B survives, single-rater.** Jerry adjudicates. What is lost is independent
   calibration on *natural* findings.
3. **The decoy bank substitutes for a second rater, and it is bigger than we thought.**
   Measured on disk: **124 usable decoys, not 48** — `false-premise` 46,
   `not-a-vulnerability` 39, `already-mitigated` 39. Three types, because false-premise
   only catches not-reading; the other two catch the harder failure. Every label must be
   re-derivable by a program at the pinned SHA — that is what makes an Opus-labelled bank
   admissible under free-only.
4. **k = 18 decoys (6/6/6)** → 85/95/98% power against a 10/15/20% false-confirm rate.
   Seat 6 **withdrew "nonzero voids the run"**: at k=18 a 2%-accurate rater trips it 30%
   of the time. Graduated instead — **any false-premise confirmation voids; two
   mitigation/capability confirmations void; one is reported as the measured floor.**
5. **Drift is caught by 8 repeat pairs** (test–retest), not by per-block decoys. That is
   the free substitute for a second rater on adjudicator consistency.
6. **6 Leg A plants routed in as known positives** — without them the abandon condition
   has no guard against over-rejection.
7. Total calibration load: **32 items, ~4.3 h, 10.7% of the 40-hour cap.**

**Seat 6's three conditions on withdrawing the dissent, all accepted:** bill the
calibration budget to the ledger; report `N_eligible`, never bare `N`; label Stage 0
telemetry as telemetry.

---

## A2 — 2026-08-23 · Composer closes for channel-less Layer 2R findings

**Ruled by:** Jerry Gamblin. **Accepts Seat 3's ruling as written, no override.**

When the producer is a Layer 2R lens and the resolved channel is `CONTACT_REQUEST_ISSUE`
or `COORDINATOR`, no document is generated. Local lead only. On Seat 3's measurement
(26 of 36 scorer-profile repos have neither `SECURITY.md` nor PVR) this closes the
Layer 2R composer for roughly three targets in four. Layer 1 keeps its patch-note/PR
path everywhere.

---

## A3 — 2026-08-23 · Overnight runs are manual with a deadline

**Ruled by:** Jerry Gamblin.

`quarry research run --until 07:00`. Holds a power assertion only while running. No
launchd agent, no automatic nightly trigger. The machine is the operator's by default.

---

## A4 — 2026-08-23 · Own-repos-first: corrected in scope, not reversed

**Original decision:** run Leg B against `jgamblin` / `rogolabs` repos first.

**Measured against the actual detector preconditions** (24 own repos shallow-cloned and
grepped, not estimated):

| precondition | repos passing |
|---|---:|
| route handlers (detector 1) | **0 / 24** |
| any auth decorator to compare siblings against (detector 1) | **0 / 24** |
| ORM model (detector 3) | **0 / 24** |
| tenancy-shaped field (detector 2, needs ≥3 models) | 3 / 24, all CVE-data field names |

Seat 6 independently found the same thing across all 80: *"4 with any route handler,
zero `@login_required` anywhere. Three of four detectors have unsatisfiable
preconditions. N_eligible ≈ 4, so the abandon condition is unreachable and Leg B there
returns 'no result' by construction."*

The corpus is CVE and data tooling — notebooks, shell, scrapers, static sites. It is
structurally unable to exercise the detectors.

**Amended, not reversed.** Own repos are retained for what they are genuinely good at:

- **Shakedown** — the first nights, where the cost of a bug is zero.
- **A free specificity control** — expected candidates: **zero**. If the gates fire here
  anyway, that is a false-positive signal and Seat 1's scored prediction landing. This is
  a real experiment, not a consolation prize.

**Leg B needs a different corpus.** Pending the principal's decision.

*(Also flagged by Seat 6: three own repos exceed P0's 20 GB sparse-image default.)*

---

## A5 — 2026-08-23 · Leg A only; Leg B deferred

**Ruled by:** Jerry Gamblin.

Leg B (40 repos, up to 40 operator-hours of blind adjudication) is **deferred entirely**
until Leg A reports. Rationale, and it is sound: if Layer 2R recovers 0 of 20 planted bugs,
there is nothing to adjudicate.

**Consequences:**

1. **The measurement programme is now entirely free *and* entirely unattended.** Leg A has
   no rater, so the whole calibration apparatus from A1 — the 124-item decoy bank, k=18,
   the 8 repeat pairs, the 32-item / 4.3-hour load — is deferred with Leg B. Operator-hours
   to first result: **zero.**
2. The corpus is ten curated OSS applications, measured against the detector preconditions
   rather than assumed. See [`../LEGA-CORPUS.md`](../LEGA-CORPUS.md).
3. Own repos remain the shakedown corpus and the free specificity control (A4).
4. Seat 6's three conditions from A1 still bind when Leg B is eventually run.

**Known limitation to carry forward:** the corpus is 9 Django, 1 Flask, 0 FastAPI, so a
Leg A recall number measures the detectors against Django conventions and must not be
quoted as a general figure.

---

## A6 — 2026-08-23 · Docker Desktop installed; Tier 2 unblocked

**By:** Jerry Gamblin, after hitting `docker-credential-desktop: executable file not
found in $PATH` — the same error the vulndb sync worked around.

**Status change.** Seat 5's round-2 ruling picked Colima *because* no container runtime
was installed and Docker Desktop could not be tested. It now is: `docker 29.7.2`
client and server, daemon up. **Docker Desktop is the Tier 2 runtime; Colima is not
needed.** Tier 2 was only ever a P3/P5 dependency (dependency resolution, Checkov with
external modules, CodeQL extraction, PoC execution), so nothing in P0/P1 changes.

**New attack surface, checked rather than assumed.** Installing Desktop places
`docker-credential-desktop` at `/usr/local/bin` — **outside `/Users`**, so the Tier 1
profile's blanket deny does not cover the binary. Measured against a live sandbox:

| from inside Tier 1 | result |
|---|---|
| run `docker-credential-desktop list` | **denied** (rc=1, no output) |
| read `~/.docker/config.json` | **denied** |
| `docker ps` (socket) | **denied** |
| read the docker socket | **denied** |

Containment holds — but only because the config and socket the helper needs are both
under `/Users`. That is a load-bearing coincidence rather than a designed control, so
it is now asserted by `test_docker_desktop_credentials_are_unreachable` instead of
relied upon. A scanner that could run the helper could read every registry credential
on the machine.

**The `DOCKER_CONFIG` override in `vulndb.py` stays**, and its justification changes:
it began as a workaround for Desktop being absent, and it remains because pulling a
public vulnerability database needs no registry credential and therefore should not be
able to read one.
