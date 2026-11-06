# Leg A corpus — the planted-bug control

**Selected 2026-08-23.** Ten OSS applications, measured against the detector preconditions
rather than assumed. Ground truth by construction, **zero operator-hours, zero dollars.**

Per amendment [A5](panel/AMENDMENTS.md), Leg A is the entire measurement programme for now;
Leg B is deferred until it clears. If Layer 2R recovers 0 of 20 plants, there is nothing to
adjudicate anyway.

## Selection method

Shallow-cloned 20 candidates and ran the actual gate preconditions — route handlers, guard
density (something must exist to *delete*), ORM models, and token size against the night
budget. Admitted on `routes > 0 AND guards ≥ 10 AND models > 0 AND tokens < 4M`.

## The corpus

| # | repo | Mtok | routes | guards | models | why it earns a slot |
|---|---|---:|---:|---:|---:|---|
| 1 | `django-helpdesk/django-helpdesk` | 0.32 | 8 | 12 | 3 | smallest; fast iteration during shakedown |
| 2 | `flaskbb/FlaskBB` | 0.33 | 12 | 32 | 4 | **the only Flask app** — blueprint-scoped `GROUP BY`, not Django's URLconf |
| 3 | `kiwitcms/Kiwi` | 0.40 | 12 | 28 | 16 | 16 models against 12 route files — detector 2/3 territory |
| 4 | `jazzband/django-oauth-toolkit` | 0.55 | 23 | 62 | 1 | an *authorization library*; if the authz lens misfires anywhere it is here |
| 5 | `healthchecks/healthchecks` | 0.56 | 35 | 114 | 4 | highest guard-to-size ratio in the set; ideal for guard-deletion plants |
| 6 | `pennersr/django-allauth` | 0.66 | 178 | 42 | 10 | 178 route files — the largest sibling populations available |
| 7 | `wger-project/wger` | 0.84 | 13 | 207 | 55 | **55 models, 207 guards** — the best detector-3 target in the set |
| 8 | `django-cms/django-cms` | 0.98 | 35 | 35 | 30 | permission-heavy CMS; per-object authz |
| 9 | `paperless-ngx/paperless-ngx` | 1.36 | 2 | 51 | 3 | document domain, DRF-style permissions rather than decorators |
| 10 | `readthedocs/readthedocs.org` | 1.52 | 31 | 55 | 15 | **genuinely multi-tenant** (projects/organizations) — the only real detector-2 target |

**Total: 7.52M tokens.** Every repo fits one night comfortably; the largest is 1.52M against
the 2.26M repo Seat 2 budgeted at ~6M PTE per wave.

**Held in reserve** (pass the preconditions, too large for routine nights):
`rafalp/Misago` 2.53M · `WeblateOrg/weblate` 3.70M · `pretix/pretix` 3.85M (272 guards,
54 models — the richest target found, if a two-night run is ever worth it).

**Rejected, with the reason recorded:** `mealie` (0 models detected — see the gap below),
`archivebox` (0 guards), `promnesia` (1 route, 0 guards), `Pylons/pyramid` (framework, not
an app), `openwisp-controller` (5 guards, below the floor), `apache/superset` (0 decorator
guards — DRF-only, 6.67M), `apache/airflow` (17.85M).

## Two limitations, stated up front

**1. The corpus is 9 Django, 1 Flask, 0 FastAPI.** Leg A therefore measures the detectors
principally against *Django conventions* — `LoginRequiredMixin`, `permission_classes`,
`urlpatterns`. A recall number from this corpus does not transfer to FastAPI's
`Depends(...)` or to Express, and must not be quoted as if it does.

**2. A detector-3 gap this selection surfaced.** `mealie` is FastAPI + SQLAlchemy and scored
**0 models**, because the pattern set is `models.Model|db.Model|declarative_base|SQLModel`
and SQLAlchemy 2.0 uses class-based `DeclarativeBase`. That is a bug in detector 3's
precondition, not a property of mealie — it would silently disable the lens on every modern
SQLAlchemy codebase. Fix before Leg A runs, and treat it as evidence for the wider point:
**a precondition that fails closed disables a lens invisibly.**

## Plant design

Per Seat 6 (amendment A1): **20 plants across the 10 repos**, floor 20 and target 60.

- **Prefer guard *deletion* to injection.** Removing an existing `@login_required` from a
  route whose siblings keep theirs produces exactly the anomaly detector 1 is built to find,
  and it is realistic by construction because the guard was really there.
- **Harvest one class from OSV** — reverted real CVE fixes in these projects' own histories.
- **Pre-flight every plant by program**: assert the gate's precondition holds, that the
  sibling population exists, and that the plant is reachable from an entry point.
- **Scrub the git history.** The commit message is the answer key.
- **Never report bare recall** — always paired with candidates/repo. A lens that flags
  everything scores 20/20.

## Abandon condition

```
ABANDON Layer 2R if it recovers 0 of 20 plants.     P(0 | recall 15%) = 3.9%
Cost: 10 nights, 0 operator-hours, $0.
```

Committed to git **before the first `research run`**, per Seat 1's condition and Seat 6's
pre-registration.

## The replay set: a small fixed corpus in the repo (2026-11-05)

The ten repositories above need cloning and a night each. To measure one Layer 2 change
(IMPROVEMENT-PLAN item 21), `tests/fixtures/replay/` holds a small set built on the same
idea, with no cloning and no network: two synthetic services and 7 plants. The answer key,
`plants.json`, sits beside the repositories and is never copied into what a model reads.
`quarry deep-replay` runs the set through the real runner (hunt, quote verification,
persistence, cross-family refutation) on a scratch database, and `quarry
deep-replay-compare` compares two results. A preflight checks every plant by program first:
anchors present, the plant's lens selected by the profile, at least two siblings that keep a
deleted guard, and no answer inside a repository.

| repo | framework | plants | lenses run |
|---|---|---|---|
| `notes_app` | Flask | N1 admin route lost `@admin_required` (guard deletion); N2 note read with no ownership check; N3 path traversal; N4 SQL injection | authz, injection, filesystem |
| `ticket_api` | Express, with an OpenAPI document whose global bearer requirement over-declares | T1 history route lost `auth.requireUser` (guard deletion); T2 role route lost `auth.requireAdmin` (guard deletion); T3 cross-org comment read | authz |

Limits: synthetic and small (about 2.4k tokens per repository), so each is one subsystem and
packing and subsystem ordering are not exercised; 7 plants is a regression check, not a
recall estimate, and nothing measured here transfers to the ten repositories above.

### First measurement, 2026-11-05

Three replays. Held fixed: qwen3-coder:30b (digest `06c1097efce0...`) and devstral:24b
(`9bd74193e939...`), Ollama 0.40.13, unit budget 45,000 tokens, num_ctx 65,536, hunt
num_predict 8,192, refute num_predict 700, temperature 0, top_k 1, seed 42, lenses authz,
injection and filesystem. A and B ran at 1ff502d, A2 at 0639110, which changed only the
replay's scoring; all three are scored with the 0639110 scorer (`--rescore`).

| replay | route intent | plants missed at the hunt | missed after refutation | unsupported claims | hunt / refute / wall |
|---|---|---|---|---|---|
| A | off | 2/7 (N1, N2) | 7/7 | 3/15 | 215 / 164 / 378 s |
| A2, a repeat of A | off | 2/7 (N1, N2) | 7/7 | 2/15 | 217 / 156 / 373 s |
| B | on | 1/7 (N2) | 7/7 | 3/16 | 253 / 174 / 427 s |

- **The refute pass killed every claim:** 0 of 46 claims survived across the three replays,
  including every claim on a plant. The refutations cite checks the code does not have:
  that `download` calls `secure_filename`, that the role route carries `auth.requireAdmin`,
  that `tickets.history` goes through `visibleTicket`. In B, with the declared access in the
  prompt, a refuter still said `reset_password` carries `admin_required`. On this set the
  refuter as prompted has no recall, which is IMPROVEMENT-PLAN item 3's asymmetry showing up
  in Layer 2.
- **Route intent:** B's authz hunt found N1, which both intent-off runs missed. That is one
  plant on one run per side, so it is suggestive, not a measured improvement; compare calls
  B against A "better" and B against A2 "mixed", and flags both as within noise. B's hunt
  took 253 s against 215 and 217 s, longer prompts, measured once.
- **Run to run:** A and A2 had the same configuration and Layer 2 code, and differed in 3 of
  15 claims by (model, lens, file, enclosing symbol, quote verified) and by one unsupported
  claim, with the same plants found. Temperature 0 and a fixed seed do not make a replay
  repeat exactly, so a one-plant or one-claim move here needs a repeat before it means
  anything.

### Decision F: a refutation has to show its guard, 2026-11-05

All 46 refutations above were `refuted`, and none carried a `counter_quote`. Every guard
they cited exists in a sibling of the planted code: `remove` calls `secure_filename`,
the other admin routes carry `auth.requireAdmin`, the other ticket controllers call
`visibleTicket`. Decision F makes a refutation carry evidence, checked in code
(`quarry/research/grounding.py`); a refutation that fails the check is asked once more
with the reason, and if it still fails it is not a vote. A claim that every refuter
tried and failed to rebut this way is kept for a human as "not rebutted", not as
"defended" (`ensemble.KEPT_SQL`, shared by the funnel gate, the digest and the run page).

Two versions were measured, two replays each, with the models, digests, Ollama version,
budget, sampling, lenses and corpus held fixed (`deep-replay-compare` found no fixed
difference against A, A2 or B). Both ran on 1e56c79 plus uncommitted changes, which the
results record.

- **F1, quote placement:** `counter_file` and `counter_quote`, with the quote on the
  claim's path (its definition, one it names, one that names it, or module level; never
  an import).
- **F2, guard:** F1 plus `guard`, the expression inside the quote the refuter says stops
  the attack, and the path rule applied to the guard's own line.

| replay | refuter | route intent | missed at the hunt | missed after refutation | unsupported claims | kept claims, on a plant / not | refutations retried | refute / wall |
|---|---|---|---|---|---|---|---|---|
| A | as before | off | 2/7 | 7/7 | 3/15 | 0 / 0 | n/a | 164 / 378 s |
| A2 | as before | off | 2/7 | 7/7 | 2/15 | 0 / 0 | n/a | 156 / 373 s |
| B | as before | on | 1/7 | 7/7 | 3/16 | 0 / 0 | n/a | 174 / 427 s |
| F1 off | quote placement | off | 2/7 | 5/7 | 3/15 | 2 / 0 | 3 of 15 | 151 / 346 s |
| F1 on | quote placement | on | 1/7 | 6/7 | 2/15 | 1 / 0 | 2 of 15 | 165 / 367 s |
| F2 off | guard | off | 2/7 | 2/7 (N1, N2) | 4/16 | 6 / 1 | 8 of 16 | 184 / 372 s |
| F2 on | guard | on | 1/7 | 2/7 (N2, T1) | 1/16 | 5 / 2 | 9 of 16 | 235 / 441 s |

- **F1 changed little, and not for the reason intended.** The path rule rejected none of
  the 30 refutations. Asked for a quote, the refuters stopped citing siblings and quoted
  the claimed definition itself, which is always real and always on the path, beside the
  same invented reason: the head of `download` beside "sanitized by `secure_filename()`",
  the planted role route beside "requires both `auth.requireUser` and
  `auth.requireAdmin`". 12 and 13 of 15 refutations grounded, 8 and 10 of them on a quote
  from inside the claimed definition. The 2 and 1 plants F1 kept were kept because a
  refuter gave no quote or miscopied one.
- **F2 kept every plant the hunt found in the intent-off run, and all but T1 with intent
  on.** Why each kept plant claim's refutation failed: in F2 off, 3 of 6 named a guard
  that is not in their own quote (`auth.requireAdmin` beside the planted route), 1 named
  a guard found only on sibling routes, and 2 miscopied the quote; in F2 on, 4 of 5 named
  a guard not in their quote and 1 miscopied it. A miscopied quote keeps a claim for a
  sloppy refuter, not a principled reason.
- **What still kills a plant claim in F2** (1 claim in F2 off, 5 in F2 on), in two kinds,
  neither of which a location check can see:
  - a real guard on the path that does not address the claim: `@login_required` cited
    against path traversal and against a cross-user read;
  - a guard that guards nothing: the handler name `tickets.history`, a not-found check,
    `os.path.isfile(path)`. In three of these the refuter's own reason concedes the
    claim ("does not perform any authorization checks").
  T1 died in F2 on that way, twice; N3 was kept there only because one of its three
  claims was not rebutted.
- **The price:** of the verified claims on no plant, 1 of 5 (F2 off) and 2 of 5 (F2 on)
  were kept for a human; before F, none were. All three are the shared-note route,
  where the refuter's real argument (the token is an intended capability) named a guard
  outside its quote or in `share_note`. The kills of claims on no plant cite guards that
  are there and do apply (`remove` does call `secure_filename`).
- **No refuter answered `survives` in any of the 62 refutations across the four runs.**
  Every kept claim is "not rebutted". The prompt still says "Default to `refuted`. Most
  findings are wrong."; F changed what a refutation must show, not that mandate.
- **Cost:** the retry ran on 8 and 9 of 16 refutations in F2, and the refute pass took
  184 and 235 s against 156 to 174 s before. Measured once each, with the test suite
  running alongside F1 off and F2 off.

Seven plants and two replays per version: the move from 7/7 to 2/7 is five plants on each
side, outside the one-plant noise the A/A2 repeat measured, but it is still two runs on a
synthetic set and says nothing yet about the ten repositories above.

### Decision K: without the kill mandate, 2026-11-05

The same two replays with F2's rule and the prompt's last line, "Default to `refuted`.
Most findings are wrong.", removed. Same models, digests, budget and corpus; run on
9465131 plus that one change.

| replay | route intent | missed at the hunt | missed after refutation | unsupported claims | kept claims, on a plant / not | `survives` answers | refute / wall |
|---|---|---|---|---|---|---|---|
| F2 off | off | 2/7 | 2/7 (N1, N2) | 4/16 | 6 / 1 | 0 of 16 | 184 / 372 s |
| K off | off | 2/7 | 3/7 (N1, N2, T3) | 2/15 | 6 / 2 | 1 of 15 | 239 / 446 s |
| F2 on | on | 1/7 | 2/7 (N2, T1) | 1/16 | 5 / 2 | 0 of 16 | 235 / 441 s |
| K on | on | 1/7 | 5/7 (N1, N2, N4, T1, T3) | 3/17 | 3 / 2 | 0 of 17 | 260 / 528 s |

Worse with intent on by three plants, and within noise with intent off. The plant kills
in K on are the kinds F2 left: `login_required` cited against an admin-only password
reset, a role allow-list cited against a missing admin check, `g.user['id']` against
SQL injection through `q`, and code that guards nothing. The line was restored. Both K
replays ran while the machine was also scanning, which moves wall time, not the
verdicts.

### Decision M: the guard must answer the claim's attacker, 2026-11-06

F2's remaining plant kills all rested on guards that sit on the claim's path and do not
stop its attacker. Across the four replays that recorded guards (F2 and K, intent off
and on), 27 refutations of verified claims passed grounding; 14 killed a plant claim
and 13 a claim on no plant. The 14 were a login check against an attacker who is
already logged in (`@login_required` against a cross-user download, an admin-only
password reset and a path traversal), a lookup by the requested id or a not-found check
offered as authorization, `ROLES.has(req.body.role)` (the attacker's requested role,
not the caller's), `g.user['id']` against injection through `q`, `os.path.isfile(path)`
against traversal, and the bare handler name `tickets.history`.

M adds a lexical check after F2's placement rule (`quarry/research/relevance.py`, called
from `grounding.ground`), and the refute prompt now states it:

- every lens: the guard must do something (a call, a comparison, a decorator, a
  condition) or be a known auth guard's name;
- `broken-authz-idor` and `multi-tenancy-isolation`: the guard must check who is asking,
  by a role or permission check or by comparing against the requesting user, directly
  or inside a helper it calls (the helper's definition is looked up in the claim's and
  the counter quote's files). A login check alone answers only a claim whose attacker is
  unauthenticated;
- data lenses (injection, filesystem-and-path, untrusted-input-handling,
  validation-bypass, mass-assignment, redos-and-resource): the guard must name the input
  the claim says the attacker controls, and an existence check does not count.

A guard that fails is handled like any ungrounded refutation: asked once more with the
reason, then counted as unsupported.

**Offline, on the 27 recorded refutations:** M rejects all 14 plant kills and keeps 9 of
the 13 kills on no plant. This is in-sample: the rule was written while reading these
records. The 4 kills on no plant it rejects are three bare login checks against "IDOR
on file delete" (the real protection is the per-user directory `_user_dir()`) and one
share-token lookup.

**Live, two replays on the same models, digests, budget and corpus** (quarry at
c8cb8b7 plus M and item 28, uncommitted; `quarry_dirty` is recorded in each result):

| replay | route intent | missed at the hunt | missed after refutation | kept claims, on a plant / not | claims on no plant kept | refutations retried | `survives` answers | wall |
|---|---|---|---|---|---|---|---|---|
| F2 off | off | 2/7 | 2/7 (N1, N2) | 6 / 1 | 1 of 5 | 8 of 16 | 0 of 16 | 372 s |
| F2 on | on | 1/7 | 2/7 (N2, T1) | 5 / 2 | 2 of 5 | 9 of 16 | 0 of 16 | 441 s |
| M off | off | 2/7 | 2/7 (N1, N2) | 7 / 2 | 2 of 3 | 9 of 15 | 0 of 15 | 387 s |
| M on | on | 1/7 | 1/7 (N2) | 8 / 2 | 2 of 5 | 10 of 14 | 0 of 14 | 436 s |

- **Refutation lost no plant the hunt found, in either run.** Every miss after
  refutation is a miss at the hunt. F2 lost T1 at refutation with intent on; K lost up
  to four.
- **The price is about what F2 paid:** two claims on no plant kept for a human in each
  run (of 3 and of 5).
- **What it does not fix:** no refuter answered `survives` in any of the 29 answers,
  and 23 of the 29 `refuted` answers were finally discarded (12 of 15 and 11 of 14).
  M's relevance check was the stated reason in 14 of the rejections across both runs
  (an answer that was retried can be rejected twice, so this counts rejections, not
  answers). The refuter now kills little; most verified claims
  reach a human as "not rebutted". On a small synthetic set that is cheap. On a real
  repository it means more review, and how much more is not measured yet: the test run
  after the reset is the first measurement at real scale.
- One run per configuration, seven plants, a synthetic corpus written by the same
  people who wrote the rule: read the zero as "no plant lost on this set", not as a
  recall figure.
