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
