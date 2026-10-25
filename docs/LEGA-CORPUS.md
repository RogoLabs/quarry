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
