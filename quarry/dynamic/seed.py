"""Bring a freshly booted target to a testable state by running the target author's own
documented operator commands inside the contained instance.

A probe is only as good as the state it probes. An empty instance answers differently
from a populated one, and a cross-principal check needs more than one principal. So a
seed recipe runs the project's OWN setup commands -- the create-user command it ships,
the importer it documents -- in the already-running, egress-blocked container, exactly as
an operator standing up a staging box would. Quarry adds no data of its own and reaches
into no datastore directly; it calls the commands the project provides and reads what they
print.

Recipes are opt-in by name (`quarry validate <run> --seed <name>`), like `--build-network`:
nothing runs the target's code beyond booting it unless the operator asks. A step that
fails is a recorded gap on the run, not a stopped validation -- a half-seeded instance is
still more testable than an empty one, and the probes stay read-only either way.

What a recipe can set for the probes that follow:
  * param_values -- real values for named path parameters (vulnerability_id -> a real
    CVE id), so a probe addresses a record that exists instead of the placeholder `1`.
  * credentials  -- values a step captured from a command's output (a test account's API
    key), kept in memory for an authenticated probe, never stored or rendered.
"""
from __future__ import annotations

import re
import secrets as _secrets
from dataclasses import dataclass, field


class SeedError(RuntimeError):
    """A required seed step failed. Optional steps never raise; they are recorded."""


@dataclass(frozen=True)
class SeedStep:
    """One operator command, run in a service container. `argv` tokens may contain a
    `{password}` placeholder, replaced per run with a freshly generated test secret so no
    credential is hard-coded. When `capture` matches the command's output, group 1 is
    stored under `capture_as` (e.g. an API key the command printed)."""
    argv: tuple[str, ...]
    service: str = ""             # default: the running target's main service
    timeout: int = 900
    optional: bool = True         # a failed optional step is recorded, not fatal
    capture: str = ""             # a regex with one group, matched against the output
    capture_as: str = ""          # the credentials key the match is stored under
    describe: str = ""            # a short line for the progress log, no secrets


@dataclass(frozen=True)
class OwnedResource:
    """One kind of per-user record the cross-user authz probe may create as `owner`,
    through the target's own API, and then address as `other`. Paths are as the server
    answers them, prefix included. `{id}` is a UUID the probe generates, so it knows
    exactly which two records it made and touches no other; `body` and `modify_body` are
    JSON templates that may also use `{marker}` and any seeded parameter value
    (`{vulnerability_id}`). `owner` and `other` are credentials keys a seed step
    captured."""
    name: str
    collection: str              # POST here creates one
    item: str                    # one record, with {id}: GET reads it, DELETE removes it
    body: str
    owner: str
    other: str
    # How the record is changed: "post-collection" (POST the same id again, VulnLookup's
    # create-or-update), "put-item", "patch-item", or "" when it cannot be changed.
    modify: str = ""
    modify_body: str = ""


@dataclass(frozen=True)
class CrossUser:
    """What the cross-user probe needs from a recipe: how a credential is presented, who
    each captured credential belongs to (for evidence text, which names accounts and never
    keys), and the per-user resources to test."""
    header: str                  # "X-API-KEY", or "Authorization: Bearer"
    accounts: dict[str, str] = field(default_factory=dict)   # credentials key -> login
    resources: tuple[OwnedResource, ...] = ()


@dataclass(frozen=True)
class SeedRecipe:
    """A named set of setup steps plus the probe inputs they establish. Steps run in
    order; `param_values` are the fixed, record-independent inputs (a known id).
    `cross_user` declares the per-user resources the cross-user authz probe may test with
    the accounts the steps created."""
    name: str
    description: str = ""
    steps: tuple[SeedStep, ...] = ()
    param_values: dict[str, str] = field(default_factory=dict)
    cross_user: CrossUser | None = None


_RECIPES: dict[str, SeedRecipe] = {}


def register(recipe: SeedRecipe) -> None:
    _RECIPES[recipe.name] = recipe


def get(name: str) -> SeedRecipe | None:
    return _RECIPES.get(name)


def names() -> list[str]:
    return sorted(_RECIPES)


@dataclass
class SeedResult:
    """What seeding established: probe inputs and a human-readable note per step. Secret
    values live in `credentials`/`param_values` for the probes; `notes` never holds one."""
    param_values: dict[str, str] = field(default_factory=dict)
    credentials: dict[str, str] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    cross_user: CrossUser | None = None


def _apply(argv: tuple[str, ...], subs: dict[str, str]) -> list[str]:
    out = []
    for tok in argv:
        for k, v in subs.items():
            tok = tok.replace("{" + k + "}", v)
        out.append(tok)
    return out


def run_seed(runtime, running, recipe: SeedRecipe,
             progress=lambda m: None) -> SeedResult:
    """Run a recipe's steps via `runtime.service_exec` (the target's own commands, inside
    the contained container). Returns the probe inputs they established. A missing
    `service_exec` (a runtime that cannot exec in a service) is a recorded gap, not a
    crash."""
    res = SeedResult(param_values=dict(recipe.param_values), cross_user=recipe.cross_user)
    if not hasattr(runtime, "service_exec"):
        res.notes.append(f"seed {recipe.name}: runtime has no service exec; skipped")
        return res
    # One throwaway password for every account this recipe creates. The contained
    # instance is torn down after the run, and probes authenticate with the API keys the
    # commands print, not this value.
    subs = {"password": _secrets.token_urlsafe(18)}
    for step in recipe.steps:
        argv = _apply(step.argv, subs)
        label = step.describe or " ".join(step.argv[:3])
        try:
            rc, out = runtime.service_exec(running, argv, service=step.service,
                                           timeout=step.timeout)
        except Exception as e:                       # noqa: BLE001 - a seed failure is data
            res.notes.append(f"seed step [{label}] errored: {type(e).__name__}")
            if not step.optional:
                raise SeedError(f"required seed step failed: {label}") from e
            continue
        if step.capture and rc == 0:
            m = re.search(step.capture, out)
            if m and step.capture_as:
                res.credentials[step.capture_as] = m.group(1)
                res.notes.append(f"seed step [{label}]: captured {step.capture_as}")
            elif step.capture_as:
                res.notes.append(f"seed step [{label}]: {step.capture_as} not found in output")
        if rc != 0:
            res.notes.append(f"seed step [{label}] rc={rc}")
            if not step.optional:
                raise SeedError(f"required seed step failed (rc={rc}): {label}")
        else:
            progress(f"  seed: {label}")
    return res


# --------------------------------------------------------------------------- recipes

# VulnLookup (CIRCL vulnerability-lookup). Uses the project's own Flask CLI, run through
# poetry inside the app container, from the image's workdir. Records come from the feeders,
# which need network at run time and so cannot be loaded under containment; what seeds
# cleanly offline is the accounts (Postgres is contained) and a known CVE id for probes.
#
# Three accounts. create_admin seeds VulnLookup's RBAC defaults, including the
# self-registration policy whose default role is `commenter` (comment:create,
# sighting:create), and create_user without --roles takes that role. So quarry_user and
# quarry_user2 are peers who can each create comments and sightings and own what they
# create (comment_owner, sighting_owner); neither has a global delete. That is the
# horizontal case an IDOR check needs. Bundles need bundle:create, which only the admin
# has, so bundles are tested as the admin's record addressed by quarry_user.
_VL = ("poetry", "run", "flask", "--app", "website.app")


def _vl_user(login: str, admin: bool = False) -> SeedStep:
    return SeedStep(
        argv=_VL + ("create_admin" if admin else "create_user", "--login", login,
                    "--email", f"{login}@quarry.test", "--password", "{password}"),
        describe=f"create {'admin' if admin else 'user'} account {login}")


# `user_get_api_key` prints `user.apikey` on a line of its own. VulnLookup makes it with
# `secrets.token_urlsafe(64)` (website/models/user.py), 86 characters of letters, digits,
# `-` and `_`, and validates a length of 30 to 100. The capture takes that whole line.
# It used to be `([0-9A-Za-z]{16,})`, which stopped at the first `-` or `_` and captured
# a fragment of the key, so every authenticated probe was answered 401 (2026-11-10).
VL_KEY_CAPTURE = r"(?m)^([A-Za-z0-9_-]{30,100})\s*$"


def _vl_key(login: str, key: str) -> SeedStep:
    return SeedStep(argv=_VL + ("user_get_api_key", "--login", login),
                    capture=VL_KEY_CAPTURE, capture_as=key,
                    describe=f"read {login} API key")


register(SeedRecipe(
    name="vulnlookup",
    description="three test accounts via the project's create_admin/create_user commands, "
                "their API keys, the per-user resources for the cross-user probe, and a "
                "known CVE id for probes",
    steps=(
        _vl_user("quarry_admin", admin=True),
        _vl_user("quarry_user"),
        _vl_user("quarry_user2"),
        _vl_key("quarry_admin", "admin_api_key"),
        _vl_key("quarry_user", "user_api_key"),
        _vl_key("quarry_user2", "user2_api_key"),
    ),
    # A real, widely-known CVE id, so a probe hits /api/vulnerability/<id> for a record
    # the instance can serve rather than the placeholder 1. Record population still needs
    # the feeders (network); this id is what probes try regardless.
    param_values={"vulnerability_id": "CVE-2021-44228"},
    # Read from website/web/api/v1/{bundle,sighting,comment}.py at a9c6edf. Each POST
    # accepts a client-supplied uuid. A bundle is checked against the CIRCL schema
    # (website/web/static/schemas/CIRCL/Security_Advisory_Bundle.json, read at 7d77b9b),
    # whose `related_vulnerabilities` needs at least one entry. The canary sent `[]`, and
    # all 8 bundle creates of 2026-11-10 were answered 400. It now names the probe CVE. A new bundle adds a `seen` sighting for each entry and a
    # bundle DELETE leaves those in place, so each bundle canary leaves one admin
    # sighting in the throwaway instance. Free text names no CVE id, which would add
    # more. A commenter's new comment awaits moderation and
    # GET serves only published ones, so the comment read check finds no baseline and
    # its delete check relies on the owner's own DELETE afterwards. Sightings cannot be
    # updated ("It is not possible to update a sighting"), so they have no modify check.
    cross_user=CrossUser(
        header="X-API-KEY",
        accounts={"admin_api_key": "quarry_admin", "user_api_key": "quarry_user",
                  "user2_api_key": "quarry_user2"},
        resources=(
            OwnedResource(
                name="bundle", collection="/api/bundle/", item="/api/bundle/{id}",
                body='{"uuid": "{id}", "name": "quarry canary {marker}", '
                     '"description": "Quarry cross-user canary.", '
                     '"related_vulnerabilities": ["{vulnerability_id}"]}',
                owner="admin_api_key", other="user_api_key", modify="post-collection"),
            OwnedResource(
                name="sighting", collection="/api/sighting/", item="/api/sighting/{id}",
                body='{"uuid": "{id}", "vulnerability": "{vulnerability_id}", '
                     '"type": "seen", "source": "quarry-canary-{marker}"}',
                owner="user_api_key", other="user2_api_key"),
            OwnedResource(
                name="comment", collection="/api/comment/", item="/api/comment/{id}",
                body='{"uuid": "{id}", "title": "quarry canary {marker}", '
                     '"description": "Quarry cross-user canary.", '
                     '"vulnerability": "{vulnerability_id}"}',
                owner="user_api_key", other="user2_api_key", modify="post-collection"),
        )),
))
