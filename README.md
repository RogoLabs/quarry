# Quarry

Quarry is a local-first vulnerability hunter for open-source repositories. It clones a
target into a sandbox, runs a stack of free scanners, and funnels the output down to the
findings worth a human's time. Then it tries to prove or kill the survivors against a
running copy of the target, and drafts a disclosure advisory for anything it can prove.

It runs on a Mac, costs nothing per scan, and sends nothing anywhere without a separate,
explicit step. It never writes to a repository you do not administer.

A [RogoLabs](https://rogolabs.net) project.

## The pipeline

```bash
quarry doctor                   # environment, sandbox profiles, tool inventory
quarry doctor --coverage        # also: does each installed scanner still read every directory
quarry db sync                  # Trivy and OSV databases, fetched outside the sandbox
quarry targets score owner/repo # rank candidates on attack surface and responsiveness
quarry ingest owner/repo        # anonymous clone into a per-run APFS sparse image
quarry scan 1                   # seven scanners under sandbox-exec, no network, no models
quarry funnel 1                 # thirteen ordered stages; nothing is deleted
quarry killed 1                 # audit what the funnel suppressed, and why
quarry status 1                 # the run page as text, one fact per line (or --json)
quarry deep 1                   # Layer 2: local-model review with cross-family refutation
quarry deep-survivors 1         # Layer 2 survivors, new or previously judged by a human
quarry deep-verdict 141 intended --note "..."   # record a human verdict on one
quarry deep-replay              # score a Layer 2 change on the fixed planted-bug corpus
quarry validate 1 --dry-run     # plan which probes fit this codebase
quarry validate 1               # stand the target up in Docker and probe the survivors
# a real-world target usually needs more, e.g. VulnLookup:
#   quarry validate 1 --build-network --memory 6g --env INSTANCE_UUID=$(uuidgen)
quarry report 1                 # Markdown advisory drafts for confirmed findings
quarry report 1 --check-head    # also ask the target's git host whether HEAD moved
quarry serve                    # dashboard on 127.0.0.1:8099
```

The scanners are opengrep, bandit, gitleaks, zizmor, osv-scanner, trivy and checkov.
Opengrep runs all its rule trees at once, but if the engine crashes on one tree or file
and writes nothing, the scan falls back to one invocation per tree so a single bad
ruleset cannot zero the others' findings. A tree that still crashes the engine is split
and rerun until the crash is pinned to a file; that file is retried with `-j 1`, and if
it still crashes the scan's coverage counts name it as skipped.
`quarry deep` adds an optional review pass by local models through Ollama; cloud model
names are refused. A model of another family then tries to refute each claim. A
refutation counts only when it quotes code and names the guard in that quote (the check,
sanitiser or middleware it says stops the attack), and the guard's line is on the
claim's own path: its function or route, something that code calls, or a wrapper that
registers it. A guard quoted from a sibling function does not count. The guard must also
be the right kind of check for the claim's attacker: on an authorization claim it must
check who is asking (a login check alone answers only an unauthenticated attacker), and
on a data claim it must touch the input the attacker controls. A claim that every
refuter tried and failed to rebut that way goes to a human marked "not rebutted", not
"defended". These checks are lexical: they test where the guard is and what kind of
check it is, not that it is correct.

**Validation is conservative by design.** A probe result counts as confirmed only when it
recorded a baseline request and the result differs from it. It counts as rejected only
when a handler answered (not 404 or 405) and the result matched a recorded control, and
only a deterministic rejection of that kind carries forward to later runs (not a
rate-limit rejection: the throttle usually lives outside the flagged code). Anything else
is stored as needs-review. Every probe class records a control; the auth-timing probe's
is a pair of absent identifiers timed beside the present one, and a SQL injection
rejection needs every declared parameter to refuse every metacharacter input.
`quarry report` only drafts confirmed findings, and every
draft ends with a reminder to review it before sending. A draft also lists the conditions
Quarry recorded for the observation (and says which it did not record), names the weakest
link in the evidence, keeps the per-CWE severity default apart from a confidence line taken
from the verdict, and searches the local OSV copy for earlier advisories under the package
names the clone's manifests declare. It does not claim the result reproduces unless
replays were recorded. It re-checks the current HEAD only with `quarry report
--check-head`, one anonymous `git ls-remote` on the egress ledger, and otherwise says it
did not.

## Why it is shaped this way

I measured the tool this one replaces before building it. Across 14 repositories it
produced 162 findings at a cost of $27.99, and 4 of the 162 held up. Free tools
(`bandit` and `grep`) recover 3 of those 4 in under a second. That is n=4, so read it as
a direction, not a rate. The working and the caveats are in [`docs/PLAN.md`](docs/PLAN.md)
and [`docs/RESEARCH.md`](docs/RESEARCH.md).

The deterministic layer is the product. Model review has to earn its place, and a
finding is not a finding until something has tried to prove it.
[`docs/LAYER3-PLAN.md`](docs/LAYER3-PLAN.md) describes the validation layer.

## Containment

Step one of any audit pipeline is downloading hostile code onto a laptop that holds SSH
keys and a GitHub token.

- Every process that reads target bytes runs under `sandbox-exec`: no network, no
  macOS service lookups, no job creation or preference writes, reads confined to the
  per-run volume and the tool, rule and database directories, and signals confined to
  the sandbox.
- No process that reads target bytes holds a credential. Clones are anonymous, with
  hooks, submodules and LFS smudge disabled.
- Symlinks in the clone are recorded and destroyed. Target-supplied scanner configs and
  inline suppressions are quarantined or ignored, with one known exception: Trivy obeys
  inline `trivy:ignore` comments and has no flag to stop it. A scan that finds any
  lists the files on the run page.
- Secrets are stored as a prefix plus SHA-256, including inside evidence windows.
- The dashboard only answers to loopback Host headers, refuses cross-site POSTs, and
  renders bidi and zero-width characters from target code as visible tokens.
- `validate` runs the target in Docker, not under `sandbox-exec`. Quarry never runs
  the author's compose file. It refuses `include`, `extends.file` and any `env_file`
  outside the clone, resolves the file with a scrubbed environment (nothing from your
  shell is interpolated), and writes a new document from an allowlist of keys:
  one internal-only network, no host ports, binds only inside the clone,
  `cap_drop: ALL` with a short list added back, `no-new-privileges`, memory and pid
  limits, and builds with `network: none`. Image pulls are the one step with network
  access. A build that needs the network fails and is recorded on the run page.
- `validate --build-network` is the opt-in for the many Dockerfiles that install
  dependencies in RUN steps. Those steps can then reach the internet, the LAN and this
  Mac (Docker Desktop routes `host.docker.internal` to it), but the build still gets
  none of your environment, registry credentials, SSH agent or BuildKit secrets, and the
  running target stays on the internal network. The run page says the build had network.
  A clone with no `.env` is interpolated from its `.env.sample` (or `.example`, `.dist`,
  `.template`), and the run page says that too. A placeholder in that sample is filled
  with `--env KEY=VALUE`, which you type; nothing is read from your shell. `--memory`
  raises the per-service memory cap (2g by default), which is a resource guard rather
  than a containment control.
- `validate --seed <name>` runs a named recipe's setup commands before probing, so an
  empty instance becomes testable. A recipe runs the target's *own* documented commands
  (its create-user command, its importer) inside the contained container; Quarry adds no
  data itself and touches no datastore directly. It establishes test accounts, captures
  their API keys in memory for an authenticated probe, and sets real parameter values so
  a probe addresses a record that exists. A seed step that fails is recorded on the run,
  not fatal, and the probes stay read-only. `vulnlookup` is the first recipe.

The test suite (1233 tests) asserts these against a hostile fixture repo and real
`sandbox-exec`. A profile with no test is a comment.

## Requirements

macOS, Python 3.12 or later, Docker Desktop for `validate`, and the scanners listed by
`quarry doctor`. Install with `pip install -e .` inside a virtualenv; the command is
`quarry`.

## License

Apache 2.0. See [`LICENSE`](LICENSE).
