# Layer 3: dynamic validation

Status: foundation landed (containment profile, verdict ledger, candidate selection,
runtime and probe interfaces, tests). Executing runtimes and probe lenses are the next
increment. This doc is the contract they plug into.

## Why it exists

Layers 1 and 2 read the target and argue about it. Every finding they produce, even one
that survives the whole funnel and a cross-family model review, is still only a claim.
The predecessor's own lesson (see `targets.py`) was that scanning mature code finds
almost nothing real, and the bottleneck is not the scanner but the depth of analysis.
The next depth increment is the one I had been doing by hand in manual audits:
stand the target up and prove the finding, or kill it with evidence.

Layer 3 is that step, automated. It converts a surviving candidate into one of:

- **confirmed**, with a reproducible probe and the effect it measured, or
- **rejected**, because the probe ran and the finding did not reproduce.

Anything the probe cannot decide stays **needs-review**. Layer 3 never promotes a guess
to a confirmation. It is the only thing in the system that writes a non-zero
`executed_score` into the verdict ledger, which is the column the schema already set
aside for "executed evidence outranks argued".

## Where it sits

```
scan (Layer 1)  ->  funnel  ->  deep (Layer 2, reads)  ->  validate (Layer 3, runs)  ->  disclosure
```

Layer 3 consumes `live_occurrences` (findings that survived the funnel) and writes
`verdicts`. It does not delete or mutate anything else; a rejection is a verdict row,
not a kill, so the finding and its provenance stay intact and auditable.

## Containment: loopback in, nothing out

Running a target is running untrusted code, which the read-only layers never did. The
posture is a third sandbox profile, `quarry-target.sb`, that differs from the scanner
profile (`quarry-tier1.sb`) by exactly one capability: loopback networking, so a local
probe can reach the target it just started. Non-loopback network stays denied at the OS,
so a target still cannot reach anything off the machine, and the "completely local"
claim the egress ledger exists to back stays true. The target runs inside the per-run
APFS sparse image, writes only there, and reads no host files. `tests/test_dynamic_
validation.py` proves the three invariants against real sandbox-exec: loopback works
under the target profile, loopback is denied under the scanner profile, and egress is
denied under the target profile.

## The verdict contract

`db.verdict(...)` writes one adjudication, keyed on the line-number-free `finding_id` so
it carries forward across runs. Layer 3 sets `seat="dynamic"`, `evidence_score=0`, and
`executed_score` > 0 only when a probe actually ran. `validate.adjudicate` maps measured
evidence to a verdict value, and `validate.record_verdict` is the single writer.

## Candidate selection

`select_candidates` returns live findings whose producer's CWE is in
`DYNAMICALLY_TESTABLE`: the classes whose effect is observable from a loopback client
(authentication and authorization, injection with an observable effect, rate limiting
and resource exhaustion, timing separation, traversal, SSRF). A finding outside that set
is left to the read-only layers rather than probed blindly. Candidates are ordered by
the producer's measured cross-repo precision, so the probe budget goes to the rules that
have earned it.

## The pluggable pieces (next increment)

Two interfaces, both empty by design today so the plumbing can be tested without them:

- **`TargetRuntime`**: detects how a target boots and starts it under
  `quarry-target.sb`, exposing a loopback base URL. `detect` returns None when it does
  not know how to run a target, with the reason surfaced by `plan_validation`, never a
  guess.
- **`ProbeLens`**: one bug class, one probe. `applies` gates on a candidate; `build`
  returns a callable that performs the probe against the running target under
  containment and returns `ProbeEvidence`. A probe captures its request and the measured
  effect for replay, and never stores secrets.

`plan_validation` is the dry run: it reports the candidates and, honestly, whether a
runtime and a matching lens exist yet. It writes nothing.

## Runtime: resolved to the container runtime

The runtime strategy was a real fork: a sandbox-exec run command (narrow, fits the
existing model) versus a container runtime (broader, new trust boundary). Resolved to
the container runtime (`runtime_docker.py`), because compose/Dockerfile is the target
author's own declared boot contract and the services worth probing need a real stack.
The egress guarantee is re-established at the container layer by `harden_compose`:
one `internal: true` network, no host port publishing, no host networking, no escaping
host bind-mounts. A live test proves a sidecar reaches the target but not the internet.
The sandbox-exec run-command runtime remains a possible narrow add-on behind the same
`TargetRuntime` interface, not the primary.

## Probe lens selection: which bug class, chosen per codebase

Not a constant. A probe lens runs only where three facts coincide, and the selection is
`lenses.select_probe_lenses(profile, candidates)`, which reads the same
`research.profile` the deep layer uses:

1. **the artifact is runnable** (a service). A library, CLI or data repo cannot be stood
   up and spoken to, so it is never dynamically probed. This is the same honesty the
   profiler already has about packages with no routes.
2. **the capability is present** (routes for authz, an auth path for a timing oracle, a
   SQL/shell/template sink for injection), at a minimum hit count, with the evidence
   path recorded.
3. **a finding survived the funnel** whose CWE this lens can confirm.

Both halves are reported: what will run and the evidence that selected it, and what will
not and why (profile does not support it, or it does but no surviving finding matches).

Priority, when several apply, is confirmability x signal x how cleanly the probe stays
non-destructive:

1. **broken-authz / IDOR** (CWE-862/863/639). The cleanest confirmation available: reach
   an object with the intended identity, then without it or as another principal, and
   compare. Deterministic, idempotent, read-only. Top of the list.
2. **missing rate limit** (CWE-307/400). A small bounded burst observing the absence of
   throttling. Near-deterministic.
3. **auth timing oracle** (CWE-208). Statistical, not a
   clean boolean (many samples, distribution separation), so it sits below the boolean
   classes.
4. **injection, observable** (CWE-89/77/79). Confirmed only through a strictly benign,
   observable signal that never modifies or destroys data, so it is gated carefully.
5. **path traversal / SSRF** (CWE-22/918), observed read-only, SSRF only against the
   isolated network.

So "which to target" has no fixed answer: on a Rails service with routes and an auth
path it is authz and rate-limit first; on a library it is nothing, correctly. The probe
bodies (turning a candidate plus a discovered route into a concrete request) are the next
increment; the catalogue, the gates and the selection are in place and tested, and an
un-wired probe can only ever return needs-review, never a false confirmation.

## Disclosure (ties into Phase 1 / 4)

A confirmed verdict is the input to the disclosure artifact: a CVE-record-shaped output
(reusing the CVE 5.x schemas), the reproducible probe, the evidence window, and the
target's own SECURITY.md contact. Layer 3 stops at the confirmed finding and its proof;
filing and coordinated disclosure stay a human step.
