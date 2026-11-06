# Improvement plan, 2026-11-01

A review of the scanning pipeline (Layer 1 scanners and funnel, Layer 2 deep review,
Layer 3 validation, disclosure) and the web dashboard, at commit 285a215.

**How it was reviewed.** I read Layer 1 myself (orchestrator, scanner adapters,
sandbox spawn and profile, taint boundary, clone and quarantine, funnel). Two read-only
review agents covered the web code and Layers 2 and 3. I checked their headline claims
against the code before including them. I also queried the live
`quarry.db` read-only and walked the running dashboard. The suite passes: 449 passed,
4 skipped, with `tests/test_runtime_docker.py` excluded because it needs live Docker.
(The full suite collected 462, which is what README and STATUS said; an earlier draft
called that count stale, and it was not.)

**Status, 2026-11-05.** On branch `fix/checkov-paths-funnel-ledger`, all committed:
items 1, 4 and 8 (1f72355), item 2's interim gate and item 3 (97f7175), items 5 and 6
(d442aad), item 2's compose rebuild (48f3191), items 7 and 9 to 14 (6f2b1b4) except
item 14's Grype entry (decision A), Layer 3 against VulnLookup (e9b8e94, 141a1e0,
febc240), the opengrep per-tree fallback (ef62ff2), and items 15, 23 and 24 (b707e82).
On 2026-11-05 the rest of the list followed, each recorded under its item: items 16
to 22, the open parts of items 2, 3 and 5, P3, P4, and decisions A, B, D and E.
Decision F (the Layer 2 refuter) is done, K was tried and reverted, and L and item
25 are done. On 2026-11-06 item 27 replaced gpt-oss:20b with granite4.2:30b in the
default deep-review models, G and H were done, and item 26 was fixed. Open decisions
are I and J. The suite collects 1045 and passes 1042, with 3 skipped because setuptools
is absent.

Every item says where its evidence came from:

- **[DB]** reproduced against the live database (runs 1 and 2).
- **[code]** traced in the source by me.
- **[agent, checked]** reported by a review agent, and I confirmed the cited lines.
- **[agent]** reported by a review agent, not independently checked.

The common thread: **the pipeline has several ways to be confidently wrong without
saying so.** Layer 1 can lose a whole tool's output while the run still reports success,
and this has happened three times now: `poetry.lock`, the OSV GIT ecosystem, and the
Checkov paths below. Layer 3 can kill a finding forever on a probe that never reached
the code. The dashboard can show two different numbers for the same run. Most of the
plan is about turning those into loud failures.

---

## P0: wrong answers and containment

### 1. Every Checkov finding is killed by quote-verify [DB]

Checkov's SARIF `uri` is relative to the run directory, not the clone, so every path
comes through as `src/<path>` (`src/docker/Dockerfile`, `src/.github/workflows/ci.yml`).
`rel_or_none` accepts it, `extract_evidence` finds no file, and `quote-verify` kills it
as "no evidence window could be captured". All 21 Checkov occurrences across both runs
are affected (21 of 21). Every other tool has 0 missing windows. The kill is marked
deterministic, so the UI does not even flag it as a recall risk. No test parses
Checkov output.

- **Fix:** in `Checkov.parse` (`scanners/tools.py:251`), resolve the uri against the run
  directory and re-relativise to `src`, or run Checkov with `cwd=src` and `-d .`.
- **Test:** a fixture SARIF with `src/`-prefixed uris, and the invariant in item 5.
- **Done.** Checkov now runs from inside the clone with `-d .` (a new
  `Scanner.workdir` hook), which gives plain relative uris. A prefix strip would have
  been wrong for repos with their own top-level `src/`. Checkov already reads
  `.checkov.y*ml` from its `-d` directory, so this opens no new config path. Tests: an
  argv check, and a live run of the installed Checkov under Tier 1 that fails on the
  old code. Existing Checkov rows keep their dead paths until the target is re-scanned.

### 2. The Docker runtime is not contained [agent, checked]

`harden_compose` (`dynamic/runtime_docker.py:141`) is a denylist. It removes `ports`,
some `network_mode` values and `extra_hosts`, and filters bind mounts. It leaves these
alone: `privileged`, `pid: host`, `cap_add`, `devices`, `security_opt`, `volumes_from`,
`env_file`, `extends`, top-level `include` and `secrets`, and named volumes with
`driver_opts` bind devices. `privileged: true` plus `pid: host` reaches the Docker VM,
and Docker Desktop shares `/Users` into that VM by default.

The build is worse. `up -d --build` runs Dockerfile `RUN` steps with full egress,
because `internal: true` does not apply to builds. `build.ssh`, `build.secrets` and an
out-of-tree `build.context` all pass through unchanged. `_compose`
(`runtime_docker.py:282`) runs `docker compose` with Quarry's inherited environment, so
`${GITHUB_TOKEN}` in `build.args` or `environment:` is interpolated from the operator's
shell. One `RUN curl -d "$T" ...` sends the token out before any probe runs.
`validate.py:86-91` says runtimes run "under quarry-target.sb", but Docker never runs
under it.

- **Fix:**
  - Run `docker compose config` with a scrubbed env (`PATH`, a temp `HOME`, nothing
    else) to resolve interpolation and `extends`. Reject `include`.
  - Emit a fresh document from an allowlist of service keys. Check every bind with
    `realpath` inside the clone. Add `cap_drop: [ALL]`, `no-new-privileges`, and pids
    and memory limits.
  - Build with `network: none` and no `ssh` or `secrets`. A build that needs the network
    fails closed and is recorded as a provisioning gap.
  - Call `docker_available()` and enforce a minimum engine version.
- **Interim:** refuse `quarry validate` without `--dry-run` until this lands.
  **Done.** `DockerRuntime.start` raises `UncontainedRuntime` unless constructed with
  `uncontained_ok=True`, and the refusal comes before any docker call. The CLI refuses a
  real run with exit 2 unless `--uncontained` is passed; `--dry-run` is unaffected. The
  README's containment section now says Docker is the exception, and the
  `TargetRuntime` docstring no longer claims Docker runs under `quarry-target.sb`.
  The full fix below is still open.
- **Full fix: done** (working tree). The interim gate and `--uncontained` are removed.
  `start` now runs `precheck_compose` (refuses `include`, `extends.file`, and any
  `env_file` or `label_file` that is outside the clone or contains `$`), then
  `docker compose config` under `scrubbed_env` (PATH, a temp HOME and DOCKER_CONFIG
  whose config.json lists only plugin dirs, and the daemon address), with the target's
  `.env` filtered of COMPOSE_/DOCKER_/BUILDKIT_/BUILDX_ keys. `harden_compose` then
  writes a fresh document from `SERVICE_KEYS` and `BUILD_KEYS`, with every bind
  realpath-checked inside the clone and named volumes recreated empty. Every service
  gets `cap_drop: ALL` plus `KEEP_CAPS`, `no-new-privileges`, `mem_limit`,
  `pids_limit`, `cpus` and `restart: "no"`. Every build gets `network: none`. The
  hardened file lives in `<rundir>/compose/`, outside the clone. `build` and `up
  --no-build` are separate steps, so a build that fails offline raises
  `ProvisioningGap`, and `run_validation` records any start failure as a `validate`
  health warning on the run page.
  - Three things the plan did not list turned up while writing it. With `build` and
    `image` both set, compose tags the build with the `image` name, so a target could
    overwrite the operator's local `postgres:16` or Quarry's own sidecar image; a
    built service now has its `image` dropped. A `# syntax=` directive (or a
    `BUILDKIT_SYNTAX` build arg) picks the BuildKit frontend, and a frontend the target
    chose need not honour the build's network mode; anything but `docker/dockerfile`
    is refused, and BUILDKIT_* args are dropped. A target's `.env` can set
    `COMPOSE_PROJECT_NAME` (MEASURED with compose v5.6.1), hence the filter.
  - `cap_drop: ALL` alone breaks images that start as root and step down (postgres,
    mysql), so eight capabilities are added back: CHOWN, DAC_OVERRIDE, FOWNER, FSETID,
    SETUID, SETGID, KILL, NET_BIND_SERVICE. NET_RAW, MKNOD, SETFCAP, SETPCAP,
    SYS_CHROOT and AUDIT_WRITE stay dropped.
  - Engine and compose versions are checked against 20.10 and 2.0. Those are the
    oldest this is written for, not versions I tested; the live tests ran on engine
    29.9.2 and compose v5.6.1.
- **Test:** done. Hermetic: a resolved document carrying every key above plus
  `use_api_socket`, `logging` to a remote syslog, `volumes_from`, external named
  volumes with bind `driver_opts`, `cache_to` to a host path and `models`; symlinked
  and `..` binds; remote and out-of-tree build contexts; the prechecks; the dotenv
  filter; frontend directives. One test runs the real `docker compose config` (no daemon
  needed) with a token in the environment and asserts it never reaches the output.
  Live: a service asking for `privileged`, `cap_add: [SYS_ADMIN, NET_RAW]` and `pid:
  host` reports `CapEff` and `CapBnd` of exactly `0x4fb` and `NoNewPrivs: 1`; a build
  whose RUN step fetches a URL fails as a provisioning gap. Removing `network: none` or
  `cap_drop` makes the matching live test fail.
- **Done 2026-11-05 (f0c3e28).** `prepare` lists every image and URL provisioning
  fetches outside `network: none` (compose images, FROM, `--from=<image>`, ADD of a URL
  or git remote, with ARG defaults substituted) into `provisioning.remote_fetches`.
  With the build network off, an ADD of a URL, an image from a registry outside
  `KNOWN_REGISTRIES`, or an unresolved reference is a `ProvisioningGap`;
  `--build-network` allows it. Every fetch host, the curl sidecar included, goes on the
  egress ledger as `validate-provision`. Measured on run 3's VulnLookup clone, prepare
  only: five docker.io images and one ADD from github.com, which needs
  `--build-network`, as VulnLookup's apt and poetry RUN steps already did.
- **Was still open.** Image pulls and Dockerfile `ADD <url>` are fetched by the daemon and
  BuildKit, not by RUN, so they still reach the network during provisioning. What they
  can carry out is the URL itself, built from the clone's own content, since no
  operator value is interpolated any more. Private registry images cannot be pulled,
  because the scrubbed DOCKER_CONFIG has no credentials; that is by design.

### 3. Rejection is easier than confirmation [agent, checked]

`adjudicate_with_reason` (`validate.py:171`) holds `confirmed` to a recorded baseline,
but `rejected` needs nothing. And `_rejected_carry_forward` (`funnel.py:496`) then
kills that finding in every later run.

- The timing probe is status-blind (`probes.py:42`). If a login route returns 404 to
  both identifiers, the medians match and the finding is `rejected`.
  `tests/test_probes_more.py:78` asserts exactly this.
- [agent] Anonymous 401/403 rejects IDOR findings, which are cross-principal by
  definition. An HTML-encoded echo on any route in the file rejects an XSS finding. A
  429 on a GET rejects CWE-400 findings, which are mostly ReDoS.
- No probe sets `baseline`, so `confirmed` cannot happen in production today, while
  `rejected` can. `grep baseline quarry/dynamic/probes.py` returns nothing. The README
  is literally true but reads as if probes record baselines.

- **Fix:**
  - A probe may reject only when it shows the request was handled: the finding's own
    route, the right method, a non-404/405 status, and a recorded control. Everything
    else is needs-review.
  - Carry-forward kills only on a Layer 3 deterministic rejection with a control.
  - Record the control the SQLi probe already sends (`probes.py:251`) as its baseline,
    then give each other probe one.
- **Done:**
  - `adjudicate_with_reason` rejects only with `handled is True`, a `baseline`, and
    `differs_from_baseline is False`. Otherwise it is needs-review with the reason
    `no control comparison recorded`. The `handled` flag is stored in the verdict's
    rationale JSON.
  - The timing probe reads the status with each sample. 404 or 405 is needs-review;
    a handled no-separation result records the absent identifier as its control.
  - The SQLi probe records its plain-value request as the baseline, so a SQL error
    differential can now reach `confirmed`. An empty control response still holds it.
  - `rejected-carry-forward` kills only on the latest verdict being a `dynamic`,
    `deterministic` rejection whose rationale shows a handled control. A statistical
    rejection, or one written before this change, is no longer carried forward.
  - The live DB has no rejected verdicts (its 2 verdicts are needs-review), so nothing
    stored changes meaning.
- **Still open:** the authz, rate-limit, XSS, command-injection and traversal/SSRF
  probes record no baseline or control. Their results are all needs-review until each
  gets one. Probes still pick routes from the finding's file, not the finding's own
  route; that needs the route map to resolve a line to a handler.

**Done 2026-11-05, the open part (merged in 1a534a1).** Every probe class now records
a control and can confirm and reject, and every probe decides only on the finding's own
route. Static routes carry their handler's line span, and `Route.encloses(path, line)`
picks the route whose handler holds the finding's line; on any other route a probe
records what it measured and leaves `differs_from_baseline` unset, so the verdict is
needs-review. A rejection also needs a parameter the handler is known to read. Authz
(anonymous) counts only a per-operation security requirement as declared protection
and never rejects; on the VulnLookup clone 146 of 400 routes carry the spec's
requirement and all 146 are spec-wide. Rate limit sends a lone request, then 20 back to
back in one curl run, and reproduces on sameness (`reproduces_when: same`). XSS pairs a
benign token with `"'><marker>`. Command injection uses `echo $((a*b))` and a replayed
`sleep 2`. Traversal reads /etc/passwd in the container. SSRF uses the target's own
root page as an internal-only canary. A live fixture run decided 12 of 12 cases as
designed. Merging it with item 17 needed one fix: replay counts a held control by the
direction-aware comparison, since a rate-limit confirmation does not differ from its
baseline. Still open: the timing probe has no baseline comparison, SQLi never rejects,
and a rate-limit rejection is not carried forward (the conservative side).

### 4. Needs-review counts as adjudicated [code]

`bump_producer_counts` (`db.py:110`) counts every verdict as an adjudication,
needs-review included. A producer probed 5 times with no signal reads as 0 of 5
confirmed, gets a -10 rank adjustment (`funnel.py:534`), and lands in the UI's
"known-bad" band. It has not triggered yet (there are 2 needs-review verdicts in the
DB), but it will on the first real validate run, since confirmed is unreachable (item 3).

- **Fix:** `n_adjudicated` counts only `confirmed` and `rejected`.
- **Done.** Also: the ledger was only recomputed by `quarry scan`, so verdicts from
  `quarry validate` did not reach it until the next scan. `run_validation` now
  recomputes it after writing verdicts.

### 5. The funnel runs once, but occurrences keep arriving [DB]

`funnel.run` refuses a second pass (`FunnelAlreadyRan`), which is right. But three
things add occurrences after it runs: a re-scan (`quarry scan 1 --only X`; nothing stops
a re-scan of a funnelled run), deep review (`research/runner.py:206`), and anything
added later. On run 1, 1,717 of 2,779 occurrences have no funnel event: 1,708 deep
candidates and 9 OSV findings from a re-scan. They are all "live". The run page says
"1983 live" next to a funnel table that ends at 266. Run 2 has the same gap: 232 of 552
occurrences have no funnel event. (Item 8 now shows this gap; it does not close it.)

[agent, checked against DB counts] The 1,708 live deep occurrences include candidates
whose quote is not in the source and candidates that were refuted. 3 of 1,940 deep
candidates survived refutation.

- **Fix:** make the funnel per occurrence, not per run. A stage acts on occurrences
  that have no system event from that stage yet. Re-running is then a no-op for old
  rows and complete for new ones.
- Add a Layer 2 stage that kills unverified quotes and refuted candidates. That keeps
  deep candidates out of triage until they pass their own gate.
- Refuse `quarry scan` on a run that already has occurrences from the same tool, unless
  told to supersede.
- **Done:**
  - `funnel.run` acts on fresh occurrences only (no non-operator funnel event yet).
    Already-funnelled live rows are context: a fresh duplicate merges into one, a
    fresh hit can cluster with one, and they count toward novelty, but they get no new
    events. `FunnelAlreadyRan` is gone; a pass with nothing fresh writes nothing.
  - A `layer2-gate` stage after quote-verify uses the digest's bar. Quote not in the
    source: deterministic kill. Refuted by every cross-family model that answered:
    heuristic kill. No refuter answered: defer, revived by a later pass once one has.
    Every refuter errored: defer, with that reason.
  - Deep rows wait while their research run is verifiably running, using the
    dashboard's `live_status` rather than the status column.
  - `quarry deep` runs a funnel pass when it finishes.
  - The run page derives each stage's remaining from the ledger, and the last row
    shows any gap from the live count as "unexplained" rather than hiding it.
  - `quarry scan` refuses a tool that already returned results for the run. A tool
    that failed or was skipped can be re-run. Supersede is not built.
- **Checked on a copy of the live DB** (SQLite backup, the real file untouched):
  - Run 1: 1,717 entered, 6 survive (4 OSV, 2 deep). The gate killed 1,693 (1,073
    quotes not in the source, 620 refuted) and deferred 12. Live goes 1,983 to 272.
  - Run 2: 232 entered, 1 survives. The gate killed 229 (107 quotes not in the source,
    122 refuted) and deferred 2. Live goes 271 to 40.
  - Ledger drift 0 on both. A second pass entered 0 on both.
  - The 3 deep survivors are the same 3 the Layer 2 digest reports.
  - Run 1's research row still says `running`; its pid is not alive and its last
    heartbeat was 2026-10-28. Without the liveness check its 1,708 candidates would
    never enter.
- **Was not done:** the real DB had not been funnelled, and the 14 deferred
  candidates whose refuters all errored had no re-refute path.
- **Done 2026-11-05.** The re-refute path (fd2fb4d): the refute pass asks a model again
  when its only record on a finding is an error, and `valid_refutations` counts only
  refuted and survives records, so an error now shows as a refuter error. Not run: it
  needs the local models and `quarry deep --resume <run>`, then a funnel pass.
  The live DB was funnelled (decision E) after a SQLite backup to
  `~/Library/Application Support/Quarry/backups/quarry-2026-11-05-before-funnel.db`
  (integrity ok) and a rehearsal on a copy that gave identical numbers. Run 1: 1,717
  entered, 6 survive, 1,693 killed and 12 deferred at the Layer 2 gate; live 1,983 to
  272. Run 2: 232 entered, 1 survives, 229 killed and 2 deferred; live 271 to 40.
  Ledger drift 0, `quick_check` ok. Opening the DB applied migration v9 (items 20, 21),
  so it is now at schema version 9. Rows whose latest event is a Layer 2 defer: 12 in
  run 1, 2 in run 2, 302 in run 3.

---

## P1: make silent failure loud

### 6. Per-tool scan outcomes are thrown away [code]

`ScanSummary.per_tool` (rc, seconds, records, skipped, error) is printed to the terminal
and never stored (`grep per_tool` finds only `cli.py:317`). A run where Trivy timed out
looks the same in the dashboard as a run where Trivy found nothing.

- Store it in `runs.manifest["scan"]`. Show it on the run page as a per-tool strip:
  ok, skipped, failed, note.
- Add invariants, checked at the end of `scan` and `funnel`, that fail the run loudly:
  - a tool whose evidence-capture rate is under 50% (this would have caught item 1);
  - a tool with records > 0 that lost all of them to deterministic stages;
  - an SCA tool with 0 records on a repo that has lockfiles.
- **Done:**
  - Each tool's outcome (ok, rc, seconds, records, skipped, error, note, and evidence
    captured out of located findings) goes into `manifest.scan.tools` as it finishes.
  - Health checks go into `manifest.health`, keyed by source and tool, and are
    printed by `quarry scan` and `quarry funnel`. Scan: a tool that failed; evidence
    captured for under half its located findings; osv-scanner with 0 results on a
    repo with lockfiles (worded as a question, since a clean result is possible).
    Funnel: a tool whose every new occurrence was killed by deterministic stages.
  - The run page has a per-tool table and a banner listing any health warning.
  - These warn; they do not change the run's status or the exit code. A real but
    clean osv-scanner result would otherwise fail a run.
  - Runs 1 and 2 were scanned before this, so they have no recorded outcomes.

### 7. Vulnerability DB age is not recorded [code]

`vulndb.status()` reports sizes only. A scan against a six-month-old Trivy or OSV
database says nothing. Record each DB's build time (Trivy's `metadata.json` `UpdatedAt`,
the OSV zip mtimes) in the run manifest. Warn in `doctor` and on the run page past a
threshold (7 days is my default).

- **Done** (working tree). `vulndb.built_at` reads Trivy's `metadata.json` `UpdatedAt`,
  the build timestamp in Grype's `import.json` archive name, and the oldest OSV
  ecosystem zip's mtime (a download time; OSV regenerates the zips continuously). Each
  carries the basis it was read from. `scan` stores the age of each database it used
  in `manifest.vulndb` and sets a `vulndb` health warning past `STALE_DAYS` (7) or
  when the build time is unknown. `doctor` and `db status` show build time and age. On
  2026-11-02 the three databases were 5.1, 5.9 and 5.0 days old.

### 8. The funnel table can disagree with its own links [agent, checked]

`cross-tool-cluster` writes `action="pass"` but adds to `sr.boosted` (`funnel.py:486,
491`), so on run 1 "boost 3" links to an empty set. The table is built from the manifest
snapshot (`web/queries.py:179`), so operator dismissals and later events never show.
Build it from `funnel_events`, using the manifest only for stages with zero rows, and
add a row for "arrived after the funnel". Add a test that every non-zero cell equals the
size of its linked set.

- **Done.** Counts come from the ledger. The manifest supplies stage order, zero-row
  stages and each stage's remaining at the time. Operator dismissals show as an
  `operator` row with a restored count. A new "arrived after the funnel" row links to
  `?arrived=1`, and the last row's remaining is the live count. Cluster events count as
  passed. Checked read-only against the live DB: every cell on runs 1 and 2 matches its
  set, run 1 ends at 266 + 1,717 = 1,983 and run 2 at 39 + 232 = 271. The "live after
  funnel" card is now just "live".

---

## P2: signal quality

### 9. Secrets in test paths are killed by path, not by value [DB]

`path-class` kills secrets under `test/` before `local-dev-fixture` can check the value.
On run 1 that was 38 Gitleaks hits. These look like test constants, but a real key
committed to `tests/` is a real leak, and it would die the same way. Exempt the
`secrets` class from the test-path rule and let the value check decide.

- **Done** (working tree). Checked: 38 path-class kills of Gitleaks hits on run 1, none
  on run 2. `path-class` no longer applies the test rule to the `secrets` class, and
  `local-dev-fixture` treats test paths as development paths, so a known placeholder
  under `tests/` is still killed on its value. The 38 existing kills stay in the ledger;
  the funnel does not re-score an occurrence it already decided.

### 10. CWE values are not normalised [agent, checked]

Opengrep's SARIF tags arrive as `CWE-22: Improper Limitation...`
(`scanners/base.py:174`). `_cwe_of` (`validate.py:122`) keeps the whole string, so no
Opengrep finding is ever selected for Layer 3. In the DB, every Opengrep CWE has the
long form. CWE-78 (what Bandit and Semgrep emit for command injection) is not in the
probe sets, so the CWE-77 probe effectively never runs.

- Normalise to `CWE-\d+` at ingest. Keep one equivalence map (78 to 77, 1333 to 400)
  shared by `DYNAMICALLY_TESTABLE`, the lens sets, and `report.py`'s CWE tables.
- **Done** (working tree). Checked: all 10 Opengrep producers with a CWE store the long
  form. New `quarry/cwe.py`: `normalise` at `upsert_producer` and again on read in
  `select_candidates` (so rows stored long are still selected), and `probe_class`
  (the equivalence map) in candidate selection, lens matching, the probes and the
  report tables. The stored CWE stays what the scanner said, so an advisory names
  CWE-78.

### 11. Dependency findings are sent to dynamic probes [DB]

Both verdicts in the DB are on `poetry.lock`: path-traversal and rate-limit probes
against an OSV finding, both "no route in the finding's file". Lockfile findings have no
route. Exclude the `sca-db` class from `select_candidates`, so it stops spending the
50-candidate budget.

- **Done** (working tree), using the funnel's own `independence_class`.

### 12. Routes miss mount prefixes [agent]

Static route extraction (`routes.py:29`) does not handle Express `app.use`, FastAPI
`include_router`/`APIRouter(prefix=)` or Flask `url_prefix`, so probes hit unprefixed
paths and get 404s. That feeds item 3. OpenAPI and crawl routes carry
`handler_file=""`, so `for_finding` only finds them through an exact key merge.
`crawl_routes` is still not wired into `run_validation`.

- **Done** (working tree). Static discovery is now two passes: read every file, then
  resolve each mount to exactly one file (an ambiguous target adds no prefix). Covered:
  FastAPI `APIRouter(prefix=)` and `include_router(prefix=)`; Flask `Blueprint(url_prefix=)`
  and `register_blueprint(url_prefix=)`, which replaces the blueprint's; Express
  `app.use`/`router.use` with a `require`, an `import` or a local `Router()`, nested.
  JS routes count only on `app`/`router`/`r` or a variable bound to `Router()`, so
  `axios.get("/x")` is not a route. `crawl_routes` now runs after the OpenAPI fetch.
  Not covered: Django `urls.py`, Starlette `Mount`, NestJS decorators, and prefixes
  built from variables rather than string literals.

### 13. Layer 2 integrity [agent, checked for 13b; rest agent]

- (a) `verify_quote` (`research/ensemble.py:491`) has no minimum length and accepts a
  match in any same-named file, so `}` verifies.
- (b) `family()` (`ensemble.py:93`) falls back to the name before `:`, so
  `qwen3-coder` and `qwen2.5-coder` count as two families, and Qwen refutes Qwen.
- (c) The prompt delimiters are fixed strings. Target file bodies can forge `=====
  THE CLAIM =====`. Use a random per-call delimiter.
- (d) The refutation record is built as `{"model": m, **json.loads(raw)}`
  (`runner.py:291`), so the model's output can overwrite its own identity.
- (e) Quotes and `raw_result` from Layer 2 skip `redact_in`, and the digest prints the
  quote verbatim. The secrets lens asks for exactly the lines that hold secrets.
- (f) A file larger than the context window is still admitted to a batch
  (`pack.py:311`). Refuse a unit that will not fit, and record model digests and the
  Ollama version for reproducibility.
- **Done** (working tree), all six:
  - (a) `MIN_QUOTE_CHARS` = 16 non-space characters, and a quote counts only in the
    named file; a same-named file stands in only when the named path does not exist
    and exactly one such file does.
  - (b) An unmapped model's family is the leading letters of its name, folded through
    an alias table (codestral, devstral and mixtral to mistral; codellama to llama;
    qwq and codeqwen to qwen). A fine-tune with a new name still needs a `FAMILY`
    entry.
  - (c) `new_tag()` per call; every header Quarry writes, including the pack's `FILE`
    headers, carries it, and the prompt says an untagged header is file content.
  - (d) `refutation_record` keeps only the schema's fields and writes `model` last.
  - (e) Title, quote, reasoning, attacker control and self-critique are redacted with
    the run's Gitleaks secrets before they are stored, and so are a refuter's reason
    and counter-quote. A secret Gitleaks did not find is not covered.
  - (f) A file over the unit budget is refused and named in the progress output and
    in `manifest.deep[<research id>].refused_files`, beside the Ollama version and
    each model's digest.
  - Existing `quote_verified` values were computed under the old rule and are not
    recomputed.

### 14. Smaller Layer 1 items [code]

- Grype's DB (2.1 GB in this plan's first draft; 3,358 MB on disk on 2026-11-02) is synced by `db sync`, and `grype`/`syft` are in the tool
  manifest, but there is no Grype adapter. See decision A.
- OSV severity is `high` for any CVSS v3 vector regardless of score
  (`tools.py:204`). Parse the score, or store `unscored`.
- OSV maps a refused source path to `"."` (`tools.py:200`) instead of dropping it,
  unlike every other adapter.
- `extract_evidence` reads with `read_bytes` (`taint.py:299`), which follows symlinks,
  in the unsandboxed parent. Tier 1 lets scanners write anywhere in the run dir,
  including `src/`. Deny `file-write*` under `RUNDIR/src` in `quarry-tier1.sb`, and open
  with `O_NOFOLLOW_ANY` as `read_capped` already does.
- `finding_id` hashes the raw target string, so `o/r` and `https://github.com/o/r` are
  different findings and verdicts do not carry. Canonicalise the target at `start_run`.
- Clustering buckets by `line // 10`, so lines 9 and 10 never cluster. `issues.target`
  is written with the file path (`funnel.py:474`).
- Checkov and Trivy honour inline `checkov:skip` / `trivy:ignore` comments in target
  files. This is not verified; check whether either one reports suppressed results in
  SARIF before deciding whether D14 needs a workaround.
- **Done** (working tree), except Grype:
  - OSV severity is the band of osv-scanner's own `max_severity` for the alias group
    (`unscored` without one). A refused source path is dropped.
  - `canonical_target` at ingest: every GitHub spelling becomes `owner/repo`, case kept
    so existing runs keep their ids.
  - Clustering groups lines within `CLUSTER_SPAN` (10) of a group's first line, reuses
    an earlier pass's issue id, and writes the repository into `issues.target`.
  - `extract_evidence` opens with `read_capped` (`O_NOFOLLOW_ANY`) under the resolved
    root. `quarry-tier1.sb` denies writes under `RUNDIR/src` and `RUNDIR/quarantine`.
    All seven scanners were run for real under the new profile on a small fixture and
    all returned ok, with the clone's file list unchanged.
  - Measured with trivy 0.76.1 and checkov on the same fixture: Checkov still
    reported both checks a `checkov:skip` comment named. Trivy obeyed
    `#trivy:ignore:AVD-DS-0001` and dropped DS-0001 from its SARIF with nothing in
    its place, and `--show-suppressed` did not bring it back. There is no flag to
    stop it, so `scan` now lists files that carry `trivy:ignore` as a Trivy health
    warning, and the README's "never obeyed" claim names the exception.

---

## P3: dashboard

From the UI review [agent], with the items I confirmed marked.

1. **Scope pages to a run.** The nav drops the run, so "Triage" from run 1 opens run 2.
   Use `/runs/{id}/triage|validation|advisories`, with the pipeline strip on each page.
2. **Show deep candidates in triage only after they pass their gate** (item 5), and
   link the triage detail to its `/research/{id}` record both ways. Today a deep
   occurrence shows no model, quote check or refutation.
3. **A per-tool health strip on the run page** (item 6), plus DB age (item 7). The scan
   card counts `deep` as a tool ("8 tool(s)").
4. **Honest dismiss semantics** [checked]. "Dismiss for this repo" and "Dismiss
   everywhere" both kill only this run's occurrences (`web/app.py:546`), and the next
   scan brings the producer back. Key repo dismissals on the target, add the note field
   the ledger already supports, and let restore undo the funnel's
   `producer dismissed` kill.
5. **Keyboard:** `d` still submits while the console is hidden below 720px (the form
   stays in the DOM). `j/k` do full page loads and lose scroll. Move the columns to
   htmx swaps with `hx-push-url`, and gate the key handler on viewport width.
6. **List the deep-review digest** with the advisories. It is on disk
   (`reports/2/2-deep-review-candidates.md`), but the UI says "0 drafts".
7. **Research resume** can start two workers on one run, since nothing locks before
   the spawn. Claim the run in the DB first.
8. **Show the CLI-only stages.** Doctor, db sync, target scores (the `targets` table
   appears nowhere), ingest, scan, validate and report have no UI. Each needs at least
   a status and a copyable command.
9. **Smaller:** the band-filter empty state says "every finding was suppressed"
   when 1,983 are live. `_INVISIBLE` (`app.py:238`) is narrower than `taint._CONTROL`
   [checked]; low impact, since stored text is already scrubbed. htmx 2 does not swap
   4xx/5xx, so the error branches never show. A stopped research run's progress panel
   refetches on every click.

The dashboard's own security held up: CSRF token plus Origin check, a Host allowlist,
no state-changing GETs, no `|safe` on stored data, and advisory reads confined to
`reports/`.

**Done 2026-11-05, items 1 to 9 (merged in 233a3c5).** Triage, validation and
advisories live at `/runs/{id}/...`, each with the pipeline strip, and the old `?run=N`
URLs redirect. Triage lists a deep candidate only after a funnel pass has seen it and
states the held count; the detail pane and the research card link to each other. The
run page shows each database's age at scan time, and the scan card no longer counts
deep as a tool. Repo dismissals are keyed on the target through a producer-level ledger
row that later funnel passes honour, the note field is on the form, and restore undoes
the funnel's `producer dismissed` kills; no row is deleted. Below 720px the key handler
refuses, row moves are htmx swaps with `hx-push-url`, and htmx's localStorage history
cache is off, since it would have stored findings and the form token. `quarry report`
records the deep-review digest in the run manifest and the advisories pages list it.
Resume claims the research run in the database before it spawns. A Setup page and a
per-run terminal table give each CLI-only stage a state and a command to copy, with no
buttons that run anything. Item 9's four defects are fixed. After all six branches were
merged, 15 pages rendered 200 against a copy of the post-funnel live DB. (`quarry deep
--resume` from a terminal takes the claim since item 26, and the parallel race test for
the claim was added on 2026-11-06; see item 26.) Open: decision J below.

---

## P4: code health

- `web/app.py` is one ~600-line `create_app` closure with SQL inline in routes. Split
  it into routers, move reads to `queries.py` and writes to a separate module, and share
  Jinja macros for the status pills.
- Missing tests that matter, in order:
  - Checkov output parsing;
  - hostile compose documents;
  - probe rejections against 404/405 responses;
  - the per-occurrence funnel;
  - `valid_refutations` with a forged `model` key;
  - curl path normalisation (`--path-as-is`).

**Done 2026-11-05, the split (merged in 233a3c5).** `app.py` now only assembles the
app, with `security.py`, `present.py`, `context.py`, `writes.py` and `routes/` around
it; inline reads moved to `queries.py`, every write to `writes.py`, and one Jinja macro
serves each status-pill vocabulary. Checked on its branch: 104 of 104 rendered pages
identical before and after on a DB copy.

**Done 2026-11-05, the tests (merged in 40650cd).** All six, in six new test files (123 tests).
Three exposed real bugs, fixed in the same commits. `rel_or_none` raised on a `uri`
that was not a string, so one malformed SARIF entry failed the whole tool instead of
costing one finding. `valid_refutations` counted every stored record, so a pre-fix
record naming the author's own family as `survives` defended a candidate both real
cross-family refuters had refuted; only records naming another family's model now
count. curl's dot-segment removal sent the traversal probe's
`/files/../../../../../../etc/passwd` as `GET /etc/passwd` (measured with curl 8.7.1
and in the curlimages/curl:8.11.1 sidecar); every probe request now passes
`--path-as-is`. Hostile compose files also go through the real `docker compose config`
and through compose's re-reading of the hardened file. Every probe lens is swept
against 404, 405 and no answer, plus one full validate loop. The funnel is checked over
four passes with arrivals between them.

Side findings from that work, not acted on: a structurally damaged SARIF result (a
location or message that is not a mapping) fails the whole tool, loudly, rather than
one finding; a non-integer `startLine` would raise in `extract_evidence` inside
`_persist` (read from the code, not run); a refuter's `{"verdict": "error"}` record is
not counted in `refuter_errors`, so the gate's "N refuter error(s)" can say 0 when
every refuter errored; and a pre-fix record that names the other real refuter cannot
be told from a genuine one.

---

## Order of work

1. Items 1, 4, 8: small and local, and they fix numbers that are wrong today.
2. Item 2's interim gate on `validate`, then item 3. Both stop false kills and unsafe
   runs before any more Layer 3 data accumulates.
3. Item 5 (per-occurrence funnel plus the Layer 2 gate), then item 6. Together they
   make the run page's numbers add up.
4. Item 2's full compose rebuild.
5. P2 items 9 to 13, then P3, then P4.

## Decisions for Jerry

- **A. Grype.** Add an adapter, or stop syncing its DB (3,358 MB on disk). My default: stop syncing
  it. It is the same `sca-db` class as OSV and Trivy, so `sca-merge` would fold its
  findings into theirs. It adds a network step and disk for little new signal.
- **Settled 2026-11-05.** A: Grype is no longer synced (08be19b); a copy on disk is
  left for Jerry to delete, and `db status` names its path. Secrets are exempt from
  path-class's generated-path rule (f926f25). Opengrep versions other than 1.27.1 get a
  health warning (d41e805). The cross-user probe (D) and funnelling the live runs 1
  and 2 (E) were approved; their results are recorded where they are done.
- **F. The Layer 2 refuter. Done 2026-11-05.** Item 21's replay measured
  0 of 7 plants surviving refutation, every kill resting on a check the code does not
  have. A `refuted` verdict now has to carry `counter_file`, `counter_quote` and
  `guard`, and `research/grounding.py` checks that the quote is in the file and the
  guard's own line is on the claim's path (its definition, one it names, one that names
  it, or module level; never an import). An ungrounded refutation is asked once more
  with the reason; a second failure is counted in `n_unsupported` (migration v10), not
  as a vote or an error. A verified claim every refuter tried and failed to rebut is
  kept as "not rebutted" by one bar, `ensemble.KEPT_SQL`, which the funnel gate (a
  `pass` event that says so), the digest, `deep-survivors` and the dashboard share.
  Measured in docs/LEGA-CORPUS.md: quote placement alone (F1) left 5 and 6 of 7 plants
  missed, because the refuters quoted the claimed code back with the same invented
  reason; with the guard (F2), 2 of 7 in both runs (the hunt's misses, plus T1 with
  intent on), at the price of 1 and 2 of 5 verified claims on no plant kept for a
  human. Not addressed: a real guard that does not apply (`@login_required` against
  path traversal) and a "guard" that guards nothing still kill, and no refuter
  answered `survives` in 62 refutations; the prompt's "Default to `refuted`" mandate is
  unchanged (decision K). Records written before F carry no grounding and count as
  they did.
- **K. The refuter's kill mandate. Tried 2026-11-05 and reverted.** After F, every
  remaining plant kill on the replay rests on a guard that exists but does not answer
  the claim. Dropping "Default to `refuted`. Most findings are wrong." and rerunning
  the same two replays made it worse: 3 of 7 plants missed after refutation with route
  intent off (2 of 7 under F) and 5 of 7 with it on (2 of 7 under F). The second is
  three plants, outside the one-plant noise. One refuter answered `survives` in 32
  refutations, so the line was not what kept the refuters from defending. The kills
  were the same two kinds as under F (a real guard that does not apply, such as
  `login_required` against an admin-only reset; a "guard" that guards nothing). The
  line is back. What is left needs a check of whether the guard answers the attack,
  which no location rule can do.
- **M. The guard must answer the claim's attacker. Done 2026-11-06.** A guard that
  passes F's placement rule must also be the right kind of check for the attacker the
  claim describes (`research/relevance.py`, called from `grounding.ground`, and stated
  in the refute prompt): on the authorization lenses it must check who is asking (a
  role or permission check, or a comparison with the requesting user, directly or in a
  helper it calls), and a login check alone answers only an unauthenticated attacker;
  on the data lenses it must name the input the claim says the attacker controls, and
  an existence check does not count; on every lens it must do something. A guard that
  fails is retried once with the reason, then counted as unsupported. Measured in
  docs/LEGA-CORPUS.md: on the two replays refutation lost no plant the hunt had found
  (F2 lost T1 with route intent on), at the price F2 paid, two claims on no plant kept
  per run. No refuter answered `survives` in 29 answers, and 23 of the 29 refutations
  were finally discarded, so most verified claims now reach a human as "not rebutted";
  the volume that means on a real repository is not measured yet.
- **L. `uncertain` deferred a claim for good. Done 2026-11-05.** An `uncertain`
  answer counted as a refuter error, and `--resume` re-asks only failed calls, so a
  claim whose refuters were all uncertain stayed deferred at the gate with nothing to
  revive it. None had happened yet (0 of 3,026 live answers; 0 on the replays), but
  F's evidence rule makes "I cannot quote a guard" a likelier answer. It now counts in
  `n_unsupported`, so the claim goes to a human as "not rebutted".
- **J. Dismissal reach.** Neither "dismiss for this repo" nor "dismiss everywhere"
  touches findings already live in other existing runs; both apply to later funnel
  passes. A repo dismissal can be withdrawn from any run of the target, the corpus
  switch only from the run that set it. The default taken: leave other runs alone.
- **G. Run 1's two deep survivors. Done 2026-11-06.** Both recorded `intended`, by
  Claude at Jerry's request (`actor` "claude-opus-5.5 for jgamblin"), after reading
  the code at efac9d67. #1: `GET /cve-id/:id` is documented as accessible to all, and
  `getCveId` gives callers outside the owning org and Secretariat only `cve_id`,
  `cve_year`, `state`, and `owning_cna` plus `dateUpdated` for IDs that are not
  RESERVED (`owning_cna` is redacted for RESERVED ones). #141: `reset_secret` exists to
  issue a new key; the repository stores only its argon2 hash and returns the
  plaintext once, and the route documents the 200 response as the new API key. Each
  note says what it does not cover (#1: the redaction condition for authenticated
  users; #141: whether the reset's access checks hold).
- **H. Disk. Done 2026-11-06.** The Grype database (`vulndb/grype`, 3,358 MB) and
  `backups/quarry-2026-11-05-before-funnel.db` were moved to the macOS Trash, not
  deleted; the space comes back when the Trash is emptied. `db status` and `doctor`
  report Grype as absent and still run. The grype binary is still installed. Kept:
  `quarry-2026-11-05-before-restart.db` and `quarry-2026-11-06-before-granite.db`, the
  rollback points for the restart and item 27. Also seen then: the dashboard's
  database panel marked a database with no age as stale, so Grype still showed there
  as stale, as it already did at 9.6 days old, though nothing reads it.
  **Done 2026-11-06.** `queries.vulndb_status` now calls a database stale only when a
  scanner reads it (`vulndb.DB_OF_TOOL`) and its age is unknown or past 7 days. A read
  database whose directory is not on disk is `missing`, shown as an alarm pill, which is
  louder than the stale pill it had before. A database no scanner reads shows "not
  used", or "absent, not used" when its directory is gone, and is never stale, at any
  age. Checked by a new test in `tests/test_web_dashboard.py` over an empty database
  directory, then Trivy 1 day, OSV 20 days and Grype 30 days old, then Trivy with no
  metadata; without the change it fails on Grype being stale. The Setup page test's
  expectation for an empty directory changed from 3 stale pills to 2 missing (Trivy,
  OSV) and Grype absent and not used. Against the live database directory (read only)
  the panel reads Trivy and OSV 0.6 days old and Grype absent, not used. Not changed:
  the run page's table of databases at scan time, which lists only databases a scanner
  read during that scan, and `quarry db status`, which has no stale label but still
  prints any age past 7 days in red, a present Grype database's included.
- **I. Re-refute. Superseded 2026-11-06 by the hard reset:** the runs it concerns are
  archived rather than re-refuted (Jerry, 2026-11-06: abandon the current runs and start
  over once the plan is built). The text below is kept as the record.
  `quarry deep --resume <run>` and a funnel pass would give the
  deferred Layer 2 rows (12, 2 and 302 in runs 1 to 3) their missing verdicts, under
  decision F's rule. It runs the local models for a while; not started. It does not
  revisit kills already made: in the live DB, 620 verified claims in run 1 and 122 in
  run 2 stand refuted with no defence, and in 515 and 95 of them no refutation carried
  a counter_quote (read-only query, 2026-11-05). `--resume` does not re-ask a model that
  answered, and the funnel does not revive a killed row, so applying F to those needs
  new code (re-ask records that have no `grounding`, and resurrect a gate kill whose
  vote changed).
- **B. Gate `quarry validate` now.** Settled: the gate shipped in 97f7175 and is
  removed again now that item 2's rebuild is in.

---

## Layer 3 against a real target: VulnLookup, 2026-11-03

Measured on a shallow clone of vulnerability-lookup/vulnerability-lookup at a9c6edf
(1,130 files). Before this batch, `quarry validate` could not get that target to a
first probe, for five separate reasons.

1. **Every build failed closed.** The root Dockerfile runs `apt-get`, `pipx install
   poetry` and `poetry install` in RUN steps, and builds had `network: none`. Most real
   Dockerfiles look like this.
   - **Done.** `quarry validate --build-network` (`DockerRuntime(build_network=
     "default")`). `host` is refused. The build still gets the scrubbed env, no
     registry auth, no `ssh` or `secrets`, and the running stack stays on the
     internal network. Residual risk, stated in the README: RUN steps can reach the
     internet, the LAN and the Mac through `host.docker.internal`. The run page shows a
     `build-network` warning and the manifest keeps `validate.provisioning`. Builds now
     get their own 1,800 s timeout; they shared the 300 s `up` budget.
2. **`env_file: .env` with no `.env` in a fresh clone.** `compose config` refused the
   file. The project ships `.env.sample`.
   - **Done.** Interpolation reads `.env`, or else `.env{.example,.sample,.dist,
     .template}`. A missing `env_file` points at its sample, or is marked
     `required: false` when there is none. The staged copy lives outside the clone and
     resolves its relative paths through `--project-directory` (checked with the real
     `compose config`). Both show on the run page.
3. **The probe address was the datastore.** `config` sorts services, and kvrocks
   publishes 10002, so `_entrypoint` picked `kvrocks_master:10002` over
   `vulnerability_lookup:10001`. A service built from the clone now wins.
4. **Flask-RESTX routes were not extracted.** `@ns.route` on Resource classes read as
   Flask GETs with no prefix. Now: `Namespace(name, path=)`, `Api(host, prefix=)` with
   nested parentheses, `add_namespace(ns, path=)`, multiple paths per decorator, and
   verbs from the class's own methods. Flask converters (`<string:x>`) normalised to
   `{}` as two parameters, so they never merged with OpenAPI, and the probes built
   `/u/11` from `/u/<int:uid>`. One `PATH_PARAM` pattern now serves both.
5. **The committed spec was never read.** `docs/_static/files/swagger.json` is three
   levels down, and Swagger 2 `basePath: /api` was ignored. Specs are now found to
   depth 4 outside test and example trees, `basePath` and the OpenAPI 3 server path are
   applied, and the served-spec fetch also tries `/api/swagger.json`.

6. **The sample's placeholder crashed the app.** `.env.sample` ships
   `INSTANCE_UUID=set_instance_uuid`; the build bakes it into `generic.json` and the
   website dies on import ("badly formed hexadecimal UUID string"). **Done:** `--env
   KEY=VALUE` (repeatable) replaces a target variable in the interpolation file and in
   every service environment that already declares it. COMPOSE_/DOCKER_/BUILDKIT_/
   BUILDX_ keys and values with line breaks are refused; the manifest keeps the keys,
   not the values.
7. **The 2g memory cap OOM-killed the web server.** VulnLookup runs 49 preloaded
   gunicorn gevent workers and all its feeders in one container. The cgroup showed
   `memory.current` at the 2 GiB cap and `oom_kill 53`, and no gunicorn left.
   **Done:** `--memory` (default still 2g), validated as a size.

**Result.** `quarry validate`'s runtime, called with `--build-network --memory 6g --env
INSTANCE_UUID=<uuid>`, built the stack, brought it up healthy in 51 s, and from the
isolated sidecar: `GET /`, `/api/`, `/api/swagger.json` and
`/api/vulnerability/CVE-2024-3094` all returned 200; the served spec gave 151 routes, 146
merged with static ones; the crawl found 20; the sidecar's own egress attempt failed
(curl rc 6, no DNS); teardown ran. This was the runtime driven directly from a script on
a scratch clone, not a full `quarry ingest/scan/validate` run, so no candidate was
probed and no verdict written.

On the VulnLookup tree: API routes 136 to 160 (now with PUT/POST/DELETE and the `/api`
prefix), committed-spec routes 0 to 155, static routes merged with the spec 0 to 137.

**Still open, VulnLookup-specific:**

- The spec's global `security: [{apikey: []}]` marks every operation as protected,
  including the public read API. The authz probe has no control yet, so it cannot
  confirm today. When it gets one, a spec-wide requirement with no per-operation
  override must not count as "this route is protected".
- A booted instance has an empty kvrocks. The feeders need the internet at run time,
  which the internal network denies by design. Probes that need a real record will see
  404s, which are needs-review, not rejections.
- Probes are anonymous only. Cross-user authz on comments, bundles and sightings
  needs two test accounts.

---

## Layer 3 seeding: make a booted target testable (2026-11-03)

A probe is only as good as the state it probes, and a booted VulnLookup instance is
empty and anonymous. Added a seed engine that runs the target's **own documented
operator commands** inside the already-contained instance, opt-in by name
(`quarry validate <run> --seed <name>`), the way an operator stands up a staging box.
Quarry adds no data itself and reaches into no datastore directly.

- `DockerRuntime.service_exec` execs a command in one of the target's service
  containers (not a sidecar), so a setup step reaches the target's database on the
  internal network and nothing beyond it.
- `quarry/dynamic/seed.py`: `SeedRecipe` / `SeedStep`, a registry, and `run_seed`.
  A step may capture a value from a command's output (an API key) into in-memory
  `credentials`, and `{password}` in an argv is replaced per run with a generated
  secret so nothing is hard-coded. A failed optional step is a recorded gap on the run
  (`health.validate.seed`), never fatal; a required step raises.
- `run_validation(..., seed=recipe)` runs the recipe after the target is healthy and
  before probing, merging its `param_values` and `credentials` onto the RunningTarget.
- The `vulnlookup` recipe creates `quarry_admin` and `quarry_user` with the project's
  `create_admin` / `create_user` Flask commands, reads both API keys with
  `user_get_api_key`, and sets `vulnerability_id=CVE-2021-44228` for the probes.

**Limitation, stated honestly:** VulnLookup's records come from the feeders, which need
the network at run time, so offline record population is not available through its CLI.
Seeding establishes the accounts and a known id; whether a given endpoint serves a real
record still depends on the feeders. An empty instance also returns 200 (not 404) for a
CVE lookup, so per-route empty-vs-seeded behaviour must be checked before trusting a
verdict.

**Done 2026-11-05 (decision D, merged in 1a534a1).** The cross-user probe is built.
A recipe declares its per-user resources (`seed.CrossUser`, `OwnedResource`). The
`vulnlookup` recipe also creates `quarry_user2`, so sightings and comments are tested
between two commenter peers; bundles are the admin's record addressed by
`quarry_user`. The owner creates two canary records through the target's own API in
the contained instance; the anonymous client is the control and the owner's own
request the baseline; delete and modify are judged by effect; both canaries are
deleted afterwards and the verdict names them, never a key. A live fixture run
confirmed a cross-user delete on a buggy handler, rejected it on an ownership-checked
one, and left neither canary behind. Not yet run against a live VulnLookup: its paths
and bodies were read from source and pinned against the static extractor.

**Was still open (needed Jerry's decision):** the authenticated cross-user probe that *uses*
the two accounts and their keys. The keys are captured and on the RunningTarget; no probe
reads them yet. That probe body is new, measured, read-only logic and is deferred for a
go-ahead.

---

## Lessons from the Harness Engineering workshop book, 2026-11-05

Source: Graham Helton and Ryan Basden, *Harness Engineering* workshop book
(grahamhelton.github.io/harness-engineering-workshop-book). These are the places where
the book names a failure Quarry still had. Items 15 to 24 are all done; each says
where under its own heading.

### 15. Opengrep silently skips test, vendor, build and dist trees [measured, DB]

With no `.semgrepignore`, Opengrep applies its built-in default ignore list. Quarry
quarantines the target's own `.semgrepignore` (D14), so the default list applies to
every scan. Measured with opengrep 1.27.1 and Quarry's exact flags on a five-file git
fixture (`app/`, `tests/`, `vendor/lib/`, `build/`, `dist/`, each holding the same
`os.system(input())`): only `app/a.py` was selected or matched.
`--x-ignore-semgrepignore-files` selected all five. An empty `.semgrepignore` at the
scan root did not change the result.

Live DB, read-only: 0 of 904 Opengrep occurrences across runs 1 to 3 have a path under
`test/`, `tests/`, `vendor/`, `build/`, `dist/`, `node_modules/`, `*_test.go` or
`*.min.js`. Bandit reported 687, 250 and 4,982 occurrences under `test/` or `tests/`
in the same three runs, so those trees exist and hold code.

This is the fourth silent loss of tool output (after `poetry.lock`, OSV GIT and the
Checkov paths). It happens before the ledger, so the funnel's own `path-class` policy
never sees these files and the run page cannot show the gap.

- **Fix:** pass `--x-ignore-semgrepignore-files` and pin the Opengrep version, since
  the flag is internal. Record per-tool file coverage: the set Opengrep selected
  (`--x-ls`, also internal) against `git ls-files` filtered to the languages the rule
  packs cover, stored in `manifest.scan.tools`, with a health warning on any gap.
- **Test:** the fixture above as a live test that fails on the current argv.
- Per-file `--timeout 20` and `--max-target-bytes` also drop files. Check whether
  Opengrep reports those in SARIF before trusting a clean coverage number.

**Done 2026-11-05 (b707e82).**

- `tools.Opengrep` passes `--x-ignore-semgrepignore-files`. The same invocation now
  also writes `out/opengrep.targets.json` (`--json-output`) and runs `--verbose`
  instead of `--quiet`, because without `--verbose` the JSON omits the skip list.
  `--x-ls` was not needed: the JSON report lists files scanned and files skipped with
  a reason, at no extra run.
- Timeouts and size limits are reported, measured on 1.27.1. A file over
  `--max-target-bytes` appears as `exceeded_size_limit`. A per-file timeout appears in
  `errors` as `Timeout` and in the skip list as
  `analysis_failed_parser_or_internal_error`. After 3 timeouts on one file
  (`--timeout-threshold`) Opengrep stops running every remaining rule on it. A
  generated 1.1 MB Python file with 6,000 Flask handlers, each calling `os.system` and
  `subprocess` with `shell=True`, returned 0 findings from the python tree. That run
  used `--timeout 1` to force the case; Quarry uses 20, so on real targets it needs a
  slower file. The only record in SARIF was `toolExecutionNotifications`, which
  Quarry did not read.
- `base.Coverage` carries scanned paths, skipped paths by reason, error counts, and
  invocations that wrote no report. The per-tree fallback merges them across trees.
  The orchestrator stores a summary in `manifest.scan.tools.opengrep.coverage` and
  compares it with the tree. The denominator is every file with a source extension
  (`orchestrator.SOURCE_EXTS`), walked without following links, with `.git` the only
  directory excluded. A file the tool neither scanned nor reported skipping is
  counted as `unexplained`. The installed pack scanned one file of every extension in
  that list, so the list undercounts rather than invents gaps. `git ls-files` is not
  run from Tier 0: ingest's fresh clone has no untracked files, and the orchestrator
  does not run commands in the target's tree.
- Health warnings for any skip reason, any rule error, any unexplained file, and any
  invocation with no report. The last one doubles as the canary for the internal flag:
  if a later Opengrep drops it, the skips reappear as warnings rather than as silence.
- Found while testing: when every rule tree failed, the per-tree fallback returned
  `ok=True` with a note. Opengrep 1.27.1 rejects `--exclude-minified-files` although
  its help lists it, and adding it made all 25 tree runs exit 2 with no output. That
  now returns `ok=False` with "every rule tree failed", and coverage reports 71 of 71
  source files unexplained.
- Live check on a `--depth 1` clone of Quarry's own HEAD, full pack, old argv against
  new: findings 77 to 143, with `tests/` going from 0 to 45. Files scanned rose from 88
  to 123. Wall time rose from 24 s to 110 s. The 4 new per-file timeouts were all on
  two vendored bundles (`htmx.min.js` 3, `alpine.min.js` 1), which also produced 21
  findings. Minified files stay in the scan on purpose. `path-class` already kills
  `*.min.js`, vendored and test paths for SAST tools, as recorded and reversible
  ledger events, which is where D8 puts suppression. Only the scanner's silent drop
  is removed.
- What this does not change: most of the newly visible test and vendor hits will be
  killed by `path-class` as before. The difference is that they now exist in the
  ledger and on `/killed`. Opengrep's secrets-class rules are exempt from the
  test-path rule, so those hits in `tests/` now reach `local-dev-fixture`. Code under
  `build/` and `dist/` that is not minified matches no `path-class` pattern and now
  survives to the later stages.
- Tests: 7 new. They cover the argv, a live Tier 1 scan of the fixture layout plus a
  file over 2 MB (it fails on the old argv: 1 of 7 files found), report parsing
  through the taint boundary, per-tree merging, all trees failing, the manifest and
  health output, and a skipped directory explaining the files under it. The suite
  collects 605 and passes 602, with 3 skipped because setuptools is absent.
- Still open: the manifest records the Opengrep version, and nothing refuses a
  different one. The canary above is what catches a change in the flag's behaviour.

### 16. Readiness accepts any HTTP response [code]

`_await_health` (`dynamic/runtime_docker.py:821`) returns on any 2xx to 5xx status
from the chosen entrypoint. A reverse proxy's 502 or 503 while the app still boots
passes, and so does any HTTP service on that port that is not the target.

- **Fix:** readiness is a known route from the clone's own route map (static or the
  committed spec) answering something other than 404, 405 or 5xx, or the served spec
  matching the committed one. Store the request, status and body hash in
  `manifest.validate.readiness` and refuse to probe without it.

**Done 2026-11-05 (aec8c1a).** Readiness now needs an answer below 500 at the base URL,
then one of the clone's own parameter-free GET routes (committed spec first, then
static, from `validate.readiness_paths`) answering with something other than 404, 405
or 5xx. The request, status and body sha256 go to `manifest.validate.readiness`, with a
random path's answer beside it; when the two match, the route did not tell the app from
a catch-all, and the run page warns. No such route, or none answering before the
deadline, raises and nothing is probed. Measured live on Docker 29.9.2 with the
containment test's `http.server` target: `GET /` 200, random path 404. The served-spec
comparison in the plan was not built; the committed spec's routes are among the
candidates instead. Not checked against VulnLookup, whose build takes about 30 minutes.

### 17. A confirmation is one observation [code]

`reproduced=True` comes from a single request, and `determinism` is set by the probe
type, not measured. The advisory then calls it "a measured, reproducible observation"
(`disclosure/report.py:347`). The book's rule: take the one request that showed the
effect, reset the environment, and run it again under only those conditions before
updating the research state.

- **Fix:** before writing `confirmed`, replay the confirming request and its control
  (my default: three times in the running instance, then once after restarting the
  target service) and store every replay. If any replay disagrees, the verdict is
  needs-review with the reason `did not replay`.

**Done 2026-11-05 (dae40c2).** A probe that confirms runs again, attack and control
together, three times in place and once after `DockerRuntime.restart` restarts the
entrypoint service and waits for readiness again (datastores keep seeded accounts).
Every replay is kept in the rationale as `replay` {attempts, reproduced, control_held,
after_restart, held, runs}. One disagreeing replay, or a failed restart, gives
needs-review with reason `did not replay`. A verdict with no replay record is left as
measured once. Tested with scripted probes through `run_validation`; not run live.

### 18. Carry-forward has no reopen condition [code]

`rejected-carry-forward` kills on `finding_id`, which hashes path, producer and the
flagged line's content. The verdict's rationale stores request, response and control,
but not which probe decided, the probe's code version, the route and method, or the
runtime conditions (seed recipe, `--env` keys, image digests). So a rejection outlives
a change to the probe that made it, and a change to the handler around an unchanged
flagged line does not reopen it. The kill reason says "symbol content unchanged", but
only the flagged lines are compared.

- **Fix:** store probe id, a hash of the probe's source, route, method and runtime
  conditions in the rationale, plus the occurrence's evidence `blob_sha` (the ±40-line
  window is already content-addressed). Carry forward only when probe hash, route and
  blob all match; otherwise reopen and say which one changed. This is conservative: an
  unrelated edit inside the window also reopens. Correct the kill reason text.

**Done 2026-11-05 (dae40c2).** Verdicts store `probe` {id, source_sha of the probe
module, method, route, evidence_blob} and `conditions` {seed, env_keys, readiness
request, build_network}. The funnel carries a controlled rejection forward only while
the probe module's sha and the occurrence's evidence window both still match, else it
reopens; a rejection without that identity reopens. The kill reason names the run,
probe and route. Hashing the whole probe module is deliberately coarse: any probe edit
reopens every rejection, which costs a re-probe, never a missed finding. The live DB
holds 2 verdicts, both needs-review (checked today), so nothing stored changes.

### 19. Advisories omit conditions and limits [code]

`render_report` has no section for the conditions a maintainer needs to reproduce:
the seed recipe and the accounts it created, `--env` overrides (VulnLookup needed
`INSTANCE_UUID` replaced to boot), `--build-network`, memory, and the compose service.
It has no limitations or weakest-link section, no prior-advisory check against the
local OSV data, and no check that the default branch HEAD is still affected; it
reports the observed commit only. Severity comes from a per-CWE table, which is a
class prior, not demonstrated impact.

- **Fix:** add Conditions, Limitations and weakest link, and Prior advisories checked
  (a miss there does not show the issue is new). Check HEAD before drafting. Label
  severity as a class default until a human sets a vector.

**Done 2026-11-05 (merged in f7fe893).** Advisory drafts now have a Conditions
section: commit, route and method, probe id and source hash, anonymous or seeded role,
seed recipe, `--env` names, build network, memory, .env source and compose service.
Each comes from the verdict's `replay`, `probe` and `conditions` keys when present and
from the run manifest otherwise, marked "recorded for the run" when taken from the
manifest and "not recorded" when absent. `run_validation` now records `validate.seed`
and `validate.service`. Severity is labelled a class default, and a separate Confidence
section comes from the verdict and its replay counts. Without replay evidence the draft
says the result was observed once and was not replayed; the "measured, reproducible
observation" line is gone. Limitations names one weakest link. Prior advisories are
searched offline in the local OSV zips by package name and repository URL: measured on
the live copy (283,287 records), 3.2 to 3.4 s per lookup; django matched 339, and the
three targets Quarry has run matched none. SECURITY.md presence is stated. HEAD is not
re-checked, because the clone is depth 1 and there is no network, and the draft says
so. Credential headers and credential-shaped query values in the evidence are redacted.
Still open: a HEAD re-check, and a real package name for the OSV name match in place of
the repository name. No real `quarry report` was run: the live DB has no confirmed
verdict.

### 20. Layer 2 has no record of intended behaviour [file]

Run 1's deep-review export (`work/survivors-run1-review.md`) kept 2 of 1,708 raw
findings. My read of both is that they describe deliberate behaviour: `GET
/cve-id/:id` runs `mw.optionallyValidateUser` and has an explicit unauthenticated
branch that returns redacted data, and `reset_secret` returns the new secret to the
caller who asked for it. These are my reads, not recorded verdicts. The book's point:
the model needs the project's documented rules and records of earlier pitfalls.

- **Fix:** give the authz lens and the refuter the route's declared access
  (per-operation OpenAPI `security`, the middleware names on the route) as stated
  intent. Store a human verdict on each deep survivor (`intended`, `real`, `unclear`,
  with a note) and have the next deep run on that target read it. Treat the spec as
  evidence with limits: VulnLookup's global `apikey` requirement over-declares.

**Done 2026-11-05 (merged in 648f6cd).** The authz hunt prompt and every refute prompt
carry a declared-access block (`research/intent.py`): middleware and decorators on each
route, plus the committed OpenAPI document, with a spec-wide requirement that no
operation overrides named as over-declaration. On run 3's VulnLookup clone: 155
operations, a global `apikey`, 0 with their own `security`; 417 routes, 282 with a
guard. Human verdicts are rows in migration v9's append-only `deep_verdicts` table:
`quarry deep-verdict <id> intended|real|unclear --note "..."` records one and
`quarry deep-survivors <run>` lists survivors as new or previously judged. A later run
matches on lens and file plus enclosing symbol or overlapping quote; an `intended`
match reaches the refuter with the note and is never dropped. Run 1's two verdicts
(#1, #141) were recorded on 2026-11-06 (decision G). Not done: Django URLconf routes,
so the block is empty on Django targets. (Showing verdicts in the dashboard and the
digest, also left undone then, is done below.)

**Done 2026-11-06, verdicts shown.** `verdicts.standing` reads, for one research
finding, its newest verdict (`latest`) and the verdict a deep run matched it to
(`detail` of `prior_verdict_id`, with `prior_match` as the basis). A match records the
verdict current when the finding was stored, so when the judged finding has a newer
verdict since, that is returned too and shown as "changed since the match". The
dashboard and the digest read only that, through one macro (`_macros.human_verdict`)
on the pages: the triage detail pane of a deep candidate, each candidate card on
`/research/<id>`, and a new "Survivors and human verdicts" table at the top of that
page, which lists the research run's survivors from `verdicts.survivors` (the
`deep-survivors` list) with counts of new and previously judged, uncapped because the
cards stop at 60. The digest's per-finding section now gives the research finding id,
the human verdict with actor, time and note (or the `quarry deep-verdict` command to
record one), and the matched earlier finding with its verdict, or "none; new to human
review". Notes, actors and matched titles go through `|visible` on the pages and the
digest's inert-text escaping. Four new tests (`standing` in
`tests/test_deep_verdicts.py`, the triage pane and the research run page in
`tests/test_web_dashboard.py`, the digest in `tests/test_disclosure.py`) all fail
without the change; the template contract test now accepts one macro calling another
in the same file. On a copy of the live database, `/research/1` lists its 2 survivors
with the two decision G verdicts, the evidence pages of #1 and #141 show them, and the
run 1 digest (written to a scratch directory, not `reports/`) carries both; each of
the 4 research run pages and its progress fragment rendered in under 0.1 s. Not done: a judged finding that is not a survivor and falls
below the 60 cards shown is not on its research run page (its evidence page still
shows the verdict), and the digest header does not count judged findings.

### 21. Layer 2 changes are not compared against a fixed set

I found no before/after measurement on a fixed set for the Layer 2 changes since run 1
(thinking off, quote minimum, family table, refute batching). `docs/LEGA-CORPUS.md`
defines a planted-bug corpus, and nothing runs it. A small replay (two Leg A repos, a
few plants) scoring missed plants, unsupported claims and wall time, with models and
budget held fixed, would show which changes helped. A tie is a valid result.

**Done 2026-11-05 (merged in 648f6cd).** `tests/fixtures/replay/` holds two synthetic
services (a Flask notes app and an Express ticket API) with 7 plants and the answer key
outside them. `quarry deep-replay` runs them through the real runner on a scratch
database and records models, digests, Ollama version, budget, sampling and a corpus
hash; `quarry deep-replay-compare` calls a tie a tie and flags changes within noise.
Measured with qwen3-coder:30b and devstral:24b, temperature 0, seed 42:

| Run | Missed at hunt | Missed after refutation | Unsupported claims | Wall |
|---|---|---|---|---|
| Route intent off | 2/7 | 7/7 | 3/15 | 378 s |
| Repeat of that run | 2/7 | 7/7 | 2/15 | 373 s |
| Route intent on | 1/7 | 7/7 | 3/16 | 427 s |

**The refute pass killed all 46 claims, plants included,** by citing checks the code
does not have (a `secure_filename` call, an `auth.requireAdmin` guard, a
`visibleTicket` filter); with the declared access in the prompt a refuter still claimed
`reset_password` carries `admin_required`. On this set the refuter as prompted has no
recall: item 3's asymmetry inside Layer 2. Route intent found one plant the two
intent-off runs missed, within the noise the repeat measured (3 of 15 claims differed
between identical runs). Decision F then changed the refuter: 2 of 7 plants missed after
refutation in both post-F runs; see decision F and docs/LEGA-CORPUS.md.

### 22. No text view of a run for an agent [code]

`quarry runs` lists runs. The run page's per-tool outcomes, health warnings, funnel
table and verdicts exist only in the dashboard, so an agent reconstructs them with ad
hoc SQL. A `quarry status <run>` built on `web/queries.py` (not a second copy of the
logic) would give both the same view.

**Done 2026-11-05 (merged in 0e2f87d).** `quarry status <run>` prints a run as
`key: value` lines, and `--json` prints the same document, built only from
`web/queries.py` (`run_summary`, `funnel_stages`, `verdict_counts`, `advisories`, plus
two small additions there, `verdict_counts_by_seat` and `scan_outcome`). It covers the
run header, each scanner's outcome and coverage counts, health warnings by source, every
funnel stage with in, kill, defer, merge, boost, restored and out, verdicts by state and
seat, and advisories. Text from a target or tool is scrubbed of control and bidi
characters and flattened to one line. Against a read-only backup of the live database,
run 3 printed 12 stages from 6,297 in to 765 out with drift 0. (The two parts left
undone then, the run page's own outcome logic and the missing quarantine and egress
tables, were done on 2026-11-06; see below.)

**Done 2026-11-06, one outcome rule.** `run_summary` stores `queries.scan_outcome` on
each scanner row as `outcome`; the run page's pill (`_macros.scan_pill`) and `quarry
status` both read that field, and the page's own if/elif copy is gone, as is a third
copy in the terminal-stage table's failed and skipped counts (`run_stages`). The page
still says "ran" where status says `ok`. Checked by rendering `/runs/<id>` before and
after: on a fixture run with 11 scanner rows covering every branch (a skip that also
says ok, a failure that also says nothing to scan, no `ok` key, `ok` of None, a legacy
note), the pages differ only in whitespace inside the pill cell and in the fixture's
own start time; on a copy of the live database, all 7 run pages are byte-identical
once the per-process form token is masked.
The old copy was not wrong on any of those rows. Two tests in `tests/test_status.py`:
the page and `status --json` agree on 10 such rows, and a page rendered with
`scan_outcome` replaced follows the replacement, which fails without the change.

**Done 2026-11-06, quarantine and egress.** `quarry status` now ends with what ingest
quarantined (`quarantine.<id>` with its kind, path, detail and hash) and the egress the
run page shows (`egress.<id>` with scope, stage, bytes out and in, destination, note
and time), from the page's own `queries.quarantined` and `queries.egress_ledger`:
this run's rows and the global ones, never another run's. Unlike the page, which shows
the newest 12, status lists every row. The ledger's totals are printed as
`egress.all_time` and sit under `all_time` in the JSON, so they cannot be read as this
run's. Paths, details, destinations and notes go through the same scrub and
flattening as the rest of the text; the JSON escapes them as before. `quarantined()`
now also returns each row's id, hash and time, in id order. Two new tests in
`tests/test_status.py` (the rows, the scoping and the totals; hostile text in a path,
detail and note), and the JSON test's key list gained the two sections; all three fail
without the change. Against a copy of the live database, run 3 printed 0 quarantined,
and 8 egress rows, 1 its own clone and 7 global database syncs, out of 14 all-time.

### 23. Bandit, Checkov and Gitleaks also skip trees without saying so [measured]

Found after item 15. Each Layer 1 adapter was run through `Scanner.run` (Tier 1, the
real argv) over a git fixture with the same `x.py` (`eval(input())` plus a random
`ghp_` token), `Dockerfile` and `requirements.txt` planted in 12 directories: `app`,
`tests`, `test`, `vendor/lib`, `node_modules/pkg`, `build`, `dist`, `.venv/lib`,
`third_party`, `examples`, `docs`, `.github/scripts`. Trivy and osv-scanner returned
results from all 12. Three did not:

- **Bandit 1.9.4** missed `.github/scripts/x.py`. Its default exclude list (`.git`,
  `.hg`, `.svn`, `CVS`, `.bzr`, `.tox`, `.eggs`, `__pycache__`, `*.egg`) matches by
  substring when the working directory is outside a git work tree, and Quarry's cwd
  (`rundir/out`) always is. From `/tmp` it also missed `lib/CVSS.py`,
  `lib/pyCVSScalc.py` and `.gitlab/ci.py`, while `lib/cvss_tools/calc.py` was found
  (the match is case-sensitive). From inside any git work tree, or with an explicit
  `-x <src>/.git`, the `.github` file came back. A CVSS module is an ordinary file
  name in the CVE tooling Quarry targets. The live DB shows no Python path containing
  `CVS`, `.git` or `.hg` from any tool in runs 1 to 3, so no past loss is shown.
- **Checkov** returned nothing from `node_modules/pkg`, `.venv/lib` or
  `.github/scripts`, so it appears to skip `node_modules` and dot-directories.
  `.github/actions/<name>/Dockerfile` is where Docker container actions live.
- **Gitleaks 8.30.1** returned nothing from `node_modules/pkg`. Its built-in config
  has a global path allowlist (the binary contains `node_modules(?:/.*)?$`), and
  Quarry runs it with no `--config`, so that list applies. A token committed under a
  tracked `node_modules/` is still a leaked token.

- **Fix:** Bandit: pass `-x <src>/.git` (this replaces the default list, which also
  brings back `.hg`-named paths and the rest) and add the fixture as a live test.
  Checkov: find the flag or config that turns off its directory skips, measured the
  same way. Gitleaks: a config that keeps the default rules without the global path
  allowlist, checked against the same fixture. Item 15's coverage check is
  Opengrep-only; the fixture run above is the cheap general form of it and could run
  in `quarry doctor` against each installed tool version.

**Done 2026-11-05 (b707e82).** Rerunning the 12-directory
fixture through all five adapters now returns results from all 12 for each tool, and
Gitleaks also reports a token in a root `package-lock.json` `resolved` URL.

- **Bandit:** Quarry now passes `-x <src>/.git/*`. The cause, from Bandit's source:
  the default `-x` is the bare names, and each becomes a `<name>/*` glob only if
  `./<name>` is a directory in the working directory. Otherwise it is tested as a
  substring of every path. The trailing `/*` keeps Quarry's value a glob whether or
  not the clone keeps `.git`, since a literal `*` never occurs in a path.
- **Checkov:** both skips are environment variables (`CKV_IGNORED_DIRECTORIES`,
  default `node_modules,.terraform,.serverless`; `CKV_IGNORE_HIDDEN_DIRECTORIES`,
  default true). The adapter sets them to `.git` and `false` through a new
  `Scanner.env()` hook. A root `.gitlab-ci.yml` was read under both settings, so the
  dot rule cost directories, not that file.
- **Gitleaks:** the default allowlist is wider than `node_modules`. Its 25 path
  entries include every common lockfile, vendored Go and Ruby trees, virtualenvs,
  `site-packages`, `bower_components` and named JS libraries. `[extend] useDefault =
  true` inherits all of it (measured), so Quarry now ships
  `quarry/scanners/gitleaks.toml`: Gitleaks' own default (222 rules), read out of the
  installed binary by `quarry/scanners/gitleaks_config.py`, with 20 path entries
  removed and the 5 binary-format entries kept, plus Gitleaks' MIT notice. The
  value-level `regexes` and `stopwords` and each rule's own allowlist are unchanged.
  A path entry the generator has not classified stops regeneration. A test fails when
  the installed Gitleaks version differs from the one the file was built from.
- **Found while fixing:** OSV's config write used `write_text` from Tier 0 into
  `out/`, where every sandboxed tool can write, so a link planted at that name would
  have redirected the write outside the run. Both config writes now go through
  `base.write_tool_config`, which creates the file the way logs are created (unlink,
  then `O_EXCL` without following links). It also creates `out/`, which does not
  exist yet when Gitleaks, the first tool, runs.
- **What the funnel then does with them:** `path-class` kills `vendored` paths for
  every tool and `generated` paths (lockfiles included) for every class except
  `sca-db`. So Gitleaks hits in `node_modules/` and `package-lock.json` will be killed
  there, as recorded and reversible recall-risk events, not dropped unseen. Whether
  the `secrets` class should be exempt from the generated-path rule, as it already is
  from the test-path rule, is a funnel policy call and is not changed here.
- Tests: 7 in `test_scanner_argv.py`. Three are live (Bandit, Checkov, Gitleaks on
  planted trees) and each fails on the previous argv or environment. The others cover
  the argv, the config's contents and version, and the link refusal.
- The `quarry doctor` fixture sweep: **done 2026-11-05 (merged in 0e2f87d)** as
  `quarry doctor --coverage` (`quarry/scanners/sweep.py`). It plants this fixture, plus
  a workflow with a template injection for zizmor, runs every installed adapter through
  its own `Scanner.run`, and exits 1 when a tool returns nothing from a planted file it
  is expected to read (expectations are per file and per tool). Measured: all 7 tools
  pass in 32 s, 26 s of it Opengrep. With the four pre-fix configurations put back, it
  reported the same losses measured by hand above, and for Opengrep (python and
  dockerfile trees, no flag) 7 of 12 directories. A machine without the offline
  databases is unit-tested only.

### 24. Opengrep fallback loses its logs, and the run page mislabels it [code]

- Every per-tree invocation writes `logs/opengrep.stderr`, and `_create_log` unlinks
  and recreates it, so the combined run's crash log is overwritten by the first tree
  and only the last tree's log survives. The error added in item 15 ("see
  logs/opengrep.stderr") points at that one log. Name per-tree logs
  `opengrep-<tree>`.
- `run.html` shows the `nothing to scan` pill for any tool with a `note`. The
  per-tree recovery sets a note ("combined run crashed; recovered per tree..."), so
  a recovered Opengrep run with hundreds of records is labelled "nothing to scan".
  Read from the template, not rendered. A separate field for "nothing to scan" fixes
  it.
- Item 15's coverage summary reaches the run page only as health warnings; the
  counts are in the manifest only.

**Done 2026-11-05 (b707e82).** Per-tree runs log to
`logs/opengrep-<tree>.stderr`, and the combined run keeps `logs/opengrep.stderr`.
`ScanOutcome.nothing_to_scan` is set only by a tool's `nothing_to_scan` check and is
stored per tool; the run page shows the pill from it. Older manifests without the
field read a note with zero records as nothing to scan. The tool table's detail cell
shows the coverage counts (files scanned, source files in the tree, unexplained
files, invocations with no report). A web test renders all three cases; the page was
not checked in a browser.

### 25. Opengrep's per-tree fallback starves the slow trees [measured]

The fresh VulnLookup scan (run 4, 2026-11-05) recovered per tree, as run 3 did, but
4 of 25 trees (generic, javascript, python, typescript) were killed with no output, and
opengrep reported 43 findings against run 3's 656. Each tree got an equal slice,
`max(60, 1800 // 25)` = 72 s. Item 15 stopped opengrep skipping test/, vendor/ and
minified files, so those four trees now scan up to 630 files and each outran 72 s,
while the opengrep run as a whole took 277 s and left about 1500 s unused. The note
said the trees "produced no usable output", which read as a crash.

Rerun on their own afterwards, under the same sandbox and flags, the python tree took
23 s and found 522 results, and the javascript tree took 473 s and found 168. Why python
took longer than 72 s inside the scan is not settled (the replay was using the machine
at the time, and opengrep may cache between runs). The javascript tree is slow because
it now reads the vendored, minified editor and toolbar scripts under `website/web/static`.

**Done 2026-11-05.** The fallback now runs two passes: every tree gets the equal slice,
then a tree killed at the end of its slice is rerun with an equal share of the time the
others left. Its coverage counts from its final attempt only. The note names the
reruns, and a tree still out of time is listed as "out of time" rather than as a
crash. Two tests cover it. Run 4 cannot be rescanned (a second scan would duplicate
every finding), so VulnLookup is ingested again as a new run, scanned with
`--timeout 3600`: at 1800 s, the reruns share roughly 1350 s, which the javascript tree
alone nearly fills.

### 26. Two workers can resume the same deep review [code]

`quarry deep --resume <id>` does not check whether another worker already holds that
research run. The dashboard knows (`web/queries.live_status` reads the pid, host and
heartbeat), but the CLI path does not ask. The 21:00 launchd job resumes the newest
research run with unfinished units, so enabling it while a manual review of the same
run is going starts a second worker on the same units. Found 2026-11-05 while starting
the run 7 review by hand; the job was left disabled for that night for this reason.

**Done 2026-11-06.** `runner.hold` runs before `quarry deep --resume` does any work. In
one `BEGIN IMMEDIATE` transaction it reads the run with the dashboard's own
`live_status` and either claims it for this process or refuses (exit 1, "refusing to
resume") when it is `running`, `unverified` or `starting`. Two resumes started
together are serialised, so the second reads the first as `running`. The dashboard's
Resume and the CLI share one list of those statuses (`queries.LIVE_STATUSES`). The
worker the dashboard spawns for its own claim carries `QUARRY_RESUME_CLAIM=<research
id>` in its environment and may fill that claim; any other process waits for it. Also
refused: `--resume` of a research run that belongs to a different ingest run than the
one named, which would check its units against the wrong source tree and which
`live_status` could not see, since it matches the worker's command line on the ingest
run. 20 tests in `tests/test_resume_guard.py`; with the refusal disabled, 9 of them
fail. Those tests take one claim after the other; the race test below runs two at once.

**Done 2026-11-06, the race test.** `test_two_processes_resuming_at_once_get_one_claim`
in `tests/test_resume_guard.py` starts two Python processes whose command lines end
`quarry.cli deep 1`, so `ps` shows each as run 1's worker. Each opens its own connection
to one SQLite file and, in each of 30 rounds, waits on that round's barrier file and
calls `runner.hold` the moment it appears; the test resets the research run to
`stopped` between rounds, and both processes stay alive throughout, since a claimant
that exited would rightly read as `died`. Every round must end with exactly one claim,
the database naming the claimant's pid, and the other process refused because that pid
holds the run. In 5 runs of the test, 29 or 30 of the 30 rounds had both processes
inside `hold` at once (the loser entered before the winner left); the test requires at
least half. One run at 500 rounds also passed. A run took under 2.5 seconds. With
`hold`'s transaction replaced by no transaction, both processes claimed in round 0, so
the test sees the race it guards against. It found no race, and `hold` is unchanged.
Not covered: the dashboard's Resume racing a terminal resume. They claim through
different code, both in a `BEGIN IMMEDIATE` transaction.

Also seen: `/private/tmp/quarry` holds 78 leftover `run-9xxxxx` directories, none
mounted, the oldest from 2026-11-02, apparently left by tests. Harmless, not cleaned.

### 27. gpt-oss:20b spends the night failing [measured]

Run 7's first deep-review night (research 4, 2026-11-05 20:34 to 06:06) hunted 105 of
its 1,551 units. gpt-oss:20b failed 20 of its 42 with `done_reason=length`. Each failure
took roughly 890 to 960 s, 18,590 s in all, out of the night's 34,306 s of hunting, and produced
nothing. Its 22 finished units produced 9 findings, all quote-verified, from 2 units.
The failed units sit at positions 0 to 19 of the resume order, so the next night would
have started by spending about five hours on them again.

Cause: gpt-oss lists `thinking levels low, medium, high` (default medium) in `ollama
show` and ignores `think: false`. Re-sending one failed unit's prompt with `false`
returned 19,346 characters of reasoning before a 20-character answer.

Measured 2026-11-06, paired (one prompt per unit, sent at both settings, single call,
`num_predict` 8,192, no length retry), on 10 of the failed units and the 2 that found
something:

| `think` | ran out of budget | other error | finished | findings | seconds |
|---|---|---|---|---|---|
| `false` (current) | 10 of 12 | 1 (empty reply) | 1 | 0 | 2,530 |
| `"low"` | 2 of 12 | 0 | 10 | 0 | 1,246 |

`low` stops the stall but finds nothing, including on the two units where gpt-oss
found 9 quote-verified findings the night before (those took about 490 s each, which
fits the 32,768-token retry finishing). So `low` was not shipped: it trades the stall
for a model that hunts nothing. Scratch scripts and raw results were not kept in the
repo.

**Done 2026-11-06.** granite4.2:30b replaced gpt-oss:20b in the default deep-review
models (`cli.DEFAULT_DEEP_MODELS`, and the dashboard's default selection, which now
reads the same list). On run 3, granite hunted 104 units with 1 error and 38 of its 60
findings quoted real code. gpt-oss stays selectable. Research 4's 495 unfinished
gpt-oss units (475 pending, 20 failed) were moved to granite in the database, with the
change and the earlier provenance recorded in `research_runs.note`; the 42 gpt-oss
units already hunted and their 9 findings stay as they are.

Also seen, then fixed as item 28: the refute pass runs after the hunt loop, and the hunt
loop runs to the deadline while units remain, so a large review shows no verdicts until
its last night.
Research 4 had 1,446 units left after night one; at that night's 125 units, that is
about 12 more nights. Moving off gpt-oss should shorten it; by how much is not yet
measured.

### 28. Refutation gets no time, and every call re-reads the subsystem [measured]

Item 27's side finding, measured. With a deadline, the refute pass ran only after the
hunt loop, which ran to the deadline while units remained: research 4 (run 7) hunted
125 of 1,551 units on its first night and refuted none of its 162 findings. Each refute
call also re-read the whole subsystem. The prompt puts a random section tag ahead of the
repository text, and the tag was new on every call, so Ollama could never reuse its
cached prefix. Timed on run 7 with qwen3-coder:30b on one 41k-token subsystem and 5 of
its findings: 102 to 123 s per call, 92 to 113 s of it reading the prompt. At that rate
one night's 162 findings, two refuters each, need about 10 hours of refuting.

**Done 2026-11-06.**

- **One tag per subsystem.** The refute pass renders each subsystem once per pass with
  one tag and refutes its findings back to back. Timed on the same 5 findings: 111 s for
  the first call, then 8.9 to 11.0 s each, prompt reading 0.5 s; all 10 answers were
  `refuted` with either tag. The hunt does the same: units run subsystem by subsystem,
  model by model within one, every lens of a model back to back with one tag. Timed with
  devstral:24b on three lenses of one subsystem: 275 s for the first (229 s reading the
  prompt), then 46 s and 105 s (about 1 s reading). The model is also swapped once per
  subsystem rather than on every unit. The tag still never reaches the target's files,
  which are written before any tag exists.
- **A refute share.** With a deadline, a night now refutes what earlier nights left
  unanswered, hunts until `runner.REFUTE_SHARE` (0.3) of the remaining window is left,
  refutes what it found, and hunts again with any time the refute pass did not use.
  Without a deadline the order is unchanged. A unit is attempted once per night: one
  that fails is retried on the next resume, not again after the refute pass.
- Tests: `tests/test_refute_share.py` (4) and `tests/test_prompt_prefix_cache.py` (2);
  both of the latter fail with a fresh tag per call.
- Not measured yet: a whole night under the new order. The share is a guess bounded by
  the timings above (0.3 of a 9.5-hour night is about 10,260 s, room for about 1,000
  refute calls at 10 s plus a cold first call per subsystem and model; night one's 162
  findings needed about 324 calls before retries);
  time the refute pass does not use goes back to the hunt, so too large a share costs
  nothing.

