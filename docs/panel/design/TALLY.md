# Design round tally — verdicts, conditions, dissent triggers

**Round:** design review, round 1 · 2026-08-24
**Question put to the panel:** make the web interface look like a professional modern SaaS security
tooling application, with room to grow, in a blue/grey palette like cve.icu, with a dark mode.
**Plan:** [`../../DESIGN-PLAN.md`](../../DESIGN-PLAN.md)

| Seat | Verdict | Conditions / key output |
|---|---|---|
| **1 Design Systems** | **Conditional approve** of the request; **reject the reference implementation** | 17 amendments. Ships a complete two-theme token set verified at **142 pairings, 0 failures** against floors stricter than AA, plus a **theme-invariant `--edge`** that fixes WCAG 1.4.11 on every control in both themes with one value. Rejects cve.icu's values on measurement (its `--color-primary` fails on *links*: 4.34 dark on cards, 4.27 light on the page) and its layout language on principle — *"a language for making a number look important,"* in a product that ratified never putting counts in a header. Replaces 4 severity-shaped pill classes with **6 semantic roles carrying glyphs**. Rejects webfonts from any host, and self-hosting too. **Dissent trigger:** if a screenshot of `/triage` leaves this machine more often than a triage sitting happens on it, withdraws the geometry and most of the typography rulings — and notes the product already has the instrument to answer that, the egress ledger |
| **2 Product & UX** | **Conditional approve** | 20 amendments. Continuation of `04-product-ux.md`; **refuses to reopen the ratified IA** and confirms it landed correctly (3.5× producer collapse on Nettacker, 25.6× on repo C). Reframes the review: *"six of the load-bearing interactions are broken right now, and every one of them is invisible in a screenshot."* Turns the density argument into arithmetic — font-size costs ~20% of rows-per-screen, the card idiom ~45%, so those are **two rulings, not one**. **Reverses its own round-1 SSE ruling** on the grounds that the `run_events` table it depended on was never built. Enumerates the nine routes a year needs and rules that **no route may ship without a shipped writer for its table**. **Dissent trigger:** moves to delete the sidebar if it ships and `/targets`/`/producers` are still not built six weeks later — *"the growth was decoration, and I will have voted for decoration"* |
| **3 Front-End Platform** | **Conditional approve** | 15 amendments. **Found that `pip install .` ships zero templates and zero static files** — 34 files, and `StaticFiles(check_dir=True)` raises at import, so an installed Quarry cannot start its dashboard. Rules the no-build constraint **sufficient**, feature by feature against a Safari 17.0 floor; everything needed shipped at 16.5 or earlier. Prices and rejects the build step, and rules **CodeMirror 6 (`PLAN.md` D7) permanently out of scope**. Records the two vendored blobs' versions and SHA-256s, which nothing in the repo did. Proves the `/evidence` fragment renders unstyled by rendering both routes; finds the **sticky `th` inert in all 8 tables** because `.tbl{overflow:hidden}` establishes a scroll container. **Dissent trigger:** flips if CodeMirror 6 or any npm dependency is scheduled within two phases — *"the build step is arriving anyway"* |
| **4 Accessibility** | **Reject as scoped**; conditional approve on a rewritten scope | 17 amendments + a 12-item acceptance gate. Corrects the brief's own contrast audit: **16 text failures, not one** — 7 static and 9 composited through `opacity`, which a token table structurally cannot see. Proves that **on a dark theme a background tint cannot be both a visible state and a legible surface** (lifting the hit-line tint to 3:1 drops the source code on it to 2.86), so selection and hit-line must be marked by border or glyph. Simulates CVD: `--ok` and `--kill` are **1.06:1 apart under deuteranopia**. **Found that `⌘D` dismisses a producer** and `⇧⌘D` fires the corpus-wide write. Establishes that `04-product-ux.md` already ratified `u` as a 20-deep undo and stated *"`D` is unbound."* **Dissent triggers:** unconditional reject if the redesign lands with `<meta http-equiv="refresh">` still in place, or with `opacity:.6` still deciding which evidence is legible — *"either one would show the panel was read as a palette request"* |
| **5 Security Domain** | **Conditional approve** | 16 amendments. Rules 12 SaaS conventions **prohibited** as certainty claims the measurements do not support, and 8 permitted. Establishes the type-size rule — *"a card is a promise of a drill-down"* — and that **22px is the ceiling for a number that resolves to an enumerable set**; 40px prohibited outright. **Found the `boost` audit links dead** (2 of 11 stages) and **the egress ledger under-counting its own hosts 1 of 3**, and makes completing the ledger a blocking prerequisite for any containment chrome: *"a badge that reads green 100% of the time carries zero bits."* Rules severity colour prohibited in every form, and that colour should encode **epistemic state** instead. On branding: a quieter wordmark, a required favicon, and no vendor identity — *"vendor chrome is the visual grammar of a hosted service, and a hosted security service is one that receives your code."* **Dissent trigger:** reject if a palette change ships without the boost links, the `defer` split, and the egress ledger fixed |
| **6 Economics** | **Conditional approve · 10 hours** | 13 amendments. Establishes the only available cost anchor and it is measured: **the whole product was built in 9 h 42 m** — 14 commits, 5,080 lines, 77 tests (`README` and `STATUS` both say 53). *"A restyle that costs more than the product did has failed a sanity check regardless of its merits."* Prices every trap and rejects it: dashboard ~5 h, charts ~4 h, build step 1.5–9 days, skeletons ~3.5 h **rejected on measurement** (largest run renders in 16.2 ms). Separates defect-fixing from beautification and prices them separately. **Found `restore` unreachable from every template** and names it the thing to ship first. Surfaces that `LAYER2-PLAN.md` says one untaken measurement *"decides whether §9's UI is worth building."* **Dissent triggers:** reject if a dashboard route is approved, if scope passes 3 days, or if `research_detail.html` is styled before that measurement is taken |

## Material findings added by this round

- **A shipping bug, not a styling one.** `pip wheel` produces 34 files with **zero** under `templates/` or
  `static/`; `app.py:37`'s `StaticFiles` raises at import because `app = create_app()` is module-level.
  The "vendored, no CDN, offline" posture is currently defended by nobody installing the package.
  → **Seat 3**, verified by the chair.

- **`⌘D` writes a `funnel_events` kill.** `triage.html:156` guards only `input,textarea` with no modifier
  test, so `⌘D` arrives as `e.key==='d'` with `metaKey` and reaches `btn.click()`. `⇧⌘D` reaches
  `[value=corpus]` — `UPDATE producers SET enabled=0` across every future run. The browser's bookmark
  dialog covers the 303, so the operator never sees it. → **Seat 4**, verified by code reading.

- **The killed-set evidence pane renders source code in proportional sans with indentation collapsed.**
  All seven classes `_detail.html` needs are defined only in `triage.html`, so the htmx swap into
  `run.html`'s `#peek` inherits `-apple-system` and `white-space:normal`. This is the audit surface for
  the product's central claim, and it is the one screen that renders code wrong — *because the CSS lives
  in a sibling template.* → **Seats 2, 3 and 5 independently**; reproduced in-browser by the chair.

- **The audit promise fails on 2 of 11 stages.** `queries.py:185` filters
  `action IN ('kill','defer','merge')`, excluding `boost`, while `run.html:57-60` emits one href for all
  four action columns. On run 5, `rule-precision-prior` boosts 191 and `novelty-rank` boosts 122; both
  render *"Suppressed at … — 0 shown"* over an empty table, directly beneath the `<h2>` asserting that
  every number links to its set. → **Seats 2 and 5 independently**, verified in SQL.

- **The egress ledger cannot produce the list `quarry doctor` claims it produces.** `targets.py:172,206`
  reach `repos.ecosyste.ms` and `api.securityscorecards.dev` with no `db.egress` call, so
  `SELECT DISTINCT destination FROM egress` reports one host of three. `STATUS.md:183`'s three-host list
  could only have been produced by reading the source. → **Seat 5**, verified.

- **`restore` is thirty lines of correct, tested inverse logic that no template references.** Two tests
  assert it; the UI says *"Reversible — writes a ledger event, deletes nothing."* Two-thirds of that
  sentence is true. → **Seats 4 and 6 independently**, verified by grep.

- **The palette being asked for is measurably less accessible than the one in place.** Over the same
  pairing set: shipped dark **16** text failures, cve.icu dark verbatim **34**, cve.icu light verbatim
  **54**. cve.icu's light half is stock Bootstrap 5, and its failures land on *links* — `#0d6efd` clears
  4.5:1 only on pure white and only by rounding. → **Seats 1 and 4 independently**.

- **Nine invalid `font:` shorthands are silently dropped by the browser.** `font: 600 20px/1.2 inherit`
  is not valid CSS, so every `h1` in the product renders at the UA default **28px** and every `button`
  renders in **Arial 13.333px**. → the chair, from computed styles.

- **The two seats who proposed palettes disagreed, and the loser's own goal decided it.** Seat 4's light
  `--rule-2 #8996A6` fails 1.4.11 at **2.54** against `--sunk` — the exact defect it raised the token to
  fix, and a failure it did not report. Seat 1's theme-invariant `--edge #6E7C90` clears 3:1 on all five
  surfaces in both themes. → the chair, recomputing both sets.

## Where the round contradicted itself

Five splits, resolved in [`../../DESIGN-PLAN.md`](../../DESIGN-PLAN.md) §3:

| Split | Resolution |
|---|---|
| 1 ↔ 4 · which palette | Seat 1's values, on measurement |
| 1 ↔ 3 · `light-dark()` vs a Safari 17.0 floor | Seat 1's values, Seat 3's three-block structure |
| 2 ↔ 6 · sidebar and new routes | Seat 6, on Seat 2's own dissent trigger |
| 1·3·5·6 ↔ 2 · Inter | System stack; the egress argument is decisive |
| 5 ↔ 2 ↔ 1 · the four stat cards | Links capped at 18px, not deletion |

## Standing note

Two seats, from opposite directions, made their vote conditional on the same unanswered question:
**is this interface a tool the operator runs, or also the argument the product makes to other people?**
Seat 6 would raise its budget if the answer is the latter; Seat 1 would withdraw its geometry rulings.
Neither can answer it — and per `AMENDMENTS.md`, *"the principal may overrule the rule; he may not
overrule it silently."* Whichever way it goes belongs in that file.
