# Design Plan — the web interface

**Round:** design review, round 1 · 2026-08-24
**Reviewing:** the request to make the dashboard "look more like a professional modern SaaS security
tooling application, with room to grow and expand," with a blue/grey palette like cve.icu, and a dark
mode.
**Panel:** six seats. Five conditional approvals on five different conditions; one reject-as-scoped.
**Tally:** [`panel/design/TALLY.md`](panel/design/TALLY.md)

Every number in this document was produced by a command run against the tree at `5e7e14a`. Where a seat
asserted something load-bearing, it was re-verified before being written down here; where a seat's number
was wrong, the correction is noted in place.

> **Superseded in part by the Quarry / RogoLabs rebrand (2026-10, branch `feat/frontend`).**
> UI9 is overturned: Inter is vendored as one `.woff2` with its OFL text and a recorded SHA-256 in
> `static/VENDOR.md`, so the "no browser egress" property this plan defended still holds. UI8's
> default changes from "system" to dark, set by the pre-paint script; the stylesheet structure is
> unchanged, so a failed script still falls back to following the OS. UI16 and UI17 are met rather
> than waived: `verdicts` now has a writer (`quarry validate`) and `advisories` has one
> (`quarry report`), and `/validation` and `/advisories` read them. The palette in Appendix A is
> replaced by RogoLabs slate tokens in `theme.css`; the floors, the six roles, the glyphs, the
> opacity ban and the type ceiling stand and are still enforced by `tests/test_design_tokens.py`.

---

## 0. The finding that reframed the review

**`pip install .` produces an Quarry whose dashboard cannot start.**

```
$ pip wheel --no-deps .
$ unzip -l quarry-0.1.0-py3-none-any.whl | grep -E 'templates|static'
(nothing)                                        # 34 files, zero assets
```

`pyproject.toml:32` declares `package-data = {quarry = ["*.sql", "sandbox/*.sb"]}` and there is no
`MANIFEST.in`, so only `schema.sql` and the two sandbox profiles ship. `app.py:37` calls
`StaticFiles(directory=HERE/"static")`; starlette's `check_dir` defaults to `True` and raises on a
missing directory. `app = create_app()` is module-level at `app.py:237`, so an installed Quarry
raises at import.

The "vendored, no CDN, offline" posture is currently defended by nobody installing the package. Adding
`app.css` would make it the third asset class that does not ship.

**This is why packaging leads the plan and the palette does not.**

---

## 1. Confirmed defects

### 1.1 Shipping bugs — these fail regardless of how the page looks

| # | Defect | Where | Evidence |
|---|---|---|---|
| 1 | The wheel ships no templates or static files | `pyproject.toml:32`, `app.py:37,237` | Built it: 34 files, zero assets |
| 2 | `⌘D` dismisses a producer; `⇧⌘D` dismisses corpus-wide | `triage.html:156` | The guard is `e.target.matches('input,textarea')` — no modifier test. `⌘D` arrives as `e.key==='d'` with `metaKey`, falls through to `btn.click()`. The bookmark dialog covers the 303 |
| 3 | The killed-set evidence pane renders code in proportional sans | `run.html:87` → `_detail.html` | Computed in-browser: `font-family: -apple-system`, `white-space: normal`. All 7 classes the fragment needs (`.dhead .code .sec .prov .msg .dtags .loc`) are defined **only** in `triage.html` |
| 4 | Nine invalid `font:` shorthands are silently dropped | `base.html:65`, `triage.html:42`, +4 files | `font: 600 20px/1.2 inherit` is invalid CSS — `inherit` is not a legal family inside the shorthand. Every `h1` renders at the UA default **28px**; every `button` renders in **Arial 13.333px**; the deep-review `select`/`input` likewise |

### 1.2 Broken promises — the UI contradicts a claim it prints on itself

| # | Defect | Where | The claim it breaks |
|---|---|---|---|
| 5 | `boost` counts are dead links | `queries.py:185`, `run.html:57-60` | `suppressed()` filters `action IN ('kill','defer','merge')`. All four action columns emit the same href. On run 5, `rule-precision-prior` boosts 191 and `novelty-rank` boosts 122; clicking either renders *"Suppressed at 'novelty-rank' — 0 shown"* over an empty table — under the `<h2>` reading *"every number is a link to the set it killed."* **The audit promise fails on 2 of 11 stages** |
| 6 | `restore` is unreachable from the UI | `app.py:101-130` | Thirty lines of careful inverse logic — including a 14-line `NOT EXISTS` clause so an operator's undo cannot resurrect what the funnel killed — two tests, and **zero templates reference it**. `triage.html:144` says *"Reversible — writes a ledger event, deletes nothing,"* which is true of the database and false of the interface |
| 7 | The egress ledger under-counts its own hosts | `targets.py:172,206` | Both call out to `repos.ecosyste.ms` and `api.securityscorecards.dev` with no `db.egress` row. Only `vulndb.py:92` and `orchestrator.py:130` log egress, so `cli.py:214`'s `SELECT DISTINCT destination FROM egress` reports **1 of 3** — on the screen headed *"'completely local' has to be auditable to mean anything"* |
| 8 | `defer` is painted as `kill` | `run.html:70-71,83`, `_detail.html:58` | The legend renders *"kill = evidence says no"* and *"defer = a rate limiter ran out, **not evidence**"* in the same colour, one line apart. D8 exists to distinguish them |
| 9 | Light mode is dead code | `base.html:2,20-21` | With macOS set to light the page stays `rgb(15,19,21)`; removing the hardcoded `data-theme="dark"` at runtime flips it to `rgb(244,245,243)`. ~30 lines of correct CSS, unreachable, and no toggle anywhere. **Both halves must change** — deleting the attribute alone leaves the light values trapped inside `@media (prefers-color-scheme: light)`, so an explicit "light" choice on a dark-set Mac still reaches nothing |
| 10 | Two definitions of "alive" | `run.html:53` vs `schema.sql:207` | The funnel recomputes `remaining` as `rem - kill - defer - merge`, discarding the `s.remaining` that `funnel.py:186` already measured; `live_occurrences` excludes only `action='kill'`. Under `quarry funnel N --top-k` they diverge silently |

### 1.3 Accessibility — measured over the 108 real pairings in the templates, not the token block

| Finding | Measured | Threshold |
|---|---|---|
| Dark-theme text failures: 7 static, 9 composited through `opacity` | **16** | 4.5:1 |
| The refuter's verdict on a refuted candidate (`research_detail.html:24`, `opacity:.6`) | **2.50** | 4.5:1 |
| The band definitions — what `known-good`/`unmeasured`/`known-bad` mean (`triage.html:18`, `opacity:.75`) | **3.41** | 4.5:1 |
| Selection state — the keyboard cursor (`triage.html:24`), colour only | **1.22** | 3.0:1 |
| Selected vs hovered — the same pixel | **1.01** | 3.0:1 |
| `--ok` vs `--kill` under deuteranopia — the same beige | **1.06** | — |
| Pill *fills* vs each other, in normal vision | **≤1.06** | — |
| Form-control boundaries (`--rule-2` on `--panel`) | **1.68** | 3.0:1 |
| `<meta http-equiv="refresh" content="20">` — an 8-hour run reloads 1,440 times | WCAG 2.2.1 | **Level A** |
| `aria-*` · `role=` · `scope=` · `<caption>` · `tabindex` · `scrollIntoView` · `<main>` · `sr-only`, across all 8 templates | **0 each** | — |

The composited failures are the important half: a token table cannot see them, which is why the brief's
original audit reported one failure where there are sixteen. **`opacity` on text is banned** (UI7).

Two more, both real conformance items rather than niceties: the evidence code pane has no `tabindex` and
no focusable descendants, so **it cannot be scrolled without a mouse** (2.1.1); and
`body{overflow:hidden}` with a fixed-height shell clips content at 200% zoom and 400% reflow (1.4.4,
1.4.10 — both AA).

### 1.4 Drift

| Measure | Count |
|---|---|
| `46px` hand-copied across 6 files (incl. an inline `style=` in `empty.html:3`) | **7** |
| Selectors defined in more than one template | **13** |
| …of which have already diverged | **10** |
| Redundant declaration instances | **63** |
| Inline `style=` attributes | **85** |
| …that would outrank a new `@layer` stylesheet | **67** |
| `<style>` blocks / `.css` files | **6 / 0** |
| Tests claimed by `README.md:13` and `STATUS.md:5` vs `pytest --collect-only` | **53 / 77** |

`.card` is defined three times at three different paddings; `h1` four times at 20/21/22px. Three
accidental card components.

---

## 2. Ratified decisions

Numbered `UI*` so they do not collide with `PLAN.md`'s `D1–D17`.

**UI1 — Blue/grey is approved; cve.icu's token values are rejected.** Take the hue family and the layout
language; re-derive the ramp against a measured floor. Its dark theme is the hand-tuned half and its
light theme is stock Bootstrap 5, and the failures land on *links*, not only timestamps: `#0d6efd` is
**4.27** on the page background and clears **4.50** on white only by rounding; `#adb5bd` as muted text is
**2.07**; `#ffc107` as text is **1.63**. Verbatim adoption ships 34 text failures in dark and 54 in light
against the current 16.

**UI2 — The palette is Seat 1's set (Appendix A), verified at 142 pairings, 0 failures**, against floors
stricter than AA. It keeps the existing accent `#7FA9E0`, which is already the better blue and shrinks
the diff by a token.

**UI3 — `--edge: #6E7C90` is theme-invariant.** All five surfaces in both themes sit at the luminance
extremes, so one mid blue-grey clears 3:1 against every one of them (worst **3.40** dark, **3.39**
light). This fixes WCAG 1.4.11 on every control boundary, the sticky-header rule, and the unmarked
default `.f` state, in one token.

**UI4 — Six semantic roles replace four severity-shaped pill classes.** Generic `--color-danger`/
`--success` is rejected: the largest red number on `/runs/{id}` today is `suppressed`, which is the funnel
*succeeding*. The name is the enforcement mechanism.

| role | the question it answers | glyph |
|---|---|---|
| `--verified` | A machine checked this and it held. | `✓` |
| `--incomplete` | Something may have been lost here, or work did not finish. | `◐` |
| `--alarm` | The instrument failed, or the operator is about to lose something. | `▲` |
| `--killed` | Evidence said no. This is the funnel working. | `−` |
| `--unmeasured` | No machine has checked this. The error rate is unknown. | `?` |
| `--inert` | This is a label, not a claim. | **none** |

`--inert` having no glyph is load-bearing: **absence of a glyph means the chip asserts nothing.** Tool
name, rule id, CWE, lens, model and `claims high` are labels. A reader who learns "glyph = judgment"
reads `claims high` correctly on first sight without the `title` attribute. All glyphs are in ranges the
system monospace already covers — no icon font, no asset.

**UI5 — Glyphs are mandatory, not decorative.** Under deuteranopia `--ok` and `--kill` are **1.06:1**
apart, and the pill fills are within 1.06:1 of each other in *normal* vision because all three were
tuned to one luminance band. No hue fixes this; the proposed palette is arguably worse on that test.
Every state indicator needs a second channel — glyph, border weight, or word.

**UI6 — `defer` gets its own role and its own word, in all three sites.** A defer is unfinished work that
may still be a real finding; a kill is adjudicated. Colouring them alike tells the operator the queue is
complete when it is not.

**UI7 — `opacity` may animate; it may never encode state.** Delete `research_detail.html:24`'s
`opacity:.6` and `triage.html:18`'s `opacity:.75`. Recovers 2.50 → 5.57 and 3.41 → 6.03. Refuted
candidates collapse in `<details>` instead — **collapsing is honest, dimming is not**: collapsing says
the reader chose not to read this and can choose otherwise; dimming says the tool decided it was not
worth reading, on the authority of a refuter whose false-kill rate is unmeasured.

**UI8 — Three-state theme (system / light / dark), default = system, expressed as the *absence* of
`data-theme`.** Structure: light unconditional on bare `:root`; dark redefined under
`@media (prefers-color-scheme: dark)` guarded as `:root:not([data-theme="light"])`; dark again under
`:root[data-theme="dark"]`. Three-state wins mechanically, not philosophically: the working default is
the unstamped state, so every failure mode of the pre-paint script degrades to "follow the OS" rather
than "wrong theme forever" — which is exactly the bug that shipped. `color-scheme` is declared with each
state; it is the only thing that themes the native `<select>` popup, the checkbox, and five scrollbars.

**UI9 — No webfont, from any host, ever.** A `fonts.googleapis.com` request would be the only egress in
the product that the egress ledger is *structurally incapable* of recording — issued by the browser, from
the Tier 0 process's own HTML, on every page render, including on the egress screen itself. There are
currently **zero** external URLs anywhere in `quarry/web/`; this decision defends an existing
property. Self-hosting is also rejected: this is a macOS-only product by ruling, `-apple-system` resolves
to San Francisco, and SF has optical sizing that a single-optical-size Inter does not. If overturned, the
vendored `.woff2` and its OFL text ship with a recorded SHA-256, and the same treatment applies
retroactively to the two JS blobs.

**UI10 — Seven type sizes; 9px is deleted; `--fs-title: 18px` is the ceiling.** *Nothing on the screen is
larger than the name of the thing you are looking at.* Today `.card .v` is 22px while `runs.html`'s `h1`
is 20px — the number is bigger than the name of the screen. 9px uppercase mono currently carries
`.prow .tool`, the scanner name on every row of the primary column; it goes to 10px and the row grows
~1px. Weights limited to 400/500/600 — light weights on a dark ground thin the strokes and drop
*effective* contrast below what the token measures.

**UI11 — This product speaks *pane*, not *card*.** Radii stay 2/3/4px, hairlines stay, elevation stays at
zero outside the two ratified overlays. An 8px corner on a 26px row consumes a third of its height and
clips the first character of a file path. And **the 3px coloured edge is already load-bearing** — it
means "here is my adjudication state" in four places (`run.html:16`, `research_detail.html:21,23,24`), so
a decorative gradient top-rule on every card would destroy a working four-state signal in the same
release that relies on it.

**UI12 — A number may be rendered large if and only if it links to the set it summarises, and its label
names the operation that produced it.** The four stat cards on `/runs/{id}` become links rather than
being deleted; `suppressed` loses the kill colour. 425 of 616 suppressed on Nettacker is the
deterministic layer working, and red says the opposite.

**UI13 — Severity colour is prohibited in every form** — hue, chip, row tint, border, icon, filter, sort,
or tiebreak. Measured predictive value: critical 0/11, high 3%, medium 0/26. Colour is pre-attentive and
survives every disclaimer printed beside it: if the rows are red, the operator triages red. `_detail.html:11`'s
`class="pill {{ 'neutral' }}"` — a Jinja expression evaluating to a constant, i.e. the vestigial socket a
severity-conditional class used to plug into — is hardcoded to `pill inert`, so reintroducing severity
colour requires writing new code rather than editing one word.

**UI14 — One `static/app.css` plus `static/theme.css`**, behind six `@layer`s, route-scoped via
`<body data-route="{{ nav }}">` — the variable already exists in every template. Served through an
`asset()` helper emitting a content hash behind an `mtime` check, because `StaticFiles` sets an ETag
derived from `mtime + size` and **no** `Cache-Control`, so a write that preserves both yields a valid
ETag for stale bytes. `theme.css` stays separate: it is the file a human edits to change the palette and
the file the contrast test reads.

**UI15 — No build step.** Every CSS feature required shipped in Safari 16.5 or earlier, against a floor
of Safari 17.0 / macOS 14. Seven components and 197 lines of CSS do not justify a toolchain, and a build
step would not fix §0 — it would add a fourth asset class that also does not ship. CodeMirror 6
(`PLAN.md` D7) is explicitly out of scope: it is ESM-only, it means a bundler, the implementation already
hand-rolled the code pane as a `<table>` of lines, and the gutter disagreement-map that justified it
belongs to a panel view that is unbuilt and gated on measurement.

**UI16 — No new route in this pass, and therefore no sidebar.** Seat 2's own dissent trigger is that a
shell sized for nine routes holding four advertises capacity that does not exist — the same inference the
funnel asks the operator to make. `/targets` and `/producers` both have populated tables and no surface,
and they are the two routes that would prove "room to grow" was a design decision; the sidebar ships in
the same commit as the first of them. Deferred, not refused.

**UI17 — No route may ship without a shipped writer for its backing table.** By this test `/targets`,
`/producers`, `/egress`, `/doctor` and `/nights` are all eligible when their turn comes; `/reports` and
any `/verdicts` screen are not, because `verdicts` has zero rows and no writer until P4. A zero must read
as a measurement, never as an unbuilt thing. The absence is reported once, honestly, on `/doctor` —
`cli.py:226` already writes that string for the terminal.

---

## 3. The five adjudicated splits

The seats contradicted each other. Each resolution below says what the losing seat gave up.

### 3.1 Seat 1 ↔ Seat 4 — which palette

Both proposed complete blue/grey sets; both agreed on `#0D1117` as the ground. **Seat 1's wins on
measurement.** Seat 4's light `--rule-2 #8996A6` fails 1.4.11 at **2.54** against `--sunk` and **2.76**
against the page — the exact defect it set out to fix, and a failure it did not report. Seat 1's
theme-invariant `--edge` clears 3:1 on all five surfaces in both themes (UI3).

*What Seat 4 gave up:* nothing structural. Its two central rulings — that a tint cannot be both a visible
state and a legible surface, and that the fix is therefore never a better colour — are adopted in full
(UI5, and the selection gutter in Phase 3).

### 3.2 Seat 1 ↔ Seat 3 — how to express two themes

Seat 1 wants `light-dark()`: one definition per token, structurally incapable of existing in only one
theme, which is precisely the failure that killed light mode. Seat 3 set the support floor at Safari 17.0
and rejects it, since `light-dark()` shipped in 17.5.

**Resolution: Seat 1's values, Seat 3's three-block structure** (UI8). The critical property survives
either way — light values must be reachable without a media query. Seat 1's `color-scheme` declaration is
adopted regardless of structure.

*What Seat 1 gave up:* 26 values are written twice. Mitigated by the contrast test, which parses both
blocks and fails the suite on any pairing under floor — the duplication becomes checkable rather than
merely disciplined.

### 3.3 Seat 2 ↔ Seat 6 — sidebar and new routes

**Seat 6 wins, on Seat 2's own terms** (UI16).

*What Seat 2 gave up:* the topbar stays a spent budget for now. Its measurement stands and is recorded
for the commit that adds route five: nav links average ~78px at 13px, so nine routes plus the brand is
~730px on a 1280 viewport, leaving ~550px for a context strip that already needs ~580px.

### 3.4 Seats 1 · 3 · 5 · 6 ↔ Seat 2 — Inter

Seat 2 accepts Inter at 14–15px, having measured that font-size costs ~20% of rows-per-screen while the
card idiom costs ~45%. Four seats reject the CDN; Seat 1 rejects self-hosting too. **System stack**
(UI9).

*What Seat 2 gave up:* the typeface. Its density arithmetic is adopted and is the reason UI11 rejects the
card idiom rather than rejecting a font size — those were two different rulings collapsed into one, and
separating them is what saves the reporting aesthetic on `/runs/{id}`.

### 3.5 Seat 5 ↔ Seat 2 ↔ Seat 1 — the four stat cards on `/runs/{id}`

Seat 5 says delete them; Seat 2 says make them links; Seat 1 caps type at 18px. **Links, capped at 18px —
not deletion** (UI12), because Seat 2's rule is satisfiable and strictly better than removal.

*What Seat 5 gave up:* only the deletion. Its second point is adopted in full — `suppressed` loses the
kill colour — as is its ordering ruling: once the cards are links, the funnel's `remaining` column
becomes both the boldest and the largest number on the screen, which is the correct outcome, because its
full derivation is visible in the eleven rows above it.

---

## 4. The plan

Ordered so the riskiest change lands when the safety net already exists. **Phases 0 and 1 contain no
design content** and are worth shipping whether or not the restyle is approved.

### Phase 0 — Make it shippable · 1.5 days

- `pyproject.toml` package-data + `MANIFEST.in`, plus a test that walks the built wheel and asserts
  `templates/` and `static/` are inside it
- The `⌘D` guard: `if (e.metaKey || e.ctrlKey || e.altKey) return;` and widen the focus guard to
  `closest('input,textarea,select,button,[contenteditable]')` — otherwise the new theme toggle becomes a
  key that dismisses producers
- **A restore affordance reaching the route that already exists.** *Ship this first if you ship nothing
  else*
- Delete `<meta http-equiv="refresh">`. Replace with scoped htmx fragment polls at 10s, self-terminating
  when the run reaches a terminal status, gated on `visibilityState`, with a persisted pause toggle
  (WCAG 2.2.1 requires a *control*, and `research_detail.html:47` currently renders a *notice*).
  Candidate cards are never swapped under a reading cursor — poll a count into a stable banner instead
- Fix the nine invalid `font:` shorthands
- Add the `rid` filter to `research_runs()`. `research_detail()` calls it unfiltered, so rendering one run
  runs 5 correlated subqueries plus an `os.kill` probe **per research run in the database** — which
  polling would multiply
- `VENDOR.md` recording htmx 2.0.4 (`e209dda5…`) and Alpine 3.14.8 (`b600e363…`) with upstream URLs
- `53` → `77` in `README.md:13` and `docs/STATUS.md:5`

**Buys:** an installed Quarry that starts; a destructive keystroke that no longer fires on a browser
chord; a reversibility promise the interface keeps; a live view usable for its only purpose.

### Phase 1 — One stylesheet · 2 days

- `theme.css` + `app.css` behind `@layer reset, base, layout, components, pages, utilities`, served
  through the `asset()` content-hash helper, route-scoped via `<body data-route="{{ nav }}">`
- **Move `_detail.html`'s component set into `components` first.** This is the commit that fixes the
  unstyled code pane, and it is the one worth looking at. `_detail.html` gets no `<style>` of its own,
  ever — it renders in two contexts, which is the whole lesson
- Delete the 63 redundant declarations, one template per commit in ascending risk order; resolve the
  `.f`, `.card` and `h1` collisions explicitly, one commit each, with the shift stated in the message
- Lift 84 of the 85 inline `style=` attributes. The survivor is `style="--pct:{{ pct }}%"` — a
  server-computed datum, with `.bar i{inline-size:var(--pct)}` in CSS
- Grid shell: `grid-template-rows: auto 1fr` with `min-block-size: 0` on the main row. `calc(100vh - 46px)`
  disappears from all 7 sites; `body{overflow:hidden}` is deleted. A tokenised `--header-h` is *rejected*
  — it is the same magic number with a name
- `.tbl{overflow:clip}` — `clip` clips to the rounded padding box exactly like `hidden` but does not
  establish a scroll container, so `th{position:sticky}` works for the first time in all 8 tables
- Move `_detail.html:80-81`'s imperative `maxHeight`/`overflowY` into CSS, leaving only the `scrollTop`
  line — inline styles beat every cascade layer, so those two would silently override the new stylesheet

**Constraint:** no commit in this phase changes a declaration's value. Moves and deletions only, provable
by screenshot diff. Required because all eight HTML assertions in `tests/test_web.py` are on prose, so
**no existing test can catch a CSS regression.**

**Buys:** the funnel's killed set renders code as code. Scroll position survives the dismiss/restore 303.
`⌘F` reaches nested panes. Responses drop 40–71% of their bytes.

### Gate — take the two free measurements · 0.75 days · $0

`docs/LAYER2-PLAN.md:498-499` says of the anomaly-cohort measurement, verbatim: *"One afternoon, $0,
**and it decides whether §9's UI is worth building.**"* Both prerequisites run against runs already on
disk, unattended.

If cohorts come back 1:1, `research_detail.html` — 160 lines, 36 inline styles, the most complex
rendering in the codebase — leaves the styling scope and becomes a digest. **This gate can only reduce
the design budget, by removing a screen from it.**

### Phase 2 — Palette and theme · 1.5 days

- Appendix A's tokens in the UI8 structure, plus `color-scheme`
- Four pill classes become six roles with glyphs, migrated **by the mapping table in Appendix B, not by
  `sed`** — and `--kill`/`--ok`/`--warn` are deleted in the same commit, so a missed site fails to a
  broken cascade rather than to a wrong colour
- `defer` gets its own role and its own word (UI6)
- Every `opacity` on text deleted (UI7); refuted candidates collapse in `<details>`
- Three-state toggle in `header.top`, preference in `localStorage`, un-deferred pre-paint script as the
  first thing in `<head>`, and a `matchMedia('change')` listener so the glyph stops lying at sunset
- `--mono` reordered to `ui-monospace, SFMono-Regular, "SF Mono", Menlo, monospace`. "SF Mono" is not
  installed on a clean macOS — it ships with Xcode — so the current stack's first entry is dead and the
  render succeeds by falling through
- Links in prose get underlines: `--accent` against `--ink-2` is **1.20**, far under the 3:1 that
  colour-only differentiation requires. Links that *are* rows or cells keep `text-decoration:none`
- `tests/test_design_tokens.py`: ~30 lines, parses `theme.css`, asserts every pairing against its floor.
  **It fails today** at `ink-3`/`--sunk` = 4.47, which is the correct outcome

**Buys:** the blue/grey that was asked for; a light mode reachable for the first time; a colourblind
operator who can still tell a kill from a recall risk.

### Phase 3 — Stop the small lies · 1.5 days

- `boost` links carry `&action=`; `suppressed()` takes an action parameter; the heading is action-derived
  (`Boosted at "novelty-rank" — 122 shown`) rather than hardcoded to "Suppressed"
- The four stat cards become links; `suppressed` loses the kill colour (UI12)
- `run.html:53` reads `s.remaining` instead of recomputing it (defect 10)
- Selection becomes a 3px `--accent` gutter — **9.10** dark, **7.55** light — plus `aria-current`, with
  the tint as reinforcement
- `tr.hit` becomes `<mark>` plus a gutter glyph, and its tint moves from amber to accent: the flagged line
  is the answer to "where", not a recall risk, and amber means recall risk everywhere else
- The funnel becomes a real `<table>` with `<caption>` and `scope` — today it is a `<div>` grid of
  `<span>`s, so a screen reader reads *"1 path-class 319 · · 297"* with no column association, on the
  screen the whole product rests on. `<caption>` and `scope` on the other six data tables; the two
  `.code` tables become `<pre>` with `tabindex="0" role="region"`, closing the 2.1.1 failure
- `scrollIntoView({block:'nearest'})` after every `j`/`k`; `j` stops navigating the document (htmx swap
  on the detail pane with `hx-push-url`, so columns 1 and 2 never re-render and `all_runs()` stops
  running per keystroke)
- `runs.html:27` adopts the status map from `research.html:95` — a `running` run is currently painted in
  the kill colour, the bug the deep-review side already fixed in `5e7e14a`
- Egress: log the two `targets.py` calls; add `/egress` with `SUM(bytes_out)`, no `LIMIT`, and a column
  distinguishing run-scoped from global rows; give the per-run table an `{% else %}` empty state and move
  it above the suppressed set. `bytes_out` is stored (`schema.sql:181`) and never rendered
- Every `title=` payload rendered as visible text — including `research_detail.html:78`, where the
  template itself says *"A lens that did not run is information, not silence"* and then puts that
  information in an attribute unreachable by keyboard and touch

**Buys:** the auditability claim becomes true on 11 of 11 stages. **Why it is in scope:** a repaint over
these makes the tool more persuasive at exactly the points where it is currently wrong.

### Phase 4 — The look · 1 day

- Sticky nav with pill-active links — already there; it needs to hold more than three items
- A `.page-header` block, **without** the gradient rule (UI11)
- Card and table polish on `/triage` and `/runs/{id}` only. Nothing on `/runs` or `/research` index —
  those carry no argument
- Bounded `minmax(240px,300px) minmax(260px,340px) 1fr` instead of `340px 300px 1fr`, detail content
  capped at 88ch. Rule ids middle-truncate on the dot boundary and paths truncate from the left, both
  with the full string in `title` — `word-break:break-all` currently renders
  `javascript.express.security.audit.xss.mustache.var-in-href` as `…audit.xss.must / ache.var-in-hre / f`
- A band rail at 1024–1279; two panes below 1024; **below 720px the console refuses to reflow** rather
  than pretending to work on a phone where `D` is one tap from a corpus-wide write
- `prefers-reduced-motion` block. Motion budget ≤120ms on interactive chrome, opacity and colour only,
  **0ms on selection state** — at four `j` presses a second a transition is latency added by hand
- An inline-SVG favicon with `prefers-color-scheme` inside the SVG. No shield, no lock — both are
  certainty iconography, and `/favicon.ico` currently 404s into the one log an operator might read

**Buys:** the professional read, landing on a codebase where it is one stylesheet instead of six blocks
in six files.

### Cut line — nothing below this ships now

| Rejected | Cost if built | Why not |
|---|---|---|
| A dashboard / overview route | ~5 h | Its content would be hero numbers over a corpus with 4 confirmed findings. The one change that would make the product *dishonest* rather than merely plain. Three seats concur; Seat 6 dissents to reject if approved |
| A charting library | ~4 h + 200–600 KB | The funnel is already a chart, and the only one whose numbers are links. Precision-over-time has n = 0 confirmed findings; a chart over one data point asserts a trend. cve.icu has charts because its product *is* charts |
| A build step / Tailwind / shadcn / SPA | 1.5–9 days | Seven components, 197 lines of CSS, one platform. Would not fix §0 |
| A design-token pipeline | ~3 h | 21 tokens in one block for one platform. A build step wearing a hat |
| Skeleton loaders | ~3.5 h | Measured against the real database: the largest run (2,456 findings) renders end-to-end in **16.2 ms**. A skeleton that appears and vanishes inside 16 ms is a flash of wrong content |
| Hover-lift cards | ~2 h | `scale(1.02)` resamples tabular figures, and it would put the strongest click affordance on the four inert numbers while the real audit links stay flat |
| A logo mark | unbounded | `omni**audit**` in monospace is already the right wordmark for a tool whose main pane renders source code. `.brand span{color:var(--accent)}` should be *deleted* — it spends the scarcest colour in the system on the second half of a word. The favicon is a separate item and it ships |
| A command palette | — | Four verbs. Revisit when the composer lands |
| Severity colour | — | UI13 |
| A containment badge in the header | gated | Permitted only as a counter (`out 0 B · in 3.4 GB · 4 destinations`), and only after defect 7 is fixed. A green shield sourced from a query that misses two of three hosts is a wrong number in the most-trusted position on every screen. A badge that reads green 100% of the time carries zero bits |

---

## 5. Acceptance gates

`tests/test_web.py` is a good file that cannot catch any of this: all eight of its HTML assertions are on
prose (`"the unit of decision"`, `"every number is a link to the set it killed"`, `"never severity"`,
`"recall risk"`, `"unmeasured"`, `"Producers"`, `"Provenance"`, `"o/r"`), so a change that preserves the
copy and destroys the layout passes every one. Those strings remain a free contract — changing them is a
deliberate act. These gates are what actually guards the refactor.

| # | Gate | Test |
|---|---|---|
| 1 | The built wheel contains `templates/` and `static/` | Walk the wheel in CI. **The one that would have caught §0** |
| 2 | No template contains a `<style>` block or a `style=` attribute | `"<style" not in r.text` for all 7 routes; `style="` count ≤ 1 per response (85 today) |
| 3 | The evidence fragment renders identically from `/triage` and from `#peek` | Every class the fragment uses has a rule in `app.css`; `white-space:pre` reaches both contexts |
| 4 | Zero text pairings below floor in either theme, with `opacity` composited | Parse `theme.css` in pytest. Fails today at `ink-3`/`--sunk` = 4.47 |
| 5 | No `opacity` on any element containing text | `grep -rnE 'opacity:\s*0?\.[0-9]'` returns nothing outside `@keyframes` |
| 6 | Every state indicator has a non-hue channel | Screenshot `/triage` and `/research/{id}` through a deuteranopia filter; every state stays identifiable |
| 7 | Modifier chords never fire a disposition | `⌘D`, `⌘J`, `⌘K`, `⇧⌘D` on `/triage` write zero `funnel_events` rows |
| 8 | Every linked number returns ≥1 row, and the heading names the action | The `boost 122` cell on `novelty-rank` opens a non-empty list |
| 9 | The queue is fully operable, and visible, by keyboard alone | Unplug the mouse: reach the code pane, scroll it with arrows, dismiss, undo. Selected row in viewport after 40 `j` presses |
| 10 | `calc(100vh - 46px)` appears in no rendered response | One substring across all 7 routes — covers the inline instance in `empty.html:3` that a `.page` grep misses |
| 11 | No request leaves the machine on any page load | `grep -rE 'https?://(fonts\|cdn\|unpkg\|jsdelivr)'` returns nothing. Defends an existing property |
| 12 | 200% zoom and 400% reflow do not clip content | WCAG 1.4.4 and 1.4.10 are AA — this makes the shell work a conformance item |
| 13 | `j`/`k` stop navigating the document | After 30 presses, column 1 `scrollTop` unchanged and the server log shows no `all_runs` query |
| 14 | No number renders above 18px without being a link | UI10 + UI12 |
| 15 | `restore` is reachable | `grep -c restore templates/triage.html` > 0, plus a test asserting the rendered page contains the restore action |
| 16 | `<meta http-equiv="refresh">` is gone, and auto-update has an off switch | `grep -rc 'http-equiv'` = 0; pause toggle present and persisted; focus and scroll survive 3 update cycles |

---

## 6. The open question — 7.5 days, or 3.5

Seat 6's cap is 10 hours, anchored on a measurement that holds: **this product was built between 07:21
and 17:03 on 2026-08-23** — 9h42m, 14 commits, 5,080 lines of Python, 77 tests. Its argument is that a
restyle costing more than the product did fails a sanity check regardless of its merits. The plan above
is 7.5 days. That conflict is real and is recorded rather than resolved by assertion.

**Where the chair comes down:** Phases 0 and 1 are not restyle work and Seat 6's cap should not be read as
covering them. Together they are 3.5 days, they contain no design content, and they fix a package that
cannot install, a keystroke that fires on `⌘D`, an undo with no button, a live view that reloads 1,440
times over an 8-hour run, and an evidence pane that renders Python with its indentation collapsed. Those
are defects. They would be worth fixing if the palette were never touched.

Phases 2–4 are the actual request, at 4 days. **Two seats independently named the same test for whether
those 4 days are worth it, from opposite directions:**

> **Seat 6:** *"If the owner states that Quarry will be published with a screenshot-led README, shown
> to people who will judge the deterministic layer by that picture — then I raise the Tier C cap from 3.25
> hours to a full day and promote `/runs/{id}` typography into Tier B."*

> **Seat 1:** *"If a screenshot of `/triage` leaves this machine more often than a triage sitting happens
> on it, I am solving the wrong problem… The product already has the instrument — it is the egress ledger
> on `run.html:110`."*

Both are asking the same question: **is this interface a tool you operate, or also the argument you make
to other people?**

- **A tool you operate** → Phases 0–2. About 5 days. You get the blue/grey, a working dark mode, and
  every defect fixed.
- **Also an argument** → Phases 0–4. 7.5 days. Phase 3 earns its place, because the auditability thesis
  genuinely is made in a picture, and a picture of a funnel whose `boost` links open an empty table makes
  it badly.

That decision is the principal's, not the panel's. Under `AMENDMENTS.md`'s standing rule — *"The principal
may overrule the rule; he may not overrule it silently"* — whichever way it goes should be recorded there.

**Recorded dissent triggers, unresolved:**

- **Seat 4** flips to unconditional reject if the redesign lands with `<meta http-equiv="refresh">` still
  in place, or with `opacity:.6` still deciding which evidence is legible. *"Either one would show the
  panel was read as a palette request."*
- **Seat 5** flips to reject if a palette change ships without defects 5, 8 and 7 fixed: *"a restyle that
  leaves the boost links dead, defer red, and the egress ledger under-counting its own hosts has made the
  tool more persuasive at exactly the six points where it is currently wrong."*
- **Seat 6** moves to reject if a dashboard route is approved, if scope passes 3 days, or if
  `research_detail.html` is styled before the gate measurement is taken.
- **Seat 2** moves to delete the sidebar if it ships and `/targets`/`/producers` are still not built six
  weeks later.
- **Seat 3** flips if CodeMirror 6 or any npm dependency is scheduled within two phases of this work — in
  that world the build step is arriving anyway and a hand-rolled stylesheet would have to be redone.

---

## Appendix A — the token block

Values verified at **142 pairings, 0 failures**, against floors stricter than AA. `--edge` is
theme-invariant by result, not by shortcut (UI3).

```css
/* static/theme.css — light is unconditional; dark redefines tokens only. */
:root{
  color-scheme: light dark;

  --bg:#F4F6FA; --panel:#FFFFFF; --sunk:#ECEFF5; --hover:#E1E6EF;
  --raised:#FFFFFF; --rule:#DDE3EC;
  --edge:#6E7C90;                        /* theme-invariant: 3.39 worst, both themes */

  --ink:#111721; --ink-2:#3F4B5C; --ink-3:#56626F; --on-fill:#FFFFFF;
  --accent:#1C58AD; --accent-h:#12417F; --accent-bg:#E3EBF7;

  --verified:#116348;   --verified-bg:#E1F1E9;
  --incomplete:#7C5209; --incomplete-bg:#F7EED9;
  --alarm:#9C281C;      --alarm-bg:#FBE6E2;
  --killed:#4E5F77;     --killed-bg:#ECEFF5;
  --unmeasured:#56626F; --unmeasured-bg:#ECEFF5;
  --inert:#56626F;      --inert-bg:#ECEFF5;

  --sans:-apple-system,BlinkMacSystemFont,system-ui,"Segoe UI",sans-serif;
  --mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,monospace;

  --fs-micro:10px; --fs-meta:11px; --fs-dense:12px; --fs-cell:13px;
  --fs-body:14px;  --fs-lead:15px; --fs-title:18px;      /* ceiling — UI10 */
  --lh-tight:1.25; --lh-ui:1.45; --lh-prose:1.6; --lh-code:1.55;
  --tr-micro:.09em; --tr-tool:.06em;
  --wt-reg:400; --wt-med:500; --wt-bold:600;             /* no 300 — UI10 */

  --r-chip:2px; --r-ctl:3px; --r-panel:4px; --r-overlay:6px;
  --bw-hair:1px; --bw-mark:3px;                          /* semantic only — UI11 */
  --sp-2:2px; --sp-4:4px; --sp-6:6px; --sp-8:8px; --sp-12:12px;
  --sp-16:16px; --sp-20:20px; --sp-24:24px; --sp-32:32px; --sp-48:48px;
  --sp-tail:64px;

  --viz-track:var(--sunk); --viz-fill:var(--accent);     /* the product has one chart */
}

@media (prefers-color-scheme: dark){
  :root:not([data-theme="light"]){
    color-scheme: dark;
    --bg:#0D1117; --panel:#141A23; --sunk:#1A212C; --hover:#222A37;
    --raised:#1E2735; --rule:#232C39;
    --ink:#E9EDF4; --ink-2:#ADB7C7; --ink-3:#8792A6; --on-fill:#0B1017;
    --accent:#7FA9E0; --accent-h:#A3C4EE; --accent-bg:#16263D;
    --verified:#6FC79E;   --verified-bg:#12261F;
    --incomplete:#E0B063; --incomplete-bg:#2A2114;
    --alarm:#EE9285;      --alarm-bg:#331F1C;
    --killed:#8FA6C6;     --killed-bg:#172130;
    --unmeasured:#9AA4B5; --unmeasured-bg:#191F29;
    --inert:#8B93A0;      --inert-bg:#1A1F27;
  }
}
:root[data-theme="dark"]{
  color-scheme: dark;
  /* …the same dark block, repeated. The duplication is the cost of UI8's
     structure over light-dark(); the contrast test reads both and is the
     mechanism that keeps them in step. */
}
```

Pre-paint script — first thing in `<head>`, **not** deferred:

```html
<script>try{var t=localStorage.getItem('oa-theme');
if(t==='light'||t==='dark')document.documentElement.dataset.theme=t}catch(e){}</script>
```

`try/catch` because `localStorage` *throws* rather than returning null in some privacy contexts.
`'system'` is never written — it is `removeItem`, so the attribute is absent and `color-scheme` does the
work.

### Measured floors

| Token | Floor | Dark, worst | Light, worst | Why the floor is above 4.5 |
|---|---|---|---|---|
| `--ink` | 12.0 | 12.30 | 14.35 | 14px prose read for an hour |
| `--ink-2` | 7.0 | 7.13 | 7.07 | tens of thousands of 13px table cells |
| `--ink-3` | 4.6 | 4.60 | 4.97 | every microlabel; the current token fails at 4.47 |
| `--accent` | 4.6 | 5.95 | 5.50 | links and the focus ring (2.4.11) |
| six roles | 4.6 | 4.66 | 4.97 | on all five surfaces **and** `--accent-bg` **and** their own fills |
| `--edge` | 3.0 | 3.40 | 3.39 | every control boundary (1.4.11) |

For comparison, over the same pairing set: **shipped dark = 16 text failures. cve.icu dark verbatim = 34.
cve.icu light verbatim = 54.**

---

## Appendix B — the role mapping table

Implement from this. **A rename by `sed` reproduces defect 8 with new spelling.** Migrate file by file
and delete `--kill`/`--ok`/`--warn` in the same commit.

| Site | Today | Role |
|---|---|---|
| `run.html:70` kill legend | `--kill` | `--killed` — no longer red |
| `run.html:71` defer legend | `--kill` | `--incomplete` — **the D8 fix** |
| `run.html:72` merge legend | `--warn` | `--inert` — a dedupe is bookkeeping |
| `run.html:41` `suppressed` stat | `--kill` | `--ink` — it is a count, not a warning |
| `run.html:56,86`, `_detail.html:61` `recall risk` / `heuristic` | `warn` | `--incomplete` — what amber is *for* |
| `run.html:83`, `_detail.html:58` kill/defer/merge | `bad`/`warn` | `--killed` / `--incomplete` / `--inert` |
| `run.html:34` `not OSI — CodeQL gated off` | `--warn` | `--incomplete` — a scanner was turned off; recall lost |
| `run.html:101` quarantine kind | `bad`/`warn` | `--inert` — containment worked; the row existing *is* the signal |
| `runs.html:27` status | `good`/`bad` | done → `--verified`, running → `--accent`, stopped → `--inert`, died/stalled → `--alarm` |
| `research.html:95` running | `warn` | `--accent` — a healthy run stops being amber |
| `research.html:102` `N err` | `bad` | `--alarm` |
| `research_detail.html:74` lenses that ran | `good` | `--inert` — completion is not corroboration |
| `research_detail.html:121` quote verified / NOT in source | `good`/`bad` | `--verified` / `--alarm` — a quote not in source means the model fabricated |
| `research_detail.html:122` model severity | `neutral`, unlabelled | `--inert`, **and prefixed `claims`** — the less trustworthy claim currently gets the more confident presentation |
| `research_detail.html:125` survived / refuted | `good`/`bad` | `--verified` / `--killed` — refuted is not an alarm |
| `research_detail.html:127` refuter error | `warn` | `--alarm` |
| `research_detail.html:21` default `.f` | `--rule-2` | `--unmeasured` — this state was semantic all along |
| `triage.html:111` `×N corrob` | `good` | `--verified` |
| `triage.html:112` precision | `good`/`bad` | `--verified` / `--killed` — never-confirmed is a band, not a failure |
| `triage.html:59` `tr.hit` | `--warn-bg` | `--accent-bg` — the flagged line is "where", not a risk |
| `triage.html:66` `.prov .delta` | `--ok`/`--kill` | **delete both.** A score delta is arithmetic; the sign carries it |
| `_detail.html:9` cross-tool cluster | `good` | `--verified` |
| `_detail.html:10` secret redacted | `bad` | `--alarm` — correct as-is |
| `_detail.html:11` `claims {severity}` | `{{ 'neutral' }}` | **hardcode `pill inert`** and delete the expression (UI13) |
| `research.html:27`, `research_detail.html:20` `.bar i` | `--accent` | `--viz-fill`, and drop `--accent` from non-interactive chrome |
| `base.html:44` `.brand span` | `--accent` | **delete** — the wordmark spends the auditability colour on half a word |

**Two grep-testable guards:**

1. Severity never carries a role but `--inert`.
   `grep -n severity templates/*.html | grep -vE 'inert'` → nothing.
2. `--alarm` has exactly five sanctioned uses — run died/stalled, unit errored, refuter errored,
   quote-not-in-source, secret found — plus the dismiss button. `grep -c alarm templates/*.html` ≤ 8.

**The colour budget, read down the "means" column, is the product's thesis rendered as a palette:**

| token | means |
|---|---|
| `--accent` | this opens its evidence |
| `--verified` | machine-checked and it held |
| `--killed` | evidence said no — the funnel working |
| `--incomplete` | the instrument is unreliable here |
| `--alarm` | the instrument failed, or you are about to lose something |
| `--inert` | someone's unverified claim |

A security tool whose dominant accent is amber rather than red is telling the truth about itself.
