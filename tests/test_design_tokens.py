"""The palette is measured, not eyeballed.

`docs/DESIGN-PLAN.md` UI2 ships a token set verified at 142 pairings against floors
stricter than WCAG AA. This file is what makes that claim enforceable: a future palette
change fails the suite rather than a review.

It failed on the palette that shipped before it — `--ink-3` on `--sunk` was 4.47:1 —
which is the correct outcome for a test like this and the reason it exists.

Two rules it also enforces, because both were real defects rather than hypotheticals:

* **`opacity` is banned on text.** `opacity` composites in non-linear sRGB *after* the
  token values are chosen, so a token table structurally cannot see the result. Nine of
  the sixteen text failures in the previous dark theme came from two `opacity`
  declarations, and the worst of them put a refuted finding's own refutation at 2.50:1.
* **No external origin.** A webfont or CDN script would be egress that the egress
  ledger cannot record, because the browser would issue it rather than `quarry`.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

WEB = Path(__file__).resolve().parents[1] / "quarry" / "web"
THEME = WEB / "static" / "theme.css"
APP_CSS = WEB / "static" / "app.css"

# ---- floors, from docs/DESIGN-PLAN.md UI2 ---------------------------------------
SURFACES = ("bg", "panel", "sunk", "hover", "raised")
ROLES = ("verified", "incomplete", "alarm", "killed", "unmeasured", "inert")
INK_FLOORS = {"ink": 12.0, "ink-2": 7.0, "ink-3": 4.6}
ROLE_FLOOR = 4.6          # body text on every surface it can land on
EDGE_FLOOR = 3.0          # WCAG 1.4.11, non-text UI boundary


# ---- WCAG 2.1 relative luminance ------------------------------------------------

def _lin(c: float) -> float:
    c /= 255
    return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4


def luminance(hex_colour: str) -> float:
    h = hex_colour.lstrip("#")
    r, g, b = (int(h[i:i + 2], 16) for i in (0, 2, 4))
    return 0.2126 * _lin(r) + 0.7152 * _lin(g) + 0.0722 * _lin(b)


def contrast(a: str, b: str) -> float:
    la, lb = luminance(a), luminance(b)
    hi, lo = max(la, lb), min(la, lb)
    return (hi + 0.05) / (lo + 0.05)


# ---- parse theme.css ------------------------------------------------------------

_HEX = re.compile(r"--([a-z0-9-]+)\s*:\s*(#[0-9A-Fa-f]{6})\s*;")


def _block(css: str, start: int) -> str:
    """The text of one brace-balanced block starting at the first `{` after `start`."""
    i = css.index("{", start)
    depth, j = 0, i
    while j < len(css):
        if css[j] == "{":
            depth += 1
        elif css[j] == "}":
            depth -= 1
            if depth == 0:
                return css[i + 1:j]
        j += 1
    raise AssertionError("unbalanced braces in theme.css")


def _rule(css: str, selector: str) -> int:
    """Where the rule for `selector` starts: the selector followed by its `{`.

    `css.index(selector)` found the first MENTION, and theme.css names both dark
    selectors in its header comment, so both lookups landed in that comment and
    `_block` then read the next brace, which was the light `:root{`. Every "dark"
    assertion in this file was checking the light palette twice, and the dark
    palette was never measured at all.
    """
    m = re.search(re.escape(selector) + r"\s*\{", css)
    assert m, f"no rule for {selector} in theme.css"
    return m.start()


def themes() -> dict[str, dict[str, str]]:
    """{'light': {...}, 'dark': {...}} — every hex token, per theme.

    Light comes from the bare `:root`. Dark is light overlaid with the
    `[data-theme="dark"]` block, which is the branch an explicit choice takes. The
    media-query block is asserted separately to hold the *same* values, because the
    two dark blocks are hand-duplicated and drift is exactly what this catches.
    """
    css = THEME.read_text()
    light = dict(_HEX.findall(_block(css, _rule(css, ":root"))))
    dark_attr = dict(_HEX.findall(
        _block(css, _rule(css, ':root[data-theme="dark"]'))))
    return {"light": light, "dark": {**light, **dark_attr}}


def _media_dark() -> dict[str, str]:
    css = THEME.read_text()
    return dict(_HEX.findall(
        _block(css, _rule(css, ':root:not([data-theme="light"])'))))


# ---- the gates ------------------------------------------------------------------

@pytest.mark.parametrize("theme", ["light", "dark"])
@pytest.mark.parametrize("token,floor", sorted(INK_FLOORS.items()))
def test_ink_clears_its_floor_on_every_surface(theme, token, floor):
    """Text tokens, against every surface they are actually rendered on.

    `--accent-bg` is included because a selected row is a surface: the old palette put
    the tool name on a selected row at 4.19:1, so contrast degraded exactly where the
    operator's attention was.
    """
    t = themes()[theme]
    for surface in (*SURFACES, "accent-bg"):
        got = contrast(t[token], t[surface])
        assert got >= floor, (
            f"{theme}: --{token} on --{surface} is {got:.2f}, floor {floor}")


@pytest.mark.parametrize("theme", ["light", "dark"])
@pytest.mark.parametrize("role", ROLES)
def test_role_clears_its_floor_everywhere_it_lands(theme, role):
    """A role colour appears on five surfaces, on a selected row, and on its own fill.

    Pills sit inside selected rows and inside legends on the page background, so
    testing a role only against its own `-bg` would miss most of where it renders.
    """
    t = themes()[theme]
    for surface in (*SURFACES, "accent-bg", f"{role}-bg"):
        got = contrast(t[role], t[surface])
        assert got >= ROLE_FLOOR, (
            f"{theme}: --{role} on --{surface} is {got:.2f}, floor {ROLE_FLOOR}")


@pytest.mark.parametrize("theme", ["light", "dark"])
def test_accent_clears_the_floor_as_link_and_focus_ring(theme):
    t = themes()[theme]
    for surface in (*SURFACES, "accent-bg"):
        got = contrast(t["accent"], t[surface])
        assert got >= ROLE_FLOOR, \
            f"{theme}: --accent on --{surface} is {got:.2f}"


@pytest.mark.parametrize("theme", ["light", "dark"])
def test_edge_is_a_visible_boundary_on_every_surface(theme):
    """WCAG 1.4.11. Every control's boundary is this one token.

    The previous `--rule-2` was 1.68:1 against `--panel`, and the control fill was
    1.07:1 against it, so the boundary of every button, input and select in the product
    was invisible. `--edge` is theme-invariant, which is a *result*: all five surfaces
    in both themes sit at the luminance extremes.
    """
    t = themes()[theme]
    for surface in SURFACES:
        got = contrast(t["edge"], t[surface])
        assert got >= EDGE_FLOOR, \
            f"{theme}: --edge on --{surface} is {got:.2f}, floor {EDGE_FLOOR}"


def test_edge_really_is_theme_invariant():
    """If someone gives --edge a per-theme value, the claim in theme.css is stale."""
    t = themes()
    assert t["light"]["edge"] == t["dark"]["edge"]


def test_both_dark_blocks_agree():
    """The media-query block and the [data-theme] block are hand-duplicated.

    `light-dark()` would make that structurally impossible, but it shipped in Safari
    17.5, above this product's 17.0 floor. So the duplication stays and this test is
    what keeps the two halves in step.
    """
    attr = themes()["dark"]
    media = _media_dark()
    assert media, "the prefers-color-scheme block defines no tokens"
    for k, v in media.items():
        assert attr[k].lower() == v.lower(), (
            f"--{k} is {v} under prefers-color-scheme but {attr[k]} under "
            f'[data-theme="dark"]')


def test_every_dark_token_is_also_defined_on_bare_root():
    """The bug that killed light mode, generalised.

    A token defined only inside a dark block is undefined in the un-stamped light
    state. Light must be the unconditional base so an explicit override always has
    values to reach.
    """
    light, dark_only = themes()["light"], _media_dark()
    missing = sorted(set(dark_only) - set(light))
    assert not missing, f"defined only in a dark block: {missing}"


def _strip_comments(text: str) -> str:
    """Blank out CSS and Jinja comments, preserving line numbers.

    The rules below scan for declarations, not for prose. Several comments in this
    codebase quote the very defects being asserted against — `opacity:.6` is named in
    app.css and research_detail.html precisely to record why it is gone — and a gate
    that cannot tell a declaration from its own changelog is a gate nobody keeps.
    """
    def blank(m: re.Match) -> str:
        return re.sub(r"[^\n]", " ", m.group(0))
    text = re.sub(r"/\*.*?\*/", blank, text, flags=re.S)
    return re.sub(r"\{#.*?#\}", blank, text, flags=re.S)


def test_opacity_is_never_used_to_encode_state():
    """`opacity` may animate; it may never carry meaning.

    It composites where the token file cannot see it, and it degrades every contrast
    ratio in a subtree at once, so it cannot be reasoned about locally.
    """
    offenders = []
    for f in [APP_CSS, THEME, *(WEB / "templates").glob("*.html")]:
        for i, line in enumerate(_strip_comments(f.read_text()).splitlines(), 1):
            if re.search(r"opacity\s*:\s*0?\.\d", line):
                offenders.append(f"{f.name}:{i}: {line.strip()}")
    assert not offenders, "fractional opacity found:\n" + "\n".join(offenders)


def test_no_type_larger_than_the_ceiling():
    """UI10: nothing on the screen is larger than the name of the thing you are
    looking at. `--fs-title` is 18px and is the largest size token."""
    css = _strip_comments(APP_CSS.read_text() + THEME.read_text())
    big = [m for m in re.findall(r"font-size:\s*(\d+)px", css) if int(m) > 18]
    assert not big, f"font sizes above the 18px ceiling: {sorted(set(big))}"
    assert "--fs-title:18px" in THEME.read_text().replace(" ", "")


def test_no_light_font_weights():
    """Light weights thin the strokes and drop *effective* contrast below what the
    token measures, because the ratio is computed on a solid colour."""
    css = _strip_comments(APP_CSS.read_text() + THEME.read_text())
    assert not re.search(r"font-weight:\s*(100|200|300)\b", css)
    assert not re.search(r"--wt-[a-z]+:\s*(100|200|300)\b", css)


def test_no_external_origin_anywhere_in_the_web_layer():
    """A webfont or CDN script would be the only egress in the product that the egress
    ledger is structurally incapable of recording.

    What is refused is anything the BROWSER fetches by itself: `src=`, a `<link>` or
    any other element's `href=`, and `url(...)` / `@import` in CSS. A plain `<a href>`
    is not a fetch; it goes nowhere until the operator clicks it. The header's
    "by RogoLabs" link is the one such anchor, and it is the reason this test reads
    the tag rather than every `href`.
    """
    offenders = []
    for f in WEB.rglob("*"):
        if f.suffix not in {".html", ".css", ".py"} or not f.is_file():
            continue
        src = _strip_comments(f.read_text(errors="replace"))
        for i, line in enumerate(src.splitlines(), 1):
            if re.search(r"""\bsrc\s*=\s*["']https?://""", line):
                offenders.append(f"{f.name}:{i}")
            for m in re.finditer(r"""<(\w+)\b[^>]*\bhref\s*=\s*["']https?://""", line):
                if m.group(1).lower() != "a":
                    offenders.append(f"{f.name}:{i}")
            if re.search(r"@import\s+url\(\s*['\"]?https?://", line):
                offenders.append(f"{f.name}:{i}")
            if re.search(r"url\(\s*['\"]?(?:https?:)?//", line):
                offenders.append(f"{f.name}:{i}")
    assert not offenders, f"external origin referenced at {offenders}"


def test_the_typeface_is_served_from_static():
    """Inter is vendored. The @font-face source must be a relative file under
    /static, which test_packaging hashes against VENDOR.md."""
    css = _strip_comments(THEME.read_text() + APP_CSS.read_text())
    srcs = re.findall(r"@font-face\s*\{[^}]*?src:\s*url\(\s*['\"]?([^'\")]+)", css)
    assert srcs, "no @font-face found"
    for s in srcs:
        assert "/" not in s and ":" not in s, f"font source {s!r} is not a local file"
        assert (WEB / "static" / s).is_file(), f"{s} is not in static/"


def test_wide_content_scrolls_inside_its_own_container():
    """MEASURED: /research/{id} rendered 1140px of document in an 855px viewport, so
    the fourth stat card and three table columns were unreachable.

    `overflow:clip` on .tbl let the sticky <th> escape to the page scroller but gave
    the table no scrollport, so a table wider than its container pushed the whole page
    sideways. `th{white-space:nowrap}` guarantees these tables have a wide content
    minimum, so this was not a corner case.

    A table cannot be both a horizontal scroller and have a page-level sticky header.
    The choice is horizontal scroll; stickiness is scoped to `.tall`, which bounds its
    height and so becomes its own scrollport.
    """
    css = _strip_comments(APP_CSS.read_text())
    tbl = re.search(r"\.tbl\{([^}]*)\}", css)
    assert tbl, ".tbl rule not found"
    body = tbl.group(1).replace(" ", "")
    assert "overflow:auto" in body, \
        ".tbl must be its own scrollport, or wide tables scroll the page instead"
    assert "overflow:clip" not in body and "overflow:hidden" not in body

    # Stickiness must be scoped to a container that actually scrolls vertically.
    assert not re.search(r"(?<!\.tall )thead th\{[^}]*position:sticky", css), \
        "an unscoped sticky thead sticks to a box that never scrolls"
    assert ".tbl.tall thead th{position:sticky" in css.replace(" ", "").replace(
        ".tbl.talltheadth", ".tbl.tall thead th"), \
        "sticky headers belong inside .tall, which bounds its height"


def test_the_shell_grid_is_bounded_to_the_container():
    """MEASURED: body clientWidth 855, scrollWidth 1140 — the page scrolled sideways
    and the fourth stat card plus three table columns were unreachable.

    `.app` is a grid, and its single implicit column was `auto`, which sizes to its
    content's MAX-CONTENT width rather than to the container. So `main` grew past the
    viewport and dragged the document with it. This is the same trap that made
    `.prow`'s text-overflow never fire: a grid item's automatic minimum size is its
    content unless told otherwise.

    Chasing this through `.tbl` first was wrong — no table was overflowing its own box.
    The container was.
    """
    css = _strip_comments(APP_CSS.read_text()).replace(" ", "").replace("\n", "")
    app_rule = re.search(r"\.app\{([^}]*)\}", css)
    assert app_rule, ".app rule not found"
    assert "grid-template-columns:minmax(0,1fr)" in app_rule.group(1), (
        "the shell grid needs an explicit bounded column, or an auto column sizes to "
        "max-content and the page scrolls sideways")
    main_rule = re.search(r"\.app>main\{([^}]*)\}", css)
    assert main_rule and "min-inline-size:0" in main_rule.group(1), (
        "the grid item needs min-inline-size:0 too — its automatic minimum is its "
        "content")
