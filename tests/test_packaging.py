"""The package has to contain the dashboard.

This is the highest-value test in the design pass, because the defect it catches was
invisible to every other kind of check: `pip install .` produced a wheel of 34 files
with nothing under `templates/` or `static/`, and `quarry/web/app.py` constructs
`StaticFiles(directory=.../static)` at *import* time — `check_dir` defaults to True and
raises on a missing directory, and `app = create_app()` is module-level. So an installed
Quarry raised on import and could not start its own dashboard.

Nothing failed in development because development runs from the source tree. The
"vendored, no CDN, offline" posture was being held up by nobody installing the package.

Building a wheel is slow enough that these are marked; run them with `-m ''` or just
`pytest tests/test_packaging.py`.
"""
from __future__ import annotations

import hashlib
import re
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "quarry" / "web" / "static"


# --------------------------------------------------------------- offline gate

def _package_data_globs() -> list[str]:
    """The `[tool.setuptools.package-data] quarry = [...]` list, as written."""
    text = (ROOT / "pyproject.toml").read_text()
    block = re.search(
        r"\[tool\.setuptools\.package-data\][^\[]*?quarry\s*=\s*\[(.*?)\]",
        text, re.S)
    assert block, "pyproject.toml declares no package-data for quarry"
    return re.findall(r'"([^"]+)"', block.group(1))


def test_package_data_globs_match_real_files():
    """Every declared glob must match something, and the assets must be covered.

    This is the always-on version of the wheel test below: it needs no build, no
    network and no setuptools, and it catches the actual defect — a package-data list
    that simply did not mention `web/templates/*.html` or `web/static/*`, so the two
    directories the dashboard cannot start without were silently absent from the
    distribution.
    """
    pkg = ROOT / "quarry"
    globs = _package_data_globs()
    for pattern in globs:
        assert list(pkg.glob(pattern)), \
            f"package-data pattern {pattern!r} matches nothing under quarry/"

    matched = {p.resolve() for pattern in globs for p in pkg.glob(pattern)}

    templates = sorted((pkg / "web" / "templates").glob("*.html"))
    assert templates, "no templates on disk — this test is checking the wrong path"
    missing = [p.name for p in templates if p.resolve() not in matched]
    assert not missing, f"templates not covered by package-data: {missing}"

    required_static = ["app.css", "theme.css", "favicon.svg",
                       "htmx.min.js", "alpine.min.js"]
    for name in required_static:
        p = pkg / "web" / "static" / name
        assert p.exists(), f"{name} is missing from static/"
        assert p.resolve() in matched, f"{name} is not covered by package-data"


def test_manifest_in_covers_the_sdist():
    """package-data covers the wheel; MANIFEST.in covers `sdist`."""
    man = (ROOT / "MANIFEST.in")
    assert man.exists(), "no MANIFEST.in — an sdist would omit the dashboard"
    text = man.read_text()
    assert "quarry/web/templates" in text
    assert "quarry/web/static" in text


# ------------------------------------------------- full build, when possible

@pytest.fixture(scope="module")
def wheel(tmp_path_factory) -> zipfile.ZipFile:
    """A real wheel, if this environment can build one without touching the network.

    Skips rather than fails when `setuptools` is absent from the venv: the offline
    gates above are the ones that must always run, and a test that silently reaches for
    the network would contradict the product it is testing.
    """
    try:
        import setuptools  # noqa: F401
    except ImportError:
        pytest.skip("setuptools is not installed in this environment; "
                    "the offline package-data gates cover the same defect")
    out = tmp_path_factory.mktemp("wheel")
    r = subprocess.run(
        [sys.executable, "-m", "pip", "wheel", "--no-deps", "--no-build-isolation",
         "--no-index", "-w", str(out), str(ROOT)],
        capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        pytest.skip(f"cannot build a wheel offline here: {r.stderr[-300:]}")
    wheels = list(out.glob("quarry-*.whl"))
    if not wheels:
        pytest.skip("pip wheel produced no quarry wheel")
    return zipfile.ZipFile(wheels[0])


def test_wheel_ships_the_templates(wheel):
    names = wheel.namelist()
    got = sorted(n for n in names if "/web/templates/" in n and n.endswith(".html"))
    assert got, ("the wheel contains no templates — an installed Quarry cannot "
                 "render a page")
    # Every template in the tree, not just some of them.
    on_disk = {p.name for p in (ROOT / "quarry" / "web" / "templates").glob("*.html")}
    shipped = {Path(n).name for n in got}
    assert on_disk == shipped, f"missing from the wheel: {sorted(on_disk - shipped)}"


def test_wheel_ships_the_static_assets(wheel):
    """Including the CSS. `StaticFiles` raises at import if the directory is absent, so
    this is the difference between a working install and an ImportError."""
    shipped = {Path(n).name for n in wheel.namelist() if "/web/static/" in n}
    required = {"app.css", "theme.css", "favicon.svg",
                "htmx.min.js", "alpine.min.js",
                "inter-latin-wght-normal.woff2", "INTER-LICENSE.txt"}
    assert required <= shipped, f"missing from the wheel: {sorted(required - shipped)}"


def test_wheel_still_ships_the_schema_and_sandbox_profiles(wheel):
    """The pre-existing package-data entries must survive the new ones."""
    shipped = {Path(n).name for n in wheel.namelist()}
    assert "schema.sql" in shipped
    assert {n for n in shipped if n.endswith(".sb")}, "no sandbox profiles in the wheel"


def test_vendored_assets_match_recorded_hashes():
    """`static/VENDOR.md` records a version and a SHA-256 for every vendored blob.

    A tool that stores every quarantined scanner config as prefix + SHA-256 should not
    serve unattributed minified third-party JavaScript. Nothing in the repo recorded
    what htmx.min.js or alpine.min.js even *were* before this.
    """
    doc = (STATIC / "VENDOR.md").read_text()
    rows = re.findall(r"^\|\s*`([^`]+)`\s*\|\s*([^|]+?)\s*\|\s*(\d+)\s*\|\s*`([0-9a-f]{64})`",
                      doc, re.M)
    assert rows, "VENDOR.md records no assets"
    for name, _version, size, sha in rows:
        f = STATIC / name
        assert f.exists(), f"VENDOR.md records {name}, which is not in static/"
        body = f.read_bytes()
        assert len(body) == int(size), \
            f"{name} is {len(body)} bytes, VENDOR.md says {size}"
        assert hashlib.sha256(body).hexdigest() == sha, \
            f"{name} does not match its recorded sha256 — update VENDOR.md deliberately"


def test_every_vendored_blob_is_recorded():
    """The inverse: a new blob in static/ must be added to VENDOR.md, not just dropped
    in. This is what stops the manifest going stale by omission."""
    doc = (STATIC / "VENDOR.md").read_text()
    blobs = [*STATIC.glob("*.js"), *STATIC.glob("*.woff2")]
    assert any(f.suffix == ".woff2" for f in blobs), "the vendored typeface is missing"
    for f in blobs:
        assert f"`{f.name}`" in doc, f"{f.name} is served but not recorded in VENDOR.md"


def test_docs_state_the_real_test_count():
    """README and STATUS carry the credibility argument, so a stale count is a defect
    in the argument. They said 53 while the suite collected 77."""
    r = subprocess.run([sys.executable, "-m", "pytest", "--collect-only", "-q"],
                       cwd=ROOT, capture_output=True, text=True, timeout=180)
    m = re.search(r"(\d+) tests? collected", r.stdout)
    if not m:
        pytest.skip("could not read the collected test count")
    actual = int(m.group(1))
    for doc in ("README.md", "docs/STATUS.md"):
        text = (ROOT / doc).read_text()
        claimed = [int(x) for x in re.findall(r"(\d+)\s+tests\b", text)]
        for c in claimed:
            assert c == actual, \
                f"{doc} claims {c} tests; the suite collects {actual}"
