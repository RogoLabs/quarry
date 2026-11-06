"""IMPROVEMENT-PLAN item 19: the prior-advisory lookup searches the package names the
clone's own manifests declare, not the repository name, and the draft says which names
were searched and which were not.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quarry import vulndb                                               # noqa: E402
from quarry.disclosure import draft_reports                             # noqa: E402
from quarry.disclosure.packages import PackageName, declared_packages   # noqa: E402
from test_disclosure import _confirm, _db                               # noqa: E402
from test_vulndb_prior import _osv_zip, _rec                            # noqa: E402


def _names(pkgs):
    return [(p.ecosystem, p.name, p.source, p.skip) for p in pkgs]


def test_every_manifest_kind_is_read_without_running_anything(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "acme-widgets"\n')
    (tmp_path / "go.mod").write_text("module github.com/acme/widgets\n\ngo 1.22\n")
    (tmp_path / "Cargo.toml").write_text('[package]\nname = "widgets_core"\n')
    (tmp_path / "package.json").write_text(json.dumps({"name": "@acme/widgets"}))
    assert _names(declared_packages(tmp_path)) == [
        ("npm", "@acme/widgets", "package.json", ""),
        ("PyPI", "acme-widgets", "pyproject.toml", ""),
        ("Go", "github.com/acme/widgets", "go.mod", ""),
        ("crates.io", "widgets_core", "Cargo.toml", "")]
    poetry = tmp_path / "poetry"
    poetry.mkdir()
    (poetry / "pyproject.toml").write_text('[tool.poetry]\nname = "acme_poetry"\n')
    assert declared_packages(poetry)[0].name == "acme_poetry"
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    (cfg / "setup.cfg").write_text("[metadata]\nname = acme-cfg\n")
    assert declared_packages(cfg)[0].name == "acme-cfg"
    setup = tmp_path / "setup"
    setup.mkdir()
    marker = tmp_path / "ran"
    (setup / "setup.py").write_text(
        f"open({str(marker)!r}, 'w').write('x')\n"
        "from setuptools import setup\nsetup(\n    name='acme-setup',\n    version='1')\n")
    assert declared_packages(setup)[0].name == "acme-setup"
    assert not marker.exists()                           # read as text, never run
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "Cargo.toml").write_text('[workspace]\nmembers = ["a"]\n')
    assert declared_packages(ws) == []


def test_the_manifest_nearest_the_finding_comes_first(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "acme"\n')
    web = tmp_path / "web" / "src"
    web.mkdir(parents=True)
    (tmp_path / "web" / "package.json").write_text(json.dumps({"name": "acme-web"}))
    (tmp_path / "package.json").write_text(json.dumps({"name": "acme-root",
                                                       "private": True}))
    assert _names(declared_packages(tmp_path, "web/src/app.js")) == [
        ("npm", "acme-web", "web/package.json", ""),
        ("npm", "acme-root", "package.json", "private, not published to npm"),
        ("PyPI", "acme", "pyproject.toml", "")]
    # A finding outside the web package sees only the root.
    assert [p.name for p in declared_packages(tmp_path, "server.py")] == ["acme-root",
                                                                          "acme"]


def test_hostile_manifests_yield_no_name(tmp_path):
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps({"name": "stolen"}))
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package.json").symlink_to(outside)                    # a link out of the clone
    (repo / "pyproject.toml").write_text('[project]\nname = "x](http://evil)"\n')
    (repo / "setup.cfg").write_text("[metadata]\nname = " + "a" * 300 + "\n")
    (repo / "go.mod").write_text("module \n")
    (repo / "Cargo.toml").write_text("not = [toml")
    assert declared_packages(repo) == []
    assert declared_packages(repo, "../../etc/passwd") == []


def test_every_declared_name_is_searched_in_its_own_ecosystem(tmp_path):
    root = tmp_path / "dbs"
    _osv_zip(root, "PyPI", [_rec("GHSA-py", "PyPI", "Acme_Widgets"),
                            _rec("GHSA-repo-name", "PyPI", "widgets")])
    _osv_zip(root, "npm", [_rec("GHSA-npm", "npm", "acme-web"),
                           _rec("GHSA-py-name-in-npm", "npm", "acme-widgets")])
    _osv_zip(root, "crates.io", [_rec("GHSA-crate", "crates.io", "widgets-core")])
    chk = vulndb.local_prior_advisories(
        "PyPI", "widgets", "", root=root,
        packages=[("PyPI", "acme-widgets"), ("npm", "acme-web"),
                  ("crates.io", "widgets_core"), ("Go", "github.com/acme/w")])
    assert {m.id for m in chk.matches} == {"GHSA-py", "GHSA-npm", "GHSA-crate"}
    assert chk.names == (("PyPI", "acme-widgets", True), ("npm", "acme-web", True),
                         ("crates.io", "widgets_core", True),
                         ("Go", "github.com/acme/w", False))
    assert (chk.package, chk.package_ecosystem) == ("acme-widgets", "PyPI")


def test_a_draft_matches_the_declared_name_not_the_repository_name(tmp_path):
    """REGRESSION. The run is acme/widgets; the project publishes acme-widgets. The
    lookup matched PyPI's unrelated `widgets` and missed the project's own advisory."""
    con, src = _db(tmp_path)
    (src / "pyproject.toml").write_text('[project]\nname = "acme-widgets"\n')
    (src / "package.json").write_text(json.dumps({"name": "acme-ui", "private": True}))
    (src / "Cargo.toml").write_text('[package]\nname = "acme-core"\n')
    _confirm(con, "f1")
    root = tmp_path / "dbs"
    _osv_zip(root, "PyPI", [_rec("GHSA-real", "PyPI", "acme-widgets", cwes=["CWE-862"]),
                            _rec("GHSA-other-project", "PyPI", "widgets")])
    text = draft_reports(con, 1, src, out_dir=tmp_path / "reports",
                         vulndb_root=root)[0].path.read_text()
    sec = text.split("\n## Prior advisories checked\n", 1)[1].split("\n## ", 1)[0]
    assert "`GHSA-real`" in sec and "GHSA-other-project" not in sec
    assert "by package name `acme-widgets` in PyPI (from `pyproject.toml`)" in sec
    assert ("- Not searched by package name: `acme-ui` (npm, `package.json`): private, "
            "not published to npm; `acme-core` (crates.io, `Cargo.toml`): no local OSV "
            "copy for crates.io.") in sec
    assert "the names searched are the ones the clone's manifests declare" in sec


def test_a_draft_without_manifests_says_the_repository_name_stood_in(tmp_path):
    con, src = _db(tmp_path)
    _confirm(con, "f1")
    root = tmp_path / "dbs"
    _osv_zip(root, "PyPI", [_rec("GHSA-x", "PyPI", "widgets")])
    text = draft_reports(con, 1, src, out_dir=tmp_path / "reports",
                         vulndb_root=root)[0].path.read_text()
    assert "- Package names: no manifest in the clone declares one" in text
    assert "by package name `widgets` in PyPI (the repository name)" in text
    assert "the repository name may not be the published package name" in text


def test_names_are_rendered_inert():
    from quarry.disclosure.report import _render_prior
    prior = vulndb.PriorCheck(True, ecosystems=("npm",), entries_read=1,
                              names=(("npm", "a`b", True), ("Go", "x<y>", False)))
    out = _render_prior(prior, "CWE-862", (), (PackageName("npm", "a`b", "p`.json"),))
    # Every target-controlled name and path sits in a code span longer than its ticks.
    assert "``a`b`` in npm (from ``p`.json``)" in out and "`x<y>` (Go)" in out
