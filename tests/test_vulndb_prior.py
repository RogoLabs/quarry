"""The local prior-advisory lookup: search the OSV zips `quarry db sync` downloaded for
records that name the target's package or repository, without touching the network.
Fixtures are tiny zips laid out the way osv-scanner lays out its offline cache.
"""
from __future__ import annotations

import json
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quarry import vulndb                                               # noqa: E402


def _osv_zip(root, eco, records):
    d = root / "osv" / "osv-scalibr" / eco
    d.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(d / "all.zip", "w") as z:
        for r in records:
            z.writestr(f"{r['id']}.json", json.dumps(r))


def _rec(rid, eco=None, name=None, repo=None, refs=(), cwes=()):
    affected = []
    if name:
        affected.append({"package": {"ecosystem": eco, "name": name}})
    if repo:
        affected.append({"ranges": [{"type": "GIT", "repo": repo, "events": []}]})
    return {"id": rid, "modified": "2025-01-01T00:00:00Z", "aliases": [],
            "summary": f"about {rid}", "affected": affected,
            "references": [{"type": "WEB", "url": u} for u in refs],
            "database_specific": {"cwe_ids": list(cwes)}}


def test_local_prior_advisories_matches_name_repository_and_reference(tmp_path):
    root = tmp_path / "dbs"
    _osv_zip(root, "PyPI", [
        _rec("GHSA-name", "PyPI", "Widgets_Lib", cwes=["CWE-862"]),     # PEP 503 equal
        _rec("GHSA-other", "PyPI", "widgets-libx"),                      # another package
        _rec("GHSA-git", repo="https://github.com/Acme/widgets-lib.git"),
        _rec("GHSA-ref", "PyPI", "unrelated",
             refs=["https://github.com/acme/widgets-lib/commit/abc"]),
        _rec("GHSA-prefix", "PyPI", "unrelated",
             refs=["https://github.com/acme/widgets-lib-extra"]),        # not this repo
    ])
    _osv_zip(root, "npm", [
        _rec("GHSA-npm", "npm", "widgets-lib"),          # same name, other registry
        _rec("GHSA-ref", "npm", "x", refs=["https://github.com/acme/widgets-lib"]),
    ])
    chk = vulndb.local_prior_advisories(
        "PyPI", "widgets-lib", "https://github.com/acme/widgets-lib.git", root=root)
    assert chk.checked and chk.entries_read == 7
    assert set(chk.ecosystems) == {"PyPI", "npm"} and chk.downloaded
    assert {m.id: m.basis for m in chk.matches} == {
        "GHSA-name": "package name", "GHSA-git": "affected repository",
        "GHSA-ref": "reference URL"}                    # one GHSA-ref, not two
    assert next(m for m in chk.matches if m.id == "GHSA-name").cwes == ("CWE-862",)


def test_local_prior_advisories_without_a_database_is_not_checked(tmp_path):
    chk = vulndb.local_prior_advisories("PyPI", "w", "https://github.com/a/w", root=tmp_path)
    assert not chk.checked and "no local OSV database" in chk.reason


def test_an_unreadable_zip_is_skipped_not_fatal(tmp_path):
    root = tmp_path / "dbs"
    _osv_zip(root, "PyPI", [_rec("GHSA-ok", "PyPI", "w")])
    bad = root / "osv" / "osv-scalibr" / "npm"
    bad.mkdir(parents=True)
    (bad / "all.zip").write_bytes(b"not a zip")
    chk = vulndb.local_prior_advisories("PyPI", "w", "", root=root)
    assert chk.checked and chk.entries_read == 1
    assert [m.id for m in chk.matches] == ["GHSA-ok"] and chk.repo == ""


def test_repo_key_spellings():
    for url in ("https://github.com/Acme/Widgets.git", "git@github.com:acme/widgets.git",
                "http://www.github.com/acme/widgets/", "https://github.com/acme/widgets#x"):
        assert vulndb.repo_key(url) == "github.com/acme/widgets", url
    assert vulndb.repo_key("https://github.com") == ""
    assert vulndb.repo_key("https://github.com/acme") == ""
