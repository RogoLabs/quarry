"""Probe-lens selection is driven by the repo profile, mirroring how Layer 2 selects
reading lenses: a probe runs only when the artifact is runnable, the capability is
present, and a surviving finding has a matching CWE. Both halves are reported.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quarry.research.profile import RepoProfile                     # noqa: E402
from quarry.dynamic.validate import Candidate, ProbeEvidence, adjudicate  # noqa: E402
from quarry.dynamic.lenses import ProbeLens, select_probe_lenses, CATALOGUE  # noqa: E402


def _profile(kind="service", caps=None, frameworks=()):
    return RepoProfile(root=Path("/x"), artifact_kind=kind,
                       capabilities=caps or {}, frameworks=list(frameworks),
                       evidence={k: f"{k}.src" for k in (caps or {})})


def _cand(fid, cwe):
    return Candidate(fid, 1, "o/r", "a.py", 1, "prod", cwe, "msg")


def test_service_with_routes_selects_authz():
    prof = _profile(caps={"http_routes": 5})
    selected, skipped = select_probe_lenses(prof, [_cand("f1", "CWE-862")])
    keys = [lens.key for lens, _, _ in selected]
    assert keys == ["broken-authz-idor"]
    assert [m[0].finding_id for _, m, _ in selected] == ["f1"]
    assert len(skipped) == len(CATALOGUE) - 1        # every other lens reported a reason


def test_a_library_is_never_probed():
    # even with routes-like capabilities, a library cannot be stood up and spoken to.
    prof = _profile(kind="library", caps={"http_routes": 50, "authn": 10})
    selected, skipped = select_probe_lenses(prof, [_cand("f1", "CWE-862")])
    assert selected == []
    assert all("artifact is library" in why for _, why in skipped)


def test_profile_supports_but_no_matching_finding():
    prof = _profile(caps={"http_routes": 5})
    selected, skipped = select_probe_lenses(prof, [_cand("f1", "CWE-200")])  # not in any lens
    assert selected == []
    authz_reason = dict(skipped)["broken-authz-idor"]
    assert "no surviving finding" in authz_reason


def test_injection_requires_a_sink_capability():
    # a SQLi candidate only selects the injection lens when the profile shows a sink.
    no_sink = _profile(caps={"http_routes": 5})
    with_sink = _profile(caps={"http_routes": 5, "raw_sql": 2})
    cand = [_cand("f1", "CWE-89")]
    assert [l.key for l, _, _ in select_probe_lenses(no_sink, cand)[0]] == []
    assert "injection-observable" in [l.key for l, _, _ in select_probe_lenses(with_sink, cand)[0]]


def test_selection_is_in_catalogue_priority_order():
    prof = _profile(caps={"http_routes": 5, "authn": 3, "raw_sql": 2})
    cands = [_cand("f-sqli", "CWE-89"), _cand("f-authz", "CWE-862"),
             _cand("f-rate", "CWE-307")]
    keys = [l.key for l, _, _ in select_probe_lenses(prof, cands)[0]]
    order = [l.key for l in CATALOGUE]
    assert keys == sorted(keys, key=order.index)
    assert keys[0] == "broken-authz-idor"            # highest priority wins the top slot


def test_an_unwired_probe_can_only_yield_needs_review():
    lens = ProbeLens(key="x", cwes=frozenset({"CWE-862"}), requires=("http_routes",),
                     rationale="")
    ev = lens.probe(running=None, candidate=_cand("f1", "CWE-862"), routes=[],
                    exec_fn=lambda a: (0, ""))
    assert ev.reproduced is False and adjudicate(ev) == "needs-review"
