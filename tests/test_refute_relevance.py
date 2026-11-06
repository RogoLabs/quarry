"""Decision M: a refutation's guard must answer the claim's attacker.

Every case below is a guard a refuter actually cited on the replay (F2 and K,
2026-11-05), with the claim it was cited against. The rejected ones killed a planted
bug; the accepted ones killed a claim on no plant, correctly.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from quarry.research import grounding, relevance as R      # noqa: E402

USER_DIR = ('def _user_dir():\n    path = os.path.join(current_app.config["UPLOAD_DIR"], '
            'str(g.user["id"]))\n    return path\n')


def _resolve(name):
    return USER_DIR if name == "_user_dir" else None


REJECTED = [
    # a login check against an attacker who can be logged in
    ("@login_required", "broken-authz-idor", "Potential IDOR in file download",
     "An attacker could download files by sending a GET request to `/files/<filename>`.",
     "def download(name):", "only requires a login"),
    ("login_required", "broken-authz-idor", "Potential IDOR in password reset",
     "An attacker could reset the password of any user by specifying their user ID.",
     "def reset_password(user_id):", "only requires a login"),
    # a lookup by the requested id, or a not-found check, is not authorization
    ("store.comments.find(c => c.id === Number(req.params.commentId))", "broken-authz-idor",
     "Potential IDOR in comment retrieval",
     "An authenticated user can supply any comment ID in the URL path.",
     "router.get('/comments/:commentId', auth.requireUser, tickets.showComment)",
     "does not check who is asking"),
    ("if (!comment) return res.status(404).json({ error: 'not found' })",
     "broken-authz-idor", "Missing Authorization Check on Comment Read Endpoint",
     "An attacker could supply any numeric comment ID in `:commentId`.",
     "router.get('/comments/:commentId', auth.requireUser, tickets.showComment)",
     "does not check who is asking"),
    # the attacker's own input, posing as the caller's role
    ("ROLES.has(req.body.role)", "broken-authz-idor",
     "Missing Authorization Check in POST /api/admin/users/:id/role",
     "An attacker who has an authenticated JWT token could supply any user ID.",
     "router.post('/users/:id/role', auth.requireUser, admin.setRole)",
     "does not check who is asking"),
    # a name that does nothing
    ("tickets.history", "broken-authz-idor", "Unauthenticated access to ticket history",
     "An attacker can supply any ticket ID in the URL path without authentication.",
     "router.get('/tickets/:id/history', tickets.history)", "does nothing by itself"),
    # the user's id against injection through another parameter
    ("g.user['id']", "injection", "SQL Injection in search_notes view",
     "An attacker supplies a value for the 'q' query parameter in the GET request.",
     'q = request.args.get("q", "")', "does nothing by itself"),
    # an authentication decorator does not sanitize a path
    ("@login_required", "filesystem-and-path", "Path Traversal in File Download",
     "An attacker supplies the `name` parameter in a GET request to `/files/<path:name>`",
     "def download(name):\n    path = os.path.join(_user_dir(), name)",
     "does not touch the input"),
    # an existence check does not constrain the input
    ("os.path.isfile(path)", "filesystem-and-path", "Path Traversal in File Download",
     "An attacker supplies the `name` parameter in a GET request to `/files/<path:name>`",
     "path = os.path.join(_user_dir(), name)\n    if not os.path.isfile(path):",
     "does not touch the input"),
]

ACCEPTED = [
    ("secure_filename(name)", "filesystem-and-path", "Path Traversal in File Deletion",
     "An attacker supplies the `name` parameter in a DELETE request to `/files/<path:name>`",
     "def remove(name):\n    path = os.path.join(_user_dir(), secure_filename(name))",
     "acts on the attacker's input"),
    ("os.path.join(_user_dir(), secure_filename(name))", "filesystem-and-path",
     "Path Traversal in File Removal Endpoint",
     "An attacker could supply a malicious filename to delete files.",
     "path = os.path.join(_user_dir(), secure_filename(name))",
     "acts on the attacker's input"),
    ("@admin_required", "broken-authz-idor", "Potential IDOR in list_users",
     "An admin user can access the list_users route.",
     "SELECT id, username, is_admin, disabled FROM users ORDER BY id",
     "role or permission check"),
    # a per-user directory, judged by what the helper it calls checks
    ("os.path.join(_user_dir(), secure_filename(name))", "broken-authz-idor",
     "Potential IDOR in file deletion", "An attacker could delete any file by its name.",
     "def remove(name):", "checks the requesting user"),
    ("note['owner_id'] != g.user['id']", "broken-authz-idor", "IDOR on note read",
     "Any logged-in user can read another user's note by id.", "def show(note_id):",
     "checks the requesting user"),
    # a login check does answer an unauthenticated attacker
    ("@login_required", "broken-authz-idor", "Unauthenticated access to notes",
     "An unauthenticated attacker can list notes without logging in.",
     "def list_notes():", "attacker is unauthenticated"),
    # outside both groups only the "does something" rule applies
    ("hmac.compare_digest(sig, expected)", "secrets-and-crypto", "Timing-unsafe compare",
     "An attacker controls `sig`.", "if sig == expected:", "operative check"),
]


@pytest.mark.parametrize("guard,lens,title,ac,quote,word", REJECTED)
def test_guards_that_do_not_answer_the_attacker_are_rejected(guard, lens, title, ac, quote,
                                                              word):
    ok, why = R.addresses(guard, lens=lens, title=title, attacker_control=ac, quote=quote,
                          resolve=_resolve)
    assert not ok and word in why


@pytest.mark.parametrize("guard,lens,title,ac,quote,word", ACCEPTED)
def test_guards_that_answer_the_attacker_are_accepted(guard, lens, title, ac, quote, word):
    ok, why = R.addresses(guard, lens=lens, title=title, attacker_control=ac, quote=quote,
                          resolve=_resolve)
    assert ok and word in why


def test_a_helper_is_not_trusted_without_its_definition():
    ok, why = R.addresses("os.path.join(_user_dir(), secure_filename(name))",
                          lens="broken-authz-idor", title="IDOR in file deletion",
                          attacker_control="any file", quote="def remove(name):")
    assert not ok and "does not check who is asking" in why


def test_named_inputs_win_over_the_claimed_code():
    assert R.attacker_inputs("the `id` route parameter", "x = 1") == {"id"}
    assert R.attacker_inputs("the 'q' query parameter", "") == {"q"}
    assert R.attacker_inputs("GET `/files/<path:name>`", "") == {"name"}
    assert R.attacker_inputs("a malicious filename", "open(os.path.join(base, fname))") \
        == {"base", "fname", "open"}


# ------------------------------------------------------------------ through grounding

FILES = """import os
from flask import g


def _user_dir():
    return os.path.join("/srv", str(g.user["id"]))


def download(name):
    path = os.path.join(_user_dir(), name)
    if not os.path.isfile(path):
        return "not found", 404
    return open(path).read()
"""


@pytest.fixture
def src(tmp_path):
    (tmp_path / "files.py").write_text(FILES)
    return tmp_path


def test_grounding_rejects_a_well_placed_guard_that_does_not_answer(src):
    """On the path (decision F passes) and still not an answer (decision M)."""
    g = grounding.ground(src, claim_file="files.py", claim_quote="def download(name):",
                         claim_line=None, counter_file="files.py",
                         counter_quote="    if not os.path.isfile(path):",
                         guard="os.path.isfile(path)", lens="filesystem-and-path",
                         title="Path traversal in download",
                         attacker_control="the `name` path parameter")
    assert not g.ok and "does not touch the input" in g.why and "definition" in g.why


def test_grounding_resolves_a_helper_in_the_file(src):
    g = grounding.ground(src, claim_file="files.py", claim_quote="def download(name):",
                         claim_line=None, counter_file="files.py",
                         counter_quote="    path = os.path.join(_user_dir(), name)",
                         guard="os.path.join(_user_dir(), name)", lens="broken-authz-idor",
                         title="IDOR in download",
                         attacker_control="another user's file by name")
    assert g.ok and "checks the requesting user" not in g.why


def test_without_a_lens_grounding_is_decision_f_alone(src):
    g = grounding.ground(src, claim_file="files.py", claim_quote="def download(name):",
                         claim_line=None, counter_file="files.py",
                         counter_quote="    if not os.path.isfile(path):",
                         guard="os.path.isfile(path)")
    assert g.ok


@pytest.mark.parametrize("claim", ["An unauthenticated attacker reads notes",
                                   "A user who is not logged in reads notes"])
def test_negated_wording_is_not_read_as_an_authenticated_attacker(claim):
    """"unauthenticated attacker" contains "authenticated attacker", and "not logged in"
    contains "logged in"; both once read as the opposite of what they say."""
    ok, _ = R.addresses("@login_required", lens="broken-authz-idor", title="Notes",
                        attacker_control=claim, quote="def list_notes():")
    assert ok
