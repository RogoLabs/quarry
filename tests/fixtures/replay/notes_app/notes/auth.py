import functools

from flask import Blueprint, abort, g, redirect, request, session, url_for
from werkzeug.security import check_password_hash

from .db import get_db

bp = Blueprint("auth", __name__, url_prefix="/auth")


@bp.before_app_request
def load_logged_in_user():
    user_id = session.get("user_id")
    g.user = None if user_id is None else get_db().execute(
        "SELECT id, username, is_admin FROM users WHERE id = ? AND disabled = 0",
        (user_id,)).fetchone()


def login_required(view):
    @functools.wraps(view)
    def wrapped(**kwargs):
        if g.user is None:
            return redirect(url_for("auth.login"))
        return view(**kwargs)
    return wrapped


def admin_required(view):
    @functools.wraps(view)
    def wrapped(**kwargs):
        if g.user is None or not g.user["is_admin"]:
            abort(403)
        return view(**kwargs)
    return wrapped


def owned_note_or_404(note_id):
    note = get_db().execute(
        "SELECT id, owner_id, title, body, share_token FROM notes WHERE id = ?",
        (note_id,)).fetchone()
    if note is None or note["owner_id"] != g.user["id"]:
        abort(404)
    return note


@bp.route("/login", methods=["POST"])
def login():
    row = get_db().execute(
        "SELECT id, password_hash FROM users WHERE username = ? AND disabled = 0",
        (request.form.get("username", ""),)).fetchone()
    if row is None or not check_password_hash(row["password_hash"],
                                              request.form.get("password", "")):
        abort(401)
    session.clear()
    session["user_id"] = row["id"]
    return redirect(url_for("notes.list_notes"))


@bp.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("auth.login"))
