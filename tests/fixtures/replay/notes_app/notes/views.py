import secrets

from flask import Blueprint, abort, g, jsonify, request

from .auth import login_required, owned_note_or_404
from .db import get_db

bp = Blueprint("notes", __name__, url_prefix="/notes")


@bp.route("/", methods=["GET"])
@login_required
def list_notes():
    rows = get_db().execute(
        "SELECT id, title FROM notes WHERE owner_id = ? ORDER BY id DESC",
        (g.user["id"],)).fetchall()
    return jsonify([dict(r) for r in rows])


@bp.route("/", methods=["POST"])
@login_required
def create_note():
    data = request.get_json(force=True)
    cur = get_db().execute(
        "INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)",
        (g.user["id"], str(data.get("title", ""))[:200], str(data.get("body", ""))))
    get_db().commit()
    return jsonify({"id": cur.lastrowid}), 201


@bp.route("/<int:note_id>", methods=["GET"])
@login_required
def view_note(note_id):
    note = get_db().execute(
        "SELECT id, owner_id, title, body FROM notes WHERE id = ?",
        (note_id,)).fetchone()
    if note is None:
        abort(404)
    return jsonify(dict(note))


@bp.route("/<int:note_id>", methods=["PUT"])
@login_required
def edit_note(note_id):
    note = owned_note_or_404(note_id)
    data = request.get_json(force=True)
    get_db().execute(
        "UPDATE notes SET title = ?, body = ? WHERE id = ?",
        (str(data.get("title", note["title"]))[:200],
         str(data.get("body", note["body"])), note["id"]))
    get_db().commit()
    return jsonify({"ok": True})


@bp.route("/<int:note_id>", methods=["DELETE"])
@login_required
def delete_note(note_id):
    note = owned_note_or_404(note_id)
    get_db().execute("DELETE FROM notes WHERE id = ?", (note["id"],))
    get_db().commit()
    return "", 204


@bp.route("/<int:note_id>/share", methods=["POST"])
@login_required
def share_note(note_id):
    note = owned_note_or_404(note_id)
    token = secrets.token_urlsafe(24)
    get_db().execute("UPDATE notes SET share_token = ? WHERE id = ?", (token, note["id"]))
    get_db().commit()
    return jsonify({"url": f"/notes/shared/{token}"})


@bp.route("/shared/<token>", methods=["GET"])
def shared_note(token):
    note = get_db().execute(
        "SELECT title, body FROM notes WHERE share_token = ?", (token,)).fetchone()
    if note is None:
        abort(404)
    return jsonify(dict(note))


@bp.route("/search", methods=["GET"])
@login_required
def search_notes():
    q = request.args.get("q", "")
    rows = get_db().execute(
        f"SELECT id, title FROM notes WHERE owner_id = {g.user['id']} "
        f"AND title LIKE '%{q}%' ORDER BY id DESC").fetchall()
    return jsonify([dict(r) for r in rows])
