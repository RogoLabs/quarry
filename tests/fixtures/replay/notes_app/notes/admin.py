from flask import Blueprint, abort, jsonify, request
from werkzeug.security import generate_password_hash

from .auth import admin_required, login_required
from .db import get_db

bp = Blueprint("admin", __name__, url_prefix="/admin")


@bp.route("/users", methods=["GET"])
@login_required
@admin_required
def list_users():
    rows = get_db().execute(
        "SELECT id, username, is_admin, disabled FROM users ORDER BY id").fetchall()
    return jsonify([dict(r) for r in rows])


@bp.route("/users/<int:user_id>/disable", methods=["POST"])
@login_required
@admin_required
def disable_user(user_id):
    get_db().execute("UPDATE users SET disabled = 1 WHERE id = ?", (user_id,))
    get_db().commit()
    return jsonify({"ok": True})


@bp.route("/users/<int:user_id>/promote", methods=["POST"])
@login_required
@admin_required
def promote_user(user_id):
    get_db().execute("UPDATE users SET is_admin = 1 WHERE id = ?", (user_id,))
    get_db().commit()
    return jsonify({"ok": True})


@bp.route("/users/<int:user_id>/password", methods=["POST"])
@login_required
def reset_password(user_id):
    new = (request.get_json(force=True) or {}).get("password", "")
    if len(new) < 12:
        abort(400)
    get_db().execute("UPDATE users SET password_hash = ? WHERE id = ?",
                     (generate_password_hash(new), user_id))
    get_db().commit()
    return jsonify({"ok": True})
