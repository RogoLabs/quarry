import os

from flask import Blueprint, abort, current_app, g, jsonify, request, send_file
from werkzeug.utils import secure_filename

from .auth import login_required

bp = Blueprint("files", __name__, url_prefix="/files")


def _user_dir():
    path = os.path.join(current_app.config["UPLOAD_DIR"], str(g.user["id"]))
    os.makedirs(path, exist_ok=True)
    return path


@bp.route("/", methods=["POST"])
@login_required
def upload():
    f = request.files["file"]
    name = secure_filename(f.filename or "")
    if not name:
        abort(400)
    f.save(os.path.join(_user_dir(), name))
    return jsonify({"name": name}), 201


@bp.route("/", methods=["GET"])
@login_required
def list_files():
    return jsonify(sorted(os.listdir(_user_dir())))


@bp.route("/<path:name>", methods=["GET"])
@login_required
def download(name):
    path = os.path.join(_user_dir(), name)
    if not os.path.isfile(path):
        abort(404)
    return send_file(path)


@bp.route("/<path:name>", methods=["DELETE"])
@login_required
def remove(name):
    path = os.path.join(_user_dir(), secure_filename(name))
    if not os.path.isfile(path):
        abort(404)
    os.remove(path)
    return "", 204
