import os

from flask import Flask

from . import admin, auth, db, files, views


def create_app():
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ["NOTES_SECRET_KEY"],
        DATABASE=os.environ.get("NOTES_DB", "notes.sqlite3"),
        UPLOAD_DIR=os.environ.get("NOTES_UPLOADS", "uploads"),
        MAX_CONTENT_LENGTH=5 * 1024 * 1024,
    )
    app.teardown_appcontext(db.close_db)
    app.register_blueprint(auth.bp)
    app.register_blueprint(views.bp)
    app.register_blueprint(admin.bp)
    app.register_blueprint(files.bp)
    return app
