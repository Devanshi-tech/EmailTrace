import sqlite3
from pathlib import Path

from flask import current_app, g

SCHEMA_PATH = Path(__file__).resolve().parent / "schema.sql"


def get_db():
    if "db" not in g:
        conn = sqlite3.connect(current_app.config["DATABASE_PATH"])
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        g.db = conn
    return g.db


def close_db(exception=None):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_db():
    db = get_db()
    db.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    db.commit()


def init_app(app):
    Path(app.config["DATABASE_PATH"]).parent.mkdir(parents=True, exist_ok=True)
    app.teardown_appcontext(close_db)

    with app.app_context():
        init_db()