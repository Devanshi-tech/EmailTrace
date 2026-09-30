import json
import sqlite3
from pathlib import Path

from flask import current_app, g

SCHEMA_PATH = Path(__file__).resolve().parent / "schema.sql"

CHILD_TABLES = {
    "iocs": ("ioc_type", "value", "description", "severity"),
    "urls": ("url", "domain", "is_suspicious"),
    "ip_addresses": ("ip_address", "hop_index", "source"),
    "attachments": ("filename", "content_type", "size_bytes", "sha256", "is_suspicious"),
    "suspicious_domains": ("domain", "reason"),
}


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


def create_investigation(
    investigation_id, original_filename, stored_filename, file_path, file_size, sha256
):
    db = get_db()
    try:
        db.execute("INSERT INTO investigations (id) VALUES (?)", (investigation_id,))
        db.execute(
            "INSERT INTO evidence "
            "(investigation_id, original_filename, stored_filename, file_path, file_size, sha256) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                investigation_id,
                original_filename,
                stored_filename,
                file_path,
                file_size,
                sha256,
            ),
        )
        db.commit()
    except Exception:
        db.rollback()
        raise


def get_investigation(investigation_id):
    row = get_db().execute(
        "SELECT i.id, i.status, i.error_message, i.created_at, i.updated_at, i.analyzed_at, "
        "e.original_filename, e.file_size, e.sha256, e.uploaded_at "
        "FROM investigations i JOIN evidence e ON e.investigation_id = i.id "
        "WHERE i.id = ?",
        (investigation_id,),
    ).fetchone()
    if row is None:
        return None
    return {
        "investigation_id": row["id"],
        "status": row["status"],
        "error_message": row["error_message"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "analyzed_at": row["analyzed_at"],
        "evidence": {
            "original_filename": row["original_filename"],
            "file_size": row["file_size"],
            "sha256": row["sha256"],
            "uploaded_at": row["uploaded_at"],
        },
    }


def get_analysis_result(investigation_id):
    row = get_db().execute(
        "SELECT result_json FROM analysis_results WHERE investigation_id = ?",
        (investigation_id,),
    ).fetchone()
    return json.loads(row["result_json"]) if row else None


def get_extracted_items(investigation_id):
    db = get_db()
    return {
        table: [
            dict(row)
            for row in db.execute(
                f"SELECT {', '.join(columns)} FROM {table} "
                "WHERE investigation_id = ? ORDER BY id",
                (investigation_id,),
            )
        ]
        for table, columns in CHILD_TABLES.items()
    }


def get_extracted_counts(investigation_id):
    db = get_db()
    return {
        table: db.execute(
            f"SELECT COUNT(*) FROM {table} WHERE investigation_id = ?",
            (investigation_id,),
        ).fetchone()[0]
        for table in CHILD_TABLES
    }