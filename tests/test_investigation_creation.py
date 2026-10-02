import re
import sqlite3
from pathlib import Path


def test_upload_creates_investigation_and_evidence_rows(upload, db_rows, sample_eml):
    body = upload().get_json()
    investigation_id = body["investigation_id"]
    investigations = db_rows("SELECT * FROM investigations WHERE id = ?", investigation_id)
    evidence = db_rows(
        "SELECT * FROM evidence WHERE investigation_id = ?", investigation_id
    )
    assert len(investigations) == 1
    assert investigations[0]["status"] == "uploaded"
    assert investigations[0]["error_message"] is None
    assert investigations[0]["analyzed_at"] is None
    assert len(evidence) == 1
    assert evidence[0]["original_filename"] == "valid.eml"
    assert evidence[0]["stored_filename"] == f"{investigation_id}.eml"
    assert evidence[0]["file_size"] == len(sample_eml)
    assert evidence[0]["sha256"] == body["sha256"]


def test_investigation_ids_are_unique_32_hex(upload):
    ids = {upload().get_json()["investigation_id"] for _ in range(5)}
    assert len(ids) == 5
    assert all(re.fullmatch(r"[0-9a-f]{32}", value) for value in ids)


def test_same_content_twice_creates_two_investigations(upload, db_rows):
    first = upload().get_json()
    second = upload().get_json()
    assert first["investigation_id"] != second["investigation_id"]
    assert first["sha256"] == second["sha256"]
    assert db_rows("SELECT COUNT(*) AS n FROM investigations")[0]["n"] == 2


def test_failed_insert_leaves_no_orphan_file(app, upload, monkeypatch):
    def failing_insert(*args, **kwargs):
        raise sqlite3.OperationalError("simulated failure")

    monkeypatch.setattr("routes.upload.create_investigation", failing_insert)
    response = upload()
    assert response.status_code == 500
    assert response.get_json() == {"error": "Database error"}
    assert list(Path(app.config["UPLOAD_FOLDER"]).iterdir()) == []