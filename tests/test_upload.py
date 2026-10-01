import hashlib
import re
from pathlib import Path

import pytest


def test_valid_upload_returns_201_with_metadata(upload, sample_eml):
    response = upload()
    body = response.get_json()
    assert response.status_code == 201
    assert re.fullmatch(r"[0-9a-f]{32}", body["investigation_id"])
    assert body["status"] == "uploaded"
    assert body["original_filename"] == "valid.eml"
    assert body["file_size"] == len(sample_eml)
    assert body["sha256"] == hashlib.sha256(sample_eml).hexdigest()


def test_stored_file_is_byte_identical_with_uuid_name(app, upload, sample_eml):
    body = upload(filename="client_name.eml").get_json()
    stored = Path(app.config["UPLOAD_FOLDER"]) / f"{body['investigation_id']}.eml"
    assert stored.read_bytes() == sample_eml
    assert [p.name for p in Path(app.config["UPLOAD_FOLDER"]).iterdir()] == [stored.name]


def test_uppercase_extension_accepted(upload):
    response = upload(filename="VALID.EML")
    assert response.status_code == 201
    assert response.get_json()["original_filename"].lower() == "valid.eml"


def test_dangerous_filename_is_sanitized(app, tmp_path, upload):
    response = upload(filename="../../evil.eml")
    body = response.get_json()
    assert response.status_code == 201
    assert body["original_filename"] == "evil.eml"
    assert not (tmp_path / "evil.eml").exists()
    assert not (tmp_path.parent / "evil.eml").exists()
    assert [p.name for p in Path(app.config["UPLOAD_FOLDER"]).iterdir()] == [
        f"{body['investigation_id']}.eml"
    ]


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (b"", "Uploaded file is empty"),
        (b"just some text", "File is not a valid RFC 822 email message"),
        (b"From: a@example.test\x00\n\nbody", "File is not a valid RFC 822 email message"),
    ],
    ids=["empty", "not-an-email", "nul-byte"],
)
def test_invalid_content_rejected(app, upload, db_rows, data, message):
    response = upload(data=data)
    assert response.status_code == 400
    assert response.get_json() == {"error": message}
    assert list(Path(app.config["UPLOAD_FOLDER"]).iterdir()) == []
    assert db_rows("SELECT COUNT(*) AS n FROM investigations")[0]["n"] == 0


def test_missing_file_part_rejected(client):
    response = client.post("/api/upload")
    assert response.status_code == 400
    assert response.get_json() == {"error": "No file part named 'file' in the request"}


def test_oversize_upload_returns_413(app, upload, db_rows):
    app.config["MAX_CONTENT_LENGTH"] = 1024
    response = upload(data=b"X" * 4096)
    assert response.status_code == 413
    assert response.get_json() == {"error": "File exceeds the maximum allowed size"}
    assert list(Path(app.config["UPLOAD_FOLDER"]).iterdir()) == []
    assert db_rows("SELECT COUNT(*) AS n FROM investigations")[0]["n"] == 0