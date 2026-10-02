import io
import sqlite3

import pytest

from app import create_app

SAMPLE_EML = (
    b"From: attacker@example.test\n"
    b"To: victim@example.test\n"
    b"Subject: Test invoice\n"
    b"Date: Tue, 29 Sep 2026 10:00:00 +0000\n"
    b"Message-ID: <test-001@example.test>\n"
    b"Received: from mail.example.test (mail.example.test [192.0.2.10]) "
    b"by mx.example.test; Tue, 29 Sep 2026 10:00:01 +0000\n"
    b"\n"
    b"Please review the attached invoice: http://example.test/invoice\n"
)


@pytest.fixture
def sample_eml():
    return SAMPLE_EML


@pytest.fixture
def app(tmp_path):
    return create_app(
        {
            "DATABASE_PATH": str(tmp_path / "test.db"),
            "UPLOAD_FOLDER": str(tmp_path / "uploads"),
            "REPORTS_FOLDER": str(tmp_path / "reports"),
            "LOG_TO_FILE": False,
            "ANALYZER_MODULE": "emailtrace_no_such_analyzer",
            "ANALYZER_FALLBACK_TO_MOCK": True,
        }
    )


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def upload(client):
    def _upload(data=SAMPLE_EML, filename="valid.eml"):
        return client.post(
            "/api/upload",
            data={"file": (io.BytesIO(data), filename)},
            content_type="multipart/form-data",
        )

    return _upload


@pytest.fixture
def investigation_id(upload):
    return upload().get_json()["investigation_id"]


@pytest.fixture
def db_rows(app):
    def _rows(sql, *params):
        connection = sqlite3.connect(app.config["DATABASE_PATH"])
        connection.row_factory = sqlite3.Row
        try:
            return [dict(row) for row in connection.execute(sql, params).fetchall()]
        finally:
            connection.close()

    return _rows