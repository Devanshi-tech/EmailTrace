import json
import sqlite3

import pytest

from analyzer.contract import normalize_result
from analyzer.mock_analyzer import analyze_email
from database.database import (
    create_investigation,
    get_db,
    get_extracted_counts,
    get_investigation,
)
from database.results import (
    build_rows,
    claim_for_analysis,
    recover_interrupted_analyses,
    save_results,
)

INV = "a" * 32
EXPECTED_COUNTS = {
    "attachments": 1,
    "iocs": 1,
    "ip_addresses": 2,
    "suspicious_domains": 1,
    "urls": 1,
}


@pytest.fixture
def ctx(app):
    with app.app_context():
        yield


def make_investigation(investigation_id=INV):
    create_investigation(
        investigation_id, "x.eml", f"{investigation_id}.eml", "/tmp/x.eml", 10, "0" * 64
    )


def mock_rows():
    result = normalize_result(analyze_email("unused"))
    rows, skipped = build_rows(result)
    return result, rows, skipped


def test_schema_creates_all_tables(ctx):
    names = {
        row["name"]
        for row in get_db().execute(
            "SELECT name FROM sqlite_master "
            "WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
        )
    }
    assert names == {
        "investigations",
        "evidence",
        "analysis_results",
        "iocs",
        "urls",
        "ip_addresses",
        "attachments",
        "suspicious_domains",
    }


def test_foreign_keys_enabled(ctx):
    assert get_db().execute("PRAGMA foreign_keys").fetchone()[0] == 1


def test_create_investigation_inserts_rows(ctx):
    make_investigation()
    record = get_investigation(INV)
    assert record["status"] == "uploaded"
    assert record["evidence"]["original_filename"] == "x.eml"
    assert record["evidence"]["file_size"] == 10
    assert record["evidence"]["sha256"] == "0" * 64


def test_orphan_child_row_rejected(ctx):
    with pytest.raises(sqlite3.IntegrityError):
        get_db().execute(
            "INSERT INTO urls (investigation_id, url) VALUES (?, ?)",
            ("missing", "http://x.test"),
        )


def test_invalid_status_rejected(ctx):
    with pytest.raises(sqlite3.IntegrityError):
        get_db().execute(
            "INSERT INTO investigations (id, status) VALUES (?, ?)", (INV, "bogus")
        )


def test_duplicate_evidence_rejected(ctx):
    make_investigation()
    with pytest.raises(sqlite3.IntegrityError):
        get_db().execute(
            "INSERT INTO evidence "
            "(investigation_id, original_filename, stored_filename, file_path, file_size, sha256) "
            "VALUES (?, 'y.eml', 'y.eml', '/tmp/y.eml', 1, ?)",
            (INV, "1" * 64),
        )


def test_cascade_delete_removes_dependents(ctx):
    make_investigation()
    result, rows, _ = mock_rows()
    save_results(INV, result, rows)
    db = get_db()
    db.execute("DELETE FROM investigations WHERE id = ?", (INV,))
    db.commit()
    for table in (
        "evidence",
        "analysis_results",
        "iocs",
        "urls",
        "ip_addresses",
        "attachments",
        "suspicious_domains",
    ):
        assert db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0


def test_build_rows_maps_and_skips():
    result = {
        "ips": [
            "198.51.100.7",
            "not-an-ip",
            {"ip": "2001:db8::1", "hop_index": True, "source": "header"},
            42,
        ],
        "urls": [
            "http://Phish.example.test/login?x=1",
            {"url": ""},
            {"url": "http://ok.example.test", "suspicious": "yes"},
        ],
        "domains": [
            "plain.example.test",
            {"domain": "BAD.example.test", "suspicious": True, "reason": "lookalike"},
            {"domain": "fine.example.test", "suspicious": False},
        ],
        "attachments": [
            {"filename": "a\nb.exe", "size": -5, "sha256": "xyz", "suspicious": True},
            "text",
            {},
        ],
        "iocs": ["evil.example.test", {"type": "domain"}, {"value": "1.2.3.4", "severity": "high"}],
    }
    rows, skipped = build_rows(result)
    assert skipped == 6
    assert {table: len(items) for table, items in rows.items()} == {
        "iocs": 2,
        "urls": 2,
        "ip_addresses": 2,
        "attachments": 1,
        "suspicious_domains": 1,
    }
    assert rows["urls"][0][:3] == (
        "http://Phish.example.test/login?x=1",
        "phish.example.test",
        0,
    )
    assert rows["urls"][1][2] == 0
    assert rows["ip_addresses"][1][:3] == ("2001:db8::1", None, "header")
    assert rows["attachments"][0][:5] == ("ab.exe", None, None, None, 1)
    assert rows["suspicious_domains"][0][:2] == ("bad.example.test", "lookalike")


def test_save_results_inserts_rows(ctx):
    make_investigation()
    result, rows, skipped = mock_rows()
    save_results(INV, result, rows)
    db = get_db()
    assert skipped == 0
    assert get_extracted_counts(INV) == EXPECTED_COUNTS
    stored = db.execute(
        "SELECT result_json FROM analysis_results WHERE investigation_id = ?", (INV,)
    ).fetchone()
    assert json.loads(stored["result_json"]) == result
    url = db.execute(
        "SELECT url, domain, is_suspicious FROM urls WHERE investigation_id = ?", (INV,)
    ).fetchone()
    assert tuple(url) == ("http://example.test/invoice", "example.test", 1)
    record = get_investigation(INV)
    assert record["status"] == "completed"
    assert record["analyzed_at"] is not None


def test_save_results_replaces_previous_rows(ctx):
    make_investigation()
    result, rows, _ = mock_rows()
    save_results(INV, result, rows)
    save_results(INV, result, rows)
    assert get_extracted_counts(INV) == EXPECTED_COUNTS
    assert get_db().execute("SELECT COUNT(*) FROM analysis_results").fetchone()[0] == 1


def test_claim_for_analysis_is_exclusive(ctx):
    make_investigation()
    assert claim_for_analysis(INV) is True
    assert claim_for_analysis(INV) is False
    assert get_investigation(INV)["status"] == "analyzing"


def test_recover_interrupted_analyses(ctx):
    make_investigation()
    claim_for_analysis(INV)
    assert recover_interrupted_analyses() == 1
    record = get_investigation(INV)
    assert record["status"] == "failed"
    assert record["error_message"] == "Analysis was interrupted"