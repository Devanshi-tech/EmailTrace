import json
import re
from pathlib import Path

EXPECTED_COUNTS = {
    "attachments": 1,
    "iocs": 1,
    "ip_addresses": 2,
    "suspicious_domains": 1,
    "urls": 1,
}
EMPTY_COUNTS = dict.fromkeys(EXPECTED_COUNTS, 0)
UNKNOWN_ID = "0" * 32


def test_health(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}


def test_detail_response_shape(client, investigation_id):
    response = client.get(f"/api/investigation/{investigation_id}")
    body = response.get_json()
    assert response.status_code == 200
    assert set(body) == {
        "investigation_id",
        "status",
        "error_message",
        "created_at",
        "updated_at",
        "analyzed_at",
        "evidence",
        "analysis_available",
        "counts",
    }
    assert set(body["evidence"]) == {
        "original_filename",
        "file_size",
        "sha256",
        "uploaded_at",
    }
    assert body["investigation_id"] == investigation_id
    assert body["status"] == "uploaded"
    assert body["analysis_available"] is False
    assert body["counts"] == EMPTY_COUNTS


def test_detail_does_not_expose_server_paths(client, investigation_id):
    text = client.get(f"/api/investigation/{investigation_id}").get_data(as_text=True)
    assert "file_path" not in text
    assert "stored_filename" not in text


def test_detail_invalid_id_returns_400(client):
    response = client.get("/api/investigation/abc")
    assert response.status_code == 400
    assert response.get_json() == {"error": "Invalid investigation ID"}
    assert client.get("/api/investigation/" + "A" * 32).status_code == 400


def test_detail_unknown_id_returns_404(client):
    response = client.get(f"/api/investigation/{UNKNOWN_ID}")
    assert response.status_code == 404
    assert response.get_json() == {"error": "Investigation not found"}


def test_unknown_api_route_returns_json_404(client):
    response = client.get("/api/nope")
    assert response.status_code == 404
    assert response.get_json() == {"error": "Resource not found"}


def test_wrong_method_returns_json_405(client):
    response = client.get("/api/upload")
    assert response.status_code == 405
    assert response.get_json() == {"error": "Method not allowed"}
    assert "POST" in response.headers["Allow"]


def test_responses_carry_request_id_header(client):
    response = client.get("/api/health")
    assert re.fullmatch(r"[0-9a-f]{12}", response.headers["X-Request-ID"])


def test_analyze_rejects_invalid_and_unknown_ids(client):
    assert client.post("/api/analyze/abc").status_code == 400
    response = client.post(f"/api/analyze/{UNKNOWN_ID}")
    assert response.status_code == 404
    assert response.get_json() == {"error": "Investigation not found"}


def test_analyze_completes_with_mock_analyzer(client, investigation_id):
    response = client.post(f"/api/analyze/{investigation_id}")
    body = response.get_json()
    assert response.status_code == 200
    assert body["investigation_id"] == investigation_id
    assert body["status"] == "completed"
    assert body["analyzer"] == "mock"
    assert body["analyzed_at"] is not None
    assert body["skipped_elements"] == 0
    assert body["counts"] == EXPECTED_COUNTS


def test_detail_after_analysis(client, investigation_id):
    client.post(f"/api/analyze/{investigation_id}")
    body = client.get(f"/api/investigation/{investigation_id}").get_json()
    assert body["status"] == "completed"
    assert body["analysis_available"] is True
    assert body["error_message"] is None
    assert body["analyzed_at"] is not None
    assert body["counts"] == EXPECTED_COUNTS


def test_report_before_analysis_returns_409(client, investigation_id):
    response = client.get(f"/api/investigation/{investigation_id}/report")
    assert response.status_code == 409
    assert response.get_json() == {
        "error": "Investigation has not been analyzed successfully",
        "status": "uploaded",
    }


def test_report_after_analysis(client, investigation_id):
    client.post(f"/api/analyze/{investigation_id}")
    response = client.get(f"/api/investigation/{investigation_id}/report")
    body = response.get_json()
    assert response.status_code == 200
    assert set(body) == {"generated_at", "investigation", "analysis", "extracted"}
    assert body["investigation"]["status"] == "completed"
    assert body["analysis"]["sender"]["address"] == "attacker@example.test"
    assert set(body["extracted"]) == set(EXPECTED_COUNTS)
    assert {key: len(value) for key, value in body["extracted"].items()} == EXPECTED_COUNTS
    assert body["extracted"]["ip_addresses"][0] == {
        "ip_address": "192.0.2.10",
        "hop_index": 0,
        "source": "received",
    }
    assert body["extracted"]["suspicious_domains"] == [
        {"domain": "example.test", "reason": "Mock indicator"}
    ]


def test_report_file_persisted(app, client, investigation_id):
    client.post(f"/api/analyze/{investigation_id}")
    client.get(f"/api/investigation/{investigation_id}/report")
    path = Path(app.config["REPORTS_FOLDER"]) / f"{investigation_id}.json"
    assert path.is_file()
    saved = json.loads(path.read_text(encoding="utf-8"))
    assert saved["investigation"]["investigation_id"] == investigation_id


def test_reanalysis_replaces_results(client, investigation_id, db_rows):
    for _ in range(2):
        assert client.post(f"/api/analyze/{investigation_id}").status_code == 200
    ips = db_rows(
        "SELECT COUNT(*) AS n FROM ip_addresses WHERE investigation_id = ?",
        investigation_id,
    )
    results = db_rows(
        "SELECT COUNT(*) AS n FROM analysis_results WHERE investigation_id = ?",
        investigation_id,
    )
    assert ips[0]["n"] == 2
    assert results[0]["n"] == 1


def test_analyzer_unavailable_returns_503_and_blocks_report(app, client, investigation_id):
    app.config["ANALYZER_FALLBACK_TO_MOCK"] = False
    response = client.post(f"/api/analyze/{investigation_id}")
    assert response.status_code == 503
    assert response.get_json()["status"] == "failed"
    detail = client.get(f"/api/investigation/{investigation_id}").get_json()
    assert detail["status"] == "failed"
    assert detail["error_message"]
    assert client.get(f"/api/investigation/{investigation_id}/report").status_code == 409