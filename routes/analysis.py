from flask import Blueprint, jsonify

from database.database import get_extracted_counts, get_investigation
from routes import error_response, is_valid_investigation_id

analysis_bp = Blueprint("analysis", __name__)


@analysis_bp.get("/investigation/<investigation_id>")
def get_investigation_detail(investigation_id):
    if not is_valid_investigation_id(investigation_id):
        return error_response("Invalid investigation ID", 400)

    record = get_investigation(investigation_id)
    if record is None:
        return error_response("Investigation not found", 404)

    payload = dict(record)
    payload["analysis_available"] = record["status"] == "completed"
    payload["counts"] = get_extracted_counts(investigation_id)
    return jsonify(payload)


@analysis_bp.post("/analyze/<investigation_id>")
def analyze_investigation(investigation_id):
    if not is_valid_investigation_id(investigation_id):
        return error_response("Invalid investigation ID", 400)

    record = get_investigation(investigation_id)
    if record is None:
        return error_response("Investigation not found", 404)

    if record["status"] == "analyzing":
        return error_response(
            "Analysis already in progress", 409, status=record["status"]
        )

    return error_response(
        "Analyzer integration is not implemented yet",
        501,
        investigation_id=investigation_id,
        status=record["status"],
    )