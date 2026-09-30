from datetime import datetime, timezone

from flask import Blueprint, jsonify

from database.database import (
    get_analysis_result,
    get_extracted_items,
    get_investigation,
)
from routes import error_response, is_valid_investigation_id

reports_bp = Blueprint("reports", __name__)


@reports_bp.get("/investigation/<investigation_id>/report")
def get_report(investigation_id):
    if not is_valid_investigation_id(investigation_id):
        return error_response("Invalid investigation ID", 400)

    record = get_investigation(investigation_id)
    if record is None:
        return error_response("Investigation not found", 404)

    if record["status"] != "completed":
        return error_response(
            "Investigation has not been analyzed successfully",
            409,
            status=record["status"],
        )

    return jsonify(
        {
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "investigation": record,
            "analysis": get_analysis_result(investigation_id),
            "extracted": get_extracted_items(investigation_id),
        }
    )