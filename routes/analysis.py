import logging
from pathlib import Path

from flask import Blueprint, current_app, jsonify

from analyzer.contract import AnalyzerError, AnalyzerUnavailableError
from analyzer.runner import run_analysis
from database.database import get_extracted_counts, get_investigation
from database.results import (
    build_rows,
    claim_for_analysis,
    get_stored_filename,
    mark_failed,
    save_results,
)
from routes import error_response, is_valid_investigation_id

logger = logging.getLogger(__name__)

analysis_bp = Blueprint("analysis", __name__)


def _fail(investigation_id, message, http_status):
    logger.warning("Analysis failed: investigation=%s reason=%s", investigation_id, message)
    try:
        mark_failed(investigation_id, message)
    except Exception:
        logger.exception("Could not mark investigation %s as failed", investigation_id)
    return error_response(
        message, http_status, investigation_id=investigation_id, status="failed"
    )


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

    if get_investigation(investigation_id) is None:
        return error_response("Investigation not found", 404)

    if not claim_for_analysis(investigation_id):
        logger.warning(
            "Analysis rejected: investigation=%s already in progress", investigation_id
        )
        return error_response("Analysis already in progress", 409, status="analyzing")

    logger.info("Analysis started: investigation=%s", investigation_id)
    try:
        stored_filename = get_stored_filename(investigation_id)
        file_path = Path(current_app.config["UPLOAD_FOLDER"]) / stored_filename
        result, analyzer_name = run_analysis(str(file_path))
        rows, skipped = build_rows(result)
        save_results(investigation_id, result, rows)
    except AnalyzerUnavailableError as exc:
        return _fail(investigation_id, str(exc), 503)
    except AnalyzerError as exc:
        return _fail(investigation_id, str(exc), 500)
    except Exception:
        logger.exception("Failed to process analysis for %s", investigation_id)
        return _fail(investigation_id, "Failed to process analysis results", 500)

    logger.info(
        "Analysis completed: investigation=%s analyzer=%s skipped=%d",
        investigation_id,
        analyzer_name,
        skipped,
    )
    record = get_investigation(investigation_id)
    return jsonify(
        {
            "investigation_id": investigation_id,
            "status": "completed",
            "analyzer": analyzer_name,
            "analyzed_at": record["analyzed_at"],
            "counts": get_extracted_counts(investigation_id),
            "skipped_elements": skipped,
        }
    )