import hashlib
import logging
import uuid
from email import policy
from email.parser import BytesParser
from pathlib import Path

from flask import Blueprint, current_app, jsonify, request
from werkzeug.utils import secure_filename

from database.database import create_investigation
from routes import error_response

logger = logging.getLogger(__name__)

upload_bp = Blueprint("upload", __name__)

EXPECTED_HEADERS = {"from", "to", "subject", "date", "message-id", "received"}
DEFAULT_DISPLAY_NAME = "evidence.eml"


def has_allowed_extension(filename):
    return Path(filename).suffix.lower() in current_app.config["ALLOWED_EXTENSIONS"]


def sanitize_display_name(filename):
    cleaned = secure_filename(filename)
    if not cleaned.lower().endswith(".eml"):
        return DEFAULT_DISPLAY_NAME
    return cleaned


def looks_like_email(data):
    if b"\x00" in data:
        return False
    try:
        message = BytesParser(policy=policy.default).parsebytes(data, headersonly=True)
        return bool(EXPECTED_HEADERS & {key.lower() for key in message.keys()})
    except Exception:
        return False


def _reject(reason, message, http_status):
    logger.warning("Upload rejected: %s", reason)
    return error_response(message, http_status)


@upload_bp.post("/upload")
def upload_evidence():
    file = request.files.get("file")

    if file is None:
        return _reject("no file part", "No file part named 'file' in the request", 400)
    if not file.filename:
        return _reject("no file selected", "No file selected", 400)
    if not has_allowed_extension(file.filename):
        return _reject("extension not allowed", "Only .eml files are accepted", 400)

    max_bytes = current_app.config["MAX_CONTENT_LENGTH"]
    data = file.stream.read(max_bytes + 1)
    if len(data) > max_bytes:
        return _reject("file too large", "File exceeds the maximum allowed size", 413)
    if not data:
        return _reject("empty file", "Uploaded file is empty", 400)
    if not looks_like_email(data):
        return _reject(
            "not a valid email", "File is not a valid RFC 822 email message", 400
        )

    investigation_id = uuid.uuid4().hex
    stored_filename = f"{investigation_id}.eml"
    file_path = Path(current_app.config["UPLOAD_FOLDER"]) / stored_filename
    display_name = sanitize_display_name(file.filename)
    sha256 = hashlib.sha256(data).hexdigest()

    created = False
    try:
        with open(file_path, "xb") as handle:
            created = True
            handle.write(data)
        create_investigation(
            investigation_id,
            display_name,
            stored_filename,
            str(file_path),
            len(data),
            sha256,
        )
    except Exception:
        if created:
            file_path.unlink(missing_ok=True)
        raise

    logger.info(
        "Upload accepted: investigation=%s size=%d sha256=%s",
        investigation_id,
        len(data),
        sha256,
    )
    return (
        jsonify(
            {
                "investigation_id": investigation_id,
                "status": "uploaded",
                "original_filename": display_name,
                "file_size": len(data),
                "sha256": sha256,
            }
        ),
        201,
    )