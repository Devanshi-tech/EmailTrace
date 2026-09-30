import hashlib
import uuid
from email import policy
from email.parser import BytesParser
from pathlib import Path

from flask import Blueprint, current_app, jsonify, request
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename

from database.database import create_investigation


upload_bp = Blueprint("upload", __name__)

EXPECTED_HEADERS = {"from", "to", "subject", "date", "message-id", "received"}
DEFAULT_DISPLAY_NAME = "evidence.eml"


def _error(message, status):
    return jsonify({"error": message}), status


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
        message = BytesParser(policy=policy.default).parsebytes(
            data, headersonly=True
        )
        return bool(EXPECTED_HEADERS & {key.lower() for key in message.keys()})
    except Exception:
        return False


@upload_bp.post("/upload")
def upload_evidence():
    try:
        file = request.files.get("file")
    except RequestEntityTooLarge:
        return _error("File exceeds the maximum allowed size", 413)

    if file is None:
        return _error("No file part named 'file' in the request", 400)
    if not file.filename:
        return _error("No file selected", 400)
    if not has_allowed_extension(file.filename):
        return _error("Only .eml files are accepted", 400)

    max_bytes = current_app.config["MAX_CONTENT_LENGTH"]
    data = file.stream.read(max_bytes + 1)
    if len(data) > max_bytes:
        return _error("File exceeds the maximum allowed size", 413)
    if not data:
        return _error("Uploaded file is empty", 400)
    if not looks_like_email(data):
        return _error("File is not a valid RFC 822 email message", 400)

    investigation_id = uuid.uuid4().hex
    stored_filename = f"{investigation_id}.eml"
    file_path = Path(current_app.config["UPLOAD_FOLDER"]) / stored_filename
    display_name = sanitize_display_name(file.filename)
    sha256 = hashlib.sha256(data).hexdigest()

    with open(file_path, "xb") as handle:
        handle.write(data)

    try:
        create_investigation(
            investigation_id,
            display_name,
            stored_filename,
            str(file_path),
            len(data),
            sha256,
        )
    except Exception:
        file_path.unlink(missing_ok=True)
        raise

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