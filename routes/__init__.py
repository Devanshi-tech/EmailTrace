import re

from flask import jsonify

INVESTIGATION_ID_PATTERN = re.compile(r"[0-9a-f]{32}")


def is_valid_investigation_id(value):
    return bool(INVESTIGATION_ID_PATTERN.fullmatch(value))


def error_response(message, http_status, **extra):
    return jsonify({"error": message, **extra}), http_status