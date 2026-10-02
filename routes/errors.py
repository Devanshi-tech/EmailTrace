import logging
import sqlite3

from flask import jsonify, request
from werkzeug.exceptions import HTTPException, MethodNotAllowed

logger = logging.getLogger(__name__)

HTTP_MESSAGES = {
    400: "Bad request",
    404: "Resource not found",
    405: "Method not allowed",
    413: "File exceeds the maximum allowed size",
    415: "Unsupported media type",
}


def _json_error(message, http_status):
    response = jsonify({"error": message})
    response.status_code = http_status
    return response


def handle_http_exception(exc):
    if exc.code is None or not request.path.startswith("/api/"):
        return exc
    response = _json_error(HTTP_MESSAGES.get(exc.code, exc.name), exc.code)
    if isinstance(exc, MethodNotAllowed) and exc.valid_methods:
        response.headers["Allow"] = ", ".join(exc.valid_methods)
    return response


def handle_database_error(exc):
    logger.exception("Database error on %s %s", request.method, request.path)
    if "locked" in str(exc).lower():
        return _json_error("Database is busy, try again", 503)
    return _json_error("Database error", 500)


def handle_unexpected_error(exc):
    logger.exception("Unhandled error on %s %s", request.method, request.path)
    return _json_error("Internal server error", 500)


def register_error_handlers(app):
    app.register_error_handler(HTTPException, handle_http_exception)
    app.register_error_handler(sqlite3.Error, handle_database_error)
    app.register_error_handler(Exception, handle_unexpected_error)