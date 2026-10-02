import logging
import re
import time
import uuid
from logging.handlers import RotatingFileHandler
from pathlib import Path

from flask import g, has_request_context, request
from flask.logging import default_handler

LOG_FORMAT = "%(asctime)s %(levelname)s [%(request_id)s] %(name)s: %(message)s"
LOG_FILENAME = "emailtrace.log"
HANDLER_MARKER = "_emailtrace_handler"
UNSAFE_CHARS = re.compile(r"[^\x20-\x7e]")
MAX_LOGGED_PATH = 200


def _escape(match):
    return match.group().encode("unicode_escape").decode("ascii")


class SafeFormatter(logging.Formatter):
    def formatMessage(self, record):
        return UNSAFE_CHARS.sub(_escape, super().formatMessage(record))


class RequestIdFilter(logging.Filter):
    def filter(self, record):
        record.request_id = g.get("request_id", "-") if has_request_context() else "-"
        return True


def _request_log_level(status):
    if status >= 500:
        return logging.ERROR
    if status >= 400:
        return logging.WARNING
    return logging.INFO


def setup_logging(app):
    level = logging.getLevelName(str(app.config["LOG_LEVEL"]).upper())
    if not isinstance(level, int):
        level = logging.INFO

    root = logging.getLogger()
    for handler in list(root.handlers):
        if getattr(handler, HANDLER_MARKER, False):
            root.removeHandler(handler)
            handler.close()

    handlers = [logging.StreamHandler()]
    if app.config["LOG_TO_FILE"]:
        folder = Path(app.config["LOG_FOLDER"])
        folder.mkdir(parents=True, exist_ok=True)
        handlers.append(
            RotatingFileHandler(
                folder / LOG_FILENAME,
                maxBytes=app.config["LOG_MAX_BYTES"],
                backupCount=app.config["LOG_BACKUP_COUNT"],
                encoding="utf-8",
            )
        )

    formatter = SafeFormatter(LOG_FORMAT)
    for handler in handlers:
        handler.setFormatter(formatter)
        handler.addFilter(RequestIdFilter())
        setattr(handler, HANDLER_MARKER, True)
        root.addHandler(handler)

    root.setLevel(level)
    app.logger.removeHandler(default_handler)
    logging.getLogger("werkzeug").setLevel(logging.WARNING)


def register_request_logging(app):
    request_logger = logging.getLogger("emailtrace.requests")

    @app.before_request
    def start_request():
        g.request_id = uuid.uuid4().hex[:12]
        g.request_started = time.perf_counter()

    @app.after_request
    def log_request(response):
        started = g.get("request_started")
        elapsed_ms = (time.perf_counter() - started) * 1000 if started is not None else 0.0
        request_logger.log(
            _request_log_level(response.status_code),
            "%s %s -> %d (%.1f ms)",
            request.method,
            request.path[:MAX_LOGGED_PATH],
            response.status_code,
            elapsed_ms,
        )
        request_id = g.get("request_id")
        if request_id:
            response.headers["X-Request-ID"] = request_id
        return response