import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent


def _env_bool(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


class Config:
    DEBUG = _env_bool("EMAILTRACE_DEBUG", False)

    DATABASE_PATH = os.environ.get(
        "EMAILTRACE_DATABASE_PATH",
        str(BASE_DIR / "database" / "emailtrace.db")
    )

    UPLOAD_FOLDER = os.environ.get(
        "EMAILTRACE_UPLOAD_FOLDER",
        str(BASE_DIR / "uploads")
    )

    REPORTS_FOLDER = os.environ.get(
        "EMAILTRACE_REPORTS_FOLDER",
        str(BASE_DIR / "reports")
    )

    MAX_CONTENT_LENGTH = (
        int(os.environ.get("EMAILTRACE_MAX_UPLOAD_MB", "5")) * 1024 * 1024
    )

    ALLOWED_EXTENSIONS = {".eml"}

    ANALYZER_FALLBACK_TO_MOCK = _env_bool(
        "EMAILTRACE_ANALYZER_FALLBACK_TO_MOCK",
        True
    )

    ENABLE_EXTERNAL_ENRICHMENT = _env_bool(
        "EMAILTRACE_ENABLE_ENRICHMENT",
        False
    )