import importlib
import logging
from pathlib import Path

from flask import current_app

from analyzer import mock_analyzer
from analyzer.contract import (
    AnalyzerExecutionError,
    AnalyzerUnavailableError,
    EvidenceFileError,
    normalize_result,
)

logger = logging.getLogger(__name__)


def _validated_path(file_path):
    upload_root = Path(current_app.config["UPLOAD_FOLDER"]).resolve()
    resolved = Path(file_path).resolve()

    if (
        not resolved.is_relative_to(upload_root)
        or resolved.suffix.lower() != ".eml"
        or not resolved.is_file()
    ):
        raise EvidenceFileError(
            "Evidence file is missing or outside the upload folder"
        )

    return str(resolved)


def resolve_analyzer():
    module_name = current_app.config["ANALYZER_MODULE"]
    module = None

    try:
        module = importlib.import_module(module_name)

    except ModuleNotFoundError as exc:
        missing = exc.name
        is_analyzer_itself = missing is not None and (
            module_name == missing
            or module_name.startswith(f"{missing}.")
        )

        if not is_analyzer_itself:
            logger.exception(
                "Analyzer module '%s' failed to import",
                module_name,
            )
            raise AnalyzerExecutionError(
                "Analyzer module failed to import: ModuleNotFoundError"
            ) from exc

    except Exception as exc:
        logger.exception(
            "Analyzer module '%s' failed to import",
            module_name,
        )
        raise AnalyzerExecutionError(
            f"Analyzer module failed to import: {type(exc).__name__}"
        ) from exc

    func = getattr(module, "analyze_email", None) if module is not None else None

    if callable(func):
        return func, module_name

    if current_app.config["ANALYZER_FALLBACK_TO_MOCK"]:
        logger.warning(
            "Analyzer '%s' does not provide analyze_email; "
            "using mock analyzer",
            module_name,
        )
        return mock_analyzer.analyze_email, "mock"

    raise AnalyzerUnavailableError(
        f"Analyzer '{module_name}' does not provide analyze_email "
        "and mock fallback is disabled"
    )


def run_analysis(file_path):
    safe_path = _validated_path(file_path)
    func, analyzer_name = resolve_analyzer()

    try:
        raw = func(safe_path)

    except Exception as exc:
        logger.exception(
            "Analyzer '%s' failed on %s",
            analyzer_name,
            Path(safe_path).name,
        )
        raise AnalyzerExecutionError(
            f"Analyzer raised {type(exc).__name__}"
        ) from exc

    result = normalize_result(raw)

    logger.info(
        "Analyzer '%s' completed for %s",
        analyzer_name,
        Path(safe_path).name,
    )

    return result, analyzer_name