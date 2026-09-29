"""
EmailTrace forensics engine.

Public entry point for the backend:

    from analyzer import analyze_email
    result = analyze_email("evidence/sample.eml")

The returned dictionary is JSON-serializable and follows analyzer.schema.
"""

import os
from typing import Any, Dict

from .schema import SCHEMA_VERSION, empty_result, validate_result

__all__ = ["analyze_email", "SCHEMA_VERSION", "validate_result"]


def analyze_email(file_path: str) -> Dict[str, Any]:
    """
    Analyze a simulated or authorized .eml file and return the result dict.

    NOTE: Step 1 stub. Returns the empty schema with file metadata only.
    Later steps plug the analyzer modules in here.
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"Email file not found: {file_path}")

    result = empty_result()
    meta = result["headers"]["meta"]
    meta["file_name"] = os.path.basename(file_path)
    meta["file_size_bytes"] = os.path.getsize(file_path)
    return result