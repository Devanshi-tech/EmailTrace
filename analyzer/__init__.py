"""
EmailTrace forensics engine.

Public entry point for the backend:

    from analyzer import analyze_email
    result = analyze_email("evidence/sample.eml")

The returned dictionary is JSON-serializable and follows analyzer.schema.
"""

from typing import Any, Dict

from .email_parser import parse_email, populate_basic_fields
from .header_analyzer import analyze_headers
from .schema import SCHEMA_VERSION, empty_result, validate_result

__all__ = ["analyze_email", "SCHEMA_VERSION", "validate_result"]


def analyze_email(file_path: str) -> Dict[str, Any]:
    """
    Analyze a simulated or authorized .eml file and return the result dict.

    Step 3: parsing + authentication/header analysis. Later steps add
    received paths, IPs, URLs, domains, attachments, content and IOCs.
    """
    parsed = parse_email(file_path)
    result = empty_result()
    populate_basic_fields(parsed, result)
    analyze_headers(parsed, result)
    return result