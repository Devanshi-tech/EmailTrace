import json

RESULT_SCHEMA = {
    "sender": dict,
    "recipient": dict,
    "headers": dict,
    "received_paths": list,
    "ips": list,
    "timestamps": list,
    "urls": list,
    "domains": list,
    "attachments": list,
    "content_analysis": dict,
    "iocs": list,
    "risk_indicators": list,
}


class AnalyzerError(Exception):
    pass


class AnalyzerUnavailableError(AnalyzerError):
    pass


class AnalyzerExecutionError(AnalyzerError):
    pass


class AnalyzerContractError(AnalyzerError):
    pass


class EvidenceFileError(AnalyzerError):
    pass


def normalize_result(raw):
    if not isinstance(raw, dict):
        raise AnalyzerContractError(
            f"Analyzer must return a dict, got {type(raw).__name__}"
        )
    result = dict(raw)
    for key, expected in RESULT_SCHEMA.items():
        value = result.get(key)
        if value is None:
            result[key] = expected()
        elif not isinstance(value, expected):
            raise AnalyzerContractError(
                f"'{key}' must be {expected.__name__}, got {type(value).__name__}"
            )
    try:
        json.dumps(result)
    except (TypeError, ValueError) as exc:
        raise AnalyzerContractError(
            "Analyzer result is not JSON-serializable"
        ) from exc
    return result