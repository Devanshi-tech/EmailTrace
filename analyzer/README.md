# Analyzer contract

Owned by the backend (Member 1): `contract.py`, `runner.py`, `mock_analyzer.py`. Do not edit them or create files with those names.

Owned by the analyzer (Member 2): everything else in this folder, including `__init__.py`.

## Entry point

Create `analyzer/__init__.py` exporting `analyze_email(file_path: str) -> dict`. Import it from your own modules if it lives elsewhere.

## Return value

A plain dict containing these keys. Missing or `None` keys default to empty. Extra keys are kept. Values must be JSON-serializable (dict, list, str, int, float, bool, None), and list keys must be lists, not tuples.

| Key | Type | Elements the backend stores in its tables |
|---|---|---|
| sender | dict | any keys |
| recipient | dict | any keys |
| headers | dict | any keys |
| received_paths | list | any JSON values |
| ips | list | str, or `{"ip", "hop_index", "source"}` |
| timestamps | list | any JSON values |
| urls | list | str, or `{"url", "domain", "suspicious"}` |
| domains | list | str, or `{"domain", "suspicious", "reason"}` |
| attachments | list | `{"filename", "content_type", "size", "sha256", "suspicious"}` |
| content_analysis | dict | any keys |
| iocs | list | str, or `{"type", "value", "description", "severity"}` |
| risk_indicators | list | any JSON values |

Malformed elements in `ips`, `urls`, `domains`, `attachments`, and `iocs` are skipped and logged.

## Rules

- Raise an exception on failure. Do not return partial error dicts.
- `file_path` is a validated path inside `uploads/`. Open it read-only.
- Treat all email content as untrusted.
- No network access: no HTTP requests, no DNS lookups, never follow URLs.
- Never execute, open, or write attachments to disk. Return metadata and hashes only.
- External enrichment must be optional and off by default.