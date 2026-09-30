"""
Output schema for the EmailTrace forensics engine.

Every analyzer module builds its records with the helpers below, so field
names and allowed values stay consistent. All records are plain
JSON-serializable dicts.

Top-level result:
{
    "sender": {},            # from / reply_to / return_path address records
    "recipient": {},         # to / cc address record lists
    "headers": {},           # subject, date, message_id, auth, mime, meta ...
    "received_paths": [],    # one record per Received header, file order
    "ips": [],               # unique IPs with classification
    "timestamps": [],        # Date + Received timestamps, normalized
    "urls": [],              # extracted URLs with static flags
    "domains": [],           # unique domains with where they were seen
    "attachments": [],       # filename, MIME, size, SHA-256
    "content_analysis": {},  # transparent rule matches on subject/body
    "iocs": [],              # {type, value, source}
    "risk_indicators": []    # {indicator, severity, evidence, category}
}
"""

import json
from typing import Any, Dict, List, Optional

SCHEMA_VERSION = "1.0"

TOP_LEVEL_KEYS = (
    "sender",
    "recipient",
    "headers",
    "received_paths",
    "ips",
    "timestamps",
    "urls",
    "domains",
    "attachments",
    "content_analysis",
    "iocs",
    "risk_indicators",
)

DICT_KEYS = ("sender", "recipient", "headers", "content_analysis")
LIST_KEYS = tuple(k for k in TOP_LEVEL_KEYS if k not in DICT_KEYS)

# Severity describes how much an indicator deserves investigator attention.
# It is NOT a verdict. There is deliberately no "critical" or "malicious".
SEVERITIES = ("info", "low", "medium", "high")

INDICATOR_CATEGORIES = (
    "header",
    "authentication",
    "routing",
    "timestamp",
    "ip",
    "url",
    "domain",
    "attachment",
    "content",
)

IOC_TYPES = ("ip", "domain", "url", "email", "hash")

IP_CLASSES = ("public", "private", "loopback", "reserved")

TIMESTAMP_STATUSES = ("ok", "missing", "malformed")


# --------------------------------------------------------------------------
# Result skeleton
# --------------------------------------------------------------------------

def empty_result() -> Dict[str, Any]:
    """Return a fresh, fully-shaped result with nothing filled in."""
    return {
        "sender": {
            "from": None,          # address record or None
            "reply_to": [],        # list of address records
            "return_path": None,   # address record or None
        },
        "recipient": {
            "to": [],              # list of address records
            "cc": [],              # list of address records
        },
        "headers": {
            "subject": None,
            "date": None,          # raw Date header string
            "message_id": None,
            "x_mailer": None,
            "user_agent": None,
            "authentication": {
                "authentication_results_raw": [],
                "received_spf_raw": None,
                "spf": None,       # e.g. "pass", "fail", or None if absent
                "dkim": None,      # "pass" if any signature passed
                "dmarc": None,
                "details": {
                    "authserv_id": None,              # server that wrote the topmost result
                    "spf_mailfrom_domain": None,      # smtp.mailfrom / envelope-from domain
                    "dkim_results": [],               # [{"result": ..., "domain": ...}]
                    "dmarc_header_from_domain": None,
                },
            },
            "mime": {
                "is_multipart": False,
                "content_type": None,
                "content_transfer_encoding": None,
                "mime_version": None,
                "parts": [],       # one summary dict per MIME part
            },
                        "routing": {
                "hop_count": 0,
                "originating_host": None,       # earliest recorded sending host (as claimed)
                "originating_ip": None,
                "final_receiving_host": None,   # "by" host of the topmost Received header
            },
            "meta": {
                "schema_version": SCHEMA_VERSION,
                "file_name": None,
                "file_size_bytes": None,
                "warnings": [],    # parse problems, never raised as errors
            },
        },
        "received_paths": [],
        "ips": [],
        "timestamps": [],
        "urls": [],
        "domains": [],
        "attachments": [],
        "content_analysis": {
            "matched_rules": [],   # see make_content_match()
            "category_counts": {},
            "body": {
                "has_plain": False,
                "has_html": False,
                "text_length": 0,
            },
        },
        "iocs": [],
        "risk_indicators": [],
    }


# --------------------------------------------------------------------------
# Record builders
# --------------------------------------------------------------------------

def make_address(
    raw: Optional[str] = None,
    display_name: Optional[str] = None,
    address: Optional[str] = None,
    domain: Optional[str] = None,
) -> Dict[str, Any]:
    """An email address as found in From/To/CC/Reply-To/Return-Path."""
    return {
        "raw": raw,
        "display_name": display_name,
        "address": address,
        "domain": domain,
    }


def make_received_hop(
    index: int,
    raw: str,
    from_host: Optional[str] = None,
    from_ip: Optional[str] = None,
    by_host: Optional[str] = None,
    by_ip: Optional[str] = None,
    protocol: Optional[str] = None,
    server_id: Optional[str] = None,
    timestamp_raw: Optional[str] = None,
    timestamp_utc: Optional[str] = None,
) -> Dict[str, Any]:
    """
    One Received header. `index` 0 is the TOP header in the file, which is the
    most recent hop. The originating hop is the highest index.
    """
    return {
        "index": index,
        "raw": raw,
        "from_host": from_host,
        "from_ip": from_ip,
        "by_host": by_host,
        "by_ip": by_ip,
        "protocol": protocol,
        "server_id": server_id,
        "timestamp_raw": timestamp_raw,
        "timestamp_utc": timestamp_utc,
    }


def make_ip_record(
    ip: str,
    version: int,
    classification: str,
    sources: Optional[List[str]] = None,
    reason: Optional[str] = None,
) -> Dict[str, Any]:
    if classification not in IP_CLASSES:
        raise ValueError(f"Invalid IP classification: {classification!r}")
    if version not in (4, 6):
        raise ValueError(f"Invalid IP version: {version!r}")
    return {
        "ip": ip,
        "version": version,
        "classification": classification,
        "reason": reason,            # why it got that class, e.g. "RFC 1918 private range"
        "sources": sources or [],    # e.g. ["received[2]:from", "header:X-Originating-IP"]
    }


def make_timestamp_record(
    source: str,
    raw: Optional[str],
    normalized_utc: Optional[str],
    status: str,
) -> Dict[str, Any]:
    if status not in TIMESTAMP_STATUSES:
        raise ValueError(f"Invalid timestamp status: {status!r}")
    return {
        "source": source,            # "date" or "received[N]"
        "raw": raw,
        "normalized_utc": normalized_utc,   # ISO 8601, e.g. 2026-01-05T10:15:00+00:00
        "status": status,
    }


def make_url_record(
    url: str,
    scheme: Optional[str],
    hostname: Optional[str],
    path: Optional[str],
    query: Optional[str],
    source: str,
    flags: Optional[List[str]] = None,
    sources: Optional[List[str]] = None,
    contexts: Optional[List[str]] = None,
    link_text: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "url": url,
        "scheme": scheme,            # None for bare "www." and "//host" URLs
        "hostname": hostname,        # lowercase, no port or credentials
        "path": path,
        "query": query,
        "source": source,            # first place seen: "text/plain" or "text/html"
        "sources": sources or [source],
        "contexts": contexts or [],  # e.g. "text", "a[href]", "img[src]"
        "link_text": link_text,      # visible text of the first <a> using this URL
        "flags": flags or [],        # e.g. ["ip_based", "url_shortener"]
    }

def make_domain_record(
    domain: str,
    sources: Optional[List[str]] = None,
    url_count: int = 0,
) -> Dict[str, Any]:
    return {
        "domain": domain,            # lowercase, exact hostname as seen
        "sources": sources or [],    # any of: "from", "reply_to", "return_path", "url"
        "url_count": url_count,      # number of unique extracted URLs on this host
    }

def make_attachment_record(
    filename: Optional[str],
    mime_type: Optional[str],
    size_bytes: int,
    sha256: str,
    content_disposition: Optional[str] = None,
    extension: Optional[str] = None,
    detected_type: Optional[str] = None,
    flags: Optional[List[str]] = None,
) -> Dict[str, Any]:
    return {
        "filename": filename,                       # raw name; escape before display
        "mime_type": mime_type,                     # as declared in Content-Type
        "size_bytes": size_bytes,
        "sha256": sha256,
        "content_disposition": content_disposition,
        "extension": extension,                     # last extension, lowercase
        "detected_type": detected_type,             # from leading bytes, or None
        "flags": flags or [],
    }


def make_content_match(
    rule: str,
    category: str,
    matched_text: str,
    location: str,
) -> Dict[str, Any]:
    """One transparent keyword/pattern rule hit in the subject or body."""
    return {
        "rule": rule,                # human-readable rule name
        "category": category,        # e.g. "urgency", "credential_request"
        "matched_text": matched_text,
        "location": location,        # "subject", "body_plain", "body_html"
    }


def make_ioc(ioc_type: str, value: str, source: str) -> Dict[str, Any]:
    if ioc_type not in IOC_TYPES:
        raise ValueError(f"Invalid IOC type: {ioc_type!r}")
    return {"type": ioc_type, "value": value, "source": source}


def make_indicator(
    indicator: str,
    severity: str,
    evidence: str,
    category: str,
) -> Dict[str, Any]:
    if severity not in SEVERITIES:
        raise ValueError(f"Invalid severity: {severity!r}")
    if category not in INDICATOR_CATEGORIES:
        raise ValueError(f"Invalid category: {category!r}")
    return {
        "indicator": indicator,
        "severity": severity,
        "evidence": evidence,
        "category": category,
    }


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------

def validate_result(result: Dict[str, Any]) -> List[str]:
    """
    Check a result against the contract. Returns a list of problems;
    an empty list means the result is valid and JSON-serializable.
    """
    problems: List[str] = []

    if not isinstance(result, dict):
        return ["result is not a dict"]

    missing = [k for k in TOP_LEVEL_KEYS if k not in result]
    extra = [k for k in result if k not in TOP_LEVEL_KEYS]
    if missing:
        problems.append(f"missing keys: {missing}")
    if extra:
        problems.append(f"unexpected keys: {extra}")

    for key in DICT_KEYS:
        if key in result and not isinstance(result[key], dict):
            problems.append(f"'{key}' must be a dict")
    for key in LIST_KEYS:
        if key in result and not isinstance(result[key], list):
            problems.append(f"'{key}' must be a list")

    for i, ind in enumerate(result.get("risk_indicators", []) or []):
        if not isinstance(ind, dict):
            problems.append(f"risk_indicators[{i}] must be a dict")
            continue
        if ind.get("severity") not in SEVERITIES:
            problems.append(f"risk_indicators[{i}] has invalid severity")
        if ind.get("category") not in INDICATOR_CATEGORIES:
            problems.append(f"risk_indicators[{i}] has invalid category")

    for i, ioc in enumerate(result.get("iocs", []) or []):
        if not isinstance(ioc, dict) or ioc.get("type") not in IOC_TYPES:
            problems.append(f"iocs[{i}] has invalid type")

    try:
        json.dumps(result)
    except (TypeError, ValueError) as exc:
        problems.append(f"not JSON-serializable: {exc}")

    return problems