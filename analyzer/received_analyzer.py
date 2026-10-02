"""
Received-path and timestamp analysis for the EmailTrace forensics engine.

analyze_received_path(parsed, result) -> fills result["received_paths"] and
                                         headers.routing, adds routing indicators
analyze_timestamps(parsed, result)    -> fills result["timestamps"], adds
                                         timestamp indicators

Principles:
- Hop order is preserved exactly as in the file: index 0 is the TOPMOST
  Received header (the most recent hop). The highest index is the oldest hop.
- Only headers added by servers YOU control are reliable. Lower hops were
  written by other systems and can be forged, so "originating" means the
  earliest sending host the chain CLAIMS.
- Nothing here contacts the network. IP classification happens in Step 5.
"""

import ipaddress
import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Dict, List, Optional, Tuple

from .email_parser import ParsedEmail
from .schema import make_indicator, make_received_hop, make_timestamp_record

CLOCK_SKEW_TOLERANCE_SECONDS = 300      # ordering differences up to 5 min are ignored
BACKWARD_MEDIUM_SECONDS = 3600          # more than 1 hour out of order -> medium
LONG_DELAY_SECONDS = 24 * 3600          # Date more than 24 h before first hop -> info

_COMMENT_RE = re.compile(r"\([^()]*\)")
_FROM_RE = re.compile(r"^\s*from\s+(\S+)\s*((?:\([^()]*\)\s*)*)", re.I)
_BY_RE = re.compile(r"(?<![\w-])by\s+(\S+)\s*((?:\([^()]*\)\s*)*)", re.I)
_WITH_RE = re.compile(r"(?<![\w-])with\s+(.+?)(?=\s+(?:id|for|via)\b|$)", re.I)
_ID_RE = re.compile(r"(?<![\w-])id\s+(\S+)", re.I)
_HELO_RE = re.compile(r"helo=([^\s)]+)", re.I)


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _ips_in(text: Optional[str]) -> List[str]:
    """Return valid IPv4/IPv6 addresses found as tokens in text, in order."""
    found: List[str] = []
    for token in re.split(r"[\s,()]+", text or ""):
        candidate = token.strip("[]<>;").strip()
        if candidate.lower().startswith("ipv6:"):
            candidate = candidate[5:]
        try:
            found.append(str(ipaddress.ip_address(candidate)))
        except ValueError:
            continue
    return found


def normalize_timestamp(raw: Optional[str]) -> Tuple[str, Optional[str], Optional[str]]:
    """
    Returns (status, iso_utc, note).
    status is "ok", "missing" or "malformed". note is set when UTC was assumed.
    """
    if raw is None or not raw.strip():
        return "missing", None, None
    cleaned = " ".join(_COMMENT_RE.sub(" ", raw).split())
    try:
        parsed = parsedate_to_datetime(cleaned)
    except (TypeError, ValueError, IndexError, OverflowError):
        return "malformed", None, None
    if parsed is None:
        return "malformed", None, None
    note = None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
        note = "no timezone; UTC assumed"
    return "ok", parsed.astimezone(timezone.utc).isoformat(), note


def _fmt_delta(seconds: float) -> str:
    seconds = int(abs(seconds))
    hours, rest = divmod(seconds, 3600)
    minutes, secs = divmod(rest, 60)
    if hours:
        return f"{hours}h {minutes:02d}m"
    if minutes:
        return f"{minutes}m {secs:02d}s"
    return f"{secs}s"


def _warn(result: Dict[str, Any], message: str) -> None:
    warnings = result["headers"]["meta"]["warnings"]
    if message not in warnings:
        warnings.append(message)


# --------------------------------------------------------------------------
# Received header parsing
# --------------------------------------------------------------------------

def parse_received_header(raw: str, index: int) -> Dict[str, Any]:
    """Parse one Received header value into a schema hop record."""
    text = " ".join(raw.split())
    body, sep, ts_part = text.rpartition(";")
    if sep:
        timestamp_raw = ts_part.strip() or None
    else:
        body, timestamp_raw = text, None

    from_host = from_ip = by_host = by_ip = None

    rest = body
    from_match = _FROM_RE.match(body)
    if from_match:
        token, comments = from_match.group(1), from_match.group(2)
        token_ips = _ips_in(token)
        if token_ips:                          # e.g. from [192.168.1.44] (helo=laptop)
            from_ip = token_ips[0]
            helo = _HELO_RE.search(comments)
            from_host = helo.group(1) if helo else None
        else:
            from_host = token
            comment_ips = _ips_in(comments)
            from_ip = comment_ips[0] if comment_ips else None
        rest = body[from_match.end():]

    tail = rest
    by_match = _BY_RE.search(rest)
    if by_match:
        token, comments = by_match.group(1), by_match.group(2)
        token_ips = _ips_in(token)
        if token_ips:
            by_ip = token_ips[0]
        else:
            by_host = token
            comment_ips = _ips_in(comments)
            by_ip = comment_ips[0] if comment_ips else None
        tail = rest[by_match.end():]

    stripped = " ".join(_COMMENT_RE.sub(" ", tail).split())
    with_match = _WITH_RE.search(stripped)
    id_match = _ID_RE.search(stripped)

    _, timestamp_utc, _ = normalize_timestamp(timestamp_raw)
    return make_received_hop(
        index=index,
        raw=text,
        from_host=from_host,
        from_ip=from_ip,
        by_host=by_host,
        by_ip=by_ip,
        protocol=with_match.group(1).strip() if with_match else None,
        server_id=id_match.group(1) if id_match else None,
        timestamp_raw=timestamp_raw,
        timestamp_utc=timestamp_utc,
    )


def analyze_received_path(parsed: ParsedEmail, result: Dict[str, Any]) -> None:
    """Parse all Received headers (file order) and fill the routing summary."""
    values = [v for n, v in parsed.header_items if n.lower() == "received"]
    hops = [parse_received_header(v, i) for i, v in enumerate(values)]
    result["received_paths"] = hops

    routing = result["headers"]["routing"]
    routing["hop_count"] = len(hops)
    if hops:
        routing["final_receiving_host"] = hops[0]["by_host"]
        for hop in reversed(hops):             # oldest hop first
            if hop["from_host"] or hop["from_ip"]:
                routing["originating_host"] = hop["from_host"]
                routing["originating_ip"] = hop["from_ip"]
                break

    indicators = result["risk_indicators"]
    if not hops:
        indicators.append(make_indicator(
            "No Received headers found",
            "info",
            "The message has no Received headers. They may have been removed, or the "
            "file may be an export or draft that never passed through a mail server.",
            "routing",
        ))
    for hop in hops:
        if not (hop["from_host"] or hop["from_ip"] or hop["by_host"] or hop["by_ip"]):
            indicators.append(make_indicator(
                "Received header could not be parsed",
                "info",
                f"received[{hop['index']}] raw value: {hop['raw'][:200]}",
                "routing",
            ))


# --------------------------------------------------------------------------
# Timestamp analysis
# --------------------------------------------------------------------------

def analyze_timestamps(parsed: ParsedEmail, result: Dict[str, Any]) -> None:
    """Normalize Date and Received timestamps and check their consistency."""
    indicators = result["risk_indicators"]
    records: List[Dict[str, Any]] = []
    valid: List[Tuple[int, datetime]] = []      # (hop index, time) in file order
    date_dt: Optional[datetime] = None

    date_raw = result["headers"]["date"]
    status, iso, note = normalize_timestamp(date_raw)
    records.append(make_timestamp_record("date", date_raw, iso, status))
    if status == "missing":
        indicators.append(make_indicator(
            "Date header is missing", "low",
            "No Date header was found in the message.", "timestamp",
        ))
    elif status == "malformed":
        indicators.append(make_indicator(
            "Date header is malformed", "low",
            f"The Date value could not be parsed: {date_raw!r}", "timestamp",
        ))
    else:
        date_dt = datetime.fromisoformat(iso)
    if note:
        _warn(result, f"date timestamp has {note}")

    for hop in result["received_paths"]:
        label = f"received[{hop['index']}]"
        status, iso, note = normalize_timestamp(hop["timestamp_raw"])
        records.append(make_timestamp_record(label, hop["timestamp_raw"], iso, status))
        if status == "missing":
            indicators.append(make_indicator(
                "Received header has no timestamp", "low",
                f"{label} has no timestamp after its final ';'.", "timestamp",
            ))
        elif status == "malformed":
            indicators.append(make_indicator(
                "Received header timestamp is malformed", "low",
                f"{label} timestamp could not be parsed: {hop['timestamp_raw']!r}",
                "timestamp",
            ))
        else:
            valid.append((hop["index"], datetime.fromisoformat(iso)))
        if note:
            _warn(result, f"{label} timestamp has {note}")

    result["timestamps"] = records

    # Ordering: an older hop (higher index) should not be later than a newer hop.
    for (new_i, new_t), (old_i, old_t) in zip(valid, valid[1:]):
        gap = (old_t - new_t).total_seconds()
        if gap > CLOCK_SKEW_TOLERANCE_SECONDS:
            severity = "medium" if gap > BACKWARD_MEDIUM_SECONDS else "low"
            indicators.append(make_indicator(
                "Received timestamps out of order",
                severity,
                f"received[{old_i}] (older hop) is stamped {old_t.isoformat()}, which is "
                f"{_fmt_delta(gap)} later than received[{new_i}] (newer hop) at "
                f"{new_t.isoformat()}. Clock skew, timezone errors or edited headers "
                "can all cause this.",
                "timestamp",
            ))

    # Date header versus the Received chain.
    if date_dt and valid:
        newest_t, oldest_t = valid[0][1], valid[-1][1]
        ahead = (date_dt - newest_t).total_seconds()
        if ahead > CLOCK_SKEW_TOLERANCE_SECONDS:
            indicators.append(make_indicator(
                "Date header is later than the most recent Received timestamp",
                "low",
                f"Date is {date_dt.isoformat()}, {_fmt_delta(ahead)} after the newest "
                f"Received timestamp ({newest_t.isoformat()}). The sender's clock may be "
                "wrong or the Date may have been set manually.",
                "timestamp",
            ))
        behind = (oldest_t - date_dt).total_seconds()
        if behind > LONG_DELAY_SECONDS:
            indicators.append(make_indicator(
                "Date header is more than 24 hours before the earliest Received timestamp",
                "info",
                f"Date is {date_dt.isoformat()}, {_fmt_delta(behind)} before the oldest "
                f"Received timestamp ({oldest_t.isoformat()}). Delayed delivery and "
                "queued mail can cause this.",
                "timestamp",
            ))