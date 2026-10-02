"""
Email parsing for the EmailTrace forensics engine.

parse_email(file_path)            -> ParsedEmail (internal object)
populate_basic_fields(parsed, r)  -> fills sender / recipient / headers /
                                     mime / body flags in the result dict

Security notes:
- The email is treated as untrusted input.
- Attachments are decoded to bytes in memory only. They are never written to
  disk, opened, or executed.
- Parse problems are collected as warnings instead of raised.
"""

import os
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses
from typing import Any, Dict, Iterator, List, Optional, Tuple

from .schema import make_address

MAX_EML_BYTES = 50 * 1024 * 1024   # refuse absurdly large evidence files
MAX_MIME_DEPTH = 20                # guard against MIME nesting bombs
BODY_TYPES = ("text/plain", "text/html")


@dataclass
class ParsedEmail:
    """Internal parse result shared by the analyzer modules (not JSON output)."""

    file_name: str
    file_size: int
    message: EmailMessage
    header_items: List[Tuple[str, str]] = field(default_factory=list)  # file order
    plain_bodies: List[str] = field(default_factory=list)
    html_bodies: List[str] = field(default_factory=list)
    attachments: List[Dict[str, Any]] = field(default_factory=list)    # includes bytes
    parts: List[Dict[str, Any]] = field(default_factory=list)          # JSON-safe
    warnings: List[str] = field(default_factory=list)


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------

def _clean(value: Any) -> Optional[str]:
    """Return a str that is safe to JSON-encode and store (no lone surrogates)."""
    if value is None:
        return None
    return str(value).encode("utf-8", "replace").decode("utf-8")


def _header_values(parsed: ParsedEmail, name: str) -> List[str]:
    """All values of a header, case-insensitive, in file order."""
    wanted = name.lower()
    return [v for n, v in parsed.header_items if n.lower() == wanted]


def _first(values: List[str]) -> Optional[str]:
    return values[0].strip() if values else None


def parse_addresses(raw_values: List[str]) -> List[Dict[str, Any]]:
    """Turn header values into a list of schema address records."""
    records: List[Dict[str, Any]] = []
    for name, addr in getaddresses(raw_values):
        name, addr = name.strip(), addr.strip()
        if not name and not addr:
            continue
        domain = addr.rpartition("@")[2].lower() if "@" in addr else None
        raw = f"{name} <{addr}>" if name and addr else (addr or name)
        records.append(
            make_address(
                raw=_clean(raw),
                display_name=_clean(name) or None,
                address=_clean(addr.lower()) or None,
                domain=_clean(domain) if domain else None,
            )
        )
    return records


def _collect_header_items(message: EmailMessage, warnings: List[str]) -> List[Tuple[str, str]]:
    items: List[Tuple[str, str]] = []
    try:
        for name, value in message.items():
            try:
                text = _clean(str(value)) or ""
            except Exception:
                text = ""
                warnings.append(f"Could not decode header: {_clean(name)}")
            items.append((_clean(name) or "", text))
    except Exception as exc:
        warnings.append(f"Header extraction failed: {type(exc).__name__}")
    return items


def _iter_leaves(msg: EmailMessage, warnings: List[str], depth: int = 0) -> Iterator[EmailMessage]:
    """Yield non-multipart parts. message/rfc822 is treated as a leaf."""
    if msg.get_content_maintype() == "multipart" and msg.is_multipart():
        if depth >= MAX_MIME_DEPTH:
            warnings.append("MIME nesting exceeded limit; deeper parts ignored")
            return
        for sub in msg.iter_parts():
            yield from _iter_leaves(sub, warnings, depth + 1)
    else:
        yield msg


def _payload_bytes(part: EmailMessage, warnings: List[str]) -> bytes:
    try:
        if part.get_content_type() == "message/rfc822":
            return part.get_payload(0).as_bytes()
        data = part.get_payload(decode=True)
        return data if data is not None else b""
    except Exception as exc:
        warnings.append(f"Could not decode a MIME part payload: {type(exc).__name__}")
        return b""


def _decode_text(part: EmailMessage, data: bytes) -> str:
    charset = part.get_content_charset() or "utf-8"
    try:
        return data.decode(charset, errors="replace")
    except (LookupError, UnicodeDecodeError):
        return data.decode("utf-8", errors="replace")


def _collect_parts(parsed: ParsedEmail) -> None:
    for index, leaf in enumerate(_iter_leaves(parsed.message, parsed.warnings)):
        ctype = leaf.get_content_type()
        try:
            disposition = leaf.get_content_disposition()
        except Exception:
            disposition = None
        try:
            filename = _clean(leaf.get_filename())
        except Exception:
            filename = None
        charset = _clean(leaf.get_content_charset())
        data = _payload_bytes(leaf, parsed.warnings)

        parsed.parts.append(
            {
                "index": index,
                "content_type": ctype,
                "content_disposition": disposition,
                "filename": filename,
                "charset": charset,
                "size_bytes": len(data),
            }
        )

        is_body = ctype in BODY_TYPES and disposition != "attachment" and not filename
        if is_body:
            text = _clean(_decode_text(leaf, data)) or ""
            (parsed.plain_bodies if ctype == "text/plain" else parsed.html_bodies).append(text)
        else:
            parsed.attachments.append(
                {
                    "filename": filename,
                    "mime_type": ctype,
                    "content_disposition": disposition,
                    "payload": data,   # INTERNAL ONLY: never put this in the output
                }
            )


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------

def parse_email(file_path: str) -> ParsedEmail:
    """Parse a .eml file into a ParsedEmail. Raises only for unreadable files."""
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"Email file not found: {file_path}")

    size = os.path.getsize(file_path)
    if size > MAX_EML_BYTES:
        raise ValueError(f"Email file too large ({size} bytes; limit {MAX_EML_BYTES})")

    with open(file_path, "rb") as fh:
        raw = fh.read()

    warnings: List[str] = []
    try:
        message = BytesParser(policy=policy.default).parsebytes(raw)
    except Exception as exc:
        message = EmailMessage()
        warnings.append(f"Email could not be parsed: {type(exc).__name__}")

    parsed = ParsedEmail(
        file_name=os.path.basename(file_path),
        file_size=size,
        message=message,
        warnings=warnings,
    )
    parsed.header_items = _collect_header_items(message, parsed.warnings)

    for defect in message.defects:
        parsed.warnings.append(f"MIME defect: {type(defect).__name__}")

    _collect_parts(parsed)
    return parsed


def populate_basic_fields(parsed: ParsedEmail, result: Dict[str, Any]) -> Dict[str, Any]:
    """Fill the parser-owned parts of the result dict."""
    def hv(name: str) -> List[str]:
        return _header_values(parsed, name)

    # --- sender ---
    from_records = parse_addresses(hv("From"))
    result["sender"]["from"] = from_records[0] if from_records else None
    if len(from_records) > 1:
        parsed.warnings.append("From header lists multiple addresses; first one used")
    result["sender"]["reply_to"] = parse_addresses(hv("Reply-To"))
    return_path = parse_addresses(hv("Return-Path"))   # "<>" (null path) -> []
    result["sender"]["return_path"] = return_path[0] if return_path else None

    # --- recipient ---
    result["recipient"]["to"] = parse_addresses(hv("To"))
    result["recipient"]["cc"] = parse_addresses(hv("Cc"))

    # --- headers ---
    for name in ("From", "Subject", "Date", "Message-ID"):
        if len(hv(name)) > 1:
            parsed.warnings.append(f"Multiple {name} headers present")

    headers = result["headers"]
    headers["subject"] = _first(hv("Subject"))
    headers["date"] = _first(hv("Date"))
    headers["message_id"] = _first(hv("Message-ID"))
    headers["x_mailer"] = _first(hv("X-Mailer"))
    headers["user_agent"] = _first(hv("User-Agent"))

    # --- MIME ---
    mime = headers["mime"]
    mime["is_multipart"] = parsed.message.is_multipart()
    mime["content_type"] = (
        parsed.message.get_content_type() if hv("Content-Type") else None
    )
    mime["content_transfer_encoding"] = _first(hv("Content-Transfer-Encoding"))
    mime["mime_version"] = _first(hv("MIME-Version"))
    mime["parts"] = list(parsed.parts)

    # --- body flags (rule matching comes later) ---
    body = result["content_analysis"]["body"]
    body["has_plain"] = bool(parsed.plain_bodies)
    body["has_html"] = bool(parsed.html_bodies)
    body["text_length"] = sum(len(t) for t in parsed.plain_bodies)

    # --- meta ---
    meta = headers["meta"]
    meta["file_name"] = parsed.file_name
    meta["file_size_bytes"] = parsed.file_size
    meta["warnings"] = list(parsed.warnings)

    return result