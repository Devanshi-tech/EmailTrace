"""
IOC extraction for the EmailTrace forensics engine.

analyze_iocs(parsed, result) -> fills result["iocs"]
defang(ioc_type, value)      -> display-safe form of a value

An IOC (indicator of compromise) here means a value an investigator may want
to search for, share or block: an IP address, domain, URL, email address or
file hash. Extraction is purely local text work. Nothing is resolved, looked
up or visited, and extraction says nothing about whether a value is harmful.

Behavior:
- One record per (type, value). A value seen in several places keeps its first
  place in "source" and every place in "sources".
- Private, loopback and reserved IPs are included, with the class in "note",
  so a consumer can filter them. Recipients are not IOCs. Sender-side
  addresses and addresses found in the body are.
- "defanged" is a non-clickable form (hxxp, [.], [@]) for safe display.
- Body text is scanned after URLs are removed, so tokens inside a URL path
  are not reported as hashes or email addresses.
"""

import html
import ipaddress
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote

from .domain_analyzer import is_valid_domain
from .email_parser import ParsedEmail
from .ip_analyzer import classify_ip
from .schema import make_ioc
from .url_analyzer import _decode_numeric_host  # package-internal helper

MAX_IOCS = 1000
MAX_BODY_CHARS = 2_000_000

DOMAIN_SOURCES = {
    "from": "header:From",
    "reply_to": "header:Reply-To",
    "return_path": "header:Return-Path",
    "url": "url",
}
HASH_ALGORITHMS = {32: "md5", 40: "sha1", 64: "sha256"}
# "file@2x.png" looks like an address but is an image name
NON_TLD_EXTENSIONS = {
    "png", "jpg", "jpeg", "gif", "svg", "webp", "bmp", "ico", "css", "js",
    "woff", "woff2", "ttf", "eot", "map",
}

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@(?:[A-Za-z0-9\-]+\.)+([A-Za-z]{2,24})\b")
_HASH_RE = re.compile(
    r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{64}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{32})(?![0-9A-Fa-f])"
)
_URL_RE = re.compile(r"(?:[a-z][a-z0-9+.\-]{1,15}://|www\.)\S+", re.IGNORECASE)
_MAILTO_RE = re.compile(r"mailto:([^\s\"'<>]+)", re.IGNORECASE)
_URL_PARTS_RE = re.compile(r"^([a-z][a-z0-9+.\-]*://)?([^/?#]*)(.*)$", re.IGNORECASE | re.DOTALL)


# --------------------------------------------------------------------------
# Defanging
# --------------------------------------------------------------------------

def defang(ioc_type: str, value: str) -> str:
    """Return a form that is not clickable or auto-linked."""
    if ioc_type == "url":
        scheme, authority, rest = _URL_PARTS_RE.match(value).groups()
        scheme = scheme or ""
        if scheme.lower().startswith("http"):
            scheme = "hxxp" + scheme[4:]
        return scheme + authority.replace(".", "[.]") + rest
    if ioc_type == "domain":
        return value.replace(".", "[.]")
    if ioc_type == "ip":
        return value.replace(".", "[.]").replace(":", "[:]")
    if ioc_type == "email":
        return value.replace("@", "[@]").replace(".", "[.]")
    return value


# --------------------------------------------------------------------------
# Extraction helpers
# --------------------------------------------------------------------------

def _valid_email(address: str) -> bool:
    local, _, domain = address.rpartition("@")
    if not local or not domain or len(address) > 254 or len(local) > 64:
        return False
    if local.startswith(".") or local.endswith(".") or ".." in local:
        return False
    return is_valid_domain(domain)


def extract_emails(text: str) -> List[str]:
    """Valid, lowercase email addresses in order of appearance, without duplicates."""
    found: List[str] = []
    for match in _EMAIL_RE.finditer(text or ""):
        address = match.group(0).lower()
        if match.group(1).lower() in NON_TLD_EXTENSIONS:
            continue
        if _valid_email(address) and address not in found:
            found.append(address)
    return found


def extract_hashes(text: str) -> List[Tuple[str, str]]:
    """(value, algorithm) pairs for 32, 40 and 64 character hex strings."""
    found: List[Tuple[str, str]] = []
    for match in _HASH_RE.finditer(text or ""):
        value = match.group(0).lower()
        if not any(c.isdigit() for c in value) or not any(c in "abcdef" for c in value):
            continue                      # all digits or all letters is not a hash
        pair = (value, HASH_ALGORITHMS[len(value)])
        if pair not in found:
            found.append(pair)
    return found


def _extract_mailto(raw_html: str) -> List[str]:
    out: List[str] = []
    for match in _MAILTO_RE.finditer(html.unescape(raw_html[:MAX_BODY_CHARS])):
        target = unquote(match.group(1).split("?", 1)[0])
        for part in target.split(","):
            for address in extract_emails(part):
                if address not in out:
                    out.append(address)
    return out


def _plain_text(text: str) -> str:
    return _URL_RE.sub(" ", text[:MAX_BODY_CHARS])


def _html_text(raw_html: str) -> str:
    text = re.sub(r"(?is)<(script|style)\b.*?</\1\s*>", " ", raw_html[:MAX_BODY_CHARS])
    text = re.sub(r"(?s)<[^>]*>", " ", text)
    return _URL_RE.sub(" ", html.unescape(text))


def _url_host_ip(url: Dict[str, Any]) -> Optional[Any]:
    host = url.get("hostname")
    if not host:
        return None
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        if "obfuscated_ip_host" in url["flags"]:
            return _decode_numeric_host(host)
        return None


# --------------------------------------------------------------------------
# Collection
# --------------------------------------------------------------------------

class _Collector:
    def __init__(self) -> None:
        self.items: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self.dropped = 0

    def add(self, ioc_type: str, value: str, source: str, note: Optional[str] = None) -> None:
        key = (ioc_type, value)
        record = self.items.get(key)
        if record is None:
            if len(self.items) >= MAX_IOCS:
                self.dropped += 1
                return
            self.items[key] = make_ioc(
                ioc_type, value, source, sources=[source],
                defanged=defang(ioc_type, value), note=note,
            )
            return
        if source not in record["sources"]:
            record["sources"].append(source)
        if note and not record["note"]:
            record["note"] = note


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------

def analyze_iocs(parsed: ParsedEmail, result: Dict[str, Any]) -> None:
    """Collect IOCs from everything the earlier analyzers found, plus body text."""
    collector = _Collector()

    # IP addresses: headers first, then IP hosts used in URLs
    for record in result["ips"]:
        for source in record["sources"] or ["header"]:
            collector.add("ip", record["ip"], source, record["classification"])
    for url in result["urls"]:
        ip = _url_host_ip(url)
        if ip is not None:
            collector.add("ip", str(ip), "url", classify_ip(ip)[0])

    # Domains
    for record in result["domains"]:
        for source in record["sources"]:
            collector.add("domain", record["domain"], DOMAIN_SOURCES.get(source, source))

    # URLs (a URL without a host, such as javascript:, is not a network indicator)
    for record in result["urls"]:
        if not record["hostname"]:
            continue
        note = ", ".join(record["flags"]) or None
        for source in record["sources"]:
            collector.add("url", record["url"], f"body:{source}", note)

    # Email addresses: sender side, then body text. Recipients are not IOCs.
    sender = result["sender"]
    from_rec = sender.get("from")
    if from_rec and from_rec.get("address") and _valid_email(from_rec["address"]):
        collector.add("email", from_rec["address"].lower(), "header:From")
    if from_rec:
        for address in extract_emails(from_rec.get("display_name") or ""):
            collector.add("email", address, "header:From:display_name")
    for record in sender.get("reply_to") or []:
        if record.get("address") and _valid_email(record["address"]):
            collector.add("email", record["address"].lower(), "header:Reply-To")
    return_path = sender.get("return_path")
    if return_path and return_path.get("address") and _valid_email(return_path["address"]):
        collector.add("email", return_path["address"].lower(), "header:Return-Path")

    plain_texts = [_plain_text(t) for t in parsed.plain_bodies]
    html_texts = [_html_text(t) for t in parsed.html_bodies]
    for text in plain_texts:
        for address in extract_emails(text):
            collector.add("email", address, "body:text/plain")
    for text in html_texts:
        for address in extract_emails(text):
            collector.add("email", address, "body:text/html")
    for raw_html in parsed.html_bodies:
        for address in _extract_mailto(raw_html):
            collector.add("email", address, "body:mailto")

    # Hashes: attachment SHA-256 values, then hash-like strings in the body
    for index, attachment in enumerate(result["attachments"]):
        if attachment["size_bytes"] == 0:
            continue                      # the hash of an empty file says nothing
        collector.add(
            "hash", attachment["sha256"], f"attachment[{index}]",
            f"sha256; {attachment['mime_type'] or 'unknown type'}, {attachment['size_bytes']} bytes",
        )
    for source, texts in (("body:text/plain", plain_texts), ("body:text/html", html_texts)):
        for text in texts:
            for value, algorithm in extract_hashes(text):
                collector.add("hash", value, source,
                              f"{algorithm}-length hex string found in body text")

    if collector.dropped:
        result["headers"]["meta"]["warnings"].append(
            f"IOC list capped at {MAX_IOCS}; {collector.dropped} more values ignored"
        )
    result["iocs"] = list(collector.items.values())