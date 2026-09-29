"""
IP address analysis for the EmailTrace forensics engine.

analyze_ips(parsed, result) -> fills result["ips"] and adds IP indicators
classify_ip(ip)             -> (classification, reason)
scan_text_for_ips(text)     -> (valid IPs in order, invalid IPv4-like literals)

Principles:
- Classification is purely offline, using Python's ipaddress module.
  No ping, port scan, DNS/PTR lookup, GeoIP or WHOIS is performed.
- IPs come from Received headers plus a fixed list of headers that commonly
  carry addresses. Body text and URLs are handled by later modules.
- Headers such as X-Originating-IP are written by servers or webmail systems.
  They are evidence, but they can be forged when added upstream.
"""

import ipaddress
import re
from typing import Any, Dict, List, Tuple, Union

from .email_parser import ParsedEmail
from .schema import make_indicator, make_ip_record

IP_HEADERS = (
    "X-Originating-IP",
    "X-Forwarded-For",
    "X-Real-IP",
    "X-Sender-IP",
    "X-Client-IP",
    "X-Source-IP",
    "Received-SPF",
    "Authentication-Results",
)

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

_PRIVATE_NETS = [
    (ipaddress.ip_network(net), label)
    for net, label in (
        ("10.0.0.0/8", "RFC 1918 private range"),
        ("172.16.0.0/12", "RFC 1918 private range"),
        ("192.168.0.0/16", "RFC 1918 private range"),
        ("fc00::/7", "IPv6 unique local range"),
    )
]

_RESERVED_NETS = [
    (ipaddress.ip_network(net), label)
    for net, label in (
        ("0.0.0.0/8", "'this network' range"),
        ("100.64.0.0/10", "shared address space (carrier-grade NAT)"),
        ("169.254.0.0/16", "link-local range"),
        ("192.0.0.0/24", "IETF protocol assignments"),
        ("192.0.2.0/24", "documentation range (TEST-NET-1)"),
        ("198.18.0.0/15", "benchmarking range"),
        ("198.51.100.0/24", "documentation range (TEST-NET-2)"),
        ("203.0.113.0/24", "documentation range (TEST-NET-3)"),
        ("224.0.0.0/4", "multicast range"),
        ("240.0.0.0/4", "reserved range (includes broadcast)"),
        ("::/128", "unspecified address"),
        ("100::/64", "discard-only range"),
        ("2001:db8::/32", "documentation range"),
        ("fe80::/10", "link-local range"),
        ("ff00::/8", "multicast range"),
    )
]

# IPv4 candidate: not glued to word characters, dots, colons or hyphens, and not
# followed by more hostname text (so "10.1.2.3.static.example.net" is ignored).
_IPV4_RE = re.compile(r"(?<![\w.:\-])(\d{1,3}(?:\.\d{1,3}){3})(?![\w\-]|\.\w)")
_TOKEN_RE = re.compile(r"[^\s,;()\[\]<>\"']+")


# --------------------------------------------------------------------------
# Classification and scanning
# --------------------------------------------------------------------------

def classify_ip(ip: IPAddress) -> Tuple[str, Any]:
    """Return (classification, reason). reason is None for public addresses."""
    if ip.version == 6 and ip.ipv4_mapped is not None:
        classification, reason = classify_ip(ip.ipv4_mapped)
        note = "IPv4-mapped IPv6 address"
        return classification, f"{note}; {reason}" if reason else note

    if ip.is_loopback:
        return "loopback", "loopback address"
    for net, label in _PRIVATE_NETS:
        if ip in net:
            return "private", f"{label} ({net})"
    for net, label in _RESERVED_NETS:
        if ip in net:
            return "reserved", f"{label} ({net})"
    if ip.is_global:
        return "public", None
    return "reserved", "special-purpose non-global range"


def scan_text_for_ips(text: str) -> Tuple[List[str], List[str]]:
    """
    Find IP addresses in free text.

    Returns (valid, invalid): valid is a de-duplicated list of normalized
    addresses in order of appearance; invalid lists IPv4-shaped literals that
    are not valid addresses (for example 999.1.1.1).
    """
    if not text:
        return [], []

    hits: List[Tuple[int, str]] = []
    invalid: List[str] = []

    for match in _IPV4_RE.finditer(text):
        try:
            hits.append((match.start(), str(ipaddress.IPv4Address(match.group(1)))))
        except ValueError:
            if match.group(1) not in invalid:
                invalid.append(match.group(1))

    for match in _TOKEN_RE.finditer(text):
        token = match.group(0).rsplit("=", 1)[-1]          # client-ip=2001:db8::1
        if token.lower().startswith("ipv6:"):              # [IPv6:2001:db8::1]
            token = token[5:]
        token = token.rstrip(".")
        if ":" not in token:
            continue
        try:
            hits.append((match.start(), str(ipaddress.IPv6Address(token))))
        except ValueError:
            continue

    hits.sort()
    valid: List[str] = []
    for _, ip_text in hits:
        if ip_text not in valid:
            valid.append(ip_text)
    return valid, invalid


# --------------------------------------------------------------------------
# Indicators
# --------------------------------------------------------------------------

def _describe(records: List[Dict[str, Any]], limit: int = 6) -> str:
    parts = [
        f"{r['ip']} ({r['classification']}: {r['reason']}; seen in "
        f"{', '.join(r['sources'][:3])})"
        for r in records[:limit]
    ]
    if len(records) > limit:
        parts.append(f"and {len(records) - limit} more")
    return "; ".join(parts)


def _build_indicators(
    records: List[Dict[str, Any]], invalid: List[Tuple[str, str]]
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []

    local = [r for r in records if r["classification"] in ("private", "loopback")]
    reserved = [r for r in records if r["classification"] == "reserved"]
    public = [r for r in records if r["classification"] == "public"]

    if local:
        out.append(make_indicator(
            "Private or loopback IP addresses in headers",
            "info",
            f"{_describe(local)}. This is normal for internal relays and local "
            "delivery. These addresses cannot be traced from outside the network.",
            "ip",
        ))
    if reserved:
        out.append(make_indicator(
            "IP addresses from reserved or special-purpose ranges",
            "low",
            f"{_describe(reserved)}. These ranges are not routable on the public "
            "Internet. They are expected in simulated or test data. In real "
            "evidence they may point to misconfiguration or edited headers.",
            "ip",
        ))
    for literal, source in invalid:
        out.append(make_indicator(
            "Invalid IP address literal in headers",
            "low",
            f"{literal!r} in {source} is not a valid IP address. It may be a "
            "formatting error, an unrelated number sequence, or an edited header.",
            "ip",
        ))

    if not records:
        out.append(make_indicator(
            "No IP addresses found in analyzed headers",
            "info",
            "No valid IPv4 or IPv6 address was found in the Received headers or "
            "in the address-bearing headers that were checked.",
            "ip",
        ))
    elif not public:
        out.append(make_indicator(
            "No public IP address found in headers",
            "info",
            f"All {len(records)} extracted address(es) are private, loopback or "
            "reserved, so the message cannot be traced to a public origin from "
            "IP addresses alone.",
            "ip",
        ))
    return out


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------

def analyze_ips(parsed: ParsedEmail, result: Dict[str, Any]) -> None:
    """Extract, classify and record IP addresses. Requires received_paths."""
    collected: Dict[str, List[str]] = {}
    invalid: Dict[Tuple[str, str], None] = {}

    def add(ip_text: str, source: str) -> None:
        sources = collected.setdefault(ip_text, [])
        if source not in sources:
            sources.append(source)

    for hop in result["received_paths"]:
        label = f"received[{hop['index']}]"
        valid, bad = scan_text_for_ips(hop["raw"])
        for ip_text in valid:
            if ip_text == hop["from_ip"]:
                add(ip_text, f"{label}:from")
            elif ip_text == hop["by_ip"]:
                add(ip_text, f"{label}:by")
            else:
                add(ip_text, label)
        for literal in bad:
            invalid.setdefault((literal, label), None)

    for name in IP_HEADERS:
        wanted = name.lower()
        for header_name, value in parsed.header_items:
            if header_name.lower() != wanted:
                continue
            valid, bad = scan_text_for_ips(value)
            for ip_text in valid:
                add(ip_text, f"header:{name}")
            for literal in bad:
                invalid.setdefault((literal, f"header:{name}"), None)

    records: List[Dict[str, Any]] = []
    for ip_text, sources in collected.items():
        ip = ipaddress.ip_address(ip_text)
        classification, reason = classify_ip(ip)
        records.append(make_ip_record(ip_text, ip.version, classification, sources, reason))

    result["ips"] = records
    result["risk_indicators"].extend(_build_indicators(records, list(invalid)))