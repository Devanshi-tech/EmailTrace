"""
URL analysis for the EmailTrace forensics engine.

analyze_urls(parsed, result)  -> fills result["urls"] and adds URL indicators
extract_urls_from_text(text)  -> URL strings found in free text

Principles:
- URLs are treated as inert text. They are parsed with urllib.parse only.
  Nothing here visits a URL, resolves a hostname, or opens a connection.
- HTML is read with the standard-library HTMLParser. Nothing is rendered
  or executed.
- Flags describe static properties of the URL text. They are evidence for an
  investigator, not a verdict. Every indicator explains legitimate causes.
- Frontends should display these URLs as plain text, never as clickable links.
"""

import ipaddress
import re
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote, urlsplit

from .email_parser import ParsedEmail
from .ip_analyzer import classify_ip
from .schema import make_indicator, make_url_record

MAX_URLS = 500                  # unique URLs kept per email
MAX_BODY_CHARS = 2_000_000      # body text scanned per part
MAX_URL_CHARS = 2048            # stored URL length
MAX_CONTEXTS = 10
MAX_LINK_TEXT_CHARS = 300
EVIDENCE_URL_LIMIT = 5
EVIDENCE_URL_CHARS = 100

MANY_SUBDOMAIN_LABELS = 5
MANY_HYPHENS = 3
HEAVY_ENCODING_MIN_ESCAPES = 10
HEAVY_ENCODING_RATIO = 0.5

WEB_SCHEMES = {"http", "https"}
DANGEROUS_SCHEMES = {"javascript", "vbscript", "data", "file", "blob", "about", "jar"}
IGNORED_SCHEMES = {"mailto", "tel", "sms", "cid", "callto", "fax", "geo"}

URL_SHORTENERS = (
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "tiny.cc", "shorturl.at", "rb.gy", "bl.ink",
    "lnkd.in", "t.ly", "s.id", "v.gd", "trib.al", "adf.ly", "bit.do",
)

# Small fixed watch list. These TLDs also host many legitimate sites.
SUSPICIOUS_TLDS = {"zip", "mov", "tk", "ml", "ga", "cf", "gq", "top", "xyz", "click"}

HOSTNAME_KEYWORDS = (
    "login", "signin", "secure", "verify", "account", "update",
    "password", "wallet", "banking", "confirm",
)

URL_ATTRS = {
    "href", "src", "action", "formaction", "data", "poster",
    "background", "xlink:href", "cite",
}

# Link text such as "invoice.pdf" is a file name, not a web address.
FILE_EXTENSIONS = {
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "csv", "rtf",
    "zip", "rar", "png", "jpg", "jpeg", "gif", "html", "htm", "exe", "js",
}

_TEXT_URL_RE = re.compile(
    r"(?<![\w@.\-])((?:[a-z][a-z0-9+.\-]{1,15}://|www\.)[^\s<>\"'`\\^{}|]+)",
    re.IGNORECASE,
)
_SCHEME_RE = re.compile(r"^([a-z][a-z0-9+.\-]+):", re.IGNORECASE)
_CSS_URL_RE = re.compile(r"url\(\s*['\"]?([^'\")\s]+)", re.IGNORECASE)
_META_URL_RE = re.compile(r"\burl\s*=\s*['\"]?([^'\";]+)", re.IGNORECASE)
_PERCENT_RE = re.compile(r"%[0-9a-fA-F]{2}")
_EMBEDDED_URL_RE = re.compile(r"\b(?:https?|ftp)://([^/\s&?#]+)", re.IGNORECASE)
_NUMERIC_HOST_RE = re.compile(
    r"^(?:0x[0-9a-f]+|\d+)(?:\.(?:0x[0-9a-f]+|\d+)){0,3}$", re.IGNORECASE
)
_TEXT_HOST_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?)*"
    r"\.([a-z]{2,24})(?:[/:?#]\S*)?$",
    re.IGNORECASE,
)

# (flag, indicator title, severity, explanation). Order = order of indicators.
FLAG_RULES = [
    ("ip_based", "URL uses an IP address instead of a hostname", "medium",
     "Legitimate services rarely link to a raw IP address, although internal "
     "tools and test systems sometimes do."),
    ("obfuscated_ip_host", "URL hides an IP address in a numeric form", "medium",
     "Decimal, hexadecimal or octal host numbers are unusual in normal links "
     "and can slip past simple filters."),
    ("dangerous_scheme", "URL uses a scheme that carries active or local content", "medium",
     "Schemes such as javascript:, data: and file: do not point to a web page. "
     "Mail clients usually block them, but their presence in a link is worth noting."),
    ("unusual_scheme", "URL uses a scheme other than http or https", "low",
     "Other schemes such as ftp are legitimate but uncommon in email."),
    ("userinfo_in_url", "URL contains text before an '@' in the address", "medium",
     "Text before '@' can make a link look like it belongs to a different site "
     "than the host that is actually contacted."),
    ("link_text_mismatch", "Link text shows a different site than the link target", "medium",
     "Marketing mail often does this through click-tracking services, so check "
     "whether the target belongs to a known tracker."),
    ("url_shortener", "URL uses a link-shortening service", "low",
     "The final destination is hidden. It was not resolved because URLs are "
     "never visited by this engine."),
    ("encoded_hostname", "URL hostname contains percent-encoding", "medium",
     "Normal hostnames are not percent-encoded, so this may be an attempt to "
     "disguise the host."),
    ("embedded_url_in_parameters", "URL embeds another URL in its path or query", "low",
     "Tracking, redirect and single-sign-on links commonly do this. The "
     "embedded destination is worth reviewing."),
    ("heavy_percent_encoding", "URL path or query is heavily percent-encoded", "low",
     "Long encoded strings hide readable text, but tracking parameters are "
     "often encoded too."),
    ("embedded_control_characters", "URL contains embedded tab or line-break characters", "low",
     "Browsers ignore these characters, so they can be used to break up a "
     "scheme or hostname."),
    ("idn_hostname", "URL hostname uses non-ASCII or punycode characters", "low",
     "Internationalized names are legitimate, but they can imitate well-known "
     "domains with lookalike characters."),
    ("many_subdomains", "URL hostname has many subdomain levels", "low",
     "Deep subdomain chains can push the real registered domain out of view."),
    ("many_hyphens", "URL hostname contains many hyphens", "low",
     "Hyphen-heavy hostnames are common in lookalike domains, but not exclusive to them."),
    ("hostname_keywords", "URL hostname contains account-related keywords", "low",
     "Words such as login or verify appear in both legitimate and lookalike hostnames."),
    ("suspicious_tld", "URL uses a top-level domain from the built-in watch list", "low",
     "The watch list is a small fixed list. These TLDs also host many legitimate sites."),
    ("malformed_url", "URL could not be parsed cleanly", "low",
     "The address may be truncated, mistyped or deliberately malformed."),
]


# --------------------------------------------------------------------------
# Text helpers
# --------------------------------------------------------------------------

def _trim_trailing(url: str) -> str:
    """Remove sentence punctuation and unbalanced closing brackets from the end."""
    while url:
        last = url[-1]
        if last in ".,;:!?*":
            url = url[:-1]
        elif last == ")" and url.count("(") < url.count(")"):
            url = url[:-1]
        elif last == "]" and url.count("[") < url.count("]"):
            url = url[:-1]
        else:
            break
    return url


def _looks_like_url(url: str) -> bool:
    if "://" in url:
        return len(url.split("://", 1)[1]) > 0
    return url.lower().startswith("www.") and "." in url[4:]


def extract_urls_from_text(text: str) -> List[str]:
    """Return unique URL-like strings in order of appearance."""
    urls: List[str] = []
    for match in _TEXT_URL_RE.finditer(text or ""):
        url = _trim_trailing(match.group(1))
        if url and _looks_like_url(url) and url not in urls:
            urls.append(url)
    return urls


def _shorten(text: str, limit: int = EVIDENCE_URL_CHARS) -> str:
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _same_or_subdomain(a: str, b: str) -> bool:
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def _decode_numeric_host(host: str) -> Optional[ipaddress.IPv4Address]:
    """Decode decimal / hex / octal IPv4 host forms such as 3232235777 or 0xC0A80001."""
    parts = host.split(".")
    values: List[int] = []
    for part in parts:
        try:
            if part.lower().startswith("0x"):
                values.append(int(part, 16))
            elif len(part) > 1 and part.startswith("0"):
                values.append(int(part, 8))
            else:
                values.append(int(part, 10))
        except ValueError:
            return None
    if any(v > 255 for v in values[:-1]) or values[-1] >= 256 ** (5 - len(values)):
        return None
    number = 0
    for v in values[:-1]:
        number = (number << 8) | v
    number = (number << (8 * (5 - len(values)))) | values[-1]
    return ipaddress.IPv4Address(number)


def _host_shown_in_text(text: str) -> Optional[str]:
    """If anchor text looks like a web address, return the hostname it shows."""
    match = re.search(r"(?i)(?:https?://|www\.)[^\s<>\"']+", text)
    candidate = match.group(0) if match else None
    if candidate is None:
        stripped = text.strip()
        host_match = _TEXT_HOST_RE.match(stripped)
        if host_match and host_match.group(1).lower() not in FILE_EXTENSIONS:
            candidate = stripped
    if not candidate:
        return None
    target = candidate if "://" in candidate else "http://" + candidate
    try:
        host = urlsplit(target).hostname
    except ValueError:
        return None
    return host.rstrip(".") if host else None


# --------------------------------------------------------------------------
# Single URL analysis
# --------------------------------------------------------------------------

def _analyze_url(raw: str, embedded_control: bool) -> Dict[str, Any]:
    """Parse one URL string and compute its static flags. No network access."""
    flags: List[str] = []
    notes: Dict[str, str] = {}

    scheme: Optional[str] = None
    match = _SCHEME_RE.match(raw)
    if match and (raw[match.end():].startswith("//")
                  or match.group(1).lower() in DANGEROUS_SCHEMES):
        scheme = match.group(1).lower()

    if scheme is not None:
        target = raw
    elif raw.startswith("//"):
        target = "http:" + raw
    else:
        target = "http://" + raw

    parts = None
    hostname: Optional[str] = None
    path: Optional[str] = None
    query: Optional[str] = None
    try:
        parts = urlsplit(target)
    except ValueError:
        flags.append("malformed_url")
    if parts is not None:
        try:
            hostname = parts.hostname
            _ = parts.port
        except ValueError:
            flags.append("malformed_url")
        path = parts.path or None
        query = parts.query or None
    if hostname:
        hostname = hostname.rstrip(".") or None

    # Scheme
    if scheme in DANGEROUS_SCHEMES:
        flags.append("dangerous_scheme")
        notes["dangerous_scheme"] = f"scheme {scheme}:"
    elif scheme is not None and scheme not in WEB_SCHEMES:
        flags.append("unusual_scheme")
        notes["unusual_scheme"] = f"scheme {scheme}://"

    # Text before '@'
    if parts is not None and "@" in parts.netloc:
        user = parts.netloc.rpartition("@")[0].split(":")[0]
        flags.append("userinfo_in_url")
        notes["userinfo_in_url"] = (
            f"text before '@' is {user!r}; the host is {hostname or 'unknown'}"
        )

    # Hostname
    if hostname:
        ip: Any = None
        try:
            ip = ipaddress.ip_address(hostname)
        except ValueError:
            pass
        if ip is None and _NUMERIC_HOST_RE.match(hostname):
            decoded = _decode_numeric_host(hostname)
            if decoded is not None:
                ip = decoded
                flags.append("obfuscated_ip_host")
                notes["obfuscated_ip_host"] = f"{hostname} decodes to {decoded}"
        if ip is not None:
            classification, _reason = classify_ip(ip)
            flags.append("ip_based")
            notes["ip_based"] = f"{ip}, {classification}"
        else:
            if parts is not None and "%" in parts.netloc:
                flags.append("encoded_hostname")
                notes["encoded_hostname"] = f"host text: {_shorten(parts.netloc, 60)}"
            labels = hostname.split(".")
            puny = [label for label in labels if label.startswith("xn--")]
            if puny or any(ord(c) > 127 for c in hostname):
                flags.append("idn_hostname")
                described = []
                for label in puny:
                    try:
                        described.append(f"{label} = {label.encode('ascii').decode('idna')}")
                    except Exception:
                        described.append(label)
                notes["idn_hostname"] = "; ".join(described) or "non-ASCII characters in hostname"
            if len(labels) >= MANY_SUBDOMAIN_LABELS:
                flags.append("many_subdomains")
                notes["many_subdomains"] = f"{hostname} has {len(labels)} labels"
            hyphens = hostname.replace("xn--", "").count("-")   # "xn--" is punycode syntax
            if hyphens >= MANY_HYPHENS:
                flags.append("many_hyphens")
                notes["many_hyphens"] = f"{hostname} has {hyphens} hyphens"
            keywords = [k for k in HOSTNAME_KEYWORDS if k in hostname]
            if keywords:
                flags.append("hostname_keywords")
                notes["hostname_keywords"] = ", ".join(keywords)
            if labels[-1] in SUSPICIOUS_TLDS:
                flags.append("suspicious_tld")
                notes["suspicious_tld"] = f".{labels[-1]}"
            if any(hostname == d or hostname.endswith("." + d) for d in URL_SHORTENERS):
                flags.append("url_shortener")
                notes["url_shortener"] = hostname

    # Path and query
    if parts is not None and scheme not in DANGEROUS_SCHEMES:
        pq = (parts.path or "") + (("?" + parts.query) if parts.query else "")
        escapes = len(_PERCENT_RE.findall(pq))
        if (escapes >= HEAVY_ENCODING_MIN_ESCAPES
                and escapes * 3 / len(pq) > HEAVY_ENCODING_RATIO):
            flags.append("heavy_percent_encoding")
            notes["heavy_percent_encoding"] = f"{escapes} escape sequences in {len(pq)} characters"
        embedded = _EMBEDDED_URL_RE.search(unquote(pq))
        if embedded:
            dest = embedded.group(1).rpartition("@")[2].split(":")[0].lower()
            if dest and dest != hostname:
                flags.append("embedded_url_in_parameters")
                notes["embedded_url_in_parameters"] = f"embeds a link to {dest}"

    if embedded_control:
        flags.append("embedded_control_characters")

    url = raw
    if len(url) > MAX_URL_CHARS:
        url = url[:MAX_URL_CHARS]
    return {
        "url": url, "scheme": scheme, "hostname": hostname,
        "path": path, "query": query, "flags": flags, "notes": notes,
    }


# --------------------------------------------------------------------------
# HTML extraction
# --------------------------------------------------------------------------

def _prepare_attr_url(value: str) -> Optional[Tuple[str, bool]]:
    """
    Clean an HTML attribute value. Returns (url, had_embedded_control_chars)
    or None if the value is not an absolute URL worth recording.
    """
    embedded = bool(re.search(r"[\t\r\n]", value.strip()))
    cleaned = re.sub(r"[\t\r\n]", "", value).strip()
    if not cleaned or cleaned.startswith("#"):
        return None
    match = _SCHEME_RE.match(cleaned)
    if match:
        scheme = match.group(1).lower()
        if scheme in IGNORED_SCHEMES:
            return None
        if cleaned[match.end():].startswith("//") or scheme in DANGEROUS_SCHEMES:
            return cleaned, embedded
        return None
    if cleaned.startswith("//") and len(cleaned) > 2:
        return cleaned, embedded
    return None


class _HtmlLinkParser(HTMLParser):
    """Collects URL attributes, anchor text and visible text. Renders nothing."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.attr_urls: List[Dict[str, Any]] = []
        self.text_chunks: List[str] = []
        self._anchor: Optional[Dict[str, Any]] = None

    def _add_attr(self, tag: str, name: str, value: str, context: Optional[str] = None):
        prepared = _prepare_attr_url(value)
        if prepared is None:
            return None
        url, embedded = prepared
        if name in ("src", "poster", "background") and url.lower().startswith("data:image/"):
            return None                      # inline images are routine, skip them
        item = {
            "url": url, "context": context or f"{tag}[{name}]",
            "embedded_control": embedded, "link_text": None,
        }
        self.attr_urls.append(item)
        return item

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        attr_map = {n.lower(): v for n, v in attrs if v is not None}
        anchor_item = None
        for name, value in attr_map.items():
            if name in URL_ATTRS:
                item = self._add_attr(tag, name, value)
                if item is not None and tag == "a" and name == "href":
                    anchor_item = item
            elif name == "style":
                for css in _CSS_URL_RE.finditer(value):
                    self._add_attr(tag, "style", css.group(1))
        if tag == "meta" and attr_map.get("http-equiv", "").lower() == "refresh":
            refresh = _META_URL_RE.search(attr_map.get("content", ""))
            if refresh:
                self._add_attr(tag, "content", refresh.group(1).strip(), "meta[refresh]")
        if tag == "a":
            self.finish()
            self._anchor = {"item": anchor_item, "text": []}

    def handle_endtag(self, tag):
        if tag.lower() == "a":
            self.finish()

    def handle_data(self, data):
        self.text_chunks.append(data)
        if self._anchor is not None:
            self._anchor["text"].append(data)

    def finish(self) -> None:
        anchor, self._anchor = self._anchor, None
        if anchor and anchor["item"] is not None:
            text = " ".join(" ".join(anchor["text"]).split())
            if text:
                anchor["item"]["link_text"] = text[:MAX_LINK_TEXT_CHARS]


# --------------------------------------------------------------------------
# Collection and indicators
# --------------------------------------------------------------------------

class _UrlCollector:
    def __init__(self) -> None:
        self.records: Dict[str, Dict[str, Any]] = {}
        self.notes: Dict[Tuple[str, str], str] = {}
        self.dropped = 0

    def add(self, raw: str, source: str, context: str,
            link_text: Optional[str] = None, embedded_control: bool = False) -> Optional[str]:
        raw = raw.strip()
        if not raw:
            return None
        record = self.records.get(raw)
        if record is None:
            if len(self.records) >= MAX_URLS:
                self.dropped += 1
                return None
            fields = _analyze_url(raw, embedded_control)
            record = make_url_record(
                url=fields["url"], scheme=fields["scheme"], hostname=fields["hostname"],
                path=fields["path"], query=fields["query"], source=source,
                flags=fields["flags"], sources=[source], contexts=[context],
                link_text=link_text,
            )
            self.records[raw] = record
            for flag, note in fields["notes"].items():
                self.notes[(raw, flag)] = note
        else:
            if source not in record["sources"]:
                record["sources"].append(source)
            if context not in record["contexts"] and len(record["contexts"]) < MAX_CONTEXTS:
                record["contexts"].append(context)
            if link_text and not record["link_text"]:
                record["link_text"] = link_text
            if embedded_control and "embedded_control_characters" not in record["flags"]:
                record["flags"].append("embedded_control_characters")
        return raw

    def flag(self, raw: str, flag: str, note: str) -> None:
        record = self.records[raw]
        if flag not in record["flags"]:
            record["flags"].append(flag)
        self.notes.setdefault((raw, flag), note)


def _build_indicators(collector: _UrlCollector) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for flag, title, severity, explanation in FLAG_RULES:
        matches = [(raw, rec) for raw, rec in collector.records.items() if flag in rec["flags"]]
        if not matches:
            continue
        shown = []
        for raw, rec in matches[:EVIDENCE_URL_LIMIT]:
            entry = _shorten(rec["url"])
            note = collector.notes.get((raw, flag))
            if note:
                entry += f" [{note}]"
            shown.append(entry)
        evidence = f"{len(matches)} URL(s): " + "; ".join(shown)
        if len(matches) > len(shown):
            evidence += f"; and {len(matches) - len(shown)} more"
        out.append(make_indicator(title, severity, f"{evidence}. {explanation}", "url"))
    return out


def _warn(result: Dict[str, Any], message: str) -> None:
    warnings = result["headers"]["meta"]["warnings"]
    if message not in warnings:
        warnings.append(message)


def _limit(text: str, result: Dict[str, Any], label: str) -> str:
    if len(text) > MAX_BODY_CHARS:
        _warn(result, f"{label} cut to {MAX_BODY_CHARS} characters for URL extraction")
        return text[:MAX_BODY_CHARS]
    return text


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------

def analyze_urls(parsed: ParsedEmail, result: Dict[str, Any]) -> None:
    """Extract URLs from plain-text and HTML bodies and flag static indicators."""
    collector = _UrlCollector()

    for body in parsed.plain_bodies:
        for url in extract_urls_from_text(_limit(body, result, "Plain text body")):
            collector.add(url, "text/plain", "text")

    for body in parsed.html_bodies:
        html = _limit(body, result, "HTML body")
        link_parser = _HtmlLinkParser()
        try:
            link_parser.feed(html)
            link_parser.close()
        except Exception as exc:
            _warn(result, f"HTML body could not be fully parsed: {type(exc).__name__}")
        link_parser.finish()

        for item in link_parser.attr_urls:
            key = collector.add(
                item["url"], "text/html", item["context"],
                item["link_text"], item["embedded_control"],
            )
            if key is None or item["context"] != "a[href]" or not item["link_text"]:
                continue
            shown_host = _host_shown_in_text(item["link_text"])
            target_host = collector.records[key]["hostname"]
            if shown_host and target_host and not _same_or_subdomain(shown_host, target_host):
                collector.flag(
                    key, "link_text_mismatch",
                    f"link text shows {shown_host}, link goes to {target_host}",
                )

        visible = "\n".join(link_parser.text_chunks)
        for url in extract_urls_from_text(visible):
            collector.add(url, "text/html", "text")

    if collector.dropped:
        _warn(result, f"URL list capped at {MAX_URLS}; {collector.dropped} more unique URLs ignored")

    result["urls"] = list(collector.records.values())
    result["risk_indicators"].extend(_build_indicators(collector))