"""
Domain analysis for the EmailTrace forensics engine.

analyze_domains(result) -> fills result["domains"] and adds domain indicators

Domains are collected from the From, Reply-To and Return-Path addresses and
from the hostnames of extracted URLs. URL hosts that are IP addresses are not
domains and are left to the IP and IOC steps.

Principles:
- Purely offline. No DNS, WHOIS or reachability checks are performed.
- Two domains are "related" when they are equal or one is a subdomain of the
  other. Without the Public Suffix List, unrelated sites under a shared suffix
  such as co.uk are compared as different domains, which is the safe direction.
- A mismatch is something to investigate, not proof of wrongdoing. Mailing
  lists, support desks and marketing platforms all cause legitimate mismatches.
"""

import re
from typing import Any, Dict, List, Optional

from .schema import make_domain_record, make_indicator

# Public webmail providers. Used only to add context to a Reply-To mismatch.
FREE_MAIL_DOMAINS = frozenset({
    "gmail.com", "googlemail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "live.com", "msn.com", "aol.com", "icloud.com", "me.com", "proton.me",
    "protonmail.com", "gmx.com", "gmx.net", "mail.com", "yandex.com", "zoho.com",
})

_BAD_LABEL_CHARS = set(" \t<>()[]{},;:\"\\/@!#$%^&*=+|`~?'")

_DISPLAY_EMAIL_RE = re.compile(
    r"[A-Za-z0-9._%+\-]+@([A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+)"
)
_DISPLAY_HOST_RE = re.compile(
    r"(?i)(?:https?://|www\.)([a-z0-9\-]+(?:\.[a-z0-9\-]+)+)"
)


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def is_valid_domain(domain: Optional[str]) -> bool:
    """Structural check only: label lengths and forbidden characters."""
    if not domain or len(domain) > 253:
        return False
    for label in domain.split("."):
        if not label or len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        if any(c in _BAD_LABEL_CHARS or c.isspace() for c in label):
            return False
    return True


def _related(a: str, b: str) -> bool:
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def _is_idn(domain: str) -> bool:
    return any(label.startswith("xn--") for label in domain.split(".")) or any(
        ord(c) > 127 for c in domain
    )


def _decode_idn(domain: str) -> str:
    try:
        return domain.encode("ascii").decode("idna")
    except Exception:
        return domain


def _display_name_domains(name: str) -> List[str]:
    found: List[str] = []
    for regex in (_DISPLAY_EMAIL_RE, _DISPLAY_HOST_RE):
        for match in regex.finditer(name):
            domain = match.group(1).lower()
            if domain not in found:
                found.append(domain)
    return found


def _usable_domain(record: Optional[Dict[str, Any]]) -> Optional[str]:
    if not record:
        return None
    domain = record.get("domain")
    return domain if is_valid_domain(domain) else None


# --------------------------------------------------------------------------
# Indicators
# --------------------------------------------------------------------------

def _build_indicators(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    sender = result["sender"]
    from_rec = sender.get("from")
    reply_to = sender.get("reply_to") or []
    return_path = sender.get("return_path")
    from_domain = _usable_domain(from_rec)

    if from_rec and from_domain is None:
        out.append(make_indicator(
            "From address has no usable domain",
            "low",
            f"The From value {from_rec.get('raw')!r} does not contain a valid "
            "address domain, so sender domain comparisons could not be made.",
            "header",
        ))

    if from_domain:
        differing = [r for r in reply_to
                     if _usable_domain(r) and not _related(r["domain"], from_domain)]
        if differing:
            listed = "; ".join(f"{r['address']} (domain {r['domain']})" for r in differing)
            evidence = (
                f"From domain: {from_domain} ({from_rec['address']}). Reply-To address(es) "
                f"on a different domain: {listed}. Replies would go to a different "
                "domain than the one displayed."
            )
            webmail = sorted({r["domain"] for r in differing if r["domain"] in FREE_MAIL_DOMAINS})
            if webmail:
                evidence += f" {', '.join(webmail)} is a public webmail provider."
            evidence += (" Mailing lists, support desks and marketing platforms also "
                         "cause this, so confirm who controls the Reply-To address.")
            out.append(make_indicator(
                "Reply-To domain differs from sender domain", "medium", evidence, "header",
            ))

        rp_domain = _usable_domain(return_path)
        if rp_domain and not _related(rp_domain, from_domain):
            out.append(make_indicator(
                "Return-Path domain differs from sender domain",
                "low",
                f"From domain: {from_domain}. Return-Path domain: {rp_domain} "
                f"({return_path['address']}). Bounce addresses often use a mail "
                "provider's own domain, so this is common in bulk and marketing mail.",
                "header",
            ))

        name = (from_rec.get("display_name") or "")
        shown = _display_name_domains(name)
        mismatched = [d for d in shown if not _related(d, from_domain)]
        if mismatched:
            out.append(make_indicator(
                "Display name shows a different domain than the sender address",
                "medium",
                f"Display name {name!r} contains {', '.join(mismatched)}, but the "
                f"sending address is on {from_domain}. Shared mailboxes and "
                "forwarded messages sometimes put a contact address in the display name.",
                "header",
            ))

    idn: List[str] = []
    roles = [("from", from_rec)] + [("reply_to", r) for r in reply_to] + [("return_path", return_path)]
    for role, rec in roles:
        domain = _usable_domain(rec)
        if domain and _is_idn(domain):
            decoded = _decode_idn(domain)
            idn.append(f"{role}: {domain}" + (f" ({decoded})" if decoded != domain else ""))
    if idn:
        out.append(make_indicator(
            "Address domain uses punycode or non-ASCII characters",
            "low",
            "; ".join(idn) + ". Internationalized domains are legitimate, but they "
            "can imitate well-known domains with lookalike characters.",
            "domain",
        ))
    return out


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------

def analyze_domains(result: Dict[str, Any]) -> None:
    """Collect domains from addresses and URLs, and compare sender-side domains."""
    sender = result["sender"]
    collected: Dict[str, Dict[str, Any]] = {}

    def add(domain: Optional[str], source: str) -> None:
        if not domain:
            return
        domain = domain.strip().lower().rstrip(".")
        if not is_valid_domain(domain):
            return
        entry = collected.setdefault(domain, {"sources": [], "url_count": 0})
        if source not in entry["sources"]:
            entry["sources"].append(source)
        if source == "url":
            entry["url_count"] += 1

    if sender.get("from"):
        add(sender["from"].get("domain"), "from")
    for record in sender.get("reply_to") or []:
        add(record.get("domain"), "reply_to")
    if sender.get("return_path"):
        add(sender["return_path"].get("domain"), "return_path")
    for url in result["urls"]:
        if "ip_based" not in url["flags"]:
            add(url.get("hostname"), "url")

    result["domains"] = [
        make_domain_record(domain, info["sources"], info["url_count"])
        for domain, info in collected.items()
    ]
    result["risk_indicators"].extend(_build_indicators(result))