"""
Header analysis for the EmailTrace forensics engine.

analyze_headers(parsed, result) fills headers.authentication and appends
evidence-based indicators to result["risk_indicators"].

Principles:
- We report what the receiving server RECORDED. We do not re-run SPF, DKIM
  or DMARC and we make no DNS lookups.
- Only the topmost Authentication-Results header feeds the summary.
- Indicators describe evidence worth investigating. They are not verdicts.
"""

import re
from typing import Any, Dict, List, Optional

from .email_parser import ParsedEmail
from .schema import make_indicator

_COMMENT_RE = re.compile(r"\([^)]*\)")
_METHOD_RE = re.compile(r"(?<![\w.\-])(spf|dkim|dmarc)\s*=\s*([A-Za-z]+)", re.I)
_MAILFROM_RE = re.compile(r"smtp\.mailfrom\s*=\s*([^\s;]+)", re.I)
_HEADER_D_RE = re.compile(r"header\.d\s*=\s*([^\s;]+)", re.I)
_HEADER_FROM_RE = re.compile(r"header\.from\s*=\s*([^\s;]+)", re.I)
_RECEIVED_SPF_RE = re.compile(
    r"^\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b", re.I
)
_ENVELOPE_FROM_RE = re.compile(r"envelope-from\s*=\s*\"?<?([^\s;>\"]+)", re.I)

# Severity for each non-"pass" result. A pass produces no indicator.
SPF_SEVERITY = {
    "fail": "medium", "softfail": "low", "neutral": "low",
    "none": "low", "permerror": "low", "temperror": "low",
}
DKIM_SEVERITY = {
    "fail": "medium", "none": "low", "neutral": "low",
    "policy": "low", "permerror": "low", "temperror": "low",
}
DMARC_SEVERITY = {
    "fail": "medium", "none": "info", "permerror": "low", "temperror": "low",
}

# Transparent list. These tools are used by legitimate and abusive senders alike.
MAILER_TOKENS = (
    "phpmailer", "swiftmailer", "mass mailer", "massmailer",
    "sendblaster", "atomic mail",
)


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _values(parsed: ParsedEmail, name: str) -> List[str]:
    wanted = name.lower()
    return [v for n, v in parsed.header_items if n.lower() == wanted]


def _domain_of(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    v = value.strip().strip("<>\"'").lower()
    d = v.rpartition("@")[2] if "@" in v else v
    d = d.strip(".;, ")
    return d or None


def _group(pattern: "re.Pattern[str]", text: str) -> Optional[str]:
    m = pattern.search(text)
    return m.group(1) if m else None


def _related(a: str, b: str) -> bool:
    """Same domain, or one is a subdomain of the other (relaxed alignment)."""
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def parse_authentication_results(value: str) -> Dict[str, Any]:
    """
    Parse one Authentication-Results header value.

    Returns {"authserv_id": str|None, "spf": [...], "dkim": [...], "dmarc": [...]}
    where each list entry is {"result": str, "domain": str|None}.
    """
    cleaned = _COMMENT_RE.sub(" ", value)
    out: Dict[str, Any] = {"authserv_id": None, "spf": [], "dkim": [], "dmarc": []}

    for i, segment in enumerate(cleaned.split(";")):
        match = _METHOD_RE.search(segment)
        if not match:
            if i == 0 and segment.strip():
                out["authserv_id"] = segment.split()[0]
            continue
        method, verdict = match.group(1).lower(), match.group(2).lower()
        if method == "spf":
            domain = _domain_of(_group(_MAILFROM_RE, segment))
        elif method == "dkim":
            domain = _domain_of(_group(_HEADER_D_RE, segment))
        else:
            domain = _domain_of(_group(_HEADER_FROM_RE, segment))
        out[method].append({"result": verdict, "domain": domain})
    return out


# --------------------------------------------------------------------------
# Authentication
# --------------------------------------------------------------------------

def _fill_authentication(parsed: ParsedEmail, auth: Dict[str, Any]) -> List[Optional[str]]:
    """Populate the authentication block. Returns the authserv-ids seen."""
    details = auth["details"]
    ar_values = _values(parsed, "Authentication-Results")
    auth["authentication_results_raw"] = [" ".join(v.split()) for v in ar_values]

    authserv_ids: List[Optional[str]] = []
    for i, value in enumerate(ar_values):
        info = parse_authentication_results(value)
        authserv_ids.append(info["authserv_id"])
        if i > 0:
            continue                      # only the topmost header feeds the summary
        details["authserv_id"] = info["authserv_id"]
        if info["spf"]:
            auth["spf"] = info["spf"][0]["result"]
            details["spf_mailfrom_domain"] = info["spf"][0]["domain"]
        if info["dkim"]:
            results = [e["result"] for e in info["dkim"]]
            auth["dkim"] = "pass" if "pass" in results else results[0]
            details["dkim_results"] = info["dkim"]
        if info["dmarc"]:
            auth["dmarc"] = info["dmarc"][0]["result"]
            details["dmarc_header_from_domain"] = info["dmarc"][0]["domain"]

    received_spf = _values(parsed, "Received-SPF")
    if received_spf:
        auth["received_spf_raw"] = " ".join(received_spf[0].split())
        if auth["spf"] is None:
            match = _RECEIVED_SPF_RE.match(received_spf[0])
            if match:
                auth["spf"] = match.group(1).lower()
                if details["spf_mailfrom_domain"] is None:
                    cleaned = _COMMENT_RE.sub(" ", received_spf[0])
                    details["spf_mailfrom_domain"] = _domain_of(
                        _group(_ENVELOPE_FROM_RE, cleaned)
                    )
    return authserv_ids


def _authentication_indicators(
    auth: Dict[str, Any],
    from_domain: Optional[str],
    authserv_ids: List[Optional[str]],
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    details = auth["details"]
    where = f"authserv-id {details['authserv_id']}" if details["authserv_id"] else "receiving server"

    if not auth["authentication_results_raw"] and auth["received_spf_raw"] is None:
        out.append(make_indicator(
            "No authentication results headers present",
            "info",
            "Neither Authentication-Results nor Received-SPF was found. The message may "
            "have been exported without them, or authentication was not recorded.",
            "authentication",
        ))
        return out

    spf, dkim, dmarc = auth["spf"], auth["dkim"], auth["dmarc"]

    if spf in SPF_SEVERITY:
        out.append(make_indicator(
            f"SPF result: {spf}",
            SPF_SEVERITY[spf],
            f"Recorded by {where}: spf={spf}; envelope sender domain: "
            f"{details['spf_mailfrom_domain'] or 'not recorded'}.",
            "authentication",
        ))
    if dkim in DKIM_SEVERITY:
        domains = [e["domain"] for e in details["dkim_results"] if e["domain"]]
        out.append(make_indicator(
            f"DKIM result: {dkim}",
            DKIM_SEVERITY[dkim],
            f"Recorded by {where}: dkim={dkim}; signing domain(s): "
            f"{', '.join(domains) or 'not recorded'}.",
            "authentication",
        ))
    if dmarc in DMARC_SEVERITY:
        out.append(make_indicator(
            f"DMARC result: {dmarc}",
            DMARC_SEVERITY[dmarc],
            f"Recorded by {where}: dmarc={dmarc}; header.from domain: "
            f"{details['dmarc_header_from_domain'] or 'not recorded'}.",
            "authentication",
        ))

    if spf == dkim == dmarc == "fail":
        out.append(make_indicator(
            "SPF, DKIM and DMARC all reported fail",
            "high",
            f"All three results were recorded as fail by {where}.",
            "authentication",
        ))

    # Alignment: authenticated domain vs visible From domain
    mailfrom = details["spf_mailfrom_domain"]
    if spf == "pass" and mailfrom and from_domain and not _related(mailfrom, from_domain):
        out.append(make_indicator(
            "SPF-authenticated domain differs from From domain",
            "low",
            f"SPF passed for {mailfrom}, but the visible From domain is {from_domain}.",
            "authentication",
        ))
    passed = [e["domain"] for e in details["dkim_results"]
              if e["result"] == "pass" and e["domain"]]
    if passed and from_domain and not any(_related(d, from_domain) for d in passed):
        out.append(make_indicator(
            "DKIM-signing domain differs from From domain",
            "low",
            f"DKIM passed for {', '.join(passed)}, but the visible From domain is {from_domain}.",
            "authentication",
        ))

    if len(authserv_ids) > 1:
        ids = ", ".join(i or "unknown" for i in authserv_ids)
        out.append(make_indicator(
            "Multiple Authentication-Results headers present",
            "low",
            f"{len(authserv_ids)} headers found (authserv-ids: {ids}). Only the topmost "
            "was used. Headers added by the sender's side can be forged, so confirm "
            "which one your own receiving server added.",
            "authentication",
        ))
    return out


# --------------------------------------------------------------------------
# Structure, mailer and MIME checks
# --------------------------------------------------------------------------

def _structure_indicators(parsed: ParsedEmail, result: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []

    for name, severity in (("From", "medium"), ("Message-ID", "low"), ("Date", "low")):
        count = len(_values(parsed, name))
        if count > 1:
            out.append(make_indicator(
                f"Multiple {name} headers",
                severity,
                f"{count} {name} headers found. Mail clients normally show only one, "
                "which can hide the others.",
                "header",
            ))
    for name in ("From", "Message-ID"):
        if not _values(parsed, name):
            out.append(make_indicator(
                f"Missing {name} header", "low",
                f"No {name} header was found in the message.", "header",
            ))

    mime = result["headers"]["mime"]
    if (mime["content_type"] or "").startswith("multipart/") and not mime["mime_version"]:
        out.append(make_indicator(
            "Multipart message without MIME-Version header", "low",
            f"Content-Type is {mime['content_type']} but no MIME-Version header exists.",
            "header",
        ))

    defects = sorted({w for w in parsed.warnings if w.startswith("MIME defect:")})
    if defects:
        out.append(make_indicator(
            "MIME structure defects reported by the parser", "info",
            "; ".join(defects), "header",
        ))

    headers = result["headers"]
    for label, value in (("X-Mailer", headers["x_mailer"]), ("User-Agent", headers["user_agent"])):
        if value and any(tok in value.lower() for tok in MAILER_TOKENS):
            out.append(make_indicator(
                f"{label} identifies a scripted or bulk mailing library",
                "info",
                f"{label}: {value}. Legitimate and abusive senders both use such tools, "
                "so this is context only.",
                "header",
            ))
    return out


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------

def analyze_headers(parsed: ParsedEmail, result: Dict[str, Any]) -> None:
    """Fill authentication fields and append header-related indicators."""
    auth = result["headers"]["authentication"]
    from_record = result["sender"]["from"]
    from_domain = from_record["domain"] if from_record else None

    authserv_ids = _fill_authentication(parsed, auth)
    result["risk_indicators"].extend(
        _authentication_indicators(auth, from_domain, authserv_ids)
    )
    result["risk_indicators"].extend(_structure_indicators(parsed, result))