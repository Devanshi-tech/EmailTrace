"""
Content analysis for the EmailTrace forensics engine.

analyze_content(parsed, result) -> fills result["content_analysis"] and adds
                                   content indicators

How it works:
- The subject and the body text are checked against the fixed rule table
  below. Every rule has a readable name, a category and a regular expression.
  There is no scoring model and no hidden weighting.
- Each hit records the rule, category, matched text, location and a short
  context, so an investigator can see exactly why it fired.
- Word lists are heuristics. Legitimate mail uses all of this wording too,
  so indicators describe wording that deserves a second look. They do not
  say what the sender intended.
- HTML is read with the standard-library HTMLParser and reduced to visible
  text. Nothing is rendered, and no link is opened.
"""

import re
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Set, Tuple

from .email_parser import ParsedEmail
from .schema import make_content_match, make_indicator

MAX_TEXT_CHARS = 200_000        # per body part scanned
MAX_MATCHES_PER_RULE = 3        # per rule and location
MAX_TOTAL_MATCHES = 100
CONTEXT_CHARS = 40
MATCH_TEXT_CHARS = 100
GREETING_WINDOW = 160
INVISIBLE_CHAR_THRESHOLD = 3
SHOUTING_MIN_LETTERS = 8
SHOUTING_RATIO = 0.7
EVIDENCE_MATCH_LIMIT = 4
EVIDENCE_URL_LIMIT = 3

_URL_TOKEN_RE = re.compile(r"(?:[a-z][a-z0-9+.\-]{1,15}://|www\.)\S+", re.IGNORECASE)
_ZERO_WIDTH = "\u200b\u200c\u200d\u2060\ufeff\u00ad"
_NORMALIZE_MAP = {ord(c): None for c in _ZERO_WIDTH}
_NORMALIZE_MAP.update({
    0x2019: "'", 0x2018: "'", 0x201C: '"', 0x201D: '"', 0x00A0: " ",
})

# (rule name, category, regular expression, scope). Scope "start" means the
# rule only looks at the first GREETING_WINDOW characters of the text.
_RULE_DEFINITIONS = [
    # --- urgency ---
    ("urgent_wording", "urgency",
     r"\b(?:urgent(?:ly)?|immediate(?:ly)?|asap|as soon as possible|right away)\b", "any"),
    ("deadline_phrase", "urgency",
     r"\b(?:within|in the next)\s+(?:\d{1,3}|one|two|three|twenty[- ]four|forty[- ]eight)"
     r"\s*(?:hours?|hrs?|days?|minutes?)\b", "any"),
    ("time_pressure_phrase", "urgency",
     r"\b(?:act now|action required|immediate action|final (?:notice|warning|reminder)|"
     r"last (?:chance|warning)|expires? (?:today|tonight|soon)|time[- ]sensitive|"
     r"respond (?:today|now)|don't delay|before it's too late)\b", "any"),
    # --- threats ---
    ("account_suspension_threat", "threat",
     r"\b(?:account|access|mailbox|card|profile)\b[^.!?]{0,40}"
     r"\b(?:will be|has been|have been|is being|was)\s+"
     r"(?:suspended|locked|limited|disabled|closed|terminated|deactivated|restricted|"
     r"blocked|deleted)\b", "any"),
    ("suspicious_activity_claim", "threat",
     r"\b(?:unusual|suspicious|unauthori[sz]ed|unrecogni[sz]ed)\s+"
     r"(?:sign[- ]?in|log[- ]?in|activity|access|transaction|attempt)s?\b", "any"),
    ("legal_or_penalty_threat", "threat",
     r"\b(?:legal action|face charges|penalt(?:y|ies)|permanently (?:deleted|closed|disabled)|"
     r"will be reported)\b", "any"),
    # --- credential requests ---
    ("verify_account_request", "credential_request",
     r"\b(?:verify|confirm|validate|re-?activate|update|restore|unlock|secure)\s+"
     r"(?:your|the)\s+(?:account|identity|profile|mailbox|email account|login|credentials?|"
     r"password|billing|payment|banking|security)(?:\s+(?:details|information|info))?\b", "any"),
    ("credential_entry_request", "credential_request",
     r"\b(?:enter|provide|send|submit|share|reply with)\s+(?:us\s+)?your\s+"
     r"(?:password|username|pin|passcode|credentials?|login (?:details|information)|"
     r"security (?:code|answers?)|(?:one[- ]time|verification|authentication)\s+(?:code|password)|"
     r"otp|social security number|ssn|card number|cvv)\b", "any"),
    ("sign_in_prompt", "credential_request",
     r"\b(?:sign|log)[- ]?in\s+(?:here|below|now|to\s+(?:verify|confirm|review|restore|"
     r"unlock|secure|avoid))\b", "any"),
    # --- payment requests ---
    ("payment_demand", "payment_request",
     r"\b(?:pay(?:ment)?\s+(?:now|immediately|today|is overdue|overdue|due)|"
     r"overdue\s+(?:invoice|payment|balance)|unpaid\s+(?:invoice|balance|bill)|"
     r"outstanding\s+(?:invoice|balance|payment))\b", "any"),
    ("transfer_request", "payment_request",
     r"\b(?:wire|bank)\s+transfer\b|\bmake\s+a\s+(?:payment|transfer)\b|"
     r"\bsend\s+(?:the\s+)?(?:money|funds|payment)\b|\btransfer\s+(?:the\s+)?(?:funds|money|amount)\b",
     "any"),
    ("gift_card_or_crypto", "payment_request",
     r"\bgift\s+cards?\b|\bbitcoin\b|\bcrypto(?:currency)?\b|\bitunes\s+cards?\b", "any"),
    ("bank_details_change", "payment_request",
     r"\b(?:change|update|new)\s+(?:of\s+)?(?:our\s+|my\s+|the\s+)?(?:bank(?:ing)?|payment|account)"
     r"\s+(?:details|information|instructions)\b|\brouting\s+number\b", "any"),
    # --- impersonation language ---
    ("internal_team_claim", "impersonation",
     r"\b(?:it|technical|security|support|help|service|billing|payroll|accounts?|hr|compliance)"
     r"\s+(?:department|team|desk|administrator|staff)\b|\bhelp\s*desk\b|\bsystem\s+administrator\b",
     "any"),
    ("executive_reference", "impersonation",
     r"\b(?:ceo|cfo|chief executive|managing director|your manager|your supervisor)\b", "any"),
    # --- other wording ---
    ("generic_greeting", "generic_greeting",
     r"^(?:dear|hello|hi|greetings)[, ]+(?:valued\s+)?(?:customer|user|client|member|"
     r"account\s+holder|sir(?:\s*/\s*|\s+or\s+)madam|madam(?:\s*/\s*|\s+or\s+)sir|beneficiary|"
     r"friend|email\s+owner|webmail\s+user)\b", "start"),
    ("prize_or_windfall", "lure",
     r"\b(?:you(?:'ve| have)? (?:won|been selected)|lottery|prize|inheritance|unclaimed funds|"
     r"claim your (?:reward|prize|gift|refund)|tax refund)\b", "any"),
    ("enable_content_request", "macro_request",
     r"\benable\s+(?:the\s+)?(?:macros?|content|editing)\b", "any"),
    ("attachment_instruction", "attachment_instruction",
     r"\b(?:open|see|view|check|review)\s+(?:the\s+)?attach(?:ed|ment)\b|"
     r"\bpassword\s+(?:for|to open)\s+(?:the\s+)?(?:attachment|file|archive|document)\b|"
     r"\bthe\s+password\s+is\b", "any"),
    ("click_prompt", "link_lure",
     r"\bclick\s+(?:here|the\s+(?:link|button)|below|on\s+the\s+link)\b|"
     r"\bfollow\s+(?:this|the)\s+link\b|\btap\s+(?:here|the\s+link)\b", "any"),
]
RULES = [
    (name, category, re.compile(pattern, re.IGNORECASE), scope)
    for name, category, pattern, scope in _RULE_DEFINITIONS
]

# category -> (indicator title, severity, explanation). Order = indicator order.
CATEGORY_INFO: Dict[str, Tuple[str, str, str]] = {
    "urgency": (
        "Urgent or time-pressure wording", "low",
        "Legitimate notices also use urgent wording. Pressure to act quickly is one "
        "of several signals that deserve a second look before acting."),
    "threat": (
        "Account-threat or penalty wording", "low",
        "Genuine security and billing notices use similar wording, so check the "
        "claim by opening the service directly rather than through the message."),
    "credential_request": (
        "Request to verify, confirm or enter account credentials", "medium",
        "Legitimate services rarely ask for passwords or codes by email, although "
        "genuine notices sometimes prompt a sign-in. Verify through the service's own site."),
    "payment_request": (
        "Payment or funds-transfer wording", "medium",
        "Real invoices use this wording too. Confirm payment details through a "
        "separate, known channel before sending money."),
    "impersonation": (
        "Wording that claims an internal or official role", "low",
        "Such wording is normal in workplace mail. It matters when the sender "
        "cannot be tied to that role."),
    "generic_greeting": (
        "Generic greeting instead of a name", "info",
        "Bulk mail and impersonation attempts both use generic greetings."),
    "lure": (
        "Prize or windfall wording", "low",
        "Promotions use this wording legitimately, and so do unsolicited offers."),
    "macro_request": (
        "Request to enable macros, content or editing", "medium",
        "Some documents need editing enabled, but macros can run code, so the "
        "request deserves care."),
    "attachment_instruction": (
        "Instruction to open an attachment or use a password", "info",
        "Ordinary workplace mail says this constantly. It is context for the "
        "attachment findings."),
    "link_lure": (
        "Prompt to click a link", "info",
        "Newsletters and notifications use this wording routinely. It is context "
        "for the URL findings."),
}

PRESSURE_CATEGORIES = {"urgency", "threat"}
REQUEST_CATEGORIES = {"credential_request", "payment_request"}
ACTION_CATEGORIES = {"urgency", "threat", "credential_request", "payment_request", "macro_request"}
LINK_WARNING_FLAGS = {
    "ip_based", "obfuscated_ip_host", "url_shortener", "link_text_mismatch",
    "userinfo_in_url", "encoded_hostname", "dangerous_scheme", "suspicious_tld", "idn_hostname",
}

# brand -> registered names (second-level labels) that count as the brand's own domains
BRAND_DOMAINS: Dict[str, Set[str]] = {
    "paypal": {"paypal"},
    "microsoft": {"microsoft", "microsoftonline", "office", "office365", "live", "outlook",
                  "windows", "xbox", "msn"},
    "apple": {"apple", "icloud"},
    "amazon": {"amazon"},
    "google": {"google", "gmail", "googlemail", "youtube"},
    "netflix": {"netflix"},
    "dhl": {"dhl"},
    "fedex": {"fedex"},
    "ups": {"ups"},
    "docusign": {"docusign"},
    "dropbox": {"dropbox", "dropboxmail"},
    "linkedin": {"linkedin"},
    "facebook": {"facebook", "facebookmail", "fb", "meta"},
    "adobe": {"adobe"},
    "wells fargo": {"wellsfargo"},
    "bank of america": {"bankofamerica", "bofa"},
    "chase": {"chase", "jpmorgan", "jpmorganchase"},
}
_BRAND_PATTERNS = {
    brand: re.compile(r"\b" + r"\s+".join(map(re.escape, brand.split())) + r"\b", re.IGNORECASE)
    for brand in BRAND_DOMAINS
}
_SECOND_LEVEL_LABELS = {"co", "com", "org", "net", "gov", "ac", "edu", "or", "ne"}


# --------------------------------------------------------------------------
# Text preparation
# --------------------------------------------------------------------------

class _VisibleTextParser(HTMLParser):
    """Reduces HTML to the text a reader would see. Renders and runs nothing."""

    SKIP = {"script", "style", "title", "template"}
    BLOCK = {"p", "br", "div", "tr", "li", "ul", "ol", "table", "blockquote", "hr",
             "h1", "h2", "h3", "h4", "h5", "h6"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.chunks: List[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag in self.SKIP:
            self._skip += 1
        elif tag in self.BLOCK:
            self.chunks.append("\n")

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag in self.SKIP:
            self._skip = max(0, self._skip - 1)
        elif tag in self.BLOCK:
            self.chunks.append("\n")

    def handle_data(self, data):
        if self._skip == 0:
            self.chunks.append(data)


def _normalize(text: str) -> str:
    """
    Prepare text for the wording rules: remove invisible characters, straighten
    quotes, replace URLs with a placeholder and collapse whitespace. URLs are
    not wording, and words inside a path (such as /login) must not trigger rules.
    """
    text = _URL_TOKEN_RE.sub(" [link] ", text.translate(_NORMALIZE_MAP))
    return " ".join(text.split())


def _count_invisible(text: str) -> int:
    return sum(text.count(c) for c in _ZERO_WIDTH)


def _html_to_text(html: str, warnings: List[str]) -> str:
    parser = _VisibleTextParser()
    try:
        parser.feed(html)
        parser.close()
    except Exception as exc:
        warnings.append(f"HTML body could not be fully read for content analysis: {type(exc).__name__}")
    return "".join(parser.chunks)


# --------------------------------------------------------------------------
# Rule matching
# --------------------------------------------------------------------------

def _context(text: str, start: int, end: int) -> str:
    left = max(0, start - CONTEXT_CHARS)
    right = min(len(text), end + CONTEXT_CHARS)
    return ("..." if left > 0 else "") + text[left:right] + ("..." if right < len(text) else "")


def _scan(text: str, location: str, seen: Set[Tuple[str, str]]) -> List[Dict[str, Any]]:
    found: List[Dict[str, Any]] = []
    if not text:
        return found
    for name, category, pattern, scope in RULES:
        window = text[:GREETING_WINDOW] if scope == "start" else text
        taken = 0
        for match in pattern.finditer(window):
            key = (name, match.group(0).lower())
            if key in seen:
                continue
            seen.add(key)
            found.append(make_content_match(
                rule=name,
                category=category,
                matched_text=match.group(0)[:MATCH_TEXT_CHARS],
                location=location,
                context=_context(text, match.start(), match.end()),
            ))
            taken += 1
            if taken >= MAX_MATCHES_PER_RULE:
                break
    return found


# --------------------------------------------------------------------------
# Indicators
# --------------------------------------------------------------------------

def _registered_label(domain: str) -> str:
    labels = domain.lower().split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _SECOND_LEVEL_LABELS:
        return labels[-3]
    return labels[-2] if len(labels) >= 2 else labels[0]


def _brand_mismatches(from_rec: Optional[Dict[str, Any]]) -> List[str]:
    if not from_rec or not from_rec.get("display_name") or not from_rec.get("domain"):
        return []
    label = _registered_label(from_rec["domain"])
    return [
        brand for brand, pattern in _BRAND_PATTERNS.items()
        if pattern.search(from_rec["display_name"]) and label not in BRAND_DOMAINS[brand]
    ]


def _subject_style_issues(subject: str) -> List[str]:
    issues: List[str] = []
    letters = [c for c in subject if c.isalpha()]
    if len(letters) >= SHOUTING_MIN_LETTERS and \
            sum(c.isupper() for c in letters) / len(letters) >= SHOUTING_RATIO:
        issues.append("mostly capital letters")
    if re.search(r"[!?]{3,}", subject):
        issues.append("repeated exclamation or question marks")
    return issues


def _describe_matches(matches: List[Dict[str, Any]]) -> str:
    shown = [f"{m['rule']}: '{m['matched_text']}' in {m['location']}"
             for m in matches[:EVIDENCE_MATCH_LIMIT]]
    if len(matches) > EVIDENCE_MATCH_LIMIT:
        shown.append(f"and {len(matches) - EVIDENCE_MATCH_LIMIT} more")
    return "; ".join(shown)


def _build_indicators(
    matches: List[Dict[str, Any]],
    result: Dict[str, Any],
    parsed: ParsedEmail,
    invisible_count: int,
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    by_category: Dict[str, List[Dict[str, Any]]] = {}
    for match in matches:
        by_category.setdefault(match["category"], []).append(match)
    present = set(by_category)

    for category, (title, severity, explanation) in CATEGORY_INFO.items():
        if category in by_category:
            group = by_category[category]
            out.append(make_indicator(
                title, severity,
                f"{len(group)} match(es): {_describe_matches(group)}. {explanation}",
                "content",
            ))

    pressure, asks = PRESSURE_CATEGORIES & present, REQUEST_CATEGORIES & present
    if pressure and asks:
        out.append(make_indicator(
            "Pressure wording appears together with a credential or payment request",
            "medium",
            f"Pressure categories: {', '.join(sorted(pressure))}. Request categories: "
            f"{', '.join(sorted(asks))}. Legitimate notices sometimes combine them, so "
            "judge the sender and the links separately.",
            "content",
        ))

    flagged = [u for u in result["urls"] if set(u["flags"]) & LINK_WARNING_FLAGS]
    action = ACTION_CATEGORIES & present
    if flagged and action:
        listed = "; ".join(
            f"{u['url'][:80]} [{', '.join(f for f in u['flags'] if f in LINK_WARNING_FLAGS)}]"
            for u in flagged[:EVIDENCE_URL_LIMIT]
        )
        out.append(make_indicator(
            "Action wording appears alongside links with static warning flags",
            "medium",
            f"Wording categories: {', '.join(sorted(action))}. Flagged links: {listed}. "
            "The links were not visited. See the URL findings for what each flag means.",
            "content",
        ))

    brands = _brand_mismatches(result["sender"].get("from"))
    if brands:
        from_rec = result["sender"]["from"]
        out.append(make_indicator(
            "Display name uses a well-known brand that the sender domain does not match",
            "medium",
            f"Display name {from_rec['display_name']!r} mentions {', '.join(brands)}, but the "
            f"sending domain is {from_rec['domain']}. Authorized third-party senders and "
            "agencies can also use a brand name, so confirm the relationship.",
            "content",
        ))

    subject = result["headers"].get("subject") or ""
    issues = _subject_style_issues(subject)
    if issues:
        out.append(make_indicator(
            "Subject uses shouting or heavy punctuation",
            "low",
            f"Subject {subject!r} has {' and '.join(issues)}. Marketing mail does this too.",
            "content",
        ))

    header_names = {name.lower() for name, _ in parsed.header_items}
    if re.match(r"\s*re\s*:", subject, re.IGNORECASE) and not (
        {"in-reply-to", "references"} & header_names
    ):
        out.append(make_indicator(
            "Subject implies a reply, but no reply headers are present",
            "low",
            f"Subject {subject!r} starts with 'Re:', yet the message has neither an "
            "In-Reply-To nor a References header. Exports and some clients drop those "
            "headers, so this only shows that no earlier message is referenced.",
            "content",
        ))

    if invisible_count >= INVISIBLE_CHAR_THRESHOLD:
        out.append(make_indicator(
            "Text contains invisible characters",
            "low",
            f"{invisible_count} zero-width or soft-hyphen characters were found in the subject "
            "or body. They are removed before the wording rules run. They also occur in "
            "some legitimate newsletters and in copied text.",
            "content",
        ))
    return out


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------

def analyze_content(parsed: ParsedEmail, result: Dict[str, Any]) -> None:
    """Apply the transparent rule table to the subject and body text."""
    analysis = result["content_analysis"]
    warnings = result["headers"]["meta"]["warnings"]

    def clip(text: str, label: str) -> str:
        if len(text) > MAX_TEXT_CHARS:
            message = f"{label} cut to {MAX_TEXT_CHARS} characters for content analysis"
            if message not in warnings:
                warnings.append(message)
            return text[:MAX_TEXT_CHARS]
        return text

    subject_raw = result["headers"].get("subject") or ""
    plain_raw = [clip(t, "Plain text body") for t in parsed.plain_bodies]
    html_raw = [clip(_html_to_text(t, warnings), "HTML body text") for t in parsed.html_bodies]

    invisible_count = _count_invisible(subject_raw) + sum(
        _count_invisible(t) for t in plain_raw + html_raw
    )
    subject = _normalize(subject_raw)
    plain = [_normalize(t) for t in plain_raw]
    html = [_normalize(t) for t in html_raw]

    matches = _scan(subject, "subject", set())
    body_seen: Set[Tuple[str, str]] = set()
    for text in plain:
        matches += _scan(text, "body_plain", body_seen)
    for text in html:
        matches += _scan(text, "body_html", body_seen)
    if len(matches) > MAX_TOTAL_MATCHES:
        matches = matches[:MAX_TOTAL_MATCHES]
        warnings.append(f"Content matches capped at {MAX_TOTAL_MATCHES}")

    analysis["matched_rules"] = matches
    analysis["category_counts"] = {
        category: sum(1 for m in matches if m["category"] == category)
        for category in CATEGORY_INFO
        if any(m["category"] == category for m in matches)
    }
    analysis["body"]["has_plain"] = bool(parsed.plain_bodies)
    analysis["body"]["has_html"] = bool(parsed.html_bodies)
    analysis["body"]["text_length"] = sum(len(t) for t in (plain if plain else html))

    result["risk_indicators"].extend(
        _build_indicators(matches, result, parsed, invisible_count)
    )