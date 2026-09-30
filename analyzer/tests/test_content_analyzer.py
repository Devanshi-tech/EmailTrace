import json
import os
import tempfile
import unittest

from analyzer import analyze_email
from analyzer import content_analyzer
from analyzer.schema import validate_result

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def fx(name):
    return os.path.join(FIXTURES, name)


def analyze_bytes(data):
    with tempfile.NamedTemporaryFile(suffix=".eml", delete=False) as f:
        f.write(data)
        path = f.name
    try:
        return analyze_email(path)
    finally:
        os.remove(path)


def mail(body, subject="Hello", sender="a@example.org", extra_headers="", content_type="text/plain"):
    text = (
        f"From: {sender}\nSubject: {subject}\nMessage-ID: <x@example.org>\n"
        f"MIME-Version: 1.0\nContent-Type: {content_type}; charset=utf-8\n{extra_headers}\n{body}"
    )
    return text.encode("utf-8")


def content_indicators(result):
    """Only the indicators produced by the content analyzer."""
    return [i for i in result["risk_indicators"] if i["category"] == "content"]


def find(result, text):
    return [i for i in content_indicators(result) if text in i["indicator"]]


def rules(result):
    return [(m["location"], m["rule"]) for m in result["content_analysis"]["matched_rules"]]


class FixtureTests(unittest.TestCase):
    def setUp(self):
        self.result = analyze_email(fx("content_pressure.eml"))
        self.analysis = self.result["content_analysis"]

    def test_matches_and_locations(self):
        self.assertEqual(rules(self.result), [
            ("subject", "urgent_wording"),
            ("subject", "time_pressure_phrase"),
            ("subject", "verify_account_request"),
            ("body_plain", "deadline_phrase"),
            ("body_plain", "account_suspension_threat"),
            ("body_plain", "legal_or_penalty_threat"),
            ("body_plain", "verify_account_request"),
            ("body_plain", "credential_entry_request"),
            ("body_plain", "payment_demand"),
            ("body_plain", "transfer_request"),
            ("body_plain", "internal_team_claim"),
            ("body_plain", "generic_greeting"),
            ("body_plain", "click_prompt"),
        ])

    def test_match_text_and_context(self):
        match = [m for m in self.analysis["matched_rules"]
                 if m["rule"] == "account_suspension_threat"][0]
        self.assertEqual(match["matched_text"], "account will be suspended")
        self.assertEqual(match["category"], "threat")
        self.assertIn("within 24 hours", match["context"])

    def test_category_counts_and_body_summary(self):
        self.assertEqual(self.analysis["category_counts"], {
            "urgency": 3, "threat": 2, "credential_request": 3, "payment_request": 2,
            "impersonation": 1, "generic_greeting": 1, "link_lure": 1,
        })
        self.assertTrue(self.analysis["body"]["has_plain"])
        self.assertFalse(self.analysis["body"]["has_html"])
        self.assertGreater(self.analysis["body"]["text_length"], 100)

    def test_indicators(self):
        found = {i["indicator"]: i["severity"] for i in content_indicators(self.result)}
        self.assertEqual(found, {
            "Urgent or time-pressure wording": "low",
            "Account-threat or penalty wording": "low",
            "Request to verify, confirm or enter account credentials": "medium",
            "Payment or funds-transfer wording": "medium",
            "Wording that claims an internal or official role": "low",
            "Generic greeting instead of a name": "info",
            "Prompt to click a link": "info",
            "Pressure wording appears together with a credential or payment request": "medium",
            "Action wording appears alongside links with static warning flags": "medium",
            "Display name uses a well-known brand that the sender domain does not match": "medium",
            "Subject uses shouting or heavy punctuation": "low",
        })

    def test_combined_indicator_evidence(self):
        link = find(self.result, "static warning flags")[0]["evidence"]
        self.assertIn("198.51.100.7", link)
        self.assertIn("ip_based", link)
        brand = find(self.result, "well-known brand")[0]["evidence"]
        self.assertIn("paypal", brand)
        self.assertIn("secure-billing.example.net", brand)

    def test_benign_message_has_no_matches(self):
        result = analyze_email(fx("content_benign.eml"))
        self.assertEqual(result["content_analysis"]["matched_rules"], [])
        self.assertEqual(result["content_analysis"]["category_counts"], {})
        self.assertEqual(content_indicators(result), [])


class TextPreparationTests(unittest.TestCase):
    def test_url_text_is_not_wording(self):
        result = analyze_bytes(mail("Visit http://x.example/login to avoid problems"))
        self.assertEqual(rules(result), [])

    def test_html_uses_visible_text_only(self):
        html = ("<html><head><title>verify your account</title><style>.a{}</style></head>"
                "<body><p>Please <b>verify</b> your account</p>"
                '<script>var s="enter your password";</script></body></html>')
        result = analyze_bytes(mail(html, content_type="text/html"))
        self.assertEqual(rules(result), [("body_html", "verify_account_request")])
        self.assertTrue(result["content_analysis"]["body"]["has_html"])
        self.assertGreater(result["content_analysis"]["body"]["text_length"], 0)

    def test_plain_and_html_alternatives_are_not_double_counted(self):
        raw = (
            b"From: a@example.org\nSubject: Hello\nMessage-ID: <x@example.org>\n"
            b"MIME-Version: 1.0\nContent-Type: multipart/alternative; boundary=\"b\"\n\n"
            b"--b\nContent-Type: text/plain\n\nPlease verify your account.\n"
            b"--b\nContent-Type: text/html\n\n"
            b"<p>Please verify your account.</p><p>Act now</p>\n--b--\n"
        )
        self.assertEqual(rules(analyze_bytes(raw)), [
            ("body_plain", "verify_account_request"),
            ("body_html", "time_pressure_phrase"),
        ])

    def test_invisible_characters_are_removed_and_reported(self):
        result = analyze_bytes(mail("Please ver\u200bify your ac\u200bcou\u200bnt now"))
        self.assertEqual(rules(result), [("body_plain", "verify_account_request")])
        found = find(result, "invisible characters")[0]
        self.assertEqual(found["severity"], "low")
        self.assertIn("3 zero-width", found["evidence"])

    def test_curly_apostrophe_is_normalized(self):
        result = analyze_bytes(mail("Don\u2019t delay, please."))
        match = result["content_analysis"]["matched_rules"][0]
        self.assertEqual(match["rule"], "time_pressure_phrase")
        self.assertEqual(match["matched_text"], "Don't delay")

    def test_greeting_only_counts_at_the_start(self):
        result = analyze_bytes(mail("Thanks for the note. Dear customer, we hope you are well."))
        self.assertEqual(rules(result), [])
        result = analyze_bytes(mail("Dear Customer, we hope you are well."))
        self.assertEqual(rules(result), [("body_plain", "generic_greeting")])

    def test_match_cap_per_rule(self):
        result = analyze_bytes(mail("urgent immediately asap right away"))
        urgent = [m for m in result["content_analysis"]["matched_rules"]
                  if m["rule"] == "urgent_wording"]
        self.assertEqual(len(urgent), content_analyzer.MAX_MATCHES_PER_RULE)


class IndicatorTests(unittest.TestCase):
    def test_pressure_alone_and_request_alone_do_not_combine(self):
        pressure = analyze_bytes(mail("Please respond today. Act now."))
        self.assertEqual(len(find(pressure, "Urgent or time-pressure")), 1)
        self.assertEqual(find(pressure, "Pressure wording appears together"), [])
        request = analyze_bytes(mail("Please confirm your password."))
        self.assertEqual(len(find(request, "Request to verify")), 1)
        self.assertEqual(find(request, "Pressure wording appears together"), [])
        both = analyze_bytes(mail("Act now and confirm your password."))
        self.assertEqual(find(both, "Pressure wording appears together")[0]["severity"], "medium")

    def test_link_combination_needs_a_flagged_link(self):
        plain_link = analyze_bytes(mail("Please confirm your password at https://example.org/a"))
        self.assertEqual(find(plain_link, "static warning flags"), [])
        short_link = analyze_bytes(mail("Please confirm your password at http://bit.ly/x"))
        found = find(short_link, "static warning flags")[0]
        self.assertIn("url_shortener", found["evidence"])

    def test_brand_in_display_name(self):
        cases = [
            ("Microsoft Account Team", "no-reply@microsoft.com", False),
            ("Microsoft", "x@microsoftonline.com", False),
            ("Amazon", "x@amazon.co.uk", False),
            ("UPS Tracking", "a@ups.com", False),
            ("Groups Team", "a@example.org", False),
            ("Amazon Deals", "d@amazon-offers.example", True),
            ("PayPal", "x@gmail.com", True),
            ("PayPal", "x@paypal.evil.example", True),
        ]
        for display, address, expected in cases:
            with self.subTest(display=display, address=address):
                result = analyze_bytes(mail("hello there", sender=f'"{display}" <{address}>'))
                self.assertEqual(bool(find(result, "well-known brand")), expected)

    def test_subject_style(self):
        shouting = analyze_bytes(mail("hi", subject="FINAL NOTICE YOUR ACCOUNT"))
        self.assertIn("mostly capital letters", find(shouting, "shouting")[0]["evidence"])
        punct = analyze_bytes(mail("hi", subject="Great news!!!"))
        self.assertIn("repeated exclamation", find(punct, "shouting")[0]["evidence"])
        for calm in ("Lunch tomorrow?", "Q3 report ready", "RE: OK"):
            self.assertEqual(find(analyze_bytes(mail("hi", subject=calm)), "shouting"), [], calm)

    def test_reply_subject_without_reply_headers(self):
        result = analyze_bytes(mail("hi", subject="Re: Invoice"))
        self.assertEqual(find(result, "implies a reply")[0]["severity"], "low")
        with_header = analyze_bytes(
            mail("hi", subject="Re: Invoice", extra_headers="In-Reply-To: <a@example.org>\n")
        )
        self.assertEqual(find(with_header, "implies a reply"), [])
        self.assertEqual(find(analyze_bytes(mail("hi", subject="Regarding invoice")), "implies a reply"), [])

    def test_missing_subject_and_body(self):
        result = analyze_bytes(b"From: a@example.org\n\n")
        self.assertEqual(result["content_analysis"]["matched_rules"], [])
        self.assertEqual(content_indicators(result), [])


class OutputTests(unittest.TestCase):
    def test_output_valid_json(self):
        result = analyze_email(fx("content_pressure.eml"))
        self.assertEqual(validate_result(result), [])
        json.dumps(result)

    def test_no_verdict_language(self):
        for name in ("content_pressure.eml", "content_benign.eml"):
            result = analyze_email(fx(name))
            text = " ".join((i["indicator"] + " " + i["evidence"]).lower()
                            for i in content_indicators(result))
            for word in ("malicious", "phishing", "fraud", "malware", "virus", "spoof"):
                self.assertNotIn(word, text)

    def test_module_imports_no_network_or_system_tools(self):
        with open(content_analyzer.__file__, encoding="utf-8") as fh:
            imports = [l for l in fh if l.startswith(("import ", "from "))]
        banned = ("subprocess", "socket", "urllib", "http.client", "requests", "os",
                  "importlib", "ctypes", "shutil", "pathlib")
        for line in imports:
            modules = line.replace("import", " ").replace("from", " ").replace(",", " ").split()
            for name in banned:
                self.assertNotIn(name, modules, line)


if __name__ == "__main__":
    unittest.main()