import os
import tempfile
import unittest

from analyzer import analyze_email
from analyzer.header_analyzer import parse_authentication_results

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


def find(result, text):
    return [i for i in result["risk_indicators"] if text in i["indicator"]]


class AuthParseTests(unittest.TestCase):
    def test_comment_text_is_ignored(self):
        info = parse_authentication_results(
            "mx.example.com; spf=pass (note: dkim=fail in comment) smtp.mailfrom=a@b.example"
        )
        self.assertEqual(info["spf"][0]["result"], "pass")
        self.assertEqual(info["dkim"], [])
        self.assertEqual(info["authserv_id"], "mx.example.com")

    def test_multiple_dkim_signatures_summary_is_pass(self):
        result = analyze_bytes(
            b"From: a@example.org\nMessage-ID: <x@example.org>\n"
            b"Authentication-Results: mx.example.com; "
            b"dkim=fail header.d=one.example; dkim=pass header.d=example.org\n\nhi"
        )
        auth = result["headers"]["authentication"]
        self.assertEqual(auth["dkim"], "pass")
        self.assertEqual(len(auth["details"]["dkim_results"]), 2)


class HeaderAnalysisTests(unittest.TestCase):
    def test_pass_results(self):
        result = analyze_email(fx("auth_pass.eml"))
        auth = result["headers"]["authentication"]
        self.assertEqual((auth["spf"], auth["dkim"], auth["dmarc"]), ("pass", "pass", "pass"))
        self.assertEqual(auth["details"]["spf_mailfrom_domain"], "example.org")
        self.assertEqual(auth["details"]["authserv_id"], "mx.example.com")
        self.assertIsNotNone(auth["received_spf_raw"])
        auth_indicators = [i for i in result["risk_indicators"] if i["category"] == "authentication"]
        self.assertEqual(auth_indicators, [])

    def test_fail_results(self):
        result = analyze_email(fx("auth_fail.eml"))
        auth = result["headers"]["authentication"]
        self.assertEqual((auth["spf"], auth["dkim"], auth["dmarc"]), ("fail", "fail", "fail"))
        self.assertEqual(find(result, "SPF result: fail")[0]["severity"], "medium")
        self.assertEqual(find(result, "all reported fail")[0]["severity"], "high")

    def test_no_auth_headers(self):
        result = analyze_email(fx("basic.eml"))
        found = find(result, "No authentication results headers present")
        self.assertEqual(found[0]["severity"], "info")

    def test_received_spf_fallback(self):
        result = analyze_bytes(
            b"From: a@example.org\nMessage-ID: <x@example.org>\n"
            b"Received-SPF: softfail (example.org: not designated) "
            b"client-ip=203.0.113.9; envelope-from=a@example.org;\n\nhi"
        )
        auth = result["headers"]["authentication"]
        self.assertEqual(auth["spf"], "softfail")
        self.assertEqual(auth["details"]["spf_mailfrom_domain"], "example.org")
        self.assertEqual(find(result, "SPF result: softfail")[0]["severity"], "low")

    def test_alignment_mismatch(self):
        result = analyze_bytes(
            b"From: a@example.org\nMessage-ID: <x@example.org>\n"
            b"Authentication-Results: mx.example.com; "
            b"spf=pass smtp.mailfrom=user@other.example; dkim=none\n\nhi"
        )
        found = find(result, "SPF-authenticated domain differs")
        self.assertEqual(found[0]["severity"], "low")
        self.assertIn("other.example", found[0]["evidence"])

    def test_multiple_from_headers(self):
        result = analyze_bytes(
            b"From: a@example.org\nFrom: b@example.net\nMessage-ID: <x@example.org>\n\nhi"
        )
        self.assertEqual(find(result, "Multiple From headers")[0]["severity"], "medium")

    def test_mailer_recorded_as_info(self):
        result = analyze_email(fx("auth_pass.eml"))
        self.assertEqual(result["headers"]["x_mailer"], "PHPMailer 6.5.0")
        self.assertEqual(find(result, "mailing library")[0]["severity"], "info")

    def test_no_verdict_language(self):
        for name in ("basic.eml", "multipart.eml", "auth_pass.eml", "auth_fail.eml"):
            text = " ".join(
                (i["indicator"] + " " + i["evidence"]).lower()
                for i in analyze_email(fx(name))["risk_indicators"]
            )
            for word in ("malicious", "phishing", "fraud"):
                self.assertNotIn(word, text)


if __name__ == "__main__":
    unittest.main()