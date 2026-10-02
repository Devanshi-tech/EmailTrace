import json
import os
import tempfile
import unittest

from analyzer import analyze_email
from analyzer.domain_analyzer import is_valid_domain
from analyzer.schema import validate_result

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
DOMAIN_TITLES = ("Reply-To domain", "Return-Path domain", "Display name shows",
                 "Address domain uses", "From address has no usable domain")


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


def mail(headers, body="hi"):
    return (headers.strip() + "\nMessage-ID: <x@example.org>\n\n" + body).encode("utf-8")


def find(result, text):
    return [i for i in result["risk_indicators"] if text in i["indicator"]]


def domain_indicators(result):
    """Only the indicators produced by the domain analyzer."""
    return [i for i in result["risk_indicators"]
            if any(t in i["indicator"] for t in DOMAIN_TITLES)]


def by_domain(result):
    return {d["domain"]: d for d in result["domains"]}


class ExtractionTests(unittest.TestCase):
    def test_domains_and_sources_in_order(self):
        result = analyze_email(fx("domains_mismatch.eml"))
        self.assertEqual(
            [(d["domain"], d["sources"], d["url_count"]) for d in result["domains"]],
            [
                ("example.com", ["from"], 0),
                ("gmail.com", ["reply_to"], 0),
                ("mailer.example.net", ["return_path"], 0),
                ("reset.example.org", ["url"], 1),
                ("www.example.com", ["url"], 1),
            ],
        )

    def test_ip_url_hosts_are_not_domains(self):
        result = analyze_email(fx("domains_mismatch.eml"))
        self.assertNotIn("203.0.113.9", by_domain(result))

    def test_sources_merge_across_headers_and_urls(self):
        result = analyze_email(fx("domains_clean.eml"))
        domains = by_domain(result)
        self.assertEqual(domains["example.org"]["sources"], ["from", "return_path", "url"])
        self.assertEqual(domains["example.org"]["url_count"], 1)
        self.assertEqual(domains["mail.example.org"]["sources"], ["reply_to"])

    def test_encoded_url_host_skipped(self):
        result = analyze_bytes(mail("From: a@example.org", "see http://%65xample.net/x"))
        self.assertEqual([d["domain"] for d in result["domains"]], ["example.org"])

    def test_no_from_no_crash(self):
        result = analyze_bytes(mail("Subject: x"))
        self.assertEqual(result["domains"], [])
        self.assertEqual(domain_indicators(result), [])

    def test_is_valid_domain(self):
        for good in ("example.org", "a-b.example.co.uk", "xn--bcher-kva.example", "localhost"):
            self.assertTrue(is_valid_domain(good), good)
        for bad in ("", "example..org", "-a.example.org", "exa mple.org", "[1.2.3.4]",
                    "example.org>", "a" * 64 + ".org"):
            self.assertFalse(is_valid_domain(bad), bad)


class MismatchIndicatorTests(unittest.TestCase):
    def setUp(self):
        self.result = analyze_email(fx("domains_mismatch.eml"))

    def test_reply_to_mismatch(self):
        found = find(self.result, "Reply-To domain differs from sender domain")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["severity"], "medium")
        self.assertEqual(found[0]["category"], "header")
        for text in ("example.com", "helpdesk@gmail.com", "public webmail provider"):
            self.assertIn(text, found[0]["evidence"])

    def test_return_path_mismatch(self):
        found = find(self.result, "Return-Path domain differs")
        self.assertEqual(found[0]["severity"], "low")
        self.assertIn("mailer.example.net", found[0]["evidence"])

    def test_display_name_mismatch(self):
        found = find(self.result, "Display name shows a different domain")
        self.assertEqual(found[0]["severity"], "medium")
        self.assertIn("example.org", found[0]["evidence"])
        self.assertIn("example.com", found[0]["evidence"])

    def test_matching_and_subdomain_not_flagged(self):
        result = analyze_email(fx("domains_clean.eml"))
        self.assertEqual(domain_indicators(result), [])

    def test_only_differing_reply_to_addresses_listed(self):
        result = analyze_bytes(mail(
            "From: a@example.org\nReply-To: b@example.org, c@other.example, d@third.example"
        ))
        evidence = find(result, "Reply-To domain differs")[0]["evidence"]
        self.assertIn("c@other.example", evidence)
        self.assertIn("d@third.example", evidence)
        self.assertNotIn("b@example.org", evidence)
        self.assertNotIn("webmail", evidence)

    def test_display_name_with_same_domain_not_flagged(self):
        result = analyze_bytes(mail('From: "Help help@example.org" <a@example.org>'))
        self.assertEqual(find(result, "Display name shows"), [])

    def test_display_name_url_mismatch(self):
        result = analyze_bytes(mail('From: "Visit www.example.net" <a@example.org>'))
        self.assertEqual(len(find(result, "Display name shows")), 1)

    def test_idn_sender_domain(self):
        result = analyze_bytes(mail("From: a@xn--bcher-kva.example"))
        found = find(result, "punycode or non-ASCII")[0]
        self.assertEqual(found["severity"], "low")
        self.assertEqual(found["category"], "domain")
        self.assertIn("from: xn--bcher-kva.example (bücher.example)", found["evidence"])

    def test_from_without_domain(self):
        result = analyze_bytes(mail("From: not-an-address\nReply-To: x@example.net"))
        found = find(result, "From address has no usable domain")
        self.assertEqual(found[0]["severity"], "low")
        self.assertEqual(find(result, "Reply-To domain differs"), [])


class OutputTests(unittest.TestCase):
    def test_output_valid_json(self):
        result = analyze_email(fx("domains_mismatch.eml"))
        self.assertEqual(validate_result(result), [])
        json.dumps(result)

    def test_no_verdict_language(self):
        for name in ("domains_mismatch.eml", "domains_clean.eml"):
            text = " ".join(
                (i["indicator"] + " " + i["evidence"]).lower()
                for i in analyze_email(fx(name))["risk_indicators"]
            )
            for word in ("malicious", "phishing", "fraud", "spoof"):
                self.assertNotIn(word, text)


if __name__ == "__main__":
    unittest.main()