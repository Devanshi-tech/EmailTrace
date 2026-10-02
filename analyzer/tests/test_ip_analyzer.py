import ipaddress
import json
import os
import tempfile
import unittest

from analyzer import analyze_email
from analyzer.ip_analyzer import classify_ip, scan_text_for_ips
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


def find(result, text):
    return [i for i in result["risk_indicators"] if text in i["indicator"]]


class ClassifyTests(unittest.TestCase):
    def test_classification_table(self):
        table = [
            ("10.1.2.3", "private"), ("172.31.255.1", "private"),
            ("192.168.0.1", "private"), ("fd00::1", "private"),
            ("127.0.0.1", "loopback"), ("::1", "loopback"),
            ("169.254.1.1", "reserved"), ("100.64.0.1", "reserved"),
            ("203.0.113.5", "reserved"), ("224.0.0.1", "reserved"),
            ("0.0.0.0", "reserved"), ("255.255.255.255", "reserved"),
            ("fe80::1", "reserved"), ("2001:db8::1", "reserved"),
            ("8.8.8.8", "public"), ("2606:4700:4700::1111", "public"),
        ]
        for text, expected in table:
            with self.subTest(ip=text):
                self.assertEqual(classify_ip(ipaddress.ip_address(text))[0], expected)

    def test_ipv4_mapped_uses_mapped_address(self):
        self.assertEqual(classify_ip(ipaddress.ip_address("::ffff:8.8.8.8"))[0], "public")
        self.assertEqual(classify_ip(ipaddress.ip_address("::ffff:10.0.0.1"))[0], "private")


class ScanTests(unittest.TestCase):
    def test_scan_finds_v4_and_v6_in_order(self):
        valid, invalid = scan_text_for_ips(
            "from a [203.0.113.5] then [IPv6:2001:db8::7] client-ip=8.8.8.8;"
        )
        self.assertEqual(valid, ["203.0.113.5", "2001:db8::7", "8.8.8.8"])
        self.assertEqual(invalid, [])

    def test_scan_reports_invalid_ipv4(self):
        valid, invalid = scan_text_for_ips("x 999.1.1.1 y 8.8.8.8")
        self.assertEqual(valid, ["8.8.8.8"])
        self.assertEqual(invalid, ["999.1.1.1"])

    def test_scan_ignores_hostname_embedded_digits(self):
        valid, invalid = scan_text_for_ips("from 10.1.2.3.static.example.net (unknown)")
        self.assertEqual((valid, invalid), ([], []))


class ExtractionTests(unittest.TestCase):
    def setUp(self):
        self.result = analyze_email(fx("ip_mixed.eml"))
        self.by_ip = {r["ip"]: r for r in self.result["ips"]}

    def test_ips_and_order(self):
        self.assertEqual(
            [r["ip"] for r in self.result["ips"]],
            ["8.8.8.8", "127.0.0.1", "10.0.0.7", "2001:db8::25",
             "fe80::1", "8.8.4.4", "172.16.5.9"],
        )

    def test_classifications_and_reasons(self):
        expected = {
            "8.8.8.8": ("public", 4), "8.8.4.4": ("public", 4),
            "127.0.0.1": ("loopback", 4), "10.0.0.7": ("private", 4),
            "172.16.5.9": ("private", 4), "2001:db8::25": ("reserved", 6),
            "fe80::1": ("reserved", 6),
        }
        for ip, (cls, version) in expected.items():
            self.assertEqual(self.by_ip[ip]["classification"], cls, ip)
            self.assertEqual(self.by_ip[ip]["version"], version, ip)
        self.assertIn("documentation", self.by_ip["2001:db8::25"]["reason"])
        self.assertIn("link-local", self.by_ip["fe80::1"]["reason"])
        self.assertIsNone(self.by_ip["8.8.8.8"]["reason"])

    def test_sources(self):
        self.assertEqual(self.by_ip["8.8.8.8"]["sources"], ["received[0]:from"])
        self.assertEqual(self.by_ip["fe80::1"]["sources"], ["received[3]:by"])
        self.assertEqual(self.by_ip["8.8.4.4"]["sources"], ["header:X-Originating-IP"])
        self.assertEqual(self.by_ip["172.16.5.9"]["sources"], ["header:X-Forwarded-For"])

    def test_dedup_merges_sources(self):
        result = analyze_bytes(
            b"From: a@example.org\n"
            b"Received: from a.example.com (a.example.com [8.8.8.8]) by b.example.com "
            b"with ESMTP id A1; Mon, 05 Jan 2026 10:00:00 +0000\n"
            b"Received-SPF: pass (b.example.com: domain of a@example.org designates "
            b"8.8.8.8 as permitted sender) client-ip=8.8.8.8;\n\nhi"
        )
        self.assertEqual(len(result["ips"]), 1)
        self.assertEqual(result["ips"][0]["sources"],
                         ["received[0]:from", "header:Received-SPF"])


class IndicatorTests(unittest.TestCase):
    def test_mixed_indicators(self):
        result = analyze_email(fx("ip_mixed.eml"))
        local = find(result, "Private or loopback")[0]
        self.assertEqual(local["severity"], "info")
        for ip in ("127.0.0.1", "10.0.0.7", "172.16.5.9"):
            self.assertIn(ip, local["evidence"])
        reserved = find(result, "reserved or special-purpose")[0]
        self.assertEqual(reserved["severity"], "low")
        self.assertIn("2001:db8::25", reserved["evidence"])
        self.assertIn("fe80::1", reserved["evidence"])
        self.assertEqual(find(result, "No public IP"), [])

    def test_invalid_literal_flagged(self):
        result = analyze_email(fx("ip_mixed.eml"))
        found = find(result, "Invalid IP address literal")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["severity"], "low")
        self.assertIn("999.1.1.1", found[0]["evidence"])
        self.assertIn("header:X-Forwarded-For", found[0]["evidence"])

    def test_all_nonpublic_chain(self):
        result = analyze_email(fx("received_chain.eml"))
        self.assertEqual(
            [(r["ip"], r["classification"]) for r in result["ips"]],
            [("198.51.100.20", "reserved"), ("203.0.113.25", "reserved"),
             ("192.168.1.44", "private")],
        )
        self.assertEqual(find(result, "No public IP")[0]["severity"], "info")
        self.assertEqual(find(result, "reserved or special-purpose")[0]["severity"], "low")

    def test_no_ips(self):
        result = analyze_bytes(b"From: a@example.org\n\nhi")
        self.assertEqual(result["ips"], [])
        self.assertEqual(find(result, "No IP addresses found")[0]["severity"], "info")

    def test_output_valid_json(self):
        result = analyze_email(fx("ip_mixed.eml"))
        self.assertEqual(validate_result(result), [])
        json.dumps(result)

    def test_no_verdict_language(self):
        for name in ("ip_mixed.eml", "received_chain.eml"):
            text = " ".join(
                (i["indicator"] + " " + i["evidence"]).lower()
                for i in analyze_email(fx(name))["risk_indicators"]
            )
            for word in ("malicious", "phishing", "fraud"):
                self.assertNotIn(word, text)


if __name__ == "__main__":
    unittest.main()