import json
import os
import tempfile
import unittest

from analyzer import analyze_email
from analyzer import ioc_analyzer
from analyzer.email_parser import parse_email
from analyzer.ioc_analyzer import defang, extract_emails, extract_hashes
from analyzer.schema import validate_result

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
HELLO_SHA256 = "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"


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


def mail(body, headers="", content_type="text/plain"):
    text = (
        f"From: a@example.org\n{headers}Message-ID: <x@example.org>\n"
        f"MIME-Version: 1.0\nContent-Type: {content_type}; charset=utf-8\n\n{body}"
    )
    return text.encode("utf-8")


def pairs(result):
    return [(i["type"], i["value"]) for i in result["iocs"]]


def by_key(result):
    return {(i["type"], i["value"]): i for i in result["iocs"]}


class FixtureTests(unittest.TestCase):
    def setUp(self):
        self.result = analyze_email(fx("iocs_mixed.eml"))
        self.iocs = by_key(self.result)

    def test_values_and_order(self):
        self.assertEqual(pairs(self.result), [
            ("ip", "198.51.100.25"),
            ("ip", "10.0.0.9"),
            ("ip", "203.0.113.9"),
            ("domain", "example.com"),
            ("domain", "gmail.com"),
            ("domain", "mailer.example.net"),
            ("domain", "portal.example.org"),
            ("url", "https://portal.example.org/help?id=7"),
            ("url", "http://203.0.113.9/x"),
            ("email", "alerts@example.com"),
            ("email", "billing@example.com"),
            ("email", "helpdesk@gmail.com"),
            ("email", "bounce@mailer.example.net"),
            ("email", "support@example.org"),
            ("hash", HELLO_SHA256),
        ])

    def test_source_is_first_of_sources(self):
        for ioc in self.result["iocs"]:
            self.assertEqual(ioc["source"], ioc["sources"][0])

    def test_sources(self):
        self.assertEqual(self.iocs[("ip", "198.51.100.25")]["sources"], ["received[0]:from"])
        self.assertEqual(self.iocs[("ip", "203.0.113.9")]["sources"], ["url"])
        self.assertEqual(self.iocs[("domain", "gmail.com")]["sources"], ["header:Reply-To"])
        self.assertEqual(
            self.iocs[("url", "https://portal.example.org/help?id=7")]["sources"],
            ["body:text/plain", "body:text/html"],
        )
        self.assertEqual(self.iocs[("email", "billing@example.com")]["sources"],
                         ["header:From:display_name"])
        self.assertEqual(self.iocs[("email", "support@example.org")]["sources"],
                         ["body:text/plain", "body:text/html", "body:mailto"])
        self.assertEqual(self.iocs[("hash", HELLO_SHA256)]["sources"],
                         ["attachment[0]", "body:text/plain"])

    def test_notes(self):
        self.assertEqual(self.iocs[("ip", "198.51.100.25")]["note"], "reserved")
        self.assertEqual(self.iocs[("ip", "10.0.0.9")]["note"], "private")
        self.assertEqual(self.iocs[("url", "http://203.0.113.9/x")]["note"], "ip_based")
        self.assertIsNone(self.iocs[("domain", "example.com")]["note"])
        self.assertEqual(self.iocs[("hash", HELLO_SHA256)]["note"], "sha256; text/plain, 6 bytes")

    def test_defanged_values(self):
        self.assertEqual(self.iocs[("ip", "198.51.100.25")]["defanged"], "198[.]51[.]100[.]25")
        self.assertEqual(self.iocs[("domain", "mailer.example.net")]["defanged"],
                         "mailer[.]example[.]net")
        self.assertEqual(self.iocs[("url", "https://portal.example.org/help?id=7")]["defanged"],
                         "hxxps://portal[.]example[.]org/help?id=7")
        self.assertEqual(self.iocs[("email", "alerts@example.com")]["defanged"],
                         "alerts[@]example[.]com")
        self.assertEqual(self.iocs[("hash", HELLO_SHA256)]["defanged"], HELLO_SHA256)

    def test_recipients_and_image_names_are_not_iocs(self):
        values = [value for _, value in pairs(self.result)]
        self.assertNotIn("bob@example.com", values)
        self.assertNotIn("logo@2x.png", values)
        self.assertNotIn("support@example.org?subject=Hi", values)

    def test_adds_no_risk_indicators_and_is_repeatable(self):
        parsed = parse_email(fx("iocs_mixed.eml"))
        before = json.dumps(self.result["risk_indicators"])
        ioc_analyzer.analyze_iocs(parsed, self.result)
        self.assertEqual(json.dumps(self.result["risk_indicators"]), before)
        self.assertEqual(len(self.result["iocs"]), 15)      # replaced, not appended


class ExtractionTests(unittest.TestCase):
    def test_defang(self):
        self.assertEqual(defang("url", "http://a.example/p?q=1.2"), "hxxp://a[.]example/p?q=1.2")
        self.assertEqual(defang("url", "www.a.example/x"), "www[.]a[.]example/x")
        self.assertEqual(defang("url", "ftp://f.example/a"), "ftp://f[.]example/a")
        self.assertEqual(defang("ip", "2001:db8::1"), "2001[:]db8[:][:]1")
        self.assertEqual(defang("hash", "ab12"), "ab12")

    def test_extract_emails(self):
        found = extract_emails(
            "a.b+tag@sub.example.co.uk, BOB@Example.ORG, bad@@example.org, x@localhost, "
            "logo@2x.png, .lead@example.org, dou..ble@example.org."
        )
        self.assertEqual(found, ["a.b+tag@sub.example.co.uk", "bob@example.org"])

    def test_extract_hashes(self):
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        text = f"{md5} {sha1} {sha256.upper()} {'a' * 32} {'1' * 32} {md5}0"
        self.assertEqual(
            extract_hashes(text),
            [(md5, "md5"), (sha1, "sha1"), (sha256, "sha256")],
        )


class BodyScanningTests(unittest.TestCase):
    def test_hash_inside_url_is_ignored(self):
        h = "d41d8cd98f00b204e9800998ecf8427e"
        result = analyze_bytes(mail(f"see http://x.example/track/{h}?u=bob@example.net now"))
        self.assertEqual([t for t, _ in pairs(result) if t == "hash"], [])
        self.assertNotIn("bob@example.net", [v for _, v in pairs(result)])

    def test_body_hash_note_names_the_algorithm(self):
        h = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        result = analyze_bytes(mail(f"checksum {h}"))
        ioc = by_key(result)[("hash", h)]
        self.assertEqual(ioc["source"], "body:text/plain")
        self.assertIn("sha1-length", ioc["note"])

    def test_mailto_with_several_recipients(self):
        html_body = '<a href="mailto:a@example.org,B@Example.org?subject=x&amp;cc=c@example.org">m</a>'
        result = analyze_bytes(mail(html_body, content_type="text/html"))
        emails = [v for t, v in pairs(result) if t == "email"]
        self.assertEqual(emails, ["a@example.org", "b@example.org"])

    def test_html_script_and_style_are_not_scanned(self):
        html_body = ("<style>.x{content:'s@example.net'}</style>"
                     "<script>var e='t@example.net';</script><p>u@example.net</p>")
        result = analyze_bytes(mail(html_body, content_type="text/html"))
        self.assertEqual([v for t, v in pairs(result) if t == "email" and v.endswith("example.net")],
                         ["u@example.net"])

    def test_empty_attachment_hash_is_skipped(self):
        raw = (
            b"From: a@example.org\nMessage-ID: <x@example.org>\nMIME-Version: 1.0\n"
            b"Content-Type: multipart/mixed; boundary=\"b\"\n\n"
            b"--b\nContent-Type: text/plain\n\nhi\n"
            b"--b\nContent-Type: application/octet-stream\n"
            b"Content-Disposition: attachment; filename=\"empty.bin\"\n\n--b--\n"
        )
        result = analyze_bytes(raw)
        self.assertEqual(result["attachments"][0]["size_bytes"], 0)
        self.assertEqual([t for t, _ in pairs(result) if t == "hash"], [])


class IpAndUrlTests(unittest.TestCase):
    def test_obfuscated_url_host_becomes_an_ip_ioc(self):
        result = analyze_bytes(mail("pay at http://3232235777/pay and http://[2001:db8::7]/x"))
        iocs = by_key(result)
        self.assertEqual(iocs[("ip", "192.168.1.1")]["sources"], ["url"])
        self.assertEqual(iocs[("ip", "192.168.1.1")]["note"], "private")
        self.assertIn(("ip", "2001:db8::7"), iocs)
        self.assertIn("obfuscated_ip_host", iocs[("url", "http://3232235777/pay")]["note"])

    def test_same_ip_in_header_and_url_is_merged(self):
        raw = mail(
            "see http://203.0.113.9/x",
            headers=("Received: from a.example.com (a.example.com [203.0.113.9]) "
                     "by b.example.com with ESMTP id A1; Mon, 05 Jan 2026 10:00:00 +0000\n"),
        )
        result = analyze_bytes(raw)
        ips = [i for i in result["iocs"] if i["type"] == "ip"]
        self.assertEqual(len(ips), 1)
        self.assertEqual(ips[0]["sources"], ["received[0]:from", "url"])

    def test_urls_without_a_host_are_not_iocs(self):
        result = analyze_bytes(mail('<a href="javascript:void(0)">x</a>', content_type="text/html"))
        self.assertEqual([t for t, _ in pairs(result) if t == "url"], [])


class RobustnessTests(unittest.TestCase):
    def test_empty_message(self):
        result = analyze_bytes(b"Subject: x\n\n")
        self.assertEqual(result["iocs"], [])

    def test_ioc_cap(self):
        body = " ".join(f"u{i}@example.org" for i in range(ioc_analyzer.MAX_IOCS + 10))
        result = analyze_bytes(mail(body))
        self.assertEqual(len(result["iocs"]), ioc_analyzer.MAX_IOCS)
        self.assertTrue(any("capped" in w for w in result["headers"]["meta"]["warnings"]))

    def test_output_valid_json(self):
        result = analyze_email(fx("iocs_mixed.eml"))
        self.assertEqual(validate_result(result), [])
        json.dumps(result)

    def test_module_imports_no_network_or_system_tools(self):
        with open(ioc_analyzer.__file__, encoding="utf-8") as fh:
            imports = [l for l in fh if l.startswith(("import ", "from "))]
        banned = ("subprocess", "socket", "urllib.request", "http.client", "requests", "os",
                  "importlib", "ctypes", "shutil", "pathlib")
        for line in imports:
            modules = line.replace("import", " ").replace("from", " ").replace(",", " ").split()
            for name in banned:
                self.assertNotIn(name, modules, line)


if __name__ == "__main__":
    unittest.main()