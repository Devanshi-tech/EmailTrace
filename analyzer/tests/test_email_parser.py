import json
import os
import tempfile
import unittest

from analyzer import analyze_email
from analyzer.email_parser import parse_email
from analyzer.schema import validate_result

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def fx(name):
    return os.path.join(FIXTURES, name)


def analyze_bytes(data):
    """Write bytes to a temp .eml, analyze it, clean up."""
    with tempfile.NamedTemporaryFile(suffix=".eml", delete=False) as f:
        f.write(data)
        path = f.name
    try:
        return analyze_email(path)
    finally:
        os.remove(path)


class BasicParsingTests(unittest.TestCase):
    def setUp(self):
        self.result = analyze_email(fx("basic.eml"))

    def test_basic_sender_fields(self):
        sender = self.result["sender"]
        self.assertEqual(sender["from"]["display_name"], "Alice Sender")
        self.assertEqual(sender["from"]["address"], "alice@example.org")
        self.assertEqual(sender["from"]["domain"], "example.org")
        self.assertEqual(sender["reply_to"][0]["domain"], "example.net")
        self.assertEqual(sender["return_path"]["address"], "alice@example.org")

    def test_basic_recipient_fields(self):
        rec = self.result["recipient"]
        self.assertEqual([r["address"] for r in rec["to"]],
                         ["bob@example.com", "carol@example.com"])
        self.assertEqual([r["address"] for r in rec["cc"]], ["dave@example.com"])

    def test_basic_headers(self):
        h = self.result["headers"]
        self.assertEqual(h["subject"], "Test message")
        self.assertEqual(h["date"], "Mon, 05 Jan 2026 10:15:00 +0000")
        self.assertEqual(h["message_id"], "<basic-001@example.org>")
        self.assertFalse(h["mime"]["is_multipart"])
        self.assertEqual(h["mime"]["content_type"], "text/plain")


class MultipartTests(unittest.TestCase):
    def setUp(self):
        self.parsed = parse_email(fx("multipart.eml"))
        self.result = analyze_email(fx("multipart.eml"))

    def test_multipart_structure(self):
        mime = self.result["headers"]["mime"]
        self.assertTrue(mime["is_multipart"])
        self.assertEqual(
            [p["content_type"] for p in mime["parts"]],
            ["text/plain", "text/html", "text/plain"],
        )

    def test_multipart_bodies(self):
        self.assertEqual(len(self.parsed.plain_bodies), 1)
        self.assertIn("Plain part body.", self.parsed.plain_bodies[0])
        self.assertIn("<p>HTML part body.</p>", self.parsed.html_bodies[0])
        body = self.result["content_analysis"]["body"]
        self.assertTrue(body["has_plain"])
        self.assertTrue(body["has_html"])

    def test_multipart_attachment_extracted(self):
        self.assertEqual(len(self.parsed.attachments), 1)
        att = self.parsed.attachments[0]
        self.assertEqual(att["filename"], "note.txt")
        self.assertEqual(att["payload"], b"hello\n")
        self.assertEqual(self.parsed.parts[2]["size_bytes"], 6)


class RobustnessTests(unittest.TestCase):
    def test_null_return_path(self):
        result = analyze_bytes(b"From: a@example.com\nReturn-Path: <>\n\nhi")
        self.assertIsNone(result["sender"]["return_path"])

    def test_garbage_input_does_not_crash(self):
        result = analyze_bytes(b"\xff\xfe this is not an email \x00\x01")
        self.assertIsNone(result["sender"]["from"])
        self.assertEqual(validate_result(result), [])

    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            analyze_email(fx("does_not_exist.eml"))

    def test_output_valid_for_fixtures(self):
        for name in ("basic.eml", "multipart.eml"):
            result = analyze_email(fx(name))
            self.assertEqual(validate_result(result), [])
            json.dumps(result)   # must not raise; also proves no bytes leaked


if __name__ == "__main__":
    unittest.main()