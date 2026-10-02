import hashlib
import io
import json
import os
import tempfile
import unittest
import zipfile
from email.message import EmailMessage

from analyzer import analyze_email
from analyzer import attachment_analyzer
from analyzer.attachment_analyzer import sniff_type
from analyzer.schema import validate_result

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")

PDF = b"%PDF-1.4\n% simulated test file\n"
PLACEHOLDER = b"simulated placeholder, not a program\n"
# 68 bytes that carry the signature fields of a PE header and nothing else.
# It is inert data, not a runnable program.
PE_HEADER = b"MZ" + b"\x00" * 58 + (64).to_bytes(4, "little") + b"PE\x00\x00"
PNG_HEADER = b"\x89PNG\r\n\x1a\n" + b"\x00" * 8


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


def build_eml(attachments):
    """Build an .eml with (filename, mime, bytes) attachments at test time."""
    msg = EmailMessage()
    msg["From"] = "a@example.org"
    msg["To"] = "b@example.com"
    msg["Message-ID"] = "<att@example.org>"
    msg.set_content("body")
    for name, mime, data in attachments:
        maintype, subtype = mime.split("/")
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=name)
    return msg.as_bytes()


def one(name, mime, data):
    result = analyze_bytes(build_eml([(name, mime, data)]))
    return result, result["attachments"][0]


def attachment_indicators(result):
    """Only the indicators produced by the attachment analyzer."""
    return [i for i in result["risk_indicators"] if i["category"] == "attachment"]


def find(result, text):
    return [i for i in attachment_indicators(result) if text in i["indicator"]]


def real_zip(encrypted_flag=False):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        z.writestr("readme.txt", "simulated archive member\n")
    data = bytearray(buf.getvalue())
    if encrypted_flag:
        data[6] |= 0x01          # general purpose bit 0: entry is encrypted
    return bytes(data)


class FixtureTests(unittest.TestCase):
    def setUp(self):
        self.result = analyze_email(fx("attachments_mixed.eml"))
        self.atts = {a["filename"]: a for a in self.result["attachments"]}

    def test_records_and_hashes(self):
        self.assertEqual(
            [a["filename"] for a in self.result["attachments"]],
            ["report.pdf", "invoice.pdf.exe", "budget.xlsm", "archive.zip", "photo.jpg"],
        )
        self.assertEqual(self.atts["report.pdf"]["sha256"], hashlib.sha256(PDF).hexdigest())
        self.assertEqual(self.atts["report.pdf"]["size_bytes"], 31)
        self.assertEqual(self.atts["invoice.pdf.exe"]["sha256"],
                         hashlib.sha256(PLACEHOLDER).hexdigest())
        self.assertEqual(self.atts["archive.zip"]["size_bytes"], 143)
        self.assertEqual(
            self.atts["archive.zip"]["sha256"],
            "f1a8000bc497fc03dd63f9819f37d61acde82090eff60378dfbbb850121b1158",
        )
        self.assertEqual(self.atts["report.pdf"]["mime_type"], "application/pdf")
        self.assertEqual(self.atts["report.pdf"]["content_disposition"], "attachment")

    def test_detected_types_and_extensions(self):
        self.assertEqual(self.atts["report.pdf"]["detected_type"], "pdf")
        self.assertEqual(self.atts["archive.zip"]["detected_type"], "zip")
        self.assertIsNone(self.atts["invoice.pdf.exe"]["detected_type"])
        self.assertEqual(self.atts["invoice.pdf.exe"]["extension"], "exe")

    def test_flags(self):
        expected = {
            "report.pdf": set(),
            "invoice.pdf.exe": {"executable_extension", "double_extension"},
            "budget.xlsm": {"macro_enabled_document"},
            "archive.zip": {"archive"},
            "photo.jpg": {"content_type_mismatch", "declared_mime_mismatch"},
        }
        for name, flags in expected.items():
            self.assertEqual(set(self.atts[name]["flags"]), flags, name)

    def test_indicators(self):
        found = {i["indicator"]: i["severity"] for i in attachment_indicators(self.result)}
        self.assertEqual(found, {
            "Attachment has an executable or script file type": "medium",
            "Attachment name has a document extension before an executable one": "medium",
            "Attachment is a macro-enabled Office document": "medium",
            "File content does not match the file extension": "medium",
            "Declared MIME type does not match file content": "low",
            "Attachment is an archive": "low",
        })

    def test_indicator_evidence(self):
        evidence = find(self.result, "executable or script")[0]["evidence"]
        self.assertIn("invoice.pdf.exe", evidence)
        self.assertIn("37 bytes", evidence)
        self.assertIn("sha256 c7d9c26d14c8b505", evidence)
        mismatch = find(self.result, "content does not match")[0]["evidence"]
        self.assertIn("content looks like PDF", mismatch)


class HashingTests(unittest.TestCase):
    def test_known_answer_from_multipart_fixture(self):
        result = analyze_email(fx("multipart.eml"))
        self.assertEqual(len(result["attachments"]), 1)
        att = result["attachments"][0]
        self.assertEqual(att["filename"], "note.txt")
        self.assertEqual(att["size_bytes"], 6)
        self.assertEqual(
            att["sha256"], "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
        )
        self.assertEqual(att["flags"], [])

    def test_no_attachments(self):
        result = analyze_email(fx("basic.eml"))
        self.assertEqual(result["attachments"], [])
        self.assertEqual(attachment_indicators(result), [])

    def test_sniff_type(self):
        self.assertEqual(sniff_type(PE_HEADER), "pe")
        self.assertEqual(sniff_type(b"MZ is just text"), None)
        self.assertEqual(sniff_type(PNG_HEADER), "png")
        self.assertEqual(sniff_type(b"\x7fELF" + b"\x00" * 8), "elf")
        self.assertEqual(sniff_type(b"plain text"), None)
        self.assertEqual(sniff_type(b""), None)


class ContentDetectionTests(unittest.TestCase):
    def test_masquerading_executable(self):
        result, att = one("photo.jpg", "image/jpeg", PE_HEADER)
        self.assertEqual(att["detected_type"], "pe")
        self.assertEqual(set(att["flags"]), {"masquerading_executable", "declared_mime_mismatch"})
        found = find(result, "Executable content under")[0]
        self.assertEqual(found["severity"], "high")
        self.assertIn("Windows executable (PE)", found["evidence"])

    def test_exe_with_matching_content_only_gets_extension_flag(self):
        _, att = one("setup.exe", "application/octet-stream", PE_HEADER)
        self.assertEqual(att["flags"], ["executable_extension"])

    def test_exe_with_pdf_content_is_mismatch(self):
        _, att = one("tool.exe", "application/octet-stream", PDF)
        self.assertEqual(set(att["flags"]), {"executable_extension", "content_type_mismatch"})

    def test_text_extension_with_binary_content(self):
        _, att = one("notes.txt", "text/plain", PNG_HEADER)
        self.assertEqual(att["flags"], ["content_type_mismatch"])

    def test_office_zip_container_is_not_an_archive(self):
        _, att = one(
            "letter.docx",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            real_zip(),
        )
        self.assertEqual(att["flags"], [])

    def test_legacy_word_may_be_rtf(self):
        _, att = one("old.doc", "application/msword", b"{\\rtf1 simulated}")
        self.assertEqual(att["flags"], [])

    def test_encrypted_zip(self):
        result, att = one("secret.zip", "application/zip", real_zip(encrypted_flag=True))
        self.assertEqual(set(att["flags"]), {"archive", "encrypted_archive"})
        self.assertEqual(find(result, "encrypted ZIP")[0]["severity"], "medium")
        _, plain = one("open.zip", "application/zip", real_zip())
        self.assertEqual(plain["flags"], ["archive"])

    def test_archive_detected_by_content(self):
        _, att = one("data.bin", "application/octet-stream", b"Rar!\x1a\x07\x00" + b"\x00" * 8)
        self.assertEqual(att["flags"], ["archive"])


class FilenameTests(unittest.TestCase):
    def test_bidi_override_is_escaped_in_evidence(self):
        name = "invoice\u202efdp.exe"
        result, att = one(name, "application/octet-stream", PLACEHOLDER)
        self.assertEqual(att["filename"], name)                 # record keeps the raw name
        self.assertEqual(att["extension"], "exe")
        self.assertEqual(set(att["flags"]), {"bidi_or_control_characters", "executable_extension"})
        for indicator in attachment_indicators(result):
            self.assertNotIn("\u202e", indicator["evidence"])
        evidence = find(result, "direction-control")[0]["evidence"]
        self.assertIn("invoice\\u202efdp.exe", evidence)
        self.assertIn("U+202E", evidence)

    def test_padded_filename(self):
        name = "invoice.pdf" + " " * 10 + ".exe"
        _, att = one(name, "application/octet-stream", PLACEHOLDER)
        self.assertEqual(
            set(att["flags"]), {"padded_filename", "executable_extension", "double_extension"}
        )

    def test_path_in_filename(self):
        _, att = one("../reports/q1.pdf", "application/pdf", PDF)
        self.assertEqual(att["flags"], ["path_in_filename"])

    def test_missing_filename_and_attached_message(self):
        raw = (
            b"From: a@example.org\nMessage-ID: <x@example.org>\n"
            b"MIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=\"b\"\n\n"
            b"--b\nContent-Type: text/plain\n\nhi\n"
            b"--b\nContent-Type: application/octet-stream\n"
            b"Content-Disposition: attachment\n\nAAAA\n"
            b"--b\nContent-Type: message/rfc822\nContent-Disposition: attachment\n\n"
            b"From: inner@example.org\nSubject: inner\n\ninner body\n"
            b"--b--\n"
        )
        result = analyze_bytes(raw)
        flags = [a["flags"] for a in result["attachments"]]
        self.assertEqual(flags, [["missing_filename"], ["attached_message"]])
        self.assertEqual(find(result, "no file name")[0]["severity"], "info")
        self.assertEqual(find(result, "message is attached")[0]["severity"], "info")


class RobustnessTests(unittest.TestCase):
    def test_attachment_cap(self):
        atts = [(f"f{i}.txt", "text/plain", b"x") for i in range(attachment_analyzer.MAX_ATTACHMENTS + 5)]
        result = analyze_bytes(build_eml(atts))
        self.assertEqual(len(result["attachments"]), attachment_analyzer.MAX_ATTACHMENTS)
        self.assertTrue(any("capped" in w for w in result["headers"]["meta"]["warnings"]))

    def test_output_is_json_and_never_contains_payload(self):
        result = analyze_email(fx("attachments_mixed.eml"))
        self.assertEqual(validate_result(result), [])
        text = json.dumps(result)                 # would fail if bytes leaked
        self.assertNotIn("simulated placeholder", text)
        for record in result["attachments"]:
            self.assertNotIn("payload", record)

    def test_module_imports_nothing_that_runs_or_opens_files(self):
        with open(attachment_analyzer.__file__, encoding="utf-8") as fh:
            imports = [l for l in fh if l.startswith(("import ", "from "))]
        banned = ("subprocess", "socket", "urllib.request", "http.client", "requests",
                  "ctypes", "zipfile", "tarfile", "importlib", "os", "shutil", "pathlib")
        for line in imports:
            modules = line.replace("import", " ").replace("from", " ").replace(",", " ").split()
            for name in banned:
                self.assertNotIn(name, modules, line)

    def test_no_verdict_language(self):
        text = " ".join(
            (i["indicator"] + " " + i["evidence"]).lower()
            for i in analyze_email(fx("attachments_mixed.eml"))["risk_indicators"]
        )
        for word in ("malicious", "phishing", "fraud", "malware", "virus"):
            self.assertNotIn(word, text)


if __name__ == "__main__":
    unittest.main()