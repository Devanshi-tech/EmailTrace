"""
End-to-end contract tests for analyzer.analyze_email.

These tests run the whole engine on every fixture and check the promises the
backend and frontend rely on: the 12-key schema, JSON/SQLite safety,
determinism, read-only and offline operation, and evidence-not-verdict wording.
Expected key sets come from the schema's own builder functions, so the tests
cannot drift from analyzer/schema.py.
"""

import builtins
import glob
import hashlib
import json
import os
import pathlib
import socket
import sqlite3
import subprocess
import tempfile
import unittest
from contextlib import ExitStack
from unittest import mock

from analyzer import analyze_email, email_parser
from analyzer.schema import (
    SCHEMA_VERSION,
    SEVERITIES,
    TOP_LEVEL_KEYS,
    empty_result,
    make_address,
    make_attachment_record,
    make_content_match,
    make_domain_record,
    make_indicator,
    make_ioc,
    make_ip_record,
    make_received_hop,
    make_timestamp_record,
    make_url_record,
    validate_result,
)

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
FIXTURE_PATHS = sorted(glob.glob(os.path.join(FIXTURES, "*.eml")))

DYNAMIC_DICT_KEYS = {"category_counts"}        # keys depend on what matched
FORBIDDEN_WORDS = ("malicious", "phishing", "fraud", "malware", "virus", "spoof")

RECORD_BUILDERS = {
    "received_paths": lambda: make_received_hop(0, "raw"),
    "ips": lambda: make_ip_record("192.0.2.1", 4, "reserved"),
    "timestamps": lambda: make_timestamp_record("date", None, None, "missing"),
    "urls": lambda: make_url_record("http://a.example/", "http", "a.example", "/", None, "text/plain"),
    "domains": lambda: make_domain_record("a.example"),
    "attachments": lambda: make_attachment_record(None, None, 0, "00"),
    "iocs": lambda: make_ioc("ip", "192.0.2.1", "header"),
    "risk_indicators": lambda: make_indicator("i", "info", "e", "header"),
}


def fx(name):
    return os.path.join(FIXTURES, name)


def walk(value, path="result"):
    """Yield (path, value) for every node, including dict keys."""
    yield path, value
    if isinstance(value, dict):
        for key, child in value.items():
            yield f"{path}.{key}", key
            yield from walk(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from walk(child, f"{path}[{index}]")


def write_sparse_file(size):
    with tempfile.NamedTemporaryFile(suffix=".eml", delete=False) as f:
        f.seek(size)
        f.write(b"x")
        return f.name


class SchemaContractTests(unittest.TestCase):
    def assert_same_structure(self, actual, skeleton, path="result"):
        """Every dict in the skeleton exists in the result with exactly the same keys."""
        if isinstance(skeleton, dict):
            self.assertIsInstance(actual, dict, path)
            self.assertEqual(set(actual), set(skeleton), path)
            for key, expected in skeleton.items():
                if key not in DYNAMIC_DICT_KEYS:
                    self.assert_same_structure(actual[key], expected, f"{path}.{key}")
        elif isinstance(skeleton, list):
            self.assertIsInstance(actual, list, path)

    def check_records(self, result):
        for key, builder in RECORD_BUILDERS.items():
            expected = set(builder())
            for index, record in enumerate(result[key]):
                self.assertEqual(set(record), expected, f"{key}[{index}]")
        match_keys = set(make_content_match("r", "c", "m", "subject"))
        for record in result["content_analysis"]["matched_rules"]:
            self.assertEqual(set(record), match_keys)
        addresses = [result["sender"]["from"], result["sender"]["return_path"]]
        addresses += result["sender"]["reply_to"] + result["recipient"]["to"] + result["recipient"]["cc"]
        for record in addresses:
            if record is not None:
                self.assertEqual(set(record), set(make_address()))

    def test_fixture_directory_is_populated(self):
        names = {os.path.basename(p) for p in FIXTURE_PATHS}
        for expected in ("basic.eml", "multipart.eml", "attachments_mixed.eml", "iocs_mixed.eml"):
            self.assertIn(expected, names)
        self.assertGreaterEqual(len(FIXTURE_PATHS), 14)

    def test_every_fixture_meets_the_schema(self):
        for path in FIXTURE_PATHS:
            with self.subTest(fixture=os.path.basename(path)):
                result = analyze_email(path)
                self.assertEqual(tuple(result), TOP_LEVEL_KEYS)
                self.assertEqual(validate_result(result), [])
                self.assert_same_structure(result, empty_result())
                self.check_records(result)
                for indicator in result["risk_indicators"]:
                    self.assertIn(indicator["severity"], SEVERITIES)
                    self.assertTrue(indicator["evidence"].strip())

    def test_meta_describes_the_input_file(self):
        for path in FIXTURE_PATHS:
            with self.subTest(fixture=os.path.basename(path)):
                meta = analyze_email(path)["headers"]["meta"]
                self.assertEqual(meta["schema_version"], SCHEMA_VERSION)
                self.assertEqual(meta["file_name"], os.path.basename(path))
                self.assertEqual(meta["file_size_bytes"], os.path.getsize(path))
                self.assertTrue(all(isinstance(w, str) for w in meta["warnings"]))


class SerializationContractTests(unittest.TestCase):
    def test_json_round_trip_is_lossless(self):
        for path in FIXTURE_PATHS:
            with self.subTest(fixture=os.path.basename(path)):
                result = analyze_email(path)
                self.assertEqual(json.loads(json.dumps(result)), result)

    def test_no_raw_bytes_and_all_text_is_utf8_safe(self):
        for path in FIXTURE_PATHS:
            with self.subTest(fixture=os.path.basename(path)):
                for where, value in walk(analyze_email(path)):
                    self.assertNotIsInstance(value, (bytes, bytearray), where)
                    self.assertNotEqual(value, "payload", where)
                    if isinstance(value, str):
                        value.encode("utf-8")            # raises on lone surrogates

    def test_result_can_be_stored_and_read_back_from_sqlite(self):
        db = sqlite3.connect(":memory:")
        db.execute("CREATE TABLE analyses (id INTEGER PRIMARY KEY, name TEXT, doc TEXT)")
        for path in FIXTURE_PATHS:
            db.execute("INSERT INTO analyses (name, doc) VALUES (?, ?)",
                       (os.path.basename(path), json.dumps(analyze_email(path))))
        for name, doc in db.execute("SELECT name, doc FROM analyses"):
            with self.subTest(fixture=name):
                self.assertEqual(json.loads(doc), analyze_email(fx(name)))
        db.close()

    def test_results_are_deterministic(self):
        for path in FIXTURE_PATHS:
            with self.subTest(fixture=os.path.basename(path)):
                self.assertEqual(analyze_email(path), analyze_email(path))


class SafetyContractTests(unittest.TestCase):
    def test_analysis_is_offline_read_only_and_runs_no_programs(self):
        real_open = builtins.open

        def guarded_open(file, mode="r", *args, **kwargs):
            if any(flag in str(mode) for flag in "wax+"):
                raise AssertionError(f"analysis opened {file!r} for writing")
            return real_open(file, mode, *args, **kwargs)

        def forbidden(name):
            def raiser(*args, **kwargs):
                raise AssertionError(f"analysis called {name}")
            return raiser

        with ExitStack() as stack:
            stack.enter_context(mock.patch("builtins.open", guarded_open))
            stack.enter_context(mock.patch.object(socket.socket, "connect", forbidden("socket.connect")))
            stack.enter_context(mock.patch.object(socket, "getaddrinfo", forbidden("getaddrinfo")))
            stack.enter_context(mock.patch.object(socket, "gethostbyname", forbidden("gethostbyname")))
            stack.enter_context(mock.patch.object(subprocess, "Popen", forbidden("subprocess.Popen")))
            stack.enter_context(mock.patch.object(os, "system", forbidden("os.system")))
            for path in FIXTURE_PATHS:
                with self.subTest(fixture=os.path.basename(path)):
                    result = analyze_email(path)
                    self.assertEqual(validate_result(result), [])

    def test_input_file_is_never_modified(self):
        for path in FIXTURE_PATHS:
            with self.subTest(fixture=os.path.basename(path)):
                with open(path, "rb") as fh:
                    before = hashlib.sha256(fh.read()).hexdigest()
                analyze_email(path)
                with open(path, "rb") as fh:
                    self.assertEqual(hashlib.sha256(fh.read()).hexdigest(), before)

    def test_wording_is_evidence_not_verdict(self):
        for path in FIXTURE_PATHS:
            with self.subTest(fixture=os.path.basename(path)):
                for indicator in analyze_email(path)["risk_indicators"]:
                    text = (indicator["indicator"] + " " + indicator["evidence"]).lower()
                    for word in FORBIDDEN_WORDS:
                        self.assertNotIn(word, text)
                    self.assertNotIn(indicator["severity"], ("critical", "malicious"))


class InputContractTests(unittest.TestCase):
    def test_missing_file_raises_file_not_found(self):
        with self.assertRaises(FileNotFoundError):
            analyze_email(fx("does_not_exist.eml"))

    def test_oversized_file_is_rejected(self):
        path = write_sparse_file(email_parser.MAX_EML_BYTES)
        try:
            with self.assertRaises(ValueError) as caught:
                analyze_email(path)
            self.assertIn("too large", str(caught.exception))
        finally:
            os.remove(path)

    def test_accepts_a_pathlib_path(self):
        result = analyze_email(pathlib.Path(fx("basic.eml")))
        self.assertEqual(result["headers"]["meta"]["file_name"], "basic.eml")

    def test_malformed_input_still_returns_a_valid_result(self):
        samples = {
            "empty": b"",
            "binary": b"\x00\x01\x02\xff\xfe",
            "headers_only": b"From: \nTo: \n\n",
            "bad_charset": b"Subject: =?bogus-charset?q?hi?=\nContent-Type: text/plain; charset=nope\n\n\xff\xfe",
            "no_blank_line": b"From: a@example.org",
            "long_line": b"Subject: " + b"A" * 200_000 + b"\n\nbody",
        }
        for label, data in samples.items():
            with self.subTest(sample=label):
                with tempfile.NamedTemporaryFile(suffix=".eml", delete=False) as f:
                    f.write(data)
                    path = f.name
                try:
                    result = analyze_email(path)
                finally:
                    os.remove(path)
                self.assertEqual(validate_result(result), [])
                self.assertEqual(json.loads(json.dumps(result)), result)


if __name__ == "__main__":
    unittest.main()