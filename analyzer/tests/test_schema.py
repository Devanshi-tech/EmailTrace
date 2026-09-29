import json
import os
import tempfile
import unittest

from analyzer import analyze_email
from analyzer.schema import (
    TOP_LEVEL_KEYS,
    empty_result,
    make_indicator,
    make_ioc,
    validate_result,
)


class SchemaTests(unittest.TestCase):
    def test_empty_result_has_exact_top_level_keys(self):
        self.assertEqual(tuple(empty_result().keys()), TOP_LEVEL_KEYS)

    def test_empty_result_is_json_serializable(self):
        json.dumps(empty_result())

    def test_empty_result_returns_fresh_copy(self):
        a, b = empty_result(), empty_result()
        a["iocs"].append("x")
        self.assertEqual(b["iocs"], [])

    def test_make_indicator_valid(self):
        ind = make_indicator("Reply-To differs", "medium", "a.com vs b.com", "header")
        self.assertEqual(ind["severity"], "medium")

    def test_make_indicator_rejects_bad_severity(self):
        with self.assertRaises(ValueError):
            make_indicator("x", "malicious", "e", "header")

    def test_make_ioc_rejects_bad_type(self):
        with self.assertRaises(ValueError):
            make_ioc("banana", "v", "s")

    def test_validate_detects_missing_key(self):
        result = empty_result()
        del result["urls"]
        self.assertTrue(any("missing keys" in p for p in validate_result(result)))

    def test_analyze_email_stub_returns_valid_schema(self):
        with tempfile.NamedTemporaryFile(suffix=".eml", delete=False) as f:
            f.write(b"From: a@example.com\r\n\r\nhi")
            path = f.name
        try:
            result = analyze_email(path)
            self.assertEqual(validate_result(result), [])
            self.assertEqual(result["headers"]["meta"]["file_name"], os.path.basename(path))
        finally:
            os.remove(path)


if __name__ == "__main__":
    unittest.main()