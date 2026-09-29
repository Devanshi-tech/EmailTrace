import os
import tempfile
import unittest

from analyzer import analyze_email

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


class ReceivedParsingTests(unittest.TestCase):
    def setUp(self):
        self.result = analyze_email(fx("received_chain.eml"))
        self.hops = self.result["received_paths"]

    def test_order_and_hosts_preserved(self):
        self.assertEqual([h["index"] for h in self.hops], [0, 1, 2])
        self.assertEqual([h["from_host"] for h in self.hops],
                         ["mx1.example.com", "relay.example.org", "laptop.local"])
        self.assertEqual([h["by_host"] for h in self.hops],
                         ["mail.example.com", "mx1.example.com", "relay.example.org"])

    def test_hop_fields(self):
        hop = self.hops[0]
        self.assertEqual(hop["from_ip"], "198.51.100.20")
        self.assertEqual(hop["protocol"], "ESMTPS")
        self.assertEqual(hop["server_id"], "3ABC123")
        self.assertEqual(hop["timestamp_utc"], "2026-01-05T10:15:30+00:00")

    def test_ip_literal_and_helo(self):
        hop = self.hops[2]
        self.assertEqual(hop["from_ip"], "192.168.1.44")
        self.assertEqual(hop["from_host"], "laptop.local")
        self.assertEqual(hop["protocol"], "esmtpsa")
        self.assertEqual(hop["server_id"], "1abCde-000123-Zx")

    def test_routing_summary(self):
        routing = self.result["headers"]["routing"]
        self.assertEqual(routing["hop_count"], 3)
        self.assertEqual(routing["originating_host"], "laptop.local")
        self.assertEqual(routing["originating_ip"], "192.168.1.44")
        self.assertEqual(routing["final_receiving_host"], "mail.example.com")

    def test_ipv6_received(self):
        result = analyze_bytes(
            b"From: a@example.org\n"
            b"Received: from mx.example.com (mx.example.com [IPv6:2001:db8::25])\n"
            b"\tby mail.example.com with ESMTP id X1; Mon, 05 Jan 2026 10:00:00 +0000\n\nhi"
        )
        self.assertEqual(result["received_paths"][0]["from_ip"], "2001:db8::25")

    def test_by_only_hop(self):
        result = analyze_bytes(
            b"From: a@example.org\n"
            b"Received: by 2002:a05:6a20:1 with SMTP id abc123; "
            b"Mon, 05 Jan 2026 10:00:00 +0000\n\nhi"
        )
        hop = result["received_paths"][0]
        self.assertIsNone(hop["from_host"])
        self.assertIsNone(hop["from_ip"])
        self.assertEqual(hop["by_host"], "2002:a05:6a20:1")
        self.assertEqual(hop["protocol"], "SMTP")
        self.assertEqual(find(result, "could not be parsed"), [])
        self.assertIsNone(result["headers"]["routing"]["originating_host"])


class TimestampTests(unittest.TestCase):
    def test_records_for_chain(self):
        result = analyze_email(fx("received_chain.eml"))
        records = result["timestamps"]
        self.assertEqual([r["source"] for r in records],
                         ["date", "received[0]", "received[1]", "received[2]"])
        self.assertTrue(all(r["status"] == "ok" for r in records))
        self.assertEqual(records[0]["normalized_utc"], "2026-01-05T10:15:00+00:00")

    def test_consistent_chain_has_no_timestamp_indicators(self):
        result = analyze_email(fx("received_chain.eml"))
        flagged = [i for i in result["risk_indicators"] if i["category"] == "timestamp"]
        self.assertEqual(flagged, [])

    def test_bad_order_flagged(self):
        result = analyze_email(fx("received_bad_order.eml"))
        found = find(result, "out of order")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["severity"], "medium")
        self.assertIn("received[1]", found[0]["evidence"])
        self.assertIn("received[0]", found[0]["evidence"])
        self.assertIn("2h 30m", found[0]["evidence"])

    def test_malformed_received_timestamp(self):
        result = analyze_email(fx("received_bad_order.eml"))
        record = [t for t in result["timestamps"] if t["source"] == "received[2]"][0]
        self.assertEqual(record["status"], "malformed")
        self.assertIsNone(record["normalized_utc"])
        found = find(result, "timestamp is malformed")
        self.assertEqual(found[0]["severity"], "low")
        self.assertIn("received[2]", found[0]["evidence"])

    def test_missing_date_and_no_received(self):
        result = analyze_bytes(b"From: a@example.org\n\nhi")
        self.assertEqual(result["timestamps"][0]["status"], "missing")
        self.assertEqual(find(result, "Date header is missing")[0]["severity"], "low")
        self.assertEqual(find(result, "No Received headers found")[0]["severity"], "info")

    def test_date_after_received(self):
        result = analyze_bytes(
            b"From: a@example.org\n"
            b"Date: Mon, 05 Jan 2026 12:00:00 +0000\n"
            b"Received: from a.example.com (a.example.com [198.51.100.1]) "
            b"by b.example.com with ESMTP id A1; Mon, 05 Jan 2026 10:00:00 +0000\n\nhi"
        )
        found = find(result, "Date header is later than")
        self.assertEqual(found[0]["severity"], "low")

    def test_no_timezone_assumes_utc(self):
        result = analyze_bytes(
            b"From: a@example.org\nDate: Mon, 05 Jan 2026 10:00:00 -0000\n\nhi"
        )
        record = result["timestamps"][0]
        self.assertEqual(record["status"], "ok")
        self.assertEqual(record["normalized_utc"], "2026-01-05T10:00:00+00:00")
        warnings = result["headers"]["meta"]["warnings"]
        self.assertTrue(any("no timezone" in w for w in warnings))

    def test_no_verdict_language(self):
        for name in ("received_chain.eml", "received_bad_order.eml"):
            text = " ".join(
                (i["indicator"] + " " + i["evidence"]).lower()
                for i in analyze_email(fx(name))["risk_indicators"]
            )
            for word in ("malicious", "phishing", "fraud"):
                self.assertNotIn(word, text)


if __name__ == "__main__":
    unittest.main()