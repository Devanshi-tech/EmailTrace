import json
import os
import tempfile
import unittest

from analyzer import analyze_email
from analyzer import url_analyzer
from analyzer.schema import validate_result
from analyzer.url_analyzer import extract_urls_from_text

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


def html_email(body):
    return (
        b"From: a@example.org\nMessage-ID: <x@example.org>\n"
        b"MIME-Version: 1.0\nContent-Type: text/html; charset=utf-8\n\n"
        + body.encode("utf-8")
    )


def text_email(body):
    return (
        b"From: a@example.org\nMessage-ID: <x@example.org>\n"
        b"MIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\n\n"
        + body.encode("utf-8")
    )


def by_url(result):
    return {u["url"]: u for u in result["urls"]}


def url_indicators(result):
    """Only the indicators produced by the URL analyzer."""
    return [i for i in result["risk_indicators"] if i["category"] == "url"]


def find(result, text):
    return [i for i in url_indicators(result) if text in i["indicator"]]


class TextExtractionTests(unittest.TestCase):
    def test_trailing_punctuation_and_brackets(self):
        urls = extract_urls_from_text(
            "See (http://example.org/a_(b)) and http://example.org/x, then www.example.net/y."
        )
        self.assertEqual(
            urls,
            ["http://example.org/a_(b)", "http://example.org/x", "www.example.net/y"],
        )

    def test_no_false_positives(self):
        self.assertEqual(extract_urls_from_text("mail bob@www.example.com or see www. now"), [])


class FixtureExtractionTests(unittest.TestCase):
    def setUp(self):
        self.result = analyze_email(fx("urls_html.eml"))
        self.urls = by_url(self.result)

    def test_urls_extracted_deduplicated_in_order(self):
        self.assertEqual(
            [u["url"] for u in self.result["urls"]],
            [
                "https://portal.example.org/login?user=bob&next=%2Fhome",
                "http://bit.ly/3AbCdE",
                "http://203.0.113.9:8080/verify/index.php",
                "www.example.net/offers",
                "http://evil.example.tk/collect",
                "http://paypal.example.com@198.51.100.7/signin",
                "http://3232235777/pay",
                "javascript:void(0)",
                "https://cdn.example.org/pixel.gif",
                "https://portal.example.org/login",
                "https://www.example-bank.example/secure",
            ],
        )

    def test_components(self):
        rec = self.urls["https://portal.example.org/login?user=bob&next=%2Fhome"]
        self.assertEqual(rec["scheme"], "https")
        self.assertEqual(rec["hostname"], "portal.example.org")
        self.assertEqual(rec["path"], "/login")
        self.assertEqual(rec["query"], "user=bob&next=%2Fhome")
        self.assertEqual(rec["sources"], ["text/plain", "text/html"])
        self.assertEqual(rec["contexts"], ["text", "a[href]"])
        self.assertEqual(rec["flags"], [])
        bare = self.urls["www.example.net/offers"]
        self.assertIsNone(bare["scheme"])
        self.assertEqual(bare["hostname"], "www.example.net")
        self.assertEqual(bare["path"], "/offers")

    def test_ignored_urls(self):
        for url in self.urls:
            self.assertFalse(url.startswith(("mailto:", "data:")), url)

    def test_pixel_context(self):
        self.assertEqual(self.urls["https://cdn.example.org/pixel.gif"]["contexts"], ["img[src]"])

    def test_flags(self):
        expected = {
            "http://bit.ly/3AbCdE": {"url_shortener"},
            "http://203.0.113.9:8080/verify/index.php": {"ip_based"},
            "http://evil.example.tk/collect": {"suspicious_tld", "link_text_mismatch"},
            "http://paypal.example.com@198.51.100.7/signin": {"userinfo_in_url", "ip_based"},
            "http://3232235777/pay": {"ip_based", "obfuscated_ip_host"},
            "javascript:void(0)": {"dangerous_scheme"},
        }
        for url, flags in expected.items():
            self.assertEqual(set(self.urls[url]["flags"]), flags, url)
        for url in ("https://cdn.example.org/pixel.gif", "https://portal.example.org/login",
                    "https://www.example-bank.example/secure", "www.example.net/offers"):
            self.assertEqual(self.urls[url]["flags"], [], url)

    def test_link_text_recorded(self):
        self.assertEqual(
            self.urls["http://evil.example.tk/collect"]["link_text"],
            "https://www.example-bank.example/secure",
        )

    def test_indicators(self):
        expected = {
            "URL uses an IP address instead of a hostname": "medium",
            "URL hides an IP address in a numeric form": "medium",
            "URL uses a scheme that carries active or local content": "medium",
            "URL contains text before an '@' in the address": "medium",
            "Link text shows a different site than the link target": "medium",
            "URL uses a link-shortening service": "low",
            "URL uses a top-level domain from the built-in watch list": "low",
        }
        found = {i["indicator"]: i["severity"] for i in url_indicators(self.result)}
        self.assertEqual(found, expected)

    def test_indicator_evidence(self):
        ip = find(self.result, "IP address instead")[0]
        self.assertIn("3 URL(s)", ip["evidence"])
        for text in ("203.0.113.9", "198.51.100.7", "3232235777"):
            self.assertIn(text, ip["evidence"])
        self.assertIn("decodes to 192.168.1.1",
                      find(self.result, "hides an IP")[0]["evidence"])
        mismatch = find(self.result, "Link text shows")[0]["evidence"]
        self.assertIn("www.example-bank.example", mismatch)
        self.assertIn("evil.example.tk", mismatch)


class FlagDetectionTests(unittest.TestCase):
    def test_hex_ip_host(self):
        result = analyze_bytes(text_email("go http://0xC0A80001/x now"))
        rec = result["urls"][0]
        self.assertEqual(set(rec["flags"]), {"ip_based", "obfuscated_ip_host"})
        self.assertIn("192.168.0.1", find(result, "hides an IP")[0]["evidence"])

    def test_encoded_hostname_and_embedded_url(self):
        result = analyze_bytes(text_email(
            "a http://%65xample.org/x b "
            "http://tracker.example.net/r?u=http%3A%2F%2Fother.example.org%2Fpage c"
        ))
        rec = by_url(result)
        self.assertIn("encoded_hostname", rec["http://%65xample.org/x"]["flags"])
        tracker = rec["http://tracker.example.net/r?u=http%3A%2F%2Fother.example.org%2Fpage"]
        self.assertEqual(tracker["flags"], ["embedded_url_in_parameters"])
        self.assertIn("other.example.org", find(result, "embeds another URL")[0]["evidence"])

    def test_same_host_redirect_not_flagged(self):
        result = analyze_bytes(text_email("http://example.org/r?u=http%3A%2F%2Fexample.org%2Fx"))
        self.assertEqual(result["urls"][0]["flags"], [])

    def test_punycode_hostname(self):
        result = analyze_bytes(text_email("http://xn--bcher-kva.example/"))
        self.assertEqual(result["urls"][0]["flags"], ["idn_hostname"])
        self.assertIn("bücher", find(result, "non-ASCII or punycode")[0]["evidence"])

    def test_hostname_heuristics(self):
        result = analyze_bytes(text_email(
            "http://login.verify.secure.update.example.org/ and http://a-b-c-d.example.org/"
        ))
        rec = result["urls"]
        self.assertEqual(set(rec[0]["flags"]), {"many_subdomains", "hostname_keywords"})
        self.assertEqual(rec[1]["flags"], ["many_hyphens"])

    def test_control_characters_and_dangerous_scheme(self):
        result = analyze_bytes(html_email('<a href="java&#9;script:alert(1)">x</a>'))
        rec = result["urls"][0]
        self.assertEqual(rec["url"], "javascript:alert(1)")
        self.assertEqual(set(rec["flags"]), {"dangerous_scheme", "embedded_control_characters"})

    def test_unusual_scheme(self):
        result = analyze_bytes(text_email("get ftp://files.example.org/a.txt"))
        self.assertEqual(result["urls"][0]["flags"], ["unusual_scheme"])

    def test_malformed_url(self):
        result = analyze_bytes(text_email("bad http://[::1/x here"))
        rec = result["urls"][0]
        self.assertEqual(rec["flags"], ["malformed_url"])
        self.assertIsNone(rec["hostname"])

    def test_link_text_same_site_not_flagged(self):
        result = analyze_bytes(html_email(
            '<a href="https://www.example.org/a">example.org</a>'
            '<a href="https://example.org/f.pdf">invoice.pdf</a>'
        ))
        for rec in result["urls"]:
            self.assertNotIn("link_text_mismatch", rec["flags"])

    def test_meta_refresh_and_css_urls(self):
        result = analyze_bytes(html_email(
            '<meta http-equiv="refresh" content="0; url=http://r.example.org/go">'
            '<div style="background:url(https://img.example.org/bg.png)">x</div>'
        ))
        contexts = {u["url"]: u["contexts"] for u in result["urls"]}
        self.assertEqual(contexts["http://r.example.org/go"], ["meta[refresh]"])
        self.assertEqual(contexts["https://img.example.org/bg.png"], ["div[style]"])


class RobustnessTests(unittest.TestCase):
    def test_no_urls(self):
        result = analyze_bytes(text_email("nothing to see here"))
        self.assertEqual(result["urls"], [])
        self.assertEqual(url_indicators(result), [])

    def test_url_cap(self):
        body = " ".join(f"http://h{i}.example.org/" for i in range(url_analyzer.MAX_URLS + 5))
        result = analyze_bytes(text_email(body))
        self.assertEqual(len(result["urls"]), url_analyzer.MAX_URLS)
        warnings = result["headers"]["meta"]["warnings"]
        self.assertTrue(any("capped" in w for w in warnings))

    def test_output_valid_json(self):
        result = analyze_email(fx("urls_html.eml"))
        self.assertEqual(validate_result(result), [])
        json.dumps(result)

    def test_module_never_imports_network_libraries(self):
        with open(url_analyzer.__file__, encoding="utf-8") as fh:
            imports = [l for l in fh if l.startswith(("import ", "from "))]
        for line in imports:
            for banned in ("socket", "urllib.request", "http.client", "requests", "urllib3"):
                self.assertNotIn(banned, line)

    def test_no_verdict_language(self):
        text = " ".join(
            (i["indicator"] + " " + i["evidence"]).lower()
            for i in analyze_email(fx("urls_html.eml"))["risk_indicators"]
        )
        for word in ("malicious", "phishing", "fraud"):
            self.assertNotIn(word, text)


if __name__ == "__main__":
    unittest.main()