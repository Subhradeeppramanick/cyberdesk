#!/usr/bin/env python3
"""Offline unit tests for CyberDesk. No network required."""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import bankintel
import server
import triage
import urlintel


class TestTriage(unittest.TestCase):
    def test_phishing_routes_correctly(self):
        r = triage.categorize(
            "Got an SMS that my account will be blocked. Clicked the link, "
            "entered netbanking password and OTP, money was debited.")
        self.assertEqual(r["category"], "Phishing")
        self.assertIn("otp", r["matched_keywords"])
        self.assertEqual(r["method"], "rules")

    def test_upi_fraud_routes_correctly(self):
        r = triage.categorize(
            "A caller made me scan a QR code on PhonePe for a refund and 24999 was debited.")
        self.assertEqual(r["category"], "UPI / Payment Fraud")

    def test_unknown_text_falls_back(self):
        r = triage.categorize("my neighbour's wifi is slow")
        self.assertEqual(r["category"], triage.OTHER)

    def test_empty_text_is_safe(self):
        r = triage.categorize("")
        self.assertEqual(r["category"], triage.OTHER)


class TestIOCExtraction(unittest.TestCase):
    def test_extracts_indicators(self):
        iocs = triage.extract_iocs(
            "Paid via payee-demo-1@example after visiting http://evil-example.top/login "
            "from 203.0.113.7; called +91 90000 00000; IFSC SBIN0000001; mail a@b.in")
        self.assertTrue(any("evil-example.top" in u for u in iocs["urls"]))
        self.assertIn("203.0.113.7", iocs["ips"])
        self.assertIn("payee-demo-1@example", iocs["upi_handles"])
        self.assertIn("SBIN0000001", iocs["ifsc_codes"])
        self.assertIn("a@b.in", iocs["emails"])

    def test_rejects_invalid_ip_octets(self):
        iocs = triage.extract_iocs("order 999.999.999.999 was placed")
        self.assertEqual(iocs["ips"], [])


class TestURLIntel(unittest.TestCase):
    def test_brand_impersonation_scores_high(self):
        r = urlintel.analyze_url("http://sbi-kyc-verify.example/login", live=False)
        self.assertGreaterEqual(r["score"], 50)
        self.assertEqual(r["verdict"], "LIKELY PHISHING")
        signals = {s["signal"] for s in r["signals"]}
        self.assertIn("brand-impersonation", signals)

    def test_ip_literal_flagged(self):
        r = urlintel.analyze_url("http://192.0.2.10/update", live=False)
        self.assertIn("ip-literal-host", {s["signal"] for s in r["signals"]})

    def test_clean_url_scores_low(self):
        r = urlintel.analyze_url("https://www.python.org/about/", live=False)
        self.assertLess(r["score"], 25)

    def test_scheme_added_when_missing(self):
        r = urlintel.analyze_url("example.com", live=False)
        self.assertEqual(r["host"], "example.com")


class TestSafety(unittest.TestCase):
    def test_default_analysis_is_offline(self):
        r = urlintel.analyze_url("http://localhost/login")
        self.assertNotIn("dns", r)
        self.assertNotIn("tls", r)
        self.assertIn("offline", r["method"])

    def test_private_and_loopback_hosts_are_blocked(self):
        for host in ("localhost", "127.0.0.1", "10.0.0.5", "169.254.169.254", "192.168.1.1"):
            with self.assertRaises(ValueError, msg=host):
                urlintel._public_addresses(host)
        self.assertIn("non-public", urlintel.tls_expiry("localhost")["error"])
        self.assertFalse(urlintel.dns_lookup("127.0.0.1")["live"])

    def test_ifsc_default_is_offline(self):
        r = bankintel.lookup_ifsc("SBIN0000001")
        self.assertIn("offline sample", r["source"])

    def test_no_known_real_world_identifiers_in_case_data(self):
        with open(server.CASES_FILE, encoding="utf-8") as fh:
            raw = fh.read()
        self.assertNotRegex(raw, r"\b[6-9]\d{9}\b")
        self.assertNotRegex(raw, r"@(?:ybl|okhdfcbank|okicici|oksbi|okaxis|paytm)\b")
        for tld in (".top", ".xyz", ".info"):
            self.assertNotIn(tld + "/", raw)


class TestServerEndpoints(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import threading
        import urllib.request
        cls.urllib = urllib.request
        cls.httpd = server.ThreadingHTTPServer(("127.0.0.1", 0), server.CyberDeskHandler)
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()
        server._hits.clear()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

    def post(self, path, payload):
        import urllib.error
        req = self.urllib.Request(self.base + path, data=json.dumps(payload).encode(),
                                  headers={"Content-Type": "application/json"})
        try:
            with self.urllib.urlopen(req) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as err:
            return err.code, json.loads(err.read())

    def test_free_text_triage_is_rejected(self):
        status, body = self.post("/api/triage", {"text": "my real complaint"})
        self.assertEqual(status, 400)
        self.assertIn("fictional", body["error"])

    def test_sample_triage_works(self):
        sid = server.load_cases()["cases"][0]["id"]
        status, body = self.post("/api/triage", {"sample_id": sid})
        self.assertEqual(status, 200)
        self.assertEqual(body["category"], "Phishing")

    def test_analyze_endpoint_makes_no_network_checks(self):
        status, body = self.post("/api/analyze", {"url": "http://127.0.0.1/x"})
        self.assertEqual(status, 200)
        self.assertNotIn("dns", body)

    def test_security_headers_present(self):
        with self.urllib.urlopen(self.base + "/api/stats") as resp:
            self.assertEqual(resp.headers["X-Content-Type-Options"], "nosniff")


class TestBankIntel(unittest.TestCase):
    def test_format_validation(self):
        self.assertTrue(bankintel.validate_ifsc("SBIN0000001"))
        self.assertTrue(bankintel.validate_ifsc("sbin0000001"))  # case-insensitive
        self.assertFalse(bankintel.validate_ifsc("SBIN1000001"))  # 5th char must be 0
        self.assertFalse(bankintel.validate_ifsc("SBIN001"))      # too short
        self.assertFalse(bankintel.validate_ifsc(""))

    def test_invalid_format_rejected(self):
        r = bankintel.lookup_ifsc("not-an-ifsc", live=False)
        self.assertFalse(r["valid_format"])
        self.assertFalse(r["found"])

    def test_offline_sample(self):
        r = bankintel.lookup_ifsc("SBIN0000001", live=False)
        self.assertTrue(r["found"])
        self.assertEqual(r["bank"], "State Bank of India")
        self.assertIn("offline sample", r["source"])

    def test_unknown_code_reports_not_found(self):
        r = bankintel.lookup_ifsc("ZZZZ0999999", live=False)
        self.assertTrue(r["valid_format"])
        self.assertFalse(r["found"])


class TestCaseData(unittest.TestCase):
    def test_case_file_integrity(self):
        data = server.load_cases()
        self.assertTrue(data["fictional"])
        self.assertGreaterEqual(len(data["cases"]), 8)
        for case in data["cases"]:
            for key in ("id", "title", "category", "status", "priority",
                        "complainant", "filed_on", "narrative", "timeline"):
                self.assertIn(key, case, f"{case.get('id')} missing {key}")
            self.assertTrue(case["id"].startswith("CD-"))
            self.assertGreaterEqual(len(case["timeline"]), 2)

    def test_stats_add_up(self):
        cases = server.load_cases()["cases"]
        stats = server.build_stats(cases)
        self.assertEqual(stats["total"], len(cases))
        self.assertEqual(sum(stats["by_category"].values()), len(cases))
        self.assertEqual(sum(stats["by_status"].values()), len(cases))

    def test_every_case_category_is_known(self):
        for case in server.load_cases()["cases"]:
            self.assertIn(case["category"], triage.CATEGORIES)


if __name__ == "__main__":
    unittest.main(verbosity=2)
