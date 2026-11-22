"""
test_api.py
-----------
Automated tests for the Flask API. Uses a TEMPORARY database, so your real
scan history is never touched.

Run:  python backend/test_api.py
"""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import app as app_module


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        app_module.DB_PATH = Path(cls.tmp.name) / "test.db"   # use a throwaway DB
        app_module.init_db()

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        self.client = app_module.app.test_client()
        self.client.delete("/api/history")                    # start every test empty

    def scan(self, url):
        return self.client.post("/api/scan", json={"url": url})

    # ---------------- health ----------------
    def test_health_reports_model_loaded(self):
        r = self.client.get("/api/health")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json()["model_loaded"])

    # ---------------- scanning ----------------
    def test_scan_returns_expected_fields(self):
        r = self.scan("https://www.wikipedia.org")
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        for key in ["label", "level", "risk_score", "model_probability", "rule_points",
                    "status", "explanation", "indicators", "features", "disclaimer", "id"]:
            self.assertIn(key, d)
        self.assertIn(d["label"], ["Low Risk", "Suspicious", "Phishing"])
        self.assertTrue(0 <= d["risk_score"] <= 100)
        self.assertTrue(0 <= d["model_probability"] <= 1)

    def test_url_without_scheme_gets_https(self):
        d = self.scan("example.com").get_json()
        self.assertEqual(d["url"], "https://example.com")
        self.assertTrue(d["scheme_assumed"])

    def test_model_alone_cannot_label_phishing(self):
        # No rule fires for a clean HTTPS URL, so the score is capped below 70.
        d = self.scan("https://www.wikipedia.org").get_json()
        self.assertEqual(d["indicators"], [])
        self.assertLess(d["risk_score"], 70)
        self.assertNotEqual(d["label"], "Phishing")

    def test_at_symbol_url_is_flagged(self):
        d = self.scan("http://paypal.com@evil-site.xyz/secure").get_json()
        self.assertTrue(any("@" in i["text"] for i in d["indicators"]))
        self.assertNotEqual(d["label"], "Low Risk")
        self.assertGreaterEqual(d["risk_score"], 55)

    def test_ip_address_url_is_flagged(self):
        d = self.scan("http://192.168.10.5/login/verify.php").get_json()
        self.assertTrue(any("IP" in i["text"] for i in d["indicators"]))
        self.assertNotEqual(d["label"], "Low Risk")

    def test_scan_never_opens_a_network_connection(self):
        # If any code tried to connect to the submitted site, this would raise.
        with mock.patch("socket.socket.connect", side_effect=AssertionError("network used!")):
            r = self.scan("http://paypal.com@evil-site.xyz/secure")
        self.assertEqual(r.status_code, 200)

    # ---------------- invalid input ----------------
    def test_invalid_urls_return_400(self):
        for bad in ["", "   ", "http:facebook.com", "ftp://example.com", "not a url",
                    "https://" + "a" * 3000 + ".com", 123]:
            with self.subTest(url=bad):
                r = self.scan(bad)
                self.assertEqual(r.status_code, 400)
                self.assertIn("error", r.get_json())

    def test_missing_or_non_json_body_returns_400(self):
        r = self.client.post("/api/scan", json={"wrong": "field"})
        self.assertEqual(r.status_code, 400)
        r = self.client.post("/api/scan", data="hello", content_type="text/plain")
        self.assertEqual(r.status_code, 400)

    def test_unknown_route_and_wrong_method_return_json_errors(self):
        r = self.client.get("/api/does-not-exist")
        self.assertEqual(r.status_code, 404)
        self.assertIn("error", r.get_json())
        r = self.client.get("/api/scan")           # scan only accepts POST
        self.assertIn(r.status_code, (404, 405))   # Flask may answer either; both are errors
        self.assertIn("error", r.get_json())

    # ---------------- history ----------------
    def test_history_saves_and_reopens_a_scan(self):
        scan_id = self.scan("https://github.com").get_json()["id"]
        hist = self.client.get("/api/history").get_json()
        self.assertEqual(hist["count"], 1)
        self.assertEqual(hist["scans"][0]["url"], "https://github.com")
        item = self.client.get(f"/api/history/{scan_id}")
        self.assertEqual(item.status_code, 200)
        self.assertIn("indicators", item.get_json())

    def test_history_missing_item_and_bad_limit(self):
        self.assertEqual(self.client.get("/api/history/99999").status_code, 404)
        self.assertEqual(self.client.get("/api/history?limit=abc").status_code, 400)

    def test_delete_history_clears_everything(self):
        self.scan("https://github.com")
        self.scan("https://www.wikipedia.org")
        d = self.client.delete("/api/history").get_json()
        self.assertEqual(d["deleted"], 2)
        self.assertEqual(self.client.get("/api/history").get_json()["count"], 0)

    # ---------------- per-visitor separation ----------------
    def test_each_visitor_sees_only_their_own_history(self):
        a = app_module.app.test_client()
        b = app_module.app.test_client()          # separate cookie jar = different visitor
        a.post("/api/scan", json={"url": "https://github.com"})
        self.assertEqual(a.get("/api/history").get_json()["count"], 1)
        self.assertEqual(b.get("/api/history").get_json()["count"], 0)
        self.assertEqual(b.get("/api/dashboard").get_json()["total_scans"], 0)
        a_id = a.get("/api/history").get_json()["scans"][0]["id"]
        self.assertEqual(b.get(f"/api/history/{a_id}").status_code, 404)
        b.delete("/api/history")                  # must not touch A's scans
        self.assertEqual(a.get("/api/history").get_json()["count"], 1)

    # ---------------- dashboard ----------------
    def test_dashboard_is_zero_when_empty(self):
        d = self.client.get("/api/dashboard").get_json()
        self.assertEqual(d["total_scans"], 0)
        self.assertIsNone(d["average_risk_score"])
        self.assertEqual(len(d["per_day"]), 7)

    def test_dashboard_counts_match_scans(self):
        for u in ["https://github.com", "http://192.168.10.5/login/verify.php",
                  "http://paypal.com@evil-site.xyz/secure"]:
            self.scan(u)
        d = self.client.get("/api/dashboard").get_json()
        self.assertEqual(d["total_scans"], 3)
        self.assertEqual(d["phishing"] + d["suspicious"] + d["low_risk"], 3)
        self.assertEqual(len(d["recent"]), 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)