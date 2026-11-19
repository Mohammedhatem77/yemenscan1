import os
import sys
import json
import tempfile
import unittest
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from fastapi.testclient import TestClient
from main import app, get_session_dir


class TestStage4UiReporting(unittest.TestCase):
    """
    Unit test suite for Phase 4:
    - /api/scan/{scan_id}/status exposes waf_bypass intelligence.
    - /api/scan/{scan_id}/vulnerabilities includes waf_bypass and tags origin findings.
    - /api/scan/{scan_id}/export/json contains waf_bypass section.
    - templates/index.html includes UI metric card and badges for WAF & Origin Recon.
    """

    def setUp(self):
        self.client = TestClient(app)
        self.test_scan_id = "test_scan_ui_phase4"
        self.session_dir = get_session_dir(self.test_scan_id)
        os.makedirs(self.session_dir, exist_ok=True)

        self.waf_data = {
            "status": "success",
            "domain": "vulterx.com",
            "is_behind_waf": True,
            "waf_provider": "Cloudflare",
            "waf_bypassed": True,
            "verified_origins": [
                {
                    "origin_ip": "195.201.45.10",
                    "verified": True,
                    "confidence": "HIGH",
                    "evidence": "Host header match"
                }
            ]
        }
        with open(os.path.join(self.session_dir, "waf_bypass.json"), "w", encoding="utf-8") as wf:
            json.dump(self.waf_data, wf)

        # Mock status.json
        status_data = {
            "scan_id": self.test_scan_id,
            "target_domain": "vulterx.com",
            "current_stage": "completed",
            "is_completed": True,
            "progress_percentage": 100,
            "logs": ["Scan completed."],
            "stats": {
                "subdomains_count": 1,
                "open_ports_count": 2,
                "live_urls_count": 1,
                "api_endpoints_count": 0,
                "vulnerabilities_count": 1
            }
        }
        with open(os.path.join(self.session_dir, "status.json"), "w", encoding="utf-8") as sf:
            json.dump(status_data, sf)

        # Mock unified_vulnerabilities.json
        vuln_data = [
            {
                "id": "CVE-2023-1234",
                "title": "SQL Injection in Search",
                "severity": "HIGH",
                "url": "https://vulterx.com/search",
                "description": "SQL injection flaw",
                "remediation": "Use parameterized queries",
                "waf_bypassed": True,
                "origin_ip": "195.201.45.10",
                "bypassed_origin": True
            }
        ]
        with open(os.path.join(self.session_dir, "unified_vulnerabilities.json"), "w", encoding="utf-8") as vf:
            json.dump(vuln_data, vf)

    def tearDown(self):
        import shutil
        if os.path.exists(self.session_dir):
            shutil.rmtree(self.session_dir, ignore_errors=True)

    def test_status_endpoint_includes_waf_bypass(self):
        res = self.client.get(f"/api/scan/{self.test_scan_id}/status")
        self.assertEqual(res.status_code, 200)
        data = res.json().get("data", {})
        waf = data.get("waf_bypass", {})
        self.assertTrue(waf.get("waf_bypassed"))
        self.assertEqual(waf.get("waf_provider"), "Cloudflare")
        self.assertEqual(waf.get("verified_origins")[0]["origin_ip"], "195.201.45.10")

    def test_vulnerabilities_endpoint_includes_waf_and_origin_tags(self):
        res = self.client.get(f"/api/scan/{self.test_scan_id}/vulnerabilities")
        self.assertEqual(res.status_code, 200)
        json_data = res.json()
        waf = json_data.get("waf_bypass", {})
        self.assertTrue(waf.get("waf_bypassed"))
        vulns = json_data.get("vulnerabilities", [])
        self.assertEqual(len(vulns), 1)
        self.assertTrue(vulns[0].get("waf_bypassed"))
        self.assertEqual(vulns[0].get("origin_ip"), "195.201.45.10")
        self.assertTrue(vulns[0].get("bypassed_origin"))

    def test_export_json_includes_waf_bypass(self):
        res = self.client.get(f"/api/scan/{self.test_scan_id}/export/json")
        self.assertEqual(res.status_code, 200)
        export_data = res.json()
        waf = export_data.get("waf_bypass", {})
        self.assertTrue(waf.get("waf_bypassed"))
        self.assertEqual(waf.get("waf_provider"), "Cloudflare")

    def test_index_html_has_waf_elements(self):
        html_path = os.path.join(_PROJECT_ROOT, "templates", "index.html")
        with open(html_path, "r", encoding="utf-8") as f:
            html = f.read()

        self.assertIn("statWafStatus", html)
        self.assertIn("metricWafCard", html)
        self.assertIn("originBypassBadge", html)
        self.assertIn("سيرفر الأصل", html)


if __name__ == "__main__":
    unittest.main()
