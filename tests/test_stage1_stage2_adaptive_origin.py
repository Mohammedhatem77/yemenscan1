import os
import sys
import json
import tempfile
import unittest
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from core.scope_classifier import classify_scope
from core.stage1_discovery import run_naabu, ORIGIN_SENSITIVE_PORTS, NAABU_PORTS
from core.stage2_web_probing import run_httpx


class TestStage1Stage2AdaptiveOrigin(unittest.TestCase):
    """
    Unit test suite for Phase 2:
    - Scope Classifier recognizes confirmed Origin IP as in-scope self-hosted backend.
    - Naabu adapts target list and sensitive port range when Origin IP is detected.
    - HTTPX executes Host-header virtual host probe on Origin IP and marks is_origin.
    """

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="yemscan_test_phase2_")

    def tearDown(self):
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_scope_classifier_origin_ip_is_in_scope(self):
        # Even though 195.201.45.10 does not string-match example.com, passing origin_ip ensures in_scope_full
        res = classify_scope(
            url="http://195.201.45.10:8080",
            host="195.201.45.10",
            root_domain="example.com",
            origin_ip="195.201.45.10"
        )
        self.assertFalse(res["is_third_party"])
        self.assertEqual(res["hosting_type"], "self_hosted_origin")
        self.assertEqual(res["scope_tag"], "in_scope_full")
        self.assertTrue(res["scope_badge"]["dast_allowed"])

    @patch("core.stage1_discovery.run_docker_tool")
    def test_naabu_adaptive_origin_routing(self, mock_docker):
        mock_docker.return_value = (True, '{"host":"195.201.45.10","port":"80"}\n{"host":"195.201.45.10","port":"22"}')

        # Setup mock waf_bypass.json in session directory
        waf_data = {
            "is_behind_waf": True,
            "waf_provider": "Cloudflare",
            "waf_bypassed": True,
            "verified_origins": [{"origin_ip": "195.201.45.10", "verified": True}]
        }
        with open(os.path.join(self.temp_dir, "waf_bypass.json"), "w", encoding="utf-8") as wf:
            json.dump(waf_data, wf)

        ok, ports = run_naabu(["example.com"], self.temp_dir, "test_scan_id")
        self.assertTrue(ok)
        self.assertIn("195.201.45.10:80", ports)
        self.assertIn("195.201.45.10:22", ports)

        # Check docker args used ORIGIN_SENSITIVE_PORTS
        call_args = mock_docker.call_args[1].get("args") or mock_docker.call_args[0][1]
        p_idx = call_args.index("-p")
        self.assertEqual(call_args[p_idx + 1], ORIGIN_SENSITIVE_PORTS)

        # Check metadata
        meta_file = os.path.join(self.temp_dir, "naabu_metadata.json")
        with open(meta_file, "r", encoding="utf-8") as mf:
            m = json.load(mf)
            self.assertEqual(m.get("origin_ip"), "195.201.45.10")
            self.assertIn("195.201.45.10:22", m.get("origin_ports", []))

    @patch("core.stage2_web_probing.run_docker_tool")
    def test_httpx_adaptive_origin_probing(self, mock_docker):
        # Create ports.txt with both domain and origin IP
        ports_content = "example.com:443\n195.201.45.10:80\n"
        with open(os.path.join(self.temp_dir, "ports.txt"), "w", encoding="utf-8") as pf:
            pf.write(ports_content)

        waf_data = {
            "domain": "example.com",
            "is_behind_waf": True,
            "waf_provider": "Cloudflare",
            "waf_bypassed": True,
            "verified_origins": [{"origin_ip": "195.201.45.10", "verified": True}]
        }
        with open(os.path.join(self.temp_dir, "waf_bypass.json"), "w", encoding="utf-8") as wf:
            json.dump(waf_data, wf)

        # Mock docker output
        mock_docker.return_value = (
            True,
            '{"url":"https://example.com","input":"example.com:443","host":"example.com","port":"443","status_code":200}\n'
            '{"url":"http://195.201.45.10","input":"195.201.45.10:80","host":"195.201.45.10","port":"80","status_code":200}'
        )

        ok, web_targets, active_urls = run_httpx(self.temp_dir, "test_scan_id")
        self.assertTrue(ok)
        self.assertIn("http://195.201.45.10", active_urls)

        # Verify origin web target has is_origin=True and in_scope_full
        origin_wt = next((wt for wt in web_targets if wt["host"] == "195.201.45.10"), None)
        self.assertIsNotNone(origin_wt)
        self.assertTrue(origin_wt.get("is_origin"))
        self.assertEqual(origin_wt.get("origin_ip"), "195.201.45.10")
        self.assertEqual(origin_wt.get("scope_tag"), "in_scope_full")


if __name__ == "__main__":
    unittest.main()
