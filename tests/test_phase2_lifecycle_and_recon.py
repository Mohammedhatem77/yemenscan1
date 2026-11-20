import os
import sys
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

import unittest
from unittest.mock import patch, MagicMock

from core.template_updater import (
    get_template_status,
    run_template_update_job,
    count_templates,
    _save_status,
)
from core.tasks import dispatch_template_update
from core.origin_recon import (
    detect_waf_presence,
    is_ip_in_cdn,
    find_candidate_origin_ips,
    verify_origin_ip,
    run_origin_recon
)


class TestPhase2LifecycleAndRecon(unittest.TestCase):
    """
    Unit test suite for Phase 2:
    - Nuclei Template Lifecycle & Validation Sandbox (Task 2.1, 2.2)
    - Celery Background Task Dispatcher (Task 2.1)
    - Origin IP Reconnaissance & WAF Bypass (Task 2.4)
    """

    def setUp(self):
        _save_status({
            "status": "idle",
            "last_updated_at": "2026-11-18T20:00:00Z",
            "total_templates": 10972,
            "upstream_version": "v10.5.1",
            "last_validation": "passed",
            "last_error": None
        })

    def tearDown(self):
        _save_status({
            "status": "idle",
            "last_updated_at": "2026-11-18T20:00:00Z",
            "total_templates": 10972,
            "upstream_version": "v10.5.1",
            "last_validation": "passed",
            "last_error": None
        })

    def test_01_template_status_retrieval(self):
        status = get_template_status()
        self.assertIn("status", status)
        self.assertIn("total_templates", status)
        self.assertIn("upstream_version", status)
        self.assertGreaterEqual(status["total_templates"], 0)

    @patch("core.template_updater.validate_templates_in_sandbox")
    @patch("core.template_updater.run_docker_tool")
    def test_02_run_template_update_job_success(self, mock_docker, mock_val):
        mock_docker.return_value = (True, "Download OK")
        mock_val.return_value = (True, "Validation passed")

        res = run_template_update_job()
        self.assertEqual(res["status"], "success")
        self.assertIn("total_templates", res)

    @patch("core.template_updater.run_template_update_job")
    @patch("core.tasks.is_celery_broker_reachable")
    def test_03_dispatch_template_update_celery_and_fallback(self, mock_reachable, mock_job):
        mock_reachable.return_value = False
        res = dispatch_template_update()
        self.assertEqual(res["status"], "started")
        self.assertEqual(res["mode"], "background_tasks")

    def test_04_cdn_ip_detection(self):
        # Cloudflare IP
        is_cf, prov = is_ip_in_cdn("104.16.12.34")
        self.assertTrue(is_cf)
        self.assertEqual(prov, "Cloudflare")

        # Non-CDN Private or Generic IP
        is_generic, prov2 = is_ip_in_cdn("192.168.1.100")
        self.assertFalse(is_generic)
        self.assertIsNone(prov2)

    @patch("core.origin_recon.resolve_domain_ips")
    def test_05_detect_waf_presence(self, mock_dns):
        mock_dns.return_value = ["104.16.1.1"]
        res = detect_waf_presence("example.com")
        self.assertTrue(res["is_behind_waf"])
        self.assertEqual(res["waf_provider"], "Cloudflare")

    @patch("requests.get")
    def test_06_verify_origin_ip_matching(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "<html><title>Target Company Portal</title><body>Welcome to target.com</body></html>"
        mock_get.return_value = mock_resp

        verified, evidence = verify_origin_ip("198.51.100.25", "target.com", baseline_title="Target Company Portal")
        self.assertTrue(verified)
        self.assertIn("198.51.100.25", evidence)

    @patch("core.origin_recon.detect_waf_presence")
    @patch("core.origin_recon.find_candidate_origin_ips")
    @patch("core.origin_recon.verify_origin_ip")
    def test_07_run_origin_recon_orchestrator(self, mock_verify, mock_candidates, mock_waf):
        mock_waf.return_value = {
            "domain": "target.com",
            "is_behind_waf": True,
            "waf_provider": "Cloudflare",
            "current_ips": ["104.21.5.12"],
            "headers_sample": {}
        }
        mock_candidates.return_value = ["198.51.100.50"]
        mock_verify.return_value = (True, "Direct backend 200 OK verified")

        res = run_origin_recon("target.com")
        self.assertEqual(res["status"], "success")
        self.assertTrue(res["is_behind_waf"])
        self.assertTrue(res["waf_bypassed"])
        self.assertTrue(res["origin_discovered"])
        self.assertEqual(len(res["verified_origins"]), 1)
        self.assertEqual(res["verified_origins"][0]["origin_ip"], "198.51.100.50")


if __name__ == "__main__":
    unittest.main()
