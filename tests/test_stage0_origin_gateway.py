import os
import sys
import json
import unittest
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from core.origin_recon import (
    is_candidate_subdomain_in_scope,
    is_ip_associated_with_cloud_saas,
    find_candidate_origin_ips,
    load_waf_bypass_info,
    run_origin_recon
)


class TestStage0OriginGateway(unittest.TestCase):
    """
    Unit test suite for Stage 0 (Origin & Scope Guard Pre-Filter Gateway):
    - Scope Guard pre-filters third-party SaaS subdomains before Origin Recon.
    - Reverse DNS checks prevent attributing major cloud SaaS as Origin IPs.
    - waf_bypass.json persistence and graceful fallback.
    """

    @patch("socket.gethostbyname_ex")
    def test_scope_pre_filter_blocks_external_cname(self, mock_gethost):
        # Subdomain pointing to external Shopify CNAME
        mock_gethost.return_value = ("shop.example.com", ["shops.myshopify.com"], ["23.227.38.65"])
        in_scope = is_candidate_subdomain_in_scope("shop.example.com", "example.com")
        self.assertFalse(in_scope)

    @patch("socket.gethostbyname_ex")
    def test_scope_pre_filter_blocks_google_workspace(self, mock_gethost):
        # Subdomain pointing to Google ghs
        mock_gethost.return_value = ("mail.example.com", ["ghs.googlehosted.com"], ["142.250.180.147"])
        in_scope = is_candidate_subdomain_in_scope("mail.example.com", "example.com")
        self.assertFalse(in_scope)

    @patch("socket.gethostbyname_ex")
    def test_scope_pre_filter_allows_internal_subdomain(self, mock_gethost):
        # Internal unproxied subdomain
        mock_gethost.return_value = ("direct.example.com", ["origin.example.com"], ["195.201.45.10"])
        in_scope = is_candidate_subdomain_in_scope("direct.example.com", "example.com")
        self.assertTrue(in_scope)

    @patch("socket.gethostbyaddr")
    def test_reverse_dns_cloud_detection(self, mock_ptr):
        mock_ptr.return_value = ("ec2-54-230-10-1.compute-1.amazonaws.com", [], ["54.230.10.1"])
        is_cloud = is_ip_associated_with_cloud_saas("54.230.10.1")
        self.assertTrue(is_cloud)

    @patch("socket.gethostbyaddr")
    def test_reverse_dns_private_server_allowed(self, mock_ptr):
        mock_ptr.return_value = ("server1.customhosting.com", [], ["195.201.45.10"])
        is_cloud = is_ip_associated_with_cloud_saas("195.201.45.10")
        self.assertFalse(is_cloud)

    def test_load_waf_bypass_info_fallback(self):
        info = load_waf_bypass_info("/non/existent/path")
        self.assertIn("is_behind_waf", info)
        self.assertIn("waf_bypassed", info)
        self.assertIn("verified_origins", info)
        self.assertFalse(info["waf_bypassed"])

    @patch("core.origin_recon.detect_waf_presence")
    @patch("core.origin_recon.find_candidate_origin_ips")
    @patch("core.origin_recon.verify_origin_ip")
    def test_run_origin_recon_workflow(self, mock_verify, mock_candidates, mock_waf):
        mock_waf.return_value = {
            "domain": "example.com",
            "is_behind_waf": True,
            "waf_provider": "Cloudflare",
            "current_ips": ["104.21.5.10"]
        }
        mock_candidates.return_value = ["195.201.45.10"]
        mock_verify.return_value = (True, "Matched host header")

        res = run_origin_recon("example.com")
        self.assertEqual(res["status"], "success")
        self.assertTrue(res["is_behind_waf"])
        self.assertTrue(res["waf_bypassed"])
        self.assertEqual(len(res["verified_origins"]), 1)
        self.assertEqual(res["verified_origins"][0]["origin_ip"], "195.201.45.10")


if __name__ == "__main__":
    unittest.main()
