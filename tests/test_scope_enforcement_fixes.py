"""
Unit Test Suite for YemScan Scope Enforcement and SSRF Safety Fixes.
Mocks all external DNS and HTTP requests — 100% offline, zero live external scanning.
"""

import os
import json
import socket
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from core.target_validator import (
    is_safe_ip_address,
    is_safe_host_or_ip,
    validate_redirect_hop,
    validate_standalone_target,
    TargetValidationError,
)
from core.scope_classifier import classify_scope, build_scope_badge, load_scoped_urls
from core.stage2_web_probing import run_kiterunner_or_api_probing, run_httpx
from core.stage3_vulnerabilities import _inspect_redirect_chain_headers
from core.origin_recon import find_candidate_origin_ips, verify_origin_ip
from core.tasks import celery_run_standalone_tool, dispatch_standalone_tool


class TestScopeEnforcementAndSSRFFixes(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.session_dir = self.temp_dir.name
        self.scan_id = "test_scope_scan_001"

    def tearDown(self):
        self.temp_dir.cleanup()

    # -------------------------------------------------------------------------
    # 1. IP and Host SSRF Safety Guards
    # -------------------------------------------------------------------------
    def test_is_safe_ip_address(self):
        # Safe public IPs
        self.assertTrue(is_safe_ip_address("8.8.8.8"))
        self.assertTrue(is_safe_ip_address("1.1.1.1"))
        self.assertTrue(is_safe_ip_address("93.184.216.34"))
        self.assertTrue(is_safe_ip_address("2606:4700:4700::1111"))

        # Loopback
        self.assertFalse(is_safe_ip_address("127.0.0.1"))
        self.assertFalse(is_safe_ip_address("127.0.0.53"))
        self.assertFalse(is_safe_ip_address("::1"))

        # Private RFC 1918 & CGNAT
        self.assertFalse(is_safe_ip_address("10.0.0.1"))
        self.assertFalse(is_safe_ip_address("172.16.0.1"))
        self.assertFalse(is_safe_ip_address("192.168.1.1"))
        self.assertFalse(is_safe_ip_address("100.64.0.1"))

        # Cloud Metadata & Link-Local
        self.assertFalse(is_safe_ip_address("169.254.169.254"))
        self.assertFalse(is_safe_ip_address("169.254.169.253"))
        self.assertFalse(is_safe_ip_address("100.100.100.200"))
        self.assertFalse(is_safe_ip_address("169.254.1.1"))
        self.assertFalse(is_safe_ip_address("fe80::1"))

        # Sinkholes & Unspecified
        self.assertFalse(is_safe_ip_address("0.0.0.0"))
        self.assertFalse(is_safe_ip_address("127.0.53.53"))
        self.assertFalse(is_safe_ip_address("255.255.255.255"))

    def test_is_safe_host_or_ip(self):
        # Blocked pseudo TLDs
        self.assertFalse(is_safe_host_or_ip("mycorp.local")[0])
        self.assertFalse(is_safe_host_or_ip("service.internal")[0])
        self.assertFalse(is_safe_host_or_ip("localhost")[0])
        self.assertFalse(is_safe_host_or_ip("printer.lan")[0])
        self.assertFalse(is_safe_host_or_ip("gateway.corp")[0])

        # Direct safe vs unsafe IPs
        self.assertFalse(is_safe_host_or_ip("127.0.0.1")[0])
        self.assertFalse(is_safe_host_or_ip("169.254.169.254")[0])
        self.assertTrue(is_safe_host_or_ip("93.184.216.34")[0])

        # Mocked DNS resolution: safe domain resolving to public IP
        with patch("socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]
            is_safe, _ = is_safe_host_or_ip("valid-domain.com")
            self.assertTrue(is_safe)

        # Mocked DNS resolution: malicious DNS rebinding resolving to private/metadata IP
        with patch("socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 0))]
            is_safe, reason = is_safe_host_or_ip("rebind-to-metadata.com")
            self.assertFalse(is_safe)
            self.assertIn("unsafe IP", reason)

    # -------------------------------------------------------------------------
    # 2. Redirect Hop Validation & SSRF Guard
    # -------------------------------------------------------------------------
    def test_validate_redirect_hop(self):
        current_url = "https://target.com/page1"

        # Safe relative redirect
        with patch("core.target_validator.is_safe_host_or_ip", return_value=(True, "")):
            safe, next_url, _ = validate_redirect_hop(current_url, "/dashboard")
            self.assertTrue(safe)
            self.assertEqual(next_url, "https://target.com/dashboard")

        # Unsafe redirect to cloud metadata
        safe, next_url, reason = validate_redirect_hop(current_url, "http://169.254.169.254/latest/meta-data/")
        self.assertFalse(safe)
        self.assertIn("169.254.169.254", str(reason))

        # Unsafe redirect to loopback
        safe, next_url, reason = validate_redirect_hop(current_url, "http://127.0.0.1:8000/internal")
        self.assertFalse(safe)

        # Unsafe scheme
        safe, next_url, reason = validate_redirect_hop(current_url, "file:///etc/passwd")
        self.assertFalse(safe)
        self.assertIn("Disallowed scheme", reason)

    @patch("requests.Session.get")
    def test_inspect_redirect_chain_headers_ssrf_blocking(self, mock_get):
        # 1. Initial URL targeting loopback is blocked before issuing HTTP request
        res = _inspect_redirect_chain_headers("http://127.0.0.1:8000/api")
        self.assertIsNone(res)
        self.assertFalse(mock_get.called)

        # 2. Safe initial URL redirects to Cloud Metadata 169.254.169.254
        mock_resp_1 = MagicMock()
        mock_resp_1.status_code = 302
        mock_resp_1.headers = {"Location": "http://169.254.169.254/latest/meta-data/"}
        mock_get.return_value = mock_resp_1

        with patch("core.stage3_vulnerabilities.is_safe_host_or_ip", side_effect=lambda h, *a, **kw: (True, "") if "safe-target-domain.com" in str(h) else (False, "Metadata blocked")), \
             patch("core.target_validator.is_safe_host_or_ip", side_effect=lambda h, *a, **kw: (True, "") if "safe-target-domain.com" in str(h) else (False, "Metadata blocked")):
            result = _inspect_redirect_chain_headers("https://safe-target-domain.com/redirect-test")
            self.assertIsNotNone(result)
            self.assertIn("blocked_redirect", result)
            self.assertEqual(result["blocked_redirect"], "http://169.254.169.254/latest/meta-data/")
            # Exactly 1 call was made to safe-target-domain.com; 169.254.169.254 was NEVER queried!
            self.assertEqual(mock_get.call_count, 1)

    # -------------------------------------------------------------------------
    # 3. Kiterunner Scope Enforcement: Exclude Third-Party & External Redirects
    # -------------------------------------------------------------------------
    @patch("core.stage2_web_probing.run_docker_tool")
    def test_kiterunner_excludes_third_party_and_external_redirects(self, mock_docker):
        mock_docker.return_value = (True, "")

        # Write active_urls.json with mixed scope tags
        json_path = os.path.join(self.session_dir, "active_urls.json")
        entries = [
            {"url": "https://app.target.com", "scope_tag": "in_scope_full"},
            {"url": "https://api.target.com", "scope_tag": "in_scope_full"},
            {"url": "https://support.target.com", "scope_tag": "third_party_passive"},
            {"url": "https://portal.target.com", "scope_tag": "external_redirect"}
        ]
        with open(json_path, "w", encoding="utf-8") as f:
            for e in entries:
                f.write(json.dumps(e) + "\n")

        # Load scoped URLs
        scoped = load_scoped_urls(self.session_dir)
        self.assertEqual(len(scoped["in_scope_urls"]), 2)
        self.assertIn("https://app.target.com", scoped["in_scope_urls"])
        self.assertIn("https://api.target.com", scoped["in_scope_urls"])
        self.assertEqual(len(scoped["third_party_urls"]), 2)
        self.assertIn("https://support.target.com", scoped["third_party_urls"])
        self.assertIn("https://portal.target.com", scoped["third_party_urls"])

        # Run Kiterunner passing all active URLs
        all_urls = [e["url"] for e in entries]
        ok, endpoints = run_kiterunner_or_api_probing(all_urls, self.session_dir, self.scan_id)
        self.assertTrue(ok)

        # Inspect the generated kiterunner_input.txt
        kr_input_file = os.path.join(self.session_dir, "kiterunner_input.txt")
        self.assertTrue(os.path.exists(kr_input_file))
        with open(kr_input_file, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()]

        # Only the 2 in-scope assets must be present
        self.assertEqual(len(lines), 2)
        self.assertIn("https://app.target.com", lines)
        self.assertIn("https://api.target.com", lines)
        self.assertNotIn("https://support.target.com", lines)
        self.assertNotIn("https://portal.target.com", lines)

    # -------------------------------------------------------------------------
    # 4. HTTPX Redirect Protection (-fhr) & CDN In-Scope Preservation
    # -------------------------------------------------------------------------
    @patch("core.stage2_web_probing.run_docker_tool")
    @patch("core.stage2_web_probing.update_status")
    def test_httpx_uses_fhr_and_classifies_redirects(self, mock_status, mock_docker):
        mock_docker.return_value = (True, "")
        ports_file = os.path.join(self.session_dir, "ports.txt")
        with open(ports_file, "w", encoding="utf-8") as f:
            f.write("target.com:443\n")

        # Run HTTPX
        run_httpx(self.session_dir, self.scan_id)
        self.assertTrue(mock_docker.called)
        args_passed = mock_docker.call_args[1].get("args") or mock_docker.call_args[0][1]

        # Must contain -fhr (follow host redirects only), NOT blind -fr
        self.assertIn("-fhr", args_passed)
        self.assertNotIn("-fr", args_passed)

    def test_scope_classification_cdn_and_redirects(self):
        # 1. External Redirect (302 to external domain)
        res_ext = classify_scope(
            url="http://mail.target.com",
            host="mail.target.com",
            root_domain="target.com",
            status_code=302,
            location="https://login.microsoftonline.com"
        )
        self.assertEqual(res_ext["scope_tag"], "external_redirect")
        self.assertEqual(res_ext["redirect_type"], "external")
        self.assertFalse(res_ext["scope_badge"]["dast_allowed"])
        self.assertEqual(res_ext["scope_badge"]["color"], "blue")

        # 2. Internal Redirect (301 to same domain / path)
        res_int = classify_scope(
            url="http://target.com",
            host="target.com",
            root_domain="target.com",
            status_code=301,
            location="https://target.com/home"
        )
        self.assertEqual(res_int["scope_tag"], "in_scope_full")
        self.assertEqual(res_int["redirect_type"], "internal")
        self.assertTrue(res_int["scope_badge"]["dast_allowed"])
        self.assertEqual(res_int["scope_badge"]["color"], "green")

        # 3. Third-party SaaS via CNAME (Zendesk)
        res_saas = classify_scope(
            url="https://help.target.com",
            host="help.target.com",
            root_domain="target.com",
            cname_list=["target.zendesk.com"]
        )
        self.assertEqual(res_saas["scope_tag"], "third_party_passive")
        self.assertTrue(res_saas["is_third_party"])
        self.assertFalse(res_saas["scope_badge"]["dast_allowed"])
        self.assertFalse(res_saas["scope_badge"]["takeover_checked"])
        self.assertEqual(res_saas["scope_badge"]["color"], "orange")

        # 4. CDN-protected asset (Cloudflare) without external SaaS CNAME
        res_cdn = classify_scope(
            url="https://shop.target.com",
            host="shop.target.com",
            root_domain="target.com",
            cname_list=[],
            cdn_name="cloudflare"
        )
        self.assertEqual(res_cdn["scope_tag"], "in_scope_full")
        self.assertEqual(res_cdn["hosting_type"], "cloud_cdn")
        self.assertTrue(res_cdn["scope_badge"]["dast_allowed"])
        self.assertEqual(res_cdn["scope_badge"]["color"], "green")
        self.assertIn("CDN-Protected", res_cdn["scope_badge"]["label"])

    @patch("core.execution_engine.run_nuclei")
    @patch("core.execution_engine.run_wapiti_dast")
    @patch("core.execution_engine.unify_and_save_vulnerabilities")
    @patch("core.execution_engine._run_nuclei_takeover_check")
    def test_zero_touch_third_party_no_takeover_probe(self, mock_takeover, mock_unify, mock_wapiti, mock_nuclei):
        from core.execution_engine import run_stage3_pipeline
        mock_nuclei.return_value = (True, [])
        mock_wapiti.return_value = (True, [])

        active_json = os.path.join(self.session_dir, "active_urls.json")
        entries = [
            {"url": "https://app.target.com", "scope_tag": "in_scope_full"},
            {"url": "https://support.target.com", "scope_tag": "third_party_passive"},
            {"url": "https://portal.target.com", "scope_tag": "external_redirect"},
        ]
        with open(active_json, "w", encoding="utf-8") as f:
            for e in entries:
                f.write(json.dumps(e) + "\n")

        with patch("core.execution_engine.get_session_dir", return_value=self.session_dir):
            with patch("core.execution_engine.update_status"):
                with patch("core.execution_engine.SessionLocal"):
                    with patch("core.execution_engine.ingest_scan_from_directory"):
                        with patch("core.execution_engine.complete_scan_session"):
                            res = run_stage3_pipeline(self.scan_id)

        # Zero-Touch Policy: _run_nuclei_takeover_check MUST NOT be called!
        self.assertFalse(mock_takeover.called, "Zero-Touch policy violated: takeover check was called on third-party assets!")
        self.assertEqual(res["nuclei_takeover_count"], 0)
        self.assertEqual(res["scope_guard"]["third_party_count"], 2)

    # -------------------------------------------------------------------------
    # 5. Independent Scanning Target Validation (FastAPI & Celery Worker)
    # -------------------------------------------------------------------------
    def test_validate_standalone_target_valid_cases(self):
        # Subfinder
        self.assertEqual(validate_standalone_target("subfinder", "example.com"), "example.com")
        self.assertEqual(validate_standalone_target("subfinder", "sub.target.edu.ye"), "sub.target.edu.ye")

        # Naabu
        self.assertEqual(validate_standalone_target("naabu", "93.184.216.34:8080"), "93.184.216.34:8080")

        # HTTPX
        targets = ["https://example.com", "93.184.216.34"]
        with patch("core.target_validator.is_safe_host_or_ip", return_value=(True, "")):
            self.assertEqual(validate_standalone_target("httpx", targets), targets)

        # Kiterunner & Wapiti
        with patch("core.target_validator.is_safe_host_or_ip", return_value=(True, "")):
            self.assertEqual(validate_standalone_target("kiterunner", "https://target.com/api"), "https://target.com/api")
            self.assertEqual(validate_standalone_target("wapiti", "http://target.com:8080/"), "http://target.com:8080/")

        # Nuclei
        with patch("core.target_validator.is_safe_host_or_ip", return_value=(True, "")):
            self.assertEqual(validate_standalone_target("nuclei", "https://target.com"), "https://target.com")

    def test_validate_standalone_target_blocks_unsafe_inputs(self):
        # Subfinder rejects IPs, loopback, and local domains
        with self.assertRaises(TargetValidationError):
            validate_standalone_target("subfinder", "127.0.0.1")
        with self.assertRaises(TargetValidationError):
            validate_standalone_target("subfinder", "169.254.169.254")
        with self.assertRaises(TargetValidationError):
            validate_standalone_target("subfinder", "localhost")
        with self.assertRaises(TargetValidationError):
            validate_standalone_target("subfinder", "target.local")

        # Naabu rejects loopback, RFC 1918, and metadata
        with self.assertRaises(TargetValidationError):
            validate_standalone_target("naabu", "127.0.0.1")
        with self.assertRaises(TargetValidationError):
            validate_standalone_target("naabu", "192.168.1.50:80")
        with self.assertRaises(TargetValidationError):
            validate_standalone_target("naabu", "169.254.169.254")

        # HTTPX rejects unsafe targets in list
        with self.assertRaises(TargetValidationError):
            validate_standalone_target("httpx", ["https://example.com", "http://127.0.0.1:8000"])

        # Kiterunner, Nuclei, Wapiti reject private & metadata URLs
        with self.assertRaises(TargetValidationError):
            validate_standalone_target("kiterunner", "http://127.0.0.1:8000/api")
        with self.assertRaises(TargetValidationError):
            validate_standalone_target("kiterunner", "http://169.254.169.254/latest/meta-data/")
        with self.assertRaises(TargetValidationError):
            validate_standalone_target("wapiti", "http://localhost:3000/")
        with self.assertRaises(TargetValidationError):
            validate_standalone_target("nuclei", "http://10.0.0.1:8080")

    def test_celery_worker_standalone_revalidation_defense_in_depth(self):
        # Even if a malicious task reaches the Celery Worker, the worker re-validates and fails closed
        with self.assertRaises(ValueError) as cm:
            celery_run_standalone_tool.__wrapped__(
                self.scan_id,
                "wapiti",
                "http://127.0.0.1:8000"
            )
        self.assertIn("فشل التحقق الأمني", str(cm.exception))

    # -------------------------------------------------------------------------
    # 6. Origin IP Reconnaissance Safety
    # -------------------------------------------------------------------------
    @patch("core.origin_recon.resolve_domain_ips")
    def test_origin_recon_filters_unsafe_ips(self, mock_resolve):
        # Subdomains resolving to a mix of public, private, loopback, and metadata
        mock_resolve.side_effect = lambda fqdn: {
            "direct.target.com": ["127.0.0.1"],
            "vpn.target.com": ["192.168.1.1"],
            "dev.target.com": ["169.254.169.254"],
            "origin.target.com": ["93.184.216.34"],
        }.get(fqdn, [])

        with patch("core.origin_recon.is_candidate_subdomain_in_scope", return_value=True):
            candidates = find_candidate_origin_ips("target.com", ["direct.target.com", "vpn.target.com", "dev.target.com", "origin.target.com"])
            # Only the safe public IP 93.184.216.34 should be returned!
            self.assertEqual(candidates, ["93.184.216.34"])

    @patch("requests.get")
    def test_verify_origin_ip_blocks_unsafe_ips_without_http_call(self, mock_get):
        ok, msg = verify_origin_ip("127.0.0.1", "target.com")
        self.assertFalse(ok)
        self.assertIn("rejected by Scope Guard", msg)
        self.assertFalse(mock_get.called)

        ok, msg = verify_origin_ip("169.254.169.254", "target.com")
        self.assertFalse(ok)
        self.assertFalse(mock_get.called)


if __name__ == "__main__":
    unittest.main()
