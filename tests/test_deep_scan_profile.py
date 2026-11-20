"""
Unit and Integration Tests for Phase 1: Deep Scan Profile & Dynamic Capabilities.
Verifies matrix profiles, planner module selection, timeout configs,
Wapiti parser injection mappings, and pipeline profile propagation.
"""

import os
import json
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from core.security_scan_planner import (
    SecurityScanPlanner,
    VALID_SCAN_PROFILES,
    WAPITI_SAFE_MODULES,
    WAPITI_DAST_LIGHT_MODULES,
    WAPITI_DEEP_MODULES
)
from core.stage3_vulnerabilities import (
    parse_wapiti_json_output,
    _extract_finding_archetype
)


class TestDeepScanProfile(unittest.TestCase):
    """Test suite for Phase 1 deep scan profile and matrix capabilities."""

    def setUp(self):
        self.planner = SecurityScanPlanner()

    def test_01_matrix_contains_all_three_profiles(self):
        """Verifies that scan_capability_matrix.json defines safe, dast_light, and deep profiles."""
        self.assertEqual(VALID_SCAN_PROFILES, {"safe", "dast_light", "deep"})
        for prof in VALID_SCAN_PROFILES:
            cfg = self.planner.get_profile_config(prof)
            self.assertIsNotNone(cfg)
            self.assertIn("wapiti_timeout", cfg)
            self.assertIn("wapiti_max_scan_time", cfg)
            self.assertIn("container_timeout_wapiti", cfg)
            self.assertIn("celery_time_limit", cfg)
            self.assertIn("celery_soft_time_limit", cfg)

    def test_02_deep_profile_extended_timeouts_and_safety_limits(self):
        """Verifies deep profile has extended timeouts and careful rate-limiting."""
        deep_cfg = self.planner.get_profile_config("deep")
        safe_cfg = self.planner.get_profile_config("safe")

        # Extended container timeout for Wapiti in deep
        self.assertGreater(deep_cfg["container_timeout_wapiti"], safe_cfg["container_timeout_wapiti"])
        self.assertEqual(deep_cfg["container_timeout_wapiti"], 2700)  # 45 minutes

        # Extended Celery time limits
        self.assertGreater(deep_cfg["celery_time_limit"], safe_cfg["celery_time_limit"])
        self.assertEqual(deep_cfg["celery_time_limit"], 9000)
        self.assertEqual(deep_cfg["celery_soft_time_limit"], 7200)

        # Form submission is enabled for deep, disabled for safe
        self.assertTrue(deep_cfg["wapiti_form_submission"])
        self.assertFalse(safe_cfg["wapiti_form_submission"])

        # Nuclei rate limiting is careful in deep to avoid WAF block
        self.assertEqual(deep_cfg["nuclei_rate_limit"], 10)
        self.assertEqual(deep_cfg["nuclei_concurrency"], 3)

    def test_03_capability_ownership_matrix_valid(self):
        """Verifies that all covered capabilities have unique primary owners and no duplicates."""
        is_valid, dups = self.planner.validate_capability_ownership()
        self.assertTrue(is_valid, f"Unexpected duplicates in capability matrix: {dups}")
        self.assertEqual(dups, [])

    def test_04_deep_modules_list_includes_injection_suites(self):
        """Verifies WAPITI_DEEP_MODULES includes active injection modules for authorised targets."""
        required_injection_mods = ["sql", "xss", "file", "ssrf", "crlf", "ldap"]
        for mod in required_injection_mods:
            self.assertIn(mod, WAPITI_DEEP_MODULES)

        # Safe modules must NOT include dangerous injection modules
        for mod in required_injection_mods:
            self.assertNotIn(mod, WAPITI_SAFE_MODULES)

    def test_05_joint_scan_plan_generation_with_deep_profile(self):
        """Verifies generate_joint_scan_plan configures deep Wapiti modules and form submission."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            plan = self.planner.generate_joint_scan_plan(
                session_dir=tmp_dir,
                origins=["http://testphp.vulnweb.com"],
                wapiti_profile="deep"
            )
            wap_plan = plan.get("wapiti_plan", {})
            self.assertEqual(wap_plan.get("profile"), "deep")
            self.assertTrue(wap_plan.get("form_submission_enabled"))

            enabled = wap_plan.get("enabled_modules", [])
            self.assertIn("sql", enabled)
            self.assertIn("xss", enabled)
            self.assertIn("file", enabled)
            self.assertIn("ssrf", enabled)
            self.assertIn("crlf", enabled)
            self.assertIn("ldap", enabled)

    def test_06_wapiti_parser_maps_deep_injection_vulnerabilities(self):
        """Verifies that parse_wapiti_json_output accurately normalizes deep injection findings."""
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
            payload = {
                "vulnerabilities": {
                    "SQL Injection": [
                        {"path": "/products.php", "parameter": "id", "method": "GET", "info": "Blind SQLi", "level": 3}
                    ],
                    "Cross Site Scripting": [
                        {"path": "/search.php", "parameter": "q", "method": "GET", "info": "Reflected XSS", "level": 2}
                    ],
                    "File Handling": [
                        {"path": "/load.php", "parameter": "page", "method": "GET", "info": "Path traversal", "level": 2}
                    ],
                    "Server Side Request Forgery": [
                        {"path": "/proxy.php", "parameter": "url", "method": "POST", "info": "SSRF to metadata", "level": 3}
                    ],
                    "CRLF Injection": [
                        {"path": "/redir.php", "parameter": "dest", "method": "GET", "info": "Header injection", "level": 2}
                    ],
                    "LDAP Injection": [
                        {"path": "/user.php", "parameter": "name", "method": "GET", "info": "LDAP filter bypass", "level": 2}
                    ]
                }
            }
            json.dump(payload, tf)
            tf_path = tf.name

        try:
            findings, _ = parse_wapiti_json_output(tf_path, "http://testphp.vulnweb.com")
            self.assertEqual(len(findings), 6)

            fam_map = {f["coverage_family"]: f for f in findings}

            # Check SQLi
            self.assertIn("sql_injection", fam_map)
            self.assertEqual(fam_map["sql_injection"]["category"], "OWASP A03:2021-Injection")
            self.assertEqual(fam_map["sql_injection"]["severity"], "CRITICAL")

            # Check XSS
            self.assertIn("cross_site_scripting", fam_map)
            self.assertEqual(fam_map["cross_site_scripting"]["category"], "OWASP A03:2021-Injection")
            self.assertEqual(fam_map["cross_site_scripting"]["severity"], "HIGH")

            # Check File Handling (Path Traversal)
            self.assertIn("file_inclusion", fam_map)
            self.assertEqual(fam_map["file_inclusion"]["category"], "OWASP A01:2021-Broken Access Control")

            # Check SSRF
            self.assertIn("server_side_request_forgery", fam_map)
            self.assertEqual(fam_map["server_side_request_forgery"]["category"], "OWASP A10:2021-Server-Side Request Forgery (SSRF)")

            # Check CRLF
            self.assertIn("crlf_injection", fam_map)
            self.assertEqual(fam_map["crlf_injection"]["category"], "OWASP A03:2021-Injection")

            # Check LDAP
            self.assertIn("ldap_injection", fam_map)
            self.assertEqual(fam_map["ldap_injection"]["category"], "OWASP A03:2021-Injection")
        finally:
            if os.path.exists(tf_path):
                os.remove(tf_path)

    def test_07_finding_archetype_crlf_and_ldap(self):
        """Verifies _extract_finding_archetype identifies CRLF and LDAP for deduplication."""
        crlf_item = {"id": "WAP-CRLF-1234", "title": "CRLF Injection", "url": "http://example.com/api"}
        ldap_item = {"id": "WAP-LDAP-5678", "title": "LDAP Injection", "url": "http://example.com/api"}

        self.assertEqual(_extract_finding_archetype(crlf_item), ("path", "/api", "crlf"))
        self.assertEqual(_extract_finding_archetype(ldap_item), ("path", "/api", "ldap"))


if __name__ == "__main__":
    unittest.main()
