"""
Unit and Integration Tests for Phase 3: WAF False-Positive Suppression & Circuit Breaker.
Verifies detection of WAF block pages, safety guards for real database errors,
origin-level circuit breaker tripping, and triage suppression integration.
"""

import os
import json
import shutil
import tempfile
import unittest

from core.waf_false_positive_filter import (
    is_waf_block_finding,
    filter_waf_block_false_positives,
    is_real_database_error,
    WAFCircuitBreaker
)
from core.stage3_vulnerabilities import unify_and_save_vulnerabilities


class TestWAFFalsePositiveFilter(unittest.TestCase):
    """Test suite for WAF False-Positive Suppression & Circuit Breaker."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="yemscan_waf_cb_test_")
        self.scan_id = "test_waf_cb_123"

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_01_detect_cloudflare_block_page(self):
        """Verifies detection of Cloudflare Attention Required and Ray ID block pages."""
        finding = {
            "id": "NUC-INFO-001",
            "title": "Information Disclosure - Error Page",
            "description": "Found Cloudflare Ray ID: 85ab1234cd56ef78 Attention Required! | Cloudflare",
            "coverage_family": "runtime_information_disclosure",
            "source_evidence": {
                "info": "Attention Required! | Cloudflare. Ray ID: 85ab1234cd56ef78"
            }
        }
        is_blocked, provider, reason = is_waf_block_finding(finding)
        self.assertTrue(is_blocked)
        self.assertIn("Cloudflare", provider)
        self.assertIn("Cloudflare", reason)

    def test_02_detect_modsecurity_block_page(self):
        """Verifies detection of ModSecurity 403 block responses."""
        finding = {
            "id": "WAP-ERR-002",
            "title": "Application Error",
            "description": "ModSecurity Action: 403. OWASP ModSecurity Core Rule Set",
            "coverage_family": "runtime_information_disclosure",
            "source_evidence": {
                "info": "ModSecurity Action: 403. Access denied with code 403."
            }
        }
        is_blocked, provider, reason = is_waf_block_finding(finding)
        self.assertTrue(is_blocked)
        self.assertEqual(provider, "ModSecurity")

    def test_03_detect_f5_bigip_block_page(self):
        """Verifies detection of F5 BIG-IP URL rejection page."""
        finding = {
            "id": "NUC-ERR-003",
            "title": "Generic Error Message",
            "description": "The requested URL was rejected. Please consult with your administrator.",
            "coverage_family": "runtime_information_disclosure"
        }
        is_blocked, provider, reason = is_waf_block_finding(finding)
        self.assertTrue(is_blocked)
        self.assertEqual(provider, "F5 BIG-IP ASM")

    def test_04_never_suppress_real_database_errors(self):
        """Safety Guard: Real SQL syntax errors must NEVER be suppressed, even if behind WAF."""
        real_sqli = {
            "id": "NUC-SQLI-001",
            "title": "SQL Injection Detected",
            "description": "Target returned: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version",
            "coverage_family": "sql_injection",
            "source_evidence": {
                "info": "Warning: mysql_fetch_array() expects parameter 1 to be resource"
            }
        }
        is_blocked, provider, reason = is_waf_block_finding(real_sqli)
        self.assertFalse(is_blocked, "Real SQL database errors must NEVER be suppressed as WAF blocks")
        self.assertTrue(is_real_database_error(real_sqli["description"]))

    def test_05_filter_waf_block_false_positives_separates_findings(self):
        """Verifies filter_waf_block_false_positives cleanly separates real bugs from WAF blocks."""
        findings = [
            # Real bug
            {
                "id": "REAL-SQLI",
                "title": "SQL Injection",
                "description": "ORA-00933: SQL command not properly ended",
                "coverage_family": "sql_injection"
            },
            # Real bug
            {
                "id": "REAL-XSS",
                "title": "Cross-Site Scripting",
                "description": "Reflected payload <script>alert(1)</script> in search results",
                "coverage_family": "cross_site_scripting"
            },
            # False positive: Cloudflare block page
            {
                "id": "WAF-BLOCK-1",
                "title": "Information Disclosure",
                "description": "Error 1020: Access Denied | Cloudflare Ray ID: abc123def",
                "coverage_family": "runtime_information_disclosure"
            },
            # False positive: Generic WAF 403
            {
                "id": "WAF-BLOCK-2",
                "title": "Stacktrace Disclosure",
                "description": "403 Forbidden - Request blocked by security rules (Web Application Firewall)",
                "coverage_family": "runtime_information_disclosure"
            }
        ]

        verified, suppressed = filter_waf_block_false_positives(findings)
        self.assertEqual(len(verified), 2)
        self.assertEqual(len(suppressed), 2)
        verified_ids = [f["id"] for f in verified]
        self.assertIn("REAL-SQLI", verified_ids)
        self.assertIn("REAL-XSS", verified_ids)
        suppressed_ids = [f["id"] for f in suppressed]
        self.assertIn("WAF-BLOCK-1", suppressed_ids)
        self.assertIn("WAF-BLOCK-2", suppressed_ids)

    def test_06_circuit_breaker_trips_after_consecutive_blocks(self):
        """Verifies WAFCircuitBreaker trips after threshold consecutive WAF block events."""
        cb = WAFCircuitBreaker(origin="https://api.example.com", threshold=5)
        self.assertFalse(cb.is_tripped)

        # 4 blocks: still not tripped
        for _ in range(4):
            tripped = cb.record_waf_block(provider="Cloudflare")
            self.assertFalse(tripped)

        # 5th block: trips breaker
        tripped = cb.record_waf_block(provider="Cloudflare")
        self.assertTrue(tripped)
        self.assertTrue(cb.is_tripped)
        self.assertIn("Cloudflare", cb.trip_reason)

        status = cb.get_status()
        self.assertEqual(status["consecutive_blocks"], 5)
        self.assertEqual(status["waf_provider"], "Cloudflare")

    def test_07_circuit_breaker_resets_on_success(self):
        """Verifies successful request resets the consecutive block counter."""
        cb = WAFCircuitBreaker(origin="https://api.example.com", threshold=5)
        cb.record_waf_block(provider="ModSecurity")
        cb.record_waf_block(provider="ModSecurity")
        self.assertEqual(cb.consecutive_blocks, 2)

        cb.record_success()
        self.assertEqual(cb.consecutive_blocks, 0)
        self.assertFalse(cb.is_tripped)

    def test_08_unify_vulnerabilities_saves_waf_suppression_telemetry(self):
        """Verifies unify_and_save_vulnerabilities records WAF suppression in triage_suppressed.json."""
        nuclei_findings = [
            {
                "id": "NUC-WAF-01",
                "title": "Information Disclosure",
                "description": "Error 1020: Access Denied. Protected by Cloudflare. Ray ID: 99887766",
                "coverage_family": "runtime_information_disclosure",
                "severity": "LOW",
                "url": "https://api.example.com/login"
            }
        ]
        wapiti_findings = [
            {
                "id": "WAP-VALID-01",
                "title": "Cleartext Submission of Password",
                "description": "Form submits password over HTTP",
                "coverage_family": "cleartext_password_submission",
                "severity": "MEDIUM",
                "url": "https://api.example.com/auth"
            }
        ]

        unified = unify_and_save_vulnerabilities(
            self.test_dir,
            self.scan_id,
            nuclei_findings=nuclei_findings,
            wapiti_findings=wapiti_findings
        )

        # WAF block finding must be suppressed from unified results
        self.assertEqual(len(unified), 1)
        self.assertEqual(unified[0]["coverage_family"], "cleartext_password_submission")

        # triage_suppressed.json must be created and contain WAF suppression telemetry
        triage_path = os.path.join(self.test_dir, "triage_suppressed.json")
        self.assertTrue(os.path.exists(triage_path))
        with open(triage_path, "r", encoding="utf-8") as f:
            triage_data = json.load(f)

        self.assertGreaterEqual(triage_data["suppressed_count"], 1)
        self.assertEqual(triage_data["waf_block_suppressed_count"], 1)
        self.assertIn("waf_suppressed_items", triage_data)
        self.assertEqual(triage_data["waf_suppressed_items"][0]["id"], "NUC-WAF-01")


if __name__ == "__main__":
    unittest.main()
