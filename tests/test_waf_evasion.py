"""
Unit and Integration Tests for Phase 2: WAF Evasion Engine & Adaptive Throttling.
Verifies header spoofing, User-Agent masking, rate throttling,
and CLI flag generation for Nuclei, Wapiti, and HTTPX.
"""

import os
import json
import shutil
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from core.waf_evasion import (
    WAFEvasionEngine,
    WAFEvasionConfig,
    DEFAULT_SPOOFED_HEADERS,
    REALISTIC_USER_AGENTS
)


class TestWAFEvasionEngine(unittest.TestCase):
    """Test suite for WAF Evasion & Adaptive Throttling Engine."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="yemscan_waf_evasion_test_")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_01_default_spoofed_headers_contents(self):
        """Verifies trusted internal proxy headers exist with 127.0.0.1."""
        self.assertIn("X-Forwarded-For", DEFAULT_SPOOFED_HEADERS)
        self.assertIn("X-Real-IP", DEFAULT_SPOOFED_HEADERS)
        self.assertIn("X-Originating-IP", DEFAULT_SPOOFED_HEADERS)
        self.assertIn("Client-IP", DEFAULT_SPOOFED_HEADERS)
        for val in DEFAULT_SPOOFED_HEADERS.values():
            self.assertEqual(val, "127.0.0.1")

    def test_02_realistic_user_agents_list(self):
        """Verifies realistic modern desktop browser User-Agents are defined."""
        self.assertGreaterEqual(len(REALISTIC_USER_AGENTS), 3)
        for ua in REALISTIC_USER_AGENTS:
            self.assertTrue(ua.startswith("Mozilla/5.0"))
            self.assertNotIn("Wapiti", ua)
            self.assertNotIn("Nuclei", ua)

    def test_03_evasion_inactive_by_default_on_direct_safe_target(self):
        """Verifies evasion is inactive when target has no WAF and safe profile is used."""
        cfg = WAFEvasionEngine.resolve_evasion_config(self.test_dir, scan_profile="safe")
        self.assertFalse(cfg.is_behind_waf)
        self.assertFalse(cfg.evasion_active)
        self.assertEqual(WAFEvasionEngine.build_nuclei_args(cfg), [])
        self.assertEqual(WAFEvasionEngine.build_wapiti_args(cfg), [])
        self.assertEqual(WAFEvasionEngine.build_httpx_args(cfg), [])

    def test_04_evasion_active_when_target_behind_waf_without_origin(self):
        """Verifies evasion activates with delay and single-task crawl when behind WAF."""
        waf_file = os.path.join(self.test_dir, "waf_bypass.json")
        with open(waf_file, "w", encoding="utf-8") as wf:
            json.dump({
                "is_behind_waf": True,
                "waf_bypassed": False,
                "waf_provider": "Cloudflare",
                "verified_origins": []
            }, wf)

        cfg = WAFEvasionEngine.resolve_evasion_config(self.test_dir, scan_profile="safe")
        self.assertTrue(cfg.is_behind_waf)
        self.assertTrue(cfg.evasion_active)
        self.assertEqual(cfg.nuclei_delay, "500ms")
        self.assertEqual(cfg.wapiti_tasks, 1)

        # Nuclei CLI args
        n_args = WAFEvasionEngine.build_nuclei_args(cfg)
        self.assertIn("-H", n_args)
        self.assertIn("X-Forwarded-For: 127.0.0.1", n_args)
        self.assertIn("-delay", n_args)
        self.assertIn("500ms", n_args)

        # Wapiti CLI args
        w_args = WAFEvasionEngine.build_wapiti_args(cfg)
        self.assertIn("--header", w_args)
        self.assertIn("X-Forwarded-For: 127.0.0.1", w_args)
        self.assertIn("--user-agent", w_args)

        # HTTPX CLI args
        h_args = WAFEvasionEngine.build_httpx_args(cfg)
        self.assertIn("-H", h_args)
        self.assertIn("X-Forwarded-For: 127.0.0.1", h_args)

    def test_05_evasion_active_in_deep_scan_profile(self):
        """Verifies deep profile activates evasion headers for benchmark stealth."""
        cfg = WAFEvasionEngine.resolve_evasion_config(self.test_dir, scan_profile="deep")
        self.assertTrue(cfg.evasion_active)
        n_args = WAFEvasionEngine.build_nuclei_args(cfg)
        self.assertIn("-H", n_args)
        self.assertIn("X-Forwarded-For: 127.0.0.1", n_args)

    def test_06_evasion_inactive_when_origin_bypassed_in_safe_profile(self):
        """Verifies that when Origin IP was discovered, network-level routing is preferred."""
        waf_file = os.path.join(self.test_dir, "waf_bypass.json")
        with open(waf_file, "w", encoding="utf-8") as wf:
            json.dump({
                "is_behind_waf": True,
                "waf_bypassed": True,
                "waf_provider": "Cloudflare",
                "verified_origins": [{"origin_ip": "198.51.100.2"}]
            }, wf)

        cfg = WAFEvasionEngine.resolve_evasion_config(self.test_dir, scan_profile="safe")
        self.assertTrue(cfg.is_behind_waf)
        self.assertTrue(cfg.waf_bypassed_via_origin)
        self.assertFalse(cfg.evasion_active)

    def test_07_payload_obfuscation_helpers(self):
        """Verifies non-destructive SQL comment substitution and double URL encoding."""
        # SQL comment insertion
        sql = "UNION SELECT username FROM users WHERE id = 1"
        obf = WAFEvasionEngine.obfuscate_sql_payload(sql)
        self.assertIn("UN/**/ION", obf)
        self.assertIn("SE/**/LECT", obf)
        self.assertIn("FR/**/OM", obf)
        self.assertIn("WH/**/ERE", obf)

        # Double URL encoding
        encoded_slash = WAFEvasionEngine.double_url_encode("/")
        self.assertEqual(encoded_slash.upper(), "%252F")

        encoded_quote = WAFEvasionEngine.double_url_encode("'")
        self.assertEqual(encoded_quote.upper(), "%2527")

    def test_08_nuclei_stage_applies_evasion_args_when_active(self):
        """Verifies run_nuclei includes evasion headers when evasion_cfg is active."""
        from core.stage3_vulnerabilities import run_nuclei

        waf_file = os.path.join(self.test_dir, "waf_bypass.json")
        with open(waf_file, "w", encoding="utf-8") as wf:
            json.dump({
                "is_behind_waf": True,
                "waf_bypassed": False,
                "waf_provider": "Cloudflare",
                "verified_origins": []
            }, wf)

        tf = os.path.join(self.test_dir, "nuclei_targets.txt")
        with open(tf, "w", encoding="utf-8") as f:
            f.write("https://api.example.com\n")

        with patch("core.stage3_vulnerabilities.run_docker_tool") as mock_dock:
            mock_dock.return_value = (True, "")
            run_nuclei(self.test_dir, "test_scan_123")

            self.assertTrue(mock_dock.called)
            args = mock_dock.call_args[1]["args"]
            self.assertIn("-H", args)
            self.assertIn("X-Forwarded-For: 127.0.0.1", args)
            self.assertIn("-delay", args)
            self.assertIn("500ms", args)


if __name__ == "__main__":
    unittest.main()
