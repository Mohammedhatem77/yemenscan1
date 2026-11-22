import os
import json
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from core.stage1_discovery import run_subfinder, run_naabu
from core.stage2_web_probing import run_httpx, run_kiterunner_or_api_probing
from core.stage3_vulnerabilities import run_nuclei, run_wapiti_dast, parse_nuclei_json_output, NUCLEI_SAFE_FLAGS
from core.waf_evasion import WAFEvasionEngine, WAFEvasionConfig

class TestEnhancedToolFlags(unittest.TestCase):
    """
    Comprehensive verification test suite for Phase 1: Tool Flags & Intelligence Upgrade.
    Verifies that all 6 tools are invoked with upgraded intelligence flags and parse
    enhanced forensics cleanly with zero regressions.
    """

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="ys_enhanced_flags_")
        self.scan_id = "test_flags_scan_001"
        self.session_dir = os.path.join(self.test_dir, self.scan_id)
        os.makedirs(self.session_dir, exist_ok=True)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)

    @patch("core.stage1_discovery.run_docker_tool")
    @patch("core.stage1_discovery.update_status")
    def test_subfinder_flags_and_source_intelligence(self, mock_update, mock_docker):
        """1. Verify Subfinder CLI args contain -cs and source provenance is recorded in metadata."""
        raw_jsonl = (
            '{"host":"api.example.com","sources":["crtsh","censys"]}\n'
            '{"host":"dev.example.com","sources":["crtsh","anubis"]}\n'
        )
        raw_file = os.path.join(self.session_dir, "subfinder_raw.jsonl")

        def fake_docker(*args, **kwargs):
            with open(raw_file, "w", encoding="utf-8") as f:
                f.write(raw_jsonl)
            return True, ""

        mock_docker.side_effect = fake_docker

        ok, subdomains = run_subfinder("example.com", self.session_dir, self.scan_id)
        self.assertTrue(ok)
        self.assertEqual(len(subdomains), 2)

        # Flag verification
        call_kwargs = mock_docker.call_args[1] if mock_docker.call_args[1] else {}
        args = call_kwargs.get("args") or mock_docker.call_args[0][1]
        self.assertIn("-cs", args)
        self.assertIn("-json", args)

        # Metadata verification
        meta_path = os.path.join(self.session_dir, "subfinder_metadata.json")
        self.assertTrue(os.path.exists(meta_path))
        with open(meta_path, "r", encoding="utf-8") as mf:
            meta = json.load(mf)
        self.assertIn("sources_summary", meta)
        self.assertEqual(meta["sources_summary"].get("crtsh"), 2)
        self.assertEqual(meta["sources_summary"].get("censys"), 1)
        self.assertEqual(meta["sources_summary"].get("anubis"), 1)

    @patch("core.stage1_discovery.run_docker_tool")
    @patch("core.stage1_discovery.update_status")
    def test_naabu_flags_and_anti_drop_tuning(self, mock_update, mock_docker):
        """2. Verify Naabu CLI args contain -Pn, rate=100, retries=3, timeout=5s."""
        raw_file = os.path.join(self.session_dir, "naabu_raw.jsonl")

        def fake_docker(*args, **kwargs):
            with open(raw_file, "w", encoding="utf-8") as f:
                f.write('{"host":"example.com","port":80,"protocol":"tcp"}\n')
            return True, ""

        mock_docker.side_effect = fake_docker

        ok, ports = run_naabu(["example.com"], self.session_dir, self.scan_id)
        self.assertTrue(ok)
        self.assertEqual(ports, ["example.com:80"])

        call_kwargs = mock_docker.call_args[1] if mock_docker.call_args[1] else {}
        args = call_kwargs.get("args") or mock_docker.call_args[0][1]

        self.assertIn("-Pn", args)
        self.assertIn("-timeout", args)
        self.assertEqual(args[args.index("-timeout") + 1], "5s")
        self.assertIn("-retries", args)
        self.assertEqual(args[args.index("-retries") + 1], "3")
        self.assertIn("-rate", args)
        self.assertEqual(args[args.index("-rate") + 1], "100")

    @patch("core.stage1_discovery.run_docker_tool")
    @patch("core.stage1_discovery.update_status")
    def test_naabu_deep_profile_scans_top_1000_ports(self, mock_update, mock_docker):
        """2b. Verify Naabu in 'deep' profile scans Top 1000 ports (-tp 1000) with rate 150."""
        raw_file = os.path.join(self.session_dir, "naabu_raw.jsonl")

        def fake_docker(*args, **kwargs):
            with open(raw_file, "w", encoding="utf-8") as f:
                f.write('{"host":"example.com","port":8088,"protocol":"tcp"}\n')
            return True, ""

        mock_docker.side_effect = fake_docker

        ok, ports = run_naabu(["example.com"], self.session_dir, self.scan_id, scan_profile="deep")
        self.assertTrue(ok)
        self.assertEqual(ports, ["example.com:8088"])

        call_kwargs = mock_docker.call_args[1] if mock_docker.call_args[1] else {}
        args = call_kwargs.get("args") or mock_docker.call_args[0][1]

        self.assertIn("-tp", args)
        self.assertEqual(args[args.index("-tp") + 1], "1000")
        self.assertIn("-rate", args)
        self.assertEqual(args[args.index("-rate") + 1], "150")

        # Verify metadata
        meta_file = os.path.join(self.session_dir, "naabu_metadata.json")
        self.assertTrue(os.path.exists(meta_file))
        with open(meta_file, "r", encoding="utf-8") as mf:
            meta = json.load(mf)
        self.assertEqual(meta.get("scan_profile"), "deep")
        self.assertEqual(meta.get("scanned_ports_mode"), "top-1000")

    @patch("core.stage2_web_probing.run_docker_tool")
    @patch("core.stage2_web_probing.update_status")
    def test_httpx_enhanced_flags_and_evidence_extraction(self, mock_update, mock_docker):
        """3. Verify HTTPX flags include -favicon, -tls-grab, -fr, -method and extract metadata."""
        ports_file = os.path.join(self.session_dir, "ports.txt")
        with open(ports_file, "w", encoding="utf-8") as f:
            f.write("example.com:443\n")

        raw_record = {
            "input": "example.com:443",
            "url": "https://example.com:443",
            "status_code": 200,
            "title": "Example Domain",
            "webserver": "nginx",
            "tech": ["Nginx"],
            "method": "GET",
            "favicon": "708578229",
            "favicon_url": "https://example.com/favicon.ico",
            "tls": {
                "subject_cn": "example.com",
                "subject_an": ["example.com", "www.example.com"],
                "issuer_cn": "DigiCert Global Root CA"
            },
            "final_url": "https://example.com/",
            "chain_status_codes": [301, 200]
        }
        raw_file = os.path.join(self.session_dir, "httpx_raw.jsonl")

        def fake_docker(*args, **kwargs):
            with open(raw_file, "w", encoding="utf-8") as f:
                f.write(json.dumps(raw_record) + "\n")
            return True, ""

        mock_docker.side_effect = fake_docker

        ok, web_targets, active_urls = run_httpx(self.session_dir, self.scan_id)
        self.assertTrue(ok)
        self.assertEqual(len(web_targets), 1)

        call_kwargs = mock_docker.call_args[1] if mock_docker.call_args[1] else {}
        args = call_kwargs.get("args") or mock_docker.call_args[0][1]

        self.assertIn("-favicon", args)
        self.assertIn("-tls-grab", args)
        self.assertIn("-fr", args)
        self.assertIn("-method", args)

        target = web_targets[0]
        self.assertEqual(target.get("favicon_hash"), "708578229")
        self.assertEqual(target.get("method"), "GET")
        self.assertIsNotNone(target.get("tls"))
        self.assertEqual(target["tls"].get("subject_cn"), "example.com")
        self.assertEqual(target.get("final_url"), "https://example.com/")

    @patch("core.stage2_web_probing.run_docker_tool")
    @patch("core.stage2_web_probing.update_status")
    def test_kiterunner_evasion_args_injection(self, mock_update, mock_docker):
        """4. Verify Kiterunner receives WAF evasion headers and User-Agent when evasion is active."""
        targets = ["https://example.com"]
        raw_output = '{"type":"response","url":"https://example.com/api/v1","status":200,"method":"GET","length":120}\n'
        mock_docker.return_value = (True, "")

        raw_file = os.path.join(self.session_dir, "kiterunner_raw.json")
        with open(raw_file, "w", encoding="utf-8") as f:
            f.write(raw_output)

        # Trigger evasion via mock config
        evasion_cfg = WAFEvasionConfig(
            evasion_active=True,
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0.0.0",
            spoofed_headers={"X-Forwarded-For": "127.0.0.1"}
        )
        with patch.object(WAFEvasionEngine, "resolve_evasion_config", return_value=evasion_cfg):
            ok, endpoints = run_kiterunner_or_api_probing(targets, self.session_dir, self.scan_id)

        self.assertTrue(ok)
        call_kwargs = mock_docker.call_args[1] if mock_docker.call_args[1] else {}
        args = call_kwargs.get("args") or mock_docker.call_args[0][1]

        self.assertIn("--user-agent", args)
        self.assertIn("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0.0.0", args)
        self.assertIn("-H", args)
        self.assertIn("X-Forwarded-For: 127.0.0.1", args)

    def test_nuclei_irr_flag_and_forensic_evidence_extraction(self):
        """5. Verify Nuclei flags include -irr and parse_nuclei_json_output captures request/response."""
        self.assertIn("-irr", NUCLEI_SAFE_FLAGS)

        raw_file = os.path.join(self.session_dir, "nuclei_raw.jsonl")
        record = {
            "template-id": "cve-2021-41773",
            "info": {
                "name": "Apache Path Traversal",
                "severity": "critical",
                "classification": {"cve-id": "CVE-2021-41773", "cwe-id": "CWE-22"}
            },
            "matched-at": "https://example.com/icons/.%%32%65/.%%32%65/etc/passwd",
            "request": "GET /icons/.%%32%65/.%%32%65/etc/passwd HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "response": "HTTP/1.1 200 OK\r\n\r\nroot:x:0:0:root:/root:/bin/bash"
        }
        with open(raw_file, "w", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

        findings, counts = parse_nuclei_json_output(raw_file, valid_target_origins={"https://example.com"})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["request"], record["request"])
        self.assertEqual(findings[0]["response"], record["response"])
        self.assertEqual(findings[0]["cve_id"], "CVE-2021-41773")

    @patch("core.stage3_vulnerabilities.verify_wapiti_image_identity", return_value=True)
    @patch("core.stage3_vulnerabilities.run_docker_tool")
    @patch("core.stage3_vulnerabilities.update_status")
    def test_wapiti_scope_and_profile_depth_levels(self, mock_update, mock_docker, mock_verify):
        """6. Verify Wapiti CLI args contain --scope domain, and sets -l 2 -dr 2 for deep profile."""
        mock_docker.return_value = (True, "")

        # Test Safe Profile
        run_wapiti_dast(self.session_dir, self.scan_id, ["https://example.com"], profile="safe")
        call_kwargs_safe = mock_docker.call_args[1] if mock_docker.call_args[1] else {}
        args_safe = call_kwargs_safe.get("args") or mock_docker.call_args[0][1]

        self.assertIn("--scope", args_safe)
        self.assertEqual(args_safe[args_safe.index("--scope") + 1], "domain")
        self.assertIn("-l", args_safe)
        self.assertEqual(args_safe[args_safe.index("-l") + 1], "1")
        self.assertIn("-dr", args_safe)
        self.assertEqual(args_safe[args_safe.index("-dr") + 1], "1")
        self.assertIn("--no-form-submission", args_safe)

        mock_docker.reset_mock()

        # Test Deep Profile
        run_wapiti_dast(self.session_dir, self.scan_id, ["https://example.com"], profile="deep")
        call_kwargs_deep = mock_docker.call_args[1] if mock_docker.call_args[1] else {}
        args_deep = call_kwargs_deep.get("args") or mock_docker.call_args[0][1]

        self.assertIn("--scope", args_deep)
        self.assertEqual(args_deep[args_deep.index("--scope") + 1], "domain")
        self.assertIn("-l", args_deep)
        self.assertEqual(args_deep[args_deep.index("-l") + 1], "2")
        self.assertIn("-dr", args_deep)
        self.assertEqual(args_deep[args_deep.index("-dr") + 1], "2")
        self.assertNotIn("--no-form-submission", args_deep)

if __name__ == "__main__":
    unittest.main()
