import os
import sys
import json
import tempfile
import unittest
from unittest.mock import patch, MagicMock

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from core.runner import run_docker_tool
from core.stage3_vulnerabilities import run_nuclei, run_wapiti_dast


class TestStage3WafBypass(unittest.TestCase):
    """
    Unit test suite for Phase 3:
    - Docker runner correctly accepts and passes --add-host flags.
    - Nuclei detects confirmed WAF bypass and injects extra_hosts to route directly to origin.
    - Wapiti DAST detects confirmed WAF bypass and injects extra_hosts to crawl and test origin.
    - Findings and metadata are properly enriched with WAF bypass provenance.
    - Normal scans without WAF bypass do not inject extra_hosts.
    """

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="yemscan_test_phase3_")

    def tearDown(self):
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    @patch("subprocess.Popen")
    @patch("core.runner.is_docker_available", return_value=True)
    def test_run_docker_tool_extra_hosts(self, mock_docker_avail, mock_popen):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.communicate.return_value = ("stdout_test", "")
        mock_popen.return_value = mock_proc

        ok, out = run_docker_tool(
            image="test_image:latest",
            args=["-arg1", "val1"],
            volume_dir=self.temp_dir,
            extra_hosts={"vulterx.com": "195.201.45.10", "www.vulterx.com": "195.201.45.10"}
        )
        self.assertTrue(ok)
        call_args = mock_popen.call_args[0][0]
        self.assertIn("--add-host", call_args)
        self.assertIn("vulterx.com:195.201.45.10", call_args)
        self.assertIn("www.vulterx.com:195.201.45.10", call_args)

    @patch("core.stage3_vulnerabilities.run_docker_tool")
    @patch("core.stage3_vulnerabilities.generate_nuclei_scan_plan")
    def test_run_nuclei_with_waf_bypass(self, mock_plan, mock_docker):
        # 1. Setup mock waf_bypass.json
        waf_data = {
            "domain": "vulterx.com",
            "is_behind_waf": True,
            "waf_provider": "Cloudflare",
            "waf_bypassed": True,
            "verified_origins": [{"origin_ip": "195.201.45.10", "verified": True}]
        }
        with open(os.path.join(self.temp_dir, "waf_bypass.json"), "w", encoding="utf-8") as wf:
            json.dump(waf_data, wf)

        # 2. Setup mock targets
        with open(os.path.join(self.temp_dir, "nuclei_targets.txt"), "w", encoding="utf-8") as tf:
            tf.write("https://vulterx.com\n")

        # 3. Setup mock scan plan
        mock_plan.return_value = {
            "profiles": [
                {
                    "profile_id": "test_profile",
                    "targets": ["https://vulterx.com"],
                    "selected_templates": [
                        {
                            "template_id": "http-headers",
                            "container_path": "/opt/nuclei-templates/http-headers.yaml",
                            "relative_path": "http-headers.yaml"
                        }
                    ],
                    "limits": {"rate_limit": 5, "concurrency": 2}
                }
            ],
            "summary": {
                "selected_template_count": 1,
                "baseline_template_count": 1
            }
        }

        # Mock template file on disk to pass fail-closed validation
        from core.stage3_vulnerabilities import NUCLEI_RUNTIME_TEMPLATES_DIR
        os.makedirs(NUCLEI_RUNTIME_TEMPLATES_DIR, exist_ok=True)
        dummy_tpl = os.path.join(NUCLEI_RUNTIME_TEMPLATES_DIR, "http-headers.yaml")
        with open(dummy_tpl, "w", encoding="utf-8") as dtf:
            dtf.write("id: http-headers\n")

        # Mock docker output with a sample finding
        def side_effect(*args, **kwargs):
            # Write a raw finding to profile raw file
            raw_path = os.path.join(self.temp_dir, "nuclei_raw_test_profile.jsonl")
            with open(raw_path, "w", encoding="utf-8") as rpf:
                finding_json = {
                    "template-id": "http-headers",
                    "matched-at": "https://vulterx.com",
                    "info": {
                        "name": "Missing Security Headers",
                        "severity": "info",
                        "classification": {"cwe-id": ["CWE-693"]}
                    }
                }
                rpf.write(json.dumps(finding_json) + "\n")
            return (True, "")

        mock_docker.side_effect = side_effect

        ok, findings = run_nuclei(self.temp_dir, "test_scan_id")
        self.assertTrue(ok)
        self.assertEqual(len(findings), 1)

        # Verify extra_hosts passed to docker
        mock_docker.assert_called_once()
        extra_hosts_passed = mock_docker.call_args[1].get("extra_hosts")
        self.assertIsNotNone(extra_hosts_passed)
        self.assertEqual(extra_hosts_passed.get("vulterx.com"), "195.201.45.10")
        self.assertEqual(extra_hosts_passed.get("www.vulterx.com"), "195.201.45.10")

        # Verify findings are tagged
        self.assertTrue(findings[0].get("waf_bypassed"))
        self.assertEqual(findings[0].get("origin_ip"), "195.201.45.10")
        self.assertTrue(findings[0].get("bypassed_origin"))

        # Verify metadata
        with open(os.path.join(self.temp_dir, "nuclei_metadata.json"), "r", encoding="utf-8") as mf:
            meta = json.load(mf)
            self.assertTrue(meta.get("waf_bypassed"))
            self.assertEqual(meta.get("origin_ip"), "195.201.45.10")
            self.assertTrue(meta.get("resolved_to_origin"))
            self.assertEqual(meta.get("waf_provider"), "Cloudflare")

    @patch("core.stage3_vulnerabilities.run_docker_tool")
    def test_run_wapiti_with_waf_bypass(self, mock_docker):
        # 1. Setup mock waf_bypass.json
        waf_data = {
            "domain": "vulterx.com",
            "is_behind_waf": True,
            "waf_provider": "Cloudflare",
            "waf_bypassed": True,
            "verified_origins": [{"origin_ip": "195.201.45.10", "verified": True}]
        }
        with open(os.path.join(self.temp_dir, "waf_bypass.json"), "w", encoding="utf-8") as wf:
            json.dump(waf_data, wf)

        # Mock docker output writing a raw wapiti file
        def side_effect(*args, **kwargs):
            raw_path = os.path.join(self.temp_dir, "wapiti_raw_1.json")
            with open(raw_path, "w", encoding="utf-8") as rpf:
                raw_data = {
                    "vulnerabilities": {
                        "CSP": [
                            {
                                "info": "CSP not set",
                                "http_request": "GET / HTTP/1.1",
                                "curl_command": "curl https://vulterx.com"
                            }
                        ]
                    },
                    "anomalies": {},
                    "infos": {}
                }
                json.dump(raw_data, rpf)
            return (True, "")

        mock_docker.side_effect = side_effect

        ok, findings = run_wapiti_dast(self.temp_dir, "test_scan_id", ["https://vulterx.com"])
        self.assertTrue(ok)
        self.assertEqual(len(findings), 1)

        # Verify extra_hosts passed to docker
        mock_docker.assert_called_once()
        extra_hosts_passed = mock_docker.call_args[1].get("extra_hosts")
        self.assertIsNotNone(extra_hosts_passed)
        self.assertEqual(extra_hosts_passed.get("vulterx.com"), "195.201.45.10")
        self.assertEqual(extra_hosts_passed.get("www.vulterx.com"), "195.201.45.10")

        # Verify findings tagged
        self.assertTrue(findings[0].get("waf_bypassed"))
        self.assertEqual(findings[0].get("origin_ip"), "195.201.45.10")
        self.assertTrue(findings[0].get("bypassed_origin"))

        # Verify metadata
        with open(os.path.join(self.temp_dir, "wapiti_metadata.json"), "r", encoding="utf-8") as mf:
            meta = json.load(mf)
            self.assertTrue(meta.get("waf_bypassed"))
            self.assertEqual(meta.get("origin_ip"), "195.201.45.10")
            self.assertTrue(meta.get("resolved_to_origin"))
            self.assertEqual(meta.get("waf_provider"), "Cloudflare")

    @patch("core.stage3_vulnerabilities.run_docker_tool")
    def test_run_wapiti_without_waf_bypass(self, mock_docker):
        # 1. Setup mock waf_bypass.json with NO bypass
        waf_data = {
            "domain": "vulterx.com",
            "is_behind_waf": True,
            "waf_provider": "Cloudflare",
            "waf_bypassed": False,
            "verified_origins": []
        }
        with open(os.path.join(self.temp_dir, "waf_bypass.json"), "w", encoding="utf-8") as wf:
            json.dump(waf_data, wf)

        mock_docker.return_value = (True, "")

        ok, findings = run_wapiti_dast(self.temp_dir, "test_scan_id", ["https://vulterx.com"])
        self.assertTrue(ok)

        # Verify extra_hosts was None
        mock_docker.assert_called_once()
        extra_hosts_passed = mock_docker.call_args[1].get("extra_hosts")
        self.assertIsNone(extra_hosts_passed)

        with open(os.path.join(self.temp_dir, "wapiti_metadata.json"), "r", encoding="utf-8") as mf:
            meta = json.load(mf)
            self.assertFalse(meta.get("waf_bypassed"))
            self.assertIsNone(meta.get("origin_ip"))
            self.assertFalse(meta.get("resolved_to_origin"))


if __name__ == "__main__":
    unittest.main()
