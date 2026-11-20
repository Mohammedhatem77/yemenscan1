import os
import sys
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

import unittest
from unittest.mock import patch

from core.stage3_vulnerabilities import run_standalone_nuclei, NUCLEI_DOCKER_IMAGE
from core.execution_engine import run_standalone_nuclei as run_standalone_nuclei_engine


class TestStandaloneNucleiExpanded(unittest.TestCase):
    """
    Validates Phase 1 enhancements for Nuclei Standalone execution:
    - Full template catalog access (liberation from 17-template limit)
    - Severity filtering (critical, high, all)
    - Category-to-path and technology-to-tag mapping
    - Bare domain normalization (probing both https and http)
    - Adaptive safe rate-limiting (-rl 150, -c 25)
    """

    @patch("core.stage3_vulnerabilities.run_docker_tool")
    def test_01_bare_domain_expands_to_both_https_and_http(self, mock_docker):
        captured_targets = []

        def capture_side_effect(*args, **kwargs):
            vol_dir = kwargs.get("volume_dir")
            targets_file = os.path.join(vol_dir, "nuclei_targets.txt")
            if os.path.exists(targets_file):
                with open(targets_file, "r", encoding="utf-8") as f:
                    captured_targets.extend([l.strip() for l in f if l.strip()])
            return (True, "")

        mock_docker.side_effect = capture_side_effect
        run_standalone_nuclei("toom.de")

        mock_docker.assert_called_once()
        self.assertEqual(mock_docker.call_args[1]["image"], NUCLEI_DOCKER_IMAGE)
        self.assertIn("https://toom.de", captured_targets)
        self.assertIn("http://toom.de", captured_targets)

    @patch("core.stage3_vulnerabilities.run_docker_tool")
    def test_02_severity_and_rate_limiting_flags(self, mock_docker):
        mock_docker.return_value = (True, "")
        run_standalone_nuclei("https://example.com", severity="critical")

        call_kwargs = mock_docker.call_args[1]
        args = call_kwargs["args"]

        self.assertIn("-severity", args)
        sev_idx = args.index("-severity")
        self.assertEqual(args[sev_idx + 1], "critical")

        self.assertIn("-rl", args)
        rl_idx = args.index("-rl")
        self.assertEqual(args[rl_idx + 1], "150")

        self.assertIn("-c", args)
        c_idx = args.index("-c")
        self.assertEqual(args[c_idx + 1], "25")

    @patch("core.stage3_vulnerabilities.run_docker_tool")
    def test_03_category_subfolder_mapping(self, mock_docker):
        mock_docker.return_value = (True, "")
        run_standalone_nuclei("https://example.com", category="cves")

        call_kwargs = mock_docker.call_args[1]
        args = call_kwargs["args"]

        self.assertIn("-t", args)
        t_idx = args.index("-t")
        self.assertIn("/opt/nuclei-templates/http/cves", args[t_idx + 1])

    @patch("core.stage3_vulnerabilities.run_docker_tool")
    def test_04_technology_tag_mapping(self, mock_docker):
        mock_docker.return_value = (True, "")
        run_standalone_nuclei("https://example.com", category="wordpress")

        call_kwargs = mock_docker.call_args[1]
        args = call_kwargs["args"]

        self.assertIn("-tags", args)
        tags_idx = args.index("-tags")
        self.assertIn("wordpress", args[tags_idx + 1])

    @patch("core.stage3_vulnerabilities.run_docker_tool")
    def test_05_execution_engine_wrapper_integration(self, mock_docker):
        mock_docker.return_value = (True, "")
        res = run_standalone_nuclei_engine("https://example.com", severity="high", category="misconfiguration")

        self.assertEqual(res["tool"], "nuclei")
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["target_url"], "https://example.com")
        self.assertIsInstance(res["findings"], list)


if __name__ == "__main__":
    unittest.main()
