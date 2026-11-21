import os
import json
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from core.pipeline import run_full_pipeline
from core.session import get_status

class TestZeroTargetGuard(unittest.TestCase):
    """
    Test suite for Phase 2: Pipeline Zero-Target Guard & Honest Status Resolution.
    Verifies that when zero open ports or zero web targets are discovered,
    the pipeline never falsely claims 100% completed success.
    """

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="ys_zero_guard_")
        self.scan_id = "test_guard_scan_001"
        self.session_dir = os.path.join(self.test_dir, self.scan_id)
        os.makedirs(self.session_dir, exist_ok=True)

        # Initialize status.json
        status_file = os.path.join(self.session_dir, "status.json")
        initial_status = {
            "scan_id": self.scan_id,
            "target_domain": "example.com",
            "status": "queued",
            "current_stage": "queued",
            "current_tool": "none",
            "progress_percentage": 0,
            "tool_statuses": {},
            "stats": {
                "subdomains_count": 0,
                "open_ports_count": 0,
                "live_urls_count": 0,
                "api_endpoints_count": 0,
                "vulnerabilities_count": 0,
                "vuln_by_severity": {
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "info": 0
                }
            },
            "logs": [],
            "is_completed": False,
            "has_error": False,
            "error_message": None
        }
        with open(status_file, "w", encoding="utf-8") as f:
            json.dump(initial_status, f, ensure_ascii=False, indent=2)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)

    @patch("core.origin_recon.run_origin_recon", return_value={"is_behind_waf": False, "waf_bypassed": False})
    @patch("core.pipeline.run_subfinder")
    @patch("core.pipeline.run_naabu")
    @patch("core.pipeline.run_httpx")
    @patch("core.pipeline.run_kiterunner_or_api_probing")
    @patch("core.pipeline.run_nuclei")
    @patch("core.pipeline.run_wapiti_dast")
    @patch("core.session.get_session_dir")
    @patch("core.pipeline.get_session_dir")
    def test_zero_ports_and_zero_urls_triggers_blocked_no_targets(
        self, mock_pipe_sess, mock_sess_sess, mock_wap, mock_nuc, mock_kite, mock_http, mock_naabu, mock_sub, mock_waf
    ):
        """
        1. When Subfinder finds a domain, but Naabu reports 0 ports and HTTPX reports 0 URLs,
        the pipeline must classify status as 'blocked_no_targets' with has_error=True,
        and MUST NOT claim 100% completed success or run Phase 3 tools.
        """
        mock_pipe_sess.return_value = self.session_dir
        mock_sess_sess.return_value = self.session_dir

        mock_sub.return_value = (True, ["example.com"])
        mock_naabu.return_value = (True, [])
        mock_http.return_value = (True, [], [])

        run_full_pipeline("example.com", self.scan_id)

        # Downstream scanners must NOT be called on 0 targets
        mock_kite.assert_not_called()
        mock_nuc.assert_not_called()
        mock_wap.assert_not_called()

        status_path = os.path.join(self.session_dir, "status.json")
        with open(status_path, "r", encoding="utf-8") as f:
            st = json.load(f)

        self.assertEqual(st.get("status"), "blocked_no_targets")
        self.assertTrue(st.get("is_completed"))
        self.assertTrue(st.get("has_error"))
        self.assertEqual(st.get("progress_percentage"), 100)

        tool_statuses = st.get("tool_statuses", {})
        self.assertEqual(tool_statuses.get("subfinder"), "success")
        self.assertEqual(tool_statuses.get("naabu"), "empty")
        self.assertEqual(tool_statuses.get("httpx"), "empty")
        self.assertEqual(tool_statuses.get("kiterunner"), "skipped")
        self.assertEqual(tool_statuses.get("nuclei"), "skipped")
        self.assertEqual(tool_statuses.get("wapiti"), "skipped")

        # Metadata consolidation check
        meta_path = os.path.join(self.session_dir, "scan_metadata.json")
        self.assertTrue(os.path.exists(meta_path))
        with open(meta_path, "r", encoding="utf-8") as mf:
            meta = json.load(mf)
        self.assertEqual(meta.get("final_status"), "blocked_no_targets")

    @patch("core.origin_recon.run_origin_recon", return_value={"is_behind_waf": False, "waf_bypassed": False})
    @patch("core.pipeline.run_subfinder")
    @patch("core.pipeline.run_naabu")
    @patch("core.pipeline.run_httpx")
    @patch("core.pipeline.run_kiterunner_or_api_probing")
    @patch("core.pipeline.run_nuclei")
    @patch("core.pipeline.run_wapiti_dast")
    @patch("core.session.get_session_dir")
    @patch("core.pipeline.get_session_dir")
    def test_non_web_ports_only_triggers_partial_status(
        self, mock_pipe_sess, mock_sess_sess, mock_wap, mock_nuc, mock_kite, mock_http, mock_naabu, mock_sub, mock_waf
    ):
        """
        2. When open ports exist (e.g. SSH 22) but zero web servers respond to HTTPX,
        the pipeline must mark status as 'partial' and skip web/API testing cleanly.
        """
        mock_pipe_sess.return_value = self.session_dir
        mock_sess_sess.return_value = self.session_dir

        mock_sub.return_value = (True, ["example.com"])
        mock_naabu.return_value = (True, ["example.com:22"])
        mock_http.return_value = (True, [], [])

        run_full_pipeline("example.com", self.scan_id)

        mock_kite.assert_not_called()
        mock_nuc.assert_not_called()
        mock_wap.assert_not_called()

        status_path = os.path.join(self.session_dir, "status.json")
        with open(status_path, "r", encoding="utf-8") as f:
            st = json.load(f)

        self.assertEqual(st.get("status"), "partial")
        self.assertTrue(st.get("is_completed"))
        self.assertEqual(st.get("tool_statuses", {}).get("naabu"), "success")
        self.assertEqual(st.get("tool_statuses", {}).get("httpx"), "empty")
        self.assertEqual(st.get("tool_statuses", {}).get("nuclei"), "skipped")

if __name__ == "__main__":
    unittest.main()
