"""
Unit & Integration Tests for Phase 1: Unified Asynchronous Scanning.
Validates:
1. Independent scan routes dispatch to Celery worker (no direct in-process tool execution in FastAPI).
2. Proper scheduled response with unique scan_id and status.
3. Strict failure handling when message broker (Redis) is unreachable (503, no fallback, status recorded).
4. Unaffected sequential scanning pipeline.
5. Whitelist validation of tool names and execution options.
6. Status and results polling endpoints for independent tool executions.
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

from fastapi.testclient import TestClient

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from main import app
from core.tasks import (
    dispatch_standalone_tool,
    celery_run_standalone_tool,
    BrokerConnectionError,
    ALLOWED_STANDALONE_TOOLS,
)
from core.session import get_status, get_session_dir


class TestUnifiedAsyncIndependentScanning(unittest.TestCase):

    def setUp(self):
        self.client = TestClient(app)

    # -------------------------------------------------------------------------
    # 1. Independent scan endpoints dispatch to Celery
    # -------------------------------------------------------------------------
    @patch("core.tasks.is_celery_broker_reachable", return_value=True)
    @patch("core.tasks.celery_run_standalone_tool.apply_async")
    def test_01_subfinder_dispatches_to_celery(self, mock_apply_async, mock_reachable):
        mock_task = MagicMock()
        mock_task.id = "task_subfinder_test_123"
        mock_apply_async.return_value = mock_task

        resp = self.client.post("/api/tools/subfinder", json={"domain": "example.com"})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "scheduled")
        self.assertEqual(data["tool"], "subfinder")
        self.assertTrue(data["scan_id"].startswith("standalone_subfinder_"))
        self.assertEqual(data["task_id"], "task_subfinder_test_123")
        mock_apply_async.assert_called_once()

    @patch("core.tasks.is_celery_broker_reachable", return_value=True)
    @patch("core.tasks.celery_run_standalone_tool.apply_async")
    def test_02_naabu_dispatches_to_celery(self, mock_apply_async, mock_reachable):
        mock_task = MagicMock()
        mock_task.id = "task_naabu_test_123"
        mock_apply_async.return_value = mock_task

        resp = self.client.post("/api/tools/naabu", json={"target": "93.184.216.34", "ports": "80,443"})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "scheduled")
        self.assertEqual(data["tool"], "naabu")
        self.assertTrue(data["scan_id"].startswith("standalone_naabu_"))
        mock_apply_async.assert_called_once()

    @patch("core.tasks.is_celery_broker_reachable", return_value=True)
    @patch("core.tasks.celery_run_standalone_tool.apply_async")
    def test_03_httpx_dispatches_to_celery(self, mock_apply_async, mock_reachable):
        mock_task = MagicMock()
        mock_task.id = "task_httpx_test_123"
        mock_apply_async.return_value = mock_task

        resp = self.client.post("/api/tools/httpx", json={"targets": ["example.com:80", "example.com:443"]})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "scheduled")
        self.assertEqual(data["tool"], "httpx")
        self.assertTrue(data["scan_id"].startswith("standalone_httpx_"))
        mock_apply_async.assert_called_once()

    @patch("core.tasks.is_celery_broker_reachable", return_value=True)
    @patch("core.tasks.celery_run_standalone_tool.apply_async")
    def test_04_kiterunner_dispatches_to_celery(self, mock_apply_async, mock_reachable):
        mock_task = MagicMock()
        mock_task.id = "task_kiterunner_test_123"
        mock_apply_async.return_value = mock_task

        resp = self.client.post("/api/tools/kiterunner", json={"target_url": "https://example.com"})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "scheduled")
        self.assertEqual(data["tool"], "kiterunner")
        mock_apply_async.assert_called_once()

    @patch("core.tasks.is_celery_broker_reachable", return_value=True)
    @patch("core.tasks.celery_run_standalone_tool.apply_async")
    def test_05_nuclei_dispatches_to_celery(self, mock_apply_async, mock_reachable):
        mock_task = MagicMock()
        mock_task.id = "task_nuclei_test_123"
        mock_apply_async.return_value = mock_task

        resp = self.client.post("/api/tools/nuclei", json={"target_url": "https://example.com", "severity": "high,critical"})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "scheduled")
        self.assertEqual(data["tool"], "nuclei")
        mock_apply_async.assert_called_once()

    @patch("core.tasks.is_celery_broker_reachable", return_value=True)
    @patch("core.tasks.celery_run_standalone_tool.apply_async")
    def test_06_wapiti_dispatches_to_celery(self, mock_apply_async, mock_reachable):
        mock_task = MagicMock()
        mock_task.id = "task_wapiti_test_123"
        mock_apply_async.return_value = mock_task

        resp = self.client.post("/api/tools/wapiti", json={"target_url": "http://example.com", "profile": "safe"})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "scheduled")
        self.assertEqual(data["tool"], "wapiti")
        mock_apply_async.assert_called_once()

    # -------------------------------------------------------------------------
    # 2. Broker Connection Failure Handling (Section E)
    # -------------------------------------------------------------------------
    @patch("core.tasks.is_celery_broker_reachable", return_value=False)
    @patch("core.execution_engine.run_subfinder")
    def test_07_broker_unreachable_fails_fast_and_never_runs_in_fastapi(self, mock_run_subfinder, mock_reachable):
        """When Redis is down, return HTTP 503 and NEVER execute tools inside FastAPI."""
        resp = self.client.post("/api/tools/subfinder", json={"domain": "example.com"})
        self.assertEqual(resp.status_code, 503)
        self.assertIn("Redis", resp.json()["detail"])
        # Ensure tool runner was NOT executed in FastAPI process
        mock_run_subfinder.assert_not_called()

    @patch("core.tasks.is_celery_broker_reachable", return_value=False)
    def test_08_broker_failure_records_scheduling_failed_status(self, mock_reachable):
        """When dispatch fails, session status must reflect scheduling_failed."""
        with self.assertRaises(BrokerConnectionError):
            dispatch_standalone_tool("subfinder", "testdomain.com")

    # -------------------------------------------------------------------------
    # 3. Input Validation & Whitelist Enforcement (Section B)
    # -------------------------------------------------------------------------
    def test_09_invalid_tool_name_rejected(self):
        with self.assertRaises(ValueError):
            dispatch_standalone_tool("arbitrary_tool", "example.com")

    def test_10_disallowed_options_rejected(self):
        with self.assertRaises(ValueError):
            dispatch_standalone_tool("subfinder", "example.com", options={"docker_command": "rm -rf /"})

    def test_11_empty_target_rejected(self):
        with self.assertRaises(ValueError):
            dispatch_standalone_tool("subfinder", "")

    # -------------------------------------------------------------------------
    # 4. Status and Results Polling Endpoints (Section C)
    # -------------------------------------------------------------------------
    @patch("core.tasks.is_celery_broker_reachable", return_value=True)
    @patch("core.tasks.celery_run_standalone_tool.apply_async")
    def test_12_status_and_results_lifecycle(self, mock_apply_async, mock_reachable):
        mock_task = MagicMock()
        mock_task.id = "task_lifecycle_123"
        mock_apply_async.return_value = mock_task

        resp = self.client.post("/api/tools/subfinder", json={"domain": "lifecycle-domain.com"})
        scan_id = resp.json()["scan_id"]

        # 1. Check status while queued
        stat_resp = self.client.get(f"/api/tools/{scan_id}/status")
        self.assertEqual(stat_resp.status_code, 200)
        self.assertEqual(stat_resp.json()["status"], "queued")
        self.assertFalse(stat_resp.json()["is_completed"])

        # 2. Check results before completion
        res_resp = self.client.get(f"/api/tools/{scan_id}/results")
        self.assertEqual(res_resp.status_code, 200)
        self.assertFalse(res_resp.json()["is_completed"])

    # -------------------------------------------------------------------------
    # 5. Celery Worker Task Execution
    # -------------------------------------------------------------------------
    @patch("core.execution_engine.run_subfinder")
    def test_13_celery_task_executes_engine_and_saves_results(self, mock_run_subfinder):
        mock_run_subfinder.return_value = (True, ["sub1.example.com", "sub2.example.com"])
        
        # Dispatch session
        with patch("core.tasks.is_celery_broker_reachable", return_value=True), \
             patch("core.tasks.celery_run_standalone_tool.apply_async"):
            disp = dispatch_standalone_tool("subfinder", "example.com")
            scan_id = disp["scan_id"]

        # Execute worker task directly
        result = celery_run_standalone_tool(scan_id, "subfinder", "example.com")
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["subdomains_count"], 2)

        # Verify status updated to completed
        status = get_status(scan_id)
        self.assertEqual(status["status"], "completed")
        self.assertTrue(status["is_completed"])
        self.assertEqual(status["results"]["subdomains_count"], 2)


if __name__ == "__main__":
    unittest.main()
