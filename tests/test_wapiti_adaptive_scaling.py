"""
Unit & Integration Tests for Optimal Wapiti DAST Scaling, Idle Watchdog,
Adaptive Concurrency, Wildcard Cluster Dedup, and Incremental Checkpoints.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from core.runner import run_docker_tool
from core.security_scan_planner import (
    SecurityScanPlanner,
    cluster_similar_live_origins,
    deduplicate_seed_url_patterns,
)
from core.stage3_vulnerabilities import run_wapiti_dast


class TestWapitiAdaptiveScaling(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="yemenscan_wapiti_scale_")
        self.scan_id = "scan_scale_001"

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    # 1. Verify balanced matrix settings & backward compatibility
    def test_01_balanced_matrix_settings(self):
        planner = SecurityScanPlanner()
        safe_cfg = planner.get_profile_config("safe")
        light_cfg = planner.get_profile_config("dast_light")
        deep_cfg = planner.get_profile_config("deep")

        self.assertEqual(safe_cfg["wapiti_max_origins"], 10)
        self.assertEqual(safe_cfg["wapiti_tasks"], 4)
        self.assertEqual(safe_cfg["wapiti_max_scan_time"], 240)
        self.assertEqual(safe_cfg["wapiti_max_parameters"], 30)

        self.assertEqual(light_cfg["wapiti_max_origins"], 15)
        self.assertEqual(light_cfg["wapiti_tasks"], 4)

        self.assertEqual(deep_cfg["wapiti_max_origins"], 25)
        self.assertEqual(deep_cfg["wapiti_tasks"], 6)
        self.assertEqual(deep_cfg["wapiti_max_scan_time"], 900)
        self.assertEqual(deep_cfg["wapiti_max_attack_time"], 450)
        self.assertEqual(deep_cfg["wapiti_max_parameters"], 120)
        self.assertEqual(deep_cfg["wapiti_max_links_per_page"], 150)
        self.assertEqual(deep_cfg["wapiti_max_files_per_dir"], 120)
        # Matrix invariants expected by existing test_deep_scan_profile
        self.assertEqual(deep_cfg["container_timeout_wapiti"], 2700)
        self.assertEqual(deep_cfg["celery_soft_time_limit"], 7200)
        self.assertEqual(deep_cfg["celery_time_limit"], 9000)

    # 2. Wildcard/Clone Cluster Deduplication & Priority Ordering
    def test_02_wildcard_cluster_dedup_keeps_admin_api_and_prunes_clones(self):
        clones = [f"https://node{i}.corp.local" for i in range(1, 9)]
        origins = clones + ["https://www.corp.local", "https://api.corp.local", "https://admin.corp.local"]
        records_by_key = {}
        for c in clones:
            records_by_key[c] = [{
                "url": c,
                "status_code": 200,
                "content_length": 4096,
                "title": "Parked Landing",
                "webserver": "nginx",
            }]
        for special in ("https://www.corp.local", "https://api.corp.local", "https://admin.corp.local"):
            records_by_key[special] = [{
                "url": special,
                "status_code": 200,
                "content_length": 1200,
                "title": "App",
                "webserver": "nginx",
            }]

        kept, pruned = cluster_similar_live_origins(origins, records_by_key, max_per_cluster=2)
        self.assertIn("https://admin.corp.local", kept)
        self.assertIn("https://api.corp.local", kept)
        self.assertIn("https://www.corp.local", kept)
        # 8 identical low-priority clones pruned to 2 -> 6 pruned
        self.assertEqual(len(pruned), 6)
        self.assertEqual(len(kept), 5)
        # High-priority endpoints ordered first
        self.assertEqual(kept[:2], ["https://admin.corp.local", "https://api.corp.local"])

    # 3. Seed URL pattern normalization deduplicates ID variations
    def test_03_seed_url_pattern_dedup(self):
        seeds = [
            "https://shop.local/products/1",
            "https://shop.local/products/2",
            "https://shop.local/products/999",
            "https://shop.local/orders/550e8400-e29b-41d4-a716-446655440000",
            "https://shop.local/orders/660e8400-e29b-41d4-a716-446655440001",
            "https://shop.local/api/v1/login",
        ]
        deduped = deduplicate_seed_url_patterns(seeds, max_seeds=10)
        self.assertEqual(
            deduped,
            [
                "https://shop.local/products/1",
                "https://shop.local/orders/550e8400-e29b-41d4-a716-446655440000",
                "https://shop.local/api/v1/login",
            ],
        )

    # 4. Overcomes old 5-origin cutoff, uses tasks=6 & smart crawl caps, saves incrementally
    @patch("core.stage3_vulnerabilities.verify_wapiti_image_identity", return_value=True)
    @patch("core.stage3_vulnerabilities.update_status")
    def test_04_deep_profile_scans_more_than_5_origins_with_incremental_checkpoints(self, mock_update, mock_verify):
        origins = [f"https://app{i}.corp.local" for i in range(1, 9)]
        invoked_args = []
        checkpoint_counts = []

        def fake_docker(image, args, volume_dir, timeout=45, scan_id=None, extra_hosts=None, **kwargs):
            invoked_args.append(list(args))
            idx = len(invoked_args)
            out_path = args[args.index("-o") + 1].replace("/data/", "")
            with open(os.path.join(volume_dir, out_path), "w", encoding="utf-8") as wf:
                json.dump({
                    "vulnerabilities": {
                        "Clickjacking Protection": [{"method": "GET", "path": "/", "parameter": None, "info": f"h{idx}", "level": 1}]
                    }
                }, wf)
            # Check previous origins already persisted before loop ends
            if idx > 1 and os.path.exists(os.path.join(volume_dir, "wapiti_findings.json")):
                with open(os.path.join(volume_dir, "wapiti_findings.json"), "r", encoding="utf-8") as ff:
                    checkpoint_counts.append(len(json.load(ff)))
            return True, ""

        with patch("core.stage3_vulnerabilities.run_docker_tool", side_effect=fake_docker):
            ok, findings = run_wapiti_dast(self.test_dir, self.scan_id, origins, profile="deep")

        self.assertTrue(ok)
        # All 8 origins scanned (old cap=5 removed)
        self.assertEqual(len(invoked_args), 8)
        self.assertEqual(len(findings), 8)
        # Verify incremental checkpoint saves progressed steadily 1, 2, 3...
        self.assertEqual(checkpoint_counts, [1, 2, 3, 4, 5, 6, 7])
        # Verify adaptive flags (no WAF -> tasks=6, params=120, links=150, files=120, scan_time=900)
        first_args = invoked_args[0]
        self.assertEqual(first_args[first_args.index("--tasks") + 1], "6")
        self.assertEqual(first_args[first_args.index("--max-parameters") + 1], "120")
        self.assertEqual(first_args[first_args.index("--max-links-per-page") + 1], "150")
        self.assertEqual(first_args[first_args.index("--max-files-per-dir") + 1], "120")
        self.assertEqual(first_args[first_args.index("--max-scan-time") + 1], "900")
        self.assertEqual(first_args[first_args.index("--max-attack-time") + 1], "450")

    # 5. Runtime Circuit Breaker auto-throttles tasks=6 -> tasks=1 when target emits 429 spikes
    @patch("core.stage3_vulnerabilities.verify_wapiti_image_identity", return_value=True)
    @patch("core.stage3_vulnerabilities.update_status")
    def test_05_runtime_circuit_breaker_steps_down_tasks_on_429(self, mock_update, mock_verify):
        origins = ["https://app1.corp.local", "https://app2.corp.local"]
        seen_tasks = []
        seen_timeouts = []

        def fake_docker(image, args, volume_dir, timeout=45, scan_id=None, extra_hosts=None, **kwargs):
            seen_tasks.append(args[args.index("--tasks") + 1])
            seen_timeouts.append(args[args.index("-t") + 1])
            if len(seen_tasks) == 1:
                return True, "HTTP 429 Too Many Requests\nHTTP 429 Too Many Requests\nHTTP 429 Too Many Requests\nHTTP 429"
            return True, ""

        with patch("core.stage3_vulnerabilities.run_docker_tool", side_effect=fake_docker):
            run_wapiti_dast(self.test_dir, self.scan_id, origins, profile="deep")

        # Origin 1 starts fast with 6 tasks; after 429 burst, Origin 2 drops safely to 1 task + 20s timeout
        self.assertEqual(seen_tasks, ["6", "1"])
        self.assertEqual(seen_timeouts, ["15", "20"])

        with open(os.path.join(self.test_dir, "wapiti_metadata.json"), "r", encoding="utf-8") as mf:
            meta = json.load(mf)
        self.assertTrue(meta["adaptive_throttled"])
        self.assertEqual(meta["final_wapiti_tasks"], 1)

    # 6. Idle Watchdog in core/runner.py kills genuinely stalled Popen processes & preserves active ones
    @patch("core.runner.is_docker_available", return_value=True)
    def test_06_runner_idle_watchdog_stops_stalled_proc_only(self, mock_avail):
        from core.runner import _communicate_with_idle_watchdog

        # Create a small real Python subprocess that stays silent for 5s and verify idle_timeout=1 stops it
        p_hang = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(10)"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        with self.assertRaises(subprocess.TimeoutExpired):
            _communicate_with_idle_watchdog(
                proc=p_hang,
                cmd=["python"],
                volume_dir=self.test_dir,
                hard_timeout=None,
                idle_timeout=1.0,
                scan_id=None,
            )
        p_hang.kill()
        p_hang.wait(timeout=3)

        # Now run a real subprocess emitting lines faster than idle_timeout -> completes cleanly!
        p_active = subprocess.Popen(
            [sys.executable, "-c", "import time; print('tick1', flush=True); time.sleep(0.4); print('tick2', flush=True)"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        out, _ = _communicate_with_idle_watchdog(
            proc=p_active,
            cmd=["python"],
            volume_dir=self.test_dir,
            hard_timeout=None,
            idle_timeout=1.5,
            scan_id=None,
        )
        self.assertIn("tick1", out)
        self.assertIn("tick2", out)


if __name__ == "__main__":
    unittest.main()
