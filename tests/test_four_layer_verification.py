"""
Comprehensive Test Suite for the 4-Layer Precision & Verification Upgrade:
  - Layer 1: Pre-Scan Canonical Target Deduplication (Planner, Kiterunner, Wapiti)
  - Layer 2: Evidence-Aware Normalization (parse_wapiti_json_output detail.response)
  - Layer 3: Active Proof-Based Verification Engine (Redirect Guard, Benign & Double-Encoded
             Canary DOM Diffing, Error/XSS/Boolean/Timing True-Positive Preservation)
  - Layer 4: Context-Aware Attack Scope (Wapiti -S normal & passive-only mode on pure redirects)
"""

import json
import os
import shutil
import tempfile
import unittest
from unittest.mock import patch

from core.injection_verifier import (
    compute_dom_similarity,
    default_canary_probe,
    filter_unverified_injection_false_positives,
    verify_single_injection_finding,
)
from core.security_scan_planner import (
    SecurityScanPlanner,
    classify_canonical_vs_redirect_targets,
)
from core.stage2_web_probing import run_kiterunner_or_api_probing
from core.stage3_vulnerabilities import (
    parse_wapiti_json_output,
    run_wapiti_dast,
    unify_and_save_vulnerabilities,
)


class TestFourLayerVerification(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="yemenscan_4layer_")
        self.scan_id = "scan_4layer_test_001"

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    # ------------------------------------------------------------------
    # Layer 1: Pre-Scan Canonical Target Deduplication
    # ------------------------------------------------------------------
    def test_layer1_skips_redundant_redirects_when_canonical_live_exists(self):
        origins = [
            "https://alixye.com",
            "http://alixye.com",
            "http://alixye.com:443",
            "https://www.alixye.com",
            "https://admin.alixye.com",
        ]
        active_records = [
            {"url": "https://alixye.com", "status_code": 308, "has_redirect": True, "location": "https://www.alixye.com/"},
            {"url": "http://alixye.com", "status_code": 308, "has_redirect": True, "location": "https://www.alixye.com/"},
            {"url": "http://alixye.com:443", "status_code": 308, "has_redirect": True, "location": "https://www.alixye.com/"},
            {"url": "https://www.alixye.com", "status_code": 200, "has_redirect": False},
            {"url": "https://admin.alixye.com", "status_code": 200, "has_redirect": False},
        ]

        res = classify_canonical_vs_redirect_targets(origins, active_records)
        self.assertEqual(res["live_canonical_origins"], ["https://www.alixye.com", "https://admin.alixye.com"])
        self.assertEqual(len(res["redundant_redirect_origins"]), 3)
        self.assertEqual(res["unfollowed_redirect_origins"], [])
        self.assertEqual(res["canonical_preferred_targets"], ["https://www.alixye.com", "https://admin.alixye.com"])

    def test_layer1_collapses_duplicate_unfollowed_redirect_mirrors(self):
        # Simulates current pre-Scope-Guard state when only bare apex redirects are in scope
        origins = [
            "https://alixye.com",
            "http://alixye.com",
            "http://alixye.com:443",
        ]
        active_records = [
            {"url": "https://alixye.com", "status_code": 308, "has_redirect": True, "location": "https://www.alixye.com/"},
            {"url": "http://alixye.com", "status_code": 308, "has_redirect": True, "location": "https://www.alixye.com/"},
            {"url": "http://alixye.com:443", "status_code": 308, "has_redirect": True, "location": "https://www.alixye.com/"},
        ]

        res = classify_canonical_vs_redirect_targets(origins, active_records)
        self.assertEqual(res["live_canonical_origins"], [])
        self.assertEqual(res["unfollowed_redirect_origins"], ["https://alixye.com"])
        self.assertEqual(len(res["redundant_redirect_origins"]), 2)

    @patch("core.stage2_web_probing.run_docker_tool", return_value=(True, ""))
    def test_layer1_kiterunner_deduplicates_redundant_redirects(self, mock_docker):
        active_json = os.path.join(self.test_dir, "active_urls.json")
        recs = [
            {"url": "https://site.local", "status_code": 308, "has_redirect": True, "location": "https://www.site.local/"},
            {"url": "http://site.local", "status_code": 308, "has_redirect": True, "location": "https://www.site.local/"},
            {"url": "https://www.site.local", "status_code": 200, "has_redirect": False},
        ]
        with open(active_json, "w", encoding="utf-8") as f:
            for r in recs:
                f.write(json.dumps(r) + "\n")

        ok, _ = run_kiterunner_or_api_probing([r["url"] for r in recs], self.test_dir, self.scan_id)
        self.assertTrue(ok)

        with open(os.path.join(self.test_dir, "kiterunner_input.txt"), "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()]
        self.assertEqual(lines, ["https://www.site.local"])

    # ------------------------------------------------------------------
    # Layer 2: Evidence-Aware Normalization
    # ------------------------------------------------------------------
    def test_layer2_parse_wapiti_preserves_response_evidence(self):
        raw_path = os.path.join(self.test_dir, "wapiti_raw.json")
        payload = {
            "vulnerabilities": {
                "LDAP Injection": [
                    {
                        "method": "GET",
                        "path": "/",
                        "parameter": "QUERY_STRING",
                        "info": "LDAP Injection in https://alixye.com/ via injection in the query string",
                        "level": 4,
                        "curl_command": 'curl "https://alixye.com/?%2A%29%29%00nosuchvalue"',
                        "detail": {
                            "response": {
                                "status_code": 308,
                                "body": '<!doctype html><h1>Redirecting (308)</h1><a href="https://www.alixye.com/?%252A%2529%2529%2500nosuchvalue">here</a>',
                                "headers": [
                                    ["content-type", "text/html"],
                                    ["location", "https://www.alixye.com/?%2A%29%29%00nosuchvalue"],
                                    ["server", "Vercel"],
                                ],
                            }
                        },
                    }
                ]
            }
        }
        with open(raw_path, "w", encoding="utf-8") as f:
            json.dump(payload, f)

        findings, _ = parse_wapiti_json_output(raw_path, "https://alixye.com")
        self.assertEqual(len(findings), 1)
        f0 = findings[0]
        self.assertEqual(f0["response_evidence"]["status_code"], 308)
        self.assertEqual(f0["response_evidence"]["location"], "https://www.alixye.com/?%2A%29%29%00nosuchvalue")
        self.assertEqual(f0["response_evidence"]["content_type"], "text/html")
        self.assertIn("Redirecting (308)", f0["response_evidence"]["body_excerpt"])
        self.assertEqual(f0["source_evidence"]["response_status_code"], 308)

    # ------------------------------------------------------------------
    # Layer 3: Active Proof-Based Verification Engine
    # ------------------------------------------------------------------
    def test_layer3_suppresses_vercel_308_double_encoded_ldap_false_positive(self):
        raw_path = os.path.join(self.test_dir, "wapiti_raw.json")
        raw_payload = {
            "vulnerabilities": {
                "LDAP Injection": [
                    {
                        "method": "GET",
                        "path": "/",
                        "parameter": "QUERY_STRING",
                        "info": "LDAP Injection in https://alixye.com/ via injection in the query string",
                        "level": 4,
                        "curl_command": 'curl "https://alixye.com/?%2A%29%29%00nosuchvalue"',
                        "detail": {
                            "response": {
                                "status_code": 308,
                                "body": '<!doctype html><h1>Redirecting (308)</h1><a href="https://www.alixye.com/?%252A%2529%2529%2500nosuchvalue">here</a>',
                                "headers": [
                                    ["location", "https://www.alixye.com/?%2A%29%29%00nosuchvalue"],
                                    ["content-type", "text/html"],
                                ],
                            }
                        },
                    }
                ],
                "Content Security Policy Configuration": [
                    {"method": "GET", "path": "/", "parameter": None, "info": "CSP missing", "level": 1}
                ],
            }
        }
        with open(raw_path, "w", encoding="utf-8") as f:
            json.dump(raw_payload, f)

        wapiti_findings, _ = parse_wapiti_json_output(raw_path, "https://alixye.com")

        def fake_header_inspector(url):
            return {
                "initial_url": url,
                "initial_status": 308,
                "is_redirect": True,
                "final_url": "https://www.alixye.com/",
                "final_status": 200,
                "final_headers": {"content-security-policy": "default-src 'self'"},
            }

        with patch("core.stage3_vulnerabilities._inspect_redirect_chain_headers", side_effect=fake_header_inspector), \
             patch("core.stage3_vulnerabilities.update_status"):
            unified = unify_and_save_vulnerabilities(self.test_dir, self.scan_id, [], wapiti_findings)

        # Both the 308 CSP FP and the 308 CRITICAL LDAP Injection FP must be suppressed!
        self.assertEqual(len(unified), 0)
        triage_file = os.path.join(self.test_dir, "triage_suppressed.json")
        self.assertTrue(os.path.exists(triage_file))
        with open(triage_file, "r", encoding="utf-8") as tf:
            tdata = json.load(tf)
        self.assertEqual(tdata["suppressed_count"], 2)
        self.assertEqual(tdata["redirect_suppressed_count"], 1)
        self.assertEqual(tdata["injection_suppressed_count"], 1)

    def test_layer3_suppresses_spa_200_canary_dom_invariant_false_positive(self):
        spa_html = (
            '<!doctype html><html lang="en"><head><title>App</title>'
            '<meta name="x-request-id" content="{nonce}">'
            '</head><body><div id="root"><h1>Welcome</h1><script src="/app.js"></script></div></body></html>'
        )

        def fake_spa_probe(url):
            # Simulates an SPA on Vercel/Cloudflare ignoring any query params & double encodings
            return {
                "url": url,
                "status_code": 200,
                "headers": {"content-type": "text/html"},
                "location": "",
                "body": spa_html.replace("{nonce}", "uuid-1234-abcd" if "canary" in url else "uuid-9999-ef01"),
            }

        finding = {
            "id": "WAP-LDAP-SPAR",
            "title": "LDAP Injection",
            "severity": "CRITICAL",
            "coverage_family": "ldap_injection",
            "url": "https://www.any-spa-site.example.org/",
            "source_evidence": {
                "parameter": "QUERY_STRING",
                "curl_command": 'curl "https://www.any-spa-site.example.org/?%2A%29%29%00nosuchvalue"',
            },
        }

        verified, suppressed = filter_unverified_injection_false_positives([finding], probe_fn=fake_spa_probe)
        self.assertEqual(len(verified), 0)
        self.assertEqual(len(suppressed), 1)
        self.assertEqual(suppressed[0]["rule_gate"], "canary_dom_invariance_proof")

    def test_layer3_preserves_genuine_sql_and_ldap_error_proofs(self):
        sqli = {
            "id": "WAP-SQLI-REAL",
            "title": "SQL Injection Vulnerability",
            "severity": "CRITICAL",
            "coverage_family": "sql_injection",
            "url": "https://vuln-shop.local/products.php?id=1",
            "response_evidence": {
                "status_code": 200,
                "body_excerpt": "Warning: mysql_fetch_array(): You have an error in your SQL syntax near ''' at line 1",
            },
        }
        ldapi = {
            "id": "WAP-LDAP-REAL",
            "title": "LDAP Injection",
            "severity": "CRITICAL",
            "coverage_family": "ldap_injection",
            "url": "https://corp-portal.local/directory?user=*",
            "response_evidence": {
                "status_code": 500,
                "body_excerpt": "javax.naming.NameNotFoundException: [LDAP: error code 32 - No Such Object]",
            },
        }

        verified, suppressed = filter_unverified_injection_false_positives([sqli, ldapi])
        self.assertEqual(len(verified), 2)
        self.assertEqual(len(suppressed), 0)
        self.assertEqual(verified[0]["verification_status"], "confirmed_error_proof")
        self.assertEqual(verified[1]["verification_status"], "confirmed_error_proof")

    def test_layer3_preserves_genuine_dom_xss_and_boolean_sqli_and_timesql(self):
        xss = {
            "id": "WAP-XSS-REAL",
            "title": "Cross-Site Scripting (XSS)",
            "severity": "HIGH",
            "coverage_family": "cross_site_scripting",
            "url": "https://legacy-site.test/search?q=1",
            "source_evidence": {
                "parameter": "q",
                "curl_command": 'curl "https://legacy-site.test/search?q=<script>alert(1)</script>"',
            },
        }

        def fake_xss_probe(url):
            base_body = "<html><body><h1>Search</h1><div class='res'>Results</div></body></html>"
            if "<script>" in url:
                return {"url": url, "status_code": 200, "headers": {}, "body": base_body.replace("Results", "<script>alert(1)</script>")}
            return {"url": url, "status_code": 200, "headers": {}, "body": base_body}

        verified_xss, sup_xss = filter_unverified_injection_false_positives([xss], probe_fn=fake_xss_probe)
        self.assertEqual(len(verified_xss), 1)
        self.assertEqual(len(sup_xss), 0)
        self.assertEqual(verified_xss[0]["verification_status"], "confirmed_dom_xss")

        # True Boolean Differential SQLi changing table rows vs static benign canary must remain preserved
        bool_sqli = {
            "id": "WAP-BOOL-REAL",
            "title": "SQL Injection Vulnerability",
            "severity": "CRITICAL",
            "coverage_family": "sql_injection",
            "url": "https://legacy-site.test/products?cat=1",
            "source_evidence": {
                "parameter": "cat",
                "curl_command": 'curl "https://legacy-site.test/products?cat=1%20OR%201=1"',
            },
        }

        def fake_bool_probe(url):
            base = "<html><body><table><tr><td>Item 1</td></tr></table></body></html>"
            if "OR" in url or "1%20OR" in url:
                rows = "".join(f"<tr><td>Leaked User {i}</td><td>hash_{i}</td></tr>" for i in range(15))
                return {"url": url, "status_code": 200, "headers": {}, "body": f"<html><body><table>{rows}</table></body></html>"}
            return {"url": url, "status_code": 200, "headers": {}, "body": base}

        verified_b, sup_b = filter_unverified_injection_false_positives([bool_sqli], probe_fn=fake_bool_probe)
        self.assertEqual(len(verified_b), 1)
        self.assertEqual(len(sup_b), 0)
        self.assertEqual(verified_b[0]["verification_status"], "confirmed_structural_differential")

        # Time-based Blind SQLi must remain untouched on 200 OK even with identical DOM
        timesql = {
            "id": "WAP-TIME-REAL",
            "title": "SQL Injection (Time-Based Blind)",
            "severity": "CRITICAL",
            "coverage_family": "sql_injection",
            "source_rule": "timesql",
            "url": "https://legacy-site.test/item?id=5",
            "source_evidence": {"parameter": "id"},
        }
        verified_t, sup_t = filter_unverified_injection_false_positives(
            [timesql],
            probe_fn=lambda u: {"url": u, "status_code": 200, "headers": {}, "body": "<html><body>Item 5</body></html>"},
        )
        self.assertEqual(len(verified_t), 1)
        self.assertEqual(len(sup_t), 0)
        self.assertEqual(verified_t[0]["verification_status"], "candidate_time_based")

    def test_layer3_ssrf_blocks_loopback_and_metadata_in_control_probes(self):
        self.assertIsNone(default_canary_probe("http://127.0.0.1:8000/test"))
        self.assertIsNone(default_canary_probe("http://169.254.169.254/latest/meta-data/"))
        self.assertIsNone(default_canary_probe("https://example.com/"))

    def test_layer3_dom_similarity_normalizes_double_url_encoding(self):
        clean = '<html><h1>Redirecting (308)</h1><a href="https://www.site.com/?ys_canary=7f3a9c12">here</a></html>'
        dbl = '<html><h1>Redirecting (308)</h1><a href="https://www.site.com/?ys_canary=%252A%2529%25007f3a9c12">here</a></html>'
        sim = compute_dom_similarity(clean, dbl, extra_strip_tokens=["ys_canary", "7f3a9c12"])
        self.assertGreaterEqual(sim, 0.99)

    # ------------------------------------------------------------------
    # Layer 4: Context-Aware Attack Scope
    # ------------------------------------------------------------------
    @patch("core.stage3_vulnerabilities.verify_wapiti_image_identity", return_value=True)
    @patch("core.stage3_vulnerabilities.run_docker_tool", return_value=(True, ""))
    @patch("core.stage3_vulnerabilities.update_status")
    def test_layer4_wapiti_restricts_redirect_only_target_to_passive_modules_and_normal_force(
        self, mock_update, mock_docker, mock_verify
    ):
        # Write active_urls.json proving https://only-redirect.com returns 308
        active_json = os.path.join(self.test_dir, "active_urls.json")
        recs = [
            {"url": "https://only-redirect.com", "status_code": 308, "has_redirect": True, "location": "https://www.external-other.com/"},
            {"url": "http://only-redirect.com", "status_code": 308, "has_redirect": True, "location": "https://www.external-other.com/"},
            {"url": "http://only-redirect.com:443", "status_code": 308, "has_redirect": True, "location": "https://www.external-other.com/"},
        ]
        with open(active_json, "w", encoding="utf-8") as f:
            for r in recs:
                f.write(json.dumps(r) + "\n")

        run_wapiti_dast(
            self.test_dir,
            self.scan_id,
            [r["url"] for r in recs],
            profile="deep",
        )

        # Should invoke Wapiti ONLY ONCE (not 3 duplicate mirrors)
        self.assertEqual(mock_docker.call_count, 1)
        args = mock_docker.call_args[1]["args"]
        self.assertEqual(args[args.index("-u") + 1], "https://only-redirect.com")
        # Should use -S normal (Layer 4)
        self.assertEqual(args[args.index("-S") + 1], "normal")
        # Redirect-only gateway must NOT run blind injection modules (sql, ldap, xss, file, crlf, ssrf)
        mods = args[args.index("-m") + 1].split(",")
        for forbidden in ("sql", "ldap", "xss", "file", "crlf", "ssrf"):
            self.assertNotIn(forbidden, mods)
        self.assertIn("http_headers", mods)
        self.assertIn("csp", mods)
        self.assertIn("--no-form-submission", args)


if __name__ == "__main__":
    unittest.main()
