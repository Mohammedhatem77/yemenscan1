import os
import json
import shutil
import tempfile
import unittest
from unittest.mock import patch

from core.stage3_vulnerabilities import (
    filter_redirect_header_false_positives,
    unify_and_save_vulnerabilities,
)


class TestSmartRedirectTriage(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="yemenscan_triage_test_")
        self.scan_id = "test-scan-redirect-triage"

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    # 1. Fully protected canonical destination (alixye.com scenario) -> all 5 redirect FPs suppressed
    def test_01_suppresses_header_fps_when_final_destination_is_protected(self):
        findings = [
            {
                "id": "WAP-CSP_POST-A19C",
                "title": "Content Security Policy (CSP) Misconfiguration",
                "severity": "LOW",
                "url": "https://alixye.com/",
                "source": "Wapiti DAST",
                "description": "CSP is not set for URL: https://alixye.com/",
            },
            {
                "id": "WAP-WEB_HEAD-BE01",
                "title": "Clickjacking Protection",
                "severity": "LOW",
                "url": "https://alixye.com/",
                "source": "Wapiti DAST",
                "description": "X-Frame-Options is not set",
            },
            {
                "id": "WAP-WEB_HEAD-30CF",
                "title": "MIME Type Confusion",
                "severity": "LOW",
                "url": "https://alixye.com/",
                "source": "Wapiti DAST",
                "description": "X-Content-Type-Options is not set",
            },
            {
                "id": "WAP-WEB_HEAD-AB97",
                "title": "Clickjacking Protection",
                "severity": "LOW",
                "url": "http://alixye.com/",
                "source": "Wapiti DAST",
                "description": "X-Frame-Options is not set",
            },
            {
                "id": "WAP-WEB_HEAD-8FF0",
                "title": "MIME Type Confusion",
                "severity": "LOW",
                "url": "http://alixye.com:443/",
                "source": "Wapiti DAST",
                "description": "X-Content-Type-Options is not set",
            },
        ]

        def fake_inspector(url):
            return {
                "initial_url": url,
                "initial_status": 308,
                "is_redirect": True,
                "redirect_hops": [{"from": url, "status_code": 308, "to": "https://www.alixye.com/"}],
                "final_url": "https://www.alixye.com/",
                "final_status": 200,
                "final_headers": {
                    "content-security-policy": "default-src 'self'",
                    "x-frame-options": "DENY",
                    "x-content-type-options": "nosniff",
                    "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
                },
            }

        verified, suppressed, canon_count = filter_redirect_header_false_positives(
            findings, header_inspector=fake_inspector
        )
        self.assertEqual(len(verified), 0)
        self.assertEqual(len(suppressed), 5)
        self.assertEqual(canon_count, 0)

    # 2. Partially protected destination across 4 Cloudflare redirect ports (hackthebox.com scenario)
    def test_02_partial_protection_and_canonical_port_deduplication(self):
        ports = ["", ":2083", ":2087", ":8443"]
        wapiti_findings = []
        for idx, p in enumerate(ports):
            base = f"https://hackthebox.com{p}/"
            wapiti_findings.extend([
                {
                    "id": f"WAP-CSP-{idx}",
                    "title": "Content Security Policy (CSP) Misconfiguration",
                    "severity": "LOW",
                    "url": base,
                    "source": "Wapiti DAST",
                    "description": f"CSP is not set for URL: {base}",
                },
                {
                    "id": f"WAP-XFO-{idx}",
                    "title": "Clickjacking Protection",
                    "severity": "LOW",
                    "url": base,
                    "source": "Wapiti DAST",
                    "description": "X-Frame-Options is not set",
                },
                {
                    "id": f"WAP-MIME-{idx}",
                    "title": "MIME Type Confusion",
                    "severity": "LOW",
                    "url": base,
                    "source": "Wapiti DAST",
                    "description": "X-Content-Type-Options is not set",
                },
            ])

        def fake_htb_inspector(url):
            return {
                "initial_url": url,
                "initial_status": 301,
                "is_redirect": True,
                "redirect_hops": [{"from": url, "status_code": 301, "to": "https://www.hackthebox.com/"}],
                "final_url": "https://www.hackthebox.com/",
                "final_status": 200,
                "final_headers": {
                    # CSP is present, X-Frame-Options and X-Content-Type-Options are genuinely missing
                    "content-security-policy": "upgrade-insecure-requests",
                    "strict-transport-security": "max-age=15552000; includeSubDomains",
                },
            }

        with patch("core.stage3_vulnerabilities._inspect_redirect_chain_headers", side_effect=fake_htb_inspector), \
             patch("core.stage3_vulnerabilities.update_status"):
            unified = unify_and_save_vulnerabilities(self.test_dir, self.scan_id, [], wapiti_findings)

        # 12 raw -> 4 CSP suppressed -> 8 remaining canonicalized to www.hackthebox.com -> deduplicated to 2 real findings!
        self.assertEqual(len(unified), 2)
        titles = sorted([u["title"] for u in unified])
        self.assertEqual(titles, ["Clickjacking Protection", "MIME Type Confusion"])
        for u in unified:
            self.assertEqual(u["url"], "https://www.hackthebox.com/")
            # Verify Security Enrichment (CWE / CVSS / OWASP) still runs cleanly on verified findings
            self.assertIsNotNone(u.get("cwe_id"))
            self.assertIsNotNone(u.get("cvss_score"))
            self.assertIsNotNone(u.get("owasp_category"))

        triage_path = os.path.join(self.test_dir, "triage_suppressed.json")
        self.assertTrue(os.path.exists(triage_path))
        with open(triage_path, "r", encoding="utf-8") as tf:
            triage_data = json.load(tf)
        self.assertEqual(triage_data["suppressed_count"], 4)
        self.assertEqual(triage_data["canonicalized_count"], 8)

    # 3. Direct 200 OK page missing headers must NEVER be suppressed
    def test_03_direct_200_missing_header_is_preserved(self):
        findings = [
            {
                "id": "WAP-WEB_HEAD-001",
                "title": "Clickjacking Protection",
                "severity": "LOW",
                "url": "https://vulnerable-app.local/",
                "source": "Wapiti DAST",
                "description": "X-Frame-Options is not set",
            }
        ]

        def fake_inspector(url):
            return {
                "initial_url": url,
                "initial_status": 200,
                "is_redirect": False,
                "redirect_hops": [],
                "final_url": url,
                "final_status": 200,
                "final_headers": {},
            }

        verified, suppressed, _ = filter_redirect_header_false_positives(
            findings, header_inspector=fake_inspector
        )
        self.assertEqual(len(verified), 1)
        self.assertEqual(len(suppressed), 0)

    # 4. Substantive flaws (CVE, SQLi, XSS, Cleartext Password) must NEVER be touched
    def test_04_substantive_vulnerabilities_never_suppressed(self):
        findings = [
            {
                "id": "CVE-2024-1234",
                "title": "Remote Code Execution",
                "severity": "CRITICAL",
                "url": "https://target.local/admin",
                "source": "Nuclei Engine",
            },
            {
                "id": "WAP-SQLI-01",
                "title": "SQL Injection",
                "severity": "HIGH",
                "url": "https://target.local/search?q=1",
                "source": "Wapiti DAST",
            },
            {
                "id": "WAP-CLEARTEXT-PASS-01",
                "title": "Cleartext Password Submission",
                "coverage_family": "cleartext_password_submission",
                "severity": "HIGH",
                "url": "http://target.local/login",
                "source": "Wapiti DAST",
                "description": "Password transmitted over cleartext HTTP",
            },
        ]

        inspector_called = []

        def fake_inspector(url):
            inspector_called.append(url)
            return None

        verified, suppressed, _ = filter_redirect_header_false_positives(
            findings, header_inspector=fake_inspector
        )
        self.assertEqual(len(verified), 3)
        self.assertEqual(len(suppressed), 0)
        self.assertEqual(inspector_called, [])

    # 5. Network failure / timeout fails safe (preserves finding)
    def test_05_network_error_fails_safe(self):
        findings = [
            {
                "id": "WAP-WEB_HEAD-002",
                "title": "MIME Type Confusion",
                "severity": "LOW",
                "url": "https://unreachable.local/",
                "source": "Wapiti DAST",
            }
        ]

        verified, suppressed, _ = filter_redirect_header_false_positives(
            findings, header_inspector=lambda url: None
        )
        self.assertEqual(len(verified), 1)
        self.assertEqual(len(suppressed), 0)

    # 6. WAF 403 challenge on final destination fails safe (does not suppress)
    def test_06_waf_403_final_response_fails_safe(self):
        findings = [
            {
                "id": "WAP-CSP-003",
                "title": "Content Security Policy (CSP) Misconfiguration",
                "severity": "LOW",
                "url": "https://waf-site.local/",
                "source": "Wapiti DAST",
            }
        ]

        def fake_waf_403(url):
            return {
                "initial_url": url,
                "initial_status": 301,
                "is_redirect": True,
                "redirect_hops": [{"from": url, "status_code": 301, "to": "https://www.waf-site.local/"}],
                "final_url": "https://www.waf-site.local/",
                "final_status": 403,
                "final_headers": {"content-security-policy": "default-src 'none'"},
            }

        verified, suppressed, _ = filter_redirect_header_false_positives(
            findings, header_inspector=fake_waf_403
        )
        self.assertEqual(len(verified), 1)
        self.assertEqual(len(suppressed), 0)

    # 7. Default web ports (:80, :443, http://host:443) collapse cleanly into one canonical HTTPS finding
    def test_07_deduplicates_default_ports_80_and_443_while_preserving_https(self):
        wapiti_findings = [
            {
                "id": "WAP-XFO-1",
                "title": "Clickjacking Protection",
                "severity": "LOW",
                "url": "http://jannahseeds.local/",
                "source": "Wapiti DAST",
                "description": "X-Frame-Options is not set",
            },
            {
                "id": "WAP-XFO-2",
                "title": "Clickjacking Protection",
                "severity": "LOW",
                "url": "http://jannahseeds.local:443/",
                "source": "Wapiti DAST",
                "description": "X-Frame-Options is not set",
            },
            {
                "id": "WAP-XFO-3",
                "title": "Clickjacking Protection",
                "severity": "LOW",
                "url": "https://jannahseeds.local:443/",
                "source": "Wapiti DAST",
                "description": "X-Frame-Options is not set",
            },
            {
                "id": "WAP-XFO-4",
                "title": "Clickjacking Protection",
                "severity": "LOW",
                "url": "http://jannahseeds.local:80/",
                "source": "Wapiti DAST",
                "description": "X-Frame-Options is not set",
            },
        ]

        with patch("core.stage3_vulnerabilities._inspect_redirect_chain_headers", return_value=None), \
             patch("core.stage3_vulnerabilities.update_status"):
            unified = unify_and_save_vulnerabilities(self.test_dir, self.scan_id, [], wapiti_findings)

        self.assertEqual(len(unified), 1)
        self.assertEqual(unified[0]["url"], "https://jannahseeds.local/")

    # 8. Non-default service ports (e.g., :2083 cPanel) remain independent from main web server (:443)
    def test_08_preserves_distinct_non_default_service_ports(self):
        wapiti_findings = [
            {
                "id": "WAP-CSP-MAIN",
                "title": "Content Security Policy (CSP) Misconfiguration",
                "severity": "LOW",
                "url": "http://jannahseeds.local/",
                "source": "Wapiti DAST",
                "description": "CSP is not set",
            },
            {
                "id": "WAP-XFO-MAIN",
                "title": "Clickjacking Protection",
                "severity": "LOW",
                "url": "http://jannahseeds.local/",
                "source": "Wapiti DAST",
                "description": "X-Frame-Options is not set",
            },
            {
                "id": "WAP-MIME-MAIN",
                "title": "MIME Type Confusion",
                "severity": "LOW",
                "url": "http://jannahseeds.local/",
                "source": "Wapiti DAST",
                "description": "X-Content-Type-Options is not set",
            },
            {
                "id": "WAP-XFO-443DUP",
                "title": "Clickjacking Protection",
                "severity": "LOW",
                "url": "http://jannahseeds.local:443/",
                "source": "Wapiti DAST",
                "description": "X-Frame-Options is not set",
            },
            {
                "id": "WAP-MIME-443DUP",
                "title": "MIME Type Confusion",
                "severity": "LOW",
                "url": "http://jannahseeds.local:443/",
                "source": "Wapiti DAST",
                "description": "X-Content-Type-Options is not set",
            },
            {
                "id": "WAP-CSP-CPANEL",
                "title": "Content Security Policy (CSP) Misconfiguration",
                "severity": "LOW",
                "url": "https://jannahseeds.local:2083/",
                "source": "Wapiti DAST",
                "description": "CSP is not set",
            },
            {
                "id": "WAP-HSTS-CPANEL",
                "title": "HTTP Strict Transport Security (HSTS)",
                "severity": "LOW",
                "url": "https://jannahseeds.local:2083/",
                "source": "Wapiti DAST",
                "description": "Strict-Transport-Security is not set",
            },
        ]

        with patch("core.stage3_vulnerabilities._inspect_redirect_chain_headers", return_value=None), \
             patch("core.stage3_vulnerabilities.update_status"):
            unified = unify_and_save_vulnerabilities(self.test_dir, self.scan_id, [], wapiti_findings)

        # 7 raw -> 2 default-port duplicates collapsed -> 5 exact distinct real findings (3 main + 2 cPanel :2083)
        self.assertEqual(len(unified), 5)
        cpanel_vulns = [u for u in unified if ":2083" in u["url"]]
        main_vulns = [u for u in unified if ":2083" not in u["url"]]
        self.assertEqual(len(cpanel_vulns), 2)
        self.assertEqual(len(main_vulns), 3)

    # 9. Scope Guard _run_nuclei_takeover_check fixes run_docker_tool signature, DooD mount, and filenames
    def test_09_nuclei_takeover_helper_invokes_run_docker_tool_correctly(self):
        from core.execution_engine import _run_nuclei_takeover_check, _NUCLEI_TAKEOVER_IMAGE

        captured = {}

        def fake_run_docker_tool(image, args, volume_dir, timeout=45, container_mount="/data", extra_volumes=None, scan_id=None):
            captured["image"] = image
            captured["args"] = list(args)
            captured["volume_dir"] = volume_dir
            captured["container_mount"] = container_mount
            captured["extra_volumes"] = extra_volumes
            captured["scan_id"] = scan_id
            # Simulate Nuclei writing a takeover finding to the exact expected output file
            out_path = os.path.join(volume_dir, "nuclei_takeover_findings.jsonl")
            with open(out_path, "w", encoding="utf-8") as fh:
                fh.write(json.dumps({
                    "template-id": "ghost-takeover",
                    "info": {
                        "name": "Ghost Subdomain Takeover",
                        "severity": "high",
                        "description": "Dangling CNAME pointing to unclaimed Ghost blog.",
                        "tags": ["takeover", "ghost"],
                    },
                    "matched-at": "https://blog.example.com",
                }) + "\n")
            return True, ""

        with patch("core.execution_engine.run_docker_tool", side_effect=fake_run_docker_tool):
            ok, findings = _run_nuclei_takeover_check(
                self.test_dir, self.scan_id, ["https://blog.example.com"]
            )

        self.assertTrue(ok)
        self.assertEqual(captured["image"], _NUCLEI_TAKEOVER_IMAGE)
        self.assertEqual(captured["volume_dir"], self.test_dir)
        self.assertEqual(captured["container_mount"], "/data")
        self.assertEqual(captured["scan_id"], self.scan_id)
        # Ensure no raw 'docker run -v' flags were stuffed into args
        self.assertNotIn("run", captured["args"])
        self.assertNotIn("-v", captured["args"])
        # Ensure exact host/container filename parity
        self.assertIn("/data/nuclei_takeover_targets.txt", captured["args"])
        self.assertIn("/data/nuclei_takeover_findings.jsonl", captured["args"])
        self.assertTrue(os.path.exists(os.path.join(self.test_dir, "nuclei_takeover_targets.txt")))
        # Ensure finding was cleanly parsed & normalized
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["id"], "ghost-takeover")
        self.assertEqual(findings[0]["severity"], "HIGH")
        self.assertEqual(findings[0]["url"], "https://blog.example.com")
        self.assertEqual(findings[0]["coverage_family"], "subdomain_takeover")


if __name__ == "__main__":
    unittest.main()
