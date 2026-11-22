import os
import json
import tempfile
import unittest

from core.nuclei_template_selector import (
    extract_origin_signals,
    AdaptiveTemplateSelector,
    generate_nuclei_scan_plan,
    FAVICON_HASH_MAP
)

class TestSmartTechDetection(unittest.TestCase):
    """
    Test suite for Phase 3: Smart Planning with Favicon & TLS SANs (Zero-Overhead CVE Targeting).
    Verifies that cryptographic favicon MurmurHash3 fingerprints and TLS certificate forensics
    accurately drive targeted, safe Nuclei vulnerability templates.
    """

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="ys_smart_tech_")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_favicon_springboot_triggers_targeted_templates(self):
        """
        1. A target with Spring Boot favicon hash (116323821) must be classified as
        springboot with high confidence (100) and select Spring Boot specific templates.
        """
        records = [{
            "url": "https://api.example.com",
            "favicon_hash": "116323821",
            "tech": []
        }]
        signals = extract_origin_signals("https://api.example.com", records, [])
        eligible_tech_names = [t["name"] for t in signals["eligible_technologies"]]
        
        self.assertIn("springboot", eligible_tech_names)
        self.assertIn("spring", eligible_tech_names)
        self.assertIn("spring-actuator", eligible_tech_names)
        self.assertEqual(signals["confidence_scores"]["springboot"], 100)

        selector = AdaptiveTemplateSelector()
        plan = selector.select_templates_for_origin(signals)
        
        selected_tids = [t["template_id"] for t in plan["selected_templates"]]
        # Must have selected Layer B technology templates
        self.assertGreater(plan["layer_b_count"], 0)
        self.assertTrue(any("springboot" in tid.lower() or "spring" in tid.lower() for tid in selected_tids))

    def test_favicon_wordpress_and_jenkins_signatures(self):
        """
        2. Test WordPress (-1444503438) and Jenkins (-81586312) favicon hashes.
        """
        records_wp = [{
            "url": "https://blog.example.com",
            "favicon_hash": -1444503438,  # Int or string supported
            "tech": []
        }]
        sig_wp = extract_origin_signals("https://blog.example.com", records_wp, [])
        self.assertIn("wordpress", [t["name"] for t in sig_wp["eligible_technologies"]])

        records_jk = [{
            "url": "https://ci.example.com",
            "favicon_hash": "-81586312",
            "tech": []
        }]
        sig_jk = extract_origin_signals("https://ci.example.com", records_jk, [])
        self.assertIn("jenkins", [t["name"] for t in sig_jk["eligible_technologies"]])

    def test_tls_san_and_issuer_forensics(self):
        """
        3. TLS Subject Alternative Names (SANs) indicating services (e.g. grafana.target.com)
        and Cloudflare issuer must be correctly detected and scored.
        """
        records = [{
            "url": "https://app.example.com",
            "tls": {
                "issuer_org": "Cloudflare, Inc.",
                "subject_an": ["app.example.com", "grafana.example.com", "gitlab.example.com"]
            }
        }]
        signals = extract_origin_signals("https://app.example.com", records, [])
        
        eligible_names = [t["name"] for t in signals["eligible_technologies"]]
        self.assertIn("grafana", eligible_names)
        self.assertIn("gitlab", eligible_names)
        
        # Cloudflare CDN detected as peripheral
        self.assertIn("cloudflare", signals["confidence_scores"])
        self.assertEqual(signals["confidence_scores"]["cloudflare"], 40)

    def test_end_to_end_generate_nuclei_scan_plan_with_active_urls(self):
        """
        4. End-to-end integration: generate_nuclei_scan_plan parses active_urls.json
        with favicon and TLS metadata and constructs explainable per-origin plans.
        """
        active_json = os.path.join(self.test_dir, "active_urls.json")
        wt = {
            "url": "https://service.target.com",
            "host": "service.target.com",
            "port": 443,
            "scheme": "https",
            "favicon_hash": "116323821",
            "tls": {
                "issuer_org": "Let's Encrypt",
                "subject_an": ["service.target.com", "jenkins.target.com"]
            }
        }
        with open(active_json, "w", encoding="utf-8") as f:
            f.write(json.dumps(wt) + "\n")

        plan = generate_nuclei_scan_plan(
            session_dir=self.test_dir,
            origins=["https://service.target.com"],
            active_urls_json=active_json
        )

        self.assertIn("profiles", plan)
        self.assertGreater(plan["summary"]["selected_template_count"], 0)
        self.assertGreater(plan["summary"]["technology_template_count"], 0)

        # Check explainability
        first_prof = plan["profiles"][0]
        selected = first_prof["selected_templates"]
        tech_templates = [t for t in selected if t.get("layer") == "technology"]
        self.assertGreater(len(tech_templates), 0)
        for t in tech_templates:
            self.assertTrue(len(t.get("reasons", [])) > 0)

if __name__ == "__main__":
    unittest.main()
