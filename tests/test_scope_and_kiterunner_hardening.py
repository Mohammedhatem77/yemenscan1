"""
Unit Test Suite for Hardened Scope Guard Policies & Kiterunner Anti-Bot Challenge Filtering.
All tests are 100% offline with deterministic mocks (zero live network calls).
"""

import os
import sys
import json
import tempfile
import unittest
from unittest.mock import patch, MagicMock

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from core.scope_classifier import classify_scope, KNOWN_PROVIDERS
from core.stage2_web_probing import (
    run_kiterunner_or_api_probing,
    filter_spurious_api_endpoints,
    _dedup_followed_http_redirects,
)
from core.origin_recon import is_ip_associated_with_cloud_saas


class TestScopeGuardHardening(unittest.TestCase):
    """Verifies policy separation between Third-Party SaaS, CDN, Cloud PaaS, and Shared Hosting."""

    def test_third_party_saas_strict_zero_touch_preserved(self):
        saas_cases = [
            ("https://help.target.com", "help.target.com", ["target.zendesk.com"], "Zendesk"),
            ("https://crm.target.com", "crm.target.com", ["target.my.salesforce.com"], "Salesforce"),
            ("https://lms.target.edu", "lms.target.edu", ["target.moodlecloud.com"], "MoodleCloud LMS"),
            ("https://support.target.com", "support.target.com", ["target.freshdesk.com"], "Freshdesk"),
            ("https://status.target.com", "status.target.com", ["stats.statuspage.io"], "Atlassian / Statuspage SaaS"),
            ("https://shop.target.com", "shop.target.com", ["shops.myshopify.com"], "Hosted Storefront / Builder SaaS"),
        ]
        for url, host, cnames, expected_brand in saas_cases:
            res = classify_scope(
                url=url,
                host=host,
                root_domain="target.edu" if host.endswith(".edu") else "target.com",
                cname_list=cnames,
                cdn_name="cloudflare",  # Must NOT let CDN signal bypass strict SaaS Zero-Touch!
            )
            self.assertTrue(res["is_third_party"], f"{host} must remain third-party")
            self.assertEqual(res["hosting_type"], "third_party_saas")
            self.assertEqual(res["scope_tag"], "third_party_passive")
            self.assertFalse(res["scope_badge"]["dast_allowed"])
            self.assertEqual(res["provider"], expected_brand)

    def test_cdn_with_real_cname_is_in_scope_full(self):
        for host, cname in [
            ("www.target.com", "target.com.cdn.cloudflare.net"),
            ("cdn.target.com", "d111111abcdef8.cloudfront.net"),
            ("portal.target.com", "portal-target.azureedge.net"),
            ("static.target.com", "target.akamaiedge.net"),
            ("edge.target.com", "target.fastly.net"),
        ]:
            res = classify_scope(
                url=f"https://{host}",
                host=host,
                root_domain="target.com",
                cname_list=[cname],
                cdn_name="cloudflare" if "cloudflare" in cname else "",
            )
            self.assertFalse(res["is_third_party"])
            self.assertEqual(res["hosting_type"], "cloud_cdn")
            self.assertEqual(res["scope_tag"], "in_scope_full")
            self.assertTrue(res["scope_badge"]["dast_allowed"])
            self.assertEqual(res["scope_badge"]["color"], "green")

    def test_paas_first_party_apps_including_numbered_vercel_in_scope(self):
        for host, cname in [
            ("www.alixye.com", "e20db5d05bc59aa7.vercel-dns-017.com"),
            ("admin.alixye.com", "cname.vercel-dns.com"),
            ("app.alixye.com", "alixye.netlify.app"),
            ("docs.alixye.com", "alixye.github.io"),
            ("api.alixye.com", "alixye-api.herokuapp.com"),
            ("web.alixye.com", "alixye.pages.dev"),
            ("svc.alixye.com", "alixye.onrender.com"),
        ]:
            res = classify_scope(
                url=f"https://{host}",
                host=host,
                root_domain="alixye.com",
                cname_list=[cname],
            )
            self.assertFalse(res["is_third_party"], f"{host} ({cname}) should be in-scope PaaS app")
            self.assertEqual(res["hosting_type"], "cloud_paas")
            self.assertEqual(res["scope_tag"], "in_scope_full")
            self.assertTrue(res["scope_badge"]["dast_allowed"])
            self.assertEqual(res["scope_badge"]["color"], "green")

    def test_unknown_cname_shared_hosting_tls_san_ownership_vs_panels_and_unknown_saas(self):
        # 1. Legitimate www site sharing root+www valid cert on unknown CNAME (cpanel121.turbify.biz)
        valid_shared_tls = {
            "probe_status": True,
            "expired": False,
            "self_signed": False,
            "mismatched": False,
            "subject_an": ["jannahseeds.com", "www.jannahseeds.com"],
        }
        res_www = classify_scope(
            url="https://www.jannahseeds.com",
            host="www.jannahseeds.com",
            root_domain="jannahseeds.com",
            cname_list=["cpanel121.turbify.biz"],
            cdn_name="azure",
            tls_info=valid_shared_tls,
        )
        self.assertFalse(res_www["is_third_party"])
        self.assertEqual(res_www["hosting_type"], "shared_hosting")
        self.assertEqual(res_www["scope_tag"], "in_scope_full")
        self.assertTrue(res_www["scope_badge"]["dast_allowed"])

        # 2. Hosting admin panel (cpcalendars / www.cpanel / webmail) MUST stay third_party_passive even if SAN matched
        res_panel = classify_scope(
            url="https://www.cpanel.jannahseeds.com",
            host="www.cpanel.jannahseeds.com",
            root_domain="jannahseeds.com",
            cname_list=["cpanel121.turbify.biz"],
            tls_info={
                "probe_status": True,
                "expired": True,
                "self_signed": True,
                "mismatched": True,
                "subject_an": ["20-106-173-157.cprapid.com"],
            },
        )
        self.assertTrue(res_panel["is_third_party"])
        self.assertEqual(res_panel["scope_tag"], "third_party_passive")
        self.assertFalse(res_panel["scope_badge"]["dast_allowed"])

        # 3. Unknown SaaS issuing single-subdomain cert (missing root_domain in SANs) stays Zero-Touch
        res_unknown_saas = classify_scope(
            url="https://docs.company.com",
            host="docs.company.com",
            root_domain="company.com",
            cname_list=["custom-docs.vendor-saas.io"],
            tls_info={
                "probe_status": True,
                "expired": False,
                "self_signed": False,
                "mismatched": False,
                "subject_an": ["docs.company.com"],
            },
        )
        self.assertTrue(res_unknown_saas["is_third_party"])
        self.assertEqual(res_unknown_saas["scope_tag"], "third_party_passive")

        # 4. External redirect with external CNAME stays external_redirect
        res_ext = classify_scope(
            url="http://mail.jannahseeds.com",
            host="mail.jannahseeds.com",
            root_domain="jannahseeds.com",
            cname_list=["mail-redirect.turbify.com"],
            status_code=301,
            location="https://mail.turbify.com",
        )
        self.assertEqual(res_ext["scope_tag"], "external_redirect")
        self.assertFalse(res_ext["scope_badge"]["dast_allowed"])

    def test_origin_recon_still_recognizes_cloud_cnames_in_known_providers(self):
        # Ensure KNOWN_PROVIDERS keeps cname_regex intact for origin_recon PTR protection
        self.assertTrue(all("cname_regex" in p and "scope_policy" in p for p in KNOWN_PROVIDERS))
        with patch("socket.gethostbyaddr", return_value=("edge.cloudflare.net", [], ["104.16.1.1"])):
            self.assertTrue(is_ip_associated_with_cloud_saas("104.16.1.1"))


class TestKiterunnerAntiBotAndRedirectFiltering(unittest.TestCase):
    """Verifies dynamic-length Anti-Bot challenge filtering, Canary probing, and HTTP->HTTPS dedup."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.session_dir = self.temp_dir.name
        self.scan_id = "test_kr_hardening_001"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_dedup_followed_http_to_https_redirects(self):
        targets = ["https://jannahseeds.com", "http://jannahseeds.com", "http://legacy.jannahseeds.com"]
        active_recs = [
            {
                "url": "https://jannahseeds.com",
                "status_code": 200,
                "final_url": None,
                "chain_status_codes": None,
            },
            {
                "url": "http://jannahseeds.com",
                "status_code": 200,
                "final_url": "https://jannahseeds.com/",
                "chain_status_codes": [301, 200],
            },
            {
                "url": "http://legacy.jannahseeds.com",
                "status_code": 200,
                "final_url": None,
                "chain_status_codes": None,
            },
        ]
        deduped = _dedup_followed_http_redirects(targets, active_recs)
        self.assertEqual(deduped, ["https://jannahseeds.com", "http://legacy.jannahseeds.com"])

    def test_fuzzy_cluster_eliminates_dynamic_token_12kb_challenge(self):
        # Simulate jannahseeds.com 12KB Anti-Bot challenge responses with jitter (11982..12088)
        sample_paths = [
            "/Employer/42/Employee/42/Revision/42",
            "/Incidents.svc/ElevatorIncidents",
            "/NoActions/",
            "/barcode/encode",
            "/chechuco/FinEureka/1.0.0/users/createWithArray",
            "/chrome/html",
            "/cws/api/authenticated",
            "/engines/nmap/readiness",
            "/ep/admin/saga/v1/user",
            "/guestservice/guests/42",
            "/ibl/v1/categories/42/programmes",
            "/joke/categories/search",
        ]
        sample_lens = [12023, 12058, 11990, 11994, 12079, 11991, 12003, 12051, 12007, 12004, 12017, 11982]
        valid = [
            {
                "url": f"https://jannahseeds.com{p}",
                "origin": "https://jannahseeds.com",
                "method": "GET",
                "path": p,
                "status_code": 200,
                "content_length": l,
                "source": "kiterunner",
            }
            for p, l in zip(sample_paths, sample_lens)
        ]
        kept, reason, stats = filter_spurious_api_endpoints(valid)
        self.assertEqual(kept, [])
        self.assertEqual(stats["wildcard_filtered"], 12)
        self.assertEqual(stats["fuzzy_wildcard_filtered"], 12)
        self.assertIn("Anti-Bot", reason)

    def test_fuzzy_cluster_preserves_distinct_small_real_json_apis(self):
        # 8 real compact JSON endpoints with natural payload size variation (>80B spread) MUST survive
        real_routes = [
            ("/api/v1/health", 310),
            ("/api/v1/users", 450),
            ("/api/v1/orders", 580),
            ("/api/v1/products", 720),
            ("/api/v1/categories", 890),
            ("/api/v1/settings", 1040),
            ("/api/v1/notifications", 1210),
            ("/api/v1/reports", 1380),
        ]
        valid = [
            {
                "url": f"https://api.target.com{p}",
                "origin": "https://api.target.com",
                "method": "GET",
                "path": p,
                "status_code": 200,
                "content_length": l,
                "source": "kiterunner",
            }
            for p, l in real_routes
        ]
        kept, _, stats = filter_spurious_api_endpoints(valid)
        self.assertEqual(len(kept), 8)
        self.assertEqual(stats["fuzzy_wildcard_filtered"], 0)

    def test_canary_probe_catches_small_batch_403_challenge_and_preserves_rate_limit_fallback(self):
        # Write active_urls.json with only 1 in-scope origin
        with open(os.path.join(self.session_dir, "active_urls.json"), "w", encoding="utf-8") as af:
            af.write(json.dumps({"url": "https://shop.target.com", "scope_tag": "in_scope_full", "status_code": 200}) + "\n")

        # Only 4 spurious 403 WAF challenge hits returned before quarantine kicked in
        kr_lines = "\n".join([
            json.dumps({"method": "GET", "responses": [{"uri": f"https://shop.target.com/fake{i}", "sc": 403, "len": 4100 + i * 7}]})
            for i in range(4)
        ])

        with patch("core.stage2_web_probing.run_docker_tool", return_value=(True, kr_lines)), \
             patch("core.stage2_web_probing._check_origin_negative_canary_baseline", return_value={
                 "confirmed_spurious": True,
                 "is_challenge": True,
                 "is_wildcard": True,
                 "status_code": 403,
                 "body_length": 4115,
                 "matched_status_codes": {403},
             }):
            ok, endpoints = run_kiterunner_or_api_probing(["https://shop.target.com"], self.session_dir, self.scan_id)
            self.assertTrue(ok)
            self.assertEqual(endpoints, [])
            with open(os.path.join(self.session_dir, "kiterunner_metadata.json"), "r", encoding="utf-8") as mf:
                meta = json.load(mf)
            self.assertEqual(meta["filter_stats"]["canary_filtered"], 4)
            self.assertIn("Anti-Bot", meta["diagnostic_reason"])


if __name__ == "__main__":
    unittest.main()
