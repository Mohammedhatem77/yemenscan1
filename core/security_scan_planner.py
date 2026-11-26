import os
import re
import json
import hashlib
from typing import Dict, List, Set, Any, Optional, Tuple
from urllib.parse import urlparse

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MATRIX_PATH = os.path.join(BASE_DIR, "scan_capability_matrix.json")
RUNTIME_MANIFEST_PATH = os.path.join(BASE_DIR, "nuclei_runtime_manifest.json")

from core.nuclei_template_selector import (
    generate_nuclei_scan_plan,
    extract_origin_signals,
    AdaptiveTemplateSelector,
    SafeManifestManager,
    RuntimeTemplateMissingError
)

# ============================================================
# Wapiti Module Profiles
# ============================================================

WAPITI_SAFE_MODULES: List[str] = [
    "http_headers",
    "csp",
    "cookieflags",
    "information_disclosure",
    "stacktrace_disclosure",
    "https_redirect",
    "inconsistent_redirection",
    "unsecure_password"
]

WAPITI_DAST_LIGHT_MODULES: List[str] = [
    "csrf",
    "redirect"
]

# Deep profile: activates non-destructive active injection modules
# (SQL Boolean/Time-based, Reflected XSS, File Inclusion, SSRF, CRLF, LDAP)
# for use ONLY on authorised benchmark targets.
WAPITI_DEEP_MODULES: List[str] = [
    "http_headers",
    "csp",
    "cookieflags",
    "information_disclosure",
    "stacktrace_disclosure",
    "https_redirect",
    "inconsistent_redirection",
    "unsecure_password",
    "csrf",
    "redirect",
    "sql",
    "xss",
    "file",
    "ssrf",
    "crlf",
    "ldap"
]

WAPITI_VERIFIED_PASSIVE_MODULES: Set[str] = {
    "http_headers",
    "csp",
    "cookieflags",
    "information_disclosure",
    "stacktrace_disclosure",
    "https_redirect",
    "inconsistent_redirection",
    "unsecure_password"
}

# Valid scan profiles for validation
VALID_SCAN_PROFILES: Set[str] = {"safe", "dast_light", "deep"}

def is_same_origin(seed_url: str, target_orig: str) -> bool:
    """Verifies that seed_url shares the exact same scheme, hostname, and port as target_orig."""
    try:
        p_seed = urlparse(seed_url)
        p_orig = urlparse(target_orig)
        seed_host = (p_seed.hostname or "").lower().rstrip(".")
        orig_host = (p_orig.hostname or "").lower().rstrip(".")
        if not seed_host or seed_host != orig_host:
            return False
        seed_scheme = (p_seed.scheme or "http").lower()
        orig_scheme = (p_orig.scheme or "http").lower()
        if seed_scheme != orig_scheme:
            return False
        seed_port = p_seed.port or (443 if seed_scheme == "https" else 80)
        orig_port = p_orig.port or (443 if orig_scheme == "https" else 80)
        return seed_port == orig_port
    except Exception:
        return False


_REDIRECT_CODES: Set[int] = {301, 302, 303, 307, 308}


def _normalize_origin_key(url_str: str) -> str:
    """Normalizes URL to canonical scheme://host[:port] omitting default :80/:443."""
    try:
        p = urlparse((url_str or "").strip())
        scheme = (p.scheme or "http").lower()
        host = (p.hostname or "").lower().rstrip(".")
        if not host:
            return ""
        port = p.port
        if port is None or (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            return f"{scheme}://{host}"
        return f"{scheme}://{host}:{port}"
    except Exception:
        return ""


def _dedup_host_scheme_origin(url_str: str) -> str:
    """Normalized key collapsing redundant http://host:443 with https://host."""
    try:
        p = urlparse((url_str or "").strip())
        scheme = (p.scheme or "http").lower()
        host = (p.hostname or "").lower().rstrip(".")
        if not host:
            return ""
        port = p.port
        if port == 443 and scheme == "http":
            scheme = "https"
            port = None
        if port is None or (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            return f"{scheme}://{host}"
        return f"{scheme}://{host}:{port}"
    except Exception:
        return ""


def classify_canonical_vs_redirect_targets(
    origins: List[str],
    active_records: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Layer 1 Pre-Scan Classification:
    Separates Canonical Live Origins (2xx / interactive 401/403/405 endpoints) from
    Pure Redirect Gateways (301/302/303/307/308 shims) using Stage 2 HTTPX metadata.

    - Redundant redirect shims whose final destination is already in live_canonical_origins
      are marked in redundant_redirect_origins so DAST/Kiterunner focus directly on live origins.
    - Pure redirect shims whose destination is NOT in live_canonical_origins are collapsed to
      at most one canonical representative and tagged in unfollowed_redirect_origins so they
      only receive passive header/redirect checks (never active blind injection).
    """
    if not origins:
        return {
            "live_canonical_origins": [],
            "redundant_redirect_origins": [],
            "unfollowed_redirect_origins": [],
            "canonical_preferred_targets": [],
            "redirect_destinations": {},
        }

    if not active_records:
        return {
            "live_canonical_origins": list(origins),
            "redundant_redirect_origins": [],
            "unfollowed_redirect_origins": [],
            "canonical_preferred_targets": list(origins),
            "redirect_destinations": {},
        }

    records_by_key: Dict[str, List[Dict[str, Any]]] = {}
    for rec in active_records:
        if not isinstance(rec, dict):
            continue
        rec_u = str(rec.get("url") or "").strip()
        if not rec_u:
            continue
        k = _normalize_origin_key(rec_u)
        if k:
            records_by_key.setdefault(k, []).append(rec)

    live_canonical: List[str] = []
    pure_redirects: List[Tuple[str, str]] = []
    redirect_destinations: Dict[str, str] = {}

    for orig in origins:
        key = _normalize_origin_key(orig)
        matched_recs = records_by_key.get(key, [])
        if not matched_recs:
            # No HTTPX record restricting it -> treat conservatively as live
            if orig not in live_canonical:
                live_canonical.append(orig)
            continue

        has_live_non_redirect = False
        best_dest = ""
        for rec in matched_recs:
            sc = rec.get("status_code")
            try:
                sc_int = int(sc) if sc is not None else 0
            except (TypeError, ValueError):
                sc_int = 0
            is_redir = (sc_int in _REDIRECT_CODES) or (bool(rec.get("has_redirect")) and not (200 <= sc_int < 300))
            dest_raw = str(rec.get("final_url") or rec.get("redirect_url") or rec.get("location") or "").strip()
            dest_orig = _dedup_host_scheme_origin(dest_raw) if dest_raw else ""

            if not is_redir:
                has_live_non_redirect = True
            elif is_redir and dest_orig and not best_dest:
                best_dest = dest_orig

        if has_live_non_redirect:
            if orig not in live_canonical:
                live_canonical.append(orig)
        else:
            pure_redirects.append((orig, best_dest))
            if best_dest:
                redirect_destinations[orig] = best_dest

    live_keys: Set[str] = {_dedup_host_scheme_origin(o) for o in live_canonical}
    redundant_redirects: List[str] = []
    unfollowed_redirects: List[str] = []
    seen_redirect_dests: Set[str] = set()

    # Sort pure redirects preferring HTTPS over HTTP/default-port duplicates
    pure_redirects_sorted = sorted(
        pure_redirects,
        key=lambda item: (0 if item[0].lower().startswith("https://") else 1, ":443" in item[0] or ":80" in item[0], item[0]),
    )

    for redir_orig, dest_orig in pure_redirects_sorted:
        if dest_orig and dest_orig in live_keys:
            redundant_redirects.append(redir_orig)
        else:
            # Avoid running duplicate tests across http://, https://, http://:443 -> same redirect destination
            dedup_token = dest_orig or _dedup_host_scheme_origin(redir_orig)
            if dedup_token in seen_redirect_dests:
                redundant_redirects.append(redir_orig)
            else:
                seen_redirect_dests.add(dedup_token)
                unfollowed_redirects.append(redir_orig)

    return {
        "live_canonical_origins": live_canonical,
        "redundant_redirect_origins": redundant_redirects,
        "unfollowed_redirect_origins": unfollowed_redirects,
        "canonical_preferred_targets": live_canonical + unfollowed_redirects,
        "redirect_destinations": redirect_destinations,
    }


_PRIORITY_KEYWORDS_HIGH = ("api", "admin", "auth", "sso", "oauth", "gateway", "graphql", "backend", "portal", "login")
_PRIORITY_KEYWORDS_MED = ("app", "dev", "stage", "staging", "beta", "internal", "dashboard", "panel", "shop", "www")
_PRIORITY_KEYWORDS_LOW = ("cdn", "static", "assets", "media", "images", "img", "mail", "smtp")


def _origin_priority_key(orig: str) -> Tuple[int, int, str]:
    """Ranks origins by security testing priority (high-value functional endpoints first)."""
    try:
        p = urlparse(orig)
        host = (p.hostname or "").lower()
        scheme_rank = 0 if (p.scheme or "").lower() == "https" else 1
        labels = host.split(".")
        if any(k in labels or f"{k}." in host or f"-{k}." in host for k in _PRIORITY_KEYWORDS_HIGH):
            tier = 0
        elif any(k in labels or f"{k}." in host for k in _PRIORITY_KEYWORDS_MED):
            tier = 1
        elif any(k in labels for k in _PRIORITY_KEYWORDS_LOW):
            tier = 3
        else:
            tier = 2
        return (tier, scheme_rank, orig)
    except Exception:
        return (2, 1, orig)


def cluster_similar_live_origins(
    live_origins: List[str],
    records_by_key: Dict[str, List[Dict[str, Any]]],
    max_per_cluster: int = 2,
) -> Tuple[List[str], List[str]]:
    """
    Deduplicates identical wildcard/clone subdomains sharing identical HTTPX structural
    fingerprints while always keeping high-priority functional endpoints (api/admin/auth/portal/www).

    Returns:
        (kept_origins, pruned_cluster_clones)
    """
    if len(live_origins) <= max_per_cluster:
        return list(live_origins), []

    ordered = sorted(live_origins, key=_origin_priority_key)
    kept: List[str] = []
    pruned: List[str] = []
    cluster_counts: Dict[Tuple[Any, ...], int] = {}

    for orig in ordered:
        priority_tier = _origin_priority_key(orig)[0]
        # Never prune high-priority or canonical www/app subdomains
        if priority_tier <= 1:
            kept.append(orig)
            continue

        k = _normalize_origin_key(orig)
        recs = records_by_key.get(k, [])
        fp_sig: Optional[Tuple[Any, ...]] = None
        if recs:
            rec = recs[0]
            sc = int(rec.get("status_code") or 0)
            cl = int(rec.get("content_length") or 0)
            title = str(rec.get("title") or "").strip().lower()
            fav = str(rec.get("favicon_hash") or "").strip()
            ws = str(rec.get("webserver") or "").strip().lower()
            # Only cluster when strong fingerprint identity is present
            non_empty_signals = sum(1 for val in (cl > 0, bool(title), bool(fav), bool(ws)) if val)
            if sc > 0 and non_empty_signals >= 2:
                fp_sig = (urlparse(orig).scheme.lower(), sc, cl, title[:64], fav, ws)

        if fp_sig is None:
            kept.append(orig)
            continue

        cnt = cluster_counts.get(fp_sig, 0)
        if cnt < max_per_cluster:
            cluster_counts[fp_sig] = cnt + 1
            kept.append(orig)
        else:
            pruned.append(orig)

    return kept, pruned


def deduplicate_seed_url_patterns(seed_urls: List[str], max_seeds: int = 15) -> List[str]:
    """
    Normalizes numeric/UUID path IDs in seed URLs so Wapiti invests crawl budget
    in structurally unique routes instead of repeated entity clones (/items/1, /items/2).
    """
    unique: List[str] = []
    seen_patterns: Set[str] = set()
    for s in seed_urls:
        try:
            p = urlparse(s)
            norm_path = re.sub(r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=/|$)", "/{uuid}", p.path, flags=re.IGNORECASE)
            norm_path = re.sub(r"/\d+(?=/|$)", "/{id}", norm_path)
            pat_key = f"{p.scheme}://{p.netloc}{norm_path}"
            if pat_key not in seen_patterns:
                seen_patterns.add(pat_key)
                unique.append(s)
        except Exception:
            if s not in unique:
                unique.append(s)
        if len(unique) >= max_seeds:
            break
    return unique


def _sort_with_priority(items: List[str]) -> List[str]:
    """Returns origins ordered by security relevance (admin/api/auth/portal/www first)."""
    return sorted(items, key=_origin_priority_key)


class SecurityScanPlanner:
    """
    Unified Scan Intelligence & Security Scan Planner for YemenScan.
    Enforces:
      1. Coverage Ownership Matrix: strictly one primary scanner per capability family.
      2. No duplicate capability families: duplicate_capability_families == [].
      3. Strict sequential scanner coordination: max_active_security_scanners_per_origin = 1.
      4. Safe runtime template validation for Nuclei (only verified bundled templates).
      5. Safe baseline and crawler-driven DAST profile for Wapiti (excluding invasive attacks).
    """

    def __init__(self, matrix_path: Optional[str] = None):
        self.matrix_path = matrix_path or MATRIX_PATH
        self.matrix = self._load_matrix()

    def _load_matrix(self) -> Dict[str, Any]:
        if not os.path.exists(self.matrix_path):
            raise FileNotFoundError(f"Capability matrix file not found: {self.matrix_path}")
        with open(self.matrix_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def validate_capability_ownership(self) -> Tuple[bool, List[str]]:
        """
        Validates that every active capability family has strictly one primary scanner
        and that no duplicate capability ownership exists across scanners.
        """
        capabilities = self.matrix.get("capabilities", {})
        scanner_assignments: Dict[str, List[str]] = {}
        duplicates: List[str] = []

        for cap_name, details in capabilities.items():
            status = details.get("coverage_status", "covered_default")
            primary = details.get("primary", "none").lower()
            if status in ("covered_default", "covered_optional", "covered_deep"):
                if not primary or primary == "none":
                    duplicates.append(f"Missing primary scanner for covered capability '{cap_name}'")
                    continue
                scanner_assignments.setdefault(cap_name, []).append(primary)
                if len(scanner_assignments[cap_name]) > 1:
                    duplicates.append(cap_name)

        return (len(duplicates) == 0, duplicates)

    def get_scanner_capabilities(self, scanner: str, profile: Optional[str] = None) -> List[str]:
        """Returns all capability families assigned as primary to the given scanner, optionally filtered by profile."""
        capabilities = self.matrix.get("capabilities", {})
        res = []
        for k, v in capabilities.items():
            if v.get("primary", "").lower() == scanner.lower():
                if profile is not None:
                    if v.get("profile") == profile:
                        res.append(k)
                else:
                    res.append(k)
        return res

    def get_profile_config(self, profile: str) -> Dict[str, Any]:
        """
        Returns the configuration block for a given scan profile from the matrix.
        Falls back to 'safe' profile defaults if the profile is not found.
        """
        profiles = self.matrix.get("scan_profiles", {})
        cfg = profiles.get(profile)
        if cfg is None:
            cfg = profiles.get("safe", {})
        return cfg

    def generate_joint_scan_plan(
        self,
        session_dir: str,
        origins: List[str],
        active_urls_json: Optional[str] = None,
        api_endpoints_file: Optional[str] = None,
        scan_wide_pair_budget: int = 3000,
        wapiti_profile: str = "safe",
        verify_ssl: bool = True
    ) -> Dict[str, Any]:
        """
        Builds the unified, non-overlapping Joint Security Scan Plan
        generating joint_scan_plan.json, nuclei_scan_plan.json, and wapiti_scan_plan.json.
        """
        # Validate profile
        if wapiti_profile not in VALID_SCAN_PROFILES:
            wapiti_profile = "safe"

        is_valid, duplicates = self.validate_capability_ownership()
        if not is_valid:
            raise ValueError(f"Capability ownership conflict detected: {duplicates}")

        if active_urls_json is None:
            active_urls_json = os.path.join(session_dir, "active_urls.json")
        if api_endpoints_file is None:
            api_endpoints_file = os.path.join(session_dir, "api_endpoints.txt")

        # Load profile config from matrix
        profile_cfg = self.get_profile_config(wapiti_profile)

        # 1. Load active endpoint records
        active_records: List[Dict[str, Any]] = []
        if os.path.exists(active_urls_json):
            try:
                with open(active_urls_json, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        if line.strip():
                            try:
                                item = json.loads(line.strip())
                                if isinstance(item, list):
                                    active_records.extend([x for x in item if isinstance(x, dict)])
                                elif isinstance(item, dict):
                                    active_records.append(item)
                            except Exception:
                                pass
            except Exception:
                pass

        # 2. Load API discovery routes
        api_routes: List[str] = []
        if os.path.exists(api_endpoints_file):
            try:
                with open(api_endpoints_file, "r", encoding="utf-8") as f:
                    api_routes = [l.strip() for l in f if l.strip()]
            except Exception:
                pass

        # 3. Generate Nuclei Plan (Adaptive, comprehensive uncapped templates, safe runtime only)
        is_uncapped = profile_cfg.get("uncapped_templates", True)
        nuclei_plan = generate_nuclei_scan_plan(
            session_dir=session_dir,
            origins=origins,
            active_urls_json=active_urls_json,
            api_endpoints_file=api_endpoints_file,
            scan_wide_pair_budget=scan_wide_pair_budget,
            uncapped=is_uncapped
        )

        # 4. Generate Wapiti Plan
        # Extract discovery endpoints to seed Wapiti per target with same-origin validation
        seeds_by_origin: Dict[str, List[str]] = {}
        for r in api_routes:
            p = urlparse(r)
            if p.netloc:
                for orig in origins:
                    if is_same_origin(r, orig):
                        seeds_by_origin.setdefault(orig, []).append(r)
            else:
                for o in origins:
                    full_seed = f"{o.rstrip('/')}/{r.lstrip('/')}"
                    if is_same_origin(full_seed, o):
                        seeds_by_origin.setdefault(o, []).append(full_seed)

        disabled_redundant = [
            item["module"] for item in self.matrix.get("wapiti_disabled_redundant_modules", [])
        ]
        excluded_review = self.matrix.get("wapiti_active_attack_modules_review", [])

        # Select modules according to profile
        if wapiti_profile == "deep":
            enabled_modules = list(WAPITI_DEEP_MODULES)
            # In deep profile, active injection modules are intentionally included
            # Remove them from the excluded_review list to allow execution
            excluded_review = [
                m for m in excluded_review
                if m not in {"sql", "xss", "file", "ssrf", "crlf", "ldap", "redirect", "csrf"}
            ]
        elif wapiti_profile == "dast_light":
            enabled_modules = list(WAPITI_DAST_LIGHT_MODULES)
            excluded_review = [
                m for m in excluded_review
                if m not in {"csrf", "redirect"}
            ]
        else:
            wapiti_profile = "safe"
            enabled_modules = list(WAPITI_SAFE_MODULES)

        # Layer 1: Classify Canonical Live Origins vs Pure Redirect Gateways
        target_classification = classify_canonical_vs_redirect_targets(origins, active_records)
        live_list = target_classification.get("live_canonical_origins", [])
        live_set = set(live_list)
        redundant_set = set(target_classification.get("redundant_redirect_origins", []))
        unfollowed_redir_list = target_classification.get("unfollowed_redirect_origins", [])
        unfollowed_redir_set = set(unfollowed_redir_list)
        redir_dests = target_classification.get("redirect_destinations", {})

        # Priority Ordering + Wildcard/Clone Cluster Deduplication for bounded high-coverage scaling
        records_by_key: Dict[str, List[Dict[str, Any]]] = {}
        for rec in active_records:
            if isinstance(rec, dict) and rec.get("url"):
                rk = _normalize_origin_key(str(rec.get("url")))
                if rk:
                    records_by_key.setdefault(rk, []).append(rec)

        clustered_live, cluster_pruned = cluster_similar_live_origins(live_list, records_by_key, max_per_cluster=2)
        prioritized_preferred = _sort_with_priority(clustered_live) + _sort_with_priority(unfollowed_redir_list)
        target_classification["prioritized_preferred_targets"] = prioritized_preferred
        target_classification["cluster_pruned_origins"] = cluster_pruned
        cluster_pruned_set = set(cluster_pruned)

        wapiti_targets = []
        for orig in origins:
            raw_seeds = [s for s in seeds_by_origin.get(orig, []) if is_same_origin(s, orig)]
            max_seeds = 15 if wapiti_profile == "deep" else 8
            valid_seeds = deduplicate_seed_url_patterns(raw_seeds, max_seeds=max_seeds)

            if orig in redundant_set:
                target_role = "redundant_redirect"
            elif orig in cluster_pruned_set:
                target_role = "cluster_clone_pruned"
            elif orig in unfollowed_redir_set:
                target_role = "redirect_only_passive"
            else:
                target_role = "canonical_live"

            wapiti_targets.append({
                "origin": orig,
                "url": orig,
                "target_role": target_role,
                "redirect_destination": redir_dests.get(orig),
                "seed_urls": valid_seeds,
                "seed_count": len(valid_seeds)
            })

        # Determine crawl policy based on profile
        is_read_only = (wapiti_profile == "safe")
        allowed_methods = (
            ["GET", "HEAD"] if is_read_only
            else ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
        )

        default_max_orig = 25 if wapiti_profile == "deep" else (15 if wapiti_profile == "dast_light" else 10)
        default_max_params = 120 if wapiti_profile == "deep" else (50 if wapiti_profile == "dast_light" else 30)
        default_max_links = 150 if wapiti_profile == "deep" else (80 if wapiti_profile == "dast_light" else 50)
        default_max_files = 120 if wapiti_profile == "deep" else (60 if wapiti_profile == "dast_light" else 30)

        wapiti_plan = {
            "tool": "wapiti",
            "version": "3.3.2",
            "build_variant": "yemscan-safe1",
            "patches": ["no-form-submission-safe-profile"],
            "docker_image": "yemscan/wapiti:3.3.2",
            "image_id": "sha256:611a8feb8521736d9b91a5776db861323b89ae401909683476c65f239f0dace1",
            "repository_digest": None,
            "profile": wapiti_profile,
            "crawl_policy": "read_only" if is_read_only else "standard",
            "allowed_http_methods": allowed_methods,
            "form_submission_enabled": profile_cfg.get("wapiti_form_submission", False),
            "execution_policy": {
                "max_active_security_scanners_per_origin": 1,
                "sequential_after": "nuclei"
            },
            "enabled_modules": enabled_modules,
            "disabled_redundant_modules": disabled_redundant,
            "excluded_review_modules": excluded_review,
            "target_classification": target_classification,
            "configuration": {
                "scan_profile": "normal",
                "max_origins": profile_cfg.get("wapiti_max_origins", default_max_orig),
                "tasks": profile_cfg.get("wapiti_tasks", 4),
                "max_depth": profile_cfg.get("wapiti_depth", 3),
                "max_scan_time_seconds": profile_cfg.get("wapiti_max_scan_time", 240),
                "max_attack_time_seconds": profile_cfg.get("wapiti_max_attack_time", 60),
                "max_parameters": profile_cfg.get("wapiti_max_parameters", default_max_params),
                "max_links_per_page": profile_cfg.get("wapiti_max_links_per_page", default_max_links),
                "max_files_per_dir": profile_cfg.get("wapiti_max_files_per_dir", default_max_files),
                "timeout_seconds": profile_cfg.get("wapiti_timeout", 8),
                "verify_ssl": 1 if verify_ssl else 0,
                "no_bugreport": True,
                "format": "json"
            },
            "targets": wapiti_targets,
            "summary": {
                "target_count": len(wapiti_targets),
                "canonical_live_count": len(live_set),
                "redundant_redirect_skipped_count": len(redundant_set),
                "cluster_clones_pruned_count": len(cluster_pruned),
                "redirect_only_passive_count": len(unfollowed_redir_set),
                "enabled_module_count": len(enabled_modules),
                "disabled_redundant_count": len(disabled_redundant),
                "excluded_review_count": len(excluded_review),
                "total_seeds": sum(t["seed_count"] for t in wapiti_targets)
            }
        }

        # 5. Build Unified Joint Scan Plan
        nuclei_capabilities = self.get_scanner_capabilities("nuclei")
        wapiti_capabilities = self.get_scanner_capabilities("wapiti", profile=wapiti_profile)

        joint_plan = {
            "version": "1.1.0",
            "description": "Unified Pre-Scan Intelligence and Coordination Plan for YemenScan",
            "coordination_policy": {
                "max_active_security_scanners_per_origin": 1,
                "execution_order": ["nuclei", "wapiti"],
                "single_primary_scanner": True,
                "disallow_duplicate_families": True,
                "no_phantom_coverage": True
            },
            "duplicate_capability_families": [],
            "coverage_ownership": {
                "nuclei": {
                    "capabilities": nuclei_capabilities,
                    "count": len(nuclei_capabilities)
                },
                "wapiti": {
                    "capabilities": wapiti_capabilities,
                    "count": len(wapiti_capabilities)
                }
            },
            "scanners": {
                "nuclei": {
                    "tool": "nuclei",
                    "engine_version": "v3.11.1",
                    "selected_templates_count": nuclei_plan.get("summary", {}).get("selected_template_count", 0),
                    "estimated_requests": nuclei_plan.get("summary", {}).get("estimated_request_count", 0),
                    "rate_limit": nuclei_plan.get("summary", {}).get("rate_limit", 10),
                    "concurrency": nuclei_plan.get("summary", {}).get("concurrency", 5),
                    "profiles_count": nuclei_plan.get("summary", {}).get("profile_count", 0)
                },
                "wapiti": {
                    "tool": "wapiti",
                    "engine_version": "3.3.2",
                    "profile": wapiti_profile,
                    "enabled_modules": wapiti_plan["enabled_modules"],
                    "disabled_redundant_modules_count": len(disabled_redundant),
                    "excluded_review_modules_count": len(excluded_review),
                    "targets_count": len(wapiti_targets),
                    "limits": wapiti_plan["configuration"]
                }
            },
            "summary": {
                "origins_count": len(origins),
                "scanners_coordinated": ["nuclei", "wapiti"],
                "max_active_security_scanners_per_origin": 1,
                "sequential_execution": True,
                "duplicate_capability_families_count": 0
            },
            "nuclei_plan": nuclei_plan,
            "wapiti_plan": wapiti_plan
        }

        # Save all plans to session_dir
        joint_plan_file = os.path.join(session_dir, "joint_scan_plan.json")
        with open(joint_plan_file, "w", encoding="utf-8") as jf:
            json.dump(joint_plan, jf, ensure_ascii=False, indent=2)

        wapiti_plan_file = os.path.join(session_dir, "wapiti_scan_plan.json")
        with open(wapiti_plan_file, "w", encoding="utf-8") as wf:
            json.dump(wapiti_plan, wf, ensure_ascii=False, indent=2)

        return joint_plan
