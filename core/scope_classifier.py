import re
import os
import json
from urllib.parse import urlsplit, urljoin
from typing import Dict, Any, List, Optional, Tuple

# Comprehensive database of prominent SaaS, Cloud, CDN, and LMS signatures
KNOWN_PROVIDERS = [
    # Google Ecosystem
    {
        "name": "Google Workspace / GCP",
        "cname_regex": [r"\.googlehosted\.com$", r"\.ghs\.google\.com$", r"\.google\.com$", r"\.1e100\.net$"],
        "asn_regex": [r"\bGOOGLE\b"]
    },
    # Microsoft Ecosystem
    {
        "name": "Microsoft 365 / Azure",
        "cname_regex": [
            r"\.azurewebsites\.net$",
            r"\.cloudapp\.net$",
            r"\.trafficmanager\.net$",
            r"\.office365\.com$",
            r"\.outlook\.com$",
            r"\.sharepoint\.com$",
            r"\.microsoftonline\.com$",
            r"\.msecnd\.net$",
            r"\.azureedge\.net$"
        ],
        "asn_regex": [r"\bMICROSOFT\b"]
    },
    # Amazon AWS
    {
        "name": "Amazon AWS / CloudFront",
        "cname_regex": [
            r"\.amazonaws\.com$",
            r"\.cloudfront\.net$",
            r"\.elasticbeanstalk\.com$",
            r"\.awsglobalaccelerator\.com$"
        ],
        "asn_regex": [r"\bAMAZON\b"]
    },
    # Cloudflare CDN & Security
    {
        "name": "Cloudflare CDN & Security",
        "cname_regex": [r"\.cloudflare\.net$", r"\.cloudflare\.com$"],
        "asn_regex": [r"\bCLOUDFLARE\b"]
    },
    # Educational & Learning Management Systems (LMS)
    {
        "name": "MoodleCloud LMS",
        "cname_regex": [r"\.moodlecloud\.com$", r"\.moodle\.com$"],
        "asn_regex": []
    },
    {
        "name": "Canvas LMS (Instructure)",
        "cname_regex": [r"\.instructure\.com$"],
        "asn_regex": []
    },
    {
        "name": "Blackboard Learn",
        "cname_regex": [r"\.blackboard\.com$"],
        "asn_regex": []
    },
    # Modern Web & Developer Platforms
    {
        "name": "GitHub Pages",
        "cname_regex": [r"\.github\.io$", r"\.githubusercontent\.com$"],
        "asn_regex": []
    },
    {
        "name": "Vercel",
        "cname_regex": [r"\.vercel\.app$", r"\.vercel-dns\.com$"],
        "asn_regex": []
    },
    {
        "name": "Netlify",
        "cname_regex": [r"\.netlify\.app$", r"\.netlify\.com$"],
        "asn_regex": []
    },
    {
        "name": "Heroku",
        "cname_regex": [r"\.herokuapp\.com$"],
        "asn_regex": []
    },
    # Helpdesk & CRM
    {
        "name": "Zendesk",
        "cname_regex": [r"\.zendesk\.com$"],
        "asn_regex": []
    },
    {
        "name": "Freshdesk",
        "cname_regex": [r"\.freshdesk\.com$"],
        "asn_regex": []
    },
    {
        "name": "Salesforce",
        "cname_regex": [r"\.force\.com$", r"\.salesforce\.com$"],
        "asn_regex": []
    },
    # Content Delivery Networks (CDNs)
    {
        "name": "Akamai CDN",
        "cname_regex": [r"\.akamai\.net$", r"\.akamaiedge\.net$", r"\.akamaihd\.net$"],
        "asn_regex": [r"\bAKAMAI\b"]
    },
    {
        "name": "Fastly CDN",
        "cname_regex": [r"\.fastly\.net$", r"\.fastlylb\.net$"],
        "asn_regex": [r"\bFASTLY\b"]
    }
]

def clean_domain(domain_str: str) -> str:
    """Extracts a normalized, lowercase host without protocols, ports, or paths."""
    if not domain_str or not isinstance(domain_str, str):
        return ""
    d = domain_str.strip().lower()
    if "://" in d:
        d = d.split("://", 1)[1]
    d = d.split("/", 1)[0].split(":", 1)[0].rstrip(".")
    return d

def is_domain_matching_root(candidate: str, root_domain: str) -> bool:
    """Checks whether candidate domain is identical to root_domain or a subdomain of it."""
    clean_c = clean_domain(candidate)
    clean_r = clean_domain(root_domain)
    if not clean_c or not clean_r:
        return False
    if clean_c == clean_r:
        return True
    return clean_c.endswith("." + clean_r)

def classify_scope(
    url: str,
    host: str,
    root_domain: str,
    cname_list: Optional[List[str]] = None,
    asn_info: Optional[Dict[str, Any]] = None,
    cdn_name: Optional[str] = None,
    status_code: Optional[int] = None,
    location: Optional[str] = None,
    origin_ip: Optional[str] = None
) -> Dict[str, Any]:
    """
    Intelligently classifies an asset into Self-Hosted vs Third-Party SaaS / CDN,
    and analyzes HTTP redirection dynamics for Scope Guarding in DAST testing.
    """
    clean_root = clean_domain(root_domain)
    cnames = [c.strip().rstrip(".").lower() for c in (cname_list or []) if c and str(c).strip()]
    asn_dict = asn_info or {}
    as_name = str(asn_dict.get("as_name") or "").strip().upper()
    cdn = str(cdn_name or "").strip().lower()

    # -------------------------------------------------------------------------
    # 1. Redirection Analysis
    # -------------------------------------------------------------------------
    has_redirect = False
    redirect_type: Optional[str] = None
    target_redirect_url: Optional[str] = None

    is_redirect_code = status_code in (301, 302, 303, 307, 308)
    if is_redirect_code or location:
        has_redirect = True
        raw_loc = (location or "").strip()
        if raw_loc:
            # Resolve relative URLs
            if raw_loc.startswith("/") or not (raw_loc.startswith("http://") or raw_loc.startswith("https://")):
                target_redirect_url = urljoin(url, raw_loc)
                redirect_type = "internal"
            else:
                target_redirect_url = raw_loc
                dest_host = urlsplit(target_redirect_url).hostname or ""
                if is_domain_matching_root(dest_host, clean_root):
                    redirect_type = "internal"
                else:
                    redirect_type = "external"
        else:
            redirect_type = "internal"

    # -------------------------------------------------------------------------
    # 2. Third-Party / SaaS & Hosting Classification (Two-Tier)
    # -------------------------------------------------------------------------
    is_third_party = False
    provider_name = "Self-Hosted (Local / On-Premise)"
    hosting_type = "self_hosted"
    external_cname_target: Optional[str] = None

    clean_h = clean_domain(host)
    if origin_ip and clean_h == clean_domain(origin_ip):
        # Confirmed backend Origin IP is inherently self-hosted and in-scope
        is_third_party = False
        provider_name = "Self-Hosted Backend (Origin Server)"
        hosting_type = "self_hosted_origin"
    else:
        # Tier 1 & 2: CNAME Inspection
        for c in cnames:
            if not is_domain_matching_root(c, clean_root):
                is_third_party = True
                external_cname_target = c
                hosting_type = "third_party_saas"
                
                # Check known signatures for a friendly brand name
                matched_brand = None
                for prov in KNOWN_PROVIDERS:
                    for pat in prov["cname_regex"]:
                        if re.search(pat, c, re.IGNORECASE):
                            matched_brand = prov["name"]
                            break
                    if matched_brand:
                        break
                
                if matched_brand:
                    provider_name = matched_brand
                else:
                    provider_name = f"External Third-Party ({c})"
                break

        # If CNAME didn't flag, check CDN & ASN signals
        if not is_third_party:
            if cdn:
                # CDN Detected (e.g. cloudflare, google, akamai, etc.)
                is_third_party = True
                hosting_type = "cloud_cdn"
                provider_name = f"Cloud CDN ({cdn.title()})"
            elif as_name:
                for prov in KNOWN_PROVIDERS:
                    for asn_pat in prov["asn_regex"]:
                        if re.search(asn_pat, as_name, re.IGNORECASE):
                            # Cloud ASN without external CNAME (could be self-hosted on AWS/GCP EC2)
                            hosting_type = "cloud_hosted"
                            provider_name = f"{prov['name']} (Infrastructure)"
                            break
                    if hosting_type != "self_hosted":
                        break

    # -------------------------------------------------------------------------
    # 3. Scope Tagging for DAST Guard & UI Badges
    # -------------------------------------------------------------------------
    if redirect_type == "external":
        scope_tag = "external_redirect"
    elif is_third_party and hosting_type == "third_party_saas":
        scope_tag = "third_party_passive"
    else:
        scope_tag = "in_scope_full"

    scope_badge = build_scope_badge(
        scope_tag=scope_tag,
        is_third_party=is_third_party,
        provider=provider_name,
        redirect_url=target_redirect_url
    )

    return {
        "is_third_party": is_third_party,
        "provider": provider_name,
        "hosting_type": hosting_type,
        "cname_target": external_cname_target,
        "has_redirect": has_redirect,
        "redirect_type": redirect_type,
        "redirect_url": target_redirect_url,
        "scope_tag": scope_tag,
        "scope_badge": scope_badge
    }


def build_scope_badge(
    scope_tag: Optional[str] = None,
    is_third_party: bool = False,
    provider: Optional[str] = None,
    redirect_url: Optional[str] = None
) -> Dict[str, Any]:
    """
    Constructs a visual badge dictionary for dashboard and API presentation.
    Colors:
      - green  : In-Scope internal assets (full DAST testing allowed)
      - orange : Third-party SaaS / Cloud assets (Takeover passive check only)
      - blue   : External redirection (out of target boundary)
    """
    tag = scope_tag or ("third_party_passive" if is_third_party else "in_scope_full")
    prov = provider or "Self-Hosted"

    if tag == "external_redirect":
        return {
            "label": f"External Redirect -> {redirect_url or 'External Domain'}",
            "color": "blue",
            "dast_allowed": False,
            "takeover_checked": True,
            "description": "يعيد التوجيه لنطاق خارجي - مستبعد من DAST ومفحوص لـ Takeover"
        }
    elif is_third_party or tag == "third_party_passive":
        return {
            "label": f"Third-Party SaaS ({prov})",
            "color": "orange",
            "dast_allowed": False,
            "takeover_checked": True,
            "description": f"مستضاف لدى طرف ثالث ({prov}) - مستبعد من DAST ومفحوص لـ Takeover"
        }
    else:
        return {
            "label": "In-Scope (Full DAST Allowed)",
            "color": "green",
            "dast_allowed": True,
            "takeover_checked": False,
            "description": "أصل داخلي ضمن نطاق الهدف - مسموح فحص DAST الكامل"
        }


# ---------------------------------------------------------------------------
# Scope-Aware URL Loader (للاستخدام في Stage 3 Scope Guard)
# ---------------------------------------------------------------------------

def load_scoped_urls(session_dir: str) -> Dict[str, List[str]]:
    """
    Reads active_urls.json from the session directory and partitions URLs
    by scope_tag into three buckets used by the Stage 3 Scope Guard:

    - in_scope_urls     : scope_tag == "in_scope_full"
                          → safe for all DAST tools (Nuclei CVE, Wapiti, Kiterunner)
    - third_party_urls  : scope_tag in ("third_party_passive", "external_redirect")
                          → allowed ONLY for Nuclei Subdomain-Takeover passive check
    - all_urls          : every URL found regardless of scope

    Falls back to active_urls.txt (plain list, treated as in_scope_full)
    if the JSON file is not found or contains no scope_tag data.

    Returns a dict with keys: 'in_scope_urls', 'third_party_urls', 'all_urls',
    'excluded_count', 'in_scope_count', 'third_party_count'.
    """
    in_scope: List[str] = []
    third_party: List[str] = []
    all_urls: List[str] = []

    json_path = os.path.join(session_dir, "active_urls.json")
    txt_path  = os.path.join(session_dir, "active_urls.txt")

    # ── Primary: read from active_urls.json (has scope metadata) ────────────
    if os.path.exists(json_path):
        try:
            with open(json_path, "r", encoding="utf-8", errors="replace") as fh:
                for raw_line in fh:
                    raw_line = raw_line.strip()
                    if not raw_line:
                        continue
                    try:
                        rec = json.loads(raw_line)
                        url = str(rec.get("url") or rec.get("input") or "").strip()
                        if not url:
                            continue
                        all_urls.append(url)
                        tag = str(rec.get("scope_tag") or "").strip()
                        if tag in ("third_party_passive", "external_redirect"):
                            third_party.append(url)
                        else:
                            # "in_scope_full" or missing/unknown tag → treat as in-scope
                            in_scope.append(url)
                    except Exception:
                        pass
        except Exception:
            pass

    # ── Fallback: active_urls.txt has no scope metadata → all in-scope ──────
    if not all_urls and os.path.exists(txt_path):
        try:
            with open(txt_path, "r", encoding="utf-8") as fh:
                for line in fh:
                    url = line.strip()
                    if url:
                        all_urls.append(url)
                        in_scope.append(url)
        except Exception:
            pass

    return {
        "in_scope_urls":    in_scope,
        "third_party_urls": third_party,
        "all_urls":         all_urls,
        "in_scope_count":   len(in_scope),
        "third_party_count": len(third_party),
        "excluded_count":   len(third_party),
    }
