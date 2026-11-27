import re
import os
import json
from urllib.parse import urlsplit, urljoin
from typing import Dict, Any, List, Optional, Tuple

# Comprehensive database of prominent SaaS, Cloud, CDN, and LMS signatures
# scope_policy values:
#   - "third_party_saas" : Independent external vendor service (strict Zero-Touch)
#   - "cloud_cdn"        : CDN / Reverse Proxy serving first-party app traffic (In-Scope)
#   - "cloud_paas"       : First-party cloud / PaaS web app hosting (In-Scope)
KNOWN_PROVIDERS = [
    # --- Strict Third-Party SaaS (Zero-Touch) ---
    {
        "name": "Google Workspace / SaaS",
        "scope_policy": "third_party_saas",
        "cname_regex": [r"\.googlehosted\.com$", r"\.ghs\.google\.com$", r"\.ghs\.googlehosted\.com$", r"\.google\.com$", r"\.1e100\.net$"],
        "asn_regex": [r"\bGOOGLE\b"]
    },
    {
        "name": "Microsoft 365 SaaS",
        "scope_policy": "third_party_saas",
        "cname_regex": [
            r"\.office365\.com$",
            r"\.outlook\.com$",
            r"\.sharepoint\.com$",
            r"\.microsoftonline\.com$",
            r"\.lync\.com$"
        ],
        "asn_regex": []
    },
    {
        "name": "MoodleCloud LMS",
        "scope_policy": "third_party_saas",
        "cname_regex": [r"\.moodlecloud\.com$", r"\.moodle\.com$"],
        "asn_regex": []
    },
    {
        "name": "Canvas LMS (Instructure)",
        "scope_policy": "third_party_saas",
        "cname_regex": [r"\.instructure\.com$"],
        "asn_regex": []
    },
    {
        "name": "Blackboard Learn",
        "scope_policy": "third_party_saas",
        "cname_regex": [r"\.blackboard\.com$"],
        "asn_regex": []
    },
    {
        "name": "Zendesk",
        "scope_policy": "third_party_saas",
        "cname_regex": [r"\.zendesk\.com$"],
        "asn_regex": []
    },
    {
        "name": "Freshdesk",
        "scope_policy": "third_party_saas",
        "cname_regex": [r"\.freshdesk\.com$"],
        "asn_regex": []
    },
    {
        "name": "Salesforce",
        "scope_policy": "third_party_saas",
        "cname_regex": [r"\.force\.com$", r"\.salesforce\.com$"],
        "asn_regex": []
    },
    {
        "name": "Atlassian / Statuspage SaaS",
        "scope_policy": "third_party_saas",
        "cname_regex": [r"\.atlassian\.net$", r"\.statuspage\.io$"],
        "asn_regex": []
    },
    {
        "name": "Marketing / Support / Docs SaaS",
        "scope_policy": "third_party_saas",
        "cname_regex": [
            r"\.hubspot\.net$",
            r"\.hs-sites\.com$",
            r"\.marketo\.com$",
            r"\.mktoweb\.com$",
            r"\.mailchimp\.com$",
            r"\.intercom\.help$",
            r"\.helpscoutdocs\.com$",
            r"\.readme\.io$"
        ],
        "asn_regex": []
    },
    {
        "name": "Hosted Storefront / Builder SaaS",
        "scope_policy": "third_party_saas",
        "cname_regex": [
            r"\.myshopify\.com$",
            r"\.shopify\.com$",
            r"\.webflow\.io$",
            r"\.proxy\.webflow\.com$",
            r"\.wixsite\.com$",
            r"\.wixdns\.net$",
            r"\.squarespace\.com$",
            r"\.squarespace-dns\.com$"
        ],
        "asn_regex": []
    },
    {
        "name": "External Hosting Portal / Mail Redirector",
        "scope_policy": "third_party_saas",
        "cname_regex": [
            r"^mail-redirect\.turbify\.com$",
            r"\.turbifyprimary\.biz$",
            r"\.cprapid\.com$"
        ],
        "asn_regex": []
    },

    # --- Cloud CDN & Reverse Proxy (In-Scope First-Party Traffic) ---
    {
        "name": "Cloudflare CDN & Security",
        "scope_policy": "cloud_cdn",
        "cname_regex": [r"\.cloudflare\.net$", r"\.cloudflare\.com$", r"\.cloudflare-dns\.com$"],
        "asn_regex": [r"\bCLOUDFLARE\b"]
    },
    {
        "name": "Amazon CloudFront CDN",
        "scope_policy": "cloud_cdn",
        "cname_regex": [r"\.cloudfront\.net$", r"\.awsglobalaccelerator\.com$"],
        "asn_regex": []
    },
    {
        "name": "Microsoft Azure CDN / Edge",
        "scope_policy": "cloud_cdn",
        "cname_regex": [r"\.azureedge\.net$", r"\.azurefd\.net$", r"\.msecnd\.net$", r"\.trafficmanager\.net$"],
        "asn_regex": []
    },
    {
        "name": "Akamai CDN",
        "scope_policy": "cloud_cdn",
        "cname_regex": [r"\.akamai\.net$", r"\.akamaiedge\.net$", r"\.akamaihd\.net$", r"\.edgekey\.net$", r"\.edgesuite\.net$"],
        "asn_regex": [r"\bAKAMAI\b"]
    },
    {
        "name": "Fastly CDN",
        "scope_policy": "cloud_cdn",
        "cname_regex": [r"\.fastly\.net$", r"\.fastlylb\.net$"],
        "asn_regex": [r"\bFASTLY\b"]
    },
    {
        "name": "Bunny / Imperva / Sucuri CDN",
        "scope_policy": "cloud_cdn",
        "cname_regex": [r"\.b-cdn\.net$", r"\.incapdns\.net$", r"\.impervadns\.net$", r"\.sucuri\.net$"],
        "asn_regex": []
    },

    # --- First-Party Cloud / PaaS App Hosting (In-Scope Web Apps) ---
    {
        "name": "Vercel",
        "scope_policy": "cloud_paas",
        "cname_regex": [r"\.vercel\.app$", r"\.vercel-dns\.com$", r"\.vercel-dns-\d+\.com$", r"^cname\.vercel-dns\.com$"],
        "asn_regex": []
    },
    {
        "name": "Netlify",
        "scope_policy": "cloud_paas",
        "cname_regex": [r"\.netlify\.app$", r"\.netlify\.com$", r"\.netlifyglobalcdn\.com$"],
        "asn_regex": []
    },
    {
        "name": "Cloudflare Pages / Workers",
        "scope_policy": "cloud_paas",
        "cname_regex": [r"\.pages\.dev$", r"\.workers\.dev$"],
        "asn_regex": []
    },
    {
        "name": "GitHub Pages",
        "scope_policy": "cloud_paas",
        "cname_regex": [r"\.github\.io$", r"\.githubusercontent\.com$"],
        "asn_regex": []
    },
    {
        "name": "Heroku",
        "scope_policy": "cloud_paas",
        "cname_regex": [r"\.herokuapp\.com$", r"\.herokudns\.com$"],
        "asn_regex": []
    },
    {
        "name": "Modern PaaS (Render / Fly / Railway / DO)",
        "scope_policy": "cloud_paas",
        "cname_regex": [r"\.onrender\.com$", r"\.fly\.dev$", r"\.up\.railway\.app$", r"\.ondigitalocean\.app$"],
        "asn_regex": []
    },
    {
        "name": "Google Cloud Run / Firebase Hosting",
        "scope_policy": "cloud_paas",
        "cname_regex": [r"\.a\.run\.app$", r"\.run\.app$", r"\.web\.app$", r"\.firebaseapp\.com$"],
        "asn_regex": []
    },
    {
        "name": "Microsoft Azure App Hosting",
        "scope_policy": "cloud_paas",
        "cname_regex": [r"\.azurewebsites\.net$", r"\.cloudapp\.net$", r"\.azurecontainerapps\.io$"],
        "asn_regex": [r"\bMICROSOFT\b"]
    },
    {
        "name": "Amazon AWS Hosting",
        "scope_policy": "cloud_paas",
        "cname_regex": [r"\.amazonaws\.com$", r"\.elasticbeanstalk\.com$", r"\.awsapprunner\.com$"],
        "asn_regex": [r"\bAMAZON\b"]
    }
]

_HOSTING_PANEL_PREFIXES = {
    "cpanel", "whm", "webmail", "webdisk",
    "cpcalendars", "cpcalendarss", "cpcontacts", "autodiscover"
}

def _is_hosting_panel_host(clean_host: str, clean_root: str) -> bool:
    """Returns True if clean_host is an administrative cPanel/mail helper subdomain."""
    if not clean_host or not clean_root or clean_host == clean_root:
        return False
    suffix = "." + clean_root
    if not clean_host.endswith(suffix):
        return False
    sub_part = clean_host[:-len(suffix)]
    labels = [lbl for lbl in sub_part.split(".") if lbl]
    return any(lbl in _HOSTING_PANEL_PREFIXES for lbl in labels)

def _match_cname_provider(cname_value: str) -> Tuple[Optional[str], Optional[str]]:
    """Matches an external CNAME against KNOWN_PROVIDERS and returns (name, scope_policy)."""
    for prov in KNOWN_PROVIDERS:
        for pat in prov.get("cname_regex", []):
            if re.search(pat, cname_value, re.IGNORECASE):
                return prov["name"], prov.get("scope_policy", "third_party_saas")
    return None, None

def _san_covers_domain(sans: List[str], domain: str) -> bool:
    """Checks if a normalized TLS SAN list covers domain either verbatim or via single-level wildcard."""
    if not domain or not sans:
        return False
    if domain in sans:
        return True
    if "." in domain:
        parent = domain.split(".", 1)[1]
        if f"*.{parent}" in sans:
            return True
    return False

def _is_verified_shared_hosting(
    clean_host: str,
    clean_root: str,
    tls_info: Optional[Dict[str, Any]]
) -> bool:
    """
    Conservative ownership proof for unknown external CNAMEs:
    Allows in-scope scanning ONLY when the host is not a hosting panel subdomain and
    presents a valid, non-expired, non-mismatched TLS certificate whose SAN list covers
    BOTH the root domain and the probed host (shared domain-owner provisioning).
    """
    if not clean_host or not clean_root or not isinstance(tls_info, dict):
        return False
    if _is_hosting_panel_host(clean_host, clean_root):
        return False
    if tls_info.get("probe_status") is False:
        return False
    if tls_info.get("expired") or tls_info.get("self_signed") or tls_info.get("mismatched"):
        return False

    raw_sans = tls_info.get("subject_an")
    if not isinstance(raw_sans, list) or not raw_sans:
        return False
    sans = [str(s).strip().lower().rstrip(".") for s in raw_sans if s and str(s).strip()]
    return _san_covers_domain(sans, clean_root) and _san_covers_domain(sans, clean_host)

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
    origin_ip: Optional[str] = None,
    tls_info: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Intelligently classifies an asset into Self-Hosted vs Third-Party SaaS / CDN / PaaS,
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
    # 2. Policy-Aware Hosting & Third-Party SaaS Classification
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
        external_cnames = [c for c in cnames if not is_domain_matching_root(c, clean_root)]

        if external_cnames:
            matched_saas: Optional[Tuple[str, str]] = None
            matched_cdn: Optional[Tuple[str, str]] = None
            matched_paas: Optional[Tuple[str, str]] = None

            for ext_c in external_cnames:
                pname, policy = _match_cname_provider(ext_c)
                if policy == "third_party_saas" and matched_saas is None:
                    matched_saas = (pname, ext_c)
                elif policy == "cloud_cdn" and matched_cdn is None:
                    matched_cdn = (pname, ext_c)
                elif policy == "cloud_paas" and matched_paas is None:
                    matched_paas = (pname, ext_c)

            if matched_saas is not None:
                # Strict Zero-Touch: real third-party SaaS wins even if cdn_name is also set
                is_third_party = True
                hosting_type = "third_party_saas"
                provider_name = matched_saas[0]
                external_cname_target = matched_saas[1]
            elif matched_cdn is not None:
                is_third_party = False
                hosting_type = "cloud_cdn"
                provider_name = f"Cloud CDN ({matched_cdn[0]})"
                external_cname_target = matched_cdn[1]
            elif matched_paas is not None:
                is_third_party = False
                hosting_type = "cloud_paas"
                provider_name = f"Cloud App Hosting ({matched_paas[0]})"
                external_cname_target = matched_paas[1]
            else:
                first_ext = external_cnames[0]
                external_cname_target = first_ext
                if _is_verified_shared_hosting(clean_h, clean_root, tls_info):
                    is_third_party = False
                    hosting_type = "shared_hosting"
                    provider_name = f"Shared Hosting ({first_ext})"
                else:
                    is_third_party = True
                    hosting_type = "third_party_saas"
                    provider_name = f"External Third-Party ({first_ext})"
        else:
            # No external CNAMEs: evaluate CDN or cloud ASN signals
            if cdn:
                is_third_party = False
                hosting_type = "cloud_cdn"
                provider_name = f"Cloud CDN ({cdn.title()})"
            elif as_name:
                for prov in KNOWN_PROVIDERS:
                    for asn_pat in prov["asn_regex"]:
                        if re.search(asn_pat, as_name, re.IGNORECASE):
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
        redirect_url=target_redirect_url,
        hosting_type=hosting_type
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
    redirect_url: Optional[str] = None,
    hosting_type: Optional[str] = None
) -> Dict[str, Any]:
    """
    Constructs a visual badge dictionary for dashboard and API presentation.
    Colors:
      - green  : In-Scope internal assets (full DAST testing allowed)
      - orange : Third-party SaaS / Cloud assets (inventory/classification only - no probing)
      - blue   : External redirection (out of target boundary - no probing)
    """
    tag = scope_tag or ("third_party_passive" if is_third_party else "in_scope_full")
    prov = provider or "Self-Hosted"

    if tag == "external_redirect":
        return {
            "label": f"External Redirect -> {redirect_url or 'External Domain'}",
            "color": "blue",
            "dast_allowed": False,
            "takeover_checked": False,
            "description": "يعيد التوجيه لنطاق خارجي - مستبعد كلياً من الفحص الأمني (تصنيف وجرد فقط)"
        }
    elif tag == "third_party_passive" or (is_third_party and hosting_type == "third_party_saas"):
        return {
            "label": f"Third-Party SaaS ({prov})",
            "color": "orange",
            "dast_allowed": False,
            "takeover_checked": False,
            "description": f"مستضاف لدى طرف ثالث ({prov}) - مستبعد كلياً من الفحص الأمني (تصنيف وجرد فقط)"
        }
    elif hosting_type == "cloud_cdn":
        return {
            "label": f"CDN-Protected ({prov})",
            "color": "green",
            "dast_allowed": True,
            "takeover_checked": False,
            "description": f"أصل داخلي محمي عبر ({prov}) - مسموح فحص DAST الكامل"
        }
    elif hosting_type == "cloud_paas":
        return {
            "label": f"{prov}",
            "color": "green",
            "dast_allowed": True,
            "takeover_checked": False,
            "description": f"تطبيق ويب تابع للجهة المستهدفة مستضاف سحابياً ({prov}) - مسموح فحص DAST الكامل"
        }
    elif hosting_type == "shared_hosting":
        return {
            "label": f"In-Scope ({prov})",
            "color": "green",
            "dast_allowed": True,
            "takeover_checked": False,
            "description": f"أصل داخلي متطابق الشهادة ومستضاف لدى ({prov}) - مسموح فحص DAST الكامل"
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
                          → excluded from all active and passive security probing (Zero-Touch)
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
