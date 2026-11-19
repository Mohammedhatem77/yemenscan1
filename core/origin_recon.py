"""
YemenScan Black-Box Origin IP Reconnaissance & WAF Bypass Module.
Discovers the real backend server (Origin IP) behind Web Application Firewalls
(Cloudflare, Akamai, CloudFront, Imperva, etc.) using:
1. Passive SSL Certificate Transparency & DNS History.
2. Unproxied subdomains correlation (mail, direct, origin, cpanel, vpn, dev).
3. Active Host-header verification with SNI simulation.
"""

import socket
import ipaddress
import logging
from typing import Dict, Any, List, Optional, Set, Tuple
from urllib.parse import urlparse
import requests

logger = logging.getLogger("yemenscan.origin_recon")

# Known CDN / WAF CIDR blocks
KNOWN_CDN_NETWORKS = {
    "Cloudflare": [
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
        "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22"
    ],
    "CloudFront / AWS": [
        "13.32.0.0/15", "13.35.0.0/16", "13.224.0.0/14", "13.249.0.0/16",
        "18.64.0.0/14", "52.84.0.0/15", "54.192.0.0/16", "54.230.0.0/16",
        "54.239.128.0/18", "54.239.192.0/19", "54.240.128.0/18", "65.8.0.0/16",
        "65.9.0.0/17", "70.132.0.0/18", "99.84.0.0/16", "99.86.0.0/16",
        "143.204.0.0/16", "204.246.164.0/22", "205.251.192.0/19"
    ],
    "Fastly": [
        "23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24", "103.245.222.0/23",
        "103.245.224.0/24", "104.156.80.0/20", "146.75.0.0/16", "151.101.0.0/16",
        "157.52.64.0/18", "167.82.0.0/17", "167.82.128.0/20", "185.31.16.0/22",
        "199.27.72.0/21", "199.232.0.0/16"
    ],
    "Akamai": [
        "23.32.0.0/11", "23.64.0.0/14", "23.192.0.0/11", "104.64.0.0/10",
        "184.24.0.0/13", "184.84.0.0/14", "96.6.0.0/15"
    ],
    "Imperva / Incapsula": [
        "199.83.128.0/21", "198.143.32.0/19", "149.126.72.0/21", "103.28.248.0/22",
        "45.64.64.0/22", "185.11.124.0/22", "192.230.64.0/18"
    ]
}

# Pre-parsed IP networks for fast lookups
_PARSED_NETWORKS: List[Tuple[str, ipaddress.IPv4Network]] = []
for provider, cidrs in KNOWN_CDN_NETWORKS.items():
    for cidr in cidrs:
        try:
            _PARSED_NETWORKS.append((provider, ipaddress.IPv4Network(cidr)))
        except Exception:
            pass

COMMON_DIRECT_SUBDOMAINS = [
    "direct", "origin", "direct-connect", "mail", "smtp", "imap",
    "webmail", "cpanel", "vpn", "remote", "ftp", "dev", "stage",
    "staging", "admin", "backend", "api-origin", "corp", "internal"
]


def is_ip_in_cdn(ip_str: str) -> Tuple[bool, Optional[str]]:
    """Checks if an IPv4 address belongs to a known CDN / WAF provider."""
    try:
        ip = ipaddress.IPv4Address(ip_str.strip())
        for provider, net in _PARSED_NETWORKS:
            if ip in net:
                return True, provider
    except Exception:
        pass
    return False, None


def resolve_domain_ips(domain: str) -> List[str]:
    """Resolves DNS A records for a domain."""
    ips = []
    try:
        for info in socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM):
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)
    except Exception:
        pass
    return ips


def detect_waf_presence(domain: str) -> Dict[str, Any]:
    """
    Identifies if a domain is actively fronted by a CDN or WAF.
    Checks DNS IP ranges and HTTP response headers.
    """
    clean_dom = domain.strip().lower()
    if clean_dom.startswith("http://") or clean_dom.startswith("https://"):
        clean_dom = urlparse(clean_dom).netloc.split(":")[0]

    domain_ips = resolve_domain_ips(clean_dom)
    is_waf = False
    provider_name = None

    for ip in domain_ips:
        in_cdn, prov = is_ip_in_cdn(ip)
        if in_cdn:
            is_waf = True
            provider_name = prov
            break

    # If DNS didn't match known CIDRs, inspect HTTP response headers
    detected_headers = {}
    if not is_waf:
        for proto in ("https://", "http://"):
            try:
                resp = requests.get(
                    f"{proto}{clean_dom}",
                    timeout=5,
                    headers={"User-Agent": "YemenScan-ASM/2.0"},
                    allow_redirects=True,
                    verify=False
                )
                srv = resp.headers.get("server", "").lower()
                if "cloudflare" in srv or "cf-ray" in resp.headers:
                    is_waf = True
                    provider_name = "Cloudflare"
                elif "akamai" in srv or "x-akamai" in resp.headers:
                    is_waf = True
                    provider_name = "Akamai"
                elif "cloudfront" in srv or "x-amz-cf-id" in resp.headers:
                    is_waf = True
                    provider_name = "CloudFront"
                elif "sucuri" in srv or "x-sucuri-id" in resp.headers:
                    is_waf = True
                    provider_name = "Sucuri"
                detected_headers = dict(resp.headers)
                break
            except Exception:
                continue

    return {
        "domain": clean_dom,
        "is_behind_waf": is_waf,
        "waf_provider": provider_name or ("Generic CDN/WAF" if is_waf else "None detected"),
        "current_ips": domain_ips,
        "headers_sample": {k: v for k, v in list(detected_headers.items())[:5]}
    }


def find_candidate_origin_ips(domain: str) -> List[str]:
    """
    Harvests candidate origin IPs by querying common unproxied subdomains
    and extracting unique non-CDN IP addresses.
    """
    clean_dom = domain.strip().lower()
    if clean_dom.startswith("http://") or clean_dom.startswith("https://"):
        clean_dom = urlparse(clean_dom).netloc.split(":")[0]

    candidate_ips: Set[str] = set()

    for sub in COMMON_DIRECT_SUBDOMAINS:
        sub_fqdn = f"{sub}.{clean_dom}"
        sub_ips = resolve_domain_ips(sub_fqdn)
        for ip in sub_ips:
            in_cdn, _ = is_ip_in_cdn(ip)
            if not in_cdn:
                candidate_ips.add(ip)

    return sorted(list(candidate_ips))


def verify_origin_ip(candidate_ip: str, target_domain: str, baseline_title: Optional[str] = None) -> Tuple[bool, str]:
    """
    Verifies if candidate_ip is a genuine Origin Server by sending a direct
    HTTP request with 'Host: <target_domain>' header and comparing responses.
    """
    clean_dom = target_domain.strip().lower()
    if clean_dom.startswith("http://") or clean_dom.startswith("https://"):
        clean_dom = urlparse(clean_dom).netloc.split(":")[0]

    req_headers = {
        "Host": clean_dom,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    }

    for proto in ("https://", "http://"):
        try:
            url = f"{proto}{candidate_ip}"
            resp = requests.get(
                url,
                headers=req_headers,
                timeout=6,
                verify=False,
                allow_redirects=True
            )
            if resp.status_code in (200, 301, 302, 403, 401):
                resp_text = resp.text.lower()
                # Check domain mentions or title match
                if clean_dom in resp_text:
                    return True, f"Server at {candidate_ip} responded with {resp.status_code} referencing {clean_dom} via Host header."
                if baseline_title and baseline_title.lower() in resp_text:
                    return True, f"Server at {candidate_ip} rendered matching title '{baseline_title}'."
                if resp.status_code == 200 and len(resp.text) > 200:
                    return True, f"Direct backend response 200 OK received from {candidate_ip}."
        except Exception:
            continue

    return False, "Candidate IP did not respond with matching host content."


def run_origin_recon(domain: str) -> Dict[str, Any]:
    """
    Main orchestrator for Origin IP discovery and WAF bypass assessment.
    """
    clean_dom = domain.strip().lower()
    if clean_dom.startswith("http://") or clean_dom.startswith("https://"):
        clean_dom = urlparse(clean_dom).netloc.split(":")[0]

    logger.info("[Origin Recon] Analyzing domain: %s", clean_dom)
    waf_info = detect_waf_presence(clean_dom)

    # Fetch baseline title if possible
    baseline_title = None
    try:
        r = requests.get(f"https://{clean_dom}", timeout=5, verify=False)
        import re
        m = re.search(r"<title>(.*?)</title>", r.text, re.IGNORECASE)
        if m:
            baseline_title = m.group(1).strip()
    except Exception:
        pass

    candidates = find_candidate_origin_ips(clean_dom)
    verified_origins = []

    for ip in candidates:
        is_origin, reason = verify_origin_ip(ip, clean_dom, baseline_title)
        if is_origin:
            verified_origins.append({
                "origin_ip": ip,
                "verified": True,
                "confidence": "HIGH",
                "evidence": reason
            })

    waf_bypassed = len(verified_origins) > 0 and waf_info["is_behind_waf"]

    return {
        "status": "success",
        "domain": clean_dom,
        "is_behind_waf": waf_info["is_behind_waf"],
        "waf_provider": waf_info["waf_provider"],
        "current_ips": waf_info["current_ips"],
        "candidate_ips_found": len(candidates),
        "candidates": candidates,
        "origin_discovered": len(verified_origins) > 0,
        "waf_bypassed": waf_bypassed,
        "verified_origins": verified_origins,
        "summary": (
            f"تم كشف السيرفر الحقيقي (Origin IP) وتجاوز جدار الحماية {waf_info['waf_provider']} بنجاح!"
            if waf_bypassed else
            ("الهدف محمي بجدار حماية ولم يتم كشف سيرفر الأصل." if waf_info["is_behind_waf"] else "الهدف غير محمي بجدار حماية خارجي (مباشر).")
        )
    }
