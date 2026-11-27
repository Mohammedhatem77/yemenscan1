"""
Active Proof-Based Injection Verification Engine for YemenScan (Layer 3).

Eliminates false-positive active injection findings (LDAP Injection, SQLi, XSS,
LFI/Path Traversal, SSTI, CRLF, Command Injection) across all websites—including
Vercel/Nginx/Cloudflare redirect edges, React/Vue/Next SPAs, Soft-404 pages,
and double-URL-encoding proxies—without suppressing genuine vulnerabilities.

Three verification gates:
  1. Non-Executable Redirect Guard:
     Rejects injection findings claimed on 301/302/303/307/308 responses that
     contain no genuine backend engine error signature.
  2. Benign Canary & Structural DOM Diffing:
     Sends neutral control probes (clean URL, benign canary, double-encoded canary),
     performs recursive URL decoding and dynamic noise normalization, and compares
     HTML DOM skeleton similarity (>= 0.98 indicates invariant SPA / Soft-404 / redirect).
  3. Deterministic Proof Gate:
     Requires positive proof (engine error signature, real DOM structural differential
     not reproduced by benign canaries, or confirmed timing/execution proof) before
     allowing heuristic/QUERY_STRING injection findings to remain CRITICAL/HIGH.
"""

from __future__ import annotations

import difflib
import html
import os
import re
import time
import warnings
from html.parser import HTMLParser
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urlencode, unquote, urlparse, urlunparse

import requests
import urllib3

from core.target_validator import is_safe_host_or_ip, validate_redirect_hop
from core.waf_false_positive_filter import is_real_database_error

# Active injection coverage families verified by Layer 3
ACTIVE_INJECTION_FAMILIES: Set[str] = {
    "sql_injection",
    "ldap_injection",
    "cross_site_scripting",
    "file_inclusion",
    "crlf_injection",
    "server_side_request_forgery",
    "command_execution",
    "xml_external_entity",
    "ssti",
}

REDIRECT_STATUS_CODES: Set[int] = {301, 302, 303, 307, 308}

# RFC 2606 / local test domains reserved for offline unit tests (never probed live)
_OFFLINE_TEST_HOSTS: Set[str] = {
    "example.com",
    "example.org",
    "example.net",
    "testphp.vulnweb.com",
}
_OFFLINE_TEST_SUFFIXES: Tuple[str, ...] = (
    ".example.com",
    ".example.org",
    ".example.net",
    ".example",
    ".test",
    ".invalid",
    ".localhost",
    ".local",
)

# Real backend error signatures proving actual parser/interpreter execution
REAL_ENGINE_ERROR_PATTERNS: List[Tuple[str, str]] = [
    # LDAP engine errors
    (r"supplied argument is not a valid ldap", "LDAP Error"),
    (r"javax\.naming\.namenotfoundexception", "Java JNDI LDAP Exception"),
    (r"\bldapexception\b", "LDAP Exception"),
    (r"com\.sun\.jndi\.ldap", "Java LDAP Context Error"),
    (r"bad search filter", "LDAP Search Filter Error"),
    (r"invalid dn syntax", "OpenLDAP Invalid DN"),
    (r"the distinguished name has an invalid syntax", "Active Directory LDAP Error"),
    (r"the search filter (is incorrect|is invalid|cannot be recognized)", "Microsoft LDAP Error"),
    (r"ipworksasp\.ldap", "IPWorks LDAP Error"),
    # File inclusion / OS command execution signatures
    (r"root:[x*]:0:0:root:", "Unix /etc/passwd Disclosure"),
    (r"\[boot loader\]|\[operating systems\]", "Windows win.ini/boot.ini Disclosure"),
    (r"uid=\d+\([a-z0-9_.-]+\)\s+gid=\d+", "OS Command id Output"),
    # Application/Runtime stacktraces indicative of broken query/template evaluation
    (r"traceback \(most recent call last\):", "Python Traceback"),
    (r"jinja2\.exceptions\.templatesyntaxerror|freemarker\.core\.parseexception", "Template Injection Error"),
    (r"java\.lang\.(nullpointerexception|illegalargumentexception)", "Java Runtime Exception"),
    (r"fatal error:\s+uncaught", "PHP Fatal Error"),
]


class _DOMSkeletonParser(HTMLParser):
    """Extracts structural HTML tag sequence + visible normalized text skeleton."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tokens: List[str] = []
        self._skip_text_depth = 0

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        tag_l = tag.lower()
        attr_keys = sorted(k.lower() for k, _ in attrs if k)
        id_val = next((v for k, v in attrs if k and k.lower() == "id" and v), "")
        if id_val:
            self.tokens.append(f"<{tag_l}#{id_val[:32]}>")
        elif attr_keys:
            self.tokens.append(f"<{tag_l}:{'/'.join(attr_keys[:4])}>")
        else:
            self.tokens.append(f"<{tag_l}>")
        if tag_l in ("script", "style"):
            self._skip_text_depth += 1

    def handle_endtag(self, tag: str) -> None:
        tag_l = tag.lower()
        self.tokens.append(f"</{tag_l}>")
        if tag_l in ("script", "style") and self._skip_text_depth > 0:
            self._skip_text_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._skip_text_depth > 0:
            return
        cleaned = " ".join(data.split())
        if cleaned:
            self.tokens.append(cleaned[:120])


def has_real_engine_error(text: str) -> Optional[str]:
    """
    Returns matched backend error label if text contains an authentic SQL, LDAP,
    LFI, SSTI, or runtime exception error proof; otherwise returns None.
    """
    if not text:
        return None
    if is_real_database_error(text):
        return "SQL Database Error"
    t_low = text.lower()
    for pat, label in REAL_ENGINE_ERROR_PATTERNS:
        if re.search(pat, t_low):
            return label
    return None


def recursive_url_decode(text: str, max_passes: int = 3) -> str:
    """Iteratively decodes URL-encoded sequences (handles double/triple %25 encoding)."""
    if not text:
        return ""
    cur = text
    for _ in range(max_passes):
        nxt = unquote(cur)
        if nxt == cur:
            break
        cur = nxt
    return cur


def _strip_reflection_tokens(text: str, tokens: Optional[List[str]]) -> str:
    """Removes raw, URL-encoded, double-encoded, and HTML-escaped forms of injected tokens."""
    out = text
    for tok in (tokens or []):
        if not tok or len(tok) < 2:
            continue
        variants = {
            tok,
            tok.lower(),
            html.escape(tok),
            recursive_url_decode(tok),
        }
        for v in variants:
            if v:
                out = out.replace(v, "")
    return out


def normalize_response_for_dom_diff(
    body: str,
    tokens_to_strip: Optional[List[str]] = None,
) -> str:
    """
    Normalizes an HTTP response body for accurate structural DOM comparison:
      1. Applies recursive URL decoding to eliminate double/triple %25 reflection diffs.
      2. Strips canary values, injected payloads, dynamic nonces, CSRF tokens, UUIDs,
         and HTTP timestamps / edge request IDs.
    """
    if not body:
        return ""
    decoded = recursive_url_decode(body)
    stripped = _strip_reflection_tokens(decoded, tokens_to_strip)

    # Strip dynamic per-request nonces, tokens, timestamps, ray/vercel IDs, UUIDs
    dynamic_patterns = [
        r'nonce=["\'][^"\']+["\']',
        r'(csrf[_-]?token|authenticity_token|_token)["\']?\s*[:=]\s*["\'][^"\']+["\']',
        r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b',
        r'\b\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\b',
        r'\b[a-z]{3}\d+::[a-z0-9-]+-\d+-[0-9a-f]+\b',
    ]
    for pat in dynamic_patterns:
        stripped = re.sub(pat, "", stripped, flags=re.IGNORECASE)

    # Normalize query strings inside redirect anchor hrefs (e.g. Vercel <a href="...?...">)
    stripped = re.sub(r'\?[^"\'>\s]{1,256}', "?__QS__", stripped)
    return " ".join(stripped.split())


def extract_dom_skeleton(body: str) -> List[str]:
    """Parses HTML into structural tag and normalized text tokens for diffing."""
    if not body:
        return []
    parser = _DOMSkeletonParser()
    try:
        parser.feed(body)
        parser.close()
    except Exception:
        return body.split()
    return parser.tokens if parser.tokens else body.split()


def compute_dom_similarity(
    body_a: str,
    body_b: str,
    extra_strip_tokens: Optional[List[str]] = None,
) -> float:
    """
    Computes structural similarity in [0.0, 1.0] between two HTTP bodies after
    recursive URL decoding and dynamic noise stripping.
    """
    norm_a = normalize_response_for_dom_diff(body_a, extra_strip_tokens)
    norm_b = normalize_response_for_dom_diff(body_b, extra_strip_tokens)

    if not norm_a and not norm_b:
        return 1.0
    if not norm_a or not norm_b:
        return 0.0
    if norm_a == norm_b:
        return 1.0

    skel_a = extract_dom_skeleton(norm_a)
    skel_b = extract_dom_skeleton(norm_b)

    if not skel_a and not skel_b:
        return 1.0
    if skel_a == skel_b:
        return 1.0

    tag_ratio = difflib.SequenceMatcher(None, skel_a, skel_b).ratio()
    text_ratio = difflib.SequenceMatcher(None, norm_a[:12000], norm_b[:12000]).ratio()
    return round((0.6 * tag_ratio) + (0.4 * text_ratio), 4)


def is_active_injection_finding(finding: Dict[str, Any]) -> bool:
    """Identifies active dynamic injection findings eligible for Layer 3 proof gating."""
    fam = str(finding.get("coverage_family") or "").strip().lower()
    if fam in ACTIVE_INJECTION_FAMILIES:
        return True
    title = str(finding.get("title") or "").strip().lower()
    keywords = (
        "ldap injection",
        "sql injection",
        "cross-site scripting",
        "cross site scripting",
        "path traversal",
        "local file inclusion",
        "file handling",
        "crlf injection",
        "template injection",
        "command execution",
    )
    return any(kw in title for kw in keywords)


def _is_offline_test_url(url: str) -> bool:
    try:
        host = (urlparse(url).hostname or "").lower().rstrip(".")
        if host in _OFFLINE_TEST_HOSTS:
            return True
        return any(host.endswith(suf) for suf in _OFFLINE_TEST_SUFFIXES)
    except Exception:
        return True


def _extract_response_evidence(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Safely extracts response status/headers/body captured during Stage 3 parsing."""
    re_ev = finding.get("response_evidence")
    if isinstance(re_ev, dict) and re_ev:
        return re_ev
    src_ev = finding.get("source_evidence")
    if isinstance(src_ev, dict):
        return {
            "status_code": src_ev.get("response_status_code"),
            "location": src_ev.get("response_location") or "",
            "content_type": src_ev.get("response_content_type") or "",
            "body_excerpt": src_ev.get("response_body_excerpt") or "",
        }
    return {}


def _extract_parameter_name(finding: Dict[str, Any]) -> str:
    src_ev = finding.get("source_evidence")
    if isinstance(src_ev, dict) and src_ev.get("parameter"):
        return str(src_ev["parameter"]).strip()
    ev_list = finding.get("evidence")
    if isinstance(ev_list, list):
        for ev in ev_list:
            if isinstance(ev, dict) and ev.get("parameter"):
                return str(ev["parameter"]).strip()
    return ""


def _extract_attack_url(finding: Dict[str, Any]) -> Optional[str]:
    """Reconstructs exact probe URL from finding's curl_command/http_request if available."""
    base_url = str(finding.get("url") or "").strip()
    src_ev = finding.get("source_evidence") if isinstance(finding.get("source_evidence"), dict) else {}
    curl_cmd = str(src_ev.get("curl_command") or "")
    m = re.search(r'https?://[^\s"\']+', curl_cmd)
    if m:
        return m.group(0)
    http_req = str(src_ev.get("http_request") or "")
    req_match = re.match(r"^(?:GET|HEAD)\s+(/\S*)", http_req)
    if req_match and base_url:
        parsed = urlparse(base_url)
        if parsed.scheme and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}{req_match.group(1)}"
    return None


def _collect_finding_corpus(finding: Dict[str, Any]) -> str:
    """Collects all text snippets from finding to check for genuine backend errors."""
    parts = [
        str(finding.get("title") or ""),
        str(finding.get("description") or ""),
        str(finding.get("response") or ""),
    ]
    re_ev = _extract_response_evidence(finding)
    parts.append(str(re_ev.get("body_excerpt") or ""))
    src_ev = finding.get("source_evidence")
    if isinstance(src_ev, dict):
        parts.append(str(src_ev.get("info") or ""))
    return "\n".join(parts)


def default_canary_probe(url: str, timeout: float = 6.0) -> Optional[Dict[str, Any]]:
    """
    SSRF-safe single-hop HTTP control probe returning status, headers, and body.
    Does not auto-follow redirects so pure 301/308 edges are accurately observed.
    Skips RFC 2606 / local offline test hosts cleanly.
    """
    if not url or _is_offline_test_url(url):
        return None
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").strip().lower()
        if not host:
            return None
        safe, _ = is_safe_host_or_ip(host)
        if not safe:
            return None

        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        session = requests.Session()
        session.trust_env = False
        t0 = time.monotonic()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", urllib3.exceptions.InsecureRequestWarning)
            resp = session.get(url, headers=headers, timeout=timeout, verify=False, allow_redirects=False)
        elapsed_ms = (time.monotonic() - t0) * 1000.0

        loc = resp.headers.get("Location") or resp.headers.get("location") or ""
        if loc and resp.status_code in REDIRECT_STATUS_CODES:
            hop_safe, _, _ = validate_redirect_hop(url, loc)
            if not hop_safe:
                loc = ""

        return {
            "url": url,
            "status_code": int(resp.status_code),
            "headers": {k.lower(): v for k, v in resp.headers.items()},
            "location": loc,
            "body": (resp.text or "")[:65536],
            "elapsed_ms": round(elapsed_ms, 2),
        }
    except Exception:
        return None


def _build_control_urls(base_url: str, param_name: str) -> Tuple[str, str, str]:
    """Builds (clean_url, benign_canary_url, double_encoded_canary_url)."""
    parsed = urlparse(base_url)
    clean_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", "", ""))

    target_param = "ys_canary"
    if param_name and param_name.upper() != "QUERY_STRING" and "=" not in param_name:
        target_param = re.sub(r"[^a-zA-Z0-9_.-]", "", param_name) or "ys_canary"

    existing_qs = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True) if k != target_param]
    benign_qs = urlencode(existing_qs + [(target_param, "7f3a9c12")])
    benign_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", benign_qs, ""))

    prefix_qs = urlencode(existing_qs)
    double_part = f"{target_param}=%252A%2529%25007f3a9c12"
    full_dbl_qs = f"{prefix_qs}&{double_part}" if prefix_qs else double_part
    double_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", full_dbl_qs, ""))

    return clean_url, benign_url, double_url


def _has_real_crlf_header_injection(probe_or_evidence: Dict[str, Any], raw_request_hint: str = "") -> bool:
    """Returns True only if CRLF injection proof exists beyond normal redirect headers."""
    body = str(probe_or_evidence.get("body_excerpt") or probe_or_evidence.get("body") or "")
    if re.search(r"(set-cookie:\s*wapiti|wapiti[_-]?header|x-crlf-test)", body, re.IGNORECASE):
        return True
    headers = probe_or_evidence.get("headers") or {}
    if isinstance(headers, dict):
        for k, v in headers.items():
            if "wapiti" in str(k).lower() or "wapiti" in str(v).lower():
                return True
    return False


def _is_time_based_finding(finding: Dict[str, Any], corpus: str) -> bool:
    """Identifies time-based blind injection findings where DOM text stays identical by design."""
    low = corpus.lower()
    src_rule = str(finding.get("source_rule") or finding.get("rule") or "").lower()
    if "time" in src_rule or "timesql" in src_rule:
        return True
    return any(tok in low for tok in ("time-based", "time based", "blind time", "sleep(", "waitfor delay", "pg_sleep("))


def verify_single_injection_finding(
    finding: Dict[str, Any],
    probe_fn: Optional[Callable[[str], Optional[Dict[str, Any]]]] = None,
    probe_cache: Optional[Dict[str, Optional[Dict[str, Any]]]] = None,
) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """
    Runs the 3 deterministic verification gates on a single active injection finding.

    Returns:
        (is_verified_real, suppression_record_if_false_positive)
    """
    if not is_active_injection_finding(finding):
        return True, None

    url = str(finding.get("url") or "").strip()
    if not url:
        return True, None

    cov_family = str(finding.get("coverage_family") or "").lower()
    param_name = _extract_parameter_name(finding)
    corpus = _collect_finding_corpus(finding)

    # Deterministic Error-Based Proof check: never suppress if authentic backend error exists
    real_err = has_real_engine_error(corpus)
    if real_err:
        finding["verification_status"] = "confirmed_error_proof"
        finding["verification_evidence"] = real_err
        return True, None

    # ── Gate 1: Non-Executable Redirect Guard (stored response evidence) ──
    resp_ev = _extract_response_evidence(finding)
    stored_status = resp_ev.get("status_code")
    try:
        stored_status_int = int(stored_status) if stored_status is not None else None
    except (TypeError, ValueError):
        stored_status_int = None

    if stored_status_int in REDIRECT_STATUS_CODES:
        if cov_family == "crlf_injection" and _has_real_crlf_header_injection(resp_ev):
            finding["verification_status"] = "confirmed_crlf"
            return True, None
        loc = str(resp_ev.get("location") or "")
        return False, {
            "id": finding.get("id", ""),
            "title": finding.get("title", ""),
            "coverage_family": cov_family or "injection",
            "url": url,
            "parameter": param_name,
            "rule_gate": "non_executable_redirect_guard",
            "status_code": stored_status_int,
            "location": loc,
            "reason": (
                f"تم التحقق واستبعاد الإنذار الآلي ({finding.get('title', 'Injection')}) على ({url}): "
                f"استجابة السيرفر الفعلية هي إعادة توجيه غير تنفيذية HTTP {stored_status_int} "
                f"(نحو {loc or 'وجهة أخرى'}) ولا تحتوي على أي خطأ من محرك قاعدة البيانات أو LDAP."
            ),
        }

    # ── Gate 2 & 3: Active Canary & Double-Encoded Canary + Structural DOM Diffing ──
    prober = probe_fn or default_canary_probe
    cache = probe_cache if probe_cache is not None else {}

    def _cached_probe(target_u: str) -> Optional[Dict[str, Any]]:
        if target_u not in cache:
            cache[target_u] = prober(target_u)
        return cache[target_u]

    clean_url, benign_url, double_url = _build_control_urls(url, param_name)

    p_clean = _cached_probe(clean_url)
    # Fail-safe: if offline / mocked host / unreachable, preserve candidate unless proven false
    if p_clean is None:
        return True, None

    clean_status = int(p_clean.get("status_code") or 0)
    clean_body = str(p_clean.get("body") or "")

    # Check if clean URL itself returned a redirect and we had no stored body error
    if clean_status in REDIRECT_STATUS_CODES and not stored_status_int:
        p_benign = _cached_probe(benign_url)
        if p_benign and int(p_benign.get("status_code") or 0) in REDIRECT_STATUS_CODES:
            sim_redir = compute_dom_similarity(
                clean_body,
                str(p_benign.get("body") or ""),
                extra_strip_tokens=["ys_canary", "7f3a9c12"],
            )
            if sim_redir >= 0.98:
                loc = str(p_clean.get("location") or "")
                return False, {
                    "id": finding.get("id", ""),
                    "title": finding.get("title", ""),
                    "coverage_family": cov_family or "injection",
                    "url": url,
                    "parameter": param_name,
                    "rule_gate": "non_executable_redirect_guard",
                    "status_code": clean_status,
                    "location": loc,
                    "dom_similarity": sim_redir,
                    "reason": (
                        f"تم التحقق الشبكي المباشر واستبعاد الإنذار الآلي ({finding.get('title', 'Injection')}) على ({url}): "
                        f"المسار يرجع بوابة إعادة توجيه HTTP {clean_status} ثابتة (تطابق البنية {sim_redir*100:.1f}%) "
                        f"ولا ينفذ أي استعلامات تطبيق."
                    ),
                }

    p_benign = _cached_probe(benign_url)
    p_double = _cached_probe(double_url)
    if p_benign is None or p_double is None:
        return True, None

    benign_body = str(p_benign.get("body") or "")
    double_body = str(p_double.get("body") or "")

    # Never suppress if a control or double probe revealed an authentic backend error
    ctrl_err = has_real_engine_error(benign_body) or has_real_engine_error(double_body)
    if ctrl_err:
        finding["verification_status"] = "confirmed_error_proof"
        finding["verification_evidence"] = ctrl_err
        return True, None

    strip_tokens = ["ys_canary", param_name, "7f3a9c12", "*))", "%252A%2529%25007f3a9c12"]
    sim_benign = compute_dom_similarity(clean_body, benign_body, extra_strip_tokens=strip_tokens)
    sim_double = compute_dom_similarity(clean_body, double_body, extra_strip_tokens=strip_tokens)

    # Probe exact attack URL if available to confirm identical DOM invariance directly
    attack_url = _extract_attack_url(finding)
    sim_attack: Optional[float] = None
    attack_body = ""
    if attack_url:
        p_attack = _cached_probe(attack_url)
        if p_attack is not None:
            attack_status = int(p_attack.get("status_code") or 0)
            attack_body = str(p_attack.get("body") or "")
            atk_err = has_real_engine_error(attack_body)
            if atk_err:
                finding["verification_status"] = "confirmed_error_proof"
                finding["verification_evidence"] = atk_err
                return True, None
            if attack_status in REDIRECT_STATUS_CODES and cov_family != "crlf_injection":
                return False, {
                    "id": finding.get("id", ""),
                    "title": finding.get("title", ""),
                    "coverage_family": cov_family or "injection",
                    "url": url,
                    "parameter": param_name,
                    "rule_gate": "non_executable_redirect_guard",
                    "status_code": attack_status,
                    "reason": (
                        f"تم إعادة فحص رابط الهجوم مباشرة على ({url}) وتبين أنه يرجع إعادة توجيه HTTP {attack_status} "
                        f"بدون أي خطأ محرك خلفي — إنذار كاذب."
                    ),
                }
            if attack_status >= 500 and 200 <= clean_status < 500:
                finding["verification_status"] = "confirmed_http500_anomaly"
                return True, None
            atk_tokens = strip_tokens + ["nosuchvalue", unquote(urlparse(attack_url).query)]
            sim_attack = compute_dom_similarity(clean_body, attack_body, extra_strip_tokens=atk_tokens)

    # Time-based blind injections retain identical DOM by design on non-redirect targets
    if _is_time_based_finding(finding, corpus) and clean_status not in REDIRECT_STATUS_CODES:
        finding["verification_status"] = "candidate_time_based"
        return True, None

    # For reflected XSS, verify upfront if unescaped script/svg/event payload was injected into DOM
    if cov_family == "cross_site_scripting" and attack_body:
        xss_dom_pat = r"<(?:script|svg|iframe)[^>]*>.*?(?:alert|confirm|prompt)|on(?:error|load|mouseover|focus)\s*="
        if re.search(xss_dom_pat, attack_body, re.IGNORECASE | re.DOTALL) and not re.search(
            xss_dom_pat, clean_body, re.IGNORECASE | re.DOTALL
        ):
            finding["verification_status"] = "confirmed_dom_xss"
            return True, None

    # Check if control probes + attack probe prove DOM invariance (SPA Fallback / Soft-404 / Static)
    is_dom_invariant = sim_benign >= 0.98 and sim_double >= 0.98
    if sim_attack is not None:
        is_dom_invariant = is_dom_invariant and (sim_attack >= 0.98)

    if is_dom_invariant:
        return False, {
            "id": finding.get("id", ""),
            "title": finding.get("title", ""),
            "coverage_family": cov_family or "injection",
            "url": url,
            "parameter": param_name,
            "rule_gate": "canary_dom_invariance_proof",
            "status_code": clean_status,
            "dom_similarity_benign": sim_benign,
            "dom_similarity_double_encoded": sim_double,
            "dom_similarity_attack": sim_attack,
            "reason": (
                f"تم التحقق النشط عبر اختبار الشاهد البريء والمشفّر مرتين على ({url}): "
                f"تطابق هيكل الـ DOM بنسبة ({min(sim_benign, sim_double, sim_attack if sim_attack is not None else 1.0)*100:.1f}%) "
                f"دون أي خطأ خلفي أو تغيّر في البيانات (صفحة ثابتة / SPA Fallback / Soft-404 تتجاهل الحقن) — إنذار كاذب مؤكد."
            ),
        }

    # Gate 3: Deterministic proof check
    if sim_attack is not None and sim_attack < 0.98 and sim_benign >= 0.98:
        finding["verification_status"] = "confirmed_structural_differential"
        return True, None

    if param_name.upper() == "QUERY_STRING":
        # If double-encoded benign canary shifted DOM identically to attack payload (double encoding artifact)
        if sim_double < 0.98 and sim_attack is not None and abs(sim_attack - sim_double) < 0.03:
            return False, {
                "id": finding.get("id", ""),
                "title": finding.get("title", ""),
                "coverage_family": cov_family or "injection",
                "url": url,
                "parameter": param_name,
                "rule_gate": "deterministic_proof_gate",
                "status_code": clean_status,
                "dom_similarity_double_encoded": sim_double,
                "dom_similarity_attack": sim_attack,
                "reason": (
                    f"أثبت فحص البرهان الحتمي على ({url}) أن التباين الظاهري في المعامل (QUERY_STRING) "
                    f"ناتج فقط عن انعكاس الترميز المزدوج بالرابط (مطابق لتأثير الشاهد البريء المشفر مرتين) "
                    f"وليس عن تنفيذ استعلام فعلي."
                ),
            }

    return True, None


def filter_unverified_injection_false_positives(
    findings: List[Dict[str, Any]],
    probe_fn: Optional[Callable[[str], Optional[Dict[str, Any]]]] = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Runs Layer 3 Proof-Based Verification over Stage 3 findings, isolating
    disproven injection false positives while keeping all real flaws intact.

    Returns:
        (verified_findings, suppressed_injection_items)
    """
    if not findings:
        return [], []

    if os.getenv("YEMENSCAN_DISABLE_INJECTION_VERIFIER", "false").lower() in ("true", "1", "yes"):
        return list(findings), []

    probe_cache: Dict[str, Optional[Dict[str, Any]]] = {}
    verified: List[Dict[str, Any]] = []
    suppressed: List[Dict[str, Any]] = []

    for finding in findings:
        is_real, suppressed_rec = verify_single_injection_finding(
            finding, probe_fn=probe_fn, probe_cache=probe_cache
        )
        if is_real:
            verified.append(finding)
        elif suppressed_rec is not None:
            suppressed.append(suppressed_rec)

    return verified, suppressed
