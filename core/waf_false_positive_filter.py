"""
WAF False-Positive Suppression & Circuit Breaker Engine for YemenScan.

Provides:
  1. Detection and suppression of WAF block pages (Cloudflare, ModSecurity, F5,
     Imperva, Akamai) that automated scanners mistake for vulnerabilities.
  2. Origin-level Circuit Breaker to prevent scanner bans and runaway false-positive cascades.
  3. Integration with Stage 3 Smart Triage (triage_suppressed.json).
"""

import re
from typing import Dict, List, Tuple, Optional, Any, Set

# ---------------------------------------------------------------------------
# Signatures of WAF Block / Challenge Pages
# ---------------------------------------------------------------------------
WAF_BLOCK_PATTERNS: List[Tuple[str, str]] = [
    # (regex_pattern, provider_name)
    (r"attention required!\s*\|\s*cloudflare", "Cloudflare"),
    (r"cloudflare ray id:\s*[0-9a-f]+", "Cloudflare"),
    (r"error 1020\s*:\s*access denied", "Cloudflare"),
    (r"error 1015\s*:\s*you are being rate limited", "Cloudflare"),
    (r"cf-browser-verification", "Cloudflare"),
    (r"just a moment\.\.\.\s*enable javascript", "Cloudflare Challenge"),
    (r"the requested url was rejected\.\s*please consult with your administrator", "F5 BIG-IP ASM"),
    (r"web application firewall", "Generic WAF"),
    (r"request blocked by security rules", "Generic WAF"),
    (r"modsecurity action\s*:\s*403", "ModSecurity"),
    (r"owasp modsecurity core rule set", "ModSecurity"),
    (r"incident id:\s*[0-9]+", "Imperva Incapsula"),
    (r"akamaighost", "Akamai"),
    (r"reference #[0-9a-f.]+", "Akamai"),
    (r"request blocked\.\s*we can't connect to the server for this app", "AWS CloudFront WAF"),
    (r"protected by sucuri", "Sucuri WAF")
]

# Database error markers that indicate a REAL vulnerability (must NEVER be suppressed)
REAL_DB_ERROR_PATTERNS: List[str] = [
    r"you have an error in your sql syntax",
    r"warning:\s*mysql_",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"ora-[0-9]{5}",
    r"pg_query\(\)",
    r"sqlite3\.operationalerror",
    r"syntax error in sql statement",
    r"microsoft ole db provider for sql server"
]


def is_real_database_error(text: str) -> bool:
    """Returns True if the text contains unmistakable SQL database error strings."""
    t_low = text.lower()
    return any(re.search(pat, t_low) for pat in REAL_DB_ERROR_PATTERNS)


def is_waf_block_finding(finding: Dict[str, Any]) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Analyzes a finding to determine if its evidence is merely a WAF block / challenge page.

    Returns:
        (is_waf_block, provider_name, reason)
    """
    # 1. Gather all searchable evidence strings
    title = str(finding.get("title") or "")
    desc = str(finding.get("description") or "")
    info = str(finding.get("source_evidence", {}).get("info") or "")
    http_req = str(finding.get("source_evidence", {}).get("http_request") or "")
    extracted = str(finding.get("extracted_results") or "")

    # Evidence array
    evidence_pieces = [title, desc, info, extracted]
    for ev in finding.get("evidence", []):
        if isinstance(ev, dict):
            for v in ev.values():
                evidence_pieces.append(str(v))
        elif isinstance(ev, str):
            evidence_pieces.append(ev)

    corpus = " \n ".join(evidence_pieces)
    corpus_lower = corpus.lower()

    # 2. Safety Guard: If it contains real SQL database error, NEVER suppress
    if is_real_database_error(corpus_lower):
        return False, None, None

    # 3. Check for specific WAF Block Patterns
    for pattern, provider in WAF_BLOCK_PATTERNS:
        match = re.search(pattern, corpus_lower)
        if match:
            # Verify context:
            # If the finding is informational or header/stacktrace/xss on the block page
            reason = f"Response matches {provider} block page signature ('{match.group(0)[:40]}')"
            return True, provider, reason

    # 4. Check for 403 / 429 block response classified as 'information_disclosure'
    cov_family = str(finding.get("coverage_family") or "").lower()
    if cov_family in ("runtime_information_disclosure", "information_disclosure", "stacktrace_disclosure"):
        if any(term in corpus_lower for term in ["403 forbidden", "429 too many requests", "access denied", "blocked"]):
            if any(term in corpus_lower for term in ["waf", "firewall", "cloudflare", "imperva", "akamai", "modsecurity", "shield"]):
                return True, "WAF", "403/429 block response mistakenly reported as information disclosure"

    return False, None, None


def filter_waf_block_false_positives(
    findings: List[Dict[str, Any]]
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Separates substantive vulnerability findings from WAF block response false positives.

    Returns:
        (verified_findings, suppressed_waf_blocks)
    """
    if not findings:
        return [], []

    verified: List[Dict[str, Any]] = []
    suppressed: List[Dict[str, Any]] = []

    for item in findings:
        is_blocked, provider, reason = is_waf_block_finding(item)
        if is_blocked:
            suppressed_record = {
                "id": item.get("id", ""),
                "title": item.get("title", ""),
                "url": item.get("url", ""),
                "severity": item.get("severity", "LOW"),
                "waf_provider": provider or "Generic WAF",
                "suppression_reason": reason,
                "coverage_family": item.get("coverage_family", "unknown")
            }
            suppressed.append(suppressed_record)
        else:
            verified.append(item)

    return verified, suppressed


class WAFCircuitBreaker:
    """
    Origin-level Circuit Breaker that detects when an origin host is actively
    blocking requests via WAF (consecutive 403/429 or challenge responses).
    """

    def __init__(self, origin: str, threshold: int = 5):
        self.origin = origin
        self.threshold = threshold
        self.consecutive_blocks = 0
        self.total_blocks = 0
        self.is_tripped = False
        self.trip_reason: Optional[str] = None
        self.waf_provider: Optional[str] = None

    def record_waf_block(self, provider: str = "WAF", reason: str = "consecutive_blocks") -> bool:
        """
        Records a detected WAF block on this origin.
        Trips breaker when consecutive_blocks reaches threshold.
        """
        self.consecutive_blocks += 1
        self.total_blocks += 1
        self.waf_provider = provider

        if self.consecutive_blocks >= self.threshold and not self.is_tripped:
            self.is_tripped = True
            self.trip_reason = f"Blocked by {provider} ({self.consecutive_blocks} consecutive block responses)"
            return True

        return self.is_tripped

    def record_success(self) -> None:
        """Resets consecutive counter on successful unblocked request."""
        self.consecutive_blocks = 0

    def get_status(self) -> Dict[str, Any]:
        """Returns circuit breaker telemetry summary."""
        return {
            "origin": self.origin,
            "is_tripped": self.is_tripped,
            "trip_reason": self.trip_reason,
            "waf_provider": self.waf_provider,
            "consecutive_blocks": self.consecutive_blocks,
            "total_blocks": self.total_blocks
        }
