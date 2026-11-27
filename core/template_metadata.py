"""
YemScan — Nuclei Template Metadata Extractor (Phase 2).

Responsibility: Given a TemplateParseResult (already parsed YAML data),
extract and normalize all relevant metadata fields into a TemplateMetadata
dataclass, without re-reading the file.

Design rules:
- Operates only on data already in TemplateParseResult.raw_data — never reads files.
- Never fabricates values: all fields are either extracted or left as None / empty.
- Normalises: CVE IDs (uppercase, strip), CWE IDs (uppercase), severity (lowercase),
  tags (always list of stripped lowercase strings), protocols (always list).
- CVSS score and vector come ONLY from info.classification.
- content_hash is taken from TemplateParseResult — never recomputed here.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from core.template_parser import TemplateParseResult

logger = logging.getLogger("yemenscan.template_metadata")

# ---------------------------------------------------------------------------
# Normalisation helpers
# ---------------------------------------------------------------------------

_CVE_RE = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)
_CWE_RE = re.compile(r"^CWE-\d+$", re.IGNORECASE)

VALID_SEVERITIES = {"info", "low", "medium", "high", "critical", "unknown"}


def _normalize_severity(raw: Any) -> str:
    if not isinstance(raw, str) or not raw.strip():
        return "unknown"
    s = raw.strip().lower()
    return s if s in VALID_SEVERITIES else "unknown"


def _normalize_tags(raw: Any) -> List[str]:
    """Return a deduplicated, sorted list of lowercase tag strings."""
    if isinstance(raw, list):
        items = raw
    elif isinstance(raw, str):
        items = [t.strip() for t in raw.split(",") if t.strip()]
    else:
        return []
    seen = set()
    result = []
    for item in items:
        item_str = str(item).strip().lower()
        if item_str and item_str not in seen:
            seen.add(item_str)
            result.append(item_str)
    return sorted(result)


def _normalize_cve_id(raw: Any) -> Optional[str]:
    """Extract and normalise a single CVE ID from various forms."""
    if isinstance(raw, list):
        for item in raw:
            result = _normalize_cve_id(item)
            if result:
                return result
        return None
    if not isinstance(raw, str) or not raw.strip():
        return None
    candidate = raw.strip().upper()
    if _CVE_RE.match(candidate):
        return candidate
    return None


def _normalize_cwe_ids(raw: Any) -> List[str]:
    """Extract and normalise a list of CWE IDs."""
    if isinstance(raw, list):
        candidates = raw
    elif isinstance(raw, str) and raw.strip():
        candidates = [raw]
    else:
        return []
    result = []
    for item in candidates:
        candidate = str(item).strip().upper()
        if _CWE_RE.match(candidate):
            result.append(candidate)
    return result


def _as_str_or_none(raw: Any) -> Optional[str]:
    if raw is None:
        return None
    s = str(raw).strip()
    return s if s else None


def _as_list_of_str(raw: Any) -> List[str]:
    if isinstance(raw, list):
        return [str(x).strip() for x in raw if str(x).strip()]
    if isinstance(raw, str) and raw.strip():
        return [raw.strip()]
    return []


# ---------------------------------------------------------------------------
# Data class
# ---------------------------------------------------------------------------

@dataclass
class TemplateMetadata:
    """
    Normalised metadata extracted from a Nuclei template.

    All string fields that are "not found" are None (never empty string).
    All list fields that are "not found" are [] (never None).
    """
    # Identity
    template_id: Optional[str]
    relative_path: str
    content_hash: str                   # from TemplateParseResult — SHA-256

    # Info block
    name: Optional[str]
    author: List[str]                   # always a list
    severity: str                       # normalised lowercase
    description: Optional[str]
    remediation: Optional[str]
    tags: List[str]                     # normalised lowercase, sorted, deduped
    reference: List[str]

    # Classification block (strictly from info.classification)
    cve_id: Optional[str]               # single CVE or None
    cwe_ids: List[str]                  # list of CWE IDs
    cvss_score: Optional[float]
    cvss_vector: Optional[str]

    # Metadata sub-block
    verified: Optional[bool]
    max_request: Optional[int]
    shodan_query: Optional[str]
    fofa_query: Optional[str]
    google_dork: Optional[str]

    # Structural flags (from TemplateParseResult)
    protocols: List[str]
    is_workflow: bool
    is_self_contained: bool
    has_flow: bool

    # Raw info dict (kept for downstream use; never mutated)
    _raw_info: Dict[str, Any] = field(default_factory=dict, repr=False, compare=False)


# ---------------------------------------------------------------------------
# Extractor
# ---------------------------------------------------------------------------

class MetadataExtractor:
    """
    Extracts TemplateMetadata from a TemplateParseResult.

    Usage:
        extractor = MetadataExtractor()
        metadata = extractor.extract(parse_result)

    Thread-safe (stateless).
    """

    def extract(self, parse_result: TemplateParseResult) -> TemplateMetadata:
        """
        Extract metadata from a parsed template result.
        Never re-reads files — operates only on parse_result.raw_data.
        """
        data = parse_result.raw_data
        info = data.get("info") if isinstance(data.get("info"), dict) else {}

        # ---- Identity ----
        template_id = parse_result.template_id  # already validated

        # ---- Info fields ----
        name = _as_str_or_none(info.get("name"))
        author = self._extract_author(info.get("author"))
        severity = _normalize_severity(info.get("severity"))
        description = _as_str_or_none(info.get("description"))
        remediation = _as_str_or_none(info.get("remediation"))
        tags = _normalize_tags(info.get("tags"))
        reference = _as_list_of_str(info.get("reference"))

        # ---- Classification (strictly from info.classification) ----
        classification = info.get("classification")
        if not isinstance(classification, dict):
            classification = {}

        cve_id = _normalize_cve_id(
            classification.get("cve-id") or classification.get("cve_id")
        )
        cwe_ids = _normalize_cwe_ids(
            classification.get("cwe-id") or classification.get("cwe_id")
        )
        cvss_score = self._extract_cvss_score(
            classification.get("cvss-score") or classification.get("cvss_score")
        )
        cvss_vector = _as_str_or_none(
            classification.get("cvss-metrics")
            or classification.get("cvss_metrics")
            or classification.get("cvss-vector")
            or classification.get("cvss_vector")
        )

        # ---- Metadata sub-block ----
        meta = info.get("metadata")
        if not isinstance(meta, dict):
            meta = {}

        verified = self._extract_bool(meta.get("verified"))
        max_request = self._extract_int(meta.get("max-request") or meta.get("max_request"))
        shodan_query = _as_str_or_none(meta.get("shodan-query") or meta.get("shodan_query"))
        fofa_query = _as_str_or_none(meta.get("fofa-query") or meta.get("fofa_query"))
        google_dork = _as_str_or_none(meta.get("google-dork") or meta.get("google_dork"))

        return TemplateMetadata(
            template_id=template_id,
            relative_path=parse_result.relative_path,
            content_hash=parse_result.content_hash,
            name=name,
            author=author,
            severity=severity,
            description=description,
            remediation=remediation,
            tags=tags,
            reference=reference,
            cve_id=cve_id,
            cwe_ids=cwe_ids,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            verified=verified,
            max_request=max_request,
            shodan_query=shodan_query,
            fofa_query=fofa_query,
            google_dork=google_dork,
            protocols=list(parse_result.protocols),
            is_workflow=parse_result.is_workflow,
            is_self_contained=parse_result.is_self_contained,
            has_flow=parse_result.has_flow,
            _raw_info=dict(info),
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_author(raw: Any) -> List[str]:
        if isinstance(raw, list):
            return [str(a).strip() for a in raw if str(a).strip()]
        if isinstance(raw, str) and raw.strip():
            return [a.strip() for a in raw.split(",") if a.strip()]
        return []

    @staticmethod
    def _extract_cvss_score(raw: Any) -> Optional[float]:
        if raw is None:
            return None
        try:
            score = float(raw)
            if 0.0 <= score <= 10.0:
                return score
        except (ValueError, TypeError):
            pass
        return None

    @staticmethod
    def _extract_bool(raw: Any) -> Optional[bool]:
        if isinstance(raw, bool):
            return raw
        if isinstance(raw, str):
            if raw.strip().lower() in ("true", "yes", "1"):
                return True
            if raw.strip().lower() in ("false", "no", "0"):
                return False
        return None

    @staticmethod
    def _extract_int(raw: Any) -> Optional[int]:
        if raw is None:
            return None
        try:
            return int(raw)
        except (ValueError, TypeError):
            return None
