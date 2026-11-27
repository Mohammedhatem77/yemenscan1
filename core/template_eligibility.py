"""
YemScan — Template Eligibility Classifier (Phase 2 / v1.2.0).

Responsibility:
  1. IgnoreRuleSet  — parse .nuclei-ignore (tags + files) and check whether
                      a template is officially excluded.
  2. ClassificationPolicy — define which protocols are eligible, conditional,
                            or ineligible, plus web-relevance heuristics and
                            DAST eligibility groups.
  3. EligibilityClassifier — apply IgnoreRuleSet + ClassificationPolicy to a
                              TemplateMetadata and return a TemplateClassificationResult.

Design rules:
- .nuclei-ignore is read dynamically from the snapshot; counts are NEVER hardcoded.
- Protocol decisions come from YAML keys (via TemplateMetadata.protocols), NOT paths.
- Structured eligibility reason codes — no free text in eligibility_reasons.
- Unresolved TCP/Network/JavaScript cases → "unresolved_classification" + NOT eligible
  (conservative by default).
- DAST templates are evaluated per-template, NOT blanket-excluded by folder path:
    1. official_ignore overrides everything.
    2. unsafe: true / race: true / mutating HTTP methods → RC_UNSAFE_BEHAVIOR.
    3. ai/* sub-category → RC_DAST_AI_UNRESOLVED (team decision required).
    4. headless+http protocol → eligible (requires_headless noted in exec_reqs).
    5. http + OAST → eligible (requires_interactsh noted in exec_reqs).
    6. plain http → eligible (standard web probe).
    Protocol eligibility is determined from actual YAML keys, not the dast/ folder.
- publish_version() is never called here.
- Thread-safe (stateless classifier + immutable policy + read-only ignore set).

Policy versions:
  v1.0.0 — Baseline policy.
  v1.1.0 — Corrected bare-filename ignore matching, dast_review_required category.
  v1.2.0 — Controlled Comprehensive DAST Integration:
            • DAST templates evaluated individually, not blanket-excluded by folder.
            • New reason code RC_DAST_AI_UNRESOLVED for ai/* DAST templates.
            • RC_DAST_REVIEW removed; DAST templates that pass safety checks are eligible.
            • 'dast' removed from ineligible_protocols (not a valid YAML protocol key).
            • unsafe_dast_subdirs no longer used as an exclusion gate.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml

from core.template_metadata import TemplateMetadata

logger = logging.getLogger("yemenscan.template_eligibility")

# ---------------------------------------------------------------------------
# Structured eligibility reason codes — the ONLY allowed values in
# TemplateClassificationResult.eligibility_reasons.
# ---------------------------------------------------------------------------
RC_OFFICIAL_IGNORE     = "official_ignore"           # excluded by .nuclei-ignore
RC_UNSUPPORTED_PROTOCOL = "unsupported_protocol"     # protocol permanently ineligible
RC_OUTSIDE_WEB_SCOPE   = "outside_web_scope"         # TCP/JS not web-relevant
RC_UNRESOLVED          = "unresolved_classification"  # TCP/JS web-relevance unresolved
RC_UNSAFE_BEHAVIOR     = "unsafe_behavior"            # mutating/destructive/race/unsafe:true
RC_DAST_AI_UNRESOLVED  = "dast_ai_unresolved"        # ai/* DAST — pending team decision
RC_INVALID_TEMPLATE    = "invalid_template"           # parse errors / missing id
RC_WORKFLOW_DEFERRED   = "workflow_deferred"          # workflows not yet supported
RC_ELIGIBLE            = "eligible"                   # positive confirmation

# Keep RC_DAST_REVIEW as a deprecated alias so v1.1.0 tests still pass
RC_DAST_REVIEW         = "dast_ai_unresolved"

VALID_REASON_CODES: Set[str] = {
    RC_OFFICIAL_IGNORE, RC_UNSUPPORTED_PROTOCOL, RC_OUTSIDE_WEB_SCOPE,
    RC_UNRESOLVED, RC_UNSAFE_BEHAVIOR, RC_DAST_AI_UNRESOLVED,
    RC_INVALID_TEMPLATE, RC_WORKFLOW_DEFERRED, RC_ELIGIBLE,
}

# ---------------------------------------------------------------------------
# Security / eligibility status values
# ---------------------------------------------------------------------------
STATUS_ELIGIBLE    = "eligible"
STATUS_INELIGIBLE  = "ineligible"
STATUS_CONDITIONAL = "conditional"


# ---------------------------------------------------------------------------
# .nuclei-ignore parser
# ---------------------------------------------------------------------------

class IgnoreRuleSet:
    """
    Parses and applies a .nuclei-ignore file.

    The file format (YAML) contains two top-level keys:
      tags:  list of tag strings to exclude
      files: list of relative path strings to exclude

    Usage:
        ruleset = IgnoreRuleSet.from_file("/path/to/.nuclei-ignore")
        excluded, reason_code, matched_rule = ruleset.is_excluded(
            template_id="xyz", tags=["dos","fuzz"], relative_path="http/..."
        )
    """

    def __init__(
        self,
        excluded_tags: Set[str],
        excluded_files: Set[str],
        source_path: str = "",
    ):
        # tags are always lowercase for case-insensitive matching
        self.excluded_tags: Set[str] = {t.strip().lower() for t in excluded_tags if t.strip()}
        # file paths are normalised to POSIX lowercase for matching
        self.excluded_files: Set[str] = {
            p.strip().replace("\\", "/").lower() for p in excluded_files if p.strip()
        }
        self.source_path = source_path

    @classmethod
    def from_file(cls, ignore_file_path: str) -> "IgnoreRuleSet":
        """
        Parse a .nuclei-ignore YAML file. Returns an empty IgnoreRuleSet if
        the file is missing or unreadable (logs warning).
        """
        if not os.path.isfile(ignore_file_path):
            logger.warning(
                "nuclei-ignore file not found at '%s'; no official exclusions will apply.",
                ignore_file_path,
            )
            return cls(set(), set(), source_path=ignore_file_path)

        try:
            with open(ignore_file_path, "r", encoding="utf-8", errors="replace") as fh:
                raw = fh.read()
            parsed = yaml.safe_load(raw)
        except Exception as exc:
            logger.warning("Failed to parse nuclei-ignore at '%s': %s", ignore_file_path, exc)
            return cls(set(), set(), source_path=ignore_file_path)

        if not isinstance(parsed, dict):
            logger.warning(
                "nuclei-ignore at '%s' has unexpected structure (%s); treating as empty.",
                ignore_file_path, type(parsed).__name__,
            )
            return cls(set(), set(), source_path=ignore_file_path)

        raw_tags = parsed.get("tags") or []
        raw_files = parsed.get("files") or []

        excluded_tags: Set[str] = set()
        if isinstance(raw_tags, list):
            for t in raw_tags:
                if isinstance(t, str) and t.strip():
                    excluded_tags.add(t.strip().lower())

        excluded_files: Set[str] = set()
        if isinstance(raw_files, list):
            for f in raw_files:
                if isinstance(f, str) and f.strip():
                    excluded_files.add(f.strip().replace("\\", "/").lower())

        logger.debug(
            "nuclei-ignore loaded: %d tag exclusions, %d file exclusions from '%s'",
            len(excluded_tags), len(excluded_files), ignore_file_path,
        )
        return cls(excluded_tags, excluded_files, source_path=ignore_file_path)

    @classmethod
    def empty(cls) -> "IgnoreRuleSet":
        """Return an empty ruleset (no exclusions)."""
        return cls(set(), set())

    def is_excluded(
        self,
        template_id: str,
        tags: List[str],
        relative_path: str,
    ) -> Tuple[bool, str, Optional[str]]:
        """
        Check whether a template is excluded by the official ignore file.

        Returns:
            (is_excluded, reason_code, matched_rule)
            - reason_code is RC_OFFICIAL_IGNORE when excluded, else "".
            - matched_rule is a human-readable description of the matched rule.
        """
        matches = self.get_all_matches(template_id, tags, relative_path)
        if matches:
            return True, RC_OFFICIAL_IGNORE, matches[0]
        return False, "", None

    def get_all_matches(
        self,
        template_id: str,
        tags: List[str],
        relative_path: str,
    ) -> List[str]:
        """
        Returns all matching ignore rules (files and tags).
        Supports exact paths, bare filenames (e.g. 'aaaa-fingerprint.yaml'), and tag exclusions.
        """
        matches: List[str] = []
        norm_path = relative_path.replace("\\", "/").lower()
        base_name = os.path.basename(norm_path)

        # 1. Exact path match
        if norm_path in self.excluded_files:
            matches.append(f"file:{relative_path}")

        # 2. Bare filename / template_id match (rules without slash)
        for exf in self.excluded_files:
            if "/" not in exf:
                if base_name == exf or norm_path.endswith("/" + exf):
                    matches.append(f"file:{exf}")
                elif template_id and template_id.lower() == exf.replace(".yaml", "").replace(".yml", ""):
                    matches.append(f"id:{template_id}")

        # 3. Tag match
        for tag in tags:
            tag_low = tag.strip().lower()
            if tag_low in self.excluded_tags:
                matches.append(f"tag:{tag_low}")

        # Deduplicate while preserving order
        seen = set()
        deduped = []
        for m in matches:
            if m not in seen:
                seen.add(m)
                deduped.append(m)
        return deduped


# ---------------------------------------------------------------------------
# Classification policy
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ClassificationPolicy:
    """
    Defines the eligibility rules for all protocol types.

    Fields:
        policy_version:          Semantic version of this policy (e.g., "v1.2.0").
        eligible_protocols:      Protocols that are always eligible.
        conditional_protocols:   Protocols that require web-relevance evaluation.
        ineligible_protocols:    Protocols that are never eligible.
        web_relevance_tags:      Tags that signal web-relevance for TCP/JS templates.
        web_relevance_ports:     TCP ports considered web-relevant.
        unsafe_dast_subdirs:     [v1.1.0 compat only] Not used as exclusion gate in v1.2.0.
        dast_ai_subdirs:         DAST sub-paths whose templates are conservatively unresolved.
    """
    policy_version: str
    eligible_protocols: frozenset
    conditional_protocols: frozenset
    ineligible_protocols: frozenset
    web_relevance_tags: frozenset
    web_relevance_ports: frozenset
    unsafe_dast_subdirs: frozenset       # kept for backward compat; not used as gate in v1.2.0
    dast_ai_subdirs: frozenset = field(default=frozenset())

    @classmethod
    def v1(cls) -> "ClassificationPolicy":
        """Version 1.0.0 — baseline policy."""
        return cls.v1_1()._replace_version("v1.0.0")

    @classmethod
    def v1_1(cls) -> "ClassificationPolicy":
        """
        Version 1.1.0 — Corrected and refined policy for Phase 4 cataloging.
        - Proper bare-filename ignore matching (.nuclei-ignore)
        - Nuanced DAST categorization (dast_review_required vs unsafe_behavior)
        - Multi-reason retention
        """
        return cls(
            policy_version="v1.1.0",
            eligible_protocols=frozenset({"http", "ssl", "dns", "headless"}),
            conditional_protocols=frozenset({"network", "javascript"}),
            ineligible_protocols=frozenset({"code", "file", "cloud", "whois", "websocket", "dast"}),
            web_relevance_tags=frozenset({
                "http", "https", "web", "api", "rest", "smtp", "ftp",
                "http-simple-table", "http-banner",
            }),
            web_relevance_ports=frozenset({
                80, 443, 8080, 8443, 8000, 8008, 8888, 9000, 9090, 3000, 5000,
                4848, 7001, 7002, 9200, 9300, 5601, 2375, 2376, 6443, 10250,
                4567, 8161, 61616, 15672,
            }),
            unsafe_dast_subdirs=frozenset({
                "dast/", "fuzzing/", "dast\\", "fuzzing\\",
            }),
        )

    @classmethod
    def v1_2(cls) -> "ClassificationPolicy":
        """
        Version 1.2.0 — Controlled Comprehensive DAST Integration.

        Key changes from v1.1.0:
        - 'dast' removed from ineligible_protocols (it is not a YAML protocol key; actual
          protocol keys used by Nuclei DAST templates are 'http', 'headless', etc.)
        - DAST templates evaluated individually by actual protocol keys and safety markers.
        - AI-category DAST templates conservatively flagged as dast_ai_unresolved.
        - unsafe_dast_subdirs retained for reference but NOT used as an exclusion gate.
        - dast_ai_subdirs added to identify AI DAST sub-paths requiring team decision.
        """
        return cls(
            policy_version="v1.2.0",
            eligible_protocols=frozenset({"http", "ssl", "dns", "headless"}),
            conditional_protocols=frozenset({"network", "javascript"}),
            # NOTE: 'dast' removed — it is a FOLDER name, not a YAML protocol key.
            # Nuclei DAST templates use 'http' and 'headless' as actual protocol keys.
            ineligible_protocols=frozenset({"code", "file", "cloud", "whois", "websocket"}),
            web_relevance_tags=frozenset({
                "http", "https", "web", "api", "rest", "smtp", "ftp",
                "http-simple-table", "http-banner",
            }),
            web_relevance_ports=frozenset({
                80, 443, 8080, 8443, 8000, 8008, 8888, 9000, 9090, 3000, 5000,
                4848, 7001, 7002, 9200, 9300, 5601, 2375, 2376, 6443, 10250,
                4567, 8161, 61616, 15672,
            }),
            # Kept for reference / test compatibility only; no longer gates eligibility
            unsafe_dast_subdirs=frozenset({
                "dast/", "fuzzing/", "dast\\", "fuzzing\\",
            }),
            # AI DAST sub-paths — conservatively unresolved pending team decision
            dast_ai_subdirs=frozenset({"dast/ai/", "dast\\ai\\"}),
        )

    def _replace_version(self, new_version: str) -> "ClassificationPolicy":
        return ClassificationPolicy(
            policy_version=new_version,
            eligible_protocols=self.eligible_protocols,
            conditional_protocols=self.conditional_protocols,
            ineligible_protocols=self.ineligible_protocols,
            web_relevance_tags=self.web_relevance_tags,
            web_relevance_ports=self.web_relevance_ports,
            unsafe_dast_subdirs=self.unsafe_dast_subdirs,
            dast_ai_subdirs=self.dast_ai_subdirs,
        )


# ---------------------------------------------------------------------------
# Execution requirements
# ---------------------------------------------------------------------------

# Interactsh OAST pattern — matches template raw text
_OAST_RE = re.compile(
    r"(interactsh|interact\.sh|oast\.fun|oast\.site|oast\.me|oast\.pro"
    r"|\{\{interactsh-url\}\}|\{\{oast\b)",
    re.IGNORECASE,
)

# External payload indicators (fuzzing key in YAML is a Nuclei DSL section, NOT an ext file)
_EXTERNAL_PAYLOAD_FILE_RE = re.compile(
    r"(wordlist|external[_\-]payload|payload[_\-]file)",
    re.IGNORECASE,
)

# Auth indicators in template id or tags
_AUTH_TAGS = frozenset({
    "default-login", "credential", "auth", "authentication",
    "login", "basic-auth", "auth-bypass",
})

# Required variable patterns (e.g., {{username}}, {{password}}, {{token}})
_VARIABLE_RE = re.compile(r"\{\{([A-Za-z_][A-Za-z0-9_]*)\}\}")
_BUILTIN_VARS = frozenset({
    "BaseURL", "RootURL", "Host", "Hostname", "Port", "Path",
    "Scheme", "interactsh-url", "oast",
    "rand_int", "rand_char", "rand_hex", "rand_base",
    "unix_time", "date_time",
})


def _detect_execution_requirements(
    metadata: TemplateMetadata,
    raw_yaml_text: str = "",
) -> Dict[str, Any]:
    """
    Inspect metadata and (optionally) raw YAML text to detect execution requirements.
    Returns a dict suitable for TemplateClassificationResult.execution_requirements.
    """
    tags_set = set(metadata.tags)

    # headless
    needs_headless = "headless" in metadata.protocols

    # interactsh / OAST
    needs_interactsh = bool(_OAST_RE.search(raw_yaml_text)) if raw_yaml_text else False
    if "oast" in tags_set or "interactsh" in tags_set:
        needs_interactsh = True

    # authentication
    needs_auth = bool(tags_set & _AUTH_TAGS)

    # external payload FILES (not Nuclei's fuzzing: DSL section)
    needs_external_payloads = bool(_EXTERNAL_PAYLOAD_FILE_RE.search(raw_yaml_text)) if raw_yaml_text else False

    # required variables (custom, non-builtin)
    required_variables: List[str] = []
    if raw_yaml_text:
        all_vars = set(_VARIABLE_RE.findall(raw_yaml_text))
        custom_vars = sorted(v for v in all_vars if v not in _BUILTIN_VARS)
        required_variables = custom_vars

    # dependencies (templates that require prior tool output)
    dependencies: List[str] = []  # reserved for future enrichment

    return {
        "headless": needs_headless,
        "interactsh": needs_interactsh,
        "authentication": needs_auth,
        "external_payloads": needs_external_payloads,
        "required_variables": required_variables,
        "dependencies": dependencies,
    }


# ---------------------------------------------------------------------------
# Classification result
# ---------------------------------------------------------------------------

@dataclass
class TemplateClassificationResult:
    """
    Per-template classification output — compatible with Phase 4 catalog schema.
    """
    # Repository linkage
    repository_version_id: str          # UUID of TemplateRepositoryVersion
    policy_version: str                 # e.g., "v1.2.0"

    # Identity
    template_id: Optional[str]
    relative_path: str
    content_hash: str

    # Full extracted metadata
    metadata: TemplateMetadata

    # Protocols detected (from YAML keys, not path)
    protocols: List[str]

    # Eligibility verdict
    security_status: str                # "eligible" | "ineligible" | "conditional"
    sequential_eligible: bool
    independent_eligible: bool
    web_relevant: Optional[bool]        # None = unresolved

    # Structured reason codes (from VALID_REASON_CODES only)
    eligibility_reasons: List[str]

    # Official ignore detail
    exclusion_rule: Optional[str]       # e.g., "tag:dos" or "file:http/..."

    # Execution requirements
    execution_requirements: Dict[str, Any]


# ---------------------------------------------------------------------------
# Eligibility classifier
# ---------------------------------------------------------------------------

class EligibilityClassifier:
    """
    Applies ClassificationPolicy + IgnoreRuleSet to a TemplateMetadata and
    returns a TemplateClassificationResult.

    Usage:
        policy = ClassificationPolicy.v1_2()
        ignore = IgnoreRuleSet.from_file("/snap/.nuclei-ignore")
        classifier = EligibilityClassifier(policy)
        result = classifier.classify(metadata, ignore, repository_version_id, raw_yaml_text)

    Thread-safe (read-only state after construction).
    """

    def __init__(self, policy: ClassificationPolicy):
        self.policy = policy

    def classify(
        self,
        metadata: TemplateMetadata,
        ignore_ruleset: IgnoreRuleSet,
        repository_version_id: str,
        raw_yaml_text: str = "",
        parse_errors: Optional[List[str]] = None,
    ) -> TemplateClassificationResult:
        """
        Classify a template. Never modifies metadata or ignore_ruleset.
        Retains ALL matching reasons for complete transparency.

        Args:
            metadata:               Extracted metadata from MetadataExtractor.
            ignore_ruleset:         IgnoreRuleSet loaded from snapshot's .nuclei-ignore.
            repository_version_id:  UUID of the TemplateRepositoryVersion being classified.
            raw_yaml_text:          Raw YAML text — used for execution requirement detection.
            parse_errors:           Any parse errors from TemplateParseResult.

        DAST Integration (v1.2.0):
        - Templates under dast/ are evaluated per-template, not by folder path.
        - Safety gates: official_ignore → unsafe_behavior → ai_unresolved → eligible.
        - Eligibility is based on actual YAML protocol keys (http, headless, etc.).
        - The 'fuzzing:' key in Nuclei DAST YAML is a DSL section, NOT a protocol.
        """
        policy = self.policy
        reasons: List[str] = []
        exclusion_rule: Optional[str] = None

        # Execution requirements (always compute — needed regardless of eligibility)
        exec_reqs = _detect_execution_requirements(metadata, raw_yaml_text)

        # 0. Invalid template (parse errors / missing id)
        if parse_errors or not metadata.template_id:
            reasons.append(RC_INVALID_TEMPLATE)

        # 1. Workflow — deferred, not yet supported
        if metadata.is_workflow:
            reasons.append(RC_WORKFLOW_DEFERRED)

        # 2. Official ignore check (must record all matching rules)
        all_ignore_matches = ignore_ruleset.get_all_matches(
            template_id=metadata.template_id or "",
            tags=metadata.tags,
            relative_path=metadata.relative_path,
        )
        if all_ignore_matches:
            reasons.append(RC_OFFICIAL_IGNORE)
            exclusion_rule = all_ignore_matches[0]

        # 3. Unsafe directives check (applies to ALL templates including DAST)
        has_mutating_or_unsafe = self._has_unsafe_directives(raw_yaml_text)
        if has_mutating_or_unsafe:
            reasons.append(RC_UNSAFE_BEHAVIOR)
        elif policy.policy_version in ("v1.0.0", "v1.1.0") and self._is_dast_or_unsafe_path(metadata.relative_path):
            reasons.append(RC_DAST_REVIEW)
        else:
            # 3b. AI DAST templates — conservatively unresolved (pending team decision)
            # Rationale: AI prompt injection / data exfiltration probes have unclear
            # risk boundaries for general automated scanning. Requires explicit team approval.
            if self._is_dast_ai_path(metadata.relative_path):
                reasons.append(RC_DAST_AI_UNRESOLVED)

        # 4. Protocols checks
        protos = set(metadata.protocols)
        if not protos:
            if RC_INVALID_TEMPLATE not in reasons and RC_WORKFLOW_DEFERRED not in reasons:
                reasons.append(RC_UNSUPPORTED_PROTOCOL)
        else:
            ineligible_protos = protos & policy.ineligible_protocols
            if ineligible_protos:
                reasons.append(RC_UNSUPPORTED_PROTOCOL)

            conditional_protos = protos & policy.conditional_protocols
            if conditional_protos:
                web_relevant, web_reason = self._evaluate_web_relevance(metadata, raw_yaml_text)
                if web_relevant is False:
                    reasons.append(RC_OUTSIDE_WEB_SCOPE)
                elif web_relevant is None:
                    reasons.append(RC_UNRESOLVED)

        # 5. Overall eligibility verdict
        has_ineligible_reasons = any(
            r in reasons for r in [
                RC_INVALID_TEMPLATE, RC_WORKFLOW_DEFERRED, RC_OFFICIAL_IGNORE,
                RC_UNSAFE_BEHAVIOR, RC_DAST_AI_UNRESOLVED, RC_UNSUPPORTED_PROTOCOL,
                RC_OUTSIDE_WEB_SCOPE, RC_UNRESOLVED,
            ]
        )

        if not has_ineligible_reasons:
            reasons.append(RC_ELIGIBLE)
            return self._make_result(
                repository_version_id=repository_version_id,
                metadata=metadata,
                status=STATUS_ELIGIBLE,
                seq_eligible=True,
                ind_eligible=True,
                web_relevant=True,
                reasons=reasons,
                exclusion_rule=None,
                exec_reqs=exec_reqs,
            )
        else:
            web_rel_val = False if RC_OUTSIDE_WEB_SCOPE in reasons else (True if "http" in protos else None)
            return self._make_result(
                repository_version_id=repository_version_id,
                metadata=metadata,
                status=STATUS_INELIGIBLE,
                seq_eligible=False,
                ind_eligible=False,
                web_relevant=web_rel_val,
                reasons=reasons,
                exclusion_rule=exclusion_rule,
                exec_reqs=exec_reqs,
            )

    @staticmethod
    def _has_unsafe_directives(raw_yaml_text: str) -> bool:
        """Detect unsafe: true, race: true, or mutating HTTP methods in raw template."""
        if not raw_yaml_text:
            return False
        if re.search(r"\bunsafe:\s*true\b", raw_yaml_text, re.IGNORECASE):
            return True
        if re.search(r"\brace:\s*true\b", raw_yaml_text, re.IGNORECASE):
            return True
        if re.search(r"\bmethod:\s*(PUT|DELETE|PATCH)\b", raw_yaml_text, re.IGNORECASE):
            return True
        return False

    # ------------------------------------------------------------------
    # DAST path detection
    # ------------------------------------------------------------------

    def _is_dast_ai_path(self, relative_path: str) -> bool:
        """
        Returns True if the template is in an AI DAST sub-path that requires team decision.
        These templates probe AI-specific attack surfaces (prompt injection, data exfiltration)
        whose risk boundaries for automated scanning require explicit team approval.
        """
        norm = relative_path.replace("\\", "/").lower()
        for prefix in self.policy.dast_ai_subdirs:
            prefix_norm = prefix.replace("\\", "/").lower()
            if norm.startswith(prefix_norm):
                return True
        return False

    # ------------------------------------------------------------------
    # Web-relevance evaluation for TCP/Network and JavaScript
    # ------------------------------------------------------------------

    def _evaluate_web_relevance(
        self,
        metadata: TemplateMetadata,
        raw_yaml_text: str,
    ) -> Tuple[Optional[bool], str]:
        """
        Determine whether a conditional-protocol template targets web services.

        Returns:
            (True, reason)   — confirmed web-relevant
            (False, reason)  — confirmed NOT web-relevant
            (None, reason)   — unresolved
        """
        tags_set = set(metadata.tags)

        # Rule W1: Explicit web tags in template metadata
        web_tag_hits = tags_set & self.policy.web_relevance_tags
        if web_tag_hits:
            return True, f"web_tags:{sorted(web_tag_hits)}"

        # Rule W2: "http" or "web" in template name or description (case-insensitive)
        combined_text = " ".join(filter(None, [
            metadata.name or "",
            metadata.description or "",
        ])).lower()
        if re.search(r"\b(http|https|web\s*app|web\s*serv|rest\s*api|api\s*endpoint)\b", combined_text):
            return True, "name_or_desc:http/web keywords"

        # Rule W3: Port declared in raw YAML is a known web port
        if raw_yaml_text:
            port_matches = re.findall(r"\bport:\s*(\d+)", raw_yaml_text, re.IGNORECASE)
            for pm in port_matches:
                try:
                    port_int = int(pm)
                    if port_int in self.policy.web_relevance_ports:
                        return True, f"port:{port_int}"
                except ValueError:
                    pass

        # Rule W4: Shodan query contains "http" or "port:80/443/8080/..."
        if metadata.shodan_query:
            sq = metadata.shodan_query.lower()
            if re.search(r"(http|port:(80|443|8080|8443|8000|8888))", sq):
                return True, "shodan_query:http/web port"

        # Rule W5: Template ID contains "http" or "web" (last resort)
        tid = (metadata.template_id or "").lower()
        if re.search(r"\b(http|web)\b", tid):
            return True, "template_id:http/web"

        # Rule W6: "network" protocol with explicit non-web tag signals
        # (e.g., tags: ftp, smtp, telnet, imap, pop3 — not web)
        non_web_service_tags = {
            "ftp", "ssh", "telnet", "smtp", "imap", "pop3", "ldap", "rdp",
            "smb", "snmp", "nfs", "vnc", "mqtt", "amqp", "redis-cli",
            "mysql", "mssql", "postgresql", "oracle-db", "mongodb",
        }
        non_web_hits = tags_set & non_web_service_tags
        if non_web_hits:
            return False, f"non_web_service_tags:{sorted(non_web_hits)}"

        # Unresolved
        return None, "no_web_relevance_signals"

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _is_dast_or_unsafe_path(self, relative_path: str) -> bool:
        """
        [v1.1.0 compat] No longer used as an eligibility gate in v1.2.0.
        Retained for backward compatibility with v1.1.0 tests.
        """
        norm = relative_path.replace("\\", "/").lower()
        for prefix in self.policy.unsafe_dast_subdirs:
            prefix_norm = prefix.replace("\\", "/").lower()
            if norm.startswith(prefix_norm):
                return True
        return False

    def _make_result(
        self,
        repository_version_id: str,
        metadata: TemplateMetadata,
        status: str,
        seq_eligible: bool,
        ind_eligible: bool,
        web_relevant: Optional[bool],
        reasons: List[str],
        exclusion_rule: Optional[str],
        exec_reqs: Dict[str, Any],
    ) -> TemplateClassificationResult:
        return TemplateClassificationResult(
            repository_version_id=repository_version_id,
            policy_version=self.policy.policy_version,
            template_id=metadata.template_id,
            relative_path=metadata.relative_path,
            content_hash=metadata.content_hash,
            metadata=metadata,
            protocols=list(metadata.protocols),
            security_status=status,
            sequential_eligible=seq_eligible,
            independent_eligible=ind_eligible,
            web_relevant=web_relevant,
            eligibility_reasons=reasons,
            exclusion_rule=exclusion_rule,
            execution_requirements=exec_reqs,
        )
