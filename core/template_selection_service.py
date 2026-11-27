"""
YemScan — Shared Template Selection Service (Phase 5).

Central read-only query interface for the nuclei_templates catalog.
Used by both the Sequential Scan Engine and the Independent Scan UI.

Design rules:
- NO YAML re-parsing: All queries operate exclusively on the PostgreSQL catalog.
- NO HTTPX dependency: Template selection never requires prior tool execution.
- NO severity exclusion: Eligibility is determined by policy, not severity level.
- NO wapiti dependency: Template selection is independent of Wapiti.
- NO staging version execution: Staging versions cannot be used for actual scans.
- Server-side pagination and filtering for performance at 10k+ templates.
- Deterministic ordering for reproducible scan sets.
- All user filter inputs are validated and parameterized — no raw SQL injection paths.
- Eligibility is separated from execution requirements:
    A template CAN BE eligible even if it requires headless, interactsh, or variables.
    The caller decides which execution requirements to satisfy.

API surfaces:
  TemplateSelectionService.get_version_info()       — repository version metadata
  TemplateSelectionService.get_template()           — single template by ID
  TemplateSelectionService.query_templates()        — paginated search with filters
  TemplateSelectionService.get_sequential_set()     — full eligible set for sequential scan
  TemplateSelectionService.get_selection_stats()    — count + distribution for filter
  TemplateSelectionService.validate_selection()     — validate template IDs before scan
  TemplateSelectionService.preview_selection()      — full preview with exec requirements
  TemplateSelectionService.get_available_filters()  — filter value enumeration

Data contracts for the Independent Scan UI are defined at the bottom of this module.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from sqlalchemy import and_, func, or_, select, text
from sqlalchemy.orm import Session

from database import SessionLocal
from models.template_catalog import NucleiTemplate
from models.template_repository import TemplateRepositoryVersion

logger = logging.getLogger("yemenscan.template_selection_service")


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class ScanMode(str, Enum):
    """Scan execution mode — determines which eligibility flag to query."""
    SEQUENTIAL   = "sequential"
    INDEPENDENT  = "independent"


class SortField(str, Enum):
    """Allowed sort fields for deterministic ordering."""
    TEMPLATE_ID   = "template_id"
    SEVERITY      = "severity"
    RELATIVE_PATH = "relative_path"


SEVERITY_ORDER = {
    "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5
}

ALLOWED_SEVERITIES   = frozenset({"critical", "high", "medium", "low", "info", "unknown"})
ALLOWED_PROTOCOLS    = frozenset({"http", "ssl", "dns", "headless", "network", "javascript", "code", "file"})
ALLOWED_SORT_FIELDS  = frozenset({e.value for e in SortField})

# Maximum IDs in a single validation/preview call
MAX_SELECTION_SIZE = 5000

# Max page size
MAX_PAGE_SIZE = 500


# ---------------------------------------------------------------------------
# Request / Response dataclasses
# ---------------------------------------------------------------------------

@dataclass
class TemplateFilter:
    """
    Filter criteria for template queries.

    Within a single criterion (e.g., severities=["critical","high"]):  OR logic.
    Across different criteria (severities AND tags):                    AND logic.
    """
    # Template ID prefix / exact match (OR among values)
    template_ids:   List[str] = field(default_factory=list)

    # Partial name search (case-insensitive ILIKE, OR among values)
    name_search:    List[str] = field(default_factory=list)

    # CVE IDs — exact match (OR among values)
    cve_ids:        List[str] = field(default_factory=list)

    # Tags — template must have AT LEAST ONE specified tag (OR within tags list)
    tags:           List[str] = field(default_factory=list)

    # Severity levels (OR among values)
    severities:     List[str] = field(default_factory=list)

    # Protocol keys (OR among values)
    protocols:      List[str] = field(default_factory=list)

    # Execution requirements filter (optional)
    exclude_requires_headless:     bool = False
    exclude_requires_interactsh:   bool = False
    exclude_requires_authentication: bool = False
    exclude_requires_variables:    bool = False

    def validate(self) -> List[str]:
        """Return list of validation error messages, empty if valid."""
        errors = []
        for sev in self.severities:
            if sev.lower() not in ALLOWED_SEVERITIES:
                errors.append(f"Invalid severity: '{sev}'. Allowed: {sorted(ALLOWED_SEVERITIES)}")
        for proto in self.protocols:
            if proto.lower() not in ALLOWED_PROTOCOLS:
                errors.append(f"Invalid protocol: '{proto}'. Allowed: {sorted(ALLOWED_PROTOCOLS)}")
        for cve in self.cve_ids:
            if not re.match(r'^CVE-\d{4}-\d+$', cve, re.IGNORECASE):
                errors.append(f"Invalid CVE ID format: '{cve}'. Expected CVE-YYYY-NNNNN")
        for tid in self.template_ids:
            if not re.match(r'^[a-zA-Z0-9_\-./]+$', tid):
                errors.append(f"Invalid template_id characters: '{tid}'")
        return errors


@dataclass
class PaginationParams:
    """Server-side pagination parameters."""
    page: int = 1          # 1-based page number
    page_size: int = 50    # records per page (max MAX_PAGE_SIZE)

    def __post_init__(self):
        if self.page < 1:
            self.page = 1
        if self.page_size < 1:
            self.page_size = 1
        if self.page_size > MAX_PAGE_SIZE:
            self.page_size = MAX_PAGE_SIZE

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.page_size


@dataclass
class TemplateRecord:
    """Single template record returned by queries."""
    id: str
    template_id: str
    name: Optional[str]
    description: Optional[str]
    severity: str
    tags: List[str]
    protocols: List[str]
    cve_ids: List[str]
    cwe_ids: List[str]
    relative_path: str
    content_hash: str
    security_status: str
    sequential_eligible: bool
    independent_eligible: bool
    # Metadata fields (from JSONB)
    author: Optional[str]
    cvss_score: Optional[float]
    cvss_vector: Optional[str]
    references: List[str]
    remediation: Optional[str]
    # Policy details (from JSONB)
    eligibility_reasons: List[str]
    requires_headless: bool
    requires_interactsh: bool
    requires_authentication: bool
    requires_variables: List[str]
    official_exclusion_matches: List[str]
    policy_version: str
    indexed_at: Optional[str] = None
    engine_validation_status: Optional[str] = None
    engine_validation_reason: Optional[str] = None


@dataclass
class TemplateQueryResult:
    """Paginated query result."""
    repository_version_id: str
    scan_mode: str
    total_count: int
    page: int
    page_size: int
    total_pages: int
    templates: List[TemplateRecord]
    filter_applied: Dict[str, Any]


@dataclass
class SelectionStats:
    """Statistics for a filter query without returning full records."""
    repository_version_id: str
    total_matching: int
    by_severity: Dict[str, int]
    by_protocol: Dict[str, int]
    requires_headless_count: int
    requires_interactsh_count: int
    requires_authentication_count: int
    requires_variables_count: int
    scan_mode: str


@dataclass
class ValidationResult:
    """Result of validating a set of template IDs."""
    valid: bool
    repository_version_id: str
    requested_count: int
    valid_count: int
    invalid_ids: List[str]           # template_ids not found in catalog
    ineligible_ids: List[str]        # template_ids found but not eligible for scan_mode
    eligible_ids: List[str]          # confirmed eligible template_ids
    errors: List[str]                # structural validation errors (bad format, etc.)


@dataclass
class SelectionPreview:
    """Full preview of a template selection before execution."""
    repository_version_id: str
    repository_version: str          # e.g., "v10.5.1"
    scan_mode: str
    is_staging: bool                 # True if version is still in staging (cannot be executed)
    total_selected: int
    templates: List[TemplateRecord]
    # Distributions
    by_severity: Dict[str, int]
    by_protocol: Dict[str, int]
    # Execution requirement summary
    requires_headless_count: int
    requires_interactsh_count: int
    requires_authentication_count: int
    requires_variables_count: int
    # Incompatibility warnings
    incompatible_templates: List[Dict[str, Any]]   # {template_id, reason}
    warnings: List[str]


@dataclass
class VersionInfo:
    """Repository version metadata."""
    version_id: str
    upstream_version: str
    upstream_commit: str
    snapshot_hash: str
    status: str
    policy_version: Optional[str]
    repository_path: str
    is_usable_for_scan: bool   # True only if status == "active"


@dataclass
class PaginatedTagsResult:
    """Paginated tag listing with occurrence counts."""
    repository_version_id: str
    scan_mode: str
    total_tags: int
    page: int
    page_size: int
    total_pages: int
    tags: List[Dict[str, Any]]     # [{"tag": "cve", "count": 5210}, ...]


@dataclass
class AvailableFilters:
    """Enumerated filter values available for the given version."""
    repository_version_id: str
    severities: List[str]
    protocols: List[str]
    top_tags: List[str]            # top 50 tags by template count
    total_tags_count: int          # total distinct tags available across all templates
    has_cve_templates: bool
    total_eligible_sequential: int
    total_eligible_independent: int


@dataclass
class SelectionState:
    """Server-side selection state for independent scan UI."""
    repository_version_id: str
    scan_mode: str
    selected_ids: List[str]
    total_selected: int
    added_ids: List[str]
    removed_ids: List[str]
    rejected_ineligible: List[str]
    rejected_nonexistent: List[str]
    warnings: List[str]


@dataclass
class EnvironmentCapabilities:
    """Environment execution capabilities for readiness check."""
    headless_available: bool = False
    interactsh_available: bool = False
    auth_credentials_provided: bool = False
    variables_provided: Dict[str, str] = field(default_factory=dict)
    dast_inputs_available: bool = False
    authorized_scopes: List[str] = field(default_factory=list)


@dataclass
class TemplateReadinessStatus:
    """Detailed target compatibility and readiness breakdown for a single template."""
    template_id: str
    eligible: bool
    target_compatible: bool
    execution_ready: bool
    in_scope: bool
    overall_ready: bool
    blocking_reasons: List[str]
    required_execution: Dict[str, Any]


@dataclass
class TargetReadinessEvaluation:
    """Aggregated evaluation of templates against a target and environment."""
    repository_version_id: str
    target: str
    target_type: str                   # "url" | "domain" | "ip"
    total_evaluated: int
    ready_count: int
    compatible_but_not_ready_count: int
    incompatible_target_count: int
    ineligible_count: int
    out_of_scope_count: int
    readiness_breakdown: Dict[str, int]
    templates: List[TemplateReadinessStatus]


# ---------------------------------------------------------------------------
# Main Service
# ---------------------------------------------------------------------------

class TemplateSelectionService:
    """
    Central read-only query service for the nuclei_templates catalog.

    All methods operate on existing PostgreSQL data — no YAML re-parsing.
    Thread-safe (each call creates/uses its own session scope).
    """

    def __init__(self, session: Optional[Session] = None):
        """
        Args:
            session: Optional externally-managed SQLAlchemy session.
                     If None, each method creates and closes its own session.
        """
        self._ext_session = session

    def _get_session(self) -> Tuple[Session, bool]:
        """Returns (session, owns_it). Caller must close if owns_it=True."""
        if self._ext_session:
            return self._ext_session, False
        return SessionLocal(), True

    # ------------------------------------------------------------------
    # Version Info
    # ------------------------------------------------------------------

    def get_version_info(self, repository_version_id: str) -> Optional[VersionInfo]:
        """Retrieve repository version metadata."""
        db, owns = self._get_session()
        try:
            rec = db.execute(
                select(TemplateRepositoryVersion).where(
                    TemplateRepositoryVersion.id == repository_version_id
                )
            ).scalar_one_or_none()
            if not rec:
                return None
            return VersionInfo(
                version_id=rec.id,
                upstream_version=rec.upstream_version,
                upstream_commit=rec.upstream_commit,
                snapshot_hash=rec.snapshot_hash,
                status=rec.status,
                policy_version=getattr(rec, "policy_version", None),
                repository_path=rec.repository_path,
                is_usable_for_scan=(rec.status == "active"),
            )
        finally:
            if owns:
                db.close()

    # ------------------------------------------------------------------
    # Single Template Retrieval
    # ------------------------------------------------------------------

    def get_template(
        self,
        repository_version_id: str,
        template_id: str,
    ) -> Optional[TemplateRecord]:
        """Retrieve a single template by template_id within a version."""
        db, owns = self._get_session()
        try:
            row = db.execute(
                select(NucleiTemplate).where(
                    NucleiTemplate.repository_version_id == repository_version_id,
                    NucleiTemplate.template_id == template_id,
                )
            ).scalar_one_or_none()
            if not row:
                return None
            return self._row_to_record(row)
        finally:
            if owns:
                db.close()

    # ------------------------------------------------------------------
    # Query Templates (paginated, with filters)
    # ------------------------------------------------------------------

    def query_templates(
        self,
        repository_version_id: str,
        scan_mode: ScanMode = ScanMode.SEQUENTIAL,
        filters: Optional[TemplateFilter] = None,
        pagination: Optional[PaginationParams] = None,
        sort_by: SortField = SortField.SEVERITY,
    ) -> TemplateQueryResult:
        """
        Paginated search with up to 6 filter dimensions.

        Filter logic:
          - Within a list criterion: OR
          - Between different criteria: AND
          - scan_mode determines which eligibility column to enforce

        Never re-parses YAML. All data comes from nuclei_templates catalog.
        """
        if filters is None:
            filters = TemplateFilter()
        if pagination is None:
            pagination = PaginationParams()

        filter_errors = filters.validate()
        if filter_errors:
            raise ValueError(f"Filter validation errors: {filter_errors}")

        db, owns = self._get_session()
        try:
            base_q = self._build_base_query(
                repository_version_id=repository_version_id,
                scan_mode=scan_mode,
                filters=filters,
            )

            # Count
            count_q = select(func.count()).select_from(base_q.subquery())
            total_count = db.execute(count_q).scalar_one()

            # Order + paginate
            ordered_q = base_q.order_by(
                *self._build_order_by(sort_by)
            ).offset(pagination.offset).limit(pagination.page_size)

            rows = db.execute(ordered_q).scalars().all()
            templates = [self._row_to_record(r) for r in rows]

            total_pages = max(1, (total_count + pagination.page_size - 1) // pagination.page_size)

            return TemplateQueryResult(
                repository_version_id=repository_version_id,
                scan_mode=scan_mode.value,
                total_count=total_count,
                page=pagination.page,
                page_size=pagination.page_size,
                total_pages=total_pages,
                templates=templates,
                filter_applied=self._filter_to_dict(filters),
            )
        finally:
            if owns:
                db.close()

    # ------------------------------------------------------------------
    # Sequential Scan Set
    # ------------------------------------------------------------------

    def get_sequential_set(
        self,
        repository_version_id: str,
        filters: Optional[TemplateFilter] = None,
    ) -> List[TemplateRecord]:
        """
        Returns ALL sequential-eligible templates for the given version.

        Contract:
        - All returned templates have sequential_eligible = True.
        - Filtered by caller-supplied TemplateFilter (optional).
        - Deterministic order: severity (critical first), then template_id.
        - No pagination — returns complete set for sequential scan planning.
        - Does NOT require HTTPX technology discovery output.
        - Does NOT exclude templates based on wapiti output.
        - Includes templates regardless of severity level.

        Caller is responsible for satisfying execution requirements
        (headless, interactsh, variables) at execution time.
        """
        if filters is None:
            filters = TemplateFilter()

        db, owns = self._get_session()
        try:
            base_q = self._build_base_query(
                repository_version_id=repository_version_id,
                scan_mode=ScanMode.SEQUENTIAL,
                filters=filters,
            ).order_by(*self._build_order_by(SortField.SEVERITY))

            rows = db.execute(base_q).scalars().all()
            return [self._row_to_record(r) for r in rows]
        finally:
            if owns:
                db.close()

    # ------------------------------------------------------------------
    # Selection Stats (count + distribution, no full records)
    # ------------------------------------------------------------------

    def get_selection_stats(
        self,
        repository_version_id: str,
        scan_mode: ScanMode = ScanMode.SEQUENTIAL,
        filters: Optional[TemplateFilter] = None,
    ) -> SelectionStats:
        """Return statistics for a filter query without fetching full records."""
        if filters is None:
            filters = TemplateFilter()

        db, owns = self._get_session()
        try:
            base_q = self._build_base_query(
                repository_version_id=repository_version_id,
                scan_mode=scan_mode,
                filters=filters,
            )
            sub = base_q.subquery()

            total = db.execute(select(func.count()).select_from(sub)).scalar_one()

            # By severity
            sev_rows = db.execute(
                select(sub.c.severity, func.count().label("n"))
                .group_by(sub.c.severity)
            ).all()
            by_severity = {r.severity: r.n for r in sev_rows}

            # By protocol — unnest array in PostgreSQL
            # We approximate using Python-side since unnest requires raw SQL
            # For exact counts: query a small sample to determine support
            proto_rows = db.execute(
                select(sub.c.protocols)
            ).scalars().all()
            by_protocol: Dict[str, int] = {}
            for proto_list in proto_rows:
                if isinstance(proto_list, list):
                    for p in proto_list:
                        by_protocol[p] = by_protocol.get(p, 0) + 1

            # Execution requirement counts (from policy_details JSONB)
            headless_count = db.execute(
                select(func.count()).select_from(sub).where(
                    text("(policy_details->>'headless_requirement')::boolean = true")
                )
            ).scalar_one()
            oast_count = db.execute(
                select(func.count()).select_from(sub).where(
                    text("(policy_details->>'oast_requirement')::boolean = true")
                )
            ).scalar_one()
            auth_count = db.execute(
                select(func.count()).select_from(sub).where(
                    text("(policy_details->>'authentication_requirements')::boolean = true")
                )
            ).scalar_one()
            vars_count = db.execute(
                select(func.count()).select_from(sub).where(
                    text("jsonb_array_length(COALESCE(policy_details->'required_variables', '[]'::jsonb)) > 0")
                )
            ).scalar_one()

            return SelectionStats(
                repository_version_id=repository_version_id,
                total_matching=total,
                by_severity=by_severity,
                by_protocol=by_protocol,
                requires_headless_count=headless_count,
                requires_interactsh_count=oast_count,
                requires_authentication_count=auth_count,
                requires_variables_count=vars_count,
                scan_mode=scan_mode.value,
            )
        finally:
            if owns:
                db.close()

    # ------------------------------------------------------------------
    # Validate Selection
    # ------------------------------------------------------------------

    def validate_selection(
        self,
        repository_version_id: str,
        template_ids: List[str],
        scan_mode: ScanMode = ScanMode.INDEPENDENT,
    ) -> ValidationResult:
        """
        Validate that a list of template_ids are present and eligible.

        Security:
        - All template_ids are sanitized before query.
        - No arbitrary paths or commands accepted.
        - Staging versions cannot be used for actual scans.

        Args:
            repository_version_id: Version to validate against.
            template_ids:          List of template_id strings from user/UI.
            scan_mode:             Which eligibility column to check.

        Returns:
            ValidationResult with valid/invalid/ineligible breakdowns.
        """
        errors = []

        # Structural validation
        if not template_ids:
            return ValidationResult(
                valid=False, repository_version_id=repository_version_id,
                requested_count=0, valid_count=0,
                invalid_ids=[], ineligible_ids=[], eligible_ids=[],
                errors=["No template IDs provided."],
            )

        if len(template_ids) > MAX_SELECTION_SIZE:
            errors.append(
                f"Selection too large: {len(template_ids)} IDs (max {MAX_SELECTION_SIZE})."
            )

        # Sanitize IDs
        safe_ids = []
        bad_format_ids = []
        for tid in template_ids:
            if re.match(r'^[a-zA-Z0-9_\-./]+$', str(tid)):
                safe_ids.append(str(tid))
            else:
                bad_format_ids.append(str(tid))
        if bad_format_ids:
            errors.append(f"Invalid template_id format for: {bad_format_ids[:10]}")

        if errors:
            return ValidationResult(
                valid=False, repository_version_id=repository_version_id,
                requested_count=len(template_ids), valid_count=0,
                invalid_ids=bad_format_ids, ineligible_ids=[], eligible_ids=[],
                errors=errors,
            )

        db, owns = self._get_session()
        try:
            # Check staging status
            version_rec = db.execute(
                select(TemplateRepositoryVersion).where(
                    TemplateRepositoryVersion.id == repository_version_id
                )
            ).scalar_one_or_none()

            if not version_rec:
                return ValidationResult(
                    valid=False, repository_version_id=repository_version_id,
                    requested_count=len(template_ids), valid_count=0,
                    invalid_ids=[], ineligible_ids=[], eligible_ids=[],
                    errors=[f"Repository version '{repository_version_id}' not found."],
                )

            if version_rec.status == "staging":
                errors.append(
                    f"Version '{version_rec.upstream_version}' is in staging status. "
                    "Staging versions cannot be used for actual scans."
                )

            # Determine eligibility column
            elig_col = (
                NucleiTemplate.sequential_eligible
                if scan_mode == ScanMode.SEQUENTIAL
                else NucleiTemplate.independent_eligible
            )

            # De-duplicate safe_ids
            unique_ids = list(dict.fromkeys(safe_ids))

            rows = db.execute(
                select(NucleiTemplate.template_id, elig_col).where(
                    NucleiTemplate.repository_version_id == repository_version_id,
                    NucleiTemplate.template_id.in_(unique_ids),
                )
            ).all()

            found_map = {r[0]: r[1] for r in rows}
            found_set = set(found_map.keys())
            requested_set = set(unique_ids)

            invalid_ids = sorted(requested_set - found_set)
            ineligible_ids = sorted(tid for tid, elig in found_map.items() if not elig)
            eligible_ids = sorted(tid for tid, elig in found_map.items() if elig)

            is_valid = (
                not invalid_ids and not ineligible_ids
                and not errors and version_rec.status != "staging"
            )

            return ValidationResult(
                valid=is_valid,
                repository_version_id=repository_version_id,
                requested_count=len(unique_ids),
                valid_count=len(eligible_ids),
                invalid_ids=invalid_ids,
                ineligible_ids=ineligible_ids,
                eligible_ids=eligible_ids,
                errors=errors,
            )
        finally:
            if owns:
                db.close()

    # ------------------------------------------------------------------
    # Selection Preview
    # ------------------------------------------------------------------

    def preview_selection(
        self,
        repository_version_id: str,
        template_ids: List[str],
        scan_mode: ScanMode = ScanMode.INDEPENDENT,
    ) -> SelectionPreview:
        """
        Full preview of a selection: distributions, exec requirements, incompatibilities.

        Security:
        - Template_ids are validated before any DB query.
        - No auto-replacement of incompatible templates.
        - Incompatible templates are reported, NOT silently dropped.
        - Staging versions are flagged (is_staging=True).
        """
        validation = self.validate_selection(
            repository_version_id=repository_version_id,
            template_ids=template_ids,
            scan_mode=scan_mode,
        )

        db, owns = self._get_session()
        try:
            version_rec = db.execute(
                select(TemplateRepositoryVersion).where(
                    TemplateRepositoryVersion.id == repository_version_id
                )
            ).scalar_one_or_none()

            version_str = version_rec.upstream_version if version_rec else "unknown"
            is_staging = (version_rec.status == "staging") if version_rec else True

            # Fetch all requested eligible templates
            safe_ids = [
                tid for tid in template_ids
                if re.match(r'^[a-zA-Z0-9_\-./]+$', str(tid))
            ]
            rows = []
            if safe_ids:
                rows = db.execute(
                    select(NucleiTemplate).where(
                        NucleiTemplate.repository_version_id == repository_version_id,
                        NucleiTemplate.template_id.in_(safe_ids),
                    ).order_by(*self._build_order_by(SortField.SEVERITY))
                ).scalars().all()

            templates = [self._row_to_record(r) for r in rows]

            # Build distributions
            by_severity: Dict[str, int] = {}
            by_protocol: Dict[str, int] = {}
            headless_count = oast_count = auth_count = vars_count = 0
            incompatible: List[Dict[str, Any]] = []

            for t in templates:
                by_severity[t.severity] = by_severity.get(t.severity, 0) + 1
                for p in t.protocols:
                    by_protocol[p] = by_protocol.get(p, 0) + 1
                if t.requires_headless:
                    headless_count += 1
                if t.requires_interactsh:
                    oast_count += 1
                if t.requires_authentication:
                    auth_count += 1
                if t.requires_variables:
                    vars_count += 1

                # Check eligibility for the requested scan mode
                if scan_mode == ScanMode.SEQUENTIAL and not t.sequential_eligible:
                    incompatible.append({
                        "template_id": t.template_id,
                        "reason": "not_sequential_eligible",
                        "security_status": t.security_status,
                    })
                elif scan_mode == ScanMode.INDEPENDENT and not t.independent_eligible:
                    incompatible.append({
                        "template_id": t.template_id,
                        "reason": "not_independent_eligible",
                        "security_status": t.security_status,
                    })

            warnings = []
            if is_staging:
                warnings.append(
                    f"Version '{version_str}' is in staging state. "
                    "This selection CANNOT be used for actual scans until published."
                )
            if validation.invalid_ids:
                warnings.append(
                    f"{len(validation.invalid_ids)} template_ids not found in catalog: "
                    f"{validation.invalid_ids[:5]}{'...' if len(validation.invalid_ids) > 5 else ''}"
                )
            if validation.ineligible_ids:
                warnings.append(
                    f"{len(validation.ineligible_ids)} templates are ineligible for {scan_mode.value} scan."
                )

            return SelectionPreview(
                repository_version_id=repository_version_id,
                repository_version=version_str,
                scan_mode=scan_mode.value,
                is_staging=is_staging,
                total_selected=len(templates),
                templates=templates,
                by_severity=by_severity,
                by_protocol=by_protocol,
                requires_headless_count=headless_count,
                requires_interactsh_count=oast_count,
                requires_authentication_count=auth_count,
                requires_variables_count=vars_count,
                incompatible_templates=incompatible,
                warnings=warnings,
            )
        finally:
            if owns:
                db.close()

    # ------------------------------------------------------------------
    # Available Filters
    # ------------------------------------------------------------------

    def get_available_filters(
        self,
        repository_version_id: str,
        scan_mode: ScanMode = ScanMode.INDEPENDENT,
    ) -> AvailableFilters:
        """Return enumerated filter values for the given version and scan mode."""
        db, owns = self._get_session()
        try:
            elig_col = (
                NucleiTemplate.sequential_eligible
                if scan_mode == ScanMode.SEQUENTIAL
                else NucleiTemplate.independent_eligible
            )
            base_where = and_(
                NucleiTemplate.repository_version_id == repository_version_id,
                elig_col == True,
            )

            # Distinct severities
            sev_rows = db.execute(
                select(NucleiTemplate.severity)
                .where(base_where)
                .distinct()
            ).scalars().all()
            severities = sorted(sev_rows, key=lambda s: SEVERITY_ORDER.get(s, 99))

            # Protocols (need unnest or Python-side)
            proto_rows = db.execute(
                select(NucleiTemplate.protocols).where(base_where)
            ).scalars().all()
            proto_set: Set[str] = set()
            for pl in proto_rows:
                if isinstance(pl, list):
                    proto_set.update(pl)
            protocols = sorted(proto_set)

            # Top 50 tags (Python-side aggregation)
            tag_rows = db.execute(
                select(NucleiTemplate.tags).where(base_where)
            ).scalars().all()
            tag_counts: Dict[str, int] = {}
            for tl in tag_rows:
                if isinstance(tl, list):
                    for t in tl:
                        tag_counts[t] = tag_counts.get(t, 0) + 1
            top_tags = sorted(tag_counts, key=lambda t: -tag_counts[t])[:50]

            # Has CVE templates
            cve_count = db.execute(
                select(func.count()).where(
                    base_where,
                    text("cve_ids != '{}'::varchar[]"),
                )
            ).scalar_one()

            # Total eligible counts
            seq_count = db.execute(
                select(func.count()).where(
                    NucleiTemplate.repository_version_id == repository_version_id,
                    NucleiTemplate.sequential_eligible == True,
                )
            ).scalar_one()
            ind_count = db.execute(
                select(func.count()).where(
                    NucleiTemplate.repository_version_id == repository_version_id,
                    NucleiTemplate.independent_eligible == True,
                )
            ).scalar_one()

            return AvailableFilters(
                repository_version_id=repository_version_id,
                severities=severities,
                protocols=protocols,
                top_tags=top_tags,
                total_tags_count=len(tag_counts),
                has_cve_templates=cve_count > 0,
                total_eligible_sequential=seq_count,
                total_eligible_independent=ind_count,
            )
        finally:
            if owns:
                db.close()

    # ------------------------------------------------------------------
    # All Tags (Paginated & Searchable)
    # ------------------------------------------------------------------

    def get_all_tags(
        self,
        repository_version_id: str,
        scan_mode: ScanMode = ScanMode.INDEPENDENT,
        search: Optional[str] = None,
        page: int = 1,
        page_size: int = 100,
    ) -> PaginatedTagsResult:
        """
        Returns a paginated list of all distinct tags and their template counts.
        Allows searching/filtering across thousands of tags, not just the top 50.
        """
        page = max(1, page)
        page_size = min(max(1, page_size), 500)
        offset = (page - 1) * page_size

        db, owns = self._get_session()
        try:
            elig_col = (
                NucleiTemplate.sequential_eligible
                if scan_mode == ScanMode.SEQUENTIAL
                else NucleiTemplate.independent_eligible
            )

            # In PostgreSQL: use unnest(tags) for high performance
            # In SQLite fallback: use Python aggregation
            is_sqlite = (db.bind.dialect.name == "sqlite") if db.bind else False
            if not is_sqlite:
                search_clause = ""
                params: Dict[str, Any] = {
                    "vid": repository_version_id,
                    "limit": page_size,
                    "offset": offset,
                }
                if search:
                    search_clause = "AND tag ILIKE :search"
                    params["search"] = f"%{search.strip().lower()}%"

                elig_filter = "sequential_eligible = true" if scan_mode == ScanMode.SEQUENTIAL else "independent_eligible = true"

                count_sql = text(f"""
                    SELECT count(DISTINCT tag)
                    FROM nuclei_templates, unnest(tags) as tag
                    WHERE repository_version_id = :vid AND {elig_filter}
                    {search_clause}
                """)
                total_tags = db.execute(count_sql, params).scalar_one()

                data_sql = text(f"""
                    SELECT tag, count(*) as cnt
                    FROM nuclei_templates, unnest(tags) as tag
                    WHERE repository_version_id = :vid AND {elig_filter}
                    {search_clause}
                    GROUP BY tag
                    ORDER BY cnt DESC, tag ASC
                    LIMIT :limit OFFSET :offset
                """)
                rows = db.execute(data_sql, params).all()
                tag_items = [{"tag": r[0], "count": r[1]} for r in rows]
            else:
                base_where = and_(
                    NucleiTemplate.repository_version_id == repository_version_id,
                    elig_col == True,
                )
                tag_rows = db.execute(select(NucleiTemplate.tags).where(base_where)).scalars().all()
                tag_counts: Dict[str, int] = {}
                for tl in tag_rows:
                    if isinstance(tl, list):
                        for t in tl:
                            tag_counts[t] = tag_counts.get(t, 0) + 1
                filtered = [
                    (t, c) for t, c in tag_counts.items()
                    if not search or search.lower() in t.lower()
                ]
                filtered.sort(key=lambda x: (-x[1], x[0]))
                total_tags = len(filtered)
                paged = filtered[offset : offset + page_size]
                tag_items = [{"tag": t, "count": c} for t, c in paged]

            total_pages = max(1, (total_tags + page_size - 1) // page_size)

            return PaginatedTagsResult(
                repository_version_id=repository_version_id,
                scan_mode=scan_mode.value,
                total_tags=total_tags,
                page=page,
                page_size=page_size,
                total_pages=total_pages,
                tags=tag_items,
            )
        finally:
            if owns:
                db.close()

    # ------------------------------------------------------------------
    # Select All Matching IDs
    # ------------------------------------------------------------------

    def select_all_matching_ids(
        self,
        repository_version_id: str,
        scan_mode: ScanMode = ScanMode.INDEPENDENT,
        filters: Optional[TemplateFilter] = None,
    ) -> List[str]:
        """
        Returns all matching template_ids across the entire catalog for given filters.
        Not limited to the current page. Deterministically ordered.
        """
        if filters is None:
            filters = TemplateFilter()

        db, owns = self._get_session()
        try:
            base_q = self._build_base_query(
                repository_version_id=repository_version_id,
                scan_mode=scan_mode,
                filters=filters,
            ).order_by(*self._build_order_by(SortField.TEMPLATE_ID))

            # Select only template_id column for speed and low memory
            id_q = select(base_q.subquery().c.template_id)
            rows = db.execute(id_q).scalars().all()
            return list(rows)
        finally:
            if owns:
                db.close()

    # ------------------------------------------------------------------
    # Manage Selection (Add, Remove, Select All, Deduplicate)
    # ------------------------------------------------------------------

    def manage_selection(
        self,
        repository_version_id: str,
        scan_mode: ScanMode = ScanMode.INDEPENDENT,
        current_selected_ids: Optional[List[str]] = None,
        add_ids: Optional[List[str]] = None,
        remove_ids: Optional[List[str]] = None,
        select_all_matching: bool = False,
        filters: Optional[TemplateFilter] = None,
    ) -> SelectionState:
        """
        Server-side template selection management:
        - Combines selections without duplicates.
        - Supports removing individual templates.
        - Supports 'Select All Matching' across all pages.
        - Strictly validates and rejects ineligible templates.
        - Binds selections to the specified repository version.
        - Never mixes templates across different versions.
        """
        current_set: Set[str] = set(current_selected_ids or [])
        to_add: Set[str] = set()

        if select_all_matching:
            all_matching = self.select_all_matching_ids(
                repository_version_id=repository_version_id,
                scan_mode=scan_mode,
                filters=filters,
            )
            to_add.update(all_matching)

        if add_ids:
            for tid in add_ids:
                if isinstance(tid, str) and tid.strip():
                    to_add.add(tid.strip())

        # Combine
        combined_candidates = current_set | to_add

        # Apply removals
        removed_ids_list: List[str] = []
        if remove_ids:
            for rid in remove_ids:
                rid_str = str(rid).strip()
                if rid_str in combined_candidates:
                    combined_candidates.discard(rid_str)
                    removed_ids_list.append(rid_str)

        if not combined_candidates:
            return SelectionState(
                repository_version_id=repository_version_id,
                scan_mode=scan_mode.value,
                selected_ids=[],
                total_selected=0,
                added_ids=sorted(to_add),
                removed_ids=sorted(removed_ids_list),
                rejected_ineligible=[],
                rejected_nonexistent=[],
                warnings=[],
            )

        # Validate candidate IDs against the database
        db, owns = self._get_session()
        try:
            elig_col = (
                NucleiTemplate.sequential_eligible
                if scan_mode == ScanMode.SEQUENTIAL
                else NucleiTemplate.independent_eligible
            )

            # Query all candidates in DB for this version
            rows = db.execute(
                select(NucleiTemplate.template_id, elig_col).where(
                    NucleiTemplate.repository_version_id == repository_version_id,
                    NucleiTemplate.template_id.in_(list(combined_candidates)),
                )
            ).all()

            found_map = {r[0]: r[1] for r in rows}
            found_set = set(found_map.keys())

            rejected_nonexistent = sorted(combined_candidates - found_set)
            rejected_ineligible = sorted(tid for tid, elig in found_map.items() if not elig)
            valid_selected = sorted(tid for tid, elig in found_map.items() if elig)

            warnings = []
            if rejected_nonexistent:
                warnings.append(
                    f"{len(rejected_nonexistent)} template IDs not found in version '{repository_version_id}'"
                )
            if rejected_ineligible:
                warnings.append(
                    f"{len(rejected_ineligible)} template IDs are not eligible for {scan_mode.value} scanning"
                )

            added_actual = sorted((set(valid_selected) - current_set))

            return SelectionState(
                repository_version_id=repository_version_id,
                scan_mode=scan_mode.value,
                selected_ids=valid_selected,
                total_selected=len(valid_selected),
                added_ids=added_actual,
                removed_ids=sorted(removed_ids_list),
                rejected_ineligible=rejected_ineligible,
                rejected_nonexistent=rejected_nonexistent,
                warnings=warnings,
            )
        finally:
            if owns:
                db.close()

    # ------------------------------------------------------------------
    # Target Compatibility and Execution Readiness Evaluation
    # ------------------------------------------------------------------

    def evaluate_target_and_readiness(
        self,
        repository_version_id: str,
        template_ids: List[str],
        target: str,
        scan_mode: ScanMode = ScanMode.INDEPENDENT,
        environment_caps: Optional[EnvironmentCapabilities] = None,
    ) -> TargetReadinessEvaluation:
        """
        Evaluates candidate templates against a specific target and environment.

        Separates:
          1. Eligibility: Intrinsic policy verdict.
          2. Target Compatibility: Target format (URL vs Domain vs IP) and protocol match.
          3. Execution Readiness: Headless browser, OAST, credentials, custom variables, DAST input.
          4. Authorization and Scope: Scope check against authorized scopes list.
        """
        caps = environment_caps or EnvironmentCapabilities()
        clean_target = str(target).strip()

        # Classify target type
        target_type, target_host = self._classify_target(clean_target)

        # Check scope
        in_scope_default = True
        if caps.authorized_scopes:
            in_scope_default = self._is_host_in_scope(target_host, caps.authorized_scopes)

        # Fetch candidate template records
        db, owns = self._get_session()
        try:
            safe_ids = [t for t in template_ids if re.match(r'^[a-zA-Z0-9_\-./]+$', str(t))]
            rows = []
            if safe_ids:
                rows = db.execute(
                    select(NucleiTemplate).where(
                        NucleiTemplate.repository_version_id == repository_version_id,
                        NucleiTemplate.template_id.in_(safe_ids),
                    )
                ).scalars().all()

            evaluated_templates: List[TemplateReadinessStatus] = []
            ready_count = 0
            compatible_not_ready = 0
            incompatible_target = 0
            ineligible_count = 0
            out_of_scope_count = 0
            breakdown = {
                "missing_headless": 0,
                "missing_oast": 0,
                "missing_auth": 0,
                "missing_variables": 0,
                "missing_dast_inputs": 0,
                "incompatible_protocol": 0,
                "ineligible": 0,
                "out_of_scope": 0,
            }

            for row in rows:
                t = self._row_to_record(row)
                blocking: List[str] = []

                # 1. Eligibility
                is_eligible = t.sequential_eligible if scan_mode == ScanMode.SEQUENTIAL else t.independent_eligible
                if not is_eligible:
                    blocking.append(f"ineligible:{t.security_status}")
                    breakdown["ineligible"] += 1
                    ineligible_count += 1

                # 2. Scope
                is_in_scope = in_scope_default
                if not is_in_scope:
                    blocking.append(f"out_of_scope:{target_host}")
                    breakdown["out_of_scope"] += 1
                    out_of_scope_count += 1

                # 3. Target Compatibility
                is_compat = self._is_template_compatible_with_target(t, target_type)
                if not is_compat:
                    blocking.append(f"incompatible_target_type:{target_type}")
                    breakdown["incompatible_protocol"] += 1
                    incompatible_target += 1

                # 4. Execution Readiness
                exec_ready = True
                if t.requires_headless and not caps.headless_available:
                    exec_ready = False
                    blocking.append("headless_browser_unavailable")
                    breakdown["missing_headless"] += 1

                if t.requires_interactsh and not caps.interactsh_available:
                    exec_ready = False
                    blocking.append("interactsh_oast_unavailable")
                    breakdown["missing_oast"] += 1

                if t.requires_authentication and not caps.auth_credentials_provided:
                    exec_ready = False
                    blocking.append("auth_credentials_missing")
                    breakdown["missing_auth"] += 1

                # Only non-builtin required variables count
                if t.requires_variables:
                    missing_vars = [v for v in t.requires_variables if v not in caps.variables_provided]
                    if missing_vars:
                        exec_ready = False
                        blocking.append(f"required_variables_missing:{missing_vars}")
                        breakdown["missing_variables"] += 1

                # DAST endpoint input check: DAST injection templates require crawled inputs/endpoints
                is_dast_template = t.relative_path.startswith("dast/") or "dast" in t.tags
                if is_dast_template and not caps.dast_inputs_available:
                    exec_ready = False
                    blocking.append("dast_crawl_endpoints_unavailable")
                    breakdown["missing_dast_inputs"] += 1

                overall = is_eligible and is_in_scope and is_compat and exec_ready

                if overall:
                    ready_count += 1
                elif is_eligible and is_in_scope and is_compat and not exec_ready:
                    compatible_not_ready += 1

                evaluated_templates.append(
                    TemplateReadinessStatus(
                        template_id=t.template_id,
                        eligible=is_eligible,
                        target_compatible=is_compat,
                        execution_ready=exec_ready,
                        in_scope=is_in_scope,
                        overall_ready=overall,
                        blocking_reasons=blocking,
                        required_execution={
                            "headless": t.requires_headless,
                            "interactsh": t.requires_interactsh,
                            "authentication": t.requires_authentication,
                            "required_variables": t.requires_variables,
                            "is_dast": is_dast_template,
                        },
                    )
                )

            return TargetReadinessEvaluation(
                repository_version_id=repository_version_id,
                target=clean_target,
                target_type=target_type,
                total_evaluated=len(evaluated_templates),
                ready_count=ready_count,
                compatible_but_not_ready_count=compatible_not_ready,
                incompatible_target_count=incompatible_target,
                ineligible_count=ineligible_count,
                out_of_scope_count=out_of_scope_count,
                readiness_breakdown=breakdown,
                templates=evaluated_templates,
            )
        finally:
            if owns:
                db.close()

    @staticmethod
    def _classify_target(target: str) -> Tuple[str, str]:
        """Returns (target_type, host_string). target_type is 'url', 'ip', or 'domain'."""
        t = target.strip()
        if t.startswith("http://") or t.startswith("https://"):
            parsed = urlparse(t)
            host = parsed.hostname or t
            return "url", host
        # Check IP
        try:
            ipaddress.ip_address(t)
            return "ip", t
        except ValueError:
            pass
        # Domain
        host = t.split(":")[0]  # strip port if present
        return "domain", host

    @staticmethod
    def _is_host_in_scope(host: str, authorized_scopes: List[str]) -> bool:
        """Check whether a host matches authorized scopes (exact or subdomain)."""
        host_low = host.lower()
        for scope in authorized_scopes:
            s_low = scope.lower().strip()
            if s_low.startswith("*."):
                suffix = s_low[2:]
                if host_low == suffix or host_low.endswith("." + suffix):
                    return True
            elif host_low == s_low:
                return True
        return False

    @staticmethod
    def _is_template_compatible_with_target(template: TemplateRecord, target_type: str) -> bool:
        """Determines if a template's protocols are compatible with the target format."""
        protos = set(template.protocols)
        if "code" in protos or "file" in protos:
            return False  # local audit only, not target-compatible
        if target_type == "url":
            # URLs can run http, headless, ssl (to host), dns (to host)
            return bool(protos & {"http", "headless", "ssl", "dns"})
        elif target_type == "ip":
            # Bare IPs cannot run DNS domain checks; can run network, ssl, http
            return bool(protos & {"network", "ssl", "http"})
        else:  # domain
            # Domains can run dns, ssl, http, headless, network
            return bool(protos & {"dns", "ssl", "http", "headless", "network"})

    # ------------------------------------------------------------------
    # Private: Build base query
    # ------------------------------------------------------------------

    def _build_base_query(
        self,
        repository_version_id: str,
        scan_mode: ScanMode,
        filters: TemplateFilter,
    ):
        """Construct the filtered SELECT query. Caller adds ORDER BY / LIMIT / OFFSET."""
        elig_col = (
            NucleiTemplate.sequential_eligible
            if scan_mode == ScanMode.SEQUENTIAL
            else NucleiTemplate.independent_eligible
        )

        conditions = [
            NucleiTemplate.repository_version_id == repository_version_id,
            elig_col == True,
        ]

        # Filter: template_ids (OR among values)
        if filters.template_ids:
            safe = [t for t in filters.template_ids if re.match(r'^[a-zA-Z0-9_\-./]+$', t)]
            if safe:
                conditions.append(NucleiTemplate.template_id.in_(safe))

        # Filter: name_search (ILIKE OR)
        if filters.name_search:
            name_conditions = [
                NucleiTemplate.name.ilike(f"%{term}%")
                for term in filters.name_search
            ]
            conditions.append(or_(*name_conditions))

        # Filter: CVE IDs (array containment OR — at least one CVE matches)
        if filters.cve_ids:
            cve_conds = [
                NucleiTemplate.cve_ids.contains([cve.upper()])
                for cve in filters.cve_ids
            ]
            conditions.append(or_(*cve_conds))

        # Filter: tags (OR within list — template must have at least one specified tag)
        if filters.tags:
            tag_norm = [t.strip().lower() for t in filters.tags if isinstance(t, str) and t.strip()]
            if tag_norm:
                tag_conds = [
                    NucleiTemplate.tags.contains([tag])
                    for tag in tag_norm
                ]
                conditions.append(or_(*tag_conds))

        # Filter: severities (OR)
        if filters.severities:
            sev_norm = [s.lower() for s in filters.severities]
            conditions.append(NucleiTemplate.severity.in_(sev_norm))

        # Filter: protocols (OR — template must have at least one matching protocol)
        if filters.protocols:
            proto_norm = [p.lower() for p in filters.protocols]
            proto_conds = [
                NucleiTemplate.protocols.contains([p])
                for p in proto_norm
            ]
            conditions.append(or_(*proto_conds))

        # Filter: execution requirements exclusions
        if filters.exclude_requires_headless:
            conditions.append(
                text("(policy_details->>'headless_requirement')::boolean IS NOT TRUE")
            )
        if filters.exclude_requires_interactsh:
            conditions.append(
                text("(policy_details->>'oast_requirement')::boolean IS NOT TRUE")
            )
        if filters.exclude_requires_authentication:
            conditions.append(
                text("(policy_details->>'authentication_requirements')::boolean IS NOT TRUE")
            )
        if filters.exclude_requires_variables:
            conditions.append(
                text("jsonb_array_length(COALESCE(policy_details->'required_variables', '[]'::jsonb)) = 0")
            )

        return select(NucleiTemplate).where(and_(*conditions))

    def _build_order_by(self, sort_by: SortField) -> list:
        """Build ORDER BY clause for deterministic ordering."""
        # Always secondary-sort by template_id for stability
        if sort_by == SortField.SEVERITY:
            # Severity: critical(0) → high(1) → medium(2) → low(3) → info(4) → unknown(5)
            return [
                text(
                    "CASE severity "
                    "WHEN 'critical' THEN 0 "
                    "WHEN 'high' THEN 1 "
                    "WHEN 'medium' THEN 2 "
                    "WHEN 'low' THEN 3 "
                    "WHEN 'info' THEN 4 "
                    "ELSE 5 END"
                ),
                NucleiTemplate.template_id,
            ]
        elif sort_by == SortField.TEMPLATE_ID:
            return [NucleiTemplate.template_id]
        elif sort_by == SortField.RELATIVE_PATH:
            return [NucleiTemplate.relative_path, NucleiTemplate.template_id]
        else:
            return [NucleiTemplate.template_id]

    def _filter_to_dict(self, f: TemplateFilter) -> Dict[str, Any]:
        return {
            "template_ids": f.template_ids,
            "name_search": f.name_search,
            "cve_ids": f.cve_ids,
            "tags": f.tags,
            "severities": f.severities,
            "protocols": f.protocols,
            "exclude_requires_headless": f.exclude_requires_headless,
            "exclude_requires_interactsh": f.exclude_requires_interactsh,
            "exclude_requires_authentication": f.exclude_requires_authentication,
            "exclude_requires_variables": f.exclude_requires_variables,
        }

    # ------------------------------------------------------------------
    # Private: Row → TemplateRecord
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_record(row: NucleiTemplate) -> TemplateRecord:
        """Convert a NucleiTemplate ORM row to a TemplateRecord dataclass."""
        meta = row.template_metadata or {}
        policy = row.policy_details or {}

        # Extract execution requirements from policy_details
        exec_reqs = policy.get("execution_requirements", {})
        requires_headless = bool(
            policy.get("headless_requirement")
            or exec_reqs.get("headless", False)
        )
        requires_interactsh = bool(
            policy.get("oast_requirement")
            or exec_reqs.get("interactsh", False)
        )
        requires_auth = bool(
            policy.get("authentication_requirements")
            or exec_reqs.get("authentication", False)
        )
        required_vars = (
            policy.get("required_variables")
            or exec_reqs.get("required_variables", [])
            or []
        )
        ev = policy.get("engine_validation") if isinstance(policy.get("engine_validation"), dict) else {}

        return TemplateRecord(
            id=str(row.id),
            template_id=row.template_id,
            name=row.name,
            description=row.description,
            severity=row.severity,
            tags=row.tags or [],
            protocols=row.protocols or [],
            cve_ids=row.cve_ids or [],
            cwe_ids=row.cwe_ids or [],
            relative_path=row.relative_path,
            content_hash=row.content_hash,
            security_status=row.security_status,
            sequential_eligible=row.sequential_eligible,
            independent_eligible=row.independent_eligible,
            author=meta.get("author"),
            cvss_score=meta.get("cvss_score"),
            cvss_vector=meta.get("cvss_vector"),
            references=meta.get("references") or [],
            remediation=meta.get("remediation"),
            eligibility_reasons=policy.get("eligibility_reasons") or [],
            requires_headless=requires_headless,
            requires_interactsh=requires_interactsh,
            requires_authentication=requires_auth,
            requires_variables=required_vars,
            official_exclusion_matches=policy.get("official_exclusion_matches") or [],
            policy_version=policy.get("policy_version", "unknown"),
            indexed_at=policy.get("indexed_at"),
            engine_validation_status=ev.get("status"),
            engine_validation_reason=ev.get("reason"),
        )


# ---------------------------------------------------------------------------
# Shared Data Contract — Independent Scan API
# ---------------------------------------------------------------------------
#
# This section defines the JSON schema for the Independent Scan UI integration.
# TypeScript interfaces and JSON examples are provided as documentation.
#
# IMPORTANT:
#  - version_id is always required; template selection is ALWAYS version-bound.
#  - staging versions are blocked; only "active" versions can be used in real scans.
#  - Ineligible templates CANNOT be selected; the server validates all IDs.
#  - select_all_matching selects the FULL filter result, not just the current page.
#  - Filter logic: OR within a single filter criterion (including tags); AND across criteria.
#  - nuclei_templates table strictly conforms to the approved 17-column schema;
#    indexing timestamp is stored in policy_details.indexed_at.
#
# --- TypeScript Contract ---
#
# interface TemplateFilterRequest {
#   version_id: string;             // Required: UUID of repository version
#   scan_mode: "sequential" | "independent";
#   template_ids?: string[];        // OR within list
#   name_search?: string[];         // OR: ILIKE match on name
#   cve_ids?: string[];             // OR: exact CVE-YYYY-NNNNN match
#   tags?: string[];                // OR: template has AT LEAST ONE specified tag
#   severities?: ("critical"|"high"|"medium"|"low"|"info"|"unknown")[];  // OR
#   protocols?: string[];           // OR
#   exclude_requires_headless?: boolean;
#   exclude_requires_interactsh?: boolean;
#   exclude_requires_authentication?: boolean;
#   exclude_requires_variables?: boolean;
#   page?: number;                  // 1-based, default=1
#   page_size?: number;             // default=50, max=500
#   sort_by?: "template_id"|"severity"|"relative_path";
# }
#
# interface TemplateQueryResponse {
#   version_id: string;
#   scan_mode: string;
#   total_count: number;
#   page: number;
#   page_size: number;
#   total_pages: number;
#   templates: TemplateRecord[];
#   filter_applied: TemplateFilterRequest;
# }
#
# interface TemplateRecord {
#   id: string;                     // UUID row identifier
#   template_id: string;            // e.g., "CVE-2021-44228"
#   name: string | null;
#   description: string | null;
#   severity: string;
#   tags: string[];
#   protocols: string[];
#   cve_ids: string[];
#   cwe_ids: string[];
#   relative_path: string;
#   content_hash: string;
#   security_status: "eligible" | "ineligible" | "conditional";
#   sequential_eligible: boolean;
#   independent_eligible: boolean;
#   author: string | null;
#   cvss_score: number | null;
#   cvss_vector: string | null;
#   references: string[];
#   remediation: string | null;
#   eligibility_reasons: string[];
#   requires_headless: boolean;
#   requires_interactsh: boolean;
#   requires_authentication: boolean;
#   requires_variables: string[];
#   official_exclusion_matches: string[];
#   policy_version: string;
#   indexed_at?: string | null;     // UTC ISO-8601 stored in policy_details JSONB
#   engine_validation_status?: "validated" | "rejected" | "pending" | null;
#   engine_validation_reason?: string | null;
# }
#
# interface ValidationRequest {
#   version_id: string;
#   template_ids: string[];
#   scan_mode: "sequential" | "independent";
# }
#
# interface ValidationResponse {
#   valid: boolean;
#   requested_count: number;
#   valid_count: number;
#   invalid_ids: string[];
#   ineligible_ids: string[];
#   eligible_ids: string[];
#   errors: string[];
# }
#
# --- JSON Example: Filter Request ---
# {
#   "version_id": "a1301c8a-e54e-4c6b-bd96-3b71d266d221",
#   "scan_mode": "independent",
#   "severities": ["critical", "high"],
#   "protocols": ["http"],
#   "tags": ["cve", "rce"],
#   "cve_ids": ["CVE-2021-44228"],
#   "page": 1,
#   "page_size": 50,
#   "sort_by": "severity"
# }
#
# --- Selection Validation Contract ---
# {
#   "version_id": "a1301c8a-e54e-4c6b-bd96-3b71d266d221",
#   "scan_mode": "independent",
#   "template_ids": ["CVE-2021-44228", "CVE-2022-22965"]
# }
#
# --- Available Filters Response ---
# {
#   "version_id": "a1301c8a-e54e-4c6b-bd96-3b71d266d221",
#   "severities": ["critical", "high", "medium", "low", "info", "unknown"],
#   "protocols": ["dns", "headless", "http", "javascript", "network", "ssl"],
#   "top_tags": ["cve", "exposure", "misconfig", "tech", "xss", ...],
#   "total_tags_count": 8438,
#   "has_cve_templates": true,
#   "total_eligible_sequential": 12113,
#   "total_eligible_independent": 12113
# }
