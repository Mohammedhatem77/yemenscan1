"""
YemScan — PostgreSQL Template Catalog Indexing Service (Phase 4).

Responsible for:
1. Receiving TemplateClassificationService output (ClassificationSummary).
2. Filtering executable templates from non-executable helpers and workflows.
3. Mapping classification results to PostgreSQL-optimized schema (UUID, ARRAY, JSONB).
4. Chunked bulk insertion in an atomic, all-or-nothing database transaction.
5. Idempotent re-indexing for staging versions; hard protection of published/active versions.
6. Recording policy version in template_repository_versions upon successful indexing.
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from sqlalchemy import delete, select, text, func
from sqlalchemy.orm import Session

from database import SessionLocal, engine
from models.template_repository import TemplateRepositoryVersion
from models.template_catalog import NucleiTemplate
from core.nuclei_repository_service import RepositoryLock
from core.nuclei_shared import NUCLEI_STORAGE_DIR
from core.template_classification_service import ClassificationSummary
from core.template_eligibility import (
    TemplateClassificationResult,
    RC_INVALID_TEMPLATE,
    RC_WORKFLOW_DEFERRED,
    STATUS_ELIGIBLE,
    STATUS_INELIGIBLE,
)

logger = logging.getLogger("yemenscan.template_catalog_indexer")

CHUNK_SIZE = 1000
NAMESPACE_YEMENSCAN = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")


class CatalogIndexingError(Exception):
    """Raised when catalog indexing fails or integrity constraints are violated."""
    pass


class PublishedVersionImmutableError(CatalogIndexingError):
    """Raised when an attempt is made to re-index or modify a published/active version."""
    pass


@dataclass
class IndexingSummary:
    """Aggregated output of a catalog indexing operation."""
    repository_version_id: str
    policy_version: str
    elapsed_seconds: float

    # Counts
    total_yaml_files: int
    total_executable_templates: int
    total_indexed: int
    total_workflows_omitted: int
    total_helpers_omitted: int

    # Eligibility counts among indexed templates
    sequential_eligible_count: int
    independent_eligible_count: int
    ineligible_count: int

    # Breakdown by severity among indexed
    by_severity: Dict[str, int]

    # Breakdown by protocol among indexed
    by_protocol: Dict[str, int]

    status: str                         # "success" | "failed"
    error_message: Optional[str] = None

    @property
    def invariant_holds(self) -> bool:
        """All YAML files accounted for: indexed + workflows + helpers == total_yaml_files."""
        return self.total_yaml_files == (
            self.total_indexed + self.total_workflows_omitted + self.total_helpers_omitted
        )


def _sanitize_pg_string(val: Any) -> Any:
    """Recursively strip NUL (0x00) bytes from strings/dicts/lists for PostgreSQL compatibility."""
    if isinstance(val, str):
        return val.replace("\x00", "")
    elif isinstance(val, dict):
        return {k: _sanitize_pg_string(v) for k, v in val.items()}
    elif isinstance(val, list):
        return [_sanitize_pg_string(x) for x in val]
    return val


class TemplateCatalogIndexer:
    """
    Coordinates loading classification results into PostgreSQL nuclei_templates table.

    Usage:
        indexer = TemplateCatalogIndexer()
        summary = indexer.index_classification_results(
            classification_summary=summary,
            session=optional_db_session,
        )
    """

    def __init__(self, chunk_size: int = CHUNK_SIZE):
        self.chunk_size = chunk_size

    def index_classification_results(
        self,
        classification_summary: ClassificationSummary,
        session: Optional[Session] = None,
    ) -> IndexingSummary:
        """
        Ingest classification results into PostgreSQL.
        Operates inside an atomic database transaction. Never re-reads YAML files.
        """
        repo_version_id = classification_summary.repository_version_id
        policy_version = classification_summary.policy_version

        logger.info(
            "[CatalogIndexer] Starting catalog indexing for version=%s policy=%s",
            repo_version_id, policy_version,
        )
        t_start = time.monotonic()

        # Enforce concurrency lock on storage
        with RepositoryLock(NUCLEI_STORAGE_DIR, stale_timeout_seconds=300):
            owns_session = session is None
            db: Session = session or SessionLocal()
            try:
                return self._execute_indexing(
                    db=db,
                    classification_summary=classification_summary,
                    t_start=t_start,
                )
            finally:
                if owns_session:
                    db.close()

    def _execute_indexing(
        self,
        db: Session,
        classification_summary: ClassificationSummary,
        t_start: float,
    ) -> IndexingSummary:
        repo_version_id = classification_summary.repository_version_id
        policy_version = classification_summary.policy_version

        # 1. Verify repository version status in DB
        version_rec = db.execute(
            select(TemplateRepositoryVersion).where(
                TemplateRepositoryVersion.id == repo_version_id
            )
        ).scalar_one_or_none()

        if not version_rec:
            raise CatalogIndexingError(
                f"Repository version '{repo_version_id}' not found in database."
            )

        if version_rec.status in ("active", "retained"):
            raise PublishedVersionImmutableError(
                f"Version '{repo_version_id}' is '{version_rec.status}' (published). "
                "Catalog records for published versions are immutable."
            )

        # 2. Separate executable templates from non-executable helpers & workflows
        executable_results: List[TemplateClassificationResult] = []
        workflows_omitted = 0
        helpers_omitted = 0

        for r in classification_summary.results:
            if r.metadata.is_workflow or RC_WORKFLOW_DEFERRED in r.eligibility_reasons:
                workflows_omitted += 1
            elif RC_INVALID_TEMPLATE in r.eligibility_reasons or not r.template_id:
                helpers_omitted += 1
            else:
                executable_results.append(r)

        total_executable = len(executable_results)
        logger.info(
            "[CatalogIndexer] Categorized: %d executable templates to index, "
            "%d workflows omitted, %d helpers/configs omitted (total %d files)",
            total_executable, workflows_omitted, helpers_omitted,
            classification_summary.total_yaml_files,
        )

        # 3. Transform to mapped records
        mapped_records: List[Dict[str, Any]] = []
        seq_eligible_count = 0
        ind_eligible_count = 0
        ineligible_count = 0
        by_severity: Dict[str, int] = {}
        by_protocol: Dict[str, int] = {}

        batch_indexed_at = datetime.now(timezone.utc).isoformat()
        for res in executable_results:
            record_dict = self._map_to_record_dict(repo_version_id, res, indexed_at=batch_indexed_at)
            mapped_records.append(record_dict)

            # Tally stats
            if res.sequential_eligible:
                seq_eligible_count += 1
            if res.independent_eligible:
                ind_eligible_count += 1
            if res.security_status == STATUS_INELIGIBLE:
                ineligible_count += 1

            sev = res.metadata.severity.lower()
            by_severity[sev] = by_severity.get(sev, 0) + 1

            for proto in res.protocols:
                by_protocol[proto] = by_protocol.get(proto, 0) + 1

        # 4. Atomic Database Transaction: Clean existing staged records, then bulk insert
        try:
            # Delete any previously staged records for this version (idempotent re-indexing)
            db.execute(
                delete(NucleiTemplate).where(
                    NucleiTemplate.repository_version_id == repo_version_id
                )
            )

            # Bulk insert in chunks
            total_records = len(mapped_records)
            for i in range(0, total_records, self.chunk_size):
                chunk = mapped_records[i : i + self.chunk_size]
                db.bulk_insert_mappings(NucleiTemplate, chunk)

            # Update repository version record with policy version
            version_rec.policy_version = policy_version
            db.commit()
            logger.info(
                "[CatalogIndexer] Successfully committed %d templates to database.",
                total_records,
            )

        except Exception as exc:
            db.rollback()
            logger.error("[CatalogIndexer] Database transaction failed: %s", exc)
            raise CatalogIndexingError(f"Database insertion failed: {exc}") from exc

        elapsed = time.monotonic() - t_start

        return IndexingSummary(
            repository_version_id=repo_version_id,
            policy_version=policy_version,
            elapsed_seconds=round(elapsed, 2),
            total_yaml_files=classification_summary.total_yaml_files,
            total_executable_templates=total_executable,
            total_indexed=len(mapped_records),
            total_workflows_omitted=workflows_omitted,
            total_helpers_omitted=helpers_omitted,
            sequential_eligible_count=seq_eligible_count,
            independent_eligible_count=ind_eligible_count,
            ineligible_count=ineligible_count,
            by_severity=dict(sorted(by_severity.items())),
            by_protocol=dict(sorted(by_protocol.items())),
            status="success",
            error_message=None,
        )

    # ------------------------------------------------------------------
    # Mapping helper
    # ------------------------------------------------------------------

    def _map_to_record_dict(
        self,
        repo_version_id: str,
        res: TemplateClassificationResult,
        indexed_at: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Maps a TemplateClassificationResult into a dict matching NucleiTemplate columns."""
        meta = res.metadata

        # Deterministic UUIDv5 based on repo_version and relative_path
        row_id = uuid.uuid5(
            NAMESPACE_YEMENSCAN,
            f"{repo_version_id}:{res.relative_path}",
        )

        # Categorize top-level directory
        path_parts = res.relative_path.replace("\\", "/").split("/")
        top_category = path_parts[0] if len(path_parts) > 1 else "root"

        # Build metadata JSONB
        meta_sub = meta._raw_info.get("metadata") if isinstance(meta._raw_info.get("metadata"), dict) else {}
        product = meta_sub.get("product") or meta._raw_info.get("product")
        vendor = meta_sub.get("vendor") or meta._raw_info.get("vendor")
        epss = meta_sub.get("epss_score") or meta_sub.get("epss-score") or meta._raw_info.get("epss_score")

        metadata_dict = {
            "author": meta.author,
            "product": product,
            "vendor": vendor,
            "cvss_score": meta.cvss_score,
            "cvss_vector": meta.cvss_vector,
            "epss": epss,
            "references": meta.reference,
            "remediation": meta.remediation,
            "category": top_category,
            "verified": meta.verified,
            "max_request": meta.max_request,
            "shodan_query": meta.shodan_query,
            "fofa_query": meta.fofa_query,
            "google_dork": meta.google_dork,
            "original_metadata": meta._raw_info,
        }

        # Build policy_details JSONB
        primary_reason = res.eligibility_reasons[0] if res.eligibility_reasons else None
        policy_details_dict = {
            "policy_version": res.policy_version,
            "web_relevance": res.web_relevant,
            "eligibility_reasons": res.eligibility_reasons,
            "primary_reason": primary_reason,
            "official_exclusion_matches": [res.exclusion_rule] if res.exclusion_rule else [],
            "execution_requirements": res.execution_requirements,
            "required_dependencies": res.execution_requirements.get("dependencies", []),
            "authentication_requirements": res.execution_requirements.get("authentication", False),
            "headless_requirement": res.execution_requirements.get("headless", False),
            "oast_requirement": res.execution_requirements.get("interactsh", False),
            "required_variables": res.execution_requirements.get("required_variables", []),
            "rule_identifiers": [res.exclusion_rule] if res.exclusion_rule else [],
            "indexed_at": indexed_at or datetime.now(timezone.utc).isoformat(),
        }

        cve_list = [meta.cve_id] if meta.cve_id else []

        name_str = meta.name or res.template_id
        return {
            "id": row_id,
            "repository_version_id": repo_version_id,
            "template_id": res.template_id,
            "name": _sanitize_pg_string(name_str),
            "description": _sanitize_pg_string(meta.description),
            "severity": meta.severity.lower(),
            "tags": _sanitize_pg_string(list(meta.tags)),
            "protocols": _sanitize_pg_string(list(res.protocols)),
            "cve_ids": _sanitize_pg_string(cve_list),
            "cwe_ids": _sanitize_pg_string(list(meta.cwe_ids)),
            "relative_path": res.relative_path,
            "content_hash": res.content_hash,
            "security_status": res.security_status,
            "sequential_eligible": res.sequential_eligible,
            "independent_eligible": res.independent_eligible,
            "metadata": _sanitize_pg_string(metadata_dict),
            "policy_details": _sanitize_pg_string(policy_details_dict),
        }
