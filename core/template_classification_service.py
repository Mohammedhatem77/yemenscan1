"""
YemScan — Template Classification Service (Phase 2 & 3).

Responsibility:
  Coordinates the full pipeline:
    TemplateParser → MetadataExtractor → EligibilityClassifier

  Processes all YAML files in a snapshot exactly once per call and returns
  a ClassificationSummary with per-template TemplateClassificationResult records.

Design rules:
  - Each YAML file is read exactly once per process_snapshot() call.
  - publish_version() is NEVER called here (Phase 1 service handles versioning).
  - Classification does NOT grant 'active' status to the repository version.
  - No templates are executed against external targets.
  - Output is deterministic: same (repo_version + policy_version) → same results.
  - Progress logging every 1000 files to avoid silent hangs on large repos.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from core.template_parser import TemplateParser
from core.template_metadata import MetadataExtractor
from core.template_eligibility import (
    ClassificationPolicy,
    EligibilityClassifier,
    IgnoreRuleSet,
    TemplateClassificationResult,
    STATUS_ELIGIBLE,
    STATUS_INELIGIBLE,
    STATUS_CONDITIONAL,
    RC_OFFICIAL_IGNORE,
    RC_UNSUPPORTED_PROTOCOL,
    RC_OUTSIDE_WEB_SCOPE,
    RC_UNRESOLVED,
    RC_UNSAFE_BEHAVIOR,
    RC_DAST_AI_UNRESOLVED,
    RC_INVALID_TEMPLATE,
    RC_WORKFLOW_DEFERRED,
    RC_ELIGIBLE,
)
from core.nuclei_shared import NUCLEI_VERSIONS_DIR

logger = logging.getLogger("yemenscan.template_classification_service")

NUCLEI_IGNORE_FILENAME = ".nuclei-ignore"


# ---------------------------------------------------------------------------
# Summary dataclass
# ---------------------------------------------------------------------------

@dataclass
class ClassificationSummary:
    """
    Aggregated output of a full snapshot classification run.
    """
    repository_version_id: str
    policy_version: str
    snapshot_path: str

    # Timing
    elapsed_seconds: float

    # Counts
    total_yaml_files: int
    total_processed: int            # successfully parsed
    total_parse_errors: int         # YAML / IO failures
    total_eligible: int
    total_ineligible: int
    total_conditional: int          # reserved; currently unused (resolved to eligible/ineligible)

    # Breakdown by reason code
    by_reason: Dict[str, int]       # {reason_code: count}

    # Breakdown by protocol
    by_protocol: Dict[str, int]     # {protocol: count of templates with this protocol}

    # Breakdown by ineligibility cause
    by_status: Dict[str, int]       # {"eligible": N, "ineligible": N, "conditional": N}

    # Per-template results
    results: List[TemplateClassificationResult]

    # Any service-level errors (not per-template)
    service_errors: List[str]

    @property
    def invariant_holds(self) -> bool:
        """
        total_yaml_files == total_eligible + total_ineligible (+ total_conditional).

        Note: parse_errors are INCLUDED in total_ineligible (they are classified as
        ineligible with reason invalid_template). The invariant therefore is:
            total_yaml_files == total_processed
            total_processed  == total_eligible + total_ineligible + total_conditional
        """
        return (
            self.total_yaml_files == self.total_processed
            and self.total_processed == (
                self.total_eligible + self.total_ineligible + self.total_conditional
            )
        )


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

class TemplateClassificationService:
    """
    Orchestrates Template Parser → Metadata Extractor → Eligibility Classifier
    for all YAML files in a snapshot.

    Usage:
        service = TemplateClassificationService()
        summary = service.process_snapshot(
            repository_version_id="a1301c8a-...",
            snapshot_path="/absolute/path/to/snapshot/",   # optional — resolved from DB if omitted
        )
    """

    def __init__(
        self,
        policy: Optional[ClassificationPolicy] = None,
    ):
        self.policy = policy or ClassificationPolicy.v1_2()
        self._parser = TemplateParser()
        self._extractor = MetadataExtractor()
        self._classifier = EligibilityClassifier(self.policy)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def process_snapshot(
        self,
        repository_version_id: str,
        snapshot_path: Optional[str] = None,
    ) -> ClassificationSummary:
        """
        Classify every YAML template file in the snapshot.

        Args:
            repository_version_id: UUID of the TemplateRepositoryVersion (staging).
            snapshot_path:         Absolute path to the snapshot directory.
                                   If None, resolved from NUCLEI_VERSIONS_DIR/<uuid>.

        Returns:
            ClassificationSummary — full statistics and per-template results.

        Raises:
            ValueError:  if snapshot_path cannot be resolved or does not exist.
        """
        # Resolve snapshot path
        if not snapshot_path:
            snapshot_path = os.path.join(NUCLEI_VERSIONS_DIR, repository_version_id)
        snapshot_path = os.path.abspath(snapshot_path)

        if not os.path.isdir(snapshot_path):
            raise ValueError(
                f"Snapshot directory not found: '{snapshot_path}' "
                f"(version_id={repository_version_id})"
            )

        logger.info(
            "[ClassificationService] Starting classification of version=%s path='%s' policy=%s",
            repository_version_id, snapshot_path, self.policy.policy_version,
        )

        t_start = time.monotonic()
        service_errors: List[str] = []

        # 1. Load .nuclei-ignore from snapshot root
        ignore_path = os.path.join(snapshot_path, NUCLEI_IGNORE_FILENAME)
        ignore_ruleset = IgnoreRuleSet.from_file(ignore_path)
        logger.info(
            "[ClassificationService] Loaded ignore rules: %d tag exclusions, %d file exclusions",
            len(ignore_ruleset.excluded_tags),
            len(ignore_ruleset.excluded_files),
        )

        # 2. Walk snapshot and classify
        results: List[TemplateClassificationResult] = []
        total_yaml_files = 0
        total_processed = 0
        total_parse_errors = 0
        total_eligible = 0
        total_ineligible = 0
        total_conditional = 0

        by_reason: Dict[str, int] = {}
        by_protocol: Dict[str, int] = {}
        by_status: Dict[str, int] = {
            STATUS_ELIGIBLE: 0,
            STATUS_INELIGIBLE: 0,
            STATUS_CONDITIONAL: 0,
        }

        for yaml_path in self._parser.walk_snapshot(snapshot_path):
            total_yaml_files += 1

            if total_yaml_files % 1000 == 0:
                logger.info(
                    "[ClassificationService] Progress: %d files processed...",
                    total_yaml_files,
                )

            # Parse
            parse_result = self._parser.parse_file(yaml_path, snapshot_path)

            if parse_result.parse_errors:
                total_parse_errors += 1

            # Extract metadata
            metadata = self._extractor.extract(parse_result)

            # Classify
            result = self._classifier.classify(
                metadata=metadata,
                ignore_ruleset=ignore_ruleset,
                repository_version_id=repository_version_id,
                raw_yaml_text=parse_result.raw_yaml_text,
                parse_errors=parse_result.parse_errors if parse_result.parse_errors else None,
            )
            results.append(result)
            total_processed += 1

            # Tally status
            status = result.security_status
            by_status[status] = by_status.get(status, 0) + 1
            if status == STATUS_ELIGIBLE:
                total_eligible += 1
            elif status == STATUS_INELIGIBLE:
                total_ineligible += 1
            else:
                total_conditional += 1

            # Tally reason codes
            for rc in result.eligibility_reasons:
                by_reason[rc] = by_reason.get(rc, 0) + 1

            # Tally protocols
            for proto in result.protocols:
                by_protocol[proto] = by_protocol.get(proto, 0) + 1

        elapsed = time.monotonic() - t_start

        summary = ClassificationSummary(
            repository_version_id=repository_version_id,
            policy_version=self.policy.policy_version,
            snapshot_path=snapshot_path,
            elapsed_seconds=round(elapsed, 2),
            total_yaml_files=total_yaml_files,
            total_processed=total_processed,
            total_parse_errors=total_parse_errors,
            total_eligible=total_eligible,
            total_ineligible=total_ineligible,
            total_conditional=total_conditional,
            by_reason=dict(sorted(by_reason.items())),
            by_protocol=dict(sorted(by_protocol.items())),
            by_status=by_status,
            results=results,
            service_errors=service_errors,
        )

        logger.info(
            "[ClassificationService] Done: %d files, %d eligible, %d ineligible, "
            "%d parse_errors in %.1fs",
            total_yaml_files, total_eligible, total_ineligible,
            total_parse_errors, elapsed,
        )

        return summary

    def get_eligible_paths(self, summary: ClassificationSummary) -> List[str]:
        """Return sorted list of relative paths for eligible templates."""
        return sorted(
            r.relative_path
            for r in summary.results
            if r.sequential_eligible
        )

    def export_summary_dict(self, summary: ClassificationSummary) -> Dict[str, Any]:
        """
        Return a JSON-serialisable summary dict (without per-template details).
        Suitable for logging, reporting, or storing in DB.
        """
        return {
            "repository_version_id": summary.repository_version_id,
            "policy_version": summary.policy_version,
            "snapshot_path": summary.snapshot_path,
            "elapsed_seconds": summary.elapsed_seconds,
            "total_yaml_files": summary.total_yaml_files,
            "total_processed": summary.total_processed,
            "total_parse_errors": summary.total_parse_errors,
            "total_eligible": summary.total_eligible,
            "total_ineligible": summary.total_ineligible,
            "total_conditional": summary.total_conditional,
            "invariant_holds": summary.invariant_holds,
            "by_reason": summary.by_reason,
            "by_protocol": summary.by_protocol,
            "by_status": summary.by_status,
            "service_errors": summary.service_errors,
        }
