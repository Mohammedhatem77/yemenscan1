"""
YemScan — Phase 7.1: Nuclei Engine Validation Service.

Validates all policy-eligible Nuclei templates against the pinned official
Nuclei engine inside an isolated Docker container (--network none, no scan
targets) using the engine's official `-tl` (template listing) and `-validate`
mechanisms.

Key Design Guarantees:
  1. Preserves the approved 17-column `nuclei_templates` schema (no DDL changes
     and no parallel catalog table): persists structured `engine_validation`
     records inside `nuclei_templates.policy_details["engine_validation"]`.
  2. Never modifies original immutable snapshot files on disk; verifies
     cryptographic snapshot integrity before validation and respects
     `RepositoryLock`.
  3. Never accepts batch/folder validation blindly: verifies every template
     against `-tl` inclusion and isolates failures via recursive binary
     bisection down to exact template-level engine errors.
  4. Distinguishes engine template rejections (`rejected`) from environment or
     container runtime failures (`pending`), supporting safe atomic batch
     commits and resumable runs (`resume=True`).
  5. Enforces the mathematical invariant:
         policy_eligible == validated + rejected + pending
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import tarfile
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Protocol, Sequence, Set, Tuple

from sqlalchemy import select
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from database import SessionLocal
from models.template_catalog import NucleiTemplate
from models.template_repository import TemplateRepositoryVersion
from core.nuclei_repository_service import (
    RepositoryLock,
    SnapshotIntegrityError,
    VersionNotFoundError,
    VersionStateError,
    get_version,
    verify_snapshot_integrity,
)
from core.nuclei_shared import (
    NUCLEI_DOCKER_IMAGE,
    NUCLEI_ENGINE_DIGEST,
    NUCLEI_ENGINE_VERSION,
    NUCLEI_STORAGE_DIR,
)
from core.runner import get_docker_cmd, get_docker_volume_path

logger = logging.getLogger("yemenscan.template_engine_validator")

# Validation status constants
VALIDATION_STATUS_VALIDATED = "validated"
VALIDATION_STATUS_REJECTED = "rejected"
VALIDATION_STATUS_PENDING = "pending"
VALID_VALIDATION_STATUSES = {
    VALIDATION_STATUS_VALIDATED,
    VALIDATION_STATUS_REJECTED,
    VALIDATION_STATUS_PENDING,
}

# Error category constants
ERR_CAT_NONE = None
ERR_CAT_ENGINE_VALIDATION = "engine_validation_error"
ERR_CAT_TL_OMITTED = "tl_omitted"
ERR_CAT_OFFICIAL_IGNORE = "official_ignore_mismatch"
ERR_CAT_ENVIRONMENT = "environment_error"
ERR_CAT_NOT_YET_VALIDATED = "not_yet_validated"

DEFAULT_BATCH_SIZE = 500
DEFAULT_BATCH_TIMEOUT_SECONDS = 240
NUCLEI_IGNORE_FILENAME = ".nuclei-ignore"
CONTAINER_TEMPLATES_DIR = "/root/nuclei-templates"
CONTAINER_CONFIG_DIR = "/root/.config/nuclei"

# ANSI escape sequence cleaner just in case
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_TL_SECTION_RE = re.compile(r"===TL_START===(.*?)===TL_END:(-?\d+)===", re.DOTALL)
_VAL_MARKER_RE = re.compile(r"===VAL_START===(.*?)===VAL_END:(-?\d+)===", re.DOTALL)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class EngineValidationError(Exception):
    """Base error for Phase 7.1 Nuclei engine validation."""


class PublishedVersionImmutableError(EngineValidationError):
    """Raised when attempting to mutate validation state of an active/retained version."""


class DockerEnvironmentError(EngineValidationError):
    """Raised when Docker execution fails due to environment/infra problems."""


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class BatchTarget:
    """Minimal immutable descriptor of a cataloged eligible template for batching."""
    row_id: str
    template_id: str
    relative_path: str
    content_hash: str
    protocols: List[str]
    policy_version: str


@dataclass
class EngineBatchResult:
    """Raw structured result returned by an engine executor for a batch of templates."""
    listed_paths: Set[str]
    validate_exit_code: int
    tl_exit_code: int
    validated_ok: bool
    stderr: str
    stdout: str
    is_environment_error: bool = False
    environment_error_reason: Optional[str] = None
    elapsed_seconds: float = 0.0


@dataclass
class TemplateValidationOutcome:
    """Validation outcome for a single catalog template row."""
    row_id: str
    template_id: str
    relative_path: str
    content_hash: str
    protocols: List[str]
    status: str  # validated | rejected | pending
    engine_included: bool
    error_category: Optional[str] = None
    reason: Optional[str] = None
    validated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class EngineValidationSummary:
    """Aggregated report for a Phase 7.1 engine validation run."""
    repository_version_id: str
    upstream_version: str
    upstream_commit: str
    policy_version: str
    engine_version: str
    engine_image: str
    engine_image_digest: str
    resumed: bool
    interrupted: bool
    elapsed_seconds: float

    total_indexed: int
    total_policy_eligible: int
    validated_count: int
    rejected_count: int
    pending_count: int

    batches_total: int
    batches_completed: int
    bisect_calls: int

    by_protocol: Dict[str, Dict[str, int]] = field(default_factory=dict)
    rejected_templates: List[Dict[str, Any]] = field(default_factory=list)
    pending_templates: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def equation_holds(self) -> bool:
        """Verify invariant: policy_eligible == validated + rejected + pending."""
        return self.total_policy_eligible == (
            self.validated_count + self.rejected_count + self.pending_count
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "repository_version_id": self.repository_version_id,
            "upstream_version": self.upstream_version,
            "upstream_commit": self.upstream_commit,
            "policy_version": self.policy_version,
            "engine_version": self.engine_version,
            "engine_image": self.engine_image,
            "engine_image_digest": self.engine_image_digest,
            "resumed": self.resumed,
            "interrupted": self.interrupted,
            "elapsed_seconds": round(self.elapsed_seconds, 3),
            "total_indexed": self.total_indexed,
            "total_policy_eligible": self.total_policy_eligible,
            "validated_count": self.validated_count,
            "rejected_count": self.rejected_count,
            "pending_count": self.pending_count,
            "equation_holds": self.equation_holds,
            "batches_total": self.batches_total,
            "batches_completed": self.batches_completed,
            "bisect_calls": self.bisect_calls,
            "by_protocol": self.by_protocol,
            "rejected_templates": self.rejected_templates,
            "pending_templates": self.pending_templates,
        }


# ---------------------------------------------------------------------------
# Engine Executor Interface & Docker Implementation
# ---------------------------------------------------------------------------

class EngineBatchExecutor(Protocol):
    """Protocol for executing `-tl` + `-validate` against a batch of templates."""

    def check_ready(self) -> Tuple[bool, Optional[str]]:
        """Check if the execution backend is ready."""
        ...

    def run_batch(
        self,
        snapshot_dir: str,
        targets: Sequence[BatchTarget],
        include_ignore: bool = True,
        timeout_seconds: int = DEFAULT_BATCH_TIMEOUT_SECONDS,
    ) -> EngineBatchResult:
        """Execute `-tl` and `-validate` over `targets` inside an isolated engine."""
        ...


def normalize_template_path(raw_path: str) -> str:
    """Normalize a Nuclei template path into snapshot-relative forward-slash format."""
    cleaned = _ANSI_RE.sub("", raw_path).strip().replace("\\", "/")
    if cleaned.startswith(CONTAINER_TEMPLATES_DIR + "/"):
        cleaned = cleaned[len(CONTAINER_TEMPLATES_DIR) + 1:]
    elif cleaned.startswith("./"):
        cleaned = cleaned[2:]
    return cleaned.lstrip("/")


def _extract_engine_error_reason(stderr: str, max_len: int = 1000) -> str:
    """Extract concise meaningful error lines from Nuclei validation stderr."""
    clean_err = _ANSI_RE.sub("", stderr or "")
    relevant: List[str] = []
    for raw_line in clean_err.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith(("[ERR]", "[FTL]", "Error ", "cause=")) or "Error occurred" in line:
            relevant.append(line)

    if not relevant:
        tail = [ln.strip() for ln in clean_err.splitlines() if ln.strip()][-5:]
        relevant = tail

    joined = " | ".join(relevant) if relevant else "Unknown validation error (empty stderr)"
    if len(joined) > max_len:
        return joined[: max_len - 3] + "..."
    return joined


def _looks_like_environment_stderr(stderr: str) -> bool:
    """Detect Docker daemon, container mount, tar, or engine runner startup errors."""
    low = (stderr or "").lower()
    env_markers = (
        "cannot connect to the docker daemon",
        "error during connect",
        "docker daemon is not running",
        "unable to find image",
        "no such image",
        "oci runtime",
        "executable file not found",
        "permission denied",
        "no space left on device",
        "could not create runner",
        "read-only file system",
    )
    return any(m in low for m in env_markers)


class DockerNucleiExecutor:
    """
    Executes isolated batch validation using the pinned official Nuclei
    Docker container with `--network none` and temporary tar staging.

    Why tar staging inside `--rm --network none`:
      On Windows Docker Desktop, opening thousands of small YAML files across a
      host bind mount causes severe per-file syscall overhead (~40s for 100 files).
      Packing only the batch's files into a single tar inside a temp directory
      mounted read-only at `/in:ro` and extracting inside the container brings
      1,000-template `-tl` + `-validate` batches under 50s while keeping the
      original snapshot directory 100% untouched on disk.
    """

    def __init__(
        self,
        docker_image: str = NUCLEI_DOCKER_IMAGE,
        timeout_seconds: int = DEFAULT_BATCH_TIMEOUT_SECONDS,
    ) -> None:
        self.docker_image = docker_image
        self.default_timeout_seconds = timeout_seconds

    def check_ready(self) -> Tuple[bool, Optional[str]]:
        docker_cmd = get_docker_cmd()
        try:
            proc = subprocess.run(
                [docker_cmd, "image", "inspect", self.docker_image],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=20.0,
            )
            if proc.returncode != 0:
                err = (proc.stderr or "").strip() or f"exit code {proc.returncode}"
                return False, f"Pinned Nuclei Docker image unavailable ({self.docker_image}): {err}"
            return True, None
        except Exception as exc:
            return False, f"Docker daemon or CLI is unavailable: {exc}"

    def _build_batch_tar(
        self,
        snapshot_dir: str,
        targets: Sequence[BatchTarget],
        tar_path: str,
        include_ignore: bool,
    ) -> None:
        needs_helpers = False
        with tarfile.open(tar_path, "w") as tf:
            for t in targets:
                rel_unix = t.relative_path.replace("\\", "/").lstrip("/")
                abs_file = os.path.join(snapshot_dir, t.relative_path)
                if not os.path.isfile(abs_file):
                    raise FileNotFoundError(f"Snapshot template file missing: {abs_file}")
                if not needs_helpers:
                    try:
                        with open(abs_file, "r", encoding="utf-8", errors="replace") as fh:
                            if "helpers/" in fh.read():
                                needs_helpers = True
                    except OSError:
                        pass
                tf.add(abs_file, arcname=rel_unix, recursive=False)

            if include_ignore:
                ignore_file = os.path.join(snapshot_dir, NUCLEI_IGNORE_FILENAME)
                if os.path.isfile(ignore_file):
                    tf.add(ignore_file, arcname=NUCLEI_IGNORE_FILENAME, recursive=False)

            if needs_helpers:
                helpers_dir = os.path.join(snapshot_dir, "helpers")
                if os.path.isdir(helpers_dir):
                    tf.add(helpers_dir, arcname="helpers", recursive=True)

    def run_batch(
        self,
        snapshot_dir: str,
        targets: Sequence[BatchTarget],
        include_ignore: bool = True,
        timeout_seconds: Optional[int] = None,
    ) -> EngineBatchResult:
        t0 = time.monotonic()
        effective_timeout = timeout_seconds or self.default_timeout_seconds
        docker_cmd = get_docker_cmd()

        try:
            with tempfile.TemporaryDirectory(prefix="yemenscan_nuc_val_") as tmp_dir:
                tar_path = os.path.join(tmp_dir, "batch.tar")
                self._build_batch_tar(snapshot_dir, targets, tar_path, include_ignore)
                vol_spec = f"{get_docker_volume_path(tmp_dir)}:/in:ro"

                container_script = (
                    f"mkdir -p {CONTAINER_TEMPLATES_DIR} {CONTAINER_CONFIG_DIR} || exit 90; "
                    f"tar -xf /in/batch.tar -C {CONTAINER_TEMPLATES_DIR} || exit 90; "
                    f"if [ -f {CONTAINER_TEMPLATES_DIR}/{NUCLEI_IGNORE_FILENAME} ]; then "
                    f"mv {CONTAINER_TEMPLATES_DIR}/{NUCLEI_IGNORE_FILENAME} {CONTAINER_CONFIG_DIR}/{NUCLEI_IGNORE_FILENAME} || exit 91; "
                    "fi; "
                    'echo "===TL_START==="; '
                    f"nuclei -no-stdin -duc -nc -tl -t {CONTAINER_TEMPLATES_DIR}; "
                    "TL_RC=$?; "
                    'echo "===TL_END:${TL_RC}==="; '
                    'echo "===VAL_START==="; '
                    f"nuclei -no-stdin -duc -nc -validate -t {CONTAINER_TEMPLATES_DIR}; "
                    "VAL_RC=$?; "
                    'echo "===VAL_END:${VAL_RC}==="; '
                    'if [ "$VAL_RC" -ne 0 ]; then exit "$VAL_RC"; fi; '
                    'exit "$TL_RC"'
                )

                cmd = [
                    docker_cmd,
                    "run",
                    "--rm",
                    "--network",
                    "none",
                    "-v",
                    vol_spec,
                    "--entrypoint",
                    "sh",
                    self.docker_image,
                    "-c",
                    container_script,
                ]

                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=effective_timeout,
                )
        except subprocess.TimeoutExpired as exc:
            elapsed = time.monotonic() - t0
            return EngineBatchResult(
                listed_paths=set(),
                validate_exit_code=-1,
                tl_exit_code=-1,
                validated_ok=False,
                stderr=str(exc),
                stdout="",
                is_environment_error=True,
                environment_error_reason=f"Docker validation batch timed out after {effective_timeout}s",
                elapsed_seconds=elapsed,
            )
        except (OSError, FileNotFoundError) as exc:
            elapsed = time.monotonic() - t0
            return EngineBatchResult(
                listed_paths=set(),
                validate_exit_code=-1,
                tl_exit_code=-1,
                validated_ok=False,
                stderr=str(exc),
                stdout="",
                is_environment_error=True,
                environment_error_reason=f"Docker execution error: {exc}",
                elapsed_seconds=elapsed,
            )

        elapsed = time.monotonic() - t0
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""

        tl_match = _TL_SECTION_RE.search(stdout)
        val_match = _VAL_MARKER_RE.search(stdout)

        # Missing markers or container/tar/Docker exit codes => infra error
        if proc.returncode in (90, 91, 125, 126, 127) or tl_match is None or val_match is None:
            reason = _extract_engine_error_reason(stderr)
            return EngineBatchResult(
                listed_paths=set(),
                validate_exit_code=proc.returncode,
                tl_exit_code=proc.returncode,
                validated_ok=False,
                stderr=stderr,
                stdout=stdout,
                is_environment_error=True,
                environment_error_reason=f"Container runtime failure (exit {proc.returncode}): {reason}",
                elapsed_seconds=elapsed,
            )

        tl_body = tl_match.group(1)
        tl_rc = int(tl_match.group(2))
        val_rc = int(val_match.group(2))

        if _looks_like_environment_stderr(stderr):
            return EngineBatchResult(
                listed_paths=set(),
                validate_exit_code=val_rc,
                tl_exit_code=tl_rc,
                validated_ok=False,
                stderr=stderr,
                stdout=stdout,
                is_environment_error=True,
                environment_error_reason=_extract_engine_error_reason(stderr),
                elapsed_seconds=elapsed,
            )

        listed_paths: Set[str] = set()
        for raw_line in tl_body.splitlines():
            norm = normalize_template_path(raw_line)
            if norm.lower().endswith((".yaml", ".yml")):
                listed_paths.add(norm)

        validated_ok = (val_rc == 0) and ("all templates validated successfully" in stderr.lower())
        return EngineBatchResult(
            listed_paths=listed_paths,
            validate_exit_code=val_rc,
            tl_exit_code=tl_rc,
            validated_ok=validated_ok,
            stderr=stderr,
            stdout=stdout,
            is_environment_error=False,
            environment_error_reason=None,
            elapsed_seconds=elapsed,
        )


# ---------------------------------------------------------------------------
# Validator Orchestrator
# ---------------------------------------------------------------------------

class NucleiEngineValidator:
    """
    Phase 7.1 Service: Validates all policy-eligible templates in PostgreSQL
    using the pinned Nuclei Docker engine and persists per-template statuses.
    """

    def __init__(
        self,
        session: Optional[Session] = None,
        executor: Optional[EngineBatchExecutor] = None,
        engine_version: str = NUCLEI_ENGINE_VERSION,
        engine_image: str = NUCLEI_DOCKER_IMAGE,
        engine_image_digest: str = NUCLEI_ENGINE_DIGEST,
        use_lock: bool = True,
        lock_dir: str = NUCLEI_STORAGE_DIR,
    ) -> None:
        self._external_session = session
        self.executor: EngineBatchExecutor = executor or DockerNucleiExecutor(
            docker_image=engine_image
        )
        self.engine_version = engine_version
        self.engine_image = engine_image
        self.engine_image_digest = engine_image_digest
        self.use_lock = use_lock
        self.lock_dir = lock_dir

    def _get_session(self) -> Tuple[Session, bool]:
        if self._external_session is not None:
            return self._external_session, False
        return SessionLocal(), True

    def _record_matches_current_run(
        self,
        existing: Any,
        version_id: str,
        target: BatchTarget,
    ) -> bool:
        if not isinstance(existing, dict):
            return False
        return (
            existing.get("status") in (VALIDATION_STATUS_VALIDATED, VALIDATION_STATUS_REJECTED)
            and existing.get("repository_version_id") == version_id
            and existing.get("template_hash") == target.content_hash
            and existing.get("policy_version") == target.policy_version
            and existing.get("engine_version") == self.engine_version
            and existing.get("engine_image_digest") == self.engine_image_digest
        )

    def _build_policy_payload(
        self,
        version_id: str,
        target: BatchTarget,
        outcome: TemplateValidationOutcome,
    ) -> Dict[str, Any]:
        return {
            "status": outcome.status,
            "repository_version_id": version_id,
            "template_hash": target.content_hash,
            "policy_version": target.policy_version,
            "engine_version": self.engine_version,
            "engine_image": self.engine_image,
            "engine_image_digest": self.engine_image_digest,
            "engine_included": outcome.engine_included,
            "validate_command": "nuclei -no-stdin -duc -nc -validate",
            "error_category": outcome.error_category,
            "reason": outcome.reason,
            "validated_at": outcome.validated_at,
        }

    def _persist_outcomes(
        self,
        db: Session,
        version_id: str,
        outcomes: Sequence[TemplateValidationOutcome],
        targets_by_id: Dict[str, BatchTarget],
    ) -> None:
        if not outcomes:
            return

        row_ids = [o.row_id for o in outcomes]
        rows = db.execute(
            select(NucleiTemplate).where(
                NucleiTemplate.repository_version_id == version_id,
                NucleiTemplate.id.in_(row_ids),
            )
        ).scalars().all()
        rows_by_id = {str(r.id): r for r in rows}

        for outcome in outcomes:
            row = rows_by_id.get(outcome.row_id)
            if row is None:
                continue
            target = targets_by_id[outcome.row_id]
            new_policy = dict(row.policy_details or {})
            new_policy["engine_validation"] = self._build_policy_payload(
                version_id=version_id,
                target=target,
                outcome=outcome,
            )
            row.policy_details = new_policy
            flag_modified(row, "policy_details")

        db.commit()

    def _verify_single_omitted(
        self,
        snapshot_dir: str,
        target: BatchTarget,
        batch_result: EngineBatchResult,
    ) -> TemplateValidationOutcome:
        """
        Inspect why `-tl` omitted a single template during a batch run.
        Never assumes validation passed when `-tl` omitted the path.
        """
        single_res = self.executor.run_batch(
            snapshot_dir=snapshot_dir,
            targets=[target],
            include_ignore=True,
        )
        if single_res.is_environment_error:
            return TemplateValidationOutcome(
                row_id=target.row_id,
                template_id=target.template_id,
                relative_path=target.relative_path,
                content_hash=target.content_hash,
                protocols=target.protocols,
                status=VALIDATION_STATUS_PENDING,
                engine_included=False,
                error_category=ERR_CAT_ENVIRONMENT,
                reason=single_res.environment_error_reason,
            )

        norm_path = normalize_template_path(target.relative_path)
        if single_res.validated_ok and norm_path in single_res.listed_paths:
            return TemplateValidationOutcome(
                row_id=target.row_id,
                template_id=target.template_id,
                relative_path=target.relative_path,
                content_hash=target.content_hash,
                protocols=target.protocols,
                status=VALIDATION_STATUS_VALIDATED,
                engine_included=True,
                error_category=ERR_CAT_NONE,
                reason=None,
            )

        # Retry without .nuclei-ignore to distinguish official-ignore mismatch from invalid template
        no_ignore_res = self.executor.run_batch(
            snapshot_dir=snapshot_dir,
            targets=[target],
            include_ignore=False,
        )
        if not no_ignore_res.is_environment_error and no_ignore_res.validated_ok and norm_path in no_ignore_res.listed_paths:
            return TemplateValidationOutcome(
                row_id=target.row_id,
                template_id=target.template_id,
                relative_path=target.relative_path,
                content_hash=target.content_hash,
                protocols=target.protocols,
                status=VALIDATION_STATUS_REJECTED,
                engine_included=False,
                error_category=ERR_CAT_OFFICIAL_IGNORE,
                reason="Skipped by Nuclei engine loader under official .nuclei-ignore rules",
            )

        reason = (
            _extract_engine_error_reason(single_res.stderr)
            if single_res.validate_exit_code != 0
            else "Template omitted by Nuclei engine listing (-tl) and did not load"
        )
        return TemplateValidationOutcome(
            row_id=target.row_id,
            template_id=target.template_id,
            relative_path=target.relative_path,
            content_hash=target.content_hash,
            protocols=target.protocols,
            status=VALIDATION_STATUS_REJECTED,
            engine_included=False,
            error_category=ERR_CAT_TL_OMITTED if single_res.validate_exit_code == 0 else ERR_CAT_ENGINE_VALIDATION,
            reason=reason,
        )

    def _validate_subset_recursive(
        self,
        snapshot_dir: str,
        subset: Sequence[BatchTarget],
        state: Dict[str, int],
    ) -> Tuple[List[TemplateValidationOutcome], bool]:
        """
        Run `-tl` + `-validate` on `subset`, recursively bisecting any failing batch
        so every valid template is proven individually and every failing template
        gets its exact engine error reason.

        Returns `(outcomes, hit_environment_error)`.
        """
        if not subset:
            return [], False

        res = self.executor.run_batch(snapshot_dir=snapshot_dir, targets=subset, include_ignore=True)

        if res.is_environment_error:
            outcomes = [
                TemplateValidationOutcome(
                    row_id=t.row_id,
                    template_id=t.template_id,
                    relative_path=t.relative_path,
                    content_hash=t.content_hash,
                    protocols=t.protocols,
                    status=VALIDATION_STATUS_PENDING,
                    engine_included=False,
                    error_category=ERR_CAT_ENVIRONMENT,
                    reason=res.environment_error_reason,
                )
                for t in subset
            ]
            return outcomes, True

        if res.validated_ok:
            outcomes: List[TemplateValidationOutcome] = []
            for t in subset:
                norm = normalize_template_path(t.relative_path)
                if norm in res.listed_paths:
                    outcomes.append(
                        TemplateValidationOutcome(
                            row_id=t.row_id,
                            template_id=t.template_id,
                            relative_path=t.relative_path,
                            content_hash=t.content_hash,
                            protocols=t.protocols,
                            status=VALIDATION_STATUS_VALIDATED,
                            engine_included=True,
                            error_category=ERR_CAT_NONE,
                            reason=None,
                        )
                    )
                else:
                    outcome = self._verify_single_omitted(snapshot_dir, t, res)
                    outcomes.append(outcome)
                    if outcome.status == VALIDATION_STATUS_PENDING and outcome.error_category == ERR_CAT_ENVIRONMENT:
                        # Mark remaining unprocessed items in subset pending? Keep inspecting or stop cleanly
                        pass
            hit_env = any(o.error_category == ERR_CAT_ENVIRONMENT for o in outcomes)
            return outcomes, hit_env

        # Validation failed at engine level
        if len(subset) == 1:
            t = subset[0]
            norm = normalize_template_path(t.relative_path)
            return [
                TemplateValidationOutcome(
                    row_id=t.row_id,
                    template_id=t.template_id,
                    relative_path=t.relative_path,
                    content_hash=t.content_hash,
                    protocols=t.protocols,
                    status=VALIDATION_STATUS_REJECTED,
                    engine_included=(norm in res.listed_paths),
                    error_category=ERR_CAT_ENGINE_VALIDATION,
                    reason=_extract_engine_error_reason(res.stderr),
                )
            ], False

        # Binary split to isolate bad template(s) and confirm valid ones
        mid = len(subset) // 2
        state["bisect_calls"] += 1
        left_outcomes, left_env = self._validate_subset_recursive(snapshot_dir, subset[:mid], state)
        if left_env:
            remaining = [
                TemplateValidationOutcome(
                    row_id=t.row_id,
                    template_id=t.template_id,
                    relative_path=t.relative_path,
                    content_hash=t.content_hash,
                    protocols=t.protocols,
                    status=VALIDATION_STATUS_PENDING,
                    engine_included=False,
                    error_category=ERR_CAT_ENVIRONMENT,
                    reason="Deferred due to environment failure in prior bisect half",
                )
                for t in subset[mid:]
            ]
            return left_outcomes + remaining, True

        right_outcomes, right_env = self._validate_subset_recursive(snapshot_dir, subset[mid:], state)
        return left_outcomes + right_outcomes, right_env

    def validate_version(
        self,
        repository_version_id: str,
        batch_size: int = DEFAULT_BATCH_SIZE,
        resume: bool = False,
        stop_on_environment_error: bool = True,
        progress_callback: Optional[Callable[[int, int, List[TemplateValidationOutcome]], None]] = None,
    ) -> EngineValidationSummary:
        """
        Validate all policy-eligible templates for `repository_version_id`.

        Args:
            repository_version_id: UUID of the staging `TemplateRepositoryVersion`.
            batch_size: Number of templates per isolated Docker batch.
            resume: If True, skips templates already validated/rejected under
                matching `(version_id, content_hash, policy_version, engine_version,
                engine_image_digest)`. If False, resets all policy-eligible rows
                to `pending` first and validates every eligible template cleanly.
            stop_on_environment_error: If True, stops processing further batches
                on Docker/environment failure while leaving unvalidated templates
                persisted as `pending` for subsequent `resume=True`.
            progress_callback: Optional `(batch_idx, total_batches, outcomes)` hook.
        """
        if batch_size < 1:
            raise EngineValidationError("batch_size must be >= 1")

        def _execute() -> EngineValidationSummary:
            t_start = time.monotonic()
            db, owns = self._get_session()
            try:
                version = get_version(repository_version_id, db=db)
                if version is None:
                    raise VersionNotFoundError(
                        f"Repository version '{repository_version_id}' does not exist"
                    )

                if version.status in ("active", "retained"):
                    raise PublishedVersionImmutableError(
                        f"Cannot mutate validation metadata on '{version.status}' repository version '{repository_version_id}'"
                    )
                if version.status != "staging":
                    raise VersionStateError(
                        f"Repository version '{repository_version_id}' must be in 'staging' status (actual: '{version.status}')"
                    )

                is_valid_snap, integrity_details = verify_snapshot_integrity(
                    repository_version_id, db=db
                )
                if not is_valid_snap:
                    raise SnapshotIntegrityError(
                        f"Snapshot integrity check failed for '{repository_version_id}': {integrity_details}"
                    )

                snapshot_dir = version.repository_path
                if not snapshot_dir or not os.path.isdir(snapshot_dir):
                    raise SnapshotIntegrityError(
                        f"Snapshot directory missing: {snapshot_dir}"
                    )

                ready, err_msg = self.executor.check_ready()
                if not ready:
                    raise DockerEnvironmentError(
                        f"Nuclei execution environment not ready: {err_msg}"
                    )

                # Load all catalog rows for counts and all policy-eligible rows ordered deterministically
                all_rows = db.execute(
                    select(NucleiTemplate)
                    .where(NucleiTemplate.repository_version_id == repository_version_id)
                    .order_by(NucleiTemplate.relative_path.asc())
                ).scalars().all()

                total_indexed = len(all_rows)
                eligible_rows = [
                    r for r in all_rows if bool(r.sequential_eligible or r.independent_eligible)
                ]

                targets: List[BatchTarget] = []
                targets_by_id: Dict[str, BatchTarget] = {}
                to_process: List[BatchTarget] = []
                pending_init_outcomes: List[TemplateValidationOutcome] = []

                for row in eligible_rows:
                    pol = row.policy_details or {}
                    p_ver = str(pol.get("policy_version") or version.policy_version or "unknown")
                    t = BatchTarget(
                        row_id=str(row.id),
                        template_id=row.template_id,
                        relative_path=row.relative_path,
                        content_hash=row.content_hash,
                        protocols=list(row.protocols or []),
                        policy_version=p_ver,
                    )
                    targets.append(t)
                    targets_by_id[t.row_id] = t

                    existing_ev = pol.get("engine_validation")
                    if resume and self._record_matches_current_run(existing_ev, repository_version_id, t):
                        continue

                    to_process.append(t)
                    # Only reset/seed pending if missing or non-matching (or fresh non-resume run)
                    if (
                        not resume
                        or not isinstance(existing_ev, dict)
                        or existing_ev.get("status") != VALIDATION_STATUS_PENDING
                        or existing_ev.get("engine_image_digest") != self.engine_image_digest
                        or existing_ev.get("template_hash") != t.content_hash
                    ):
                        pending_init_outcomes.append(
                            TemplateValidationOutcome(
                                row_id=t.row_id,
                                template_id=t.template_id,
                                relative_path=t.relative_path,
                                content_hash=t.content_hash,
                                protocols=t.protocols,
                                status=VALIDATION_STATUS_PENDING,
                                engine_included=False,
                                error_category=ERR_CAT_NOT_YET_VALIDATED,
                                reason="Queued for Nuclei engine validation",
                            )
                        )

                # Seed pending state atomically before executing batches so partial interrupts retain invariant
                if pending_init_outcomes:
                    chunk_sz = 1000
                    for i in range(0, len(pending_init_outcomes), chunk_sz):
                        self._persist_outcomes(
                            db,
                            repository_version_id,
                            pending_init_outcomes[i : i + chunk_sz],
                            targets_by_id,
                        )

                batches = [
                    to_process[i : i + batch_size]
                    for i in range(0, len(to_process), batch_size)
                ]

                state = {"bisect_calls": 0}
                batches_completed = 0
                interrupted = False

                for idx, batch in enumerate(batches, 1):
                    logger.info(
                        "Validating batch %d/%d (%d templates) for version %s",
                        idx,
                        len(batches),
                        len(batch),
                        repository_version_id,
                    )
                    outcomes, hit_env_error = self._validate_subset_recursive(
                        snapshot_dir=snapshot_dir,
                        subset=batch,
                        state=state,
                    )
                    self._persist_outcomes(db, repository_version_id, outcomes, targets_by_id)
                    batches_completed += 1

                    if progress_callback is not None:
                        progress_callback(idx, len(batches), outcomes)

                    if hit_env_error and stop_on_environment_error:
                        interrupted = True
                        logger.warning(
                            "Environment error on batch %d/%d; halting safely with remaining templates in pending",
                            idx,
                            len(batches),
                        )
                        break

                return self._compile_summary_from_db(
                    db=db,
                    version=version,
                    total_indexed=total_indexed,
                    resumed=resume,
                    interrupted=interrupted,
                    elapsed_seconds=time.monotonic() - t_start,
                    batches_total=len(batches),
                    batches_completed=batches_completed,
                    bisect_calls=state["bisect_calls"],
                )
            finally:
                if owns:
                    db.close()

        if self.use_lock:
            with RepositoryLock(lock_dir=self.lock_dir, stale_timeout_seconds=7200):
                return _execute()
        return _execute()

    def get_validation_summary(self, repository_version_id: str) -> EngineValidationSummary:
        """Read and summarize persisted Phase 7.1 validation results from PostgreSQL."""
        db, owns = self._get_session()
        try:
            version = get_version(repository_version_id, db=db)
            if version is None:
                raise VersionNotFoundError(
                    f"Repository version '{repository_version_id}' does not exist"
                )
            total_indexed = (
                db.execute(
                    select(NucleiTemplate).where(
                        NucleiTemplate.repository_version_id == repository_version_id
                    )
                )
                .scalars()
                .all()
            )
            return self._compile_summary_from_db(
                db=db,
                version=version,
                total_indexed=len(total_indexed),
                resumed=False,
                interrupted=False,
                elapsed_seconds=0.0,
                batches_total=0,
                batches_completed=0,
                bisect_calls=0,
            )
        finally:
            if owns:
                db.close()

    def _compile_summary_from_db(
        self,
        db: Session,
        version: TemplateRepositoryVersion,
        total_indexed: int,
        resumed: bool,
        interrupted: bool,
        elapsed_seconds: float,
        batches_total: int,
        batches_completed: int,
        bisect_calls: int,
    ) -> EngineValidationSummary:
        eligible_rows = db.execute(
            select(NucleiTemplate)
            .where(
                NucleiTemplate.repository_version_id == version.id,
                (NucleiTemplate.sequential_eligible == True) | (NucleiTemplate.independent_eligible == True),
            )
            .order_by(NucleiTemplate.relative_path.asc())
        ).scalars().all()

        validated_count = 0
        rejected_count = 0
        pending_count = 0
        by_protocol: Dict[str, Dict[str, int]] = {}
        rejected_list: List[Dict[str, Any]] = []
        pending_list: List[Dict[str, Any]] = []

        for row in eligible_rows:
            ev = (row.policy_details or {}).get("engine_validation")
            if isinstance(ev, dict) and ev.get("status") in VALID_VALIDATION_STATUSES:
                status = ev["status"]
                reason = ev.get("reason")
                error_cat = ev.get("error_category")
            else:
                status = VALIDATION_STATUS_PENDING
                reason = "Not yet validated"
                error_cat = ERR_CAT_NOT_YET_VALIDATED

            if status == VALIDATION_STATUS_VALIDATED:
                validated_count += 1
            elif status == VALIDATION_STATUS_REJECTED:
                rejected_count += 1
                rejected_list.append(
                    {
                        "template_id": row.template_id,
                        "relative_path": row.relative_path,
                        "protocols": list(row.protocols or []),
                        "error_category": error_cat,
                        "reason": reason,
                    }
                )
            else:
                pending_count += 1
                pending_list.append(
                    {
                        "template_id": row.template_id,
                        "relative_path": row.relative_path,
                        "protocols": list(row.protocols or []),
                        "error_category": error_cat,
                        "reason": reason,
                    }
                )

            protos = list(row.protocols or ["unknown"])
            combo_key = "+".join(sorted(protos))
            bucket = by_protocol.setdefault(
                combo_key,
                {"eligible": 0, "validated": 0, "rejected": 0, "pending": 0},
            )
            bucket["eligible"] += 1
            bucket[status] += 1

        return EngineValidationSummary(
            repository_version_id=str(version.id),
            upstream_version=version.upstream_version,
            upstream_commit=version.upstream_commit,
            policy_version=version.policy_version or "unknown",
            engine_version=self.engine_version,
            engine_image=self.engine_image,
            engine_image_digest=self.engine_image_digest,
            resumed=resumed,
            interrupted=interrupted,
            elapsed_seconds=elapsed_seconds,
            total_indexed=total_indexed,
            total_policy_eligible=len(eligible_rows),
            validated_count=validated_count,
            rejected_count=rejected_count,
            pending_count=pending_count,
            batches_total=batches_total,
            batches_completed=batches_completed,
            bisect_calls=bisect_calls,
            by_protocol=by_protocol,
            rejected_templates=rejected_list,
            pending_templates=pending_list,
        )
