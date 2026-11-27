"""
YemScan — Phase 7.1 Tests: Comprehensive Nuclei Engine Validation Service.

Tests cover every mandatory requirement of Phase 7.1:
  - Strict -tl inclusion check (never blindly accepts a batch when -tl omits a template)
  - Persists structured engine validation state inside policy_details["engine_validation"]
    linked to repository_version_id, template_hash, policy_version, engine_image_digest
  - Preserves approved 17-column nuclei_templates schema (zero schema drift)
  - Isolates failing templates via recursive bisect with exact stderr causes -> rejected
  - Distinguishes environment / container failures from engine rejections -> pending
  - Supports mid-run interruption preservation and clean resume (resume=True)
  - Guards active/retained versions against mutation and rejects tampered snapshots
  - Leaves original immutable snapshot files completely unchanged
  - Real Docker (--network none, projectdiscovery/nuclei:v3.11.1) multi-protocol smoke test
  - Verifies invariant: policy_eligible == validated + rejected + pending
"""

from __future__ import annotations

import hashlib
import os
import sys
import uuid
from typing import Dict, List, Optional, Sequence, Set, Tuple

import pytest
from sqlalchemy import delete, select, text

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import SessionLocal
from models.template_catalog import NucleiTemplate
from models.template_repository import TemplateRepositoryVersion
from core.nuclei_repository_service import (
    SnapshotIntegrityError,
    VersionNotFoundError,
    VersionStateError,
    compute_deterministic_snapshot_hash,
    verify_snapshot_integrity,
)
from core.nuclei_shared import (
    NUCLEI_DOCKER_IMAGE,
    NUCLEI_ENGINE_DIGEST,
    NUCLEI_ENGINE_VERSION,
)
from core.template_engine_validator import (
    DockerEnvironmentError,
    DockerNucleiExecutor,
    EngineBatchResult,
    NucleiEngineValidator,
    PublishedVersionImmutableError,
    VALIDATION_STATUS_PENDING,
    VALIDATION_STATUS_REJECTED,
    VALIDATION_STATUS_VALIDATED,
    normalize_template_path,
)
from core.template_selection_service import ScanMode, TemplateFilter, TemplateSelectionService


# ---------------------------------------------------------------------------
# Mock Engine Executor
# ---------------------------------------------------------------------------

class FakeEngineExecutor:
    """Deterministic controllable executor simulating Nuclei -tl + -validate."""

    def __init__(
        self,
        ready: bool = True,
        bad_paths: Optional[Dict[str, str]] = None,
        omitted_with_ignore: Optional[Set[str]] = None,
        omitted_always: Optional[Set[str]] = None,
        env_error_on_call: Optional[int] = None,
    ) -> None:
        self.ready = ready
        self.bad_paths = bad_paths or {}
        self.omitted_with_ignore = omitted_with_ignore or set()
        self.omitted_always = omitted_always or set()
        self.env_error_on_call = env_error_on_call
        self.calls: List[Tuple[List[str], bool]] = []

    def check_ready(self) -> Tuple[bool, Optional[str]]:
        if not self.ready:
            return False, "Mock Docker daemon unavailable"
        return True, None

    def run_batch(
        self,
        snapshot_dir: str,
        targets,
        include_ignore: bool = True,
        timeout_seconds: int = 120,
    ) -> EngineBatchResult:
        call_num = len(self.calls) + 1
        paths = [normalize_template_path(t.relative_path) for t in targets]
        self.calls.append((paths, include_ignore))

        if self.env_error_on_call is not None and call_num >= self.env_error_on_call:
            return EngineBatchResult(
                listed_paths=set(),
                validate_exit_code=125,
                tl_exit_code=125,
                validated_ok=False,
                stderr="Cannot connect to the Docker daemon",
                stdout="",
                is_environment_error=True,
                environment_error_reason="Simulated Docker outage",
            )

        listed: Set[str] = set()
        failing: List[Tuple[str, str]] = []
        for p in paths:
            if p in self.omitted_always:
                continue
            if include_ignore and p in self.omitted_with_ignore:
                continue
            listed.add(p)
            if p in self.bad_paths:
                failing.append((p, self.bad_paths[p]))

        if failing:
            bad_p, cause = failing[0]
            return EngineBatchResult(
                listed_paths=listed,
                validate_exit_code=1,
                tl_exit_code=0,
                validated_ok=False,
                stderr=f'[ERR] Error occurred loading template /root/nuclei-templates/{bad_p}: cause="{cause}"\n[FTL] Could not validate templates',
                stdout="\n".join(sorted(listed)),
                is_environment_error=False,
            )

        return EngineBatchResult(
            listed_paths=listed,
            validate_exit_code=0,
            tl_exit_code=0,
            validated_ok=True,
            stderr="[INF] All templates validated successfully",
            stdout="\n".join(sorted(listed)),
            is_environment_error=False,
        )


# ---------------------------------------------------------------------------
# Helpers for isolated temporary snapshots & PostgreSQL catalog rows
# ---------------------------------------------------------------------------

def _sha256(text_val: str) -> str:
    return hashlib.sha256(text_val.encode("utf-8")).hexdigest()


def _create_test_version_with_templates(
    db,
    tmp_path,
    files_spec: List[Dict],
    status: str = "staging",
    policy_version: str = "v1.2.0",
) -> str:
    """Create a real snapshot folder + DB version + catalog rows cleanly."""
    snap_dir = tmp_path / f"snap_{uuid.uuid4().hex[:8]}"
    snap_dir.mkdir(parents=True, exist_ok=True)

    for spec in files_spec:
        fpath = snap_dir / spec["relative_path"]
        fpath.parent.mkdir(parents=True, exist_ok=True)
        fpath.write_text(spec["content"], encoding="utf-8")

    snap_hash, _, _ = compute_deterministic_snapshot_hash(str(snap_dir))
    version_id = str(uuid.uuid4())

    version = TemplateRepositoryVersion(
        id=version_id,
        upstream_version="v10.5.1-test",
        upstream_commit="79fb682760ab3d5b0e22afbb44709353cbebf023",
        repository_path=str(snap_dir),
        snapshot_hash=snap_hash,
        policy_version=policy_version,
        status=status,
    )
    db.add(version)
    db.flush()

    for spec in files_spec:
        eligible = spec.get("eligible", True)
        row = NucleiTemplate(
            id=uuid.uuid4(),
            repository_version_id=version_id,
            template_id=spec["template_id"],
            name=spec.get("name", spec["template_id"]),
            description="Test template",
            severity=spec.get("severity", "info"),
            tags=spec.get("tags", ["test"]),
            protocols=spec.get("protocols", ["http"]),
            cve_ids=[],
            cwe_ids=[],
            relative_path=spec["relative_path"].replace("\\", "/"),
            content_hash=_sha256(spec["content"]),
            security_status="eligible" if eligible else "ineligible",
            sequential_eligible=eligible,
            independent_eligible=eligible,
            template_metadata={"author": "test", "references": []},
            policy_details={
                "policy_version": policy_version,
                "eligibility_reasons": ["eligible"] if eligible else ["official_ignore"],
                "headless_requirement": "headless" in spec.get("protocols", []),
                "oast_requirement": False,
                "authentication_requirements": False,
                "required_variables": [],
                "official_exclusion_matches": [] if eligible else ["files:test"],
            },
        )
        db.add(row)

    db.commit()
    return version_id


def _cleanup_test_version(db, version_id: str) -> None:
    try:
        db.rollback()
        db.execute(delete(NucleiTemplate).where(NucleiTemplate.repository_version_id == version_id))
        db.execute(delete(TemplateRepositoryVersion).where(TemplateRepositoryVersion.id == version_id))
        db.commit()
    except Exception:
        db.rollback()


# ---------------------------------------------------------------------------
# Phase 7.1 Tests
# ---------------------------------------------------------------------------

def test_01_all_eligible_verified_and_persisted_17_columns(tmp_path):
    db = SessionLocal()
    specs = [
        {"template_id": "t-http", "relative_path": "http/t1.yaml", "protocols": ["http"], "content": "id: t-http\n", "eligible": True},
        {"template_id": "t-headless", "relative_path": "headless/t2.yaml", "protocols": ["headless", "http"], "content": "id: t-headless\n", "eligible": True},
        {"template_id": "t-dast", "relative_path": "dast/t3.yaml", "protocols": ["http"], "tags": ["dast"], "content": "id: t-dast\n", "eligible": True},
        {"template_id": "t-net", "relative_path": "network/t4.yaml", "protocols": ["network"], "content": "id: t-net\n", "eligible": True},
        {"template_id": "t-dns", "relative_path": "dns/t5.yaml", "protocols": ["dns"], "content": "id: t-dns\n", "eligible": True},
        {"template_id": "t-excluded", "relative_path": "http/excluded.yaml", "protocols": ["http"], "content": "id: t-excluded\n", "eligible": False},
    ]
    vid = _create_test_version_with_templates(db, tmp_path, specs)
    try:
        executor = FakeEngineExecutor()
        validator = NucleiEngineValidator(session=db, executor=executor, use_lock=False)
        summary = validator.validate_version(vid, batch_size=3)

        assert summary.total_indexed == 6
        assert summary.total_policy_eligible == 5
        assert summary.validated_count == 5
        assert summary.rejected_count == 0
        assert summary.pending_count == 0
        assert summary.equation_holds is True
        assert summary.interrupted is False

        # Verify persisted JSONB schema & 17-column preservation
        col_count = db.execute(
            text(
                "SELECT COUNT(*) FROM information_schema.columns "
                "WHERE table_schema = 'public' AND table_name = 'nuclei_templates'"
            )
        ).scalar_one()
        assert col_count == 17

        rows = db.execute(
            select(NucleiTemplate).where(NucleiTemplate.repository_version_id == vid)
        ).scalars().all()
        rows_by_tid = {r.template_id: r for r in rows}

        ev = rows_by_tid["t-http"].policy_details["engine_validation"]
        assert ev["status"] == VALIDATION_STATUS_VALIDATED
        assert ev["repository_version_id"] == vid
        assert ev["template_hash"] == rows_by_tid["t-http"].content_hash
        assert ev["policy_version"] == "v1.2.0"
        assert ev["engine_version"] == NUCLEI_ENGINE_VERSION
        assert ev["engine_image_digest"] == NUCLEI_ENGINE_DIGEST
        assert ev["engine_included"] is True

        # Ineligible template remains excluded from validation
        assert "engine_validation" not in (rows_by_tid["t-excluded"].policy_details or {})

        # Selection service surfaces engine_validation_status
        sel = TemplateSelectionService(session=db)
        page = sel.query_templates(
            vid,
            scan_mode=ScanMode.INDEPENDENT,
            filters=TemplateFilter(template_ids=["t-http"]),
        )
        assert page.total_count == 1
        assert page.templates[0].engine_validation_status == VALIDATION_STATUS_VALIDATED
    finally:
        _cleanup_test_version(db, vid)
        db.close()


def test_02_tl_omission_never_blindly_marked_validated(tmp_path):
    db = SessionLocal()
    specs = [
        {"template_id": "t-ok", "relative_path": "http/ok.yaml", "content": "id: t-ok\n"},
        {"template_id": "t-ignored", "relative_path": "http/ign.yaml", "content": "id: t-ignored\n"},
        {"template_id": "t-omitted", "relative_path": "http/omit.yaml", "content": "id: t-omitted\n"},
    ]
    vid = _create_test_version_with_templates(db, tmp_path, specs)
    try:
        # Even though batch -validate exits 0, -tl omitted two templates
        executor = FakeEngineExecutor(
            omitted_with_ignore={"http/ign.yaml"},
            omitted_always={"http/omit.yaml"},
        )
        validator = NucleiEngineValidator(session=db, executor=executor, use_lock=False)
        summary = validator.validate_version(vid, batch_size=10)

        assert summary.total_policy_eligible == 3
        assert summary.validated_count == 1
        assert summary.rejected_count == 2
        assert summary.pending_count == 0
        assert summary.equation_holds is True

        reasons_by_tid = {item["template_id"]: item for item in summary.rejected_templates}
        assert reasons_by_tid["t-ignored"]["error_category"] == "official_ignore_mismatch"
        assert reasons_by_tid["t-omitted"]["error_category"] == "tl_omitted"
    finally:
        _cleanup_test_version(db, vid)
        db.close()


def test_03_rejected_template_isolated_via_bisect_with_exact_cause(tmp_path):
    db = SessionLocal()
    specs = [
        {"template_id": "t1", "relative_path": "http/a1.yaml", "content": "id: t1\n"},
        {"template_id": "t2", "relative_path": "http/a2.yaml", "content": "id: t2\n"},
        {"template_id": "t-bad", "relative_path": "http/bad.yaml", "content": "id: t-bad\nbad: ["},
        {"template_id": "t4", "relative_path": "http/a4.yaml", "content": "id: t4\n"},
    ]
    vid = _create_test_version_with_templates(db, tmp_path, specs)
    try:
        executor = FakeEngineExecutor(bad_paths={"http/bad.yaml": "yaml: line 2: did not find expected node content"})
        validator = NucleiEngineValidator(session=db, executor=executor, use_lock=False)
        summary = validator.validate_version(vid, batch_size=4)

        assert summary.total_policy_eligible == 4
        assert summary.validated_count == 3
        assert summary.rejected_count == 1
        assert summary.pending_count == 0
        assert summary.bisect_calls >= 1
        assert summary.equation_holds is True

        rej = summary.rejected_templates[0]
        assert rej["template_id"] == "t-bad"
        assert "yaml: line 2" in rej["reason"]
    finally:
        _cleanup_test_version(db, vid)
        db.close()


def test_04_environment_failure_preserves_pending_and_resumes_cleanly(tmp_path):
    db = SessionLocal()
    specs = [
        {"template_id": f"t{i}", "relative_path": f"http/t{i}.yaml", "content": f"id: t{i}\n"}
        for i in range(1, 5)
    ]
    vid = _create_test_version_with_templates(db, tmp_path, specs)
    try:
        # Batch 1 passes (t1, t2), Batch 2 hits Docker error -> interrupted, leaves t3 & t4 pending
        failing_exec = FakeEngineExecutor(env_error_on_call=2)
        v1 = NucleiEngineValidator(session=db, executor=failing_exec, use_lock=False)
        s1 = v1.validate_version(vid, batch_size=2)

        assert s1.interrupted is True
        assert s1.total_policy_eligible == 4
        assert s1.validated_count == 2
        assert s1.rejected_count == 0
        assert s1.pending_count == 2
        assert s1.equation_holds is True

        # Resume with healthy executor -> processes ONLY t3 and t4
        healthy_exec = FakeEngineExecutor()
        v2 = NucleiEngineValidator(session=db, executor=healthy_exec, use_lock=False)
        s2 = v2.validate_version(vid, batch_size=2, resume=True)

        assert s2.interrupted is False
        assert s2.resumed is True
        assert s2.validated_count == 4
        assert s2.rejected_count == 0
        assert s2.pending_count == 0
        assert s2.equation_holds is True
        assert len(healthy_exec.calls) == 1
        assert sorted(healthy_exec.calls[0][0]) == ["http/t3.yaml", "http/t4.yaml"]
    finally:
        _cleanup_test_version(db, vid)
        db.close()


def test_05_preconditions_block_published_tampered_missing_and_unready(tmp_path):
    db = SessionLocal()
    specs = [{"template_id": "t1", "relative_path": "http/t1.yaml", "content": "id: t1\n"}]
    vid_active = _create_test_version_with_templates(db, tmp_path, specs, status="active")
    vid_staging = _create_test_version_with_templates(db, tmp_path, specs, status="staging")
    try:
        validator = NucleiEngineValidator(session=db, executor=FakeEngineExecutor(), use_lock=False)

        with pytest.raises(VersionNotFoundError):
            validator.validate_version(str(uuid.uuid4()))

        with pytest.raises(PublishedVersionImmutableError):
            validator.validate_version(vid_active)

        with pytest.raises(DockerEnvironmentError):
            unready = NucleiEngineValidator(session=db, executor=FakeEngineExecutor(ready=False), use_lock=False)
            unready.validate_version(vid_staging)

        # Tamper 1 byte in snapshot directory on disk
        ver_row = db.execute(
            select(TemplateRepositoryVersion).where(TemplateRepositoryVersion.id == vid_staging)
        ).scalar_one()
        tamper_file = os.path.join(ver_row.repository_path, "http", "t1.yaml")
        with open(tamper_file, "w", encoding="utf-8") as fh:
            fh.write("id: tampered!\n")

        with pytest.raises(SnapshotIntegrityError):
            validator.validate_version(vid_staging)
    finally:
        _cleanup_test_version(db, vid_active)
        _cleanup_test_version(db, vid_staging)
        db.close()


def test_06_snapshot_files_untouched_and_hash_unchanged(tmp_path):
    db = SessionLocal()
    specs = [
        {"template_id": "t1", "relative_path": "http/t1.yaml", "content": "id: t1\ninfo:\n  name: t1\n  author: test\n  severity: info\n"},
    ]
    vid = _create_test_version_with_templates(db, tmp_path, specs)
    try:
        ver_row = db.execute(
            select(TemplateRepositoryVersion).where(TemplateRepositoryVersion.id == vid)
        ).scalar_one()
        before_hash, before_cnt, _ = compute_deterministic_snapshot_hash(ver_row.repository_path)

        validator = NucleiEngineValidator(session=db, executor=FakeEngineExecutor(), use_lock=False)
        validator.validate_version(vid)

        after_hash, after_cnt, _ = compute_deterministic_snapshot_hash(ver_row.repository_path)
        assert before_hash == after_hash
        assert before_cnt == after_cnt
        ok, _ = verify_snapshot_integrity(vid, db=db)
        assert ok is True
    finally:
        _cleanup_test_version(db, vid)
        db.close()


@pytest.mark.skipif(not DockerNucleiExecutor().check_ready()[0], reason="Pinned Nuclei Docker image not available")
def test_07_real_docker_smoke_multi_protocol_and_invalid_yaml(tmp_path):
    db = SessionLocal()
    valid_http = """id: smoke-http-valid
info:
  name: Smoke HTTP Valid
  author: yemenscan
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: status
        status:
          - 200
"""
    valid_headless = """id: smoke-headless-valid
info:
  name: Smoke Headless Valid
  author: yemenscan
  severity: info
headless:
  - steps:
      - action: navigate
        args:
          url: "{{BaseURL}}"
      - action: waitload
    matchers:
      - type: word
        words:
          - "html"
"""
    valid_dast = """id: smoke-dast-valid
info:
  name: Smoke DAST Valid
  author: yemenscan
  severity: low
  tags: dast
http:
  - pre-condition:
      - type: dsl
        dsl:
          - 'method == "GET"'
    fuzzing:
      - part: query
        type: postfix
        mode: single
        fuzz:
          - "'"
    matchers:
      - type: word
        words:
          - "sql syntax"
"""
    invalid_yaml = """id: smoke-invalid-yaml
info:
  name: Smoke Broken
  author: yemenscan
  severity: bogus_invalid_severity_xyz
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
"""
    specs = [
        {"template_id": "smoke-http-valid", "relative_path": "http/smoke_http.yaml", "protocols": ["http"], "content": valid_http},
        {"template_id": "smoke-headless-valid", "relative_path": "headless/smoke_headless.yaml", "protocols": ["headless"], "content": valid_headless},
        {"template_id": "smoke-dast-valid", "relative_path": "dast/smoke_dast.yaml", "protocols": ["http"], "tags": ["dast"], "content": valid_dast},
        {"template_id": "smoke-invalid-yaml", "relative_path": "http/smoke_broken.yaml", "protocols": ["http"], "content": invalid_yaml},
    ]
    vid = _create_test_version_with_templates(db, tmp_path, specs)
    try:
        validator = NucleiEngineValidator(
            session=db,
            executor=DockerNucleiExecutor(docker_image=NUCLEI_DOCKER_IMAGE, timeout_seconds=90),
            use_lock=False,
        )
        summary = validator.validate_version(vid, batch_size=4)

        assert summary.total_policy_eligible == 4
        assert summary.validated_count == 3
        assert summary.rejected_count == 1
        assert summary.pending_count == 0
        assert summary.equation_holds is True
        assert summary.bisect_calls >= 1
        assert summary.rejected_templates[0]["template_id"] == "smoke-invalid-yaml"
        assert summary.rejected_templates[0]["reason"]
    finally:
        _cleanup_test_version(db, vid)
        db.close()
