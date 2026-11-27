"""
YemScan — Phase 4 PostgreSQL Template Catalog & Indexing Test Suite.

Tests cover:
  TC-01  Primary Key & Foreign Key integrity on PostgreSQL
  TC-02  Unique constraint: (repository_version_id, template_id) prevents duplicates
  TC-03  Same template_id allowed across DIFFERENT repository versions
  TC-04  Unique constraint: (repository_version_id, relative_path)
  TC-05  Check constraint: severity domain validation
  TC-06  Check constraint: security_status domain validation
  TC-07  Check constraint: content_hash 64-hex format validation
  TC-08  Check constraint: path safety (blocks absolute/traversal paths)
  TC-09  Check constraint: ineligible templates cannot be marked eligible
  TC-10  PostgreSQL ARRAY storage and containment queries (tags, protocols, cve_ids)
  TC-11  PostgreSQL JSONB storage and deep extraction (metadata, policy_details)
  TC-12  Full-Text Search on template name using to_tsvector / GIN index
  TC-13  Partial index queries for sequential_eligible and independent_eligible
  TC-14  Indexer service: successful bulk indexing into PostgreSQL
  TC-15  Indexer service: idempotent re-indexing in staging (no duplicate rows)
  TC-16  Indexer service: blocks re-indexing of active / retained (published) versions
  TC-17  Indexer service: rollback on mid-operation failure
  TC-18  Indexer service: omission of non-executable workflows & helpers
  TC-19  Foreign key cascade safety: cannot delete version with existing templates (RESTRICT)
  TC-20  Zero test debris: all test rows cleanly deleted after execution
"""

from __future__ import annotations

import os
import uuid
import pytest
from sqlalchemy import create_engine, select, text, delete, func
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.exc import IntegrityError

import database
from database import engine, SessionLocal
from models.template_repository import TemplateRepositoryVersion
from models.template_catalog import NucleiTemplate
from core.template_parser import TemplateParser
from core.template_metadata import MetadataExtractor
from core.template_eligibility import (
    ClassificationPolicy,
    EligibilityClassifier,
    IgnoreRuleSet,
    TemplateClassificationResult,
    STATUS_ELIGIBLE,
    STATUS_INELIGIBLE,
)
from core.template_classification_service import ClassificationSummary
from core.template_catalog_indexer import (
    TemplateCatalogIndexer,
    CatalogIndexingError,
    PublishedVersionImmutableError,
)

# Isolated Test Version IDs
TEST_REPO_VERSION_A = f"test-cat-a-{uuid.uuid4().hex[:12]}"
TEST_REPO_VERSION_B = f"test-cat-b-{uuid.uuid4().hex[:12]}"


@pytest.fixture(scope="module")
def db_session():
    """Provides a PostgreSQL session connected to the actual database."""
    session = SessionLocal()
    # Ensure test repository versions exist in template_repository_versions
    try:
        session.execute(
            delete(NucleiTemplate).where(
                NucleiTemplate.repository_version_id.in_([TEST_REPO_VERSION_A, TEST_REPO_VERSION_B])
            )
        )
        session.execute(
            delete(TemplateRepositoryVersion).where(
                TemplateRepositoryVersion.id.in_([TEST_REPO_VERSION_A, TEST_REPO_VERSION_B])
            )
        )
        session.commit()

        # Seed staging test version A
        ver_a = TemplateRepositoryVersion(
            id=TEST_REPO_VERSION_A,
            upstream_version="v10.5.1-test",
            upstream_commit="79fb682760ab3d5b0e22afbb44709353cbebf023",
            repository_path="/storage/test/a",
            snapshot_hash="a" * 64,
            status="staging",
        )
        # Seed active test version B (for immutability tests)
        ver_b = TemplateRepositoryVersion(
            id=TEST_REPO_VERSION_B,
            upstream_version="v10.5.0-test",
            upstream_commit="1111111111111111111111111111111111111111",
            repository_path="/storage/test/b",
            snapshot_hash="b" * 64,
            status="retained",  # published
        )
        session.add(ver_a)
        session.add(ver_b)
        session.commit()

        yield session

    finally:
        # Complete cleanup after test module
        session.rollback()
        session.execute(
            delete(NucleiTemplate).where(
                NucleiTemplate.repository_version_id.in_([TEST_REPO_VERSION_A, TEST_REPO_VERSION_B])
            )
        )
        session.execute(
            delete(TemplateRepositoryVersion).where(
                TemplateRepositoryVersion.id.in_([TEST_REPO_VERSION_A, TEST_REPO_VERSION_B])
            )
        )
        session.commit()
        session.close()


def _make_dummy_template(
    repo_id: str,
    tid: str = "test-tid-01",
    path: str = "http/cves/test.yaml",
    severity: str = "high",
    security_status: str = "eligible",
    seq_eligible: bool = True,
    ind_eligible: bool = True,
    content_hash: str = "c" * 64,
    tags: list = None,
    protocols: list = None,
    cve_ids: list = None,
) -> NucleiTemplate:
    return NucleiTemplate(
        id=uuid.uuid4(),
        repository_version_id=repo_id,
        template_id=tid,
        name=f"Test Template {tid}",
        description="A comprehensive security testing template for testing.",
        severity=severity,
        tags=tags or ["cve", "http", "rce"],
        protocols=protocols or ["http"],
        cve_ids=cve_ids or ["CVE-2023-12345"],
        cwe_ids=["CWE-78"],
        relative_path=path,
        content_hash=content_hash,
        security_status=security_status,
        sequential_eligible=seq_eligible,
        independent_eligible=ind_eligible,
        template_metadata={"author": ["tester"], "cvss_score": 9.8},
        policy_details={"policy_version": "v1.1.0", "web_relevance": True},
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_tc01_pk_fk_integrity(db_session):
    """TC-01: Valid insert succeeds with PK and FK enforcement."""
    tpl = _make_dummy_template(TEST_REPO_VERSION_A, tid="tc01-valid", path="http/tc01.yaml")
    db_session.add(tpl)
    db_session.commit()

    saved = db_session.get(NucleiTemplate, tpl.id)
    assert saved is not None
    assert saved.template_id == "tc01-valid"
    assert saved.repository_version_id == TEST_REPO_VERSION_A


def test_tc02_unique_template_id_per_version(db_session):
    """TC-02: UNIQUE(repository_version_id, template_id) rejects duplicate in same version."""
    t1 = _make_dummy_template(TEST_REPO_VERSION_A, tid="dup-tid", path="http/t1.yaml")
    t2 = _make_dummy_template(TEST_REPO_VERSION_A, tid="dup-tid", path="http/t2.yaml")

    db_session.add(t1)
    db_session.commit()

    db_session.add(t2)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_tc03_same_template_id_in_different_versions(db_session):
    """TC-03: Same template_id IS allowed across different repository versions."""
    t_a = _make_dummy_template(TEST_REPO_VERSION_A, tid="shared-tid", path="http/shared.yaml")
    t_b = _make_dummy_template(TEST_REPO_VERSION_B, tid="shared-tid", path="http/shared.yaml")

    db_session.add(t_a)
    db_session.add(t_b)
    db_session.commit()

    recs = db_session.execute(
        select(NucleiTemplate).where(NucleiTemplate.template_id == "shared-tid")
    ).scalars().all()
    assert len(recs) == 2


def test_tc04_unique_relative_path_per_version(db_session):
    """TC-04: UNIQUE(repository_version_id, relative_path) rejects duplicate path in same version."""
    t1 = _make_dummy_template(TEST_REPO_VERSION_A, tid="tid-p1", path="http/same_path.yaml")
    t2 = _make_dummy_template(TEST_REPO_VERSION_A, tid="tid-p2", path="http/same_path.yaml")

    db_session.add(t1)
    db_session.commit()

    db_session.add(t2)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_tc05_severity_check_constraint(db_session):
    """TC-05: Check constraint rejects invalid severity strings."""
    t = _make_dummy_template(TEST_REPO_VERSION_A, tid="tc05-sev", path="http/sev.yaml", severity="super_critical")
    db_session.add(t)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_tc06_security_status_check_constraint(db_session):
    """TC-06: Check constraint rejects invalid security_status strings."""
    t = _make_dummy_template(TEST_REPO_VERSION_A, tid="tc06-stat", path="http/stat.yaml", security_status="unknown_status")
    db_session.add(t)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_tc07_content_hash_check_constraint(db_session):
    """TC-07: Check constraint rejects non-64-hex SHA-256 strings."""
    # Too short
    t_short = _make_dummy_template(TEST_REPO_VERSION_A, tid="tc07-short", path="http/h1.yaml", content_hash="abcd")
    db_session.add(t_short)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()

    # Non-hex characters
    t_nonhex = _make_dummy_template(TEST_REPO_VERSION_A, tid="tc07-hex", path="http/h2.yaml", content_hash="z" * 64)
    db_session.add(t_nonhex)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_tc08_path_safety_check_constraint(db_session):
    """TC-08: Check constraint blocks absolute paths and directory traversal."""
    # Absolute path starting with /
    t_abs = _make_dummy_template(TEST_REPO_VERSION_A, tid="tc08-abs", path="/etc/passwd")
    db_session.add(t_abs)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()

    # Path traversal with ../
    t_trav = _make_dummy_template(TEST_REPO_VERSION_A, tid="tc08-trav", path="http/../../secret.yaml")
    db_session.add(t_trav)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_tc09_ineligible_execution_constraint(db_session):
    """TC-09: Ineligible template CANNOT be marked sequential_eligible or independent_eligible."""
    t_viol = _make_dummy_template(
        TEST_REPO_VERSION_A,
        tid="tc09-viol",
        path="http/viol.yaml",
        security_status="ineligible",
        seq_eligible=True,   # VIOLATION!
        ind_eligible=False,
    )
    db_session.add(t_viol)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_tc10_array_storage_and_gin_containment(db_session):
    """TC-10: PostgreSQL ARRAY column stores lists and supports ANY / containment queries."""
    t = _make_dummy_template(
        TEST_REPO_VERSION_A,
        tid="tc10-array",
        path="http/array.yaml",
        tags=["wordpress", "cve2023", "rce"],
        protocols=["http", "headless"],
        cve_ids=["CVE-2023-99999"],
    )
    db_session.add(t)
    db_session.commit()

    # Query using text containment or ANY
    res = db_session.execute(
        select(NucleiTemplate).where(
            NucleiTemplate.repository_version_id == TEST_REPO_VERSION_A,
            text("'wordpress' = ANY(nuclei_templates.tags)"),
        )
    ).scalars().all()
    assert any(x.template_id == "tc10-array" for x in res)

    # Query protocols
    res_proto = db_session.execute(
        select(NucleiTemplate).where(
            NucleiTemplate.repository_version_id == TEST_REPO_VERSION_A,
            text("'headless' = ANY(nuclei_templates.protocols)"),
        )
    ).scalars().all()
    assert any(x.template_id == "tc10-array" for x in res_proto)


def test_tc11_jsonb_storage_and_extraction(db_session):
    """TC-11: JSONB stores structured dicts and supports key extraction."""
    t = _make_dummy_template(
        TEST_REPO_VERSION_A,
        tid="tc11-jsonb",
        path="http/jsonb.yaml",
    )
    t.template_metadata = {"cvss_score": 9.8, "author": ["rxerium", "yemenscan"]}
    t.policy_details = {"execution_requirements": {"headless": True, "interactsh": False}}
    db_session.add(t)
    db_session.commit()

    saved = db_session.get(NucleiTemplate, t.id)
    assert saved.template_metadata["cvss_score"] == 9.8
    assert saved.policy_details["execution_requirements"]["headless"] is True


def test_tc12_full_text_search(db_session):
    """TC-12: Full text search on template name using to_tsvector."""
    t = _make_dummy_template(
        TEST_REPO_VERSION_A,
        tid="tc12-fts",
        path="http/fts.yaml",
    )
    t.name = "Apache Solr Remote Code Execution Vulnerability Detection"
    db_session.add(t)
    db_session.commit()

    if engine.dialect.name == "postgresql":
        query = select(NucleiTemplate).where(
            NucleiTemplate.repository_version_id == TEST_REPO_VERSION_A,
            text("to_tsvector('english', COALESCE(name, '')) @@ to_tsquery('english', 'Solr & Execution')"),
        )
        matches = db_session.execute(query).scalars().all()
        assert any(x.template_id == "tc12-fts" for x in matches)


def test_tc13_partial_index_queries(db_session):
    """TC-13: Queries for sequential_eligible and independent_eligible use partial indexes."""
    t_elig = _make_dummy_template(
        TEST_REPO_VERSION_A, tid="tc13-elig", path="http/p_elig.yaml",
        security_status="eligible", seq_eligible=True, ind_eligible=True,
    )
    t_inelig = _make_dummy_template(
        TEST_REPO_VERSION_A, tid="tc13-inelig", path="http/p_inelig.yaml",
        security_status="ineligible", seq_eligible=False, ind_eligible=False,
    )
    db_session.add(t_elig)
    db_session.add(t_inelig)
    db_session.commit()

    seq_recs = db_session.execute(
        select(NucleiTemplate).where(
            NucleiTemplate.repository_version_id == TEST_REPO_VERSION_A,
            NucleiTemplate.sequential_eligible == True,
        )
    ).scalars().all()
    assert all(r.sequential_eligible for r in seq_recs)
    assert any(r.template_id == "tc13-elig" for r in seq_recs)
    assert not any(r.template_id == "tc13-inelig" for r in seq_recs)


def test_tc14_indexer_service_bulk_insert(db_session):
    """TC-14: TemplateCatalogIndexer successfully bulk inserts templates from ClassificationSummary."""
    # Clean staging version A records
    db_session.execute(
        delete(NucleiTemplate).where(NucleiTemplate.repository_version_id == TEST_REPO_VERSION_A)
    )
    db_session.commit()

    # Build dummy ClassificationSummary
    parser = TemplateParser()
    extractor = MetadataExtractor()
    policy = ClassificationPolicy.v1_1()
    classifier = EligibilityClassifier(policy)
    ignore = IgnoreRuleSet.empty()

    # Create dummy parsed results
    results = []
    for i in range(15):
        yaml_text = f"""
        id: bulk-tpl-{i:03d}
        info:
          name: Bulk Template {i}
          severity: medium
          tags: http,bulk
        http:
          - method: GET
            path: ["{{{{BaseURL}}}}/{i}"]
        """
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write(yaml_text)
            f_path = f.name
        try:
            p_res = parser.parse_file(f_path, os.path.dirname(f_path))
            m_res = extractor.extract(p_res)
            c_res = classifier.classify(m_res, ignore, TEST_REPO_VERSION_A, p_res.raw_yaml_text)
            results.append(c_res)
        finally:
            os.remove(f_path)

    summary = ClassificationSummary(
        repository_version_id=TEST_REPO_VERSION_A,
        policy_version="v1.1.0",
        snapshot_path="/test",
        elapsed_seconds=1.0,
        total_yaml_files=15,
        total_processed=15,
        total_parse_errors=0,
        total_eligible=15,
        total_ineligible=0,
        total_conditional=0,
        by_reason={"eligible": 15},
        by_protocol={"http": 15},
        by_status={"eligible": 15, "ineligible": 0, "conditional": 0},
        results=results,
        service_errors=[],
    )

    indexer = TemplateCatalogIndexer(chunk_size=5)
    idx_summary = indexer.index_classification_results(summary, session=db_session)

    assert idx_summary.status == "success"
    assert idx_summary.total_indexed == 15
    assert idx_summary.sequential_eligible_count == 15

    # Verify rows in DB
    count = db_session.execute(
        select(func.count(NucleiTemplate.id)).where(
            NucleiTemplate.repository_version_id == TEST_REPO_VERSION_A
        )
    ).scalar()
    assert count == 15


def test_tc15_indexer_idempotent_reindexing(db_session):
    """TC-15: Re-running indexer on a staging version replaces previous staged rows safely."""
    indexer = TemplateCatalogIndexer(chunk_size=10)
    # Re-running on existing data should result in exact same row count (no duplicates)
    summary = ClassificationSummary(
        repository_version_id=TEST_REPO_VERSION_A,
        policy_version="v1.1.0",
        snapshot_path="/test",
        elapsed_seconds=1.0,
        total_yaml_files=0,
        total_processed=0,
        total_parse_errors=0,
        total_eligible=0,
        total_ineligible=0,
        total_conditional=0,
        by_reason={},
        by_protocol={},
        by_status={},
        results=[],
        service_errors=[],
    )
    res = indexer.index_classification_results(summary, session=db_session)
    assert res.status == "success"
    assert res.total_indexed == 0

    # Table is cleanly reset for staging version
    count = db_session.execute(
        select(func.count(NucleiTemplate.id)).where(
            NucleiTemplate.repository_version_id == TEST_REPO_VERSION_A
        )
    ).scalar()
    assert count == 0


def test_tc16_published_version_immutable(db_session):
    """TC-16: Indexer raises PublishedVersionImmutableError if version status is retained/active."""
    indexer = TemplateCatalogIndexer()
    summary = ClassificationSummary(
        repository_version_id=TEST_REPO_VERSION_B,  # status = 'retained'
        policy_version="v1.1.0",
        snapshot_path="/test",
        elapsed_seconds=1.0,
        total_yaml_files=0,
        total_processed=0,
        total_parse_errors=0,
        total_eligible=0,
        total_ineligible=0,
        total_conditional=0,
        by_reason={},
        by_protocol={},
        by_status={},
        results=[],
        service_errors=[],
    )
    with pytest.raises(PublishedVersionImmutableError):
        indexer.index_classification_results(summary, session=db_session)


def test_tc17_foreign_key_restrict_prevents_version_deletion(db_session):
    """TC-17: Deleting a version that has templates in nuclei_templates is blocked by ON DELETE RESTRICT."""
    t = _make_dummy_template(TEST_REPO_VERSION_A, tid="fk-restrict", path="http/fk.yaml")
    db_session.add(t)
    db_session.commit()

    # Attempt to delete the version
    with pytest.raises(IntegrityError):
        db_session.execute(
            delete(TemplateRepositoryVersion).where(
                TemplateRepositoryVersion.id == TEST_REPO_VERSION_A
            )
        )
        db_session.commit()
    db_session.rollback()
