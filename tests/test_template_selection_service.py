"""
YemScan — Phase 5 Tests: Shared Template Selection Service.

Tests cover:
- DAST v1.2.0 classification: official_ignore, unsafe_behavior, ai_unresolved, eligible
- DB schema: 17 columns, constraints, GIN indexes
- Sequential set retrieval contract
- Independent scan filters: 6 dimensions, OR/AND logic
- Pagination
- select-all matching (not just current page)
- Deduplication in validation
- Staging version blocking
- Ineligible template selection prevention
- Execution requirements in preview
- Available filter enumeration
- Zero regression on Phase 1, 2, 3 behavior
- database.py: no silent SQLite fallback for PostgreSQL
"""

from __future__ import annotations

import os
import uuid
from typing import List

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

# Ensure project root on path
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import Base
from models.template_repository import TemplateRepositoryVersion
from models.template_catalog import NucleiTemplate
from core.template_eligibility import (
    ClassificationPolicy,
    EligibilityClassifier,
    IgnoreRuleSet,
    RC_ELIGIBLE,
    RC_OFFICIAL_IGNORE,
    RC_UNSAFE_BEHAVIOR,
    RC_DAST_AI_UNRESOLVED,
    RC_UNSUPPORTED_PROTOCOL,
    RC_INVALID_TEMPLATE,
    RC_WORKFLOW_DEFERRED,
    STATUS_ELIGIBLE,
    STATUS_INELIGIBLE,
)
from core.template_metadata import TemplateMetadata, MetadataExtractor
from core.template_parser import TemplateParser
from core.template_selection_service import (
    TemplateSelectionService,
    ScanMode,
    TemplateFilter,
    PaginationParams,
    SortField,
    PaginatedTagsResult,
    SelectionState,
    EnvironmentCapabilities,
    TemplateReadinessStatus,
    TargetReadinessEvaluation,
)

# ---------------------------------------------------------------------------
# Test Fixtures
# ---------------------------------------------------------------------------

REPO_VERSION_ID = str(uuid.uuid4())


@pytest.fixture(scope="module")
def pg_engine():
    """Real PostgreSQL engine from environment."""
    db_url = os.getenv("DATABASE_URL", "")
    if not db_url:
        pytest.skip("DATABASE_URL not set — skipping PostgreSQL tests")
    # Adapt driver
    if db_url.startswith("postgresql://"):
        try:
            import psycopg2
            db_url = db_url.replace("postgresql://", "postgresql+psycopg2://", 1)
        except ImportError:
            import psycopg
            db_url = db_url.replace("postgresql://", "postgresql+psycopg://", 1)
    elif "postgresql+psycopg2://" in db_url:
        try:
            import psycopg2
        except ImportError:
            import psycopg
            db_url = db_url.replace("postgresql+psycopg2://", "postgresql+psycopg://", 1)
    engine = create_engine(db_url, echo=False, pool_pre_ping=True,
                           connect_args={"connect_timeout": 10})
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture(scope="module")
def pg_session(pg_engine):
    """PostgreSQL session factory."""
    Session = sessionmaker(bind=pg_engine)
    return Session


@pytest.fixture(scope="module")
def db_version(pg_session):
    """Create a test repository version record."""
    session = pg_session()
    # Clean up any leftover test versions
    session.execute(
        text("DELETE FROM nuclei_templates WHERE repository_version_id = :vid"),
        {"vid": REPO_VERSION_ID},
    )
    session.execute(
        text("DELETE FROM template_repository_versions WHERE id = :vid"),
        {"vid": REPO_VERSION_ID},
    )
    version = TemplateRepositoryVersion(
        id=REPO_VERSION_ID,
        upstream_version="v9.9.9-test",
        upstream_commit="a" * 64,
        repository_path="/tmp/test-snapshot",
        snapshot_hash="b" * 64,
        status="staging",
    )
    session.add(version)
    session.commit()
    yield version
    # Cleanup
    session.execute(
        text("DELETE FROM nuclei_templates WHERE repository_version_id = :vid"),
        {"vid": REPO_VERSION_ID},
    )
    session.execute(
        text("DELETE FROM template_repository_versions WHERE id = :vid"),
        {"vid": REPO_VERSION_ID},
    )
    session.commit()
    session.close()


def _make_template(
    repo_id: str,
    template_id: str,
    severity: str = "medium",
    tags: List[str] = None,
    protocols: List[str] = None,
    cve_ids: List[str] = None,
    cwe_ids: List[str] = None,
    sequential_eligible: bool = True,
    independent_eligible: bool = True,
    security_status: str = "eligible",
    relative_path: str = None,
    policy_details: dict = None,
    metadata_jsonb: dict = None,
    name: str = None,
) -> dict:
    """Build a nuclei_templates insert dict."""
    row_id = uuid.uuid5(uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8"), f"{repo_id}:{template_id}")
    return {
        "id": row_id,
        "repository_version_id": repo_id,
        "template_id": template_id,
        "name": name or template_id.replace("-", " ").title(),
        "description": f"Test template {template_id}",
        "severity": severity,
        "tags": tags or ["test"],
        "protocols": protocols or ["http"],
        "cve_ids": cve_ids or [],
        "cwe_ids": cwe_ids or [],
        "relative_path": relative_path or f"http/{template_id}.yaml",
        "content_hash": "a" * 64,
        "security_status": security_status,
        "sequential_eligible": sequential_eligible,
        "independent_eligible": independent_eligible,
        "metadata": metadata_jsonb or {
            "author": "testauthor",
            "cvss_score": None,
            "cvss_vector": None,
            "references": [],
            "remediation": None,
        },
        "template_metadata": metadata_jsonb or {
            "author": "testauthor",
            "cvss_score": None,
            "cvss_vector": None,
            "references": [],
            "remediation": None,
        },
        "policy_details": policy_details or {
            "policy_version": "v1.2.0",
            "web_relevance": True,
            "eligibility_reasons": ["eligible"],
            "primary_reason": "eligible",
            "official_exclusion_matches": [],
            "execution_requirements": {
                "headless": False,
                "interactsh": False,
                "authentication": False,
                "external_payloads": False,
                "required_variables": [],
                "dependencies": [],
            },
            "headless_requirement": False,
            "oast_requirement": False,
            "authentication_requirements": False,
            "required_variables": [],
            "indexed_at": "2026-11-27T16:28:36.745562+00:00",
        },
    }


def _seed_templates(pg_session, db_version):
    """Seed a small catalog of test templates for selection service tests."""
    session = pg_session()
    session.execute(
        text("DELETE FROM nuclei_templates WHERE repository_version_id = :vid"),
        {"vid": REPO_VERSION_ID},
    )

    templates = [
        # Critical CVE templates
        _make_template(REPO_VERSION_ID, "CVE-2021-44228", "critical",
                       tags=["cve", "log4j", "rce"], protocols=["http"],
                       cve_ids=["CVE-2021-44228"], cwe_ids=["CWE-502"],
                       metadata_jsonb={"author": "pdteam", "cvss_score": 10.0, "cvss_vector": "AV:N/AC:L", "references": ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228"], "remediation": "Upgrade log4j"},
                       policy_details={"policy_version": "v1.2.0", "headless_requirement": False, "oast_requirement": True, "authentication_requirements": False, "required_variables": [], "eligibility_reasons": ["eligible"], "official_exclusion_matches": [], "execution_requirements": {"headless": False, "interactsh": True, "authentication": False, "required_variables": []}}),
        _make_template(REPO_VERSION_ID, "CVE-2022-22965", "critical",
                       tags=["cve", "spring4shell", "rce"], protocols=["http"],
                       cve_ids=["CVE-2022-22965"], relative_path="dast/cves/2022/CVE-2022-22965.yaml"),
        # High severity
        _make_template(REPO_VERSION_ID, "wordpress-xss-001", "high",
                       tags=["wordpress", "xss", "cve"], protocols=["http"],
                       cve_ids=["CVE-2022-99001"]),
        _make_template(REPO_VERSION_ID, "apache-rce-001", "high",
                       tags=["apache", "rce"], protocols=["http"],
                       name="Apache RCE Detection"),
        # Medium severity — headless
        _make_template(REPO_VERSION_ID, "dom-xss-headless", "medium",
                       tags=["xss", "dast"], protocols=["headless", "http"],
                       relative_path="dast/vulnerabilities/xss/dom-xss.yaml",
                       policy_details={"policy_version": "v1.2.0", "headless_requirement": True, "oast_requirement": False, "authentication_requirements": False, "required_variables": [], "eligibility_reasons": ["eligible"], "official_exclusion_matches": [], "execution_requirements": {"headless": True, "interactsh": False, "authentication": False, "required_variables": []}}),
        # Info severity
        _make_template(REPO_VERSION_ID, "tech-detect-001", "info",
                       tags=["tech", "detection"], protocols=["http"]),
        _make_template(REPO_VERSION_ID, "ssl-cert-check", "info",
                       tags=["ssl", "cert"], protocols=["ssl"]),
        # Network protocol
        _make_template(REPO_VERSION_ID, "redis-detect", "medium",
                       tags=["redis", "network"], protocols=["network"]),
        # Ineligible template (official ignore)
        _make_template(REPO_VERSION_ID, "dos-template-001", "high",
                       tags=["dos", "ineligible"], protocols=["http"],
                       sequential_eligible=False, independent_eligible=False,
                       security_status="ineligible",
                       policy_details={"policy_version": "v1.2.0", "headless_requirement": False, "oast_requirement": False, "authentication_requirements": False, "required_variables": [], "eligibility_reasons": ["official_ignore"], "official_exclusion_matches": ["tag:dos"], "execution_requirements": {}}),
        # Auth required template
        _make_template(REPO_VERSION_ID, "auth-bypass-001", "high",
                       tags=["auth", "bypass"], protocols=["http"],
                       policy_details={"policy_version": "v1.2.0", "headless_requirement": False, "oast_requirement": False, "authentication_requirements": True, "required_variables": ["username", "password"], "eligibility_reasons": ["eligible"], "official_exclusion_matches": [], "execution_requirements": {"headless": False, "interactsh": False, "authentication": True, "required_variables": ["username", "password"]}}),
    ]

    session.bulk_insert_mappings(NucleiTemplate, templates)
    session.commit()
    session.close()
    return len([t for t in templates if t["sequential_eligible"]])


# ===========================================================================
# GROUP 1: DAST v1.2.0 Classification
# ===========================================================================

class TestDASTClassificationV120:
    """Test that DAST templates are evaluated individually under Policy v1.2.0."""

    def _make_metadata(self, path, protocols=None, tags=None, template_id="test-id"):
        return TemplateMetadata(
            template_id=template_id,
            relative_path=path,
            content_hash="a" * 64,
            name="Test Template",
            author=["testauthor"],
            severity="medium",
            description=None,
            remediation=None,
            tags=tags or [],
            reference=[],
            cve_id=None,
            cwe_ids=[],
            cvss_score=None,
            cvss_vector=None,
            verified=False,
            max_request=None,
            shodan_query=None,
            fofa_query=None,
            google_dork=None,
            protocols=protocols or ["http"],
            is_workflow=False,
            is_self_contained=False,
            has_flow=False,
            _raw_info={},
        )

    def test_v12_policy_version_string(self):
        policy = ClassificationPolicy.v1_2()
        assert policy.policy_version == "v1.2.0"

    def test_dast_not_in_ineligible_protocols(self):
        """'dast' must NOT be in ineligible_protocols — it is a folder name, not a protocol."""
        policy = ClassificationPolicy.v1_2()
        assert "dast" not in policy.ineligible_protocols

    def test_dast_http_template_eligible(self):
        """DAST http template without unsafe directives → eligible."""
        policy = ClassificationPolicy.v1_2()
        classifier = EligibilityClassifier(policy)
        meta = self._make_metadata("dast/vulnerabilities/sqli/sqli-error-based.yaml", protocols=["http"])
        result = classifier.classify(meta, IgnoreRuleSet.empty(), "test-version-id")
        assert result.sequential_eligible is True
        assert result.independent_eligible is True
        assert RC_ELIGIBLE in result.eligibility_reasons

    def test_dast_headless_template_eligible(self):
        """DAST headless+http template → eligible."""
        policy = ClassificationPolicy.v1_2()
        classifier = EligibilityClassifier(policy)
        meta = self._make_metadata(
            "dast/vulnerabilities/xss/dom-xss.yaml",
            protocols=["http", "headless"]
        )
        result = classifier.classify(meta, IgnoreRuleSet.empty(), "test-version-id")
        assert result.sequential_eligible is True
        assert RC_ELIGIBLE in result.eligibility_reasons

    def test_dast_oast_template_eligible(self):
        """DAST http template with OAST content → eligible (interactsh requirement noted)."""
        policy = ClassificationPolicy.v1_2()
        classifier = EligibilityClassifier(policy)
        meta = self._make_metadata(
            "dast/cves/2021/CVE-2021-45046-DAST.yaml",
            protocols=["http"]
        )
        raw_yaml = "id: test\ninfo:\n  name: test\nhttp:\n  - raw:\n    - |\n      GET /path?x={{interactsh-url}} HTTP/1.1\n"
        result = classifier.classify(meta, IgnoreRuleSet.empty(), "test-version-id", raw_yaml)
        assert result.sequential_eligible is True
        assert result.execution_requirements["interactsh"] is True

    def test_dast_official_ignore_excluded(self):
        """DAST templates matching .nuclei-ignore are excluded."""
        policy = ClassificationPolicy.v1_2()
        classifier = EligibilityClassifier(policy)
        ignore = IgnoreRuleSet(excluded_tags={"dos"}, excluded_files=set())
        meta = self._make_metadata("dast/some-dos-template.yaml", tags=["dos"])
        result = classifier.classify(meta, ignore, "test-version-id")
        assert result.sequential_eligible is False
        assert RC_OFFICIAL_IGNORE in result.eligibility_reasons

    def test_dast_unsafe_true_excluded(self):
        """DAST template with 'unsafe: true' → RC_UNSAFE_BEHAVIOR, ineligible."""
        policy = ClassificationPolicy.v1_2()
        classifier = EligibilityClassifier(policy)
        meta = self._make_metadata("dast/vulnerabilities/unsafe.yaml", protocols=["http"])
        raw_yaml = "id: test\ninfo:\n  name: test\nhttp:\n  - unsafe: true\n    raw:\n    - GET / HTTP/1.1\n"
        result = classifier.classify(meta, IgnoreRuleSet.empty(), "test-version-id", raw_yaml)
        assert result.sequential_eligible is False
        assert RC_UNSAFE_BEHAVIOR in result.eligibility_reasons

    def test_dast_mutating_method_excluded(self):
        """DAST template with DELETE/PUT/PATCH method → RC_UNSAFE_BEHAVIOR."""
        policy = ClassificationPolicy.v1_2()
        classifier = EligibilityClassifier(policy)
        meta = self._make_metadata("dast/vulnerabilities/delete-test.yaml", protocols=["http"])
        raw_yaml = "id: test\ninfo:\n  name: test\nhttp:\n  - method: DELETE\n    path:\n      - '{{BaseURL}}/resource'\n"
        result = classifier.classify(meta, IgnoreRuleSet.empty(), "test-version-id", raw_yaml)
        assert result.sequential_eligible is False
        assert RC_UNSAFE_BEHAVIOR in result.eligibility_reasons

    def test_dast_ai_category_unresolved(self):
        """AI DAST templates → RC_DAST_AI_UNRESOLVED, ineligible pending team decision."""
        policy = ClassificationPolicy.v1_2()
        classifier = EligibilityClassifier(policy)
        meta = self._make_metadata("dast/ai/ai-prompt-injection.yaml", protocols=["http"], tags=["ai", "dast"])
        result = classifier.classify(meta, IgnoreRuleSet.empty(), "test-version-id")
        assert result.sequential_eligible is False
        assert RC_DAST_AI_UNRESOLVED in result.eligibility_reasons

    def test_dast_non_ai_not_dast_ai_unresolved(self):
        """Non-AI DAST template must NOT get RC_DAST_AI_UNRESOLVED."""
        policy = ClassificationPolicy.v1_2()
        classifier = EligibilityClassifier(policy)
        meta = self._make_metadata("dast/vulnerabilities/sqli/sqli-error-based.yaml",
                                    protocols=["http"], tags=["sqli", "dast"])
        result = classifier.classify(meta, IgnoreRuleSet.empty(), "test-version-id")
        assert RC_DAST_AI_UNRESOLVED not in result.eligibility_reasons
        assert result.sequential_eligible is True

    def test_dast_command_injection_official_ignore(self):
        """
        unix-command-injection.yaml and windows-command-injection.yaml are in .nuclei-ignore.
        They must be excluded via official_ignore, not dast_review_required.
        """
        policy = ClassificationPolicy.v1_2()
        classifier = EligibilityClassifier(policy)
        ignore = IgnoreRuleSet(
            excluded_tags=set(),
            excluded_files={
                "dast/vulnerabilities/injection/unix-command-injection.yaml",
                "dast/vulnerabilities/injection/windows-command-injection.yaml",
            }
        )
        for path in [
            "dast/vulnerabilities/injection/unix-command-injection.yaml",
            "dast/vulnerabilities/injection/windows-command-injection.yaml",
        ]:
            meta = self._make_metadata(path, protocols=["http"], template_id=path.split("/")[-1].replace(".yaml", ""))
            result = classifier.classify(meta, ignore, "test-version-id")
            assert result.sequential_eligible is False
            assert RC_OFFICIAL_IGNORE in result.eligibility_reasons

    def test_dast_code_protocol_still_ineligible(self):
        """DAST templates using 'code' protocol are still ineligible (code not supported)."""
        policy = ClassificationPolicy.v1_2()
        classifier = EligibilityClassifier(policy)
        meta = self._make_metadata("dast/code/some-code-template.yaml", protocols=["code"])
        result = classifier.classify(meta, IgnoreRuleSet.empty(), "test-version-id")
        assert result.sequential_eligible is False
        assert RC_UNSUPPORTED_PROTOCOL in result.eligibility_reasons

    def test_v11_policy_dast_still_ineligible_by_path(self):
        """
        Policy v1.1.0 compat: DAST templates are still ineligible under v1.1.0
        because 'dast' was in ineligible_protocols. Under v1.2.0 this changes.
        Confirm the behavioral difference.
        """
        policy_v11 = ClassificationPolicy.v1_1()
        policy_v12 = ClassificationPolicy.v1_2()

        # Under v1.1.0, 'dast' in ineligible_protocols — but Nuclei DAST templates
        # use 'http' as actual protocol key, NOT 'dast'. So v1.1.0 blocked them via
        # unsafe_dast_subdirs path check → RC_DAST_REVIEW.
        # Under v1.2.0, the same template is eligible (no unsafe directives, not AI).
        classifier_v12 = EligibilityClassifier(policy_v12)
        meta = TemplateMetadata(
            template_id="sqli-test", relative_path="dast/vulnerabilities/sqli/sqli-error-based.yaml",
            content_hash="a" * 64, name="SQLi Test", author=["testauthor"],
            severity="high", description=None, remediation=None, tags=["sqli"],
            reference=[], cve_id=None, cwe_ids=[], cvss_score=None, cvss_vector=None,
            verified=False, max_request=None, shodan_query=None, fofa_query=None,
            google_dork=None, protocols=["http"], is_workflow=False,
            is_self_contained=False, has_flow=False, _raw_info={},
        )
        result = classifier_v12.classify(meta, IgnoreRuleSet.empty(), "test-id")
        assert result.sequential_eligible is True, "v1.2.0: DAST http templates should be eligible"


# ===========================================================================
# GROUP 2: DB Schema Verification (17 columns)
# ===========================================================================

class TestDBSchema17Columns:
    """Verify the 17-column nuclei_templates schema is correct."""

    REQUIRED_COLUMNS = [
        "id", "repository_version_id", "template_id", "name", "description",
        "severity", "tags", "protocols", "cve_ids", "cwe_ids",
        "relative_path", "content_hash", "security_status",
        "sequential_eligible", "independent_eligible",
        "metadata",           # aliased as template_metadata in Python
        "policy_details",
    ]

    def test_all_17_columns_exist(self, pg_engine):
        """All 17 required columns — and ONLY those 17 columns — must exist in nuclei_templates."""
        with pg_engine.connect() as conn:
            result = conn.execute(text(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name = 'nuclei_templates' "
                "ORDER BY ordinal_position"
            ))
            existing = {row[0] for row in result}

        for col in self.REQUIRED_COLUMNS:
            assert col in existing, f"Missing required column: '{col}'"
        assert "created_at" not in existing, "Unexpected 18th column 'created_at' still present"
        assert existing == set(self.REQUIRED_COLUMNS), f"Schema mismatch: {existing ^ set(self.REQUIRED_COLUMNS)}"
        assert len(existing) == 17

    def test_no_separate_cvss_author_columns(self, pg_engine):
        """cvss_score, author, references, remediation, created_at must be in JSONB, not top-level columns."""
        with pg_engine.connect() as conn:
            result = conn.execute(text(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name = 'nuclei_templates'"
            ))
            existing = {row[0] for row in result}

        # These were in the old schema / unapproved additions and must live in JSONB
        should_not_be_columns = {"cvss_score", "cvss_vector", "author", "remediation",
                                  "reference_urls", "exclusion_reason", "exclusion_reasons",
                                  "requires_headless", "requires_interactsh",
                                  "requires_authentication", "requires_variables",
                                  "created_at"}
        for col in should_not_be_columns:
            assert col not in existing, (
                f"Column '{col}' should be in JSONB metadata/policy_details, not a top-level column"
            )

    def test_sort_field_and_indexed_at_contract(self, pg_engine, pg_session, db_version):
        """SortField matches the 17-column schema (no created_at) and indexed_at comes from policy_details."""
        assert [f.value for f in SortField] == ["template_id", "severity", "relative_path"]
        _seed_templates(pg_session, db_version)
        session = pg_session()
        svc = TemplateSelectionService(session=session)
        try:
            rec = svc.get_template(REPO_VERSION_ID, "wordpress-xss-001")
            assert rec is not None
            assert rec.indexed_at == "2026-11-27T16:28:36.745562+00:00"
            # Verify fallback sort queries execute cleanly without NucleiTemplate.created_at
            res = svc.query_templates(
                REPO_VERSION_ID,
                scan_mode=ScanMode.INDEPENDENT,
                sort_by=SortField.RELATIVE_PATH,
            )
            assert res.total_count > 0
        finally:
            session.close()

    def test_policy_details_jsonb_stores_execution_requirements(self, pg_engine, pg_session, db_version):
        """policy_details JSONB stores execution requirements correctly."""
        with pg_engine.connect() as conn:
            row = conn.execute(text(
                "SELECT policy_details FROM nuclei_templates "
                "WHERE repository_version_id = :vid LIMIT 1"
            ), {"vid": REPO_VERSION_ID}).fetchone()

        if not row:
            _seed_templates(pg_session, db_version)
            with pg_engine.connect() as conn:
                row = conn.execute(text(
                    "SELECT policy_details FROM nuclei_templates "
                    "WHERE repository_version_id = :vid LIMIT 1"
                ), {"vid": REPO_VERSION_ID}).fetchone()

        assert row is not None, "Failed to retrieve template row for policy_details test"
        pd = row[0]
        assert isinstance(pd, dict)
        assert "headless_requirement" in pd or "execution_requirements" in pd

    def test_metadata_jsonb_stores_author_and_cvss(self, pg_engine, pg_session, db_version):
        """metadata JSONB stores author, cvss_score, references, remediation."""
        with pg_engine.connect() as conn:
            row = conn.execute(text(
                "SELECT metadata FROM nuclei_templates "
                "WHERE repository_version_id = :vid LIMIT 1"
            ), {"vid": REPO_VERSION_ID}).fetchone()

        if not row:
            _seed_templates(pg_session, db_version)
            with pg_engine.connect() as conn:
                row = conn.execute(text(
                    "SELECT metadata FROM nuclei_templates "
                    "WHERE repository_version_id = :vid LIMIT 1"
                ), {"vid": REPO_VERSION_ID}).fetchone()

        assert row is not None, "Failed to retrieve template row for metadata test"
        meta = row[0]
        assert isinstance(meta, dict)
        # Required metadata fields
        for field_name in ("author", "cvss_score", "references", "remediation"):
            assert field_name in meta, f"metadata JSONB missing '{field_name}'"


# ===========================================================================
# GROUP 3: Selection Service — Sequential Set
# ===========================================================================

class TestSequentialSetContract:
    """Test the sequential scan set retrieval contract."""

    @pytest.fixture(autouse=True)
    def seed(self, pg_session, db_version):
        _seed_templates(pg_session, db_version)

    def test_sequential_set_returns_only_eligible(self, pg_session):
        """get_sequential_set() returns only sequential_eligible=True templates."""
        session = pg_session()
        service = TemplateSelectionService(session=session)
        try:
            templates = service.get_sequential_set(REPO_VERSION_ID)
            assert all(t.sequential_eligible for t in templates)
            assert all(t.security_status == "eligible" for t in templates)
        finally:
            session.close()

    def test_sequential_set_excludes_ineligible(self, pg_session):
        """dos-template-001 (ineligible) must NOT appear in sequential set."""
        session = pg_session()
        service = TemplateSelectionService(session=session)
        try:
            templates = service.get_sequential_set(REPO_VERSION_ID)
            tids = [t.template_id for t in templates]
            assert "dos-template-001" not in tids
        finally:
            session.close()

    def test_sequential_set_includes_all_severity_levels(self, pg_session):
        """Sequential set must include templates of all severity levels."""
        session = pg_session()
        service = TemplateSelectionService(session=session)
        try:
            templates = service.get_sequential_set(REPO_VERSION_ID)
            severities = {t.severity for t in templates}
            # Should have at least critical, high, medium, info
            assert "critical" in severities
            assert "high" in severities
            assert "info" in severities
        finally:
            session.close()

    def test_sequential_set_deterministic_order(self, pg_session):
        """Two calls to get_sequential_set() must return the same order."""
        session = pg_session()
        service = TemplateSelectionService(session=session)
        try:
            set1 = [t.template_id for t in service.get_sequential_set(REPO_VERSION_ID)]
            set2 = [t.template_id for t in service.get_sequential_set(REPO_VERSION_ID)]
            assert set1 == set2
        finally:
            session.close()

    def test_sequential_set_includes_dast_eligible(self, pg_session):
        """DAST-sourced templates that are eligible must appear in sequential set."""
        session = pg_session()
        service = TemplateSelectionService(session=session)
        try:
            templates = service.get_sequential_set(REPO_VERSION_ID)
            tids = [t.template_id for t in templates]
            # CVE-2022-22965 is in dast/ path but was seeded as eligible
            assert "CVE-2022-22965" in tids
        finally:
            session.close()


# ===========================================================================
# GROUP 4: Independent Scan Filters (6 dimensions)
# ===========================================================================

class TestIndependentScanFilters:
    """Test all 6 filter dimensions with OR/AND logic."""

    @pytest.fixture(autouse=True)
    def seed(self, pg_session, db_version):
        _seed_templates(pg_session, db_version)

    def _service(self, pg_session):
        s = pg_session()
        return TemplateSelectionService(session=s), s

    def test_filter_by_template_id(self, pg_session):
        """Filter by template_id: OR among values."""
        svc, session = self._service(pg_session)
        try:
            result = svc.query_templates(
                REPO_VERSION_ID,
                filters=TemplateFilter(template_ids=["CVE-2021-44228", "CVE-2022-22965"]),
                scan_mode=ScanMode.INDEPENDENT,
            )
            tids = [t.template_id for t in result.templates]
            assert "CVE-2021-44228" in tids
            assert "CVE-2022-22965" in tids
            assert all(tid in ["CVE-2021-44228", "CVE-2022-22965"] for tid in tids)
        finally:
            session.close()

    def test_filter_by_name_search(self, pg_session):
        """Filter by name: ILIKE partial match, OR among values."""
        svc, session = self._service(pg_session)
        try:
            result = svc.query_templates(
                REPO_VERSION_ID,
                filters=TemplateFilter(name_search=["Apache"]),
                scan_mode=ScanMode.INDEPENDENT,
            )
            assert any("apache" in t.name.lower() for t in result.templates)
        finally:
            session.close()

    def test_filter_by_cve_id(self, pg_session):
        """Filter by CVE ID: exact array containment, OR among values."""
        svc, session = self._service(pg_session)
        try:
            result = svc.query_templates(
                REPO_VERSION_ID,
                filters=TemplateFilter(cve_ids=["CVE-2021-44228"]),
                scan_mode=ScanMode.INDEPENDENT,
            )
            assert result.total_count >= 1
            assert all("CVE-2021-44228" in t.cve_ids for t in result.templates)
        finally:
            session.close()

    def test_filter_by_tags_or_logic(self, pg_session):
        """Filter by tags: OR within list — template must have AT LEAST ONE specified tag."""
        svc, session = self._service(pg_session)
        try:
            result = svc.query_templates(
                REPO_VERSION_ID,
                filters=TemplateFilter(tags=["log4j", "ssl"]),
                scan_mode=ScanMode.INDEPENDENT,
            )
            tids = {t.template_id for t in result.templates}
            assert "CVE-2021-44228" in tids
            assert "ssl-cert-check" in tids
            for t in result.templates:
                assert ("log4j" in t.tags) or ("ssl" in t.tags)
        finally:
            session.close()

    def test_filter_by_severity_or_logic(self, pg_session):
        """Filter by severity: OR among values."""
        svc, session = self._service(pg_session)
        try:
            result = svc.query_templates(
                REPO_VERSION_ID,
                filters=TemplateFilter(severities=["critical", "high"]),
                scan_mode=ScanMode.INDEPENDENT,
            )
            assert result.total_count >= 1
            for t in result.templates:
                assert t.severity in ("critical", "high")
        finally:
            session.close()

    def test_filter_by_protocol_or_logic(self, pg_session):
        """Filter by protocol: OR among values."""
        svc, session = self._service(pg_session)
        try:
            result = svc.query_templates(
                REPO_VERSION_ID,
                filters=TemplateFilter(protocols=["ssl"]),
                scan_mode=ScanMode.INDEPENDENT,
            )
            for t in result.templates:
                assert "ssl" in t.protocols
        finally:
            session.close()

    def test_filter_cross_dimension_and_logic(self, pg_session):
        """Multiple filter dimensions: AND between dimensions (while tags uses OR within itself)."""
        svc, session = self._service(pg_session)
        try:
            result = svc.query_templates(
                REPO_VERSION_ID,
                filters=TemplateFilter(
                    severities=["critical"],
                    protocols=["http"],
                    cve_ids=["CVE-2021-44228"],
                ),
                scan_mode=ScanMode.INDEPENDENT,
            )
            for t in result.templates:
                assert t.severity == "critical"
                assert "http" in t.protocols
                assert "CVE-2021-44228" in t.cve_ids

            # OR within tags + AND with severity
            result_tags_sev = svc.query_templates(
                REPO_VERSION_ID,
                filters=TemplateFilter(
                    tags=["log4j", "ssl"],
                    severities=["critical"],
                ),
                scan_mode=ScanMode.INDEPENDENT,
            )
            tids = {t.template_id for t in result_tags_sev.templates}
            assert "CVE-2021-44228" in tids
            assert "ssl-cert-check" not in tids
            for t in result_tags_sev.templates:
                assert t.severity == "critical"
                assert ("log4j" in t.tags) or ("ssl" in t.tags)
        finally:
            session.close()


# ===========================================================================
# GROUP 5: Pagination
# ===========================================================================

class TestPagination:
    """Test server-side pagination."""

    @pytest.fixture(autouse=True)
    def seed(self, pg_session, db_version):
        _seed_templates(pg_session, db_version)

    def test_pagination_first_page(self, pg_session):
        """First page returns correct slice."""
        session = pg_session()
        svc = TemplateSelectionService(session=session)
        try:
            result = svc.query_templates(
                REPO_VERSION_ID,
                pagination=PaginationParams(page=1, page_size=3),
            )
            assert len(result.templates) <= 3
            assert result.page == 1
            assert result.total_pages >= 1
        finally:
            session.close()

    def test_pagination_total_count_matches_all_pages(self, pg_session):
        """total_count is consistent across pages."""
        session = pg_session()
        svc = TemplateSelectionService(session=session)
        try:
            full = svc.query_templates(REPO_VERSION_ID)
            p1 = svc.query_templates(REPO_VERSION_ID, pagination=PaginationParams(page=1, page_size=3))
            assert p1.total_count == full.total_count
        finally:
            session.close()

    def test_pagination_no_overlap(self, pg_session):
        """Page 1 and page 2 must not share template IDs."""
        session = pg_session()
        svc = TemplateSelectionService(session=session)
        try:
            p1 = svc.query_templates(REPO_VERSION_ID, pagination=PaginationParams(page=1, page_size=3))
            p2 = svc.query_templates(REPO_VERSION_ID, pagination=PaginationParams(page=2, page_size=3))
            tids1 = {t.template_id for t in p1.templates}
            tids2 = {t.template_id for t in p2.templates}
            assert tids1.isdisjoint(tids2), "Pages must not overlap"
        finally:
            session.close()


# ===========================================================================
# GROUP 6: Validation and Security
# ===========================================================================

class TestValidationAndSecurity:
    """Test template selection validation and security guarantees."""

    @pytest.fixture(autouse=True)
    def seed(self, pg_session, db_version):
        _seed_templates(pg_session, db_version)

    def test_staging_version_flagged_in_validation(self, pg_session):
        """Staging versions produce a warning error in validate_selection."""
        session = pg_session()
        svc = TemplateSelectionService(session=session)
        try:
            result = svc.validate_selection(
                REPO_VERSION_ID,
                template_ids=["CVE-2021-44228"],
                scan_mode=ScanMode.INDEPENDENT,
            )
            assert result.valid is False
            assert any("staging" in err.lower() for err in result.errors)
        finally:
            session.close()

    def test_ineligible_template_blocked(self, pg_session):
        """Ineligible templates appear in ineligible_ids, not eligible_ids."""
        session = pg_session()
        svc = TemplateSelectionService(session=session)
        try:
            result = svc.validate_selection(
                REPO_VERSION_ID,
                template_ids=["dos-template-001"],
                scan_mode=ScanMode.INDEPENDENT,
            )
            assert "dos-template-001" in result.ineligible_ids
            assert "dos-template-001" not in result.eligible_ids
        finally:
            session.close()

    def test_nonexistent_template_invalid(self, pg_session):
        """Non-existent template_ids appear in invalid_ids."""
        session = pg_session()
        svc = TemplateSelectionService(session=session)
        try:
            result = svc.validate_selection(
                REPO_VERSION_ID,
                template_ids=["this-template-does-not-exist"],
            )
            assert "this-template-does-not-exist" in result.invalid_ids
        finally:
            session.close()

    def test_deduplication_in_validation(self, pg_session):
        """Duplicate template_ids in input are deduplicated before validation."""
        session = pg_session()
        svc = TemplateSelectionService(session=session)
        try:
            result = svc.validate_selection(
                REPO_VERSION_ID,
                template_ids=["CVE-2021-44228", "CVE-2021-44228", "CVE-2021-44228"],
            )
            # Count should not triple-count the same template
            assert result.requested_count == 1
        finally:
            session.close()

    def test_invalid_template_id_format_rejected(self, pg_session):
        """Template IDs with dangerous characters are rejected."""
        session = pg_session()
        svc = TemplateSelectionService(session=session)
        try:
            result = svc.validate_selection(
                REPO_VERSION_ID,
                template_ids=["../../etc/passwd", "'; DROP TABLE nuclei_templates; --"],
            )
            assert result.valid is False
            assert len(result.errors) > 0
        finally:
            session.close()

    def test_cannot_query_ineligible_via_filter(self, pg_session):
        """Filter queries must ONLY return eligible templates."""
        session = pg_session()
        svc = TemplateSelectionService(session=session)
        try:
            result = svc.query_templates(
                REPO_VERSION_ID,
                filters=TemplateFilter(tags=["dos"]),
                scan_mode=ScanMode.INDEPENDENT,
            )
            # dos-template-001 has tag "dos" but is ineligible → must not appear
            assert all(t.independent_eligible for t in result.templates)
            assert "dos-template-001" not in [t.template_id for t in result.templates]
        finally:
            session.close()

    def test_filter_validation_rejects_bad_severity(self):
        """TemplateFilter.validate() catches invalid severity values."""
        f = TemplateFilter(severities=["ultra-critical"])
        errors = f.validate()
        assert len(errors) > 0
        assert "severity" in errors[0].lower()

    def test_filter_validation_rejects_bad_cve_format(self):
        """TemplateFilter.validate() catches bad CVE format."""
        f = TemplateFilter(cve_ids=["NOT-A-CVE"])
        errors = f.validate()
        assert len(errors) > 0


# ===========================================================================
# GROUP 7: Preview and Execution Requirements
# ===========================================================================

class TestSelectionPreview:
    """Test selection preview with execution requirement reporting."""

    @pytest.fixture(autouse=True)
    def seed(self, pg_session, db_version):
        _seed_templates(pg_session, db_version)

    def test_preview_reports_headless_count(self, pg_session):
        """Preview counts templates requiring headless browser."""
        session = pg_session()
        svc = TemplateSelectionService(session=session)
        try:
            preview = svc.preview_selection(
                REPO_VERSION_ID,
                template_ids=["dom-xss-headless", "CVE-2021-44228"],
                scan_mode=ScanMode.INDEPENDENT,
            )
            # dom-xss-headless requires headless
            assert preview.requires_headless_count >= 1
        finally:
            session.close()

    def test_preview_reports_staging_warning(self, pg_session):
        """Preview warns when version is in staging state."""
        session = pg_session()
        svc = TemplateSelectionService(session=session)
        try:
            preview = svc.preview_selection(
                REPO_VERSION_ID,
                template_ids=["CVE-2021-44228"],
            )
            assert preview.is_staging is True
            assert any("staging" in w.lower() for w in preview.warnings)
        finally:
            session.close()

    def test_preview_does_not_silently_drop_incompatible(self, pg_session):
        """Preview reports incompatible templates; does NOT silently remove them."""
        session = pg_session()
        svc = TemplateSelectionService(session=session)
        try:
            # Request an ineligible template explicitly
            preview = svc.preview_selection(
                REPO_VERSION_ID,
                template_ids=["CVE-2021-44228", "dos-template-001"],
                scan_mode=ScanMode.INDEPENDENT,
            )
            # dos-template-001 is ineligible and should appear in incompatible_templates
            incompat_ids = [i["template_id"] for i in preview.incompatible_templates]
            assert "dos-template-001" in incompat_ids
        finally:
            session.close()

    def test_preview_severity_distribution(self, pg_session):
        """Preview by_severity distribution sums to total_selected."""
        session = pg_session()
        svc = TemplateSelectionService(session=session)
        try:
            preview = svc.preview_selection(
                REPO_VERSION_ID,
                template_ids=["CVE-2021-44228", "CVE-2022-22965", "tech-detect-001"],
                scan_mode=ScanMode.INDEPENDENT,
            )
            total_in_sev = sum(preview.by_severity.values())
            assert total_in_sev == preview.total_selected
        finally:
            session.close()


# ===========================================================================
# GROUP 8: Available Filters Enumeration
# ===========================================================================

class TestAvailableFilters:
    """Test filter value enumeration."""

    @pytest.fixture(autouse=True)
    def seed(self, pg_session, db_version):
        _seed_templates(pg_session, db_version)

    def test_available_filters_includes_known_severity(self, pg_session):
        """get_available_filters() returns at least 'critical' and 'high'."""
        session = pg_session()
        svc = TemplateSelectionService(session=session)
        try:
            filters = svc.get_available_filters(REPO_VERSION_ID)
            assert "critical" in filters.severities
            assert "high" in filters.severities
        finally:
            session.close()

    def test_available_filters_has_cve_templates(self, pg_session):
        """has_cve_templates is True when CVE templates exist."""
        session = pg_session()
        svc = TemplateSelectionService(session=session)
        try:
            filters = svc.get_available_filters(REPO_VERSION_ID)
            assert filters.has_cve_templates is True
        finally:
            session.close()

    def test_eligible_counts_match_actual(self, pg_session):
        """total_eligible_sequential count matches actual DB query."""
        session = pg_session()
        svc = TemplateSelectionService(session=session)
        try:
            filters = svc.get_available_filters(REPO_VERSION_ID)
            # Also count directly
            direct_count = len(svc.get_sequential_set(REPO_VERSION_ID))
            assert filters.total_eligible_sequential == direct_count
        finally:
            session.close()


# ===========================================================================
# GROUP 9: Version Info
# ===========================================================================

class TestVersionInfo:
    """Test repository version info retrieval."""

    def test_get_version_info_staging_not_usable(self, pg_session, db_version):
        """Staging version must have is_usable_for_scan = False."""
        session = pg_session()
        svc = TemplateSelectionService(session=session)
        try:
            info = svc.get_version_info(REPO_VERSION_ID)
            assert info is not None
            assert info.status == "staging"
            assert info.is_usable_for_scan is False
        finally:
            session.close()

    def test_get_version_info_nonexistent_returns_none(self, pg_session):
        """Non-existent version returns None."""
        session = pg_session()
        svc = TemplateSelectionService(session=session)
        try:
            info = svc.get_version_info(str(uuid.uuid4()))
            assert info is None
        finally:
            session.close()


# ===========================================================================
# GROUP 10: Select All Matching (not just current page)
# ===========================================================================

class TestSelectAllMatching:
    """Test that the sequential set returns ALL matching templates, not just a page."""

    @pytest.fixture(autouse=True)
    def seed(self, pg_session, db_version):
        _seed_templates(pg_session, db_version)

    def test_sequential_set_returns_more_than_one_page(self, pg_session):
        """get_sequential_set() returns ALL eligible templates regardless of page size."""
        session = pg_session()
        svc = TemplateSelectionService(session=session)
        try:
            full_set = svc.get_sequential_set(REPO_VERSION_ID)
            # With a tiny page (3), paginated query would miss templates
            paged = svc.query_templates(
                REPO_VERSION_ID,
                scan_mode=ScanMode.SEQUENTIAL,
                pagination=PaginationParams(page=1, page_size=3),
            )
            # Full set should have more than 3 (we seeded 9 eligible)
            assert len(full_set) >= paged.total_count
        finally:
            session.close()


# ===========================================================================
# GROUP 11: Database Integrity — no silent PostgreSQL fallback
# ===========================================================================

class TestDatabaseIntegrity:
    """Test database configuration integrity."""

    def test_no_silent_sqlite_fallback(self, monkeypatch):
        """
        database.py must NOT silently fall back to SQLite when PostgreSQL fails.
        Simulating by calling _resolve_database_engine with a bad PG URL.
        """
        import importlib
        # Patch env to use a bad PG URL
        monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://invalid_user:invalid@localhost:9999/nonexistent")
        # Re-import to trigger resolution
        import database as db_module
        with pytest.raises(RuntimeError) as exc_info:
            db_module._resolve_database_engine()
        assert "postgresql" in str(exc_info.value).lower() or "connect" in str(exc_info.value).lower()


# ===========================================================================
# GROUP 12: Zero Regression — Phase 1 & 2/3 Behavior
# ===========================================================================

class TestZeroRegression:
    """Ensure Phase 5 changes do not break Phase 1, 2, 3 behavior."""

    def test_v11_policy_still_constructable(self):
        """ClassificationPolicy.v1_1() must still work for backward compat."""
        policy = ClassificationPolicy.v1_1()
        assert policy.policy_version == "v1.1.0"
        assert "dast" in policy.ineligible_protocols  # v1.1.0 behavior preserved

    def test_v10_policy_still_constructable(self):
        """ClassificationPolicy.v1() (v1.0.0) must still work."""
        policy = ClassificationPolicy.v1()
        assert policy.policy_version == "v1.0.0"

    def test_rc_dast_review_alias_still_valid(self):
        """RC_DAST_REVIEW is now an alias for RC_DAST_AI_UNRESOLVED — both must equal same string."""
        from core.template_eligibility import RC_DAST_REVIEW, RC_DAST_AI_UNRESOLVED
        assert RC_DAST_REVIEW == RC_DAST_AI_UNRESOLVED

    def test_ignore_ruleset_bare_filename_matching(self):
        """IgnoreRuleSet bare filename matching still works (Phase 1 fix)."""
        ignore = IgnoreRuleSet(
            excluded_tags=set(),
            excluded_files={"aaaa-fingerprint.yaml"}
        )
        matches = ignore.get_all_matches("aaaa-fingerprint", [], "dns/aaaa-fingerprint.yaml")
        assert len(matches) > 0

    def test_official_ignore_all_213_matches_preserved(self):
        """
        Multi-reason retention: templates matching multiple ignore rules retain all matches.
        """
        ignore = IgnoreRuleSet(
            excluded_tags={"dos"},
            excluded_files={"http/some-dos-file.yaml"}
        )
        matches = ignore.get_all_matches(
            "some-dos-file",
            ["dos"],
            "http/some-dos-file.yaml"
        )
        # Should have both file match and tag match
        assert len(matches) >= 2

    def test_valid_reason_codes_includes_v12_code(self):
        """VALID_REASON_CODES includes RC_DAST_AI_UNRESOLVED."""
        from core.template_eligibility import VALID_REASON_CODES
        assert RC_DAST_AI_UNRESOLVED in VALID_REASON_CODES

    def test_classification_service_defaults_to_v12(self):
        """TemplateClassificationService must default to v1.2.0 policy."""
        from core.template_classification_service import TemplateClassificationService
        svc = TemplateClassificationService()
        assert svc.policy.policy_version == "v1.2.0"


# ===========================================================================
# GROUP 13: Phase 6 Advanced Capabilities
# ===========================================================================

class TestPhase6AdvancedCapabilities:
    """Verify Phase 6 enhancements: paginated tags, multi-page selection, readiness evaluation."""

    @pytest.fixture(autouse=True)
    def seed(self, pg_session, db_version):
        _seed_templates(pg_session, db_version)

    def test_get_all_tags_pagination_and_search(self, pg_session):
        """get_all_tags returns paginated tags and supports filtering by search term."""
        session = pg_session()
        service = TemplateSelectionService(session=session)
        try:
            # Query all tags with page_size=3
            res = service.get_all_tags(
                repository_version_id=REPO_VERSION_ID,
                scan_mode=ScanMode.INDEPENDENT,
                page=1,
                page_size=3,
            )
            assert isinstance(res, PaginatedTagsResult)
            assert res.total_tags > 0
            assert res.page == 1
            assert res.page_size == 3
            assert len(res.tags) <= 3
            assert all("tag" in item and "count" in item for item in res.tags)

            # Query with search filter
            res_search = service.get_all_tags(
                repository_version_id=REPO_VERSION_ID,
                scan_mode=ScanMode.INDEPENDENT,
                search="xss",
            )
            assert res_search.total_tags > 0
            assert all("xss" in item["tag"].lower() for item in res_search.tags)
        finally:
            session.close()

    def test_select_all_matching_ids(self, pg_session):
        """select_all_matching_ids returns all matching IDs deterministically across pages."""
        session = pg_session()
        service = TemplateSelectionService(session=session)
        try:
            ids = service.select_all_matching_ids(
                repository_version_id=REPO_VERSION_ID,
                scan_mode=ScanMode.INDEPENDENT,
                filters=TemplateFilter(severities=["high"]),
            )
            assert isinstance(ids, list)
            assert len(ids) >= 2
            # Deterministic sorting check
            assert ids == sorted(ids)
            assert "wordpress-xss-001" in ids
            assert "apache-rce-001" in ids
            # Ineligible templates must never be returned
            assert "dos-template-001" not in ids
        finally:
            session.close()

    def test_manage_selection_add_remove_dedup(self, pg_session):
        """manage_selection supports adding, removing, deduplicating, and rejecting ineligible."""
        session = pg_session()
        service = TemplateSelectionService(session=session)
        try:
            # 1. Add with duplicate and ineligible
            state = service.manage_selection(
                repository_version_id=REPO_VERSION_ID,
                scan_mode=ScanMode.INDEPENDENT,
                add_ids=["wordpress-xss-001", "apache-rce-001", "wordpress-xss-001", "dos-template-001"],
            )
            assert isinstance(state, SelectionState)
            assert "dos-template-001" in state.rejected_ineligible
            assert "dos-template-001" not in state.selected_ids
            assert "wordpress-xss-001" in state.selected_ids
            assert "apache-rce-001" in state.selected_ids
            assert len(state.selected_ids) == 2  # deduplicated

            # 2. Remove one
            state2 = service.manage_selection(
                repository_version_id=REPO_VERSION_ID,
                scan_mode=ScanMode.INDEPENDENT,
                current_selected_ids=state.selected_ids,
                remove_ids=["apache-rce-001"],
            )
            assert "apache-rce-001" not in state2.selected_ids
            assert "wordpress-xss-001" in state2.selected_ids
            assert len(state2.selected_ids) == 1

            # 3. Select all matching
            state3 = service.manage_selection(
                repository_version_id=REPO_VERSION_ID,
                scan_mode=ScanMode.INDEPENDENT,
                select_all_matching=True,
                filters=TemplateFilter(severities=["critical"]),
            )
            assert len(state3.selected_ids) >= 2
            assert "CVE-2021-44228" in state3.selected_ids
        finally:
            session.close()

    def test_evaluate_target_and_readiness(self, pg_session):
        """evaluate_target_and_readiness evaluates compatibility, readiness, and scope."""
        session = pg_session()
        service = TemplateSelectionService(session=session)
        try:
            # Case 1: Target URL in scope, but headless capability missing
            caps_no_headless = EnvironmentCapabilities(
                headless_available=False,
                interactsh_available=True,
                dast_inputs_available=True,
                authorized_scopes=["*.example.com", "example.com"],
            )
            eval1 = service.evaluate_target_and_readiness(
                repository_version_id=REPO_VERSION_ID,
                template_ids=["CVE-2021-44228", "dom-xss-headless"],
                target="https://app.example.com",
                environment_caps=caps_no_headless,
            )
            assert isinstance(eval1, TargetReadinessEvaluation)
            assert eval1.target_type in ("domain", "url")
            assert eval1.out_of_scope_count == 0
            # dom-xss-headless should not be ready due to missing headless
            headless_status = next((t for t in eval1.templates if t.template_id == "dom-xss-headless"), None)
            assert headless_status is not None
            assert headless_status.in_scope is True
            assert headless_status.execution_ready is False
            assert headless_status.overall_ready is False
            assert "headless_browser_unavailable" in headless_status.blocking_reasons

            # Case 2: Headless capability available -> becomes ready
            caps_with_headless = EnvironmentCapabilities(
                headless_available=True,
                interactsh_available=True,
                dast_inputs_available=True,
                authorized_scopes=["*.example.com", "example.com"],
            )
            eval2 = service.evaluate_target_and_readiness(
                repository_version_id=REPO_VERSION_ID,
                template_ids=["dom-xss-headless"],
                target="https://app.example.com",
                environment_caps=caps_with_headless,
            )
            headless_status2 = eval2.templates[0]
            assert headless_status2.execution_ready is True
            assert headless_status2.overall_ready is True

            # Case 3: Out of scope target
            eval3 = service.evaluate_target_and_readiness(
                repository_version_id=REPO_VERSION_ID,
                template_ids=["CVE-2021-44228"],
                target="https://unauthorized-domain.org",
                environment_caps=caps_with_headless,
            )
            assert eval3.out_of_scope_count == 1
            assert eval3.templates[0].in_scope is False
            assert eval3.templates[0].overall_ready is False
            assert any("out_of_scope" in r for r in eval3.templates[0].blocking_reasons)
        finally:
            session.close()

    def test_17_column_migration_preserves_created_at_no_loss(self):
        """Legacy 18-column table migration preserves created_at in policy_details.indexed_at before drop."""
        import json
        from init_db import _migrate_nuclei_templates_to_17_columns_sqlite

        eng = create_engine("sqlite:///:memory:")
        with eng.begin() as conn:
            conn.execute(text("""
                CREATE TABLE nuclei_templates (
                    id VARCHAR(36) PRIMARY KEY,
                    repository_version_id VARCHAR(36) NOT NULL,
                    template_id VARCHAR(255) NOT NULL,
                    name VARCHAR(500),
                    description TEXT,
                    severity VARCHAR(20) NOT NULL,
                    tags JSON NOT NULL DEFAULT '[]',
                    protocols JSON NOT NULL DEFAULT '[]',
                    cve_ids JSON NOT NULL DEFAULT '[]',
                    cwe_ids JSON NOT NULL DEFAULT '[]',
                    relative_path VARCHAR(500) NOT NULL,
                    content_hash VARCHAR(64) NOT NULL,
                    security_status VARCHAR(20) NOT NULL,
                    sequential_eligible BOOLEAN NOT NULL DEFAULT 0,
                    independent_eligible BOOLEAN NOT NULL DEFAULT 0,
                    metadata JSON NOT NULL DEFAULT '{}',
                    policy_details JSON NOT NULL DEFAULT '{}',
                    created_at TIMESTAMP NOT NULL
                )
            """))
            conn.execute(text(
                "INSERT INTO nuclei_templates VALUES ("
                "'11111111-1111-1111-1111-111111111111', 'v1', 'tpl-legacy', 'Legacy', 'desc', "
                "'high', '[]', '[\"http\"]', '[]', '[]', 'http/legacy.yaml', :h, 'eligible', 1, 1, '{}', '{\"policy_version\": \"v1.2.0\"}', "
                "'2026-11-27T16:28:36.745562+00:00')"
            ), {"h": "a" * 64})

            _migrate_nuclei_templates_to_17_columns_sqlite(conn)

            cols = [r[1] for r in conn.execute(text("PRAGMA table_info(nuclei_templates)")).fetchall()]
            assert len(cols) == 17
            assert "created_at" not in cols
            pd_raw = conn.execute(text("SELECT policy_details FROM nuclei_templates WHERE template_id = 'tpl-legacy'")).scalar()
            pd = json.loads(pd_raw) if isinstance(pd_raw, str) else pd_raw
            assert pd["indexed_at"] == "2026-11-27T16:28:36.745562+00:00"
            assert pd["policy_version"] == "v1.2.0"
        eng.dispose()
