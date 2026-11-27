"""
YemScan — Nuclei Template Catalog Database Model (Phase 4).

Persists the centralized catalog of parsed and classified Nuclei templates
associated with immutable repository versions.

Design rules:
- Uses PostgreSQL UUID, ARRAY, and JSONB types (with SQLite JSON fallback via with_variant).
- The Python attribute for the 'metadata' column is named 'template_metadata' to avoid
  collision with SQLAlchemy's reserved Declarative 'metadata' attribute.
- Table name is strictly 'nuclei_templates'.
- Enforces relational and security integrity constraints.
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    ForeignKey,
    Index,
    JSON,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import relationship

from database import Base


class NucleiTemplate(Base):
    """
    NucleiTemplate Model.

    Represents an executable security testing template indexed within a specific
    repository version snapshot.
    """
    __tablename__ = "nuclei_templates"

    # 1. Primary Key: UUID
    id = Column(
        UUID(as_uuid=True).with_variant(String(36), "sqlite"),
        primary_key=True,
        default=uuid.uuid4,
        nullable=False,
    )

    # 2. Foreign Key: Repository Version ID
    repository_version_id = Column(
        String(36),
        ForeignKey("template_repository_versions.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )

    # 3. Template Identifier (from YAML id)
    template_id = Column(String(255), nullable=False, index=True)

    # 4. Human-readable Name
    name = Column(String(500), nullable=True)

    # 5. Full Description
    description = Column(Text, nullable=True)

    # 6. Severity (info, low, medium, high, critical, unknown)
    severity = Column(String(20), nullable=False, default="unknown", index=True)

    # 7. Tags (array of strings)
    tags = Column(
        ARRAY(String).with_variant(JSON(), "sqlite"),
        nullable=False,
        default=list,
    )

    # 8. Protocols (array of canonical protocol strings)
    protocols = Column(
        ARRAY(String).with_variant(JSON(), "sqlite"),
        nullable=False,
        default=list,
    )

    # 9. CVE IDs (array of strings)
    cve_ids = Column(
        ARRAY(String).with_variant(JSON(), "sqlite"),
        nullable=False,
        default=list,
    )

    # 10. CWE IDs (array of strings)
    cwe_ids = Column(
        ARRAY(String).with_variant(JSON(), "sqlite"),
        nullable=False,
        default=list,
    )

    # 11. Relative Path (from snapshot root)
    relative_path = Column(String(500), nullable=False)

    # 12. SHA-256 Content Hash
    content_hash = Column(String(64), nullable=False)

    # 13. Security Eligibility Status (eligible, ineligible, conditional)
    security_status = Column(String(20), nullable=False, default="ineligible")

    # 14. Sequential Scan Eligibility
    sequential_eligible = Column(Boolean, nullable=False, default=False)

    # 15. Independent Scan Eligibility
    independent_eligible = Column(Boolean, nullable=False, default=False)

    # 16. Template Metadata JSONB (aliased to template_metadata to avoid Declarative collision)
    template_metadata = Column(
        "metadata",
        JSONB().with_variant(JSON(), "sqlite"),
        nullable=False,
        default=dict,
    )

    # 17. Policy Details JSONB (reasons, requirements, exclusions, rule IDs, indexed_at)
    policy_details = Column(
        JSONB().with_variant(JSON(), "sqlite"),
        nullable=False,
        default=dict,
    )

    # Relationship to version record
    repository_version = relationship(
        "TemplateRepositoryVersion",
        backref="templates",
    )

    __table_args__ = (
        # Unique constraints per repository version
        UniqueConstraint("repository_version_id", "template_id", name="uq_nuclei_templates_repo_tid"),
        UniqueConstraint("repository_version_id", "relative_path", name="uq_nuclei_templates_repo_path"),

        # Check constraint on severity values
        CheckConstraint(
            "severity IN ('info', 'low', 'medium', 'high', 'critical', 'unknown')",
            name="ck_nuclei_templates_severity",
        ),

        # Check constraint on security status
        CheckConstraint(
            "security_status IN ('eligible', 'ineligible', 'conditional')",
            name="ck_nuclei_templates_security_status",
        ),

        # Check constraint on SHA-256 format (64 characters)
        CheckConstraint(
            "length(content_hash) = 64",
            name="ck_nuclei_templates_content_hash",
        ),

        # Path safety constraint (no absolute paths or directory traversal)
        CheckConstraint(
            "relative_path NOT LIKE '/%' AND relative_path NOT LIKE '\\\\%' "
            "AND relative_path NOT LIKE '..%' AND relative_path NOT LIKE '%/..%' "
            "AND relative_path NOT LIKE '%\\\\..%'",
            name="ck_nuclei_templates_path_safety",
        ),

        # Ineligible execution constraint (ineligible templates CANNOT be marked eligible)
        CheckConstraint(
            "(security_status = 'eligible') OR (sequential_eligible = FALSE AND independent_eligible = FALSE)",
            name="ck_nuclei_templates_ineligible_execution",
        ),

        # Composite B-tree indexes
        Index("ix_nuclei_templates_repo_sev", "repository_version_id", "severity"),
        Index("ix_nuclei_templates_repo_status", "repository_version_id", "security_status"),

        # Partial indexes for scan engine query acceleration
        Index(
            "ix_nuclei_templates_seq_eligible",
            "repository_version_id",
            postgresql_where=text("sequential_eligible = TRUE"),
            sqlite_where=text("sequential_eligible = 1"),
        ),
        Index(
            "ix_nuclei_templates_ind_eligible",
            "repository_version_id",
            postgresql_where=text("independent_eligible = TRUE"),
            sqlite_where=text("independent_eligible = 1"),
        ),
    )

    def __repr__(self) -> str:
        return (
            f"<NucleiTemplate(id='{self.id}', "
            f"template_id='{self.template_id}', "
            f"severity='{self.severity}', "
            f"status='{self.security_status}')>"
        )
