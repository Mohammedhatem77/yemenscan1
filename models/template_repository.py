"""
Template Repository Versions Model for YemenScan.

Tracks official Nuclei template repository releases, immutable snapshot storage,
deterministic cryptographic hashes, and version lifecycle states (staging, active, retained, failed).
"""

import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    String,
    Text,
    DateTime,
    Index,
    CheckConstraint,
)
from sqlalchemy.sql import func
from database import Base


def utc_now() -> datetime:
    """Returns the current UTC datetime."""
    return datetime.now(timezone.utc)


class TemplateRepositoryVersion(Base):
    """
    TemplateRepositoryVersion Table.
    
    Persists immutable repository snapshots with cryptographic provenance.
    Enforces that at most one repository version can be 'active' simultaneously.
    """
    __tablename__ = "template_repository_versions"

    id = Column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        nullable=False
    )
    upstream_version = Column(String(50), nullable=False, index=True)
    upstream_commit = Column(String(64), nullable=False, index=True)
    repository_path = Column(String(500), nullable=False)
    snapshot_hash = Column(String(64), nullable=False, index=True)
    policy_version = Column(String(50), nullable=True)
    status = Column(
        String(20),
        nullable=False,
        default="staging",
        index=True
    )
    error_message = Column(Text, nullable=True)
    created_at = Column(
        DateTime(timezone=True),
        default=func.now(),
        nullable=False
    )
    published_at = Column(
        DateTime(timezone=True),
        nullable=True
    )

    __table_args__ = (
        CheckConstraint(
            "status IN ('staging', 'active', 'retained', 'failed')",
            name="ck_template_repo_version_status"
        ),
        # Partial unique index ensuring at most one active version at any time
        Index(
            "uq_template_repo_single_active",
            "status",
            unique=True,
            postgresql_where=(status == "active"),
            sqlite_where=(status == "active"),
        ),
    )

    def __repr__(self) -> str:
        return (
            f"<TemplateRepositoryVersion(id='{self.id}', "
            f"version='{self.upstream_version}', commit='{self.upstream_commit[:8]}', "
            f"status='{self.status}')>"
        )
