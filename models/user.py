"""
User & RBAC Models for YemenScan.

Defines the User model, UserRole enumeration, and associations for
data ownership isolation (Ownership Isolation) across Targets and ScanSessions.
"""

from datetime import datetime, timezone
import enum
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Integer,
    String,
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from database import Base


class UserRole(str, enum.Enum):
    """
    Role-Based Access Control (RBAC) Roles.
    - admin: Complete system access (manage users, view/edit all targets and scans).
    - analyst: Standard operator (can scan, view and manage their own targets and scans).
    - viewer: Read-only access to authorized scan reports and dashboard metrics.
    """
    admin = "admin"
    analyst = "analyst"
    viewer = "viewer"


class User(Base):
    """
    Users Table.
    Central authentication and identity model for YemenScan platform.
    """
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username = Column(String(100), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(50), nullable=False, default=UserRole.analyst.value)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=func.now(), nullable=False)

    # Ownership Isolation Relationships
    targets = relationship(
        "Targets",
        back_populates="owner",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    scan_sessions = relationship(
        "ScanSessions",
        back_populates="owner",
        cascade="all, delete-orphan",
        passive_deletes=True
    )

    def __repr__(self) -> str:
        return f"<User(id={self.id}, username='{self.username}', role='{self.role}')>"

    def to_dict(self) -> dict:
        """Safe dictionary representation omitting sensitive credentials."""
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
