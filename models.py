"""
Database Models Module for YemenScan (Compatibility Layer).

Re-exports models from the models package.
"""

from models.user import User, UserRole
from models.scan import (
    Targets,
    ScanSessions,
    Assets,
    VulnerabilityCatalog,
    VulnerabilityFindings,
    AIReports,
    SystemSettings,
    JSON_TYPE,
    utc_now,
)

__all__ = [
    "User",
    "UserRole",
    "Targets",
    "ScanSessions",
    "Assets",
    "VulnerabilityCatalog",
    "VulnerabilityFindings",
    "AIReports",
    "SystemSettings",
    "JSON_TYPE",
    "utc_now",
]
