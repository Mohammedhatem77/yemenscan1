"""
Database Initialization & Enterprise Schema Migration for YemenScan.

Connects to the database, executes schema upgrades (PostgreSQL / SQLite),
seeds default system settings, and optionally ingests historical scan
sessions from the disk storage into PostgreSQL.

Usage:
    python init_db.py                     # Initialize schema & seed settings
    python init_db.py --migrate-scans     # Ingest all historical disk scans
    python init_db.py --all               # Initialize, migrate schema & ingest scans
"""

import argparse
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Dict, List, Tuple

from sqlalchemy import text
from sqlalchemy.orm import Session

from database import Base, SessionLocal, engine
from models import (
    Targets,
    ScanSessions,
    Assets,
    VulnerabilityCatalog,
    VulnerabilityFindings,
    AIReports,
    SystemSettings,
    TemplateRepositoryVersion,
    NucleiTemplate,
)
from core.db_service import (
    ingest_scan_from_directory,
    get_or_set_system_setting,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("yemenscan.init_db")


def _migrate_nuclei_templates_to_17_columns_pg(conn) -> None:
    """
    Preserves nuclei_templates.created_at inside policy_details.indexed_at
    before removing the extra 18th column to match the approved 17-column design.
    """
    has_created_at = conn.execute(text(
        "SELECT 1 FROM information_schema.columns "
        "WHERE table_schema = current_schema() "
        "AND table_name = 'nuclei_templates' "
        "AND column_name = 'created_at'"
    )).scalar()
    if not has_created_at:
        return

    # Copy created_at into policy_details JSONB before any DDL drop
    conn.execute(text(
        "UPDATE nuclei_templates "
        "SET policy_details = jsonb_set("
        "    COALESCE(policy_details, '{}'::jsonb), "
        "    '{indexed_at}', "
        "    to_jsonb(created_at), "
        "    true"
        ") "
        "WHERE created_at IS NOT NULL "
        "AND NOT (COALESCE(policy_details, '{}'::jsonb) ? 'indexed_at')"
    ))

    unpreserved = conn.execute(text(
        "SELECT COUNT(*) FROM nuclei_templates "
        "WHERE created_at IS NOT NULL "
        "AND NOT (COALESCE(policy_details, '{}'::jsonb) ? 'indexed_at')"
    )).scalar_one()
    if unpreserved != 0:
        raise RuntimeError(
            f"Aborting nuclei_templates 17-column migration: {unpreserved} rows unpreserved"
        )

    conn.execute(text("ALTER TABLE nuclei_templates DROP COLUMN created_at;"))
    logger.info("Preserved created_at into policy_details.indexed_at and aligned nuclei_templates to 17 columns.")


def rollback_nuclei_templates_created_at_pg(conn) -> None:
    """Reversible rollback helper: restores nuclei_templates.created_at from policy_details.indexed_at."""
    conn.execute(text(
        "ALTER TABLE nuclei_templates "
        "ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITH TIME ZONE;"
    ))
    conn.execute(text(
        "UPDATE nuclei_templates "
        "SET created_at = COALESCE((policy_details->>'indexed_at')::timestamptz, NOW()) "
        "WHERE created_at IS NULL;"
    ))
    conn.execute(text(
        "ALTER TABLE nuclei_templates "
        "ALTER COLUMN created_at SET NOT NULL, "
        "ALTER COLUMN created_at SET DEFAULT NOW();"
    ))


def _migrate_nuclei_templates_to_17_columns_sqlite(conn) -> None:
    """SQLite helper: preserves created_at inside policy_details.indexed_at and drops extra column."""
    cols = [row[1] for row in conn.execute(text("PRAGMA table_info(nuclei_templates);")).fetchall()]
    if "created_at" not in cols:
        return

    conn.execute(text(
        "UPDATE nuclei_templates "
        "SET policy_details = json_set(COALESCE(policy_details, '{}'), '$.indexed_at', created_at) "
        "WHERE created_at IS NOT NULL "
        "AND json_extract(COALESCE(policy_details, '{}'), '$.indexed_at') IS NULL"
    ))
    unpreserved = conn.execute(text(
        "SELECT COUNT(*) FROM nuclei_templates "
        "WHERE created_at IS NOT NULL "
        "AND json_extract(COALESCE(policy_details, '{}'), '$.indexed_at') IS NULL"
    )).scalar_one()
    if unpreserved != 0:
        raise RuntimeError(
            f"Aborting SQLite nuclei_templates 17-column migration: {unpreserved} rows unpreserved"
        )

    conn.execute(text("ALTER TABLE nuclei_templates DROP COLUMN created_at;"))


def migrate_schema() -> bool:
    """
    Executes non-destructive schema migrations for PostgreSQL and SQLite,
    ensuring newly added columns and indexes exist without dropping data.
    """
    dialect = engine.dialect.name
    logger.info("Running schema migration for dialect: %s", dialect)

    if dialect == "postgresql":
        pg_migrations = [
            # Targets
            "ALTER TABLE targets ADD COLUMN IF NOT EXISTS organization VARCHAR(255);",
            "ALTER TABLE targets ADD COLUMN IF NOT EXISTS description TEXT;",
            "ALTER TABLE targets ADD COLUMN IF NOT EXISTS last_scanned_at TIMESTAMP WITH TIME ZONE;",
            "ALTER TABLE targets ADD COLUMN IF NOT EXISTS owner_id INTEGER REFERENCES users(id) ON DELETE SET NULL;",
            # ScanSessions
            "ALTER TABLE scan_sessions ADD COLUMN IF NOT EXISTS current_stage VARCHAR(50);",
            "ALTER TABLE scan_sessions ADD COLUMN IF NOT EXISTS progress INTEGER DEFAULT 0;",
            "ALTER TABLE scan_sessions ADD COLUMN IF NOT EXISTS stats_summary JSONB;",
            "ALTER TABLE scan_sessions ADD COLUMN IF NOT EXISTS execution_logs JSONB;",
            "ALTER TABLE scan_sessions ADD COLUMN IF NOT EXISTS owner_id INTEGER REFERENCES users(id) ON DELETE SET NULL;",
            # Assets
            "ALTER TABLE assets ADD COLUMN IF NOT EXISTS asset_type VARCHAR(50) DEFAULT 'web_service';",
            "ALTER TABLE assets ADD COLUMN IF NOT EXISTS status_code INTEGER;",
            # VulnerabilityCatalog
            "ALTER TABLE vulnerability_catalog ADD COLUMN IF NOT EXISTS severity VARCHAR(20);",
            "ALTER TABLE vulnerability_catalog ADD COLUMN IF NOT EXISTS reference_links JSONB;",
            # VulnerabilityFindings
            "ALTER TABLE vulnerability_findings ADD COLUMN IF NOT EXISTS source VARCHAR(100) DEFAULT 'Vulnerability Engine';",
            "ALTER TABLE vulnerability_findings ADD COLUMN IF NOT EXISTS status VARCHAR(50) DEFAULT 'open';",
            # AIReports
            "ALTER TABLE ai_reports ADD COLUMN IF NOT EXISTS model_used VARCHAR(100);",
            "ALTER TABLE ai_reports ADD COLUMN IF NOT EXISTS report_metadata JSONB;",
            # TemplateRepositoryVersions
            """CREATE TABLE IF NOT EXISTS template_repository_versions (
                id VARCHAR(36) PRIMARY KEY,
                upstream_version VARCHAR(50) NOT NULL,
                upstream_commit VARCHAR(64) NOT NULL,
                repository_path VARCHAR(500) NOT NULL,
                snapshot_hash VARCHAR(64) NOT NULL,
                policy_version VARCHAR(50),
                status VARCHAR(20) NOT NULL DEFAULT 'staging' CHECK (status IN ('staging', 'active', 'retained', 'failed')),
                error_message TEXT,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
                published_at TIMESTAMP WITH TIME ZONE
            );""",
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_template_repo_single_active ON template_repository_versions (status) WHERE status = 'active';",
            "CREATE INDEX IF NOT EXISTS ix_template_repo_version_commit ON template_repository_versions (upstream_commit);",
            "CREATE INDEX IF NOT EXISTS ix_template_repo_version_hash ON template_repository_versions (snapshot_hash);",
            # NucleiTemplates Catalog
            """CREATE TABLE IF NOT EXISTS nuclei_templates (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                repository_version_id VARCHAR(36) NOT NULL REFERENCES template_repository_versions(id) ON DELETE RESTRICT,
                template_id VARCHAR(255) NOT NULL,
                name VARCHAR(500),
                description TEXT,
                severity VARCHAR(20) NOT NULL DEFAULT 'unknown' CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical', 'unknown')),
                tags VARCHAR[] NOT NULL DEFAULT '{}',
                protocols VARCHAR[] NOT NULL DEFAULT '{}',
                cve_ids VARCHAR[] NOT NULL DEFAULT '{}',
                cwe_ids VARCHAR[] NOT NULL DEFAULT '{}',
                relative_path VARCHAR(500) NOT NULL,
                content_hash VARCHAR(64) NOT NULL CHECK (length(content_hash) = 64 AND content_hash ~ '^[0-9a-fA-F]{64}$'),
                security_status VARCHAR(20) NOT NULL DEFAULT 'ineligible' CHECK (security_status IN ('eligible', 'ineligible', 'conditional')),
                sequential_eligible BOOLEAN NOT NULL DEFAULT FALSE,
                independent_eligible BOOLEAN NOT NULL DEFAULT FALSE,
                metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
                policy_details JSONB NOT NULL DEFAULT '{}'::jsonb,
                CONSTRAINT ck_nuclei_templates_ineligible_execution CHECK ((security_status = 'eligible') OR (sequential_eligible = FALSE AND independent_eligible = FALSE)),
                CONSTRAINT ck_nuclei_templates_path_safety CHECK (relative_path NOT LIKE '/%' AND relative_path NOT LIKE '\\%' AND relative_path NOT LIKE '..%' AND relative_path NOT LIKE '%/..%' AND relative_path NOT LIKE '%\\..%'),
                CONSTRAINT uq_nuclei_templates_repo_tid UNIQUE (repository_version_id, template_id),
                CONSTRAINT uq_nuclei_templates_repo_path UNIQUE (repository_version_id, relative_path)
            );""",
            "CREATE INDEX IF NOT EXISTS ix_nuclei_templates_repo_id ON nuclei_templates (repository_version_id);",
            "CREATE INDEX IF NOT EXISTS ix_nuclei_templates_template_id ON nuclei_templates (template_id);",
            "CREATE INDEX IF NOT EXISTS ix_nuclei_templates_severity ON nuclei_templates (severity);",
            "CREATE INDEX IF NOT EXISTS ix_nuclei_templates_repo_sev ON nuclei_templates (repository_version_id, severity);",
            "CREATE INDEX IF NOT EXISTS ix_nuclei_templates_repo_status ON nuclei_templates (repository_version_id, security_status);",
            "CREATE INDEX IF NOT EXISTS ix_nuclei_templates_tags_gin ON nuclei_templates USING gin (tags);",
            "CREATE INDEX IF NOT EXISTS ix_nuclei_templates_protocols_gin ON nuclei_templates USING gin (protocols);",
            "CREATE INDEX IF NOT EXISTS ix_nuclei_templates_cve_ids_gin ON nuclei_templates USING gin (cve_ids);",
            "CREATE INDEX IF NOT EXISTS ix_nuclei_templates_name_fts ON nuclei_templates USING gin (to_tsvector('english', COALESCE(name, '')));",
            "CREATE INDEX IF NOT EXISTS ix_nuclei_templates_seq_eligible ON nuclei_templates (repository_version_id) WHERE sequential_eligible = TRUE;",
            "CREATE INDEX IF NOT EXISTS ix_nuclei_templates_ind_eligible ON nuclei_templates (repository_version_id) WHERE independent_eligible = TRUE;",
            # Performance Indexes
            "CREATE INDEX IF NOT EXISTS ix_vulnerability_findings_source ON vulnerability_findings (source);",
            "CREATE INDEX IF NOT EXISTS ix_assets_asset_type ON assets (asset_type);",
            "CREATE INDEX IF NOT EXISTS ix_system_settings_key ON system_settings (key);",
            # Synchronize sequences after migrations/imports
            "SELECT setval(pg_get_serial_sequence('targets', 'id'), COALESCE(max(id), 1)) FROM targets;",
            "SELECT setval(pg_get_serial_sequence('scan_sessions', 'id'), COALESCE(max(id), 1)) FROM scan_sessions;",
            "SELECT setval(pg_get_serial_sequence('assets', 'id'), COALESCE(max(id), 1)) FROM assets;",
            "SELECT setval(pg_get_serial_sequence('vulnerability_catalog', 'id'), COALESCE(max(id), 1)) FROM vulnerability_catalog;",
            "SELECT setval(pg_get_serial_sequence('vulnerability_findings', 'id'), COALESCE(max(id), 1)) FROM vulnerability_findings;",
            "SELECT setval(pg_get_serial_sequence('ai_reports', 'id'), COALESCE(max(id), 1)) FROM ai_reports;",
            "SELECT setval(pg_get_serial_sequence('system_settings', 'id'), COALESCE(max(id), 1)) FROM system_settings;",
        ]

        with engine.begin() as conn:
            for stmt in pg_migrations:
                try:
                    conn.execute(text(stmt))
                except Exception as ex:
                    logger.warning("Migration statement note: %s (%s)", stmt.strip(), ex)
            _migrate_nuclei_templates_to_17_columns_pg(conn)

        logger.info("PostgreSQL schema migration completed successfully.")
        return True

    elif dialect == "sqlite":
        # SQLite inspection and safe column additions
        sqlite_columns = [
            ("targets", "organization", "VARCHAR(255)"),
            ("targets", "description", "TEXT"),
            ("targets", "last_scanned_at", "DATETIME"),
            ("targets", "owner_id", "INTEGER"),
            ("scan_sessions", "current_stage", "VARCHAR(50)"),
            ("scan_sessions", "progress", "INTEGER DEFAULT 0"),
            ("scan_sessions", "stats_summary", "JSON"),
            ("scan_sessions", "execution_logs", "JSON"),
            ("scan_sessions", "owner_id", "INTEGER"),
            ("assets", "asset_type", "VARCHAR(50) DEFAULT 'web_service'"),
            ("assets", "status_code", "INTEGER"),
            ("vulnerability_catalog", "severity", "VARCHAR(20)"),
            ("vulnerability_catalog", "reference_links", "JSON"),
            ("vulnerability_findings", "source", "VARCHAR(100) DEFAULT 'Vulnerability Engine'"),
            ("vulnerability_findings", "status", "VARCHAR(50) DEFAULT 'open'"),
            ("ai_reports", "model_used", "VARCHAR(100)"),
            ("ai_reports", "report_metadata", "JSON"),
        ]

        with engine.begin() as conn:
            for table, col_name, col_type in sqlite_columns:
                try:
                    # Check if table exists
                    tbl_check = conn.execute(
                        text(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table}';")
                    ).scalar()
                    if not tbl_check:
                        continue
                    # Check if column exists
                    cols = [
                        row[1]
                        for row in conn.execute(text(f"PRAGMA table_info({table});")).fetchall()
                    ]
                    if col_name not in cols:
                        logger.info("Adding column %s.%s (%s)", table, col_name, col_type)
                        conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col_name} {col_type};"))
                except Exception as ex:
                    logger.warning("SQLite migration note for %s.%s: %s", table, col_name, ex)

            # Ensure template_repository_versions and partial unique index exist in SQLite
            try:
                conn.execute(text("""
                    CREATE TABLE IF NOT EXISTS template_repository_versions (
                        id VARCHAR(36) PRIMARY KEY,
                        upstream_version VARCHAR(50) NOT NULL,
                        upstream_commit VARCHAR(64) NOT NULL,
                        repository_path VARCHAR(500) NOT NULL,
                        snapshot_hash VARCHAR(64) NOT NULL,
                        policy_version VARCHAR(50),
                        status VARCHAR(20) NOT NULL DEFAULT 'staging' CHECK (status IN ('staging', 'active', 'retained', 'failed')),
                        error_message TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                        published_at TIMESTAMP
                    );
                """))
                conn.execute(text("""
                    CREATE UNIQUE INDEX IF NOT EXISTS uq_template_repo_single_active
                    ON template_repository_versions (status) WHERE status = 'active';
                """))
            except Exception as ex:
                logger.warning("SQLite migration note for template_repository_versions: %s", ex)

            # Ensure nuclei_templates exists in SQLite
            try:
                conn.execute(text("""
                    CREATE TABLE IF NOT EXISTS nuclei_templates (
                        id VARCHAR(36) PRIMARY KEY,
                        repository_version_id VARCHAR(36) NOT NULL REFERENCES template_repository_versions(id) ON DELETE RESTRICT,
                        template_id VARCHAR(255) NOT NULL,
                        name VARCHAR(500),
                        description TEXT,
                        severity VARCHAR(20) NOT NULL DEFAULT 'unknown' CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical', 'unknown')),
                        tags JSON NOT NULL DEFAULT '[]',
                        protocols JSON NOT NULL DEFAULT '[]',
                        cve_ids JSON NOT NULL DEFAULT '[]',
                        cwe_ids JSON NOT NULL DEFAULT '[]',
                        relative_path VARCHAR(500) NOT NULL,
                        content_hash VARCHAR(64) NOT NULL,
                        security_status VARCHAR(20) NOT NULL DEFAULT 'ineligible' CHECK (security_status IN ('eligible', 'ineligible', 'conditional')),
                        sequential_eligible BOOLEAN NOT NULL DEFAULT 0,
                        independent_eligible BOOLEAN NOT NULL DEFAULT 0,
                        metadata JSON NOT NULL DEFAULT '{}',
                        policy_details JSON NOT NULL DEFAULT '{}',
                        CONSTRAINT ck_nuclei_templates_ineligible_execution CHECK ((security_status = 'eligible') OR (sequential_eligible = 0 AND independent_eligible = 0)),
                        CONSTRAINT uq_nuclei_templates_repo_tid UNIQUE (repository_version_id, template_id),
                        CONSTRAINT uq_nuclei_templates_repo_path UNIQUE (repository_version_id, relative_path)
                    );
                """))
                conn.execute(text("CREATE INDEX IF NOT EXISTS ix_nuclei_templates_repo_id ON nuclei_templates (repository_version_id);"))
                conn.execute(text("CREATE INDEX IF NOT EXISTS ix_nuclei_templates_template_id ON nuclei_templates (template_id);"))
                conn.execute(text("CREATE INDEX IF NOT EXISTS ix_nuclei_templates_severity ON nuclei_templates (severity);"))
                conn.execute(text("CREATE INDEX IF NOT EXISTS ix_nuclei_templates_repo_sev ON nuclei_templates (repository_version_id, severity);"))
                conn.execute(text("CREATE INDEX IF NOT EXISTS ix_nuclei_templates_repo_status ON nuclei_templates (repository_version_id, security_status);"))
                conn.execute(text("CREATE INDEX IF NOT EXISTS ix_nuclei_templates_seq_eligible ON nuclei_templates (repository_version_id) WHERE sequential_eligible = 1;"))
                conn.execute(text("CREATE INDEX IF NOT EXISTS ix_nuclei_templates_ind_eligible ON nuclei_templates (repository_version_id) WHERE independent_eligible = 1;"))
                _migrate_nuclei_templates_to_17_columns_sqlite(conn)
            except Exception as ex:
                logger.warning("SQLite migration note for nuclei_templates: %s", ex)
                logger.warning("SQLite template_repository_versions migration note: %s", ex)

        logger.info("SQLite schema migration completed successfully.")
        return True

    return True


def seed_system_settings(db: Session) -> None:
    """
    Ensures core system settings are initialized in the database.
    """
    defaults = [
        ("app_name", "YemenScan Cyber Security Platform", "Name of the security platform"),
        ("version", "2.0.0", "Current system version"),
        ("gemini_model", "gemini-1.5-flash", "Primary Gemini AI model for assessment analysis"),
        ("max_concurrent_scans", "3", "Maximum number of parallel scan pipelines"),
        ("subdomain_concurrency", "100", "Default concurrency rate for subfinder/amass"),
        ("default_scan_mode", "full", "Default scan mode: surface, fast, full, or nuclei_only"),
    ]

    for key, val, desc in defaults:
        get_or_set_system_setting(db, key, default_value=val, description=desc)

    logger.info("System settings seeded and verified (%d entries).", len(defaults))


def init_database() -> bool:
    """
    Initializes database schema, creates tables, executes migrations,
    and seeds default configuration records.
    """
    try:
        logger.info("Connecting to database: %s", engine.url)
        logger.info("Creating base database tables if they do not exist...")

        # Base.metadata.create_all creates tables in topological order respecting foreign keys
        Base.metadata.create_all(bind=engine)

        # Non-destructive column additions
        migrate_schema()

        # Seed system settings
        with SessionLocal() as session:
            seed_system_settings(session)

        logger.info("Verified all YemenScan database tables:")
        for table_name in Base.metadata.tables.keys():
            logger.info("  - Table: %s", table_name)

        logger.info("Database initialization completed successfully.")
        return True

    except Exception as exc:
        logger.error("Failed to initialize database: %s", exc, exc_info=True)
        return False


def migrate_scans_from_disk(force: bool = False) -> Dict[str, int]:
    """
    Scans the local 'scans/' directory and ingests all historical scan sessions
    into the database.

    :param force: If True, re-ingests scans even if they already exist in ScanSessions
    :return: Summary dictionary with counts of processed records
    """
    base_dir = os.path.dirname(os.path.abspath(__file__))
    scans_dir = os.path.join(base_dir, "scans")

    if not os.path.exists(scans_dir):
        logger.warning("Scans directory not found: %s", scans_dir)
        return {"scans_processed": 0, "errors": 0}

    logger.info("Scanning historical scans directory: %s", scans_dir)
    scan_entries = [
        d for d in os.listdir(scans_dir)
        if os.path.isdir(os.path.join(scans_dir, d)) and d.startswith("scan_")
    ]
    scan_entries.sort()

    logger.info("Found %d historical scan directories on disk.", len(scan_entries))

    stats = {
        "total_scans_on_disk": len(scan_entries),
        "newly_ingested": 0,
        "already_existing": 0,
        "errors": 0,
    }

    with SessionLocal() as db:
        for idx, scan_id in enumerate(scan_entries, start=1):
            session_dir = os.path.join(scans_dir, scan_id)
            try:
                # Check if session already exists
                existing = db.query(ScanSessions).filter(ScanSessions.scan_id == scan_id).first()
                if existing and not force:
                    stats["already_existing"] += 1
                    continue

                logger.info("[%d/%d] Ingesting scan: %s", idx, len(scan_entries), scan_id)
                ingest_scan_from_directory(db, scan_id=scan_id, session_dir=session_dir)
                stats["newly_ingested"] += 1

            except Exception as exc:
                stats["errors"] += 1
                logger.error("Error ingesting scan %s: %s", scan_id, exc)

        # Print final database summary
        total_targets = db.query(Targets).count()
        total_sessions = db.query(ScanSessions).count()
        total_assets = db.query(Assets).count()
        total_catalog = db.query(VulnerabilityCatalog).count()
        total_findings = db.query(VulnerabilityFindings).count()
        total_reports = db.query(AIReports).count()

        logger.info("=" * 60)
        logger.info(" Historical Scan Ingestion Summary:")
        logger.info("  - Total on Disk:     %d", stats["total_scans_on_disk"])
        logger.info("  - Newly Ingested:    %d", stats["newly_ingested"])
        logger.info("  - Already in DB:     %d", stats["already_existing"])
        logger.info("  - Ingestion Errors:  %d", stats["errors"])
        logger.info(" Current PostgreSQL Database Totals:")
        logger.info("  - Targets:           %d", total_targets)
        logger.info("  - Scan Sessions:     %d", total_sessions)
        logger.info("  - Discovered Assets: %d", total_assets)
        logger.info("  - Vuln Catalog:      %d", total_catalog)
        logger.info("  - Findings:          %d", total_findings)
        logger.info("  - AI Reports:        %d", total_reports)
        logger.info("=" * 60)

    return stats


def main():
    parser = argparse.ArgumentParser(
        description="YemenScan PostgreSQL Database Initializer & Migration Manager"
    )
    parser.add_argument(
        "--migrate-scans",
        action="store_true",
        help="Scan and ingest all historical scan sessions from disk into the database",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force re-ingestion of scan sessions even if already present",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Initialize database, apply schema migrations, and ingest all scans",
    )

    args = parser.parse_args()

    # Step 1: Initialize database & schema migrations
    success = init_database()
    if not success:
        sys.exit(1)

    # Step 2: Historical scan ingestion if requested
    if args.migrate_scans or args.all:
        migrate_scans_from_disk(force=args.force)


if __name__ == "__main__":
    main()
