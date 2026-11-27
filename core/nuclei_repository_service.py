"""
Nuclei Repository and Version Management Service for YemenScan.

Provides:
1. Versioned Immutable Snapshots of the official Nuclei template repository.
2. Deterministic SHA-256 cryptographic hashing of snapshot payloads.
3. Strict path traversal and symlink boundary validation.
4. Concurrency control via file-based update locking.
5. Atomic state transitions in PostgreSQL / SQLite version registry.
6. Zero scan disruption and full isolation from active scan pipelines.
"""

import os
import stat
import uuid
import shutil
import hashlib
import logging
import subprocess
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Optional, Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from database import SessionLocal
from models.template_repository import TemplateRepositoryVersion
from core.nuclei_shared import (
    BASE_DIR,
    NUCLEI_TEMPLATES_OFFICIAL_DIR,
    NUCLEI_STORAGE_DIR,
    NUCLEI_VERSIONS_DIR,
    NUCLEI_STAGING_DIR,
    NUCLEI_OFFICIAL_REPO_URL,
    NUCLEI_TEMPLATES_COMMIT,
)

logger = logging.getLogger("yemenscan.repository_service")


# -----------------------------------------------------------------------------
# Process Liveness Helper
# -----------------------------------------------------------------------------

def _is_process_alive(pid: int) -> bool:
    """
    Checks whether a process with the given PID is currently active.
    Safe across platforms: Uses Win32 OpenProcess/GetExitCodeProcess on Windows
    (avoiding os.kill which invokes TerminateProcess on Win32), and os.kill(pid, 0) on POSIX.
    """
    if pid <= 0:
        return False

    if os.name == "nt":
        try:
            import ctypes
            import ctypes.wintypes
            # PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.OpenProcess(0x1000, False, pid)
            if not handle:
                return False
            try:
                exit_code = ctypes.wintypes.DWORD()
                # STILL_ACTIVE = 259
                if kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                    return exit_code.value == 259
                return False
            finally:
                kernel32.CloseHandle(handle)
        except Exception:
            return False
    else:
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False


# -----------------------------------------------------------------------------
# Custom Exceptions
# -----------------------------------------------------------------------------

class RepositoryServiceError(Exception):
    """Base exception for all repository management errors."""
    pass


class RepositoryLockError(RepositoryServiceError):
    """Raised when repository update lock cannot be acquired."""
    pass


class SecurityViolationError(RepositoryServiceError):
    """Raised when insecure paths, symlinks, or unauthorized sources are detected."""
    pass


class SnapshotIntegrityError(RepositoryServiceError):
    """Raised when a snapshot fails cryptographic verification or is modified."""
    pass


class VersionNotFoundError(RepositoryServiceError):
    """Raised when a requested version ID does not exist."""
    pass


class VersionStateError(RepositoryServiceError):
    """Raised when an illegal or premature version state transition is attempted."""
    pass


# -----------------------------------------------------------------------------
# Concurrency Lock with Stale-Lock Recovery
# -----------------------------------------------------------------------------

class RepositoryLock:
    """
    File-based and process-safe mutex preventing concurrent repository updates.
    Includes automated stale-lock detection and crash recovery.
    """
    def __init__(
        self,
        lock_dir: str = NUCLEI_STORAGE_DIR,
        filename: str = ".update.lock",
        stale_timeout_seconds: int = 600
    ):
        self.lock_dir = lock_dir
        self.lock_file = os.path.join(lock_dir, filename)
        self.stale_timeout = stale_timeout_seconds
        self._acquired = False

    def acquire(self) -> bool:
        os.makedirs(self.lock_dir, exist_ok=True)

        # Inspect existing lockfile for crash recovery
        if os.path.exists(self.lock_file):
            try:
                with open(self.lock_file, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                lock_pid = -1
                lock_time = None
                for line in lines:
                    if line.startswith("pid="):
                        try:
                            lock_pid = int(line.strip().split("=")[1])
                        except ValueError:
                            pass
                    elif line.startswith("time="):
                        try:
                            lock_time = datetime.fromisoformat(line.strip().split("=")[1])
                        except Exception:
                            pass

                is_stale = False
                if lock_pid > 0:
                    if not _is_process_alive(lock_pid):
                        is_stale = True
                        logger.warning("Detected stale repository lock from terminated PID %d. Reclaiming lock.", lock_pid)
                    else:
                        # Process is still actively running. Never reclaim an active process's lock.
                        logger.info("Repository lock actively held by running PID %d.", lock_pid)
                elif lock_time and (datetime.now(timezone.utc) - lock_time).total_seconds() > self.stale_timeout:
                    # Lockfile lacks a recognizable PID and has exceeded timeout
                    is_stale = True
                    logger.warning("Detected orphaned repository lock exceeding %ds timeout. Reclaiming lock.", self.stale_timeout)

                if is_stale:
                    try:
                        os.remove(self.lock_file)
                    except Exception as ex:
                        logger.warning("Could not remove stale lockfile: %s", ex)
            except Exception as e:
                logger.warning("Error inspecting existing lockfile: %s", e)

        try:
            # Atomic file creation in exclusive mode (O_CREAT | O_EXCL)
            fd = os.open(self.lock_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            with os.fdopen(fd, "w") as f:
                f.write(f"pid={os.getpid()}\ntime={datetime.now(timezone.utc).isoformat()}\n")
            self._acquired = True
            return True
        except FileExistsError:
            raise RepositoryLockError(
                f"Repository update is already in progress by another task (lockfile: {self.lock_file})."
            )
        except Exception as e:
            raise RepositoryLockError(f"Failed to acquire repository lock: {e}")

    def release(self) -> None:
        if self._acquired and os.path.exists(self.lock_file):
            try:
                os.remove(self.lock_file)
            except Exception as e:
                logger.warning("Failed to remove lockfile %s: %s", self.lock_file, e)
            finally:
                self._acquired = False

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.release()


# -----------------------------------------------------------------------------
# Cryptographic and Security Utilities
# -----------------------------------------------------------------------------

def compute_deterministic_snapshot_hash(directory_path: str) -> Tuple[str, int, List[str]]:
    """
    Computes a deterministic SHA-256 cryptographic hash of an entire directory snapshot.
    
    Algorithm:
    1. Collects all file paths relative to directory_path.
    2. Normalizes path separators to POSIX '/' regardless of host OS.
    3. Strictly sorts relative paths alphabetically.
    4. Hashes each relative path followed by its exact file byte content.
    
    Returns:
        (sha256_hexdigest, total_files_count, sorted_relative_paths)
    """
    if not os.path.exists(directory_path):
        raise FileNotFoundError(f"Snapshot directory does not exist: {directory_path}")

    hasher = hashlib.sha256()
    rel_files: List[Tuple[str, str]] = []

    for root, _, files in os.walk(directory_path):
        for fname in files:
            full_path = os.path.join(root, fname)
            rel_path = os.path.relpath(full_path, directory_path).replace("\\", "/")
            rel_files.append((rel_path, full_path))

    rel_files.sort(key=lambda x: x[0])

    for rel_path, full_path in rel_files:
        hasher.update(rel_path.encode("utf-8"))
        hasher.update(b"\x00")
        with open(full_path, "rb") as fp:
            while chunk := fp.read(65536):
                hasher.update(chunk)
        hasher.update(b"\x00")

    return hasher.hexdigest(), len(rel_files), [rf[0] for rf in rel_files]


def validate_directory_safety(source_dir: str) -> None:
    """
    Inspects source directory to ensure no path traversal or symlinks pointing outside boundary.
    """
    real_source = os.path.realpath(source_dir)
    for root, dirs, files in os.walk(source_dir, followlinks=False):
        for item in dirs + files:
            full_item = os.path.join(root, item)
            # Detect symlinks
            if os.path.islink(full_item):
                target = os.path.realpath(full_item)
                try:
                    common = os.path.commonpath([real_source, target])
                    if common != real_source:
                        raise SecurityViolationError(
                            f"Illegal symlink pointing outside repository boundary: {item} -> {target}"
                        )
                except ValueError:
                    raise SecurityViolationError(
                        f"Illegal cross-drive symlink detected: {item} -> {target}"
                    )


def extract_git_remote_url(repo_dir: str) -> str:
    """Reads remote origin URL directly from .git/config without subprocess invocation."""
    git_dir = os.path.join(repo_dir, ".git")
    if not os.path.exists(git_dir):
        return NUCLEI_OFFICIAL_REPO_URL
    config_file = os.path.join(git_dir, "config") if os.path.isdir(git_dir) else None
    if config_file and os.path.exists(config_file):
        try:
            with open(config_file, "r", encoding="utf-8", errors="ignore") as f:
                in_origin = False
                for line in f:
                    stripped = line.strip()
                    if stripped.startswith("[remote") and "origin" in stripped:
                        in_origin = True
                    elif stripped.startswith("[") and in_origin:
                        break
                    elif in_origin and stripped.startswith("url ="):
                        return stripped.split("=", 1)[1].strip()
        except Exception:
            pass
    return NUCLEI_OFFICIAL_REPO_URL


def extract_git_metadata(repo_dir: str) -> Tuple[str, str, str]:
    """
    Extracts version tag, commit hash, and remote URL from a local Git repository.
    Optimized for high-speed single-call extraction.
    """
    git_dir = os.path.join(repo_dir, ".git")
    if not os.path.exists(git_dir):
        raise RepositoryServiceError(f"Directory is not a valid git repository: {repo_dir}")

    # 1. Read remote origin URL from .git/config directly (avoids extra subprocess)
    remote_url = extract_git_remote_url(repo_dir)

    # 2. Extract commit hash and tag in a single git execution
    try:
        res = subprocess.run(
            ["git", "--no-pager", "-C", repo_dir, "log", "-1", "--format=%H%x00%D"],
            capture_output=True,
            text=True,
            check=True
        )
        parts = res.stdout.strip().split("\x00", 1)
        commit_hash = parts[0].strip()
        ref_names = parts[1] if len(parts) > 1 else ""

        # Extract tag from ref_names (e.g. 'tag: v10.5.1')
        tag = None
        for ref in ref_names.split(","):
            ref = ref.strip()
            if ref.startswith("tag:"):
                tag = ref.split(":", 1)[1].strip()
                break

        if not tag:
            try:
                tag_res = subprocess.run(
                    ["git", "--no-pager", "-C", repo_dir, "describe", "--tags", "--always", "HEAD"],
                    capture_output=True,
                    text=True,
                    check=True
                )
                tag = tag_res.stdout.strip()
            except Exception:
                tag = commit_hash[:8]

        return tag, commit_hash, remote_url
    except Exception as e:
        raise RepositoryServiceError(f"Failed to extract git metadata from {repo_dir}: {e}")


def _remove_readonly(func, path, exc_info):
    """Error handler for shutil.rmtree on Windows read-only files."""
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except Exception:
        pass


def make_directory_readonly(directory_path: str) -> None:
    """
    Applies read-only file mode to all files in an immutable snapshot directory.
    """
    for root, _, files in os.walk(directory_path):
        for f in files:
            p = os.path.join(root, f)
            try:
                # Retain read permissions, drop write permissions
                current_mode = os.stat(p).st_mode
                os.chmod(p, current_mode & ~stat.S_IWRITE)
            except Exception:
                pass


# -----------------------------------------------------------------------------
# Repository Service API
# -----------------------------------------------------------------------------

def get_active_version(db: Optional[Session] = None) -> Optional[TemplateRepositoryVersion]:
    """
    Retrieves the currently 'active' TemplateRepositoryVersion, or None if none is active.
    """
    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True

    try:
        stmt = select(TemplateRepositoryVersion).where(
            TemplateRepositoryVersion.status == "active"
        )
        return db.execute(stmt).scalar_one_or_none()
    finally:
        if close_db:
            db.close()


def get_version(version_id: str, db: Optional[Session] = None) -> Optional[TemplateRepositoryVersion]:
    """
    Retrieves a TemplateRepositoryVersion by its primary key UUID.
    """
    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True

    try:
        stmt = select(TemplateRepositoryVersion).where(
            TemplateRepositoryVersion.id == version_id
        )
        return db.execute(stmt).scalar_one_or_none()
    finally:
        if close_db:
            db.close()


def list_versions(
    status: Optional[str] = None,
    db: Optional[Session] = None
) -> List[TemplateRepositoryVersion]:
    """
    Lists template repository versions, optionally filtered by status, ordered newest first.
    """
    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True

    try:
        stmt = select(TemplateRepositoryVersion)
        if status:
            stmt = stmt.where(TemplateRepositoryVersion.status == status)
        stmt = stmt.order_by(TemplateRepositoryVersion.created_at.desc())
        return list(db.execute(stmt).scalars().all())
    finally:
        if close_db:
            db.close()


def prepare_repository_version(
    source_dir: Optional[str] = None,
    upstream_version: Optional[str] = None,
    upstream_commit: Optional[str] = None,
    approved_commit: Optional[str] = None,
    db: Optional[Session] = None
) -> TemplateRepositoryVersion:
    """
    Executes the official version preparation lifecycle:
    1. Acquires repository mutex lock.
    2. Validates upstream git provenance and file safety.
    3. Stages templates in an isolated staging workspace.
    4. Computes deterministic cryptographic SHA-256 snapshot hash.
    5. Deduplicates against existing registered snapshots.
    6. Stores immutable snapshot in storage/nuclei/versions/<id>/.
    7. Applies read-only attributes to snapshot files.
    8. Registers in database with status='staging' and policy_version=None.
    9. Safely cleans up temporary staging files.
    """
    if source_dir is None:
        source_dir = NUCLEI_TEMPLATES_OFFICIAL_DIR

    if not os.path.exists(source_dir):
        raise FileNotFoundError(f"Template repository source directory does not exist: {source_dir}")

    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True

    with RepositoryLock():
        # 1. Validate upstream Git provenance
        if upstream_version and upstream_commit:
            final_version = upstream_version
            final_commit = upstream_commit
            remote_url = extract_git_remote_url(source_dir)
        else:
            extracted_tag, extracted_commit, remote_url = extract_git_metadata(source_dir)
            final_version = upstream_version or extracted_tag
            final_commit = upstream_commit or extracted_commit

        # Ensure official remote provenance
        norm_remote = remote_url.rstrip("/").lower()
        norm_official = NUCLEI_OFFICIAL_REPO_URL.rstrip("/").lower()
        if norm_remote != norm_official and not norm_remote.endswith("nuclei-templates.git"):
            raise SecurityViolationError(
                f"Unauthorized repository origin: '{remote_url}'. Only official Nuclei repository is allowed."
            )

        # Verify approved Git commit provenance
        # By default, baseline initialization is pegged to NUCLEI_TEMPLATES_COMMIT (v10.5.1).
        # Future official releases can supply an approved_commit to validate upstream provenance.
        target_approved_commit = approved_commit or NUCLEI_TEMPLATES_COMMIT
        if source_dir == NUCLEI_TEMPLATES_OFFICIAL_DIR:
            if target_approved_commit and final_commit != target_approved_commit:
                raise SecurityViolationError(
                    f"Official repository commit '{final_commit}' does not match vetted approved commit '{target_approved_commit}'."
                )

        # 2. Validate safety and symlink boundaries
        validate_directory_safety(source_dir)

        # 3. Create isolated staging directory
        staging_uuid = str(uuid.uuid4())
        staging_path = os.path.join(NUCLEI_STAGING_DIR, staging_uuid)
        os.makedirs(staging_path, exist_ok=True)

        try:
            logger.info("Staging template version %s (commit %s) into %s", final_version, final_commit[:8], staging_path)

            # Copy all files except internal .git metadata to keep immutable snapshot pure
            def _copy_filter(src, names):
                ignored = set()
                if ".git" in names:
                    ignored.add(".git")
                return ignored

            shutil.copytree(source_dir, staging_path, dirs_exist_ok=True, ignore=_copy_filter)

            # 4. Verify essential files exist (.nuclei-ignore is mandatory)
            ignore_file = os.path.join(staging_path, ".nuclei-ignore")
            if not os.path.exists(ignore_file):
                logger.warning("Mandatory .nuclei-ignore missing from staging; copying from source")
                src_ignore = os.path.join(source_dir, ".nuclei-ignore")
                if os.path.exists(src_ignore):
                    shutil.copy2(src_ignore, ignore_file)
                else:
                    raise SnapshotIntegrityError(".nuclei-ignore file is missing from official templates repository.")

            # 5. Compute deterministic cryptographic snapshot hash
            snapshot_hash, total_files, _ = compute_deterministic_snapshot_hash(staging_path)
            logger.info("Computed deterministic snapshot hash: %s across %d files", snapshot_hash, total_files)

            # 6. Deduplication check
            stmt_dup = select(TemplateRepositoryVersion).where(
                TemplateRepositoryVersion.snapshot_hash == snapshot_hash,
                TemplateRepositoryVersion.status.in_(["staging", "active", "retained"])
            )
            existing = db.execute(stmt_dup).scalar_one_or_none()
            if existing:
                rel_exist_path = existing.repository_path
                abs_exist_path = os.path.join(BASE_DIR, rel_exist_path) if not os.path.isabs(rel_exist_path) else rel_exist_path
                if os.path.exists(abs_exist_path):
                    logger.info("Snapshot hash %s already registered (id: %s). Reusing existing version.", snapshot_hash, existing.id)
                    return existing

            # 7. Move to immutable storage
            version_id = str(uuid.uuid4())
            rel_version_path = os.path.join("storage", "nuclei", "versions", version_id).replace("\\", "/")
            abs_version_path = os.path.join(BASE_DIR, "storage", "nuclei", "versions", version_id)
            os.makedirs(os.path.dirname(abs_version_path), exist_ok=True)

            shutil.copytree(staging_path, abs_version_path)
            make_directory_readonly(abs_version_path)

            # 8. Register in PostgreSQL / SQLite
            version_record = TemplateRepositoryVersion(
                id=version_id,
                upstream_version=final_version,
                upstream_commit=final_commit,
                repository_path=rel_version_path,
                snapshot_hash=snapshot_hash,
                policy_version=None,  # Nullable in Phase 1; set during Phase 2 classification
                status="staging",
                error_message=None,
                created_at=datetime.now(timezone.utc),
                published_at=None
            )
            db.add(version_record)
            db.commit()
            db.refresh(version_record)

            logger.info("Successfully registered snapshot %s (version: %s, status: staging)", version_id, final_version)
            return version_record

        except Exception as e:
            db.rollback()
            logger.error("Failed to prepare repository version: %s", e)
            raise
        finally:
            # 9. Clean up staging directory
            if os.path.exists(staging_path):
                shutil.rmtree(staging_path, onerror=_remove_readonly, ignore_errors=True)
            if close_db:
                db.close()


def verify_snapshot_integrity(
    version_id: str,
    db: Optional[Session] = None
) -> Tuple[bool, Dict[str, Any]]:
    """
    Verifies that an immutable snapshot on disk has not been altered, corrupted, or tampered with.
    Re-hashes all snapshot files deterministically and compares with stored snapshot_hash.
    """
    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True

    try:
        version = get_version(version_id, db=db)
        if not version:
            raise VersionNotFoundError(f"Version ID '{version_id}' not found in registry.")

        rel_path = version.repository_path
        abs_path = os.path.join(BASE_DIR, rel_path) if not os.path.isabs(rel_path) else rel_path

        if not os.path.exists(abs_path):
            return False, {
                "error": f"Snapshot directory missing on disk: {abs_path}",
                "version_id": version_id,
                "expected_hash": version.snapshot_hash
            }

        recalculated_hash, file_count, _ = compute_deterministic_snapshot_hash(abs_path)
        is_valid = (recalculated_hash == version.snapshot_hash)

        return is_valid, {
            "version_id": version_id,
            "expected_hash": version.snapshot_hash,
            "actual_hash": recalculated_hash,
            "file_count": file_count,
            "is_valid": is_valid,
            "repository_path": rel_path
        }
    finally:
        if close_db:
            db.close()


def publish_version(
    version_id: str,
    db: Optional[Session] = None
) -> TemplateRepositoryVersion:
    """
    Version publication to 'active' status is strictly disabled in Phase 1.
    Version activation requires complete template eligibility classification and catalog indexing (Phase 2 & Phase 3).
    All Phase 1 repository snapshots must remain safely in 'staging' status.
    """
    raise VersionStateError(
        "Version publication to 'active' status is strictly disabled in Phase 1. "
        "Version activation requires template eligibility classification and catalog indexing (Phase 2 & Phase 3). "
        "All Phase 1 repository snapshots must remain safely in 'staging' status."
    )


def initialize_repository(db: Optional[Session] = None) -> TemplateRepositoryVersion:
    """
    Initializes the shared template repository management infrastructure:
    - Creates necessary storage directories (storage/nuclei/versions, storage/nuclei/staging).
    - Checks for an existing registered snapshot matching the local official repository.
    - If none exists, prepares and registers the baseline snapshot in staging status.
    """
    os.makedirs(NUCLEI_VERSIONS_DIR, exist_ok=True)
    os.makedirs(NUCLEI_STAGING_DIR, exist_ok=True)

    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True

    try:
        # Check if an active version already exists
        active = get_active_version(db=db)
        if active:
            logger.info("Repository already initialized with active version: %s (%s)", active.id, active.upstream_version)
            return active

        # Check if any staging or retained version matches local official repo commit
        if os.path.exists(NUCLEI_TEMPLATES_OFFICIAL_DIR):
            tag, commit, _ = extract_git_metadata(NUCLEI_TEMPLATES_OFFICIAL_DIR)
            stmt = select(TemplateRepositoryVersion).where(
                TemplateRepositoryVersion.upstream_commit == commit,
                TemplateRepositoryVersion.status.in_(["staging", "retained", "active"])
            )
            existing = db.execute(stmt).scalar_one_or_none()
            if existing:
                logger.info("Found existing registered baseline version: %s (%s)", existing.id, existing.upstream_version)
                return existing

            # Prepare baseline snapshot from official clone
            logger.info("Creating initial immutable snapshot from local official repository...")
            baseline = prepare_repository_version(
                source_dir=NUCLEI_TEMPLATES_OFFICIAL_DIR,
                upstream_version=tag,
                upstream_commit=commit,
                db=db
            )
            return baseline

        raise FileNotFoundError(f"Official template repository not found at {NUCLEI_TEMPLATES_OFFICIAL_DIR}")
    finally:
        if close_db:
            db.close()
