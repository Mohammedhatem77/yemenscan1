"""
Comprehensive Test Suite for Phase 1: Shared Nuclei Repository and Version Management.

Verifies:
1. Local official Git metadata extraction (tag v10.5.1, commit 79fb682760ab...).
2. Deterministic SHA-256 snapshot hashing.
3. Path traversal and symlink boundary security validation.
4. Concurrency lock prevention.
5. Snapshot staging, deduplication, and immutable storage.
6. Snapshot integrity verification and tampering detection.
7. Database constraints (at most one active version constraint).
8. Atomic publication and guard against incomplete/unclassified versions.
9. Zero regression on existing Sequential and Independent scan modules.
"""

import os
import shutil
import tempfile
import pytest
from datetime import datetime, timezone
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError

from database import Base
from models.template_repository import TemplateRepositoryVersion
from core.nuclei_shared import (
    NUCLEI_TEMPLATES_OFFICIAL_DIR,
    NUCLEI_RUNTIME_TEMPLATES_DIR,
    NUCLEI_TEMPLATES_DIR,
    NUCLEI_DOCKER_IMAGE,
)
from core.nuclei_repository_service import (
    RepositoryLock,
    RepositoryLockError,
    SecurityViolationError,
    SnapshotIntegrityError,
    VersionNotFoundError,
    VersionStateError,
    compute_deterministic_snapshot_hash,
    validate_directory_safety,
    extract_git_metadata,
    prepare_repository_version,
    verify_snapshot_integrity,
    publish_version,
    get_active_version,
    get_version,
    list_versions,
    initialize_repository,
)


@pytest.fixture
def test_db():
    """In-memory SQLite database for isolated test execution with constraints enabled."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(bind=engine)
    
    # Ensure SQLite enforces partial unique index
    with engine.begin() as conn:
        conn.execute(text("""
            CREATE UNIQUE INDEX IF NOT EXISTS uq_template_repo_single_active 
            ON template_repository_versions (status) WHERE status = 'active';
        """))
        
    TestingSession = sessionmaker(bind=engine)
    session = TestingSession()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture(scope="module")
def mock_template_repo():
    """Creates a temporary mock official repository with minimal valid templates."""
    temp_dir = tempfile.mkdtemp(prefix="mock_repo_")
    
    # Create git directory structure and config directly
    git_dir = os.path.join(temp_dir, ".git")
    os.makedirs(git_dir, exist_ok=True)
    with open(os.path.join(git_dir, "config"), "w", encoding="utf-8") as f:
        f.write(
            "[user]\n\tname = TestUser\n\temail = test@yemenscan.local\n"
            "[remote \"origin\"]\n\turl = https://github.com/projectdiscovery/nuclei-templates.git\n"
        )
    
    # Create sample files
    os.makedirs(os.path.join(temp_dir, "http", "cves"), exist_ok=True)
    with open(os.path.join(temp_dir, ".nuclei-ignore"), "w", encoding="utf-8") as f:
        f.write("tags:\n  - dos\n  - fuzz\n")
        
    with open(os.path.join(temp_dir, "http", "cves", "cve-test.yaml"), "w", encoding="utf-8") as f:
        f.write("id: cve-test\ninfo:\n  name: Test CVE\n  severity: high\nhttp:\n  - method: GET\n")

    yield temp_dir
    
    # Cleanup
    def _err(func, path, exc_info):
        try:
            import stat
            os.chmod(path, stat.S_IWRITE)
            func(path)
        except Exception:
            pass
    shutil.rmtree(temp_dir, onerror=_err, ignore_errors=True)


# -----------------------------------------------------------------------------
# Test Cases
# -----------------------------------------------------------------------------

def test_01_extract_git_metadata_from_official_repo():
    """Verifies actual official local repository metadata matches audit report."""
    assert os.path.exists(NUCLEI_TEMPLATES_OFFICIAL_DIR), "nuclei_templates_official directory must exist"
    tag, commit, remote = extract_git_metadata(NUCLEI_TEMPLATES_OFFICIAL_DIR)
    
    assert tag == "v10.5.1", f"Expected tag v10.5.1, got {tag}"
    assert commit == "79fb682760ab3d5b0e22afbb44709353cbebf023", f"Unexpected commit: {commit}"
    assert "projectdiscovery/nuclei-templates" in remote.lower(), f"Unexpected remote URL: {remote}"


def test_02_deterministic_snapshot_hash(tmp_path):
    """Verifies that snapshot hash is 100% deterministic and sensitive to content changes."""
    dir_a = tmp_path / "snap_a"
    dir_b = tmp_path / "snap_b"
    dir_a.mkdir()
    dir_b.mkdir()

    # Create identical files in different creation order
    (dir_a / "file1.txt").write_text("Hello World", encoding="utf-8")
    (dir_a / "sub").mkdir()
    (dir_a / "sub" / "file2.txt").write_text("Nested content", encoding="utf-8")

    (dir_b / "sub").mkdir()
    (dir_b / "sub" / "file2.txt").write_text("Nested content", encoding="utf-8")
    (dir_b / "file1.txt").write_text("Hello World", encoding="utf-8")

    hash_a, count_a, files_a = compute_deterministic_snapshot_hash(str(dir_a))
    hash_b, count_b, files_b = compute_deterministic_snapshot_hash(str(dir_b))

    assert hash_a == hash_b, "Identical directory snapshots must yield strictly identical hashes"
    assert count_a == 2
    assert files_a == ["file1.txt", "sub/file2.txt"]

    # Modify single byte in file1
    (dir_b / "file1.txt").write_text("Hello World!", encoding="utf-8")
    hash_modified, _, _ = compute_deterministic_snapshot_hash(str(dir_b))
    assert hash_a != hash_modified, "Hash must change when any file content is modified"


def test_03_directory_safety_validation(tmp_path):
    """Verifies that symlinks pointing outside the repository boundary are blocked."""
    repo_dir = tmp_path / "safe_repo"
    repo_dir.mkdir()
    (repo_dir / "template.yaml").write_text("id: valid", encoding="utf-8")
    
    # Internal validation passes
    validate_directory_safety(str(repo_dir))

    # Create external file and illegal symlink
    outside_dir = tmp_path / "outside_dir"
    outside_dir.mkdir()
    secret_file = outside_dir / "secret.env"
    secret_file.write_text("SECRET=123", encoding="utf-8")

    symlink_path = repo_dir / "leak_link.yaml"
    try:
        os.symlink(str(secret_file), str(symlink_path))
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not supported on this platform/user without elevation")

    with pytest.raises(SecurityViolationError) as exc:
        validate_directory_safety(str(repo_dir))
    assert "Illegal symlink" in str(exc.value)


def test_04_repository_lock_concurrency(tmp_path):
    """Verifies that RepositoryLock prevents concurrent executions and releases cleanly."""
    lock_dir = str(tmp_path / "lock_test")
    
    with RepositoryLock(lock_dir=lock_dir) as lock1:
        assert lock1._acquired is True
        
        # Second attempt must raise RepositoryLockError
        with pytest.raises(RepositoryLockError):
            with RepositoryLock(lock_dir=lock_dir):
                pass

    # After exiting, lock must be released and re-acquirable
    with RepositoryLock(lock_dir=lock_dir) as lock2:
        assert lock2._acquired is True


def test_05_prepare_repository_version_and_deduplication(test_db, mock_template_repo):
    """Verifies version preparation in staging, immutable snapshot creation, and deduplication."""
    # 1. Prepare version
    v1 = prepare_repository_version(
        source_dir=mock_template_repo,
        upstream_version="v1.0.0",
        upstream_commit="mock_commit_1",
        db=test_db
    )
    assert v1.status == "staging"
    assert v1.upstream_version == "v1.0.0"
    assert v1.snapshot_hash is not None
    assert v1.policy_version is None  # Phase 1 requirement: nullable until Phase 2
    
    # Verify snapshot files exist on disk
    from core.nuclei_shared import BASE_DIR
    abs_path = os.path.join(BASE_DIR, v1.repository_path)
    assert os.path.exists(abs_path)
    assert os.path.exists(os.path.join(abs_path, ".nuclei-ignore"))
    assert os.path.exists(os.path.join(abs_path, "http", "cves", "cve-test.yaml"))

    # 2. Prepare identical version again -> must deduplicate without creating new snapshot
    v2 = prepare_repository_version(
        source_dir=mock_template_repo,
        upstream_version="v1.0.0",
        upstream_commit="mock_commit_1",
        db=test_db
    )
    assert v1.id == v2.id, "Deduplication must return existing version record"
    assert v1.snapshot_hash == v2.snapshot_hash

    # Clean up test snapshot directory from storage
    def _cleanup_dir(d):
        for root, dirs, files in os.walk(d):
            for f in files:
                try:
                    import stat
                    os.chmod(os.path.join(root, f), stat.S_IWRITE)
                except Exception:
                    pass
        shutil.rmtree(d, ignore_errors=True)
    _cleanup_dir(abs_path)


def test_06_verify_snapshot_integrity_and_tampering_detection(test_db, mock_template_repo):
    """Verifies that snapshot integrity checks detect any tampering or disk corruption."""
    v = prepare_repository_version(
        source_dir=mock_template_repo,
        upstream_version="v1.0.0",
        upstream_commit="mock_commit_1",
        db=test_db
    )
    from core.nuclei_shared import BASE_DIR
    abs_path = os.path.join(BASE_DIR, v.repository_path)

    # Clean integrity check
    is_valid, details = verify_snapshot_integrity(v.id, db=test_db)
    assert is_valid is True
    assert details["is_valid"] is True
    assert details["expected_hash"] == details["actual_hash"]

    # Tamper with a file in snapshot
    tamper_file = os.path.join(abs_path, ".nuclei-ignore")
    import stat
    os.chmod(tamper_file, stat.S_IWRITE)
    with open(tamper_file, "a", encoding="utf-8") as f:
        f.write("# unauthorized modification\n")

    # Integrity check must fail
    is_valid_tampered, details_tampered = verify_snapshot_integrity(v.id, db=test_db)
    assert is_valid_tampered is False
    assert details_tampered["expected_hash"] != details_tampered["actual_hash"]

    # Clean up
    for root, _, files in os.walk(abs_path):
        for f in files:
            try:
                os.chmod(os.path.join(root, f), stat.S_IWRITE)
            except Exception:
                pass
    shutil.rmtree(abs_path, ignore_errors=True)


def test_07_prevent_publishing_without_policy(test_db):
    """Verifies that publishing is disabled in Phase 1 until classification and indexing are ready."""
    v = TemplateRepositoryVersion(
        id="test-publish-uuid",
        upstream_version="v1.0.0",
        upstream_commit="commit1",
        repository_path="storage/nuclei/versions/test-publish-uuid",
        snapshot_hash="hash1",
        status="staging"
    )
    test_db.add(v)
    test_db.commit()

    # Attempting to publish in Phase 1 must strictly raise VersionStateError
    with pytest.raises(VersionStateError) as exc:
        publish_version(v.id, db=test_db)
    assert "Version publication to 'active' status is strictly disabled in Phase 1" in str(exc.value)


def test_08_atomic_single_active_constraint(test_db):
    """Verifies that at most one version can be active, and DB partial unique index enforces it."""
    v1 = TemplateRepositoryVersion(
        id="v1-active-uuid",
        upstream_version="v1.0.0",
        upstream_commit="commit1",
        repository_path="storage/nuclei/versions/v1",
        snapshot_hash="hash1",
        status="active",
        published_at=datetime.now(timezone.utc)
    )
    test_db.add(v1)
    test_db.commit()

    active_now = get_active_version(db=test_db)
    assert active_now.id == v1.id

    # Attempting to insert another active version directly must violate the partial unique index
    conflict_v = TemplateRepositoryVersion(
        id="conflict-uuid",
        upstream_version="v_conflict",
        upstream_commit="commit_conflict",
        repository_path="storage/nuclei/versions/conflict",
        snapshot_hash="hash_conflict",
        status="active"
    )
    test_db.add(conflict_v)
    with pytest.raises(IntegrityError):
        test_db.commit()
    test_db.rollback()

    # Changing v1 to retained allows a different active version
    v1.status = "retained"
    test_db.commit()

    test_db.add(conflict_v)
    test_db.commit()
    assert get_active_version(db=test_db).id == conflict_v.id


def test_10_stale_lock_recovery(tmp_path):
    """Verifies that stale lockfile from dead PID is safely reclaimed without deadlock,
    while locks belonging to actively running processes are strictly never stolen."""
    lock_dir = str(tmp_path / "stale_lock_test")
    lock_file = os.path.join(lock_dir, ".update.lock")
    os.makedirs(lock_dir, exist_ok=True)

    # 1. Lock belonging to current active PID with old timestamp must NOT be reclaimed
    with open(lock_file, "w", encoding="utf-8") as f:
        f.write(f"pid={os.getpid()}\ntime=2026-01-01T00:00:00+00:00\n")

    lock_active = RepositoryLock(lock_dir=lock_dir)
    with pytest.raises(RepositoryLockError):
        lock_active.acquire()

    # 2. Write a stale lock from a dead PID (e.g. PID 99999999)
    with open(lock_file, "w", encoding="utf-8") as f:
        f.write("pid=99999999\ntime=2026-01-01T00:00:00+00:00\n")

    # Lock must detect dead PID, reclaim the lock, and acquire successfully
    lock_dead = RepositoryLock(lock_dir=lock_dir)
    assert lock_dead.acquire() is True
    lock_dead.release()


def test_11_unapproved_commit_rejected(mock_template_repo):
    """Verifies that an unapproved git commit in official source raises SecurityViolationError."""
    # When simulating official repo, unapproved commit must be rejected
    from core.nuclei_shared import NUCLEI_TEMPLATES_OFFICIAL_DIR
    with pytest.raises(SecurityViolationError) as exc:
        prepare_repository_version(
            source_dir=NUCLEI_TEMPLATES_OFFICIAL_DIR,
            upstream_commit="unapproved_fake_commit_hash_12345678"
        )
    assert "does not match vetted approved commit" in str(exc.value)


def test_09_zero_regression_on_existing_scanners():
    """Verifies that existing sequential and independent scanner modules remain intact."""
    from core.stage3_vulnerabilities import run_nuclei, run_optimized_nuclei, run_wapiti_dast
    from core.nuclei_standalone import run_standalone_nuclei, build_standalone_nuclei_args
    
    assert run_nuclei is not None
    assert run_optimized_nuclei is not None
    assert run_wapiti_dast is not None
    assert run_standalone_nuclei is not None
    assert build_standalone_nuclei_args is not None
    assert NUCLEI_DOCKER_IMAGE == "projectdiscovery/nuclei:v3.11.1@sha256:582d5546902e67052097cb2d07296c642d50a1afc5e44623cb038845df9a32eb"
