"""
Comprehensive Unit & Integration Tests for YemenScan Authentication, RBAC, and Ownership Isolation.
"""

import os
import sys
from fastapi import HTTPException

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from database import Base, engine, SessionLocal
from models.user import User, UserRole
from models.scan import Targets, ScanSessions
from core.security import (
    get_password_hash,
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_token,
    validate_password_strength,
)
from core.dependencies import (
    RoleChecker,
    verify_ownership,
    filter_by_ownership,
    get_current_user,
)
from routers.auth import (
    register,
    login,
    get_me,
    UserRegisterRequest,
    UserLoginRequest,
)


def run_all_tests():
    print("[*] Starting YemenScan Auth & RBAC Test Suite...", flush=True)
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    try:
        # 1. Test Password Validation & Hashing
        print("[-] Testing Password Strength Validation...", flush=True)
        valid, _ = validate_password_strength("Short1!")
        assert not valid, "Short password should fail"
        valid, _ = validate_password_strength("alllowercase123!")
        assert not valid, "Password without uppercase should fail"
        valid, msg = validate_password_strength("ValidP@ssw0rd2026")
        assert valid, f"Valid password failed: {msg}"

        h = get_password_hash("ValidP@ssw0rd2026")
        assert verify_password("ValidP@ssw0rd2026", h) is True
        assert verify_password("WrongP@ssw0rd", h) is False
        print("  -> Password validation & Argon2id hashing: PASSED")

        # 2. Test User Registration
        print("[-] Testing User Registration Endpoint...", flush=True)
        test_username = "analyst_unit_test"
        test_email = "analyst_unit@yemenscan.ye"
        test_pwd = "P@sswordForUnitTest2026!"

        # Remove previous test user if exists
        db.query(User).filter(
            (User.username == test_username) | (User.email == test_email)
        ).delete()
        db.commit()

        reg_req = UserRegisterRequest(
            username=test_username,
            email=test_email,
            password=test_pwd
        )
        new_user = register(reg_req, db)
        assert new_user.username == test_username
        assert new_user.email == test_email
        assert new_user.role == UserRole.analyst.value
        assert new_user.is_active is True
        print("  -> User registration with default 'analyst' role: PASSED")

        # Test duplicate registration rejection
        try:
            register(reg_req, db)
            assert False, "Duplicate user should have raised 400"
        except HTTPException as exc:
            assert exc.status_code == 400
        print("  -> Duplicate registration rejection: PASSED")

        # 3. Test Login & JWT Token Generation
        print("[-] Testing User Login Endpoint...", flush=True)
        login_req = UserLoginRequest(
            username_or_email=test_username,
            password=test_pwd
        )
        token_res = login(login_req, db)
        assert token_res.access_token is not None
        assert token_res.refresh_token is not None
        assert token_res.token_type == "Bearer"
        assert token_res.user.username == test_username

        # Login via email identifier
        login_by_email = UserLoginRequest(
            username_or_email=test_email,
            password=test_pwd
        )
        token_res_email = login(login_by_email, db)
        assert token_res_email.access_token is not None
        print("  -> Login and JWT token issuance: PASSED")

        # 4. Test Anti-Enumeration Protection
        print("[-] Testing Anti-User Enumeration Protection...", flush=True)
        try:
            login(UserLoginRequest(username_or_email=test_username, password="WrongPassword!"), db)
            assert False, "Invalid password should raise 401"
        except HTTPException as exc:
            assert exc.status_code == 401
            assert exc.detail == "Invalid credentials"

        try:
            login(UserLoginRequest(username_or_email="completely_nonexistent_user", password="AnyPassword123!"), db)
            assert False, "Nonexistent user should raise 401"
        except HTTPException as exc:
            assert exc.status_code == 401
            assert exc.detail == "Invalid credentials"
        print("  -> Anti-enumeration uniform 'Invalid credentials' response: PASSED")

        # 5. Test Token Decoding & get_me Dependency
        print("[-] Testing Token Decoding & Current User Extraction...", flush=True)
        payload = decode_token(token_res.access_token)
        assert payload["sub"] == test_username
        assert payload["role"] == UserRole.analyst.value
        assert payload["type"] == "access"

        current_u = get_current_user(token=token_res.access_token, db=db)
        assert current_u.id == new_user.id
        assert current_u.username == test_username

        me_profile = get_me(current_user=current_u)
        assert me_profile.username == test_username
        print("  -> Current user profile retrieval: PASSED")

        # 6. Test RBAC (RoleChecker)
        print("[-] Testing Role-Based Access Control (RBAC)...", flush=True)
        admin_checker = RoleChecker(allowed_roles=["admin"])
        analyst_or_admin_checker = RoleChecker(allowed_roles=["admin", "analyst"])

        # Analyst user should pass analyst_or_admin_checker
        assert analyst_or_admin_checker(current_user=current_u).id == current_u.id

        # Analyst user should be denied access by admin_checker
        try:
            admin_checker(current_user=current_u)
            assert False, "Analyst accessing admin endpoint should raise 403"
        except HTTPException as exc:
            assert exc.status_code == 403
            assert "Access denied" in exc.detail
        print("  -> RBAC RoleChecker enforcement: PASSED")

        # 7. Test Data Ownership Isolation (verify_ownership)
        print("[-] Testing Data Ownership Isolation...", flush=True)
        admin_user = User(id=1, username="superadmin", role=UserRole.admin.value)
        analyst_user1 = User(id=10, username="analyst_1", role=UserRole.analyst.value)
        analyst_user2 = User(id=20, username="analyst_2", role=UserRole.analyst.value)

        # Admin can access any resource
        assert verify_ownership(resource_owner_id=10, current_user=admin_user) is True
        assert verify_ownership(resource_owner_id=20, current_user=admin_user) is True
        assert verify_ownership(resource_owner_id=None, current_user=admin_user) is True

        # Analyst can only access resources they own
        assert verify_ownership(resource_owner_id=10, current_user=analyst_user1) is True

        # Analyst is denied when attempting to access another user's resource
        try:
            verify_ownership(resource_owner_id=20, current_user=analyst_user1)
            assert False, "Cross-user access without ownership should raise 403"
        except HTTPException as exc:
            assert exc.status_code == 403
            assert "Access denied" in exc.detail

        print("  -> Data Ownership Isolation (Analyst isolated, Admin full-access): PASSED")

        print("\n=======================================================")
        print("  ALL AUTH, RBAC, AND OWNERSHIP TESTS PASSED (100%)    ")
        print("=======================================================")

    finally:
        db.close()


if __name__ == "__main__":
    run_all_tests()
