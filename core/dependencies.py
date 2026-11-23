"""
Authentication, RBAC and Data Ownership Dependencies for YemenScan.

Provides:
- JWT token validation and current active user extraction (get_current_user).
- Role-Based Access Control dependency factory (RoleChecker).
- Ownership Isolation verification (verify_ownership) preventing unauthorized cross-tenant data access.
"""

from typing import List, Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
import jwt
from sqlalchemy.orm import Session

from database import get_db
from models.user import User, UserRole
from core.security import decode_token

# OAuth2 Password Bearer scheme configured to point to the login endpoint
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/api/auth/login",
    auto_error=False
)


def get_current_user(
    token: Optional[str] = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> User:
    """
    FastAPI dependency that extracts and validates the JWT Bearer token from headers,
    retrieves the authenticated user from the database, and verifies account active status.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = decode_token(token)
        token_type = payload.get("type")
        if token_type != "access":
            # Refresh tokens must not be permitted for general API access
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type: Expected access token",
                headers={"WWW-Authenticate": "Bearer"},
            )

        username: Optional[str] = payload.get("sub")
        if not username:
            raise credentials_exception

    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired. Please refresh your session.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.PyJWTError:
        raise credentials_exception

    # Query the user in the database
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated. Contact an administrator."
        )

    return user


class RoleChecker:
    """
    RBAC dependency factory for endpoint-level authorization.
    Enforces allowed roles (admin, analyst, viewer).
    """

    def __init__(self, allowed_roles: List[str]):
        self.allowed_roles = [
            r.value if hasattr(r, "value") else str(r) for r in allowed_roles
        ]

    def __call__(self, current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in self.allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Access denied: Role '{current_user.role}' is not authorized "
                    f"for this action. Required: {', '.join(self.allowed_roles)}"
                )
            )
        return current_user


def verify_ownership(resource_owner_id: Optional[int], current_user: User) -> bool:
    """
    Enforces Data Ownership Isolation.
    - Admins: Permitted full read/write/delete access across all resources.
    - Analysts / Viewers: Strictly restricted to resources where owner_id == current_user.id.
    Raises HTTP 403 Forbidden on ownership mismatch.
    """
    if current_user.role == UserRole.admin.value:
        return True

    if resource_owner_id is not None and resource_owner_id == current_user.id:
        return True

    # If unowned legacy resource, only admin can manage it
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Access denied: You do not have ownership privileges for this resource"
    )


def filter_by_ownership(query, model, current_user: User):
    """
    Helper to scope SQLAlchemy queries to the current user's data when not admin.
    """
    if current_user.role == UserRole.admin.value:
        return query
    return query.filter(model.owner_id == current_user.id)
