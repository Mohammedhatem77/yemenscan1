"""
Authentication & RBAC Router for YemenScan.

Provides endpoints for:
- POST /api/auth/register: Self-registration with default role 'analyst'.
- POST /api/auth/login: Credential verification, constant-time failure response (anti-user enumeration), and JWT token issuance.
- POST /api/auth/refresh: Access token renewal using valid refresh tokens.
- GET  /api/auth/me: Retrieve profile and active role of currently authenticated user.
"""

from datetime import datetime
import re
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func
from sqlalchemy.orm import Session

from database import get_db
from models.user import User, UserRole
from core.security import (
    verify_password,
    get_password_hash,
    create_access_token,
    create_refresh_token,
    decode_token,
    validate_password_strength,
)
from core.dependencies import get_current_user

router = APIRouter(prefix="", tags=["Authentication & RBAC"])

# Regular expression for email validation
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
# Dummy hash for constant-time mitigation against timing attacks on nonexistent accounts
DUMMY_HASH = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$dGVzdGhhc2h2YWx1ZQ"


# ---------------------------------------------------------------------------
# Pydantic Schemas
# ---------------------------------------------------------------------------

class UserRegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, description="Unique username")
    email: str = Field(..., max_length=255, description="Valid corporate or user email")
    password: str = Field(..., min_length=8, max_length=128, description="Strong password")

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        clean = v.strip().lower()
        if not re.match(r"^[a-z0-9_-]+$", clean):
            raise ValueError("Username can only contain alphanumeric characters, underscores, and hyphens.")
        return clean

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        clean = v.strip().lower()
        if not EMAIL_REGEX.match(clean):
            raise ValueError("Invalid email format.")
        return clean

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        is_valid, msg = validate_password_strength(v)
        if not is_valid:
            raise ValueError(msg)
        return v


class UserLoginRequest(BaseModel):
    username_or_email: str = Field(..., description="Username or registered email address")
    password: str = Field(..., min_length=1, description="Account password")


class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    role: str
    is_active: bool
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in_minutes: int = 30
    user: UserResponse


class RefreshTokenRequest(BaseModel):
    refresh_token: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register new user account",
    description="Registers a new platform user with the default role of 'analyst' and Argon2id password hashing."
)
def register(request: UserRegisterRequest, db: Session = Depends(get_db)):
    """
    Registers a new user account.
    Enforces uniqueness of username and email.
    Stores password hashed with Argon2id.
    """
    # Check if username or email already exists
    existing_user = db.query(User).filter(
        (User.username == request.username) | (User.email == request.email)
    ).first()

    if existing_user:
        if existing_user.username == request.username:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username is already taken"
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email address is already registered"
            )

    # Securely hash the password using Argon2id
    hashed_pwd = get_password_hash(request.password)

    new_user = User(
        username=request.username,
        email=request.email,
        hashed_password=hashed_pwd,
        role=UserRole.analyst.value,  # Default role analyst per specification
        is_active=True,
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="User login and JWT token issuance",
    description="Authenticates via username/email and password. Returns uniform 'Invalid credentials' on failure to prevent User Enumeration."
)
def login(request: UserLoginRequest, db: Session = Depends(get_db)):
    """
    Authenticates user and returns JWT access and refresh tokens.
    Implements anti-enumeration security controls (generic error and constant-time behavior).
    """
    identifier = request.username_or_email.strip().lower()

    # Query user by username or email (case-insensitive)
    user = db.query(User).filter(
        (func.lower(User.username) == identifier) | (func.lower(User.email) == identifier)
    ).first()

    # Constant-time mitigation against user enumeration
    if not user:
        # Perform a dummy verification to burn comparable CPU cycles
        verify_password("dummy_password_for_timing", DUMMY_HASH)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Verify password hash
    if not verify_password(request.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated. Please contact an administrator."
        )

    token_payload = {
        "sub": user.username,
        "user_id": user.id,
        "role": user.role,
        "email": user.email,
    }

    access_token = create_access_token(token_payload)
    refresh_token = create_refresh_token(token_payload)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="Bearer",
        expires_in_minutes=30,
        user=UserResponse.model_validate(user),
    )


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Refresh access token",
    description="Exchanges a valid refresh token for a fresh access token."
)
def refresh_token(request: RefreshTokenRequest, db: Session = Depends(get_db)):
    """
    Renews access token using a valid refresh token.
    """
    try:
        payload = decode_token(request.refresh_token)
        if payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type: Expected refresh token",
                headers={"WWW-Authenticate": "Bearer"},
            )

        username = payload.get("sub")
        if not username:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token subject",
                headers={"WWW-Authenticate": "Bearer"},
            )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = db.query(User).filter(User.username == username).first()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or deactivated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token_payload = {
        "sub": user.username,
        "user_id": user.id,
        "role": user.role,
        "email": user.email,
    }

    new_access_token = create_access_token(token_payload)
    new_refresh_token = create_refresh_token(token_payload)

    return TokenResponse(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        token_type="Bearer",
        expires_in_minutes=30,
        user=UserResponse.model_validate(user),
    )


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current user profile",
    description="Returns identity, email, and assigned RBAC role of the currently authenticated user."
)
def get_me(current_user: User = Depends(get_current_user)):
    """
    Protected endpoint: Returns identity and role of the currently authenticated user.
    """
    return current_user
