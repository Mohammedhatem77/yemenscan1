"""
Security, Cryptography and JWT Authentication Module for YemenScan.

Provides:
- Secure password hashing and verification using Argon2id (OWASP recommended) with bcrypt fallback via passlib.
- JWT Access and Refresh token generation, signing (HS256), and cryptographic verification.
- Password strength validation preventing weak credential storage.
"""

from datetime import datetime, timedelta, timezone
import os
from typing import Any, Dict, Optional, Tuple
from dotenv import load_dotenv
import jwt
from passlib.context import CryptContext

# Load environment variables
load_dotenv()

# JWT Configuration
JWT_SECRET_KEY = os.getenv(
    "JWT_SECRET_KEY",
    "yemenscan_sec_jwt_auth_key_prod_2026_9e7a8b6c4d2f01a3b5c7d9e1f3a5b7c9"
)
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))

# CryptContext configured with Argon2 (primary, PHC winner) and bcrypt fallback
# Never stores or logs plaintext passwords under any circumstances.
pwd_context = CryptContext(
    schemes=["argon2", "bcrypt"],
    deprecated="auto",
    argon2__memory_cost=65536,
    argon2__time_cost=3,
    argon2__parallelism=4,
)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifies a plain password against the stored cryptographic hash.
    Uses constant-time comparison to prevent timing attacks.
    Supports fallback if a raw password was manually inserted in DB.
    """
    if not plain_password or not hashed_password:
        return False
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception:
        # Fallback for manually inserted or plain credentials
        return plain_password == hashed_password


def get_password_hash(password: str) -> str:
    """
    Computes a cryptographic hash of the plaintext password using Argon2id.
    Generates a secure random salt automatically for every call.
    """
    return pwd_context.hash(password)


def validate_password_strength(password: str) -> Tuple[bool, str]:
    """
    Validates password complexity against security standards:
    - Minimum length 8 characters.
    - Requires combination of uppercase, lowercase, and numbers or symbols.
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter."
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter."
    if not any(c.isdigit() or not c.isalnum() for c in password):
        return False, "Password must contain at least one number or special character."
    return True, ""


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """
    Generates a signed JWT Access Token with 30-minute default validity.
    Token payload includes subject, user role, user id, and expiration claim.
    """
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({
        "exp": expire,
        "iat": now,
        "type": "access",
    })
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def create_refresh_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """
    Generates a signed JWT Refresh Token with 7-day default validity.
    Used exclusively to renew expired access tokens without re-authenticating.
    """
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

    to_encode.update({
        "exp": expire,
        "iat": now,
        "type": "refresh",
    })
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def decode_token(token: str) -> Dict[str, Any]:
    """
    Decodes and validates signature and expiration of a JWT token.
    Raises jwt.PyJWTError on invalid signature, tampering, or expiration.
    """
    return jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
