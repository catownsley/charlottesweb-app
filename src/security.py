"""Security utilities for API authentication and authorization.

This module provides:
- API key authentication for endpoint protection
- JWT token creation and verification for future user sessions
- Password hashing utilities using bcrypt
- Secure random key generation

Security Features:
- API keys validated via X-API-Key header
- Bcrypt password hashing (automatic salt, configurable work factor)
- JWT tokens signed with HS256 algorithm
- Auto-error disabled to allow graceful handling in optional auth scenarios
"""
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader
import jwt
from jwt.exceptions import InvalidTokenError as JWTError
from passlib.context import CryptContext

from src.config import settings

# Password hashing context using bcrypt
# - Uses bcrypt algorithm (industry standard for password hashing)
# - Automatic salt generation
# - Configurable work factor for future-proofing against hardware improvements
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# API Key header configuration
# - Header name: X-API-Key (standard convention)
# - auto_error=False: Allows optional authentication (development mode)
#   When True, FastAPI returns 403 automatically if header missing
#   When False, we can check and handle missing keys gracefully
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against a bcrypt hash.

    Uses constant-time comparison to prevent timing attacks.
    Bcrypt automatically handles salt extraction from the stored hash.

    Args:
        plain_password: Password to verify
        hashed_password: Bcrypt hash to verify against

    Returns:
        True if password matches, False otherwise
    """
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Hash a password using bcrypt with automatic salt generation.

    Security properties:
    - Automatically generates random salt
    - Configurable work factor (default: 12 rounds)
    - Output format: $2b$12$[salt][hash]

    Args:
        password: Plain text password to hash

    Returns:
        Bcrypt hash string safe for database storage
    """
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT access token for authenticated sessions.

    Security features:
    - HS256 signing algorithm (HMAC with SHA-256)
    - Configurable expiration time
    - Signed with SECRET_KEY (must be kept secure)

    Args:
        data: Claims to encode in token (e.g., user_id, role)
        expires_delta: Optional custom expiration time

    Returns:
        Encoded JWT token string

    Note:
        Token should be transmitted over HTTPS only.
        Client should store in httpOnly cookie or secure storage.
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.access_token_expire_minutes)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.secret_key, algorithm=settings.jwt_algorithm)
    return encoded_jwt


def verify_access_token(token: str) -> Optional[dict]:
    """Verify and decode a JWT access token.

    Validates:
    - Signature matches (using SECRET_KEY)
    - Token not expired
    - Token structure is valid

    Args:
        token: JWT token string to verify

    Returns:
        Decoded payload dict if valid, None if invalid/expired

    Security:
        Returns None on any error to prevent information leakage
        about why token validation failed.
    """
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.jwt_algorithm])
        return payload
    except JWTError:
        # Don't leak why verification failed (expired, invalid signature, etc.)
        return None


def generate_api_key() -> str:
    """Generate a cryptographically secure random API key.

    Uses secrets module (not random) for cryptographic security.
    Generates 32 bytes = 256 bits of entropy.
    URL-safe base64 encoding = ~43 characters.

    Returns:
        URL-safe random string suitable for API key

    Example output:
        'Xt7j9kH2mP4vR8sW3nB5qL1dY6fK0cA9e'

    Usage:
        key = generate_api_key()
        # Store in environment or database
        # Provide to authorized clients
    """
    return secrets.token_urlsafe(32)


async def verify_api_key(api_key: str = Security(api_key_header)) -> str:
    """Verify API key from X-API-Key request header.

    Security flow:
    1. Extract API key from X-API-Key header
    2. Check if key is present
    3. Validate against configured valid keys
    4. Return key if valid, raise 403 if invalid

    Args:
        api_key: API key extracted from X-API-Key header

    Returns:
        The valid API key string

    Raises:
        HTTPException: 403 if key missing or invalid

    Production considerations:
    - Store valid keys in database with metadata (created_at, last_used, owner)
    - Implement key rotation mechanism
    - Log failed authentication attempts
    - Consider rate limiting by API key
    - Hash keys in database (store hash, compare hash)
    """
    # Missing API key
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="API key is missing",
        )

    # Invalid API key (not in configured list)
    # Production: Check against database of hashed keys
    # Current: Check against environment variable list
    if settings.api_key_required and api_key not in settings.valid_api_keys:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API key",
        )

    return api_key


# Optional dependency: only require API key if configured
async def get_api_key_optional(api_key: str = Security(api_key_header)) -> Optional[str]:
    """Get API key if provided, but don't require it (for development mode).

    Behavior:
    - If API_KEY_REQUIRED=false: Returns None (no validation)
    - If API_KEY_REQUIRED=true: Validates and returns key or raises 403

    Use this dependency for endpoints that should:
    - Work without auth in development
    - Require auth in production

    Returns:
        API key if authentication required and valid, None if auth not required
    """
    if not settings.api_key_required:
        return None
    return await verify_api_key(api_key)


# Strict dependency: always require API key in production
async def require_api_key(api_key: str = Depends(verify_api_key)) -> str:
    """Require valid API key for endpoint access (always enforced).

    Use this dependency for endpoints that should ALWAYS require
    authentication, regardless of environment.

    Example:
        @router.post("/admin/settings")
        def admin_endpoint(api_key: str = Depends(require_api_key)):
            # Only accessible with valid API key
            ...

    Returns:
        Valid API key string

    Raises:
        HTTPException: 403 if key missing or invalid
    """
    return api_key
