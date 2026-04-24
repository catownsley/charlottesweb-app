"""Security utilities for API authentication and authorization.

This module provides:
- API key authentication for endpoint protection
- JWT token creation and verification for future user sessions
- OAuth/OIDC token validation for external IdP integration
- Password hashing utilities using bcrypt
- Secure random key generation
- Pluggable auth: switches between local API keys and external OAuth

Security Features:
- API keys validated via X-API-Key header
- OAuth Bearer tokens validated against external IdP JWKS
- Bcrypt password hashing (automatic salt, configurable work factor)
- JWT tokens signed with HS256 (local) or validated via RS256 (external IdP)
- Auto-error disabled to allow graceful handling in optional auth scenarios
"""

import logging
import secrets
from datetime import UTC, datetime, timedelta

import jwt
from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from jwt.exceptions import InvalidTokenError as JWTError
from passlib.context import CryptContext

from src.config import settings

logger = logging.getLogger(__name__)

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


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
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
        expire = datetime.now(UTC) + expires_delta
    else:
        expire = datetime.now(UTC) + timedelta(
            minutes=settings.access_token_expire_minutes
        )
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(
        to_encode, settings.secret_key, algorithm=settings.jwt_algorithm
    )
    return encoded_jwt


def verify_access_token(token: str) -> dict | None:
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
        payload = jwt.decode(
            token, settings.secret_key, algorithms=[settings.jwt_algorithm]
        )
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
async def get_api_key_optional(api_key: str = Security(api_key_header)) -> str | None:
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


# ============================================================================
# OAUTH / OIDC - EXTERNAL IDENTITY PROVIDER SUPPORT
# ============================================================================
# When OAUTH_ENABLED=true, the app validates Bearer tokens issued by an
# external IdP (Okta, Azure AD, Google Workspace, etc.) using the IdP's
# public keys (JWKS).
#
# This enables plug-and-play deployment in customer environments:
#   1. Customer configures their IdP with CharlottesWeb as a registered app
#   2. Set OAUTH_ENABLED=true and the IdP's issuer URL
#   3. Users authenticate with the IdP and receive a Bearer token
#   4. CharlottesWeb validates that token against the IdP's JWKS
#
# When OAUTH_ENABLED=false (default), existing API key auth is used.
# ============================================================================

# Bearer token header for OAuth (Authorization: Bearer <token>)
bearer_scheme = HTTPBearer(auto_error=False)

# Cache for JWKS client (fetches and caches IdP public keys)
_jwks_client = None


def get_jwks_client() -> jwt.PyJWKClient:
    """Get or create a cached PyJWKClient for the configured IdP.

    The PyJWKClient handles:
    - Fetching the JWKS (JSON Web Key Set) from the IdP
    - Caching the keys to avoid fetching on every request
    - Key rotation (re-fetches when an unknown key ID is encountered)

    Returns:
        jwt.PyJWKClient configured for the IdP's JWKS endpoint

    Raises:
        ValueError: If OAuth is enabled but issuer URL is not configured
    """
    global _jwks_client

    if _jwks_client is not None:
        return _jwks_client

    if not settings.oauth_issuer_url:
        raise ValueError("OAUTH_ISSUER_URL must be set when OAUTH_ENABLED=true")

    # Determine JWKS URI: use explicit override or derive from issuer
    if settings.oauth_jwks_uri:
        jwks_uri = settings.oauth_jwks_uri
    else:
        # Standard OIDC discovery: issuer + /.well-known/openid-configuration
        # The JWKS URI is at issuer + /v1/keys (Okta) or issuer + /discovery/v2.0/keys (Azure)
        # PyJWKClient handles this by fetching directly from the JWKS endpoint
        # Most IdPs publish JWKS at: {issuer}/.well-known/jwks.json
        # or it can be discovered from: {issuer}/.well-known/openid-configuration
        issuer = settings.oauth_issuer_url.rstrip("/")
        jwks_uri = f"{issuer}/.well-known/jwks.json"

    _jwks_client = jwt.PyJWKClient(jwks_uri)
    logger.info("OAuth JWKS client initialized")
    return _jwks_client


def verify_oauth_token(token: str) -> dict:
    """Verify and decode a Bearer token from an external IdP.

    Validation steps:
    1. Fetch the IdP's public signing key (cached via JWKS)
    2. Verify the token signature (RS256)
    3. Check token expiration
    4. Validate issuer matches configured IdP
    5. Validate audience matches this application
    6. Return decoded claims

    Args:
        token: JWT Bearer token string

    Returns:
        Decoded token claims (sub, email, roles, etc.)

    Raises:
        HTTPException: 401 if token is invalid, expired, or untrusted
    """
    try:
        client = get_jwks_client()
        # Get the signing key that matches this token's key ID (kid header)
        signing_key = client.get_signing_key_from_jwt(token)

        # Build decode options
        decode_options = {
            "verify_exp": True,  # Check expiration
            "verify_aud": bool(settings.oauth_audience),  # Check audience if configured
            "verify_iss": bool(settings.oauth_issuer_url),  # Check issuer
        }

        # Build decode kwargs
        decode_kwargs = {
            "algorithms": [
                "RS256",
                "RS384",
                "RS512",
            ],  # RSA algorithms (IdPs use asymmetric)
        }
        if settings.oauth_audience:
            decode_kwargs["audience"] = settings.oauth_audience
        if settings.oauth_issuer_url:
            decode_kwargs["issuer"] = settings.oauth_issuer_url

        payload = jwt.decode(
            token,
            signing_key.key,
            options=decode_options,
            **decode_kwargs,
        )

        return payload

    except jwt.exceptions.ExpiredSignatureError:
        logger.warning("OAuth token expired")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None
    except jwt.exceptions.InvalidAudienceError:
        logger.warning("OAuth token audience mismatch")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None
    except jwt.exceptions.InvalidIssuerError:
        logger.warning("OAuth token issuer mismatch")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None
    except JWTError as e:
        logger.warning("OAuth token validation failed: %s", e)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None
    except Exception as e:
        logger.error("OAuth token verification error: %s", e)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None


# ============================================================================
# PLUGGABLE AUTH DEPENDENCY
# ============================================================================
# Use this as the single auth dependency across all endpoints.
# It automatically selects the right auth method based on configuration:
#   - OAUTH_ENABLED=true  → validates Bearer token from external IdP
#   - OAUTH_ENABLED=false → uses existing API key auth
# ============================================================================


async def get_current_auth(
    request: Request,
    api_key: str = Security(api_key_header),
    bearer: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
) -> dict | str | None:
    """Pluggable authentication dependency.

    Behavior:
    - OAUTH_ENABLED=true:
        Validates Bearer token from Authorization header against external IdP.
        Returns decoded token claims (dict with sub, email, roles, etc.)
    - OAUTH_ENABLED=false:
        Falls back to API key authentication (existing behavior).
        Returns API key string or None if not required.

    Usage:
        @router.get("/protected")
        def protected_endpoint(auth: dict | str | None = Depends(get_current_auth)):
            if isinstance(auth, dict):
                # OAuth mode: auth contains token claims
                user_email = auth.get("email")
            else:
                # API key mode: auth is the key string or None
                pass

    Returns:
        OAuth mode: decoded token claims (dict)
        API key mode: API key string or None

    Raises:
        HTTPException: 401/403 if authentication fails
    """
    if settings.oauth_enabled:
        # OAuth mode: require Bearer token
        if not bearer:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Bearer token required",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return verify_oauth_token(bearer.credentials)

    # Local mode: use existing API key auth
    if not settings.api_key_required:
        return None
    return await verify_api_key(api_key)
