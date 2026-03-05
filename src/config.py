"""Application configuration with security-first settings.

All configuration is loaded from environment variables for:
- Security (no secrets in code)
- Flexibility (different configs per environment)
- 12-Factor App compliance

Configuration sources (in order):
1. Environment variables
2. .env file (if present)
3. Default values (for development convenience)

Security guidelines:
- NEVER commit .env file to version control
- Use strong SECRET_KEY in production (32+ characters)
- Enable API_KEY_REQUIRED in production
- Whitelist CORS_ORIGINS in production (no *)
- Use PostgreSQL in production (not SQLite)
- Set DEBUG=false in production
"""
import secrets
from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables.

    Uses Pydantic for:
    - Type validation
    - Environment variable parsing
    - Default values
    - .env file loading

    All settings can be overridden via environment variables.
    Example: APP_ENV=production python -m src.main
    """

    model_config = SettingsConfigDict(
        env_file=".env",  # Load from .env file if present
        env_file_encoding="utf-8",
        case_sensitive=False,  # APP_ENV and app_env both work
    )

    # ========================================================================
    # APPLICATION SETTINGS
    # ========================================================================

    app_env: str = "development"  # Environment: development, staging, production
    app_name: str = "CharlottesWeb"  # Application name
    debug: bool = True  # Enable debug mode (detailed errors, docs, etc.)

    # ========================================================================
    # DATABASE SETTINGS
    # ========================================================================

    database_url: str = "sqlite:///./charlottesweb.db"  # SQLite for dev, PostgreSQL for prod
    # Production example: "postgresql://user:pass@localhost/charlottesweb"

    # ========================================================================
    # API SETTINGS
    # ========================================================================

    api_v1_prefix: str = "/api/v1"  # API version prefix

    # ========================================================================
    # SECURITY - AUTHENTICATION & JWT
    # ========================================================================

    # JWT Secret Key: Used to sign JWT tokens
    # CRITICAL: Must be kept secret and unique per environment
    # Auto-generated if not provided (fine for dev, set explicitly in prod)
    # Generate with: python -c "import secrets; print(secrets.token_urlsafe(32))"
    secret_key: str = secrets.token_urlsafe(32)

    # JWT algorithm: HS256 (HMAC with SHA-256) - symmetric signing
    # Alternative: RS256 (RSA) for distributed systems
    jwt_algorithm: str = "HS256"

    # JWT token expiration in minutes
    # Default: 60 minutes (1 hour)
    # Consider shorter for high-security environments
    access_token_expire_minutes: int = 60

    # ========================================================================
    # SECURITY - API KEYS
    # ========================================================================

    # Require API key authentication for all endpoints
    # Development: False (convenience)
    # Production: MUST be True
    api_key_required: bool = False

    # List of valid API keys
    # Format in .env: VALID_API_KEYS=key1,key2,key3
    # Generate keys with: python -c "from src.security import generate_api_key; print(generate_api_key())"
    # Production: Store in database with metadata (created_at, last_used, owner)
    valid_api_keys: List[str] = []

    # ========================================================================
    # SECURITY - CORS (Cross-Origin Resource Sharing)
    # ========================================================================

    # Allowed origins for CORS
    # Development: Empty list → defaults to "*" (allow all)
    # Production: Explicit whitelist required
    # Format in .env: CORS_ORIGINS=https://app.example.com,https://dashboard.example.com
    cors_origins: List[str] = []

    # Allow credentials (cookies, authorization headers) in CORS requests
    # Required for cookie-based authentication
    cors_allow_credentials: bool = True

    # Allowed HTTP methods
    cors_allow_methods: List[str] = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]

    # Allowed headers in CORS requests
    # "*" allows all headers (fine for API)
    # Can restrict to specific headers for tighter security
    cors_allow_headers: List[str] = ["*"]

    # ========================================================================
    # SECURITY - RATE LIMITING
    # ========================================================================

    # Enable rate limiting globally
    # Prevents DoS attacks and API abuse
    rate_limit_enabled: bool = True

    # Default rate limit: requests per minute per IP address
    # Adjust based on expected legitimate usage patterns
    # Can override per-endpoint in route decorators
    rate_limit_per_minute: int = 60

    # ========================================================================
    # EXTERNAL SERVICES
    # ========================================================================

    # NVD (National Vulnerability Database) API key
    # Optional: Provides higher rate limits for CVE data
    # Get key from: https://nvd.nist.gov/developers/request-an-api-key
    nvd_api_key: str = ""

    # ========================================================================
    # COMPUTED PROPERTIES (Convenience Helpers)
    # ========================================================================

    @property
    def is_production(self) -> bool:
        """Check if running in production environment.

        Returns True if APP_ENV is 'production' or 'prod'.
        Used to enable stricter security controls.
        """
        return self.app_env.lower() in ("production", "prod")

    @property
    def cors_allowed_origins(self) -> List[str]:
        """Get CORS allowed origins based on environment.

        Logic:
        - Development + no explicit origins → Allow all ("*")
        - Production or explicit origins → Use whitelist

        Security:
        - Never return ["*"] in production
        - Requires explicit origin configuration in production
        """
        if self.debug and not self.cors_origins:
            return ["*"]  # Allow all in development for convenience
        return self.cors_origins  # Use explicit whitelist


# ============================================================================
# GLOBAL SETTINGS INSTANCE
# ============================================================================
# Singleton settings object loaded at import time
# Access anywhere with: from src.config import settings
# ============================================================================
settings = Settings()


# ============================================================================
# SECURITY VALIDATION
# ============================================================================
def validate_security_config() -> List[str]:
    """Validate security configuration at startup.

    Checks for common misconfigurations that could lead to security issues:
    - Weak or default SECRET_KEY in production
    - CORS wildcard (*) in production
    - Debug mode enabled in production
    - API key authentication disabled in production
    - SQLite database in production (not scalable/concurrent-safe)

    Returns:
        List of warning messages (empty if all validations pass)

    Usage:
        warnings = validate_security_config()
        if warnings:
            for warning in warnings:
                logger.warning(warning)
    """
    warnings = []

    if settings.is_production:
        # Check 1: Debug mode should be disabled in production
        if settings.debug:
            warnings.append(
                "🚨 SECURITY: DEBUG=True in production! "
                "Exposes API docs, detailed errors, and internal state. "
                "Set DEBUG=false"
            )

        # Check 2: SECRET_KEY should be explicitly set (not auto-generated)
        # Auto-generated keys change on restart, invalidating all JWT tokens
        if len(settings.secret_key) < 32:
            warnings.append(
                "🚨 SECURITY: SECRET_KEY is weak (< 32 chars). "
                "Generate strong key: python -c 'import secrets; print(secrets.token_urlsafe(32))'"
            )

        # Check 3: CORS should have explicit origin whitelist (not *)
        if "*" in settings.cors_allowed_origins:
            warnings.append(
                "🚨 SECURITY: CORS allows all origins (*) in production! "
                "Set CORS_ORIGINS=https://yourdomain.com"
            )

        # Check 4: API key authentication should be required
        if not settings.api_key_required and not settings.valid_api_keys:
            warnings.append(
                "⚠️  SECURITY: API authentication disabled in production. "
                "Set API_KEY_REQUIRED=true and VALID_API_KEYS"
            )

        # Check 5: SQLite not recommended for production
        if "sqlite" in settings.database_url.lower():
            warnings.append(
                "⚠️  PRODUCTION: SQLite not recommended for production. "
                "Use PostgreSQL for better concurrency and reliability. "
                "Set DATABASE_URL=postgresql://..."
            )

        # Check 6: Rate limiting should be enabled
        if not settings.rate_limit_enabled:
            warnings.append(
                "⚠️  SECURITY: Rate limiting disabled in production. "
                "Set RATE_LIMIT_ENABLED=true to prevent abuse"
            )

    return warnings
