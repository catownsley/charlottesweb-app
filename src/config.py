"""Application configuration with security-first settings.

SECURITY MODEL
==============

This application uses environment variables for ALL configuration, including
secrets. This follows the 12-Factor App methodology and ensures secrets are
never stored in version control.

Secrets are managed as follows:

  PRODUCTION (Recommended)
  ├─ Use platform environment variables (no files)
  │  - Heroku: `heroku config:set SECRET_KEY=...`
  │  - AWS Lambda/ECS: Use Secrets Manager
  │  - GCP Cloud Run: Use Secret Manager
  │  - Kubernetes: Use Secrets
  │  - Docker: Pass via --env or -e flags
  │
  STAGING / DEVELOPMENT
  ├─ Option 1: Environment variables in shell
  │  - `export SECRET_KEY="..."`
  │  - `export VALID_API_KEYS="key1,key2"`
  │
  ├─ Option 2: .env file (excluded from git)
  │  - Create `.env` file with your secrets
  │  - LoadedAutomatically by Pydantic
  │  - .gitignore prevents accidental commits
  │
  └─ Option 3: Encrypted .env file (extra protection)
     - Encrypt sensitive file: `python src/encryption.py encrypt .env my-password`
     - Load at startup with: `load_encrypted_env('.env.encrypted', 'my-password')`

KEY PRINCIPLES
==============

✓ DO:
  - Use environment variables
  - Generate strong secrets (32+ characters)
  - Rotate secrets quarterly or after compromise
  - Whitelist CORS origins in production
  - Require API keys in production
  - Use PostgreSQL in production
  - Enable HTTPS/TLS always
  - Log authentication failures
  - Use strong database passwords

✗ DON'T:
  - Commit .env files to git
  - Hardcode secrets in Python
  - Use weak/default secrets
  - Use DEBUG=true in production
  - Allow all origins with CORS "*"
  - Use SQLite in production
  - Share secrets via chat/email
  - Skip TLS
  - Log secret values

CONFIGURATION SOURCES (in order)
================================

1. Environment variables (highest priority)
2. .env file (if present)
3. Default values (lowest priority)

Example:
  export SECRET_KEY="my-secret"  # This overrides .env and defaults
  python -m src.main

For encrypted .env:
  from src.encryption import load_encrypted_env
  load_encrypted_env('.env.encrypted', password='master-password')
  # Then all vars are available to Pydantic

SECURITY CHECKLIST
==================

Before deploying to production:
  □ SECRET_KEY set to strong random value (32+ chars)
  □ VALID_API_KEYS set and non-empty
  □ API_KEY_REQUIRED=true
  □ DEBUG=false
  □ APP_ENV=production
  □ CORS_ORIGINS explicitly whitelisted (not "*")
  □ DATABASE_URL points to production database
  □ Database has strong password
  □ HTTPS/TLS enabled
  □ .env file not committed to git
  □ No hardcoded secrets in code

SEED DOCUMENTATION
====================

See SECURITY_KEYS.md for:
  - How to generate secrets
  - Platform-specific setup (Heroku, AWS, GCP, etc.)
  - Secret rotation procedures
  - Encryption setup
  - Compliance checklist

GENERATE SECRETS
================

JWT Secret Key (32+ characters):
  python -c "import secrets; print(secrets.token_urlsafe(32))"

API Keys:
  python -c "from src.security import generate_api_key; print(generate_api_key())"

Database Password:
  python -c "import secrets; print(secrets.token_urlsafe(24))"

Example values (for testing - replace with your own!):
  SECRET_KEY=mXpF_nJk9Q2wL5v7r3t8Y6u1s4d2gH0K
  VALID_API_KEYS=ck_liveA1b2c3d4e5f6g7h8i9j0,ck_testX9y8z7w6v5u4t3s2r1q0p
"""
import secrets
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_SQLITE_DB_PATH = BASE_DIR / "charlottesweb.db"
DEFAULT_SQLITE_DATABASE_URL = f"sqlite:///{DEFAULT_SQLITE_DB_PATH.as_posix()}"


class Settings(BaseSettings):
    """Application settings loaded from environment variables.

    Uses Pydantic for:
    - Type validation
    - Environment variable parsing
    - Default values
    - .env file loading

    All settings can be overridden via environment variables.
    Example: APP_ENV=production python -m src.main

    For encrypted .env file support:
      from src.encryption import load_encrypted_env
      env_dict = load_encrypted_env('.env.encrypted', password='master-password')
      # Variables will be available to this settings class
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

    database_url: str = DEFAULT_SQLITE_DATABASE_URL  # SQLite for dev, PostgreSQL for prod
    # Production example: "postgresql://user:pass@localhost/charlottesweb"

    # Development convenience flag. When true, startup drops and recreates all tables.
    # Keep false by default to avoid accidental data loss on restart.
    reset_db_on_startup: bool = False

    # ========================================================================
    # API SETTINGS
    # ========================================================================

    api_v1_prefix: str = "/api/v1"  # API version prefix

    # ========================================================================
    # SECURITY - AUTHENTICATION & JWT
    # ========================================================================

    # JWT Secret Key: Used to sign JWT tokens
    # CRITICAL: Must be kept secret and unique per environment
    # Development: Auto-generated if not provided
    # Production: MUST be explicitly set (errors if missing)
    # Generate with: python -c "import secrets; print(secrets.token_urlsafe(32))"
    secret_key: str = ""

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
    valid_api_keys: list[str] = []

    # ========================================================================
    # SECURITY - CORS (Cross-Origin Resource Sharing)
    # ========================================================================

    # Allowed origins for CORS
    # Development: Empty list → defaults to "*" (allow all)
    # Production: Explicit whitelist required
    # Format in .env: CORS_ORIGINS=https://app.example.com,https://dashboard.example.com
    cors_origins: list[str] = []

    # Allow credentials (cookies, authorization headers) in CORS requests
    # Required for cookie-based authentication
    cors_allow_credentials: bool = True

    # Allowed HTTP methods
    cors_allow_methods: list[str] = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]

    # Allowed headers in CORS requests
    # "*" allows all headers (fine for API)
    # Can restrict to specific headers for tighter security
    cors_allow_headers: list[str] = ["*"]

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

    # GitHub API Token for Dependabot alerts integration
    # Optional: Required to fetch Dependabot security alerts
    # Generate token at: https://github.com/settings/tokens with repo/security_events scopes
    # Set via: GITHUB_TOKEN environment variable
    github_token: str = ""

    # GitHub repository owner (e.g., "catownsley")
    # Used with Dependabot alert fetching
    # Default: "catownsley" (CharlottesWeb repo owner)
    github_repo_owner: str = "catownsley"

    # GitHub repository name (e.g., "charlottesweb-app")
    # Used with Dependabot alert fetching
    # Default: "charlottesweb-app"
    github_repo_name: str = "charlottesweb-app"

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
    def cors_allowed_origins(self) -> list[str]:
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

# Pre-initialize settings to allow validation
_settings = Settings()

# Generate secret key if not provided (development only)
if not _settings.secret_key:
    if _settings.is_production:
        raise ValueError(
            "SECRET_KEY must be explicitly set in production. "
            "Generate with: python -c 'import secrets; print(secrets.token_urlsafe(32))'"
        )
    else:
        # Auto-generate for development convenience
        _settings.secret_key = secrets.token_urlsafe(32)

settings = _settings


# ============================================================================
# SECURITY VALIDATION
# ============================================================================
def validate_security_config() -> list[str]:
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
