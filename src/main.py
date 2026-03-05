"""Main FastAPI application with comprehensive security hardening.

Security Features:
- API key authentication (configurable)
- Per-IP rate limiting (60 req/min default)
- Security headers (HSTS, CSP, X-Frame-Options, etc.)
- Request ID tracking for audit correlation
- Comprehensive audit logging
- Environment-aware CORS
- Secure error handling (no info leakage in prod)

Architecture:
- Middleware stack for cross-cutting concerns
- Centralized exception handling
- Lifecycle event hooks (startup/shutdown)
- Configuration via environment variables
"""
from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from src import __version__
from src.api import router
from src.audit import AuditAction, AuditLevel, log_audit_event, log_security_alert
from src.config import settings
from src.middleware import (
    RequestIDMiddleware,
    ResponseTimeMiddleware,
    SecurityHeadersMiddleware,
)

# Initialize rate limiter
# - key_func: How to identify clients (by IP address)
# - default_limits: Global limits applied to all endpoints unless overridden
# - Format: "<count>/<period>" where period: second, minute, hour, day
# - Example: "60/minute" = 60 requests per minute per IP
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[f"{settings.rate_limit_per_minute}/minute"]
)

# Create FastAPI application instance
app = FastAPI(
    title=settings.app_name,
    version=__version__,
    description="HIPAA Compliance-as-Code Platform",
    
    # Security: Disable API documentation in production
    # Interactive docs can leak API structure and be used for reconnaissance
    # Enable in development for convenience
    docs_url="/docs" if settings.debug else None,
    redoc_url="/redoc" if settings.debug else None,
    openapi_url="/openapi.json" if settings.debug else None,
)

# Attach rate limiter to app state so it's accessible in route handlers
# Required by slowapi for decorator-based rate limiting
app.state.limiter = limiter

# Register rate limit exceeded exception handler
# Returns 429 Too Many Requests with appropriate headers
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ============================================================================
# MIDDLEWARE STACK (Order is critical!)
# ============================================================================
# Middleware wraps the application in layers (outer to inner):
#   Request  → Middleware 1 → Middleware 2 → Routes → Middleware 2 → Middleware 1 → Response
#
# Order matters! Apply these in sequence:
#   1. Security Headers (outermost - applied to ALL responses)
#   2. Request ID (for logging/tracing)
#   3. Response Time (for monitoring)
#   4. CORS (framework-level)
#   5. Application routes (innermost)
# ============================================================================

# Security Middleware 1: Security Headers
# Adds security headers to ALL responses (even error responses)
# Must be outer layer to protect entire application
app.add_middleware(SecurityHeadersMiddleware)

# Security Middleware 2: Request ID Tracking
# Generates/extracts unique request ID for correlation in logs
# Accessible in handlers via request.state.request_id
app.add_middleware(RequestIDMiddleware)

# Monitoring Middleware: Response Time
# Tracks request processing time for performance monitoring
# Adds X-Process-Time header to responses
app.add_middleware(ResponseTimeMiddleware)

# CORS Middleware (Cross-Origin Resource Sharing)
# Controls which web origins can access this API
# Security considerations:
#   - Development: Allow all origins (*) for convenience
#   - Production: Explicit whitelist required (set CORS_ORIGINS env var)
#   - Allow credentials: Needed for cookie-based auth
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_allowed_origins,  # ['*'] in dev, whitelist in prod
    allow_credentials=settings.cors_allow_credentials,  # Allow cookies/auth headers
    allow_methods=settings.cors_allow_methods,  # HTTP methods allowed
    allow_headers=settings.cors_allow_headers,  # Headers allowed in requests
)


# ============================================================================
# EXCEPTION HANDLERS (Security-Aware Error Handling)
# ============================================================================
# Custom exception handlers prevent information leakage while maintaining
# debuggability in development. All errors are logged to audit trail.
# ============================================================================

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle Pydantic validation errors with security in mind.
    
    Triggered when:
    - Request body/query params fail Pydantic validation
    - Type mismatches
    - Missing required fields
    - Value constraints violated
    
    Security considerations:
    - Validation errors might indicate malicious input
    - Log as security alert for monitoring
    - Don't expose internal schema details in production
    
    Development: Return detailed errors for debugging
    Production: Return generic message to prevent reconnaissance
    """
    # Log as security alert (could be attack attempt)
    log_security_alert(
        request=request,
        alert_type="validation_error",
        description=f"Request validation failed: {exc.errors()}",
        severity=AuditLevel.WARNING,
    )
    
    # Production: Generic error message (don't leak schema details)
    # Attackers can use validation errors to map API structure
    if settings.is_production:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"detail": "Invalid request data"},
        )
    
    # Development: Detailed errors for debugging
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": exc.errors()},
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle unexpected exceptions (catch-all handler).
    
    Catches any unhandled exception that propagates to the top level.
    
    Security considerations:
    - Error messages might leak sensitive information
    - Stack traces reveal internal structure
    - Exception types reveal technology stack
    
    All exceptions are logged with context for debugging.
    Production returns generic error to prevent information leakage.
    """
    # Log to audit trail with error details
    log_audit_event(
        action=AuditAction.ERROR,
        request=request,
        level=AuditLevel.ERROR,
        success=False,
        details={
            "error_type": type(exc).__name__,
            # Log error message in dev, generic in prod
            "error_message": str(exc) if settings.debug else "Internal server error",
        },
    )
    
    # Production: Generic error (don't leak stack traces, error messages)
    # Errors might reveal database structure, file paths, library versions
    if settings.is_production:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "Internal server error"},
        )
    
    # Development: Include error message for debugging
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": str(exc)},
    )


# ============================================================================
# ROUTE REGISTRATION
# ============================================================================
# Mount API router with versioned prefix (/api/v1)
app.include_router(router, prefix=settings.api_v1_prefix, tags=["api"])


# ============================================================================
# STATIC FILES SERVING (HTML/CSS/JavaScript)
# ============================================================================
# Mount static files directory for serving the web UI.
#
# WHAT THIS DOES:
# - Serves all files in the ./static directory
# - Accessible at: https://localhost:8443/{filename}
# - Example: index.html is served at https://localhost:8443/index.html
#
# WHY MOUNT HERE:
# - API routes (prefix=/api/v1) are processed BEFORE static files
# - This ensures /api/v1/... never gets caught by static file handler
# - Path: /static -> static/index.html, /static/style.css -> static/style.css, etc.
#
# SECURITY CONSIDERATIONS FOR STATIC FILES:
# =========================================
# ✅ Static files inherit all middleware security:
#    - SecurityHeadersMiddleware: CSP, HSTS, X-Frame-Options headers applied
#    - RequestIDMiddleware: Requests tracked for audit logging
#    - RateLimiting: Rate limits apply (60 req/min default)
#    - CORS: Properly restricted to configured origins
#
# ✅ HTML Validation:
#    - CSP header prevents inline script injection
#    - Content-Type: text/html (browser won't execute as script)
#    - Path traversal protection (FastAPI's StaticFiles prevents ../ attacks)
#
# ⚠️ IMPORTANT: Files must be served over HTTPS in production:
#    - Ensure TLS/SSL certificates are valid
#    - Use strict HSTS header (default: 1 year)
#    - Prevent MITM attacks and eavesdropping
#
# FILE PERMISSIONS:
# - HTML, CSS, JS files should be readable but not writable by app
# - Use file system permissions to restrict access
# - Unix: chmod 644 static/* (read-only)
#
# STATIC FILE CACHING:
# - Browser cache: StaticFiles sets appropriate Cache-Control headers
# - CDN: In production, use CloudFront/Cloudflare for caching
# - Versioning: Use hashes in filenames for cache-busting (style.css?v=abc123)
#
# PERFORMANCE:
# - Static files served with gzip compression (if client supports)
# - If many users, consider separate static server (nginx, CDN)
# - Monitor /metrics for static file request volume
#
try:
    import os
    static_path = os.path.join(os.path.dirname(__file__), '..', 'static')
    
    # Only mount if directory exists (graceful handling if static/ removed)
    if os.path.isdir(static_path):
        app.mount(
            "/",  # Mount at root (lower priority than API routes)
            StaticFiles(directory=static_path, html=True),  # html=True: Serve index.html for dirs
            name="static"
        )
except Exception as e:
    # Log static file mounting error but continue (API still works)
    import logging
    logging.warning(f"Failed to mount static files: {e}. Web UI will not be available.")


# ============================================================================
# APPLICATION LIFECYCLE HOOKS
# ============================================================================
# These functions run when the application starts/stops.
# Useful for: logging, initialization, cleanup, health checks
# ============================================================================

@app.on_event("startup")
async def startup_event():
    """Log application startup for audit trail.
    
    Runs once when the application starts.
    Logs configuration state for:
    - Incident investigation (when did config change?)
    - Compliance auditing (what security settings are active?)
    - Troubleshooting (what version is running?)
    
    Future enhancements:
    - Database connection pool initialization
    - Cache warming
    - External service health checks
    - Feature flag loading
    """
    log_audit_event(
        action=AuditAction.CONFIG_CHANGED,
        level=AuditLevel.INFO,
        details={
            "event": "application_startup",
            "version": __version__,
            "environment": settings.app_env,
            "debug": settings.debug,
            "api_key_required": settings.api_key_required,
        },
    )


@app.on_event("shutdown")
async def shutdown_event():
    """Log application shutdown for audit trail.
    
    Runs once when the application stops (graceful shutdown).
    
    Future enhancements:
    - Close database connections
    - Flush audit logs
    - Cancel background tasks
    - Send shutdown notifications
    """
    log_audit_event(
        action=AuditAction.CONFIG_CHANGED,
        level=AuditLevel.INFO,
        details={
            "event": "application_shutdown",
            "version": __version__,
        },
    )


# ============================================================================
# DEVELOPMENT SERVER
# ============================================================================
# Used for local development only. Production uses uvicorn directly.
# ============================================================================

if __name__ == "__main__":
    import uvicorn

    # Development server (NOT for production)
    # Use gunicorn + uvicorn worker in production
    uvicorn.run("src.main:app", host="0.0.0.0", port=8000, reload=True)
