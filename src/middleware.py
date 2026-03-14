"""Security middleware for FastAPI application.

This module provides three critical middleware components:

1. SecurityHeadersMiddleware - Adds security headers to all responses
   - Prevents clickjacking, XSS, MIME sniffing
   - Enforces HTTPS (HSTS)
   - Implements Content Security Policy

2. RequestIDMiddleware - Unique ID per request for tracing/debugging
   - Enables request tracking through logs
   - Helps correlate audit events
   - Supports distributed tracing

3. ResponseTimeMiddleware - Performance monitoring
   - Tracks request processing time
   - Identifies slow endpoints
   - Helps with SLA monitoring

Middleware order matters! Apply in this sequence:
1. Security headers (outer layer)
2. Request ID (for logging)
3. Response time (for monitoring)
4. CORS (framework-level)
5. Application routes (innermost)
"""

import time
import uuid
from collections.abc import Callable

from fastapi import Request, Response
from slowapi import Limiter
from slowapi.util import get_remote_address
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from src.security import get_api_key_optional  # Re-export for convenience

# Rate limiter instance for use in route decorators
limiter = Limiter(key_func=get_remote_address)

__all__ = [
    "SecurityHeadersMiddleware",
    "RequestIDMiddleware",
    "ResponseTimeMiddleware",
    "limiter",
    "get_api_key_optional",
]


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all HTTP responses.

    Headers added:
    - X-Frame-Options: Prevents clickjacking attacks
    - X-Content-Type-Options: Prevents MIME sniffing
    - X-XSS-Protection: Browser XSS filter
    - Content-Security-Policy: Controls resource loading
    - Referrer-Policy: Controls referrer information
    - Permissions-Policy: Controls browser features
    - Strict-Transport-Security: Enforces HTTPS (HTTPS only)

    Security benefits:
    - OWASP Top 10 mitigation
    - Defense in depth
    - Browser-level security controls
    - Compliance requirements (SOC 2, PCI-DSS)

    Note: These headers are applied to ALL responses automatically.
    """

    def __init__(self, app: ASGIApp):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Process the request first
        response = await call_next(request)

        # Security Header 1: Clickjacking Protection
        # Prevents the page from being embedded in <iframe>, <frame>, or <object>
        # DENY = never allow framing (most secure)
        # Alternative: SAMEORIGIN = allow same-origin framing
        # Exception: Allow for /docs and /redoc endpoints (self-hosted documentation)
        is_docs_endpoint = request.url.path in ["/docs", "/redoc", "/openapi.json"]
        response.headers["X-Frame-Options"] = (
            "SAMEORIGIN" if is_docs_endpoint else "DENY"
        )

        # Security Header 2: MIME Sniffing Protection
        # Forces browser to respect declared Content-Type
        # Prevents XSS via uploaded files with incorrect Content-Type
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Security Header 3: XSS Filter
        # Enables browser's built-in XSS protection
        # mode=block stops page rendering if attack detected
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Security Header 4: Content Security Policy
        # Strategy: Different policies for different endpoints
        # - Docs endpoints (/docs, /redoc): Allow all resources
        # - Root/static files (/): Allow inline styles/scripts for vulnerability analyzer UI
        # - API endpoints: Strict policy (no resources needed)
        if is_docs_endpoint:
            # Docs page needs to load Swagger UI
            # Disable CSP for docs to avoid conflicts
            pass  # Don't set CSP for docs
        elif request.url.path == "/":
            # App UI needs: inline scripts/styles + Cytoscape.js CDN for diagram
            csp = (
                "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
                "style-src 'self' 'unsafe-inline'; "
                "connect-src 'self'; "
                "img-src 'self' data: https://nvd.nist.gov https://fastapi.tiangolo.com; "
                "font-src 'self'; "
                "default-src 'none'; "
                "upgrade-insecure-requests"
            )
            response.headers["Content-Security-Policy"] = csp
        else:
            # API responses should be JSON only, no scripts/styles needed
            # default-src 'none' blocks all content by default (most secure)
            csp = "default-src 'none'; frame-ancestors 'none'"
            response.headers["Content-Security-Policy"] = csp

        # Security Header 5: Referrer Policy
        # no-referrer = Never send referrer information
        # Prevents leaking URLs to external sites
        # Alternative: strict-origin-when-cross-origin for less strict policy
        response.headers["Referrer-Policy"] = "no-referrer"

        # Security Header 6: Permissions Policy (Feature Policy)
        # Disables browser features we don't use
        # Reduces attack surface
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=()"
        )

        # Security Header 7: HTTP Strict Transport Security (HSTS)
        # Forces HTTPS for all future requests (31536000 sec = 1 year)
        # includeSubDomains = applies to all subdomains too
        # preload = eligible for browser HSTS preload lists
        # Only add for HTTPS connections (adding on HTTP has no effect)
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )

        return response


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Add unique request ID to all requests and responses for tracing.

    Flow:
    1. Check if client provided X-Request-ID header
    2. If not, generate a new UUID
    3. Store in request.state for access in route handlers
    4. Add to response headers for client reference

    Benefits:
    - Correlate logs across services
    - Debug specific requests
    - Track request through audit logs
    - Support distributed tracing

    Usage in route handlers:
        def my_route(request: Request):
            request_id = request.state.request_id
            logger.info(f"Processing {request_id}")

    Client usage:
        curl -H "X-Request-ID: my-custom-id" https://api.example.com/
        # Response will include: X-Request-ID: my-custom-id
    """

    def __init__(self, app: ASGIApp):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Generate or extract request ID
        # Prefer client-provided ID for distributed tracing
        # Generate UUID if not provided
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())

        # Store in request state for access in route handlers and logging
        # Available as: request.state.request_id
        request.state.request_id = request_id

        # Process request
        response = await call_next(request)

        # Add request ID to response headers
        # Client can use this to reference specific requests in support tickets
        response.headers["X-Request-ID"] = request_id

        return response


class ResponseTimeMiddleware(BaseHTTPMiddleware):
    """Add response time header to track endpoint performance.

    Measures wall-clock time from request receipt to response ready.
    Useful for:
    - Identifying slow endpoints
    - SLA monitoring
    - Performance regression detection
    - Capacity planning

    Header added:
        X-Process-Time: <milliseconds>

    Example:
        X-Process-Time: 42.15
        (Request took 42.15 milliseconds to process)

    Note:
        This is server-side processing time only.
        Does not include network latency or client rendering time.
    """

    def __init__(self, app: ASGIApp):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Record start time (high precision)
        start_time = time.time()

        # Process request
        response = await call_next(request)

        # Calculate elapsed time in seconds
        process_time = time.time() - start_time

        # Add header in milliseconds (rounded to 2 decimal places)
        # Example: 0.04215 seconds → "42.15" milliseconds
        response.headers["X-Process-Time"] = str(round(process_time * 1000, 2))

        return response
