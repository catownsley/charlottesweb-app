# Copyright (C) 2026 Charlotte Townsley
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Audit logging service for security and compliance tracking.

This module provides audit logging for:
- HIPAA compliance evidence
- SOC 2 control evidence (CC6.1, CC7.1, etc.)
- Security incident investigation
- Forensic analysis
- Regulatory audits

Log Format:
- JSON structured logs for machine parsing
- One event per line for easy processing
- Includes request metadata (IP, user agent, etc.)
- Separate file from application logs

Security Considerations:
- Never log PHI (Protected Health Information)
- Never log API keys or anything derived from them (caller slot in VALID_API_KEYS only)
- Never log passwords or sensitive data
- Protect audit.log with appropriate file permissions
- Implement log rotation to prevent disk fill
- Consider shipping logs to SIEM system

Compliance:
- HIPAA: 164.312(b) - Audit Controls
- SOC 2: CC6.1 - Logical and Physical Access Controls
- SOC 2: CC7.1 - System Monitoring
"""

import hmac
import json
import logging
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from fastapi import Request

from src.config import settings
from src.utils import sanitize_log_value

# Configure dedicated audit logger (separate from application logs)
# Name: "audit" - allows separation in log aggregation systems
audit_logger = logging.getLogger("audit")
audit_logger.setLevel(logging.INFO)

# Create handler for audit logs (writes to audit.log file)
# Security: Set file permissions to 640 (owner read/write, group read)
# Production: Consider shipping to centralized log management (ELK, Splunk)
handler = logging.FileHandler("audit.log")
handler.setLevel(logging.INFO)

# JSON formatter for structured logging
# Format: {"timestamp": "...", "level": "...", "message": {...}}
# Benefits:
#   - Machine parseable
#   - Easy to query/filter
#   - Standard for SIEM integration
formatter = logging.Formatter(
    '{"timestamp": "%(asctime)s", "level": "%(levelname)s", "message": %(message)s}'
)
handler.setFormatter(formatter)
audit_logger.addHandler(handler)

# Prevent propagation to root logger
# Keeps audit logs separate from application logs
audit_logger.propagate = False


class AuditAction(StrEnum):
    """Enumeration of auditable actions.

    Categorized by type for easy filtering and reporting.
    Add new actions as features are implemented.

    Compliance mapping:
    - Authentication events → SOC 2 CC6.1
    - Data access events → HIPAA 164.312(b)
    - System events → SOC 2 CC7.1
    """

    # Authentication & Authorization Events
    # Log all auth attempts for security monitoring
    LOGIN = "login"  # User logged in successfully
    LOGOUT = "logout"  # User logged out
    API_KEY_CREATED = "api_key_created"  # New API key generated
    API_KEY_REVOKED = "api_key_revoked"  # API key revoked/deleted
    AUTH_FAILED = "auth_failed"  # Failed authentication attempt

    # Data Access Events (CRUD operations)
    # Critical for HIPAA audit control requirements
    DATA_READ = "data_read"  # Data viewed/retrieved
    DATA_CREATED = "data_created"  # New data created
    DATA_UPDATED = "data_updated"  # Existing data modified
    DATA_DELETED = "data_deleted"  # Data deleted

    # Assessment Events (Core business logic)
    # Track compliance assessment lifecycle
    ASSESSMENT_CREATED = "assessment_created"  # New assessment initiated
    ASSESSMENT_RUN = "assessment_run"  # Assessment executed
    ASSESSMENT_VIEWED = "assessment_viewed"  # Assessment results viewed
    ROADMAP_GENERATED = "roadmap_generated"  # Remediation roadmap created
    NVD_QUERY = "nvd_query"  # Vulnerability database queried (OSV.dev; enum kept for audit log compat)
    THREAT_INTEL_QUERY = "threat_intel_query"  # Threat intel providers queried

    # Organization Management
    # Track customer onboarding and changes
    ORG_CREATED = "org_created"  # New organization registered
    ORG_UPDATED = "org_updated"  # Organization info modified
    ORG_DELETED = "org_deleted"  # Organization removed

    # Metadata Profile Management
    # Critical: Changes affect compliance assessments
    PROFILE_CREATED = "profile_created"  # New profile created
    PROFILE_UPDATED = "profile_updated"  # Profile modified
    PROFILE_DELETED = "profile_deleted"  # Profile deleted

    # System Events
    # Track system configuration and errors
    CONFIG_CHANGED = "config_changed"  # Configuration modified
    ERROR = "error"  # System error occurred
    SECURITY_ALERT = "security_alert"  # Security event detected


class AuditLevel(StrEnum):
    """Audit log severity levels.

    Maps to standard logging levels but with security context:
    - INFO: Normal operations (most events)
    - WARNING: Suspicious but not critical (failed auth, validation errors)
    - ERROR: Operation failed (system errors, exceptions)
    - CRITICAL: Security incident or system compromise
    """

    INFO = "info"  # Normal auditable event
    WARNING = "warning"  # Suspicious activity
    ERROR = "error"  # Operation failed
    CRITICAL = "critical"  # Security incident


def resolve_caller_slot(presented: str) -> int | None:
    """Return the 1-based slot of the presented credential in VALID_API_KEYS.

    Audit events are correlated to a caller by slot number in the configured
    list, so nothing derived from the credential itself is written to disk.
    Returns None when the credential is not in the list, which can happen
    when API_KEY_REQUIRED is false. Comparison is constant time.
    """
    for position, candidate in enumerate(settings.valid_api_keys, start=1):
        if hmac.compare_digest(candidate, presented):
            return position
    return None


def _sanitize_details(value: Any, *, max_length: int = 1000) -> Any:
    """Recursively scrub strings inside an audit details structure.

    Strings are passed through sanitize_log_value. Dict keys are coerced to
    sanitized strings. Numbers, booleans and None pass through unchanged so
    the JSON types in the log stay stable.
    """
    if isinstance(value, str):
        return sanitize_log_value(value, max_length=max_length)
    if isinstance(value, dict):
        return {
            sanitize_log_value(str(k), max_length=100): _sanitize_details(
                v, max_length=max_length
            )
            for k, v in value.items()
        }
    if isinstance(value, list | tuple):
        return [_sanitize_details(v, max_length=max_length) for v in value]
    return value


def log_audit_event(
    action: AuditAction,
    request: Request | None = None,
    user_id: str | None = None,
    api_key: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    details: dict[str, Any] | None = None,
    level: AuditLevel = AuditLevel.INFO,
    success: bool = True,
) -> None:
    """Log an auditable event.

    This is the primary audit logging function. Call it for any security-relevant
    event that should be tracked for compliance, forensics, or monitoring.

    Args:
        action: What happened (from AuditAction enum)
        request: FastAPI Request object (captures IP, user agent, path, etc.)
        user_id: ID of authenticated user (for user-specific actions)
        api_key: API key used (logged only as its slot number in VALID_API_KEYS)
        resource_type: Type of resource affected (e.g., 'organization', 'assessment')
        resource_id: ID of specific resource affected
        details: Additional context (free-form dict, don't include PHI)
        level: Severity/importance (INFO, WARNING, ERROR, CRITICAL)
        success: True if action succeeded, False if failed

    Security considerations:
        - NEVER log PHI (Protected Health Information)
        - NEVER log full API keys (last 4 chars only)
        - NEVER log passwords or credentials
        - NEVER log sensitive business data

    Log structure:
        {
            "timestamp": "2026-03-04T12:34:56.789",
            "action": "assessment_created",
            "success": true,
            "level": "info",
            "request": {
                "id": "uuid",
                "ip": "192.168.1.100",
                "method": "POST",
                "path": "/api/v1/assessments",
                "user_agent": "curl/7.88.1"
            },
            "user_id": "user-123",
            "caller_slot": 2,
            "resource_type": "assessment",
            "resource_id": "assessment-abc",
            "details": {"organization_id": "org-456"}
        }

    Example usage:
        # Log successful organization creation
        log_audit_event(
            action=AuditAction.ORG_CREATED,
            request=request,
            api_key=api_key,
            resource_type="organization",
            resource_id=org.id,
            details={"name": org.name},
        )

        # Log failed authentication
        log_audit_event(
            action=AuditAction.AUTH_FAILED,
            request=request,
            level=AuditLevel.WARNING,
            success=False,
            details={"reason": "invalid_api_key"},
        )
    """
    # Build base log entry
    log_entry: dict[str, Any] = {
        "action": action.value,
        "success": success,
        "timestamp": datetime.now(UTC).isoformat(),
        "level": level.value,
    }

    # Extract request information (IP, user agent, path, etc.)
    # Correlate with request ID for distributed tracing
    if request:
        log_entry["request"] = {
            "id": sanitize_log_value(
                str(getattr(request.state, "request_id", ""))
            ),  # From RequestIDMiddleware
            "ip": request.client.host if request.client else None,  # Source IP
            "method": request.method,  # HTTP method (GET, POST, etc.)
            "path": sanitize_log_value(
                str(request.url.path), max_length=500
            ),  # Request path (don't include query params)
            "user_agent": sanitize_log_value(
                request.headers.get("user-agent", ""), max_length=500
            ),  # Client identification
        }

    # User identification (for user-specific actions)
    if user_id:
        log_entry["user_id"] = sanitize_log_value(str(user_id))

    # Caller tracking (SECURITY: never log the key or anything derived from it)
    # The slot number in VALID_API_KEYS is enough to tell which caller it was
    # without putting credential material, or a hash of it, in the log.
    if api_key:
        log_entry["caller_slot"] = resolve_caller_slot(api_key)

    # Resource information (what was accessed/modified)
    # Helps identify which resource was affected by the action
    if resource_type:
        log_entry["resource_type"] = resource_type  # E.g., "organization", "assessment"
    if resource_id:
        log_entry["resource_id"] = sanitize_log_value(str(resource_id))

    # Additional context-specific details
    # Use this for action-specific information
    # Example: {"name": "Acme Corp", "industry": "healthcare"}
    # SECURITY: Don't include PHI or sensitive data
    # Every string inside details is scrubbed of newlines and control
    # characters so that a user supplied value cannot forge a log line.
    if details:
        log_entry["details"] = _sanitize_details(details)

    # Serialize to JSON (one line per event for easy parsing)
    # json.dumps never emits a raw newline, but the explicit scrub makes the
    # one line per event guarantee visible at the write site.
    log_message = json.dumps(log_entry).replace("\r", "\\r").replace("\n", "\\n")

    # Write to audit log at appropriate severity level
    # Maps AuditLevel to Python logging levels
    if level == AuditLevel.CRITICAL:
        audit_logger.critical(log_message)  # Security incident
    elif level == AuditLevel.ERROR:
        audit_logger.error(log_message)  # Operation failed
    elif level == AuditLevel.WARNING:
        audit_logger.warning(log_message)  # Suspicious activity
    else:
        audit_logger.info(log_message)  # Normal auditable event


def log_security_alert(
    request: Request,
    alert_type: str,
    description: str,
    severity: AuditLevel = AuditLevel.WARNING,
) -> None:
    """Log a security-specific alert (convenience wrapper).

    Use this for security events that need immediate attention:
    - Failed authentication attempts
    - Input validation failures
    - Rate limit violations
    - Suspicious patterns
    - Potential attacks

    Args:
        request: FastAPI Request object
        alert_type: Category of alert (e.g., "validation_error", "rate_limit_exceeded")
        description: Human-readable description of what happened
        severity: How serious (WARNING or CRITICAL typically)

    Example:
        # Log suspicious input
        log_security_alert(
            request=request,
            alert_type="sql_injection_attempt",
            description="Detected SQL keywords in user input",
            severity=AuditLevel.WARNING,
        )

        # Log rate limit violation
        log_security_alert(
            request=request,
            alert_type="rate_limit_exceeded",
            description=f"IP {request.client.host} exceeded rate limit",
            severity=AuditLevel.WARNING,
        )

    Note:
        All security alerts are marked as success=False
        Review security alerts regularly for patterns
    """
    log_audit_event(
        action=AuditAction.SECURITY_ALERT,
        request=request,
        level=severity,
        success=False,  # Security alerts are always "failures"
        details={
            "alert_type": alert_type,
            "description": description,
        },
    )
