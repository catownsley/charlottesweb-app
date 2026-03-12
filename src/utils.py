"""Shared utility functions for type conversion, ranking, and input sanitization."""

from __future__ import annotations

import html
import re
from urllib.parse import urlparse

from src.constants import PriorityWindow, Severity

# ---------------------------------------------------------------------------
# Input sanitization
# ---------------------------------------------------------------------------

# Protocols allowed in user-supplied URLs.
_ALLOWED_URL_SCHEMES = {"https", "http"}

# Characters allowed in sanitized text (letters, digits, common punctuation).
_SAFE_TEXT_RE = re.compile(r"[^\w\s@.,;:!?/\\#\-_()\[\]{}'\"+=&%$<>|~`^]", re.UNICODE)

# Control characters (C0/C1) except tab, newline, carriage-return.
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")


def sanitize_url(url: str, *, max_length: int = 2048) -> str:
    """Validate and sanitize a URL string.

    Raises ``ValueError`` for disallowed schemes, oversized URLs,
    or structurally invalid input.
    """
    if not url or not url.strip():
        raise ValueError("URL must not be empty")

    url = url.strip()

    if len(url) > max_length:
        raise ValueError(f"URL exceeds maximum length of {max_length} characters")

    # Strip control characters that could hide payloads.
    url = _CONTROL_CHAR_RE.sub("", url)

    try:
        parsed = urlparse(url)
    except ValueError as exc:
        raise ValueError(f"Malformed URL: {exc}") from exc

    if not parsed.scheme:
        raise ValueError("URL must include a scheme (e.g. https://)")

    if parsed.scheme.lower() not in _ALLOWED_URL_SCHEMES:
        raise ValueError(
            f"URL scheme '{parsed.scheme}' is not allowed. "
            f"Allowed: {', '.join(sorted(_ALLOWED_URL_SCHEMES))}"
        )

    if not parsed.netloc:
        raise ValueError("URL must include a valid host")

    return url


def sanitize_text(
    text: str,
    *,
    max_length: int = 5000,
    strip_html: bool = True,
) -> str:
    """Sanitize free-text input.

    - Strips control characters.
    - Optionally HTML-escapes to prevent stored XSS.
    - Enforces a maximum length.
    """
    if not text:
        return text

    text = text.strip()

    if len(text) > max_length:
        raise ValueError(f"Text exceeds maximum length of {max_length} characters")

    # Remove control characters.
    text = _CONTROL_CHAR_RE.sub("", text)

    if strip_html:
        text = html.escape(text, quote=True)

    return text


def sanitize_filename(filename: str, *, max_length: int = 255) -> str:
    """Sanitize a filename to prevent path traversal and injection.

    Returns only the basename with dangerous characters removed.
    """
    if not filename:
        raise ValueError("Filename must not be empty")

    # Take only the final path component to defeat ../../../ traversal.
    import os

    filename = os.path.basename(filename)

    if not filename:
        raise ValueError("Filename resolves to empty after path stripping")

    if len(filename) > max_length:
        raise ValueError(f"Filename exceeds maximum length of {max_length} characters")

    # Remove control characters.
    filename = _CONTROL_CHAR_RE.sub("", filename)

    # Remove null bytes explicitly (double-safety).
    filename = filename.replace("\x00", "")

    # Reject names that are just dots (., ..)
    if filename.strip(".") == "":
        raise ValueError("Invalid filename")

    return filename


def escape_for_html(text: str) -> str:
    """HTML-escape a string for safe rendering in innerHTML contexts."""
    return html.escape(str(text), quote=True)


def to_str(value: object | None, default: str = "") -> str:
    """Convert a value to string, returning default if None."""
    if value is None:
        return default
    return str(value)


def to_optional_str(value: object | None) -> str | None:
    """Convert a value to string, returning None if None."""
    if value is None:
        return None
    return str(value)


def to_float(value: object | None, default: float = 0.0) -> float:
    """Convert a value to float, returning default if conversion fails."""
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return default
    return default


def to_str_list(value: object | None) -> list[str]:
    """Convert a collection to a list of strings."""
    if isinstance(value, list | tuple | set):
        return [str(item) for item in value]
    return []


def severity_rank(value: str) -> int:
    """Return numeric rank for severity level (higher = more severe)."""
    severity_order = {
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4,
    }
    return severity_order.get(value.lower(), 0)


def priority_rank(value: str) -> int:
    """Return numeric rank for priority window (higher = more urgent)."""
    priority_order = {
        PriorityWindow.ANNUAL: 1,
        PriorityWindow.QUARTERLY: 2,
        PriorityWindow.THIRTY_DAYS: 3,
        PriorityWindow.IMMEDIATE: 4,
    }
    return priority_order.get(value.lower(), 0)
