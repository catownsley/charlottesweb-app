"""Shared utility functions for type conversion and ranking."""

from __future__ import annotations

from src.constants import PriorityWindow, Severity


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
