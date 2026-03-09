"""Risk scoring utilities that fuse HIPAA control posture with threat intelligence.

This module intentionally builds on existing domain objects (Assessment, Finding,
Control, Evidence) so we can deliver meaningful risk prioritization without a
breaking schema migration.

Security and robustness principles used here:
- Never trust free-form values from DB rows; normalize before scoring.
- Clamp all computed scores to bounded ranges to avoid overflow/drift.
- Prefer deterministic scoring (same inputs -> same outputs) for auditability.
- Keep all scoring logic explicit and commented for compliance review.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any


def _clamp(value: float, low: float, high: float) -> float:
    """Clamp a float to a safe bounded range."""
    return max(low, min(high, value))


def _normalize_text(value: Any, default: str = "") -> str:
    """Safely convert values to normalized text for deterministic comparisons."""
    if value is None:
        return default
    text = str(value).strip()
    return text if text else default


def _severity_score(severity: str, cvss_score: float | None) -> float:
    """Map severity + CVSS into a bounded threat-pressure base score.

    We favor explicit severity labels from finding generation, with CVSS as
    a tie-breaker / fallback. This allows non-CVE compliance findings to still
    participate in risk ranking.
    """
    severity_map: dict[str, float] = {
        "critical": 95.0,
        "immediate": 90.0,
        "high": 80.0,
        "medium": 60.0,
        "low": 35.0,
    }
    severity_key = _normalize_text(severity, default="low").lower()
    severity_weight = severity_map.get(severity_key, 35.0)

    if cvss_score is None:
        return severity_weight

    # Convert CVSS (0-10) to 0-100 and average with severity weight.
    # Bounded output keeps downstream formulas stable and explainable.
    cvss_normalized = _clamp(float(cvss_score) * 10.0, 0.0, 100.0)
    return (severity_weight + cvss_normalized) / 2.0


def _freshness_penalty(reference_time: datetime | None, now_utc: datetime) -> float:
    """Return a bounded freshness penalty based on evidence recency.

    Newer evidence should increase confidence; stale evidence should lower it.
    We implement this as a penalty to keep confidence calculations transparent.
    """
    if reference_time is None:
        return 25.0

    # Normalize to UTC-aware datetime to avoid timezone ambiguity bugs.
    if reference_time.tzinfo is None:
        reference_time = reference_time.replace(tzinfo=UTC)

    age_days = max(0, (now_utc - reference_time).days)
    if age_days <= 30:
        return 0.0
    if age_days <= 90:
        return 10.0
    return 20.0


def evidence_status_score(status: str) -> float:
    """Convert evidence workflow status to base confidence points."""
    status_map: dict[str, float] = {
        "completed": 100.0,
        "not_applicable": 80.0,
        "in_progress": 55.0,
        "not_started": 20.0,
    }
    return status_map.get(_normalize_text(status, default="not_started").lower(), 20.0)


def control_confidence_score(
    evidence_statuses: list[str],
    freshest_collected_at: datetime | None,
    freshest_updated_at: datetime | None,
) -> float:
    """Compute control confidence from evidence completion + freshness.

    This score intentionally uses only persisted system-of-record data, making
    it reproducible for audits and easier to explain to compliance reviewers.
    """
    now_utc = datetime.now(UTC)

    if not evidence_statuses:
        # No evidence means extremely low confidence by default.
        return 10.0

    base = sum(evidence_status_score(status) for status in evidence_statuses) / len(
        evidence_statuses
    )
    freshness_reference = freshest_collected_at or freshest_updated_at
    penalty = _freshness_penalty(freshness_reference, now_utc)

    return _clamp(base - penalty, 0.0, 100.0)


def threat_pressure_score(
    max_severity: str,
    max_cvss: float | None,
    finding_count: int,
    cve_count: int,
) -> float:
    """Compute threat pressure from finding severity, CVSS, and signal volume."""
    base = _severity_score(max_severity, max_cvss)

    # Incremental pressure based on finding/cve volume, capped for stability.
    pressure_boost = min(15.0, (finding_count * 1.5) + (cve_count * 0.75))
    return _clamp(base + pressure_boost, 0.0, 100.0)


def residual_risk_score(
    threat_pressure: float,
    control_confidence: float,
    blast_radius_multiplier: float,
) -> float:
    """Compute residual risk after accounting for control confidence.

    Formula:
        residual = threat_pressure * (1 - confidence/100) * blast_radius
    """
    normalized_confidence = _clamp(control_confidence, 0.0, 100.0)
    bounded_pressure = _clamp(threat_pressure, 0.0, 100.0)
    bounded_blast = _clamp(blast_radius_multiplier, 1.0, 1.5)

    residual = (
        bounded_pressure * (1.0 - (normalized_confidence / 100.0)) * bounded_blast
    )
    return _clamp(residual, 0.0, 100.0)


def priority_bucket(residual_risk: float) -> str:
    """Map residual risk score to a deterministic execution window."""
    if residual_risk >= 80.0:
        return "immediate"
    if residual_risk >= 60.0:
        return "30_days"
    if residual_risk >= 35.0:
        return "quarterly"
    return "annual"


@dataclass(slots=True)
class RiskComputationInput:
    """Input bundle for control-level risk scoring."""

    max_severity: str
    max_cvss: float | None
    finding_count: int
    cve_count: int
    evidence_statuses: list[str]
    freshest_collected_at: datetime | None
    freshest_updated_at: datetime | None
    blast_radius_multiplier: float


@dataclass(slots=True)
class RiskComputationResult:
    """Output bundle for control-level risk scoring."""

    control_confidence: float
    threat_pressure: float
    residual_risk: float
    priority: str


def compute_control_risk(data: RiskComputationInput) -> RiskComputationResult:
    """Compute full risk model output for one control in a deterministic way."""
    confidence = control_confidence_score(
        evidence_statuses=data.evidence_statuses,
        freshest_collected_at=data.freshest_collected_at,
        freshest_updated_at=data.freshest_updated_at,
    )
    pressure = threat_pressure_score(
        max_severity=data.max_severity,
        max_cvss=data.max_cvss,
        finding_count=data.finding_count,
        cve_count=data.cve_count,
    )
    residual = residual_risk_score(
        threat_pressure=pressure,
        control_confidence=confidence,
        blast_radius_multiplier=data.blast_radius_multiplier,
    )
    return RiskComputationResult(
        control_confidence=round(confidence, 2),
        threat_pressure=round(pressure, 2),
        residual_risk=round(residual, 2),
        priority=priority_bucket(residual),
    )
