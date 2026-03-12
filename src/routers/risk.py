"""Risk prioritization endpoints that fuse compliance posture with threat data.

This router intentionally reuses current entities (Assessment, Finding, Evidence,
Control, MetadataProfile) to provide immediate value without disruptive schema
changes. It supports multi-framework regulatory mapping (HIPAA, NIST 800-53, GDPR, SOX, FedRAMP, APRA CPS 234, CCPA).
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, TypeVar, cast

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import or_
from sqlalchemy.orm import Session

from src.audit import AuditAction, AuditLevel, log_audit_event
from src.config import settings
from src.database import get_db, get_or_404
from src.middleware import get_api_key_optional, limiter
from src.models import Assessment, Control, Evidence, Finding
from src.risk_engine import RiskComputationInput, compute_control_risk
from src.utils import to_str

router = APIRouter(prefix="/risk", tags=["risk"])
F = TypeVar("F", bound=Callable[..., Any])


def _typed_get(path: str) -> Callable[[F], F]:
    """Typed wrapper around FastAPI route decorators for mypy compatibility."""
    return cast(Callable[[F], F], router.get(path))


def _typed_limit(rule: str) -> Callable[[F], F]:
    """Typed wrapper around slowapi limiter decorators for mypy compatibility."""
    return cast(Callable[[F], F], limiter.limit(rule))


def _resolve_scope(
    db: Session, organization_id: str | None, assessment_id: str | None
) -> tuple[str, str | None]:
    """Resolve and validate organization/assessment scope for risk queries."""
    if not organization_id and not assessment_id:
        raise HTTPException(
            status_code=400,
            detail="Provide organization_id or assessment_id to scope risk backlog",
        )

    scoped_assessment_id = assessment_id
    scoped_organization_id = organization_id

    if scoped_assessment_id:
        assessment = get_or_404(
            db, Assessment, scoped_assessment_id, "Assessment not found"
        )
        assessment_org = to_str(getattr(assessment, "organization_id", None))

        if scoped_organization_id and assessment_org != scoped_organization_id:
            raise HTTPException(
                status_code=400,
                detail="assessment_id does not belong to provided organization_id",
            )

        scoped_organization_id = assessment_org

    if not scoped_organization_id:
        raise HTTPException(
            status_code=400, detail="Unable to determine organization scope"
        )

    return scoped_organization_id, scoped_assessment_id


def _fetch_scoped_findings(
    db: Session, organization_id: str, assessment_id: str | None
) -> list[Finding]:
    """Fetch findings in a validated organization/assessment scope."""
    findings_query = db.query(Finding).join(
        Assessment, Finding.assessment_id == Assessment.id
    )

    if assessment_id:
        findings_query = findings_query.filter(Finding.assessment_id == assessment_id)
    else:
        findings_query = findings_query.filter(
            Assessment.organization_id == organization_id
        )

    return findings_query.filter(Finding.control_id.isnot(None)).all()


def _collect_evidence_by_control(
    db: Session, organization_id: str, control_ids: set[str]
) -> dict[str, list[Evidence]]:
    """Collect evidence rows grouped by control for scoring."""
    evidence_rows: list[Evidence] = (
        db.query(Evidence)
        .outerjoin(Assessment, Evidence.assessment_id == Assessment.id)
        .filter(
            Evidence.control_id.in_(list(control_ids)),
            or_(
                Assessment.organization_id == organization_id,
                Evidence.assessment_id.is_(None),
            ),
        )
        .all()
    )

    evidence_by_control: dict[str, list[Evidence]] = defaultdict(list)
    for ev in evidence_rows:
        key = to_str(getattr(ev, "control_id", None))
        if key:
            evidence_by_control[key].append(ev)
    return evidence_by_control


def _blast_radius_multiplier(db: Session, assessment_id: str | None) -> float:
    """Infer blast-radius multiplier from software stack size."""
    if not assessment_id:
        return 1.0

    scoped_assessment = get_or_404(
        db, Assessment, assessment_id, "Assessment not found"
    )
    profile = getattr(scoped_assessment, "metadata_profile", None)
    stack_raw = getattr(profile, "software_stack", None) if profile else None
    stack_size = len(stack_raw) if isinstance(stack_raw, dict) else 0
    return min(1.5, 1.0 + (stack_size / 100.0))


def _summarize_findings(
    grouped_findings: list[Finding],
) -> tuple[str, float | None, int, list[str]]:
    """Summarize findings into severity/CVSS/CVE aggregates for scoring."""
    max_cvss: float | None = None
    max_severity = "low"
    cve_count = 0
    sample_findings: list[str] = []

    severity_rank = {
        "critical": 4,
        "immediate": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
    }

    for idx, finding in enumerate(grouped_findings):
        finding_cvss = getattr(finding, "cvss_score", None)
        if isinstance(finding_cvss, int | float):
            cvss_value = float(finding_cvss)
            if max_cvss is None or cvss_value > max_cvss:
                max_cvss = cvss_value

        severity = to_str(getattr(finding, "severity", None), default="low")
        if severity_rank.get(severity.lower(), 1) > severity_rank.get(
            max_severity.lower(), 1
        ):
            max_severity = severity

        cve_ids = getattr(finding, "cve_ids", None)
        if isinstance(cve_ids, list):
            cve_count += len(cve_ids)

        if idx < 3:
            sample_findings.append(
                to_str(getattr(finding, "title", None), default="Untitled finding")
            )

    return max_severity, max_cvss, cve_count, sample_findings


def _extract_evidence_signal(
    evidence_rows: list[Evidence],
) -> tuple[list[str], datetime | None, datetime | None]:
    """Extract confidence-relevant evidence status and freshness values."""
    evidence_statuses = [
        to_str(getattr(ev, "status", None), default="not_started")
        for ev in evidence_rows
    ]

    freshest_collected_at: datetime | None = None
    freshest_updated_at: datetime | None = None
    for ev in evidence_rows:
        collected = getattr(ev, "collected_at", None)
        updated = getattr(ev, "updated_at", None)
        if isinstance(collected, datetime) and (
            freshest_collected_at is None or collected > freshest_collected_at
        ):
            freshest_collected_at = collected
        if isinstance(updated, datetime) and (
            freshest_updated_at is None or updated > freshest_updated_at
        ):
            freshest_updated_at = updated

    return evidence_statuses, freshest_collected_at, freshest_updated_at


def _build_backlog_items(
    findings: list[Finding],
    control_by_id: dict[str, Control],
    evidence_by_control: dict[str, list[Evidence]],
    blast_radius_multiplier: float,
) -> list[dict[str, Any]]:
    """Build scored backlog items for each control with findings."""
    findings_by_control: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        control_id = to_str(getattr(finding, "control_id", None))
        if control_id:
            findings_by_control[control_id].append(finding)

    items: list[dict[str, Any]] = []
    for control_id, grouped_findings in findings_by_control.items():
        control = control_by_id.get(control_id)
        control_title = to_str(
            getattr(control, "title", None), default="Unknown control"
        )
        control_category = to_str(getattr(control, "category", None), default="Unknown")

        max_severity, max_cvss, cve_count, sample_findings = _summarize_findings(
            grouped_findings
        )
        evidence_statuses, freshest_collected_at, freshest_updated_at = (
            _extract_evidence_signal(evidence_by_control.get(control_id, []))
        )

        scored = compute_control_risk(
            RiskComputationInput(
                max_severity=max_severity,
                max_cvss=max_cvss,
                finding_count=len(grouped_findings),
                cve_count=cve_count,
                evidence_statuses=evidence_statuses,
                freshest_collected_at=freshest_collected_at,
                freshest_updated_at=freshest_updated_at,
                blast_radius_multiplier=blast_radius_multiplier,
            )
        )

        recommended_action = (
            "Strengthen and validate control evidence; prioritize remediation for mapped findings"
            if scored.residual_risk >= 60
            else "Maintain evidence freshness and continue scheduled remediation"
        )

        items.append(
            {
                "control_id": control_id,
                "control_title": control_title,
                "control_category": control_category,
                "finding_count": len(grouped_findings),
                "cve_count": cve_count,
                "max_severity": max_severity,
                "max_cvss": round(max_cvss, 2) if max_cvss is not None else None,
                "control_confidence": scored.control_confidence,
                "threat_pressure": scored.threat_pressure,
                "residual_risk": scored.residual_risk,
                "priority_bucket": scored.priority,
                "recommended_action": recommended_action,
                "sample_findings": sample_findings,
            }
        )

    return items


@_typed_get("/prioritized-backlog")
@_typed_limit(f"{settings.rate_limit_per_minute}/minute")
def get_prioritized_risk_backlog(
    request: Request,
    organization_id: str | None = Query(default=None, min_length=1),
    assessment_id: str | None = Query(default=None, min_length=1),
    top: int = Query(default=20, ge=1, le=200),
    db: Session = Depends(get_db),
    api_key: str = Depends(get_api_key_optional),
) -> dict[str, Any]:
    """Return risk-prioritized backlog for HIPAA control hardening.

    Security and integrity safeguards:
    - Requires at least one scope filter (`organization_id` or `assessment_id`) to
      prevent accidental full-dataset scans.
    - Validates assessment-organization relationship to prevent cross-tenant leakage.
    - Uses bounded query parameters (`top`) to prevent abuse and oversized responses.
    """
    scoped_organization_id, scoped_assessment_id = _resolve_scope(
        db=db, organization_id=organization_id, assessment_id=assessment_id
    )

    findings = _fetch_scoped_findings(
        db=db,
        organization_id=scoped_organization_id,
        assessment_id=scoped_assessment_id,
    )

    if not findings:
        log_audit_event(
            action=AuditAction.DATA_READ,
            request=request,
            api_key=api_key,
            resource_type="risk_backlog",
            level=AuditLevel.INFO,
            details={
                "organization_id": scoped_organization_id,
                "assessment_id": scoped_assessment_id,
                "total_items": 0,
            },
        )
        return {
            "organization_id": scoped_organization_id,
            "assessment_id": scoped_assessment_id,
            "generated_at": datetime.now(UTC),
            "total_items": 0,
            "items": [],
        }

    control_ids = {
        to_str(getattr(finding, "control_id", None))
        for finding in findings
        if to_str(getattr(finding, "control_id", None))
    }
    controls: list[Control] = (
        db.query(Control).filter(Control.id.in_(list(control_ids))).all()
    )
    control_by_id = {
        to_str(getattr(control, "id", None)): control for control in controls
    }

    evidence_by_control = _collect_evidence_by_control(
        db=db,
        organization_id=scoped_organization_id,
        control_ids=control_ids,
    )
    blast_multiplier = _blast_radius_multiplier(
        db=db, assessment_id=scoped_assessment_id
    )

    items = _build_backlog_items(
        findings=findings,
        control_by_id=control_by_id,
        evidence_by_control=evidence_by_control,
        blast_radius_multiplier=blast_multiplier,
    )

    sorted_items = sorted(items, key=lambda item: item["residual_risk"], reverse=True)[
        :top
    ]

    log_audit_event(
        action=AuditAction.DATA_READ,
        request=request,
        api_key=api_key,
        resource_type="risk_backlog",
        level=AuditLevel.INFO,
        details={
            "organization_id": scoped_organization_id,
            "assessment_id": scoped_assessment_id,
            "top": top,
            "total_items": len(sorted_items),
        },
    )

    return {
        "organization_id": scoped_organization_id,
        "assessment_id": scoped_assessment_id,
        "generated_at": datetime.now(UTC),
        "total_items": len(sorted_items),
        "items": sorted_items,
    }
