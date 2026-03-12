"""Finding listing, filtering, and threat enrichment endpoints."""

from collections.abc import Callable
from datetime import UTC, datetime
from typing import TypeVar

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from src.database import get_db, get_or_404
from src.mitre_service import mitre_service
from src.models import Assessment, Control, Finding
from src.schemas import FindingResponse, ThreatContext
from src.utils import (
    priority_rank,
    severity_rank,
    to_float,
    to_optional_str,
    to_str,
    to_str_list,
)

router = APIRouter(prefix="/assessments", tags=["assessments"])

F = TypeVar("F", bound=Callable[..., object])


def _validate_sort_params(sort_by: str, sort_order: str) -> None:
    valid_sort_by = {"severity", "cvss_score", "priority_window", "created_at"}
    valid_sort_order = {"asc", "desc"}

    if sort_by not in valid_sort_by:
        raise HTTPException(
            status_code=400,
            detail=(
                "Invalid sort_by value. Use one of: "
                "severity, cvss_score, priority_window, created_at"
            ),
        )

    if sort_order.lower() not in valid_sort_order:
        raise HTTPException(
            status_code=400, detail="Invalid sort_order value. Use asc or desc"
        )


def _query_findings(
    db: Session,
    assessment_id: str,
    severity: str | None,
    priority_window: str | None,
    control_id: str | None,
) -> list[Finding]:
    findings_query = db.query(Finding).filter(Finding.assessment_id == assessment_id)
    if severity:
        findings_query = findings_query.filter(Finding.severity == severity.lower())
    if priority_window:
        findings_query = findings_query.filter(
            Finding.priority_window == priority_window.lower()
        )
    if control_id:
        findings_query = findings_query.filter(Finding.control_id == control_id)
    return findings_query.all()


def _build_control_domain_map(
    db: Session, findings: list[Finding]
) -> dict[str, str | None]:
    control_ids = {
        to_str(getattr(finding, "control_id", None))
        for finding in findings
        if to_str(getattr(finding, "control_id", None))
    }
    if not control_ids:
        return {}

    controls = (
        db.query(Control.id, Control.category).filter(Control.id.in_(control_ids)).all()
    )
    return {
        to_str(control_item[0]): to_optional_str(control_item[1])
        for control_item in controls
    }


def _to_finding_response(
    finding: Finding,
    resolved_control_domain: str | None,
) -> FindingResponse:
    control_id = to_str(getattr(finding, "control_id", None))
    cwe_ids = to_str_list(getattr(finding, "cwe_ids", None))
    threat_context: ThreatContext | None = None

    if cwe_ids:
        candidate_context = mitre_service.enrich_finding_with_threat_context(
            cwe_ids=cwe_ids,
            control_id=control_id,
        )
        if candidate_context and candidate_context.get("techniques"):
            threat_context = ThreatContext(**candidate_context)

    return FindingResponse(
        id=to_str(getattr(finding, "id", None)),
        assessment_id=to_str(getattr(finding, "assessment_id", None)),
        control_id=control_id,
        control_domain=resolved_control_domain,
        title=to_str(getattr(finding, "title", None)),
        description=to_str(getattr(finding, "description", None)),
        severity=to_str(getattr(finding, "severity", None)),
        cvss_score=to_float(getattr(finding, "cvss_score", None), default=0.0),
        external_id=to_optional_str(getattr(finding, "external_id", None)),
        cve_ids=to_str_list(getattr(finding, "cve_ids", None)),
        cwe_ids=cwe_ids,
        remediation_guidance=to_optional_str(
            getattr(finding, "remediation_guidance", None)
        ),
        priority_window=to_optional_str(getattr(finding, "priority_window", None)),
        owner=to_optional_str(getattr(finding, "owner", None)),
        created_at=getattr(finding, "created_at", datetime.now(UTC)),
        threat_context=threat_context,
    )


def _sort_finding_responses(
    findings: list[FindingResponse],
    sort_by: str,
    sort_order: str,
) -> list[FindingResponse]:
    reverse_sort = sort_order.lower() == "desc"
    if sort_by == "severity":
        findings.sort(
            key=lambda f: severity_rank(f.severity),
            reverse=reverse_sort,
        )
    elif sort_by == "cvss_score":
        findings.sort(
            key=lambda f: f.cvss_score or 0.0,
            reverse=reverse_sort,
        )
    elif sort_by == "priority_window":
        findings.sort(
            key=lambda f: priority_rank(f.priority_window or ""),
            reverse=reverse_sort,
        )
    elif sort_by == "created_at":
        findings.sort(
            key=lambda f: f.created_at,
            reverse=reverse_sort,
        )
    return findings


@router.get("/{assessment_id}/findings", response_model=list[FindingResponse])
def get_assessment_findings(
    assessment_id: str,
    severity: str | None = Query(None, description="Filter by severity"),
    priority_window: str | None = Query(None, description="Filter by priority window"),
    control_id: str | None = Query(None, description="Filter by control ID"),
    control_domain: str | None = Query(
        None, description="Filter by control category/domain"
    ),
    sort_by: str = Query(
        "severity",
        description="Sort field: severity, cvss_score, priority_window, created_at",
    ),
    sort_order: str = Query("desc", description="Sort order: asc or desc"),
    db: Session = Depends(get_db),
) -> list[FindingResponse]:
    """Get findings for an assessment with threat intelligence context."""
    get_or_404(db, Assessment, assessment_id, "Assessment not found")
    _validate_sort_params(sort_by=sort_by, sort_order=sort_order)
    findings = _query_findings(
        db=db,
        assessment_id=assessment_id,
        severity=severity,
        priority_window=priority_window,
        control_id=control_id,
    )
    control_map = _build_control_domain_map(db=db, findings=findings)

    enriched_findings: list[FindingResponse] = []
    domain_filter = (control_domain or "").lower().strip()
    for finding in findings:
        resolved_control_domain = control_map.get(
            to_str(getattr(finding, "control_id", None))
        )
        if domain_filter:
            if (
                not resolved_control_domain
                or domain_filter not in resolved_control_domain.lower()
            ):
                continue

        enriched_findings.append(
            _to_finding_response(
                finding=finding,
                resolved_control_domain=resolved_control_domain,
            )
        )

    return _sort_finding_responses(
        findings=enriched_findings,
        sort_by=sort_by,
        sort_order=sort_order,
    )
