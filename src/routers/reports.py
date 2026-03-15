"""Assessment report generation, download, and remediation roadmap endpoints."""

import logging
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypeVar, cast
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from src.audit import AuditAction, log_audit_event
from src.config import settings
from src.constants import Severity
from src.database import get_db, get_or_404
from src.middleware import get_api_key_optional, limiter
from src.models import Assessment, Finding, Organization
from src.schemas import (
    AssessmentReportCreateResponse,
    AssessmentReportStatusResponse,
    RemediationRoadmapResponse,
    RoadmapItem,
    RoadmapSummary,
)
from src.utils import severity_rank, to_float, to_str

router = APIRouter(prefix="/assessments", tags=["assessments"])
logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., object])
REPORT_OUTPUT_DIR = Path("generated_reports")
REPORT_JOBS: dict[str, dict[str, Any]] = {}


def _rate_limited(limit_value: str) -> Callable[[F], F]:
    limiter_any = cast(Any, limiter)
    return cast(Callable[[F], F], limiter_any.limit(limit_value))


def _report_file_path(report_id: str) -> Path:
    return REPORT_OUTPUT_DIR / f"assessment-report-{report_id}.txt"


def _render_assessment_report(
    organization: Organization,
    assessment: Assessment,
    findings: list[Finding],
) -> str:
    now_text = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%SZ")
    organization_id = to_str(getattr(organization, "id", None))
    organization_name = to_str(getattr(organization, "name", None), default="Unknown")
    assessment_id = to_str(getattr(assessment, "id", None))

    lines = [
        "========================================",
        "CHARLOTTESWEB ASSESSMENT REPORT",
        "========================================",
        "",
        "Executive Summary",
        "-----------------",
        f"Organization: {organization_name}",
        f"Organization ID: {organization_id}",
        f"Assessment ID: {assessment_id}",
        f"Generated At (UTC): {now_text}",
        f"Total Findings: {len(findings)}",
        "",
        "Technical Appendix",
        "------------------",
    ]

    if not findings:
        lines.extend(["No findings were recorded for this assessment.", ""])
        return "\n".join(lines)

    sorted_findings = sorted(
        findings,
        key=lambda f: severity_rank(
            to_str(getattr(f, "severity", None), default="low")
        ),
        reverse=True,
    )

    for index, finding in enumerate(sorted_findings, start=1):
        lines.extend(
            [
                f"[{index}] {to_str(getattr(finding, 'title', None), default='Untitled finding')}",
                f"Severity: {to_str(getattr(finding, 'severity', None), default='unknown')}",
                f"CVSS: {to_float(getattr(finding, 'cvss_score', None), default=0.0)}",
                f"Priority Window: {to_str(getattr(finding, 'priority_window', None), default='n/a')}",
                f"Control ID: {to_str(getattr(finding, 'control_id', None), default='n/a')}",
                f"External ID: {to_str(getattr(finding, 'external_id', None), default='n/a')}",
                "Description:",
                to_str(
                    getattr(finding, "description", None),
                    default="No description available.",
                ),
                "Remediation Guidance:",
                to_str(
                    getattr(finding, "remediation_guidance", None),
                    default="No remediation guidance provided.",
                ),
                "",
            ]
        )

    return "\n".join(lines)


def _store_report_job(
    report_id: str,
    assessment_id: str,
    generated_at: datetime,
    download_token: str,
    report_path: Path,
) -> None:
    REPORT_JOBS[report_id] = {
        "assessment_id": assessment_id,
        "status": "completed",
        "generated_at": generated_at,
        "download_token": download_token,
        "report_path": str(report_path),
    }


def _get_report_job_or_404(report_id: str, assessment_id: str) -> dict[str, Any]:
    report_job = REPORT_JOBS.get(report_id)
    if not report_job or report_job.get("assessment_id") != assessment_id:
        raise HTTPException(status_code=404, detail="Report not found")
    return report_job


@router.post("/{assessment_id}/reports", response_model=AssessmentReportCreateResponse)
@_rate_limited(f"{settings.rate_limit_per_minute}/minute")
def generate_assessment_report(
    assessment_id: str,
    request: Request,
    db: Session = Depends(get_db),
    api_key: str = Depends(get_api_key_optional),
) -> AssessmentReportCreateResponse:
    """Generate a downloadable plain-text report for an assessment."""
    assessment = get_or_404(db, Assessment, assessment_id, "Assessment not found")
    organization = get_or_404(
        db,
        Organization,
        to_str(getattr(assessment, "organization_id", None)),
        "Organization not found",
    )
    findings: list[Finding] = (
        db.query(Finding).filter(Finding.assessment_id == assessment_id).all()
    )

    report_id = str(uuid4())
    generated_at = datetime.now(UTC)
    download_token = str(uuid4())
    report_text = _render_assessment_report(
        organization=organization,
        assessment=assessment,
        findings=findings,
    )

    REPORT_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    report_path = _report_file_path(report_id)
    report_path.write_text(report_text, encoding="utf-8")

    _store_report_job(
        report_id=report_id,
        assessment_id=assessment_id,
        generated_at=generated_at,
        download_token=download_token,
        report_path=report_path,
    )

    log_audit_event(
        action=AuditAction.DATA_CREATED,
        request=request,
        api_key=api_key,
        resource_type="assessment_report",
        resource_id=report_id,
        details={"assessment_id": assessment_id, "findings_count": len(findings)},
    )

    return AssessmentReportCreateResponse(
        report_id=report_id,
        assessment_id=assessment_id,
        status="completed",
        generated_at=generated_at,
        download_token=download_token,
    )


@router.get(
    "/{assessment_id}/reports/{report_id}/status",
    response_model=AssessmentReportStatusResponse,
)
def get_assessment_report_status(
    assessment_id: str,
    report_id: str,
    db: Session = Depends(get_db),
) -> AssessmentReportStatusResponse:
    """Get generation status and download URL for a previously generated report."""
    get_or_404(db, Assessment, assessment_id, "Assessment not found")
    report_job = _get_report_job_or_404(
        report_id=report_id, assessment_id=assessment_id
    )

    token = to_str(report_job.get("download_token"), default="")
    download_url = f"/api/v1/assessments/{assessment_id}/reports/{report_id}/download?token={token}"

    return AssessmentReportStatusResponse(
        report_id=report_id,
        assessment_id=assessment_id,
        status=to_str(report_job.get("status"), default="pending"),
        generated_at=cast(datetime, report_job.get("generated_at", datetime.now(UTC))),
        download_url=download_url,
    )


@router.get("/{assessment_id}/reports/{report_id}/download")
def download_assessment_report(
    assessment_id: str,
    report_id: str,
    request: Request,
    token: str = Query(..., description="Download token from report status endpoint"),
    api_key: str = Depends(get_api_key_optional),
) -> FileResponse:
    """Download generated assessment report when token access check succeeds."""
    report_job = _get_report_job_or_404(
        report_id=report_id, assessment_id=assessment_id
    )

    expected_token = to_str(report_job.get("download_token"), default="")
    if not token or token != expected_token:
        raise HTTPException(status_code=403, detail="Invalid report download token")

    report_path = Path(to_str(report_job.get("report_path"), default=""))
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report file not found")

    # Guard against path traversal — report must be inside expected directory.
    expected_dir = REPORT_OUTPUT_DIR.resolve()
    if not report_path.resolve().is_relative_to(expected_dir):
        raise HTTPException(status_code=403, detail="Invalid report path")

    log_audit_event(
        action=AuditAction.DATA_READ,
        request=request,
        api_key=api_key,
        resource_type="assessment_report",
        resource_id=report_id,
        details={"assessment_id": assessment_id},
    )

    return FileResponse(
        path=str(report_path),
        media_type="text/plain",
        filename=f"assessment-report-{assessment_id}.txt",
    )


@router.get("/{assessment_id}/roadmap", response_model=RemediationRoadmapResponse)
@_rate_limited(f"{settings.rate_limit_per_minute}/minute")
def get_remediation_roadmap(
    request: Request,
    assessment_id: str,
    db: Session = Depends(get_db),
    api_key: str = Depends(get_api_key_optional),
) -> RemediationRoadmapResponse:
    """Generate prioritized remediation roadmap for an assessment."""
    assessment = get_or_404(db, Assessment, assessment_id, "Assessment not found")

    findings: list[Finding] = (
        db.query(Finding).filter(Finding.assessment_id == assessment_id).all()
    )

    immediate: list[RoadmapItem] = []
    thirty_days: list[RoadmapItem] = []
    quarterly: list[RoadmapItem] = []
    annual: list[RoadmapItem] = []

    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0

    for finding in findings:
        item = RoadmapItem(
            finding_id=finding.id,
            control_id=finding.control_id,
            title=finding.title,
            severity=finding.severity,
            cvss_score=finding.cvss_score,
            priority_window=finding.priority_window or "quarterly",
            owner=finding.owner,
            remediation_guidance=finding.remediation_guidance
            or "Contact security team for guidance",
            cve_ids=finding.cve_ids or [],
            cwe_ids=finding.cwe_ids or [],
        )

        priority = str(finding.priority_window or "quarterly")
        if priority == "immediate":
            immediate.append(item)
        elif priority == "30_days":
            thirty_days.append(item)
        elif priority == "quarterly":
            quarterly.append(item)
        elif priority == "annual":
            annual.append(item)
        else:
            quarterly.append(item)

        sev = to_str(getattr(finding, "severity", None)).lower()
        if sev == Severity.CRITICAL:
            critical_count += 1
        elif sev == Severity.HIGH:
            high_count += 1
        elif sev == Severity.MEDIUM:
            medium_count += 1
        elif sev == Severity.LOW:
            low_count += 1

    summary = RoadmapSummary(
        total_findings=len(findings),
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        immediate_actions=len(immediate),
        thirty_day_actions=len(thirty_days),
        quarterly_actions=len(quarterly),
        annual_actions=len(annual),
    )

    roadmap = RemediationRoadmapResponse(
        assessment_id=assessment_id,
        organization_id=assessment.organization_id,
        generated_at=datetime.now(UTC),
        summary=summary,
        immediate=immediate,
        thirty_days=thirty_days,
        quarterly=quarterly,
        annual=annual,
    )

    log_audit_event(
        action=AuditAction.ROADMAP_GENERATED,
        request=request,
        api_key=api_key,
        resource_type="assessment",
        resource_id=assessment_id,
        details={
            "total_findings": summary.total_findings,
            "immediate_actions": summary.immediate_actions,
        },
    )

    return roadmap
