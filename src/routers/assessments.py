"""Assessment workflow endpoints."""

import logging
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, TypeVar, cast

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from src.audit import AuditAction, AuditLevel, log_audit_event
from src.compliance_as_code import ComplianceAsCodeEvaluator
from src.config import settings
from src.constants import AssessmentStatus, PriorityWindow, Severity
from src.cwe_mappings import CWE_TO_HIPAA_CONTROL, FALLBACK_CONTROL_CANDIDATES
from src.database import get_db, get_or_404
from src.dependabot_service import DependabotService
from src.middleware import get_api_key_optional, limiter
from src.mitre_service import mitre_service
from src.models import (
    Assessment,
    Control,
    Evidence,
    Finding,
    MetadataProfile,
    Organization,
)
from src.nvd_service import NVDService
from src.rules_engine import RulesEngine
from src.schemas import (
    AssessmentCreate,
    AssessmentResponse,
    AssessmentStatusResponse,
    ComplianceAsCodeResponse,
    EvidenceChecklistItem,
    EvidenceChecklistResponse,
    FindingResponse,
    RemediationRoadmapResponse,
    RoadmapItem,
    RoadmapSummary,
    ThreatContext,
)

router = APIRouter(prefix="/assessments", tags=["assessments"])
logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., object])


def _rate_limited(limit_value: str) -> Callable[[F], F]:
    limiter_any = cast(Any, limiter)
    return cast(Callable[[F], F], limiter_any.limit(limit_value))


def _to_str(value: object | None, default: str = "") -> str:
    if value is None:
        return default
    return str(value)


def _to_optional_str(value: object | None) -> str | None:
    if value is None:
        return None
    return str(value)


def _to_float(value: object | None, default: float = 0.0) -> float:
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return default
    return default


def _to_str_list(value: object | None) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in cast(list[Any], value)]
    if isinstance(value, tuple):
        return [str(item) for item in cast(tuple[Any, ...], value)]
    if isinstance(value, set):
        return [str(item) for item in cast(set[Any], value)]
    return []


def _get_metadata_profile_or_404(
    db: Session, assessment: Assessment
) -> MetadataProfile:
    metadata_profile: MetadataProfile | None = (
        db.query(MetadataProfile)
        .filter(
            MetadataProfile.id == assessment.metadata_profile_id  # type: ignore[attr-defined]
        )
        .first()
    )
    if not metadata_profile:
        raise HTTPException(status_code=404, detail="Metadata profile not found")
    return metadata_profile


def _get_available_control_ids(db: Session) -> set[str]:
    available_control_ids = {control_id for (control_id,) in db.query(Control.id).all()}
    if not available_control_ids:
        logger.warning(
            "No controls found in database; findings will be created without control mapping"
        )
    return available_control_ids


def _map_control_id_for_cwes(
    cwe_ids: list[str], available_control_ids: set[str]
) -> tuple[str | None, str]:
    for cwe_id in cwe_ids:
        mapped_control_id = CWE_TO_HIPAA_CONTROL.get(cwe_id)
        if mapped_control_id and mapped_control_id in available_control_ids:
            return mapped_control_id, "cwe"

    for fallback_control in FALLBACK_CONTROL_CANDIDATES:
        if fallback_control in available_control_ids:
            return fallback_control, "fallback"

    return None, "none"


def _finding_exists(db: Session, assessment_id: str, external_id: str) -> bool:
    existing_finding = (
        db.query(Finding)
        .filter(
            Finding.assessment_id == assessment_id,  # type: ignore[attr-defined]
            Finding.external_id == external_id,  # type: ignore[attr-defined]
        )
        .first()
    )
    return existing_finding is not None


def _build_nvd_findings(
    db: Session,
    assessment_id: str,
    nvd_results: dict[str, list[dict[str, Any]]],
    nvd_service: NVDService,
    available_control_ids: set[str],
) -> tuple[list[Finding], int, int, int, int]:
    new_findings: list[Finding] = []
    total_cves_processed = 0
    mapped_via_cwe = 0
    mapped_via_fallback = 0
    unmapped_cves = 0

    for component, cves in nvd_results.items():
        for cve in cves:
            cve_id = _to_str(cve.get("cve_id"), default="")
            if not cve_id:
                continue
            if _finding_exists(db, assessment_id, cve_id):
                continue

            total_cves_processed += 1
            cvss_score = _to_float(cve.get("cvss_score"))
            cwe_ids = _to_str_list(cve.get("cwe_ids"))

            control_id, mapping_source = _map_control_id_for_cwes(
                cwe_ids=cwe_ids,
                available_control_ids=available_control_ids,
            )

            if mapping_source == "cwe":
                mapped_via_cwe += 1
            elif mapping_source == "fallback":
                mapped_via_fallback += 1
            else:
                unmapped_cves += 1

            finding = Finding(
                assessment_id=assessment_id,  # type: ignore[arg-type]
                control_id=control_id,
                external_id=cve_id,
                title=f"{cve_id}: {component} vulnerability",
                description=_to_str(cve.get("description"), default=""),
                severity=nvd_service.get_severity_from_cvss(cvss_score),
                cvss_score=cvss_score,
                cwe_ids=cwe_ids,
                priority_window=nvd_service.get_priority_window_from_cvss(cvss_score),
                remediation_guidance=(
                    f"Update {component} to a patched version. "
                    f"Check CVE details at https://nvd.nist.gov/vuln/detail/{cve_id}"
                ),
            )
            db.add(finding)
            new_findings.append(finding)

    return (
        new_findings,
        total_cves_processed,
        mapped_via_cwe,
        mapped_via_fallback,
        unmapped_cves,
    )


def _create_evidence_for_findings(
    db: Session,
    assessment_id: str,
    new_findings: list[Finding],
) -> int:
    evidence_created_count = 0
    unique_control_ids = {
        _to_str(getattr(finding, "control_id", None))
        for finding in new_findings
        if _to_str(getattr(finding, "control_id", None))
    }

    for control_id in unique_control_ids:
        control = db.query(Control).filter(Control.id == control_id).first()
        if not control:
            continue

        evidence_types = _to_str_list(getattr(control, "evidence_types", None))
        if not evidence_types:
            continue

        for evidence_type in evidence_types:
            existing_evidence = (
                db.query(Evidence)
                .filter(
                    Evidence.assessment_id == assessment_id,
                    Evidence.control_id == control_id,
                    Evidence.evidence_type == evidence_type,
                )
                .first()
            )

            if existing_evidence:
                continue

            db.add(
                Evidence(
                    assessment_id=assessment_id,
                    control_id=control_id,
                    evidence_type=evidence_type,
                    title=f"{control_id}: {evidence_type}",
                    description=f"Evidence for {control.title}",
                    status="not_started",
                    owner="system",
                )
            )
            evidence_created_count += 1

    return evidence_created_count


def _persist_nvd_findings_and_evidence(
    db: Session,
    assessment: Assessment,
    assessment_id: str,
    new_findings: list[Finding],
) -> int:
    if not new_findings:
        return 0

    try:
        db.commit()
        db.refresh(assessment)
        evidence_created_count = _create_evidence_for_findings(
            db=db,
            assessment_id=assessment_id,
            new_findings=new_findings,
        )
        db.commit()
        return evidence_created_count
    except Exception as err:
        db.rollback()
        logger.error("Failed to commit findings: %s", err, exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=(
                "Failed to save vulnerability findings. "
                "Please try again with a different software stack or contact support."
            ),
        ) from err


def _build_dependabot_findings(
    db: Session,
    assessment_id: str,
    alerts: list[dict[str, Any]],
    nvd_service: NVDService,
    available_control_ids: set[str],
) -> tuple[list[Finding], int, int]:
    new_findings: list[Finding] = []
    mapped_via_cwe = 0
    unmapped_alerts = 0

    for alert in alerts:
        cve_id = _to_str(alert.get("cve_id"), default="")
        if not cve_id:
            continue
        if _finding_exists(db, assessment_id, cve_id):
            continue

        cvss_score = _to_float(alert.get("cvss_score"))
        cwe_ids = _to_str_list(alert.get("cwe_ids"))
        control_id, mapping_source = _map_control_id_for_cwes(
            cwe_ids=cwe_ids,
            available_control_ids=available_control_ids,
        )

        if mapping_source == "cwe":
            mapped_via_cwe += 1
        elif mapping_source == "none":
            unmapped_alerts += 1

        package_name = _to_str(alert.get("package_name"), default="unknown-package")
        ecosystem = _to_str(alert.get("ecosystem"), default="unknown-ecosystem")
        advisory_url = _to_str(alert.get("url"), default="N/A")

        finding = Finding(
            assessment_id=assessment_id,  # type: ignore[arg-type]
            control_id=control_id,
            external_id=cve_id,
            title=(
                f"{cve_id}: {package_name} " f"({ecosystem}) dependency vulnerability"
            ),
            description=_to_str(alert.get("description"), default=""),
            severity=nvd_service.get_severity_from_cvss(cvss_score),
            cvss_score=cvss_score,
            cwe_ids=cwe_ids,
            priority_window=nvd_service.get_priority_window_from_cvss(cvss_score),
            owner="Supply Chain Security",
            remediation_guidance=(
                f"Update {package_name} to a patched version. "
                f"See GitHub Advisory: {advisory_url}"
            ),
        )
        db.add(finding)
        new_findings.append(finding)

    return new_findings, mapped_via_cwe, unmapped_alerts


@router.post("", response_model=AssessmentResponse, status_code=201)
@_rate_limited(f"{settings.rate_limit_per_minute}/minute")
def create_assessment(
    request: Request,
    assessment_data: AssessmentCreate,
    db: Session = Depends(get_db),
    api_key: str = Depends(get_api_key_optional),
) -> Assessment:
    """Create and run a new assessment."""
    # Verify organization and metadata profile exist
    get_or_404(
        db, Organization, assessment_data.organization_id, "Organization not found"
    )
    get_or_404(
        db,
        MetadataProfile,
        assessment_data.metadata_profile_id,
        "Metadata profile not found",
    )

    # Create assessment
    try:
        assessment = Assessment(
            organization_id=assessment_data.organization_id,
            metadata_profile_id=assessment_data.metadata_profile_id,
            status=AssessmentStatus.RUNNING,
        )
        db.add(assessment)
        db.commit()
        db.refresh(assessment)
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to create assessment: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500, detail="Failed to create assessment. Please try again."
        ) from e

    # Audit log - assessment created
    log_audit_event(
        action=AuditAction.ASSESSMENT_CREATED,
        request=request,
        api_key=api_key,
        resource_type="assessment",
        resource_id=assessment.id,  # type: ignore[arg-type] - SQLAlchemy Column unwraps at runtime
        details={"organization_id": assessment.organization_id},
    )

    # Run rules engine
    try:
        engine = RulesEngine(db)
        findings = engine.run_assessment(assessment.id)  # type: ignore[arg-type] - SQLAlchemy Column unwraps at runtime

        # Save findings
        for finding in findings:
            db.add(finding)

        # Mark assessment complete
        assessment.status = AssessmentStatus.COMPLETED  # type: ignore[attr-defined] - SQLAlchemy ORM attribute assignment
        assessment.completed_at = datetime.now(UTC)  # type: ignore[attr-defined] - SQLAlchemy ORM attribute assignment
        db.commit()

        # Audit log - assessment completed
        log_audit_event(
            action=AuditAction.ASSESSMENT_RUN,
            request=request,
            api_key=api_key,
            resource_type="assessment",
            resource_id=assessment.id,  # type: ignore[arg-type] - SQLAlchemy Column unwraps at runtime
            details={"findings_count": len(findings), "status": "completed"},
        )

    except Exception as e:
        assessment.status = AssessmentStatus.FAILED  # type: ignore[attr-defined] - SQLAlchemy ORM attribute assignment
        try:
            db.commit()
        except Exception as commit_error:
            logger.warning(
                f"Failed to commit assessment failure status: {commit_error}"
            )
            db.rollback()

        logger.error(f"Assessment failed: {str(e)}", exc_info=True)
        # Audit log - assessment failed
        log_audit_event(
            action=AuditAction.ERROR,
            request=request,
            api_key=api_key,
            resource_type="assessment",
            resource_id=assessment.id,  # type: ignore[arg-type] - SQLAlchemy Column unwraps at runtime
            success=False,
            details={"status": "failed"},
        )
        # Return safe error message
        raise HTTPException(
            status_code=500,
            detail="Assessment execution failed. Please try again or contact support.",
        ) from e

    db.refresh(assessment)
    return assessment


@router.get("/{assessment_id}", response_model=AssessmentResponse)
def get_assessment(assessment_id: str, db: Session = Depends(get_db)) -> Assessment:
    """Get assessment by ID."""
    assessment = get_or_404(db, Assessment, assessment_id, "Assessment not found")
    return assessment


@router.get("/{assessment_id}/status", response_model=AssessmentStatusResponse)
def get_assessment_status(
    assessment_id: str,
    db: Session = Depends(get_db),
) -> AssessmentStatusResponse:
    """Get assessment run status with coarse-grained progress for UI workflows."""
    assessment = get_or_404(db, Assessment, assessment_id, "Assessment not found")

    findings_count = (
        db.query(Finding)
        .filter(Finding.assessment_id == assessment_id)  # type: ignore[attr-defined]
        .count()
    )

    status = _to_str(getattr(assessment, "status", None), default="pending")
    completed_at = getattr(assessment, "completed_at", None)
    initiated_at = getattr(assessment, "initiated_at", None)

    if status == AssessmentStatus.COMPLETED:
        progress_percent = 100
        current_step = "Assessment complete"
        updated_at = completed_at
    elif status == AssessmentStatus.FAILED:
        progress_percent = 100
        current_step = "Assessment failed"
        updated_at = completed_at or initiated_at
    elif status == AssessmentStatus.RUNNING:
        progress_percent = 60
        current_step = "Assessment running"
        updated_at = initiated_at
    else:
        progress_percent = 20
        current_step = "Assessment queued"
        updated_at = initiated_at

    return AssessmentStatusResponse(
        assessment_id=assessment_id,
        status=status,
        progress_percent=progress_percent,
        current_step=current_step,
        findings_count=findings_count,
        updated_at=updated_at,
    )


@router.get(
    "/{assessment_id}/compliance-as-code", response_model=ComplianceAsCodeResponse
)
def evaluate_compliance_as_code(
    assessment_id: str,
    persist_findings: bool = Query(
        False, description="Persist failed policy rules as findings"
    ),
    auto_resolve: bool = Query(
        True, description="Automatically resolve/remove findings when rules pass"
    ),
    db: Session = Depends(get_db),
) -> ComplianceAsCodeResponse:
    """Evaluate metadata profile against JSON-defined compliance rules.

    Args:
        assessment_id: Assessment to evaluate
        persist_findings: If True, create/update findings for failed rules
        auto_resolve: If True, remove findings for rules that now pass (only applies when persist_findings=True)
    """
    assessment = get_or_404(db, Assessment, assessment_id, "Assessment not found")
    metadata = get_or_404(
        db,
        MetadataProfile,
        str(assessment.metadata_profile_id),
        "Metadata profile not found",
    )

    evaluator = ComplianceAsCodeEvaluator()
    output = evaluator.evaluate(metadata)

    persisted_rule_ids: list[str] = []
    persisted_findings = 0
    resolved_findings = 0

    if persist_findings:
        failed_results = [
            result for result in output["results"] if result["status"] == "fail"
        ]
        passed_results = [
            result for result in output["results"] if result["status"] == "pass"
        ]

        # Handle failed rules: create or update findings
        for result in failed_results:
            rule_id = result["rule_id"]
            severity = result["severity_on_fail"]
            operator = result["operator"]
            expected = result["expected"]
            actual = result["actual"]

            if operator == "equals":
                comparison = "equal"
            elif operator == "gte":
                comparison = "be greater than or equal to"
            else:
                comparison = operator

            rule_description = result.get("description") or result["title"]
            failure_description = (
                f"{rule_description} Rule path '{result['path']}' expected value to {comparison} "
                f"{expected!r}, but found {actual!r}."
            )
            remediation_guidance = (
                f"Update metadata or underlying implementation so '{result['path']}' satisfies "
                f"{operator} {expected!r}. Then re-run compliance-as-code evaluation."
            )

            existing_finding = (
                db.query(Finding)
                .filter(Finding.assessment_id == str(assessment.id))
                .filter(Finding.external_id == rule_id)
                .first()
            )

            if existing_finding:
                existing_finding.control_id = result["control_id"]  # type: ignore[attr-defined]
                existing_finding.title = f"[Policy] {result['title']}"  # type: ignore[attr-defined]
                existing_finding.description = failure_description  # type: ignore[attr-defined]
                existing_finding.severity = severity  # type: ignore[attr-defined]
                existing_finding.remediation_guidance = remediation_guidance  # type: ignore[attr-defined]
                existing_finding.priority_window = PriorityWindow.IMMEDIATE if Severity.is_high_priority(severity) else PriorityWindow.THIRTY_DAYS  # type: ignore[attr-defined]
                existing_finding.owner = "Security"  # type: ignore[attr-defined]
            else:
                finding = Finding(
                    assessment_id=str(assessment.id),
                    control_id=result["control_id"],
                    title=f"[Policy] {result['title']}",
                    description=failure_description,
                    severity=severity,
                    external_id=rule_id,
                    cve_ids=[],
                    cwe_ids=[],
                    remediation_guidance=remediation_guidance,
                    priority_window=(
                        PriorityWindow.IMMEDIATE
                        if Severity.is_high_priority(severity)
                        else PriorityWindow.THIRTY_DAYS
                    ),
                    owner="Security",
                )
                db.add(finding)

            persisted_rule_ids.append(rule_id)

        # Handle passed rules: remove findings if auto_resolve is enabled
        if auto_resolve:
            for result in passed_results:
                rule_id = result["rule_id"]

                existing_finding = (
                    db.query(Finding)
                    .filter(Finding.assessment_id == str(assessment.id))
                    .filter(Finding.external_id == rule_id)
                    .first()
                )

                if existing_finding:
                    logger.info(f"Auto-resolving finding for passing rule: {rule_id}")
                    db.delete(existing_finding)
                    resolved_findings += 1

        if failed_results or resolved_findings > 0:
            db.commit()
            persisted_findings = len(failed_results)

    return ComplianceAsCodeResponse(
        assessment_id=str(assessment.id),
        metadata_profile_id=str(assessment.metadata_profile_id),
        framework=output["framework"],
        policy_version=output["policy_version"],
        evaluated_at=output["evaluated_at"],
        total_rules=output["total_rules"],
        passed=output["passed"],
        failed=output["failed"],
        persistence_enabled=persist_findings,
        persisted_findings=persisted_findings,
        persisted_rule_ids=persisted_rule_ids,
        resolved_findings=resolved_findings,
        results=output["results"],
    )


@router.get("/{assessment_id}/findings", response_model=list[FindingResponse])
def get_assessment_findings(
    assessment_id: str, db: Session = Depends(get_db)
) -> list[FindingResponse]:
    """Get findings for an assessment with threat intelligence context."""
    get_or_404(db, Assessment, assessment_id, "Assessment not found")
    findings: list[Finding] = (
        db.query(Finding).filter(Finding.assessment_id == assessment_id).all()
    )

    # Enrich each finding with MITRE ATT&CK threat context
    enriched_findings: list[FindingResponse] = []
    for finding in findings:
        control_id = _to_str(getattr(finding, "control_id", None))
        cwe_ids = _to_str_list(getattr(finding, "cwe_ids", None))
        threat_context: ThreatContext | None = None

        if cwe_ids:
            candidate_context = mitre_service.enrich_finding_with_threat_context(
                cwe_ids=cwe_ids,
                control_id=control_id,
            )
            if candidate_context and candidate_context.get("techniques"):
                threat_context = ThreatContext(**candidate_context)

        enriched_findings.append(
            FindingResponse(
                id=_to_str(getattr(finding, "id", None)),
                assessment_id=_to_str(getattr(finding, "assessment_id", None)),
                control_id=control_id,
                title=_to_str(getattr(finding, "title", None)),
                description=_to_str(getattr(finding, "description", None)),
                severity=_to_str(getattr(finding, "severity", None)),
                cvss_score=_to_float(getattr(finding, "cvss_score", None), default=0.0),
                external_id=_to_optional_str(getattr(finding, "external_id", None)),
                cve_ids=_to_str_list(getattr(finding, "cve_ids", None)),
                cwe_ids=cwe_ids,
                remediation_guidance=_to_optional_str(
                    getattr(finding, "remediation_guidance", None)
                ),
                priority_window=_to_optional_str(
                    getattr(finding, "priority_window", None)
                ),
                owner=_to_optional_str(getattr(finding, "owner", None)),
                created_at=getattr(finding, "created_at", datetime.now(UTC)),
                threat_context=threat_context,
            )
        )

    return enriched_findings


@router.get("/{assessment_id}/roadmap", response_model=RemediationRoadmapResponse)
@_rate_limited(f"{settings.rate_limit_per_minute}/minute")
def get_remediation_roadmap(
    request: Request,
    assessment_id: str,
    db: Session = Depends(get_db),
    api_key: str = Depends(get_api_key_optional),
) -> RemediationRoadmapResponse:
    """Generate prioritized remediation roadmap for an assessment."""
    # Verify assessment exists
    assessment = get_or_404(db, Assessment, assessment_id, "Assessment not found")

    # Get all findings for this assessment
    findings: list[Finding] = (
        db.query(Finding).filter(Finding.assessment_id == assessment_id).all()
    )

    # Group findings by priority window
    immediate: list[RoadmapItem] = []
    thirty_days: list[RoadmapItem] = []
    quarterly: list[RoadmapItem] = []
    annual: list[RoadmapItem] = []

    # Count by severity
    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0

    for finding in findings:
        # Create roadmap item
        item = RoadmapItem(
            finding_id=finding.id,  # type: ignore[arg-type] - SQLAlchemy Column unwraps at runtime
            control_id=finding.control_id,  # type: ignore[arg-type] - SQLAlchemy Column unwraps at runtime
            title=finding.title,  # type: ignore[arg-type] - SQLAlchemy Column unwraps at runtime
            severity=finding.severity,  # type: ignore[arg-type] - SQLAlchemy Column unwraps at runtime
            cvss_score=finding.cvss_score,  # type: ignore[arg-type] - SQLAlchemy Column unwraps at runtime
            priority_window=finding.priority_window or "quarterly",  # type: ignore[arg-type] - SQLAlchemy Column unwraps at runtime
            owner=finding.owner,  # type: ignore[arg-type] - SQLAlchemy Column unwraps at runtime
            remediation_guidance=finding.remediation_guidance or "Contact security team for guidance",  # type: ignore[arg-type] - SQLAlchemy Column unwraps at runtime
            cve_ids=finding.cve_ids or [],  # type: ignore[arg-type] - SQLAlchemy Column unwraps at runtime
            cwe_ids=finding.cwe_ids or [],  # type: ignore[arg-type] - SQLAlchemy Column unwraps at runtime
        )

        # Group by priority window
        priority = str(
            finding.priority_window or "quarterly"
        )  # Extract value from Column for conditional
        if priority == "immediate":
            immediate.append(item)
        elif priority == "30_days":
            thirty_days.append(item)
        elif priority == "quarterly":
            quarterly.append(item)
        elif priority == "annual":
            annual.append(item)
        else:
            quarterly.append(item)  # Default to quarterly

        # Count by severity
        severity = _to_str(getattr(finding, "severity", None)).lower()
        if severity == Severity.CRITICAL:
            critical_count += 1
        elif severity == Severity.HIGH:
            high_count += 1
        elif severity == Severity.MEDIUM:
            medium_count += 1
        elif severity == Severity.LOW:
            low_count += 1

    # Build summary
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

    # Build roadmap response
    roadmap = RemediationRoadmapResponse(
        assessment_id=assessment_id,
        organization_id=assessment.organization_id,  # type: ignore[arg-type] - SQLAlchemy Column unwraps at runtime
        generated_at=datetime.now(UTC),
        summary=summary,
        immediate=immediate,
        thirty_days=thirty_days,
        quarterly=quarterly,
        annual=annual,
    )

    # Audit log
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


@router.post("/{assessment_id}/analyze-nvd", response_model=list[FindingResponse])
@_rate_limited(f"{settings.rate_limit_per_minute}/minute")
def analyze_nvd_vulnerabilities(
    assessment_id: str,
    request: Request,
    db: Session = Depends(get_db),
    api_key: str = Depends(get_api_key_optional),
) -> list[Finding]:
    """Analyze software stack for known NVD vulnerabilities.

    Queries the National Vulnerability Database (NVD) for CVEs matching
    the software stack specified in the assessment's metadata profile.
    Creates findings for each discovered vulnerability.

    Rate limit: Standard (60 req/min)
    """
    # Get assessment and metadata
    assessment = get_or_404(db, Assessment, assessment_id, "Assessment not found")

    metadata_profile = _get_metadata_profile_or_404(db=db, assessment=assessment)

    # Get software stack from metadata profile
    software_stack_raw = metadata_profile.software_stack or {}  # type: ignore[attr-defined]
    software_stack: dict[str, str] = {
        str(name): str(version)
        for name, version in cast(dict[str, Any], software_stack_raw).items()
        if version is not None
    }
    if not software_stack:
        # Log and return empty (no software stack provided yet)
        log_audit_event(
            action=AuditAction.NVD_QUERY,
            request=request,
            api_key=api_key,
            resource_type="assessment",
            resource_id=assessment_id,
            details={"status": "skipped", "reason": "no_software_stack_provided"},
            level=AuditLevel.INFO,
        )
        return []

    # Initialize NVD service with optional API key from config
    nvd_service = NVDService(
        api_key=settings.nvd_api_key if settings.nvd_api_key else None
    )

    # Analyze software stack for vulnerabilities
    nvd_results = nvd_service.analyze_software_stack(software_stack)
    normalized_nvd_results: dict[str, list[dict[str, Any]]] = {
        component: [cast(dict[str, Any], cve) for cve in cves]
        for component, cves in nvd_results.items()
    }

    available_control_ids = _get_available_control_ids(db=db)
    (
        new_findings,
        total_cves_processed,
        mapped_via_cwe,
        mapped_via_fallback,
        unmapped_cves,
    ) = _build_nvd_findings(
        db=db,
        assessment_id=assessment_id,
        nvd_results=normalized_nvd_results,
        nvd_service=nvd_service,
        available_control_ids=available_control_ids,
    )
    evidence_created_count = _persist_nvd_findings_and_evidence(
        db=db,
        assessment=assessment,
        assessment_id=assessment_id,
        new_findings=new_findings,
    )

    logger.warning(
        "NVD analysis summary: findings=%s mapped_via_cwe=%s mapped_via_fallback=%s unmapped=%s evidence_created=%s",
        len(new_findings),
        mapped_via_cwe,
        mapped_via_fallback,
        unmapped_cves,
        evidence_created_count,
    )

    # Audit log
    log_audit_event(
        action=AuditAction.NVD_QUERY,
        request=request,
        api_key=api_key,
        resource_type="assessment",
        resource_id=assessment_id,
        details={
            "software_stack_components": len(software_stack),
            "cves_found": sum(len(cves) for cves in nvd_results.values()),
            "cves_processed": total_cves_processed,
            "findings_created": len(new_findings),
            "mapped_via_cwe": mapped_via_cwe,
            "mapped_via_fallback": mapped_via_fallback,
            "unmapped_cves": unmapped_cves,
            "evidence_created": evidence_created_count,
            "components_analyzed": list(nvd_results.keys()),
        },
        level=AuditLevel.INFO,
    )

    return new_findings


@router.post(
    "/{assessment_id}/analyze-dependabot", response_model=list[FindingResponse]
)
@_rate_limited(f"{settings.rate_limit_per_minute}/minute")
def analyze_dependabot_alerts(
    assessment_id: str,
    request: Request,
    db: Session = Depends(get_db),
    api_key: str = Depends(get_api_key_optional),
) -> list[Finding]:
    """Analyze GitHub Dependabot alerts as threat intelligence.

    Fetches open Dependabot alerts from the repository and creates findings
    for dependency vulnerabilities. Complements NVD analysis with GitHub's
    advisory database.

    Requires: GitHub API token in GITHUB_TOKEN environment variable
    Rate limit: Standard (60 req/min)
    """
    # Get assessment and metadata
    get_or_404(db, Assessment, assessment_id, "Assessment not found")

    # Check if GitHub token is configured
    github_token = settings.github_token if hasattr(settings, "github_token") else None
    if not github_token:
        log_audit_event(
            action=AuditAction.THREAT_INTEL_QUERY,
            request=request,
            api_key=api_key,
            resource_type="assessment",
            resource_id=assessment_id,
            details={"status": "skipped", "reason": "github_token_not_configured"},
            level=AuditLevel.WARNING,
        )
        raise HTTPException(
            status_code=400,
            detail="GitHub token not configured. Set GITHUB_TOKEN environment variable.",
        )

    # Initialize Dependabot service
    repo_owner = (
        settings.github_repo_owner
        if hasattr(settings, "github_repo_owner")
        else "catownsley"
    )
    repo_name = (
        settings.github_repo_name
        if hasattr(settings, "github_repo_name")
        else "charlottesweb-app"
    )
    dependabot = DependabotService(repo_owner, repo_name, github_token)

    # Fetch open Dependabot alerts
    dependabot_alerts = dependabot.get_alerts(state="open", ecosystem="pip")

    if not dependabot_alerts:
        log_audit_event(
            action=AuditAction.THREAT_INTEL_QUERY,
            request=request,
            api_key=api_key,
            resource_type="assessment",
            resource_id=assessment_id,
            details={"status": "completed", "alerts_found": 0},
            level=AuditLevel.INFO,
        )
        return []

    available_control_ids = _get_available_control_ids(db=db)
    nvd_service = NVDService()
    new_findings, mapped_via_cwe, unmapped_alerts = _build_dependabot_findings(
        db=db,
        assessment_id=assessment_id,
        alerts=dependabot_alerts,
        nvd_service=nvd_service,
        available_control_ids=available_control_ids,
    )

    # Commit all findings
    if new_findings:
        db.commit()

    # Audit log
    log_audit_event(
        action=AuditAction.THREAT_INTEL_QUERY,
        request=request,
        api_key=api_key,
        resource_type="assessment",
        resource_id=assessment_id,
        details={
            "source": "dependabot",
            "alerts_found": len(dependabot_alerts),
            "findings_created": len(new_findings),
            "mapped_via_cwe": mapped_via_cwe,
            "unmapped_alerts": unmapped_alerts,
        },
        level=AuditLevel.INFO,
    )

    return new_findings


@router.get(
    "/{assessment_id}/evidence-checklist", response_model=EvidenceChecklistResponse
)
def generate_evidence_checklist(
    assessment_id: str,
    db: Session = Depends(get_db),
) -> EvidenceChecklistResponse:
    """Generate evidence checklist for an assessment."""
    from src.models import Evidence

    # Verify assessment exists
    assessment = get_or_404(db, Assessment, assessment_id, "Assessment not found")

    # Get all findings for this assessment
    findings: list[Finding] = (
        db.query(Finding)
        .filter(Finding.assessment_id == assessment_id)
        .filter(Finding.control_id.isnot(None))
        .all()
    )

    # Get unique control IDs from findings
    control_ids = [
        control_id
        for control_id in {
            _to_str(getattr(finding, "control_id", None)) for finding in findings
        }
        if control_id
    ]

    # Get controls with evidence requirements
    controls: list[Control] = (
        db.query(Control)
        .filter(Control.id.in_(control_ids))
        .filter(Control.evidence_types.isnot(None))
        .all()
    )

    # Get existing evidence for these controls, scoped to the organization
    # This allows evidence to persist across assessments for the same org
    existing_evidence: list[Evidence] = (
        db.query(Evidence)
        .join(Assessment, Evidence.assessment_id == Assessment.id)
        .filter(
            Assessment.organization_id == assessment.organization_id,
            Evidence.control_id.in_(control_ids),
        )
        .all()
    )

    # Also get evidence not linked to any assessment but matching controls
    orphan_evidence: list[Evidence] = (
        db.query(Evidence)
        .filter(
            Evidence.assessment_id.is_(None),
            Evidence.control_id.in_(control_ids),
        )
        .all()
    )

    # Merge both lists
    all_evidence = existing_evidence + orphan_evidence

    # Create a map of (control_id, evidence_type) -> evidence
    # Prefer most recently updated evidence for each (control, type) combo
    evidence_map: dict[tuple[str, str], Evidence] = {}
    for ev in sorted(
        all_evidence, key=lambda e: getattr(e, "updated_at", datetime.min)
    ):
        evidence_map[
            (
                _to_str(getattr(ev, "control_id", None)),
                _to_str(getattr(ev, "evidence_type", None)),
            )
        ] = ev

    # Generate checklist items
    checklist_items: list[EvidenceChecklistItem] = []
    for control in controls:
        evidence_types = _to_str_list(getattr(control, "evidence_types", None))
        if not evidence_types:
            continue

        control_id = _to_str(getattr(control, "id", None))
        control_title = _to_str(getattr(control, "title", None))

        for evidence_type in evidence_types:
            evidence = evidence_map.get((control_id, evidence_type))

            item = EvidenceChecklistItem(
                control_id=control_id,
                control_title=control_title,
                evidence_type=evidence_type,
                required_evidence=evidence_type.replace("_", " ").title(),
                status=(
                    _to_str(getattr(evidence, "status", None), default="not_started")
                    if evidence
                    else "not_started"
                ),
                owner=(
                    _to_optional_str(getattr(evidence, "owner", None))
                    if evidence
                    else None
                ),
                due_date=getattr(evidence, "due_date", None) if evidence else None,
                collected_at=(
                    getattr(evidence, "collected_at", None) if evidence else None
                ),
                notes=(
                    _to_optional_str(getattr(evidence, "notes", None))
                    if evidence
                    else None
                ),
                evidence_id=(
                    _to_optional_str(getattr(evidence, "id", None))
                    if evidence
                    else None
                ),
            )
            checklist_items.append(item)

    # Calculate statistics
    total_items = len(checklist_items)
    completed = sum(1 for item in checklist_items if item.status == "completed")
    in_progress = sum(1 for item in checklist_items if item.status == "in_progress")
    not_started = sum(1 for item in checklist_items if item.status == "not_started")

    return EvidenceChecklistResponse(
        assessment_id=assessment_id,
        organization_id=_to_str(getattr(assessment, "organization_id", None)),
        generated_at=datetime.now(UTC).replace(tzinfo=None),
        total_items=total_items,
        completed=completed,
        in_progress=in_progress,
        not_started=not_started,
        items=checklist_items,
    )
