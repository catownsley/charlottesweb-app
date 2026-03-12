"""Assessment CRUD, compliance intelligence, and evidence checklist endpoints."""

import logging
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, TypeVar, cast

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from src.audit import AuditAction, log_audit_event
from src.compliance_intelligence import ComplianceIntelligenceEvaluator
from src.config import settings
from src.constants import AssessmentStatus, PriorityWindow, Severity
from src.database import get_db, get_or_404
from src.middleware import get_api_key_optional, limiter
from src.models import (
    Assessment,
    Control,
    Evidence,
    Finding,
    MetadataProfile,
    Organization,
)
from src.rules_engine import RulesEngine
from src.schemas import (
    AssessmentCreate,
    AssessmentResponse,
    AssessmentStatusResponse,
    ComplianceIntelligenceResponse,
    EvidenceChecklistItem,
    EvidenceChecklistResponse,
)
from src.utils import to_optional_str, to_str, to_str_list

router = APIRouter(prefix="/assessments", tags=["assessments"])
logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., object])


def _rate_limited(limit_value: str) -> Callable[[F], F]:
    limiter_any = cast(Any, limiter)
    return cast(Callable[[F], F], limiter_any.limit(limit_value))


# ---------------------------------------------------------------------------
# Assessment CRUD
# ---------------------------------------------------------------------------


@router.post("", response_model=AssessmentResponse, status_code=201)
@_rate_limited(f"{settings.rate_limit_per_minute}/minute")
def create_assessment(
    request: Request,
    assessment_data: AssessmentCreate,
    db: Session = Depends(get_db),
    api_key: str = Depends(get_api_key_optional),
) -> Assessment:
    """Create and run a new assessment."""
    get_or_404(
        db, Organization, assessment_data.organization_id, "Organization not found"
    )
    get_or_404(
        db,
        MetadataProfile,
        assessment_data.metadata_profile_id,
        "Metadata profile not found",
    )

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
        logger.error("Failed to create assessment: %s", e, exc_info=True)
        raise HTTPException(
            status_code=500, detail="Failed to create assessment. Please try again."
        ) from e

    log_audit_event(
        action=AuditAction.ASSESSMENT_CREATED,
        request=request,
        api_key=api_key,
        resource_type="assessment",
        resource_id=assessment.id,
        details={"organization_id": assessment.organization_id},
    )

    try:
        engine = RulesEngine(db)
        findings = engine.run_assessment(assessment.id)

        for finding in findings:
            db.add(finding)

        assessment.status = AssessmentStatus.COMPLETED
        assessment.completed_at = datetime.now(UTC)
        db.commit()

        log_audit_event(
            action=AuditAction.ASSESSMENT_RUN,
            request=request,
            api_key=api_key,
            resource_type="assessment",
            resource_id=assessment.id,
            details={"findings_count": len(findings), "status": "completed"},
        )

    except Exception as e:
        assessment.status = AssessmentStatus.FAILED
        try:
            db.commit()
        except Exception as commit_error:
            logger.warning(
                "Failed to commit assessment failure status: %s", commit_error
            )
            db.rollback()

        logger.error("Assessment failed: %s", e, exc_info=True)
        log_audit_event(
            action=AuditAction.ERROR,
            request=request,
            api_key=api_key,
            resource_type="assessment",
            resource_id=assessment.id,
            success=False,
            details={"status": "failed"},
        )
        raise HTTPException(
            status_code=500,
            detail="Assessment execution failed. Please try again or contact support.",
        ) from e

    db.refresh(assessment)
    return assessment


@router.get("/{assessment_id}", response_model=AssessmentResponse)
def get_assessment(assessment_id: str, db: Session = Depends(get_db)) -> Assessment:
    """Get assessment by ID."""
    return get_or_404(db, Assessment, assessment_id, "Assessment not found")


@router.get("/{assessment_id}/status", response_model=AssessmentStatusResponse)
def get_assessment_status(
    assessment_id: str,
    db: Session = Depends(get_db),
) -> AssessmentStatusResponse:
    """Get assessment run status with coarse-grained progress for UI workflows."""
    assessment = get_or_404(db, Assessment, assessment_id, "Assessment not found")

    findings_count = (
        db.query(Finding).filter(Finding.assessment_id == assessment_id).count()
    )

    status = to_str(getattr(assessment, "status", None), default="pending")
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


# ---------------------------------------------------------------------------
# Compliance Intelligence
# ---------------------------------------------------------------------------


@router.get(
    "/{assessment_id}/compliance-intelligence",
    response_model=ComplianceIntelligenceResponse,
)
def evaluate_compliance_intelligence(
    assessment_id: str,
    persist_findings: bool = Query(
        False, description="Persist failed policy rules as findings"
    ),
    auto_resolve: bool = Query(
        True, description="Automatically resolve/remove findings when rules pass"
    ),
    db: Session = Depends(get_db),
) -> ComplianceIntelligenceResponse:
    """Evaluate metadata profile against JSON-defined compliance rules."""
    assessment = get_or_404(db, Assessment, assessment_id, "Assessment not found")
    metadata = get_or_404(
        db,
        MetadataProfile,
        str(assessment.metadata_profile_id),
        "Metadata profile not found",
    )

    evaluator = ComplianceIntelligenceEvaluator()
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
                f"{operator} {expected!r}. Then re-run compliance intelligence evaluation."
            )

            existing_finding = (
                db.query(Finding)
                .filter(Finding.assessment_id == str(assessment.id))
                .filter(Finding.external_id == rule_id)
                .first()
            )

            if existing_finding:
                existing_finding.control_id = result["control_id"]
                existing_finding.title = f"[Policy] {result['title']}"
                existing_finding.description = failure_description
                existing_finding.severity = severity
                existing_finding.remediation_guidance = remediation_guidance
                existing_finding.priority_window = (
                    PriorityWindow.IMMEDIATE
                    if Severity.is_high_priority(severity)
                    else PriorityWindow.THIRTY_DAYS
                )
                existing_finding.owner = "Security"
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
                    logger.info("Auto-resolving finding for passing rule: %s", rule_id)
                    db.delete(existing_finding)
                    resolved_findings += 1

        if failed_results or resolved_findings > 0:
            db.commit()
            persisted_findings = len(failed_results)

    return ComplianceIntelligenceResponse(
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


# ---------------------------------------------------------------------------
# Evidence Checklist
# ---------------------------------------------------------------------------


def _status_rank(status: str) -> int:
    rank = {
        "completed": 4,
        "not_applicable": 3,
        "in_progress": 2,
        "not_started": 1,
    }
    return rank.get(status, 0)


def _evidence_rank(evidence: Evidence) -> tuple[int, int, int, int, float]:
    status_value = to_str(getattr(evidence, "status", None), default="not_started")
    notes_value = to_optional_str(getattr(evidence, "notes", None))
    owner_value = to_optional_str(getattr(evidence, "owner", None))
    updated_at = getattr(evidence, "updated_at", None)
    updated_at_ts = updated_at.timestamp() if isinstance(updated_at, datetime) else 0.0

    return (
        _status_rank(status_value),
        1 if getattr(evidence, "collected_at", None) else 0,
        1 if notes_value else 0,
        1 if owner_value else 0,
        updated_at_ts,
    )


@router.get(
    "/{assessment_id}/evidence-checklist", response_model=EvidenceChecklistResponse
)
def generate_evidence_checklist(
    assessment_id: str,
    db: Session = Depends(get_db),
) -> EvidenceChecklistResponse:
    """Generate evidence checklist for an assessment.

    Shows ALL controls with evidence requirements, not just ones with findings.
    Automatically creates evidence records so everything can be tracked.
    """
    assessment = get_or_404(db, Assessment, assessment_id, "Assessment not found")

    controls: list[Control] = (
        db.query(Control).filter(Control.evidence_types.isnot(None)).all()
    )

    control_ids = [to_str(getattr(control, "id", None)) for control in controls]

    existing_evidence: list[Evidence] = (
        db.query(Evidence)
        .join(Assessment, Evidence.assessment_id == Assessment.id)
        .filter(
            Assessment.organization_id == assessment.organization_id,
            Evidence.control_id.in_(control_ids),
        )
        .all()
    )

    evidence_map: dict[tuple[str, str], Evidence] = {}
    for evidence_item in existing_evidence:
        map_key = (
            to_str(getattr(evidence_item, "control_id", None)),
            to_str(getattr(evidence_item, "evidence_type", None)),
        )
        current_best = evidence_map.get(map_key)
        if current_best is None or _evidence_rank(evidence_item) > _evidence_rank(
            current_best
        ):
            evidence_map[map_key] = evidence_item

    new_evidence_records: list[Evidence] = []

    for control in controls:
        evidence_types = to_str_list(getattr(control, "evidence_types", None))
        if not evidence_types:
            continue

        control_id = to_str(getattr(control, "id", None))
        control_title = to_str(getattr(control, "title", None))

        for evidence_type in evidence_types:
            evidence = evidence_map.get((control_id, evidence_type))

            if evidence is None:
                new_evidence = Evidence(
                    assessment_id=assessment_id,
                    control_id=control_id,
                    evidence_type=evidence_type,
                    title=f"{control_id}: {evidence_type}",
                    description=f"Evidence for {control_title}",
                    status="not_started",
                    owner="system",
                )
                db.add(new_evidence)
                new_evidence_records.append(new_evidence)
                evidence_map[(control_id, evidence_type)] = new_evidence

    if new_evidence_records:
        try:
            db.commit()
            for new_ev in new_evidence_records:
                db.refresh(new_ev)
        except Exception as e:
            db.rollback()
            logger.error("Failed to create evidence records: %s", e, exc_info=True)

    checklist_items: list[EvidenceChecklistItem] = []
    for control in controls:
        evidence_types = to_str_list(getattr(control, "evidence_types", None))
        if not evidence_types:
            continue

        control_id = to_str(getattr(control, "id", None))
        control_title = to_str(getattr(control, "title", None))

        for evidence_type in evidence_types:
            evidence = evidence_map.get((control_id, evidence_type))

            item = EvidenceChecklistItem(
                control_id=control_id,
                control_title=control_title,
                evidence_type=evidence_type,
                required_evidence=evidence_type.replace("_", " ").title(),
                status=to_str(getattr(evidence, "status", None), default="not_started"),
                owner=to_optional_str(getattr(evidence, "owner", None)),
                due_date=getattr(evidence, "due_date", None),
                collected_at=getattr(evidence, "collected_at", None),
                notes=to_optional_str(getattr(evidence, "notes", None)),
                evidence_id=to_optional_str(getattr(evidence, "id", None)),
            )
            checklist_items.append(item)

    total_items = len(checklist_items)
    completed = sum(1 for item in checklist_items if item.status == "completed")
    in_progress = sum(1 for item in checklist_items if item.status == "in_progress")
    not_started = sum(1 for item in checklist_items if item.status == "not_started")

    return EvidenceChecklistResponse(
        assessment_id=assessment_id,
        organization_id=to_str(getattr(assessment, "organization_id", None)),
        generated_at=datetime.now(UTC).replace(tzinfo=None),
        total_items=total_items,
        completed=completed,
        in_progress=in_progress,
        not_started=not_started,
        items=checklist_items,
    )
