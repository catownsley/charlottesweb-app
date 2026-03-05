"""Evidence collection and management endpoints."""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from src.audit import AuditAction, log_audit_event
from src.config import settings
from src.database import get_db, get_or_404
from src.middleware import get_api_key_optional, limiter
from src.models import Assessment, Control, Evidence
from src.schemas import EvidenceCreate, EvidenceResponse, EvidenceUpdate

router = APIRouter(prefix="/evidence", tags=["evidence"])


@router.post("", response_model=EvidenceResponse, status_code=201)
@limiter.limit(f"{settings.rate_limit_per_minute}/minute")
def create_evidence(
    request: Request,
    evidence_data: EvidenceCreate,
    db: Session = Depends(get_db),
    api_key: str = Depends(get_api_key_optional),
) -> Evidence:
    """Create a new evidence item."""
    # Verify control exists
    control = get_or_404(db, Control, evidence_data.control_id, "Control not found")

    # Verify assessment exists if provided
    if evidence_data.assessment_id:
        assessment = get_or_404(db, Assessment, evidence_data.assessment_id, "Assessment not found")

    evidence = Evidence(
        control_id=evidence_data.control_id,
        assessment_id=evidence_data.assessment_id,
        evidence_type=evidence_data.evidence_type,
        title=evidence_data.title,
        description=evidence_data.description,
        owner=evidence_data.owner,
        due_date=evidence_data.due_date,
    )
    db.add(evidence)
    db.commit()
    db.refresh(evidence)

    # Audit log
    log_audit_event(
        action=AuditAction.DATA_CREATE,
        request=request,
        api_key=api_key,
        resource_type="evidence",
        resource_id=evidence.id,  # type: ignore[arg-type]
        details={"control_id": evidence.control_id, "evidence_type": evidence.evidence_type},
    )

    return evidence


@router.get("/{evidence_id}", response_model=EvidenceResponse)
def get_evidence(evidence_id: str, db: Session = Depends(get_db)) -> Evidence:
    """Get evidence by ID."""
    evidence = get_or_404(db, Evidence, evidence_id, "Evidence not found")
    return evidence


@router.patch("/{evidence_id}", response_model=EvidenceResponse)
@limiter.limit(f"{settings.rate_limit_per_minute}/minute")
def update_evidence(
    request: Request,
    evidence_id: str,
    evidence_update: EvidenceUpdate,
    db: Session = Depends(get_db),
    api_key: str = Depends(get_api_key_optional),
) -> Evidence:
    """Update evidence item."""
    evidence = get_or_404(db, Evidence, evidence_id, "Evidence not found")

    # Update fields
    update_data = evidence_update.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(evidence, field, value)

    if evidence_update.artifact_path or evidence_update.artifact_url:
        evidence.uploaded_at = datetime.now(timezone.utc).replace(tzinfo=None)

    db.commit()
    db.refresh(evidence)

    # Audit log
    log_audit_event(
        action=AuditAction.DATA_UPDATE,
        request=request,
        api_key=api_key,
        resource_type="evidence",
        resource_id=evidence.id,  # type: ignore[arg-type]
        details={"updated_fields": list(update_data.keys())},
    )

    return evidence
