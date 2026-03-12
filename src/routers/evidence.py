"""Evidence collection and management endpoints."""

import logging
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from src.audit import AuditAction, log_audit_event
from src.config import settings
from src.database import get_db, get_or_404
from src.middleware import get_api_key_optional, limiter
from src.models import Assessment, Control, Evidence
from src.schemas import (
    EvidenceAttachUrlRequest,
    EvidenceCreate,
    EvidenceResponse,
    EvidenceUpdate,
)
from src.utils import sanitize_text, sanitize_url

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/evidence", tags=["evidence"])

# ---------------------------------------------------------------------------
# FUTURE: File Upload Support
# ---------------------------------------------------------------------------
# When file uploads are enabled, add a multipart/form-data endpoint.
# Security requirements that MUST be implemented before enabling:
#
# import hashlib
# import uuid
# from pathlib import Path
#
# ALLOWED_EXTENSIONS = {".pdf", ".png", ".jpg", ".jpeg", ".docx", ".xlsx", ".csv", ".txt", ".log"}
# MAX_FILE_SIZE_BYTES = 25 * 1024 * 1024  # 25 MB
#
# def _generate_safe_filename(original_filename: str, org_slug: str) -> str:
#     """Generate randomized filename to prevent path traversal and enumeration.
#
#     NEVER use the original filename for storage — it may contain:
#     - Path traversal sequences (../../etc/passwd)
#     - Script injection (<script>alert(1)</script>.pdf)
#     - Null bytes (file.pdf%00.exe)
#     - Unicode tricks (file\u202e.pdf → renders as fdp.elif)
#     """
#     from src.utils import sanitize_filename
#     sanitize_filename(original_filename)  # validate but don't use
#     ext = Path(original_filename).suffix.lower()
#     if ext not in ALLOWED_EXTENSIONS:
#         raise HTTPException(status_code=400, detail=f"File type '{ext}' not allowed")
#     random_name = uuid.uuid4().hex
#     return f"{org_slug}/{random_name}{ext}"
#
# def _validate_file_size(content_length: int) -> None:
#     """Reject oversized uploads before reading the full body."""
#     if content_length > MAX_FILE_SIZE_BYTES:
#         raise HTTPException(status_code=413, detail="File exceeds 25 MB limit")
#
# async def _scan_for_viruses(file_bytes: bytes) -> bool:
#     """Scan uploaded file for malware.
#
#     Integrate one of:
#     - ClamAV (open-source, self-hosted):
#         import clamd
#         cd = clamd.ClamdUnixSocket()
#         result = cd.instream(io.BytesIO(file_bytes))
#         return result['stream'][0] == 'OK'
#     - AWS: Submit to S3 with server-side scanning via GuardDuty
#     - Google Cloud: Use Cloud DLP or VirusTotal API
#     """
#     raise NotImplementedError("Virus scanning must be configured before enabling uploads")
#
# def _validate_content_type(file_bytes: bytes, claimed_extension: str) -> None:
#     """Verify file magic bytes match the claimed extension.
#
#     Prevents uploading an executable renamed to .pdf.
#     """
#     import mimetypes
#     # Use python-magic for robust detection:
#     # import magic
#     # detected = magic.from_buffer(file_bytes[:2048], mime=True)
#     # expected = mimetypes.types_map.get(claimed_extension)
#     # if detected != expected:
#     #     raise HTTPException(status_code=400, detail="File content does not match extension")
#     pass
#
# S3 upload example:
# import boto3
# s3 = boto3.client("s3")
# bucket = settings.s3_evidence_bucket  # Add to config.py
# key = _generate_safe_filename(file.filename, org_slug)
# s3.upload_fileobj(file.file, bucket, key, ExtraArgs={
#     "ContentType": file.content_type,
#     "ServerSideEncryption": "aws:kms",
# })
# artifact_path = f"s3://{bucket}/{key}"
# artifact_hash = hashlib.sha256(file_bytes).hexdigest()
# ---------------------------------------------------------------------------


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
    get_or_404(db, Control, evidence_data.control_id, "Control not found")

    # Verify assessment exists if provided
    if evidence_data.assessment_id:
        get_or_404(db, Assessment, evidence_data.assessment_id, "Assessment not found")

    evidence = Evidence(
        control_id=evidence_data.control_id,
        assessment_id=evidence_data.assessment_id,
        evidence_type=evidence_data.evidence_type,
        title=evidence_data.title,
        description=evidence_data.description,
        owner=evidence_data.owner,
        due_date=evidence_data.due_date,
    )

    try:
        db.add(evidence)
        db.commit()
        db.refresh(evidence)
    except Exception as e:
        db.rollback()
        logger.error("Failed to create evidence: %s", e, exc_info=True)
        raise HTTPException(
            status_code=500, detail="Failed to create evidence item. Please try again."
        ) from e

    # Audit log
    log_audit_event(
        action=AuditAction.DATA_CREATED,
        request=request,
        api_key=api_key,
        resource_type="evidence",
        resource_id=evidence.id,
        details={
            "control_id": evidence.control_id,
            "evidence_type": evidence.evidence_type,
        },
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

    # Validate URL if provided
    if evidence_update.artifact_url:
        try:
            evidence_update.artifact_url = sanitize_url(evidence_update.artifact_url)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    # Sanitize free-text fields
    if evidence_update.notes:
        try:
            evidence_update.notes = sanitize_text(evidence_update.notes)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    if evidence_update.artifact_path or evidence_update.artifact_url:
        evidence.uploaded_at = datetime.now(UTC).replace(tzinfo=None)

    db.commit()
    db.refresh(evidence)

    # Audit log
    log_audit_event(
        action=AuditAction.DATA_UPDATED,
        request=request,
        api_key=api_key,
        resource_type="evidence",
        resource_id=evidence.id,
        details={"updated_fields": list(update_data.keys())},
    )

    return evidence


@router.post("/{evidence_id}/attach", response_model=EvidenceResponse)
@limiter.limit(f"{settings.rate_limit_per_minute}/minute")
def attach_evidence_url(
    request: Request,
    evidence_id: str,
    attach_data: EvidenceAttachUrlRequest,
    db: Session = Depends(get_db),
    api_key: str = Depends(get_api_key_optional),
) -> Evidence:
    """Attach a URL as evidence for an action plan item.

    Accepts only validated http/https URLs. File uploads are not yet supported;
    see the commented scaffolding at the top of this module for the security
    requirements that must be met before enabling them.
    """
    evidence = get_or_404(db, Evidence, evidence_id, "Evidence not found")

    # Validate and sanitize the URL
    try:
        clean_url = sanitize_url(attach_data.artifact_url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # Sanitize description if provided
    clean_description: str | None = None
    if attach_data.description:
        try:
            clean_description = sanitize_text(attach_data.description, max_length=1000)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    evidence.artifact_url = clean_url
    if clean_description:
        evidence.description = clean_description
    evidence.uploaded_at = datetime.now(UTC).replace(tzinfo=None)

    # Auto-advance status from not_started
    if str(getattr(evidence, "status", "not_started")) == "not_started":
        evidence.status = "in_progress"

    try:
        db.commit()
        db.refresh(evidence)
    except Exception as e:
        db.rollback()
        logger.error("Failed to attach evidence URL: %s", e, exc_info=True)
        raise HTTPException(
            status_code=500, detail="Failed to attach evidence. Please try again."
        ) from e

    log_audit_event(
        action=AuditAction.DATA_UPDATED,
        request=request,
        api_key=api_key,
        resource_type="evidence",
        resource_id=evidence.id,
        details={
            "action": "attach_url",
            "artifact_url_domain": (
                clean_url.split("/")[2] if "/" in clean_url else "unknown"
            ),
        },
    )

    return evidence
