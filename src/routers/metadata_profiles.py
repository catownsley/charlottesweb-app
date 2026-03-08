"""Metadata profile management endpoints."""
import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from src.audit import AuditAction, log_audit_event
from src.config import settings
from src.database import get_db, get_or_404
from src.middleware import get_api_key_optional, limiter
from src.models import MetadataProfile, Organization
from src.schemas import MetadataProfileCreate, MetadataProfileResponse

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/metadata-profiles", tags=["metadata-profiles"])


@router.post("", response_model=MetadataProfileResponse, status_code=201)
@limiter.limit(f"{settings.rate_limit_per_minute}/minute")
def create_metadata_profile(
    request: Request,
    profile_data: MetadataProfileCreate,
    db: Session = Depends(get_db),
    api_key: str = Depends(get_api_key_optional),
) -> MetadataProfile:
    """Create a new metadata profile."""
    # Verify organization exists
    get_or_404(db, Organization, profile_data.organization_id, "Organization not found")

    profile = MetadataProfile(
        organization_id=profile_data.organization_id,
        phi_types=profile_data.phi_types,
        cloud_provider=profile_data.cloud_provider,
        infrastructure=profile_data.infrastructure,
        applications=profile_data.applications,
        access_controls=profile_data.access_controls,
        software_stack=profile_data.software_stack,
    )

    try:
        db.add(profile)
        db.commit()
        db.refresh(profile)
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to create metadata profile: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="Failed to create metadata profile. Please try again."
        ) from e

    # Audit log
    log_audit_event(
        action=AuditAction.DATA_CREATED,
        request=request,
        api_key=api_key,
        resource_type="metadata_profile",
        resource_id=profile.id,  # type: ignore[arg-type] - SQLAlchemy Column unwraps at runtime
        details={"organization_id": profile.organization_id},
    )

    return profile


@router.get("/{profile_id}", response_model=MetadataProfileResponse)
@limiter.limit(f"{settings.rate_limit_per_minute}/minute")
def get_metadata_profile(request: Request, profile_id: str, db: Session = Depends(get_db)) -> MetadataProfile:
    """Get metadata profile by ID."""
    profile = get_or_404(db, MetadataProfile, profile_id, "Metadata profile not found")
    return profile
