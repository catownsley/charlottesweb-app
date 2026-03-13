"""Organization management endpoints.

Provides CRUD operations for organizations. The DELETE endpoint supports
data sovereignty requirements — customers can remove all their data from
the system after completing their analysis.

Security:
- All endpoints are rate-limited and audit-logged.
- Delete cascades through ORM relationships (members, profiles, assessments,
  findings) and explicitly removes evidence records (direct FK, not covered
  by ORM cascade).
- No organization data is retained after deletion.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func
from sqlalchemy.orm import Session

from src.audit import AuditAction, log_audit_event
from src.config import settings
from src.database import get_db, get_or_404
from src.middleware import get_api_key_optional, limiter
from src.models import CacheEntry, Evidence, Organization, OrganizationMember
from src.schemas import (
    OrganizationCreate,
    OrganizationOnboardingCreate,
    OrganizationOnboardingResponse,
    OrganizationResponse,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/organizations", tags=["organizations"])


@router.get("", response_model=list[OrganizationResponse])
@limiter.limit(f"{settings.rate_limit_per_minute}/minute")
def list_organizations(
    request: Request,
    name: str | None = Query(default=None, min_length=1),
    db: Session = Depends(get_db),
    api_key: str = Depends(get_api_key_optional),
) -> list[Organization]:
    """List organizations, optionally filtering by exact name (case-insensitive)."""
    query = db.query(Organization)
    if name:
        normalized_name = name.strip().lower()
        query = query.filter(func.lower(Organization.name) == normalized_name)

    orgs: list[Organization] = query.order_by(Organization.created_at.desc()).all()

    log_audit_event(
        action=AuditAction.DATA_READ,
        request=request,
        api_key=api_key,
        resource_type="organization",
        details={"count": len(orgs), "filtered_by_name": bool(name)},
    )

    return orgs


@router.post("", response_model=OrganizationResponse, status_code=201)
@limiter.limit(f"{settings.rate_limit_per_minute}/minute")
def create_organization(
    request: Request,
    org_data: OrganizationCreate,
    db: Session = Depends(get_db),
    api_key: str = Depends(get_api_key_optional),
) -> Organization:
    """Create a new organization."""
    try:
        org = Organization(
            name=org_data.name,
            industry=org_data.industry,
            stage=org_data.stage,
        )
        db.add(org)
        db.commit()
        db.refresh(org)
    except Exception as e:
        db.rollback()
        # Log actual error server-side
        logger.error("Failed to create organization: %s", e, exc_info=True)
        # Return safe error message to client
        raise HTTPException(
            status_code=500,
            detail="Failed to create organization. Please ensure the application has write access and try again.",
        ) from e

    # Audit log
    log_audit_event(
        action=AuditAction.ORG_CREATED,
        request=request,
        api_key=api_key,
        resource_type="organization",
        resource_id=org.id,
        details={"name": org.name, "industry": org.industry},
    )

    return org


@router.post("/onboard", response_model=OrganizationOnboardingResponse, status_code=201)
@limiter.limit(f"{settings.rate_limit_per_minute}/minute")
def onboard_organization(
    request: Request,
    onboarding_data: OrganizationOnboardingCreate,
    db: Session = Depends(get_db),
    api_key: str = Depends(get_api_key_optional),
) -> OrganizationOnboardingResponse:
    """Create a new organization and first member in a single onboarding flow."""
    try:
        org = Organization(
            name=onboarding_data.name,
            industry=onboarding_data.industry,
            stage=onboarding_data.stage,
        )
        db.add(org)
        db.flush()

        member = OrganizationMember(
            organization_id=org.id,
            email=onboarding_data.admin_email,
            full_name=onboarding_data.admin_name,
            role=onboarding_data.admin_role,
        )
        db.add(member)
        db.commit()
        db.refresh(org)
        db.refresh(member)
    except Exception as e:
        db.rollback()
        logger.error("Failed to onboard organization: %s", e, exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="Failed to onboard organization. Please ensure the application has write access and try again.",
        ) from e

    log_audit_event(
        action=AuditAction.ORG_CREATED,
        request=request,
        api_key=api_key,
        resource_type="organization",
        resource_id=org.id,
        details={
            "name": org.name,
            "industry": org.industry,
            "onboarding": True,
            "member_email": member.email,
            "member_role": member.role,
        },
    )

    return OrganizationOnboardingResponse(organization=org, member=member)


@router.get("/{org_id}", response_model=OrganizationResponse)
@limiter.limit(f"{settings.rate_limit_per_minute}/minute")
def get_organization(
    request: Request,
    org_id: str,
    db: Session = Depends(get_db),
    api_key: str = Depends(get_api_key_optional),
) -> Organization:
    """Get organization by ID."""
    org = get_or_404(db, Organization, org_id, "Organization not found")

    # Audit log
    log_audit_event(
        action=AuditAction.DATA_READ,
        request=request,
        api_key=api_key,
        resource_type="organization",
        resource_id=org.id,
    )

    return org


@router.delete("/{org_id}", status_code=200)
@limiter.limit(f"{settings.rate_limit_per_minute}/minute")
def delete_organization(
    request: Request,
    org_id: str,
    db: Session = Depends(get_db),
    api_key: str = Depends(get_api_key_optional),
) -> dict[str, str]:
    """Delete an organization and all associated data (data sovereignty).

    This is a complete data removal — after deletion, no organization data
    remains in the system. Intended for customers who have completed their
    analysis and want their data purged.

    Cascade order:
      1. Evidence records (direct FK to organizations, not ORM-cascaded)
      2. Cached AI threat models and NVD results for this org
      3. Organization + ORM-cascaded children (members, profiles, assessments, findings)
    """
    org = get_or_404(db, Organization, org_id, "Organization not found")
    org_name = org.name

    try:
        # Evidence has a direct FK to organizations (not covered by ORM cascade)
        db.query(Evidence).filter(Evidence.organization_id == org_id).delete()

        # Purge cached AI threat models / NVD results for this org so no
        # stale data lingers after the org is removed.
        db.query(CacheEntry).filter(CacheEntry.key.contains(org_id)).delete(
            synchronize_session="fetch"
        )

        db.delete(org)
        db.commit()
    except Exception as e:
        db.rollback()
        logger.error("Failed to delete organization %s: %s", org_id, e, exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="Failed to delete organization. Please try again.",
        ) from e

    log_audit_event(
        action=AuditAction.ORG_DELETED,
        request=request,
        api_key=api_key,
        resource_type="organization",
        resource_id=org_id,
        details={"name": org_name},
    )

    return {"detail": f"Organization '{org_name}' and all associated data deleted."}
