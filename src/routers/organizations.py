"""Organization management endpoints."""
from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from src.audit import AuditAction, log_audit_event
from src.config import settings
from src.database import get_db, get_or_404
from src.middleware import get_api_key_optional, limiter
from src.models import Organization
from src.schemas import OrganizationCreate, OrganizationResponse

router = APIRouter(prefix="/organizations", tags=["organizations"])


@router.post("", response_model=OrganizationResponse, status_code=201)
@limiter.limit(f"{settings.rate_limit_per_minute}/minute")
def create_organization(
    request: Request,
    org_data: OrganizationCreate,
    db: Session = Depends(get_db),
    api_key: str = Depends(get_api_key_optional),
) -> Organization:
    """Create a new organization."""
    org = Organization(
        name=org_data.name,
        industry=org_data.industry,
        stage=org_data.stage,
    )
    db.add(org)
    db.commit()
    db.refresh(org)

    # Audit log
    log_audit_event(
        action=AuditAction.ORG_CREATED,
        request=request,
        api_key=api_key,
        resource_type="organization",
        resource_id=org.id,  # type: ignore[arg-type] - SQLAlchemy Column unwraps at runtime
        details={"name": org.name, "industry": org.industry},
    )

    return org


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
        resource_id=org.id,  # type: ignore[arg-type] - SQLAlchemy Column unwraps at runtime
    )

    return org
