"""Regulatory framework listing and cross-framework coverage endpoints."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from src.database import get_db
from src.models import Control, Framework, FrameworkRequirement
from src.schemas import FrameworkRequirementResponse, FrameworkResponse
from src.utils import to_str

router = APIRouter(prefix="/frameworks", tags=["frameworks"])


@router.get("", response_model=list[FrameworkResponse])
def list_frameworks(
    db: Session = Depends(get_db),
) -> list[Framework]:
    """List all supported regulatory frameworks."""
    return db.query(Framework).order_by(Framework.name).all()


@router.get("/{code}", response_model=FrameworkResponse)
def get_framework(
    code: str,
    db: Session = Depends(get_db),
) -> Framework:
    """Get a specific framework by code."""
    framework = db.query(Framework).filter(Framework.code == code).first()
    if not framework:
        raise HTTPException(status_code=404, detail="Framework not found")
    return framework


@router.get("/{code}/requirements")
def get_framework_requirements(
    code: str,
    db: Session = Depends(get_db),
) -> dict:
    """Get all controls mapped to a framework with their citations.

    Returns the framework info, total requirements, and each control
    with its framework-specific citation.
    """
    framework = db.query(Framework).filter(Framework.code == code).first()
    if not framework:
        raise HTTPException(status_code=404, detail="Framework not found")

    requirements = (
        db.query(FrameworkRequirement, Control)
        .join(Control, FrameworkRequirement.control_id == Control.id)
        .filter(FrameworkRequirement.framework_id == framework.id)
        .order_by(FrameworkRequirement.citation)
        .all()
    )

    items = []
    for req, control in requirements:
        items.append(
            {
                "citation": to_str(getattr(req, "citation", None)),
                "citation_title": to_str(
                    getattr(req, "citation_title", None), default=""
                ),
                "baseline": getattr(req, "baseline", None),
                "required": to_str(getattr(req, "required", None), default="true"),
                "control_id": to_str(getattr(control, "id", None)),
                "control_title": to_str(getattr(control, "title", None)),
                "category": getattr(control, "category", None),
                "evidence_types": getattr(control, "evidence_types", None),
            }
        )

    return {
        "framework": FrameworkResponse.model_validate(framework).model_dump(),
        "total_requirements": len(items),
        "requirements": items,
    }


@router.get("/{code}/controls/{control_id}/coverage")
def get_control_framework_coverage(
    code: str,
    control_id: str,
    db: Session = Depends(get_db),
) -> dict:
    """Show which frameworks a specific control satisfies."""
    control = db.query(Control).filter(Control.id == control_id).first()
    if not control:
        raise HTTPException(status_code=404, detail="Control not found")

    requirements = (
        db.query(FrameworkRequirement, Framework)
        .join(Framework, FrameworkRequirement.framework_id == Framework.id)
        .filter(FrameworkRequirement.control_id == control_id)
        .order_by(Framework.name)
        .all()
    )

    coverage = []
    for req, fw in requirements:
        coverage.append(
            FrameworkRequirementResponse(
                framework_code=to_str(getattr(fw, "code", None)),
                framework_name=to_str(getattr(fw, "name", None)),
                citation=to_str(getattr(req, "citation", None)),
                citation_title=getattr(req, "citation_title", None),
                baseline=getattr(req, "baseline", None),
                required=to_str(getattr(req, "required", None), default="true"),
            )
        )

    return {
        "control_id": control_id,
        "control_title": to_str(getattr(control, "title", None)),
        "frameworks_covered": len(coverage),
        "coverage": [c.model_dump() for c in coverage],
    }
