"""API routes for CharlottesWeb."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from src import __version__
from src.config import settings
from src.database import get_db
from src.models import Assessment, Control, Finding, MetadataProfile, Organization
from src.rules_engine import RulesEngine
from src.schemas import (
    AssessmentCreate,
    AssessmentResponse,
    ControlResponse,
    FindingResponse,
    HealthResponse,
    MetadataProfileCreate,
    MetadataProfileResponse,
    OrganizationCreate,
    OrganizationResponse,
)

router = APIRouter()


@router.get("/health", response_model=HealthResponse)
def health_check():
    """Health check endpoint."""
    return HealthResponse(
        status="healthy",
        version=__version__,
        environment=settings.app_env,
    )


# Organization endpoints
@router.post("/organizations", response_model=OrganizationResponse, status_code=201)
def create_organization(org_data: OrganizationCreate, db: Session = Depends(get_db)):
    """Create a new organization."""
    org = Organization(
        name=org_data.name,
        industry=org_data.industry,
        stage=org_data.stage,
    )
    db.add(org)
    db.commit()
    db.refresh(org)
    return org


@router.get("/organizations/{org_id}", response_model=OrganizationResponse)
def get_organization(org_id: str, db: Session = Depends(get_db)):
    """Get organization by ID."""
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    return org


# Metadata Profile endpoints
@router.post("/metadata-profiles", response_model=MetadataProfileResponse, status_code=201)
def create_metadata_profile(
    profile_data: MetadataProfileCreate, db: Session = Depends(get_db)
):
    """Create a new metadata profile."""
    # Verify organization exists
    org = db.query(Organization).filter(Organization.id == profile_data.organization_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    profile = MetadataProfile(
        organization_id=profile_data.organization_id,
        phi_types=profile_data.phi_types,
        cloud_provider=profile_data.cloud_provider,
        infrastructure=profile_data.infrastructure,
        applications=profile_data.applications,
        access_controls=profile_data.access_controls,
    )
    db.add(profile)
    db.commit()
    db.refresh(profile)
    return profile


@router.get("/metadata-profiles/{profile_id}", response_model=MetadataProfileResponse)
def get_metadata_profile(profile_id: str, db: Session = Depends(get_db)):
    """Get metadata profile by ID."""
    profile = db.query(MetadataProfile).filter(MetadataProfile.id == profile_id).first()
    if not profile:
        raise HTTPException(status_code=404, detail="Metadata profile not found")
    return profile


# Control endpoints
@router.get("/controls", response_model=list[ControlResponse])
def list_controls(db: Session = Depends(get_db)):
    """List all controls."""
    controls = db.query(Control).all()
    return controls


@router.get("/controls/{control_id}", response_model=ControlResponse)
def get_control(control_id: str, db: Session = Depends(get_db)):
    """Get control by ID."""
    control = db.query(Control).filter(Control.id == control_id).first()
    if not control:
        raise HTTPException(status_code=404, detail="Control not found")
    return control


# Assessment endpoints
@router.post("/assessments", response_model=AssessmentResponse, status_code=201)
def create_assessment(assessment_data: AssessmentCreate, db: Session = Depends(get_db)):
    """Create and run a new assessment."""
    # Verify organization and metadata profile exist
    org = db.query(Organization).filter(Organization.id == assessment_data.organization_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    profile = (
        db.query(MetadataProfile)
        .filter(MetadataProfile.id == assessment_data.metadata_profile_id)
        .first()
    )
    if not profile:
        raise HTTPException(status_code=404, detail="Metadata profile not found")

    # Create assessment
    assessment = Assessment(
        organization_id=assessment_data.organization_id,
        metadata_profile_id=assessment_data.metadata_profile_id,
        status="running",
    )
    db.add(assessment)
    db.commit()
    db.refresh(assessment)

    # Run rules engine
    try:
        engine = RulesEngine(db)
        findings = engine.run_assessment(assessment.id)

        # Save findings
        for finding in findings:
            db.add(finding)

        # Mark assessment complete
        assessment.status = "completed"
        from datetime import datetime
        assessment.completed_at = datetime.utcnow()
        db.commit()

    except Exception as e:
        assessment.status = "failed"
        db.commit()
        raise HTTPException(status_code=500, detail=f"Assessment failed: {str(e)}")

    db.refresh(assessment)
    return assessment


@router.get("/assessments/{assessment_id}", response_model=AssessmentResponse)
def get_assessment(assessment_id: str, db: Session = Depends(get_db)):
    """Get assessment by ID."""
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return assessment


@router.get("/assessments/{assessment_id}/findings", response_model=list[FindingResponse])
def get_assessment_findings(assessment_id: str, db: Session = Depends(get_db)):
    """Get findings for an assessment."""
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")

    findings = db.query(Finding).filter(Finding.assessment_id == assessment_id).all()
    return findings
