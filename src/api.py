"""API routes for CharlottesWeb."""
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.orm import Session

from src import __version__
from src.audit import AuditAction, AuditLevel, log_audit_event
from src.config import settings
from src.database import get_db
from src.models import Assessment, Control, Finding, MetadataProfile, Organization
from src.nvd_service import NVDService
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
    RemediationRoadmapResponse,
    RoadmapItem,
    RoadmapSummary,
)
from src.security import get_api_key_optional

# Rate limiter
limiter = Limiter(key_func=get_remote_address)

router = APIRouter()


@router.get("/health", response_model=HealthResponse)
@limiter.limit(f"{settings.rate_limit_per_minute * 2}/minute")
def health_check(request: Request) -> HealthResponse:
    """Health check endpoint."""
    return HealthResponse(
        status="healthy",
        version=__version__,
        environment=settings.app_env,
    )


# Organization endpoints
@router.post("/organizations", response_model=OrganizationResponse, status_code=201)
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


@router.get("/organizations/{org_id}", response_model=OrganizationResponse)
@limiter.limit(f"{settings.rate_limit_per_minute}/minute")
def get_organization(
    request: Request,
    org_id: str,
    db: Session = Depends(get_db),
    api_key: str = Depends(get_api_key_optional),
) -> Organization:
    """Get organization by ID."""
    org: Organization | None = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    # Audit log
    log_audit_event(
        action=AuditAction.DATA_READ,
        request=request,
        api_key=api_key,
        resource_type="organization",
        resource_id=org.id,  # type: ignore[arg-type] - SQLAlchemy Column unwraps at runtime
    )
    
    return org


# Metadata Profile endpoints
@router.post("/metadata-profiles", response_model=MetadataProfileResponse, status_code=201)
@limiter.limit(f"{settings.rate_limit_per_minute}/minute")
def create_metadata_profile(
    request: Request,
    profile_data: MetadataProfileCreate,
    db: Session = Depends(get_db),
    api_key: str = Depends(get_api_key_optional),
) -> MetadataProfile:
    """Create a new metadata profile."""
    # Verify organization exists
    org: Organization | None = db.query(Organization).filter(Organization.id == profile_data.organization_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    profile = MetadataProfile(
        organization_id=profile_data.organization_id,
        phi_types=profile_data.phi_types,
        cloud_provider=profile_data.cloud_provider,
        infrastructure=profile_data.infrastructure,
        applications=profile_data.applications,
        access_controls=profile_data.access_controls,
        software_stack=profile_data.software_stack,
    )
    db.add(profile)
    db.commit()
    db.refresh(profile)
    
    # Audit log
    log_audit_event(
        action=AuditAction.PROFILE_CREATED,
        request=request,
        api_key=api_key,
        resource_type="metadata_profile",
        resource_id=profile.id,  # type: ignore[arg-type] - SQLAlchemy Column unwraps at runtime
        details={"organization_id": profile.organization_id},
    )
    
    return profile


@router.get("/metadata-profiles/{profile_id}", response_model=MetadataProfileResponse)
def get_metadata_profile(profile_id: str, db: Session = Depends(get_db)) -> MetadataProfile:
    """Get metadata profile by ID."""
    profile: MetadataProfile | None = db.query(MetadataProfile).filter(MetadataProfile.id == profile_id).first()
    if not profile:
        raise HTTPException(status_code=404, detail="Metadata profile not found")
    return profile


# Control endpoints
@router.get("/controls", response_model=list[ControlResponse])
def list_controls(db: Session = Depends(get_db)) -> List[Control]:
    """List all controls."""
    controls: List[Control] = db.query(Control).all()
    return controls


@router.get("/controls/{control_id}", response_model=ControlResponse)
def get_control(control_id: str, db: Session = Depends(get_db)) -> Control:
    """Get control by ID."""
    control: Control | None = db.query(Control).filter(Control.id == control_id).first()
    if not control:
        raise HTTPException(status_code=404, detail="Control not found")
    return control


# Assessment endpoints
@router.post("/assessments", response_model=AssessmentResponse, status_code=201)
@limiter.limit(f"{settings.rate_limit_per_minute}/minute")
def create_assessment(
    request: Request,
    assessment_data: AssessmentCreate,
    db: Session = Depends(get_db),
    api_key: str = Depends(get_api_key_optional),
) -> Assessment:
    """Create and run a new assessment."""
    from datetime import datetime, timezone
    
    # Verify organization and metadata profile exist
    org: Organization | None = db.query(Organization).filter(Organization.id == assessment_data.organization_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    profile: MetadataProfile | None = (
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
        assessment.status = "completed"  # type: ignore[attr-defined] - SQLAlchemy ORM attribute assignment
        assessment.completed_at = datetime.now(timezone.utc)  # type: ignore[attr-defined] - SQLAlchemy ORM attribute assignment
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
        assessment.status = "failed"  # type: ignore[attr-defined] - SQLAlchemy ORM attribute assignment
        db.commit()
        
        # Audit log - assessment failed
        log_audit_event(
            action=AuditAction.ERROR,
            request=request,
            api_key=api_key,
            resource_type="assessment",
            resource_id=assessment.id,  # type: ignore[arg-type] - SQLAlchemy Column unwraps at runtime
            success=False,
            details={"error": str(e), "status": "failed"},
        )
        
        raise HTTPException(status_code=500, detail=f"Assessment failed: {str(e)}")

    db.refresh(assessment)
    return assessment


@router.get("/assessments/{assessment_id}", response_model=AssessmentResponse)
def get_assessment(assessment_id: str, db: Session = Depends(get_db)) -> Assessment:
    """Get assessment by ID."""
    assessment: Assessment | None = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return assessment


@router.get("/assessments/{assessment_id}/findings", response_model=list[FindingResponse])
def get_assessment_findings(assessment_id: str, db: Session = Depends(get_db)) -> List[Finding]:
    """Get findings for an assessment."""
    assessment: Assessment | None = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")

    findings: List[Finding] = db.query(Finding).filter(Finding.assessment_id == assessment_id).all()
    return findings


@router.get("/assessments/{assessment_id}/roadmap", response_model=RemediationRoadmapResponse)
@limiter.limit(f"{settings.rate_limit_per_minute}/minute")
def get_remediation_roadmap(
    request: Request,
    assessment_id: str,
    db: Session = Depends(get_db),
    api_key: str = Depends(get_api_key_optional),
) -> RemediationRoadmapResponse:
    """Generate prioritized remediation roadmap for an assessment."""
    from datetime import datetime
    
    # Verify assessment exists
    assessment: Assessment | None = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")

    # Get all findings for this assessment
    findings: List[Finding] = db.query(Finding).filter(Finding.assessment_id == assessment_id).all()

    # Group findings by priority window
    immediate = []
    thirty_days = []
    quarterly = []
    annual = []

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
        priority = str(finding.priority_window or "quarterly")  # Extract value from Column for conditional
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
        severity = finding.severity.lower()
        if severity == "critical":
            critical_count += 1
        elif severity == "high":
            high_count += 1
        elif severity == "medium":
            medium_count += 1
        elif severity == "low":
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
        generated_at=datetime.now(timezone.utc),
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


# NVD (National Vulnerability Database) endpoints
@router.post("/assessments/{assessment_id}/analyze-nvd", response_model=list[FindingResponse])
@limiter.limit(f"{settings.rate_limit_per_minute}/minute")
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
    assessment: Assessment | None = db.query(Assessment).filter(Assessment.id == assessment_id).first()  # type: ignore[assignment]
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    
    metadata_profile: MetadataProfile | None = db.query(MetadataProfile).filter(
        MetadataProfile.id == assessment.metadata_profile_id  # type: ignore[attr-defined]
    ).first()
    if not metadata_profile:
        raise HTTPException(status_code=404, detail="Metadata profile not found")
    
    # Get software stack from metadata profile
    software_stack: dict = metadata_profile.software_stack or {}  # type: ignore[attr-defined]
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
    nvd_service = NVDService(api_key=settings.nvd_api_key if settings.nvd_api_key else None)
    
    # Analyze software stack for vulnerabilities
    nvd_results = nvd_service.analyze_software_stack(software_stack)
    
    # Create findings from NVD results
    new_findings: list[Finding] = []
    
    for component, cves in nvd_results.items():
        for cve in cves:
            # Check if this CVE finding already exists
            existing = db.query(Finding).filter(
                Finding.assessment_id == assessment_id,  # type: ignore[attr-defined]
                Finding.external_id == cve["cve_id"],  # type: ignore[attr-defined]
            ).first()
            
            if existing:
                # Skip if finding already exists
                continue
            
            # Determine priority window based on CVSS score
            priority_window = nvd_service.get_priority_window_from_cvss(cve["cvss_score"])
            severity = nvd_service.get_severity_from_cvss(cve["cvss_score"])
            
            # Find related controls (security controls affected by this CVE)
            # For now, associate with general "vulnerability_management" controls
            related_controls = db.query(Control).filter(
                Control.title.contains("vulnerability")  # type: ignore[attr-defined]
            ).all()
            
            # Create finding record
            finding = Finding(
                id=f"finding-nvd-{cve['cve_id'].replace('CVE-', '').replace('-', '')[:20]}",
                assessment_id=assessment_id,  # type: ignore[arg-type]
                control_id=related_controls[0].id if related_controls else None,  # type: ignore[attr-defined]
                external_id=cve["cve_id"],
                title=f"{cve['cve_id']}: {component} vulnerability",
                description=cve["description"],
                severity=severity,
                cvss_score=cve["cvss_score"],
                cwe_ids=cve["cwe_ids"],
                priority_window=priority_window,
                remediation_guidance=f"Update {component} to a patched version. Check CVE details at https://nvd.nist.gov/vuln/detail/{cve['cve_id']}",
            )
            
            db.add(finding)
            new_findings.append(finding)
    
    # Commit findings to database
    if new_findings:
        db.commit()
    
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
            "findings_created": len(new_findings),
            "components_analyzed": list(nvd_results.keys()),
        },
        level=AuditLevel.INFO,
    )
    
    return new_findings

