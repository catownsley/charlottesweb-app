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
from src.models import Assessment, Control, Evidence, Finding, MetadataProfile, Organization
from src.nvd_service import NVDService
from src.rules_engine import RulesEngine
from src.schemas import (
    AssessmentCreate,
    AssessmentResponse,
    ControlResponse,
    EvidenceChecklistItem,
    EvidenceChecklistResponse,
    EvidenceCreate,
    EvidenceResponse,
    EvidenceUpdate,
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


# Component version discovery endpoint
@router.get("/components/{component_name}/versions")
@limiter.limit(f"{settings.rate_limit_per_minute * 3}/minute")
def get_component_versions(request: Request, component_name: str) -> dict:
    """Get known versions of a component for autocomplete suggestions.
    
    Returns the latest versions for popular software components.
    Users can type any version manually; actual CVE analysis searches by component name only.
    
    Args:
        component_name: Name of the component (e.g., 'postgres', 'java', 'nodejs')
    
    Returns:
        Dictionary with 'versions' list of strings (top 3 latest versions)
    
    Example:
        GET /api/v1/components/java/versions
        Response: {"versions": ["21", "20", "19"]}
    """
    component_lower = component_name.lower().strip()
    
    # Common versions for popular components (listed newest first)
    # Organized by component with realistic version strings
    known_versions = {
        'java': ['21', '20', '19', '18', '17', '16', '15', '14', '13', '12', '11', '10', '9', '8'],
        'postgres': ['16', '15', '14', '13', '12', '11', '10', '9.6', '9.5'],
        'postgresql': ['16', '15', '14', '13', '12', '11', '10', '9.6', '9.5'],
        'nodejs': ['21', '20', '19', '18', '17', '16', '15', '14', '12'],
        'node': ['21', '20', '19', '18', '17', '16', '15', '14', '12'],
        'python': ['3.13', '3.12', '3.11', '3.10', '3.9', '3.8', '3.7'],
        'nginx': ['1.26', '1.25', '1.24', '1.23', '1.22', '1.21', '1.20'],
        'mysql': ['8.3', '8.2', '8.1', '8.0', '5.7', '5.6'],
        'mongodb': ['7.0', '6.3', '6.2', '6.1', '6.0', '5.0', '4.4'],
        'redis': ['7.2', '7.1', '7.0', '6.2', '6.1', '6.0', '5.0'],
        'docker': ['25', '24', '23', '22', '21', '20', '19'],
        'openssl': ['3.2', '3.1', '3.0', '1.1.1', '1.0.2'],
    }
    
    # Get versions for this component, or use first few letters as fallback
    versions_to_test = known_versions.get(component_lower, [])
    
    if not versions_to_test:
        # Try prefix matching (e.g., "post" matches "postgres")
        for key, versions in known_versions.items():
            if key.startswith(component_lower) or component_lower.startswith(key[:3]):
                versions_to_test = versions
                break
    
    # If still no match but component name is provided, return empty gracefully
    if not versions_to_test:
        return {"versions": []}
    
    # Return top 3 latest versions for autocomplete suggestions
    # (User can type any version they want, actual NVD analysis searches by component name only)
    top_versions = versions_to_test[:3]
    
    return {"versions": top_versions}


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
            # NOTE: Do NOT set id manually - let the database generate UUIDs to avoid uniqueness violations
            finding = Finding(
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
        try:
            db.commit()
        except Exception as e:
            db.rollback()
            # Log the actual error server-side but don't expose to user
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Failed to commit findings: {str(e)}")
            raise HTTPException(
                status_code=500,
                detail="Failed to save vulnerability findings. Please try again with a different software stack or contact support."
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
            "findings_created": len(new_findings),
            "components_analyzed": list(nvd_results.keys()),
        },
        level=AuditLevel.INFO,
    )
    
    return new_findings


# Evidence endpoints (Phase 2)
@router.post("/evidence", response_model=EvidenceResponse, status_code=201)
@limiter.limit(f"{settings.rate_limit_per_minute}/minute")
def create_evidence(
    request: Request,
    evidence_data: EvidenceCreate,
    db: Session = Depends(get_db),
    api_key: str = Depends(get_api_key_optional),
) -> Evidence:
    """Create a new evidence item."""
    # Verify control exists
    control: Control | None = db.query(Control).filter(Control.id == evidence_data.control_id).first()
    if not control:
        raise HTTPException(status_code=404, detail="Control not found")
    
    # Verify assessment exists if provided
    if evidence_data.assessment_id:
        assessment: Assessment | None = db.query(Assessment).filter(Assessment.id == evidence_data.assessment_id).first()
        if not assessment:
            raise HTTPException(status_code=404, detail="Assessment not found")
    
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


@router.get("/evidence/{evidence_id}", response_model=EvidenceResponse)
def get_evidence(evidence_id: str, db: Session = Depends(get_db)) -> Evidence:
    """Get evidence by ID."""
    evidence: Evidence | None = db.query(Evidence).filter(Evidence.id == evidence_id).first()
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return evidence


@router.patch("/evidence/{evidence_id}", response_model=EvidenceResponse)
@limiter.limit(f"{settings.rate_limit_per_minute}/minute")
def update_evidence(
    request: Request,
    evidence_id: str,
    evidence_update: EvidenceUpdate,
    db: Session = Depends(get_db),
    api_key: str = Depends(get_api_key_optional),
) -> Evidence:
    """Update evidence item."""
    evidence: Evidence | None = db.query(Evidence).filter(Evidence.id == evidence_id).first()
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found")
    
    # Update fields
    update_data = evidence_update.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(evidence, field, value)
    
    from datetime import datetime, timezone
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


@router.get("/assessments/{assessment_id}/evidence-checklist", response_model=EvidenceChecklistResponse)
def generate_evidence_checklist(
    assessment_id: str,
    db: Session = Depends(get_db),
) -> EvidenceChecklistResponse:
    """Generate evidence checklist for an assessment."""
    from datetime import datetime, timezone
    
    # Verify assessment exists
    assessment: Assessment | None = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    
    # Get all findings for this assessment
    findings: List[Finding] = (
        db.query(Finding)
        .filter(Finding.assessment_id == assessment_id)
        .filter(Finding.control_id.isnot(None))
        .all()
    )
    
    # Get unique control IDs from findings
    control_ids = list(set(f.control_id for f in findings if f.control_id))
    
    # Get controls with evidence requirements
    controls: List[Control] = (
        db.query(Control)
        .filter(Control.id.in_(control_ids))
        .filter(Control.evidence_types.isnot(None))
        .all()
    )
    
    # Get existing evidence for these controls
    existing_evidence: List[Evidence] = (
        db.query(Evidence)
        .filter(Evidence.assessment_id == assessment_id)
        .all()
    )
    
    # Create a map of (control_id, evidence_type) -> evidence
    evidence_map = {
        (ev.control_id, ev.evidence_type): ev
        for ev in existing_evidence
    }
    
    # Generate checklist items
    checklist_items: List[EvidenceChecklistItem] = []
    for control in controls:
        if not control.evidence_types:
            continue
            
        for evidence_type in control.evidence_types:
            evidence = evidence_map.get((control.id, evidence_type))
            
            item = EvidenceChecklistItem(
                control_id=control.id,
                control_title=control.title,
                evidence_type=evidence_type,
                required_evidence=evidence_type.replace("_", " ").title(),
                status=evidence.status if evidence else "not_started",
                owner=evidence.owner if evidence else None,
                due_date=evidence.due_date if evidence else None,
                evidence_id=evidence.id if evidence else None,  # type: ignore[attr-defined]
            )
            checklist_items.append(item)
    
    # Calculate statistics
    total_items = len(checklist_items)
    completed = sum(1 for item in checklist_items if item.status == "completed")
    in_progress = sum(1 for item in checklist_items if item.status == "in_progress")
    not_started = sum(1 for item in checklist_items if item.status == "not_started")
    
    return EvidenceChecklistResponse(
        assessment_id=assessment_id,
        organization_id=assessment.organization_id,
        generated_at=datetime.now(timezone.utc).replace(tzinfo=None),
        total_items=total_items,
        completed=completed,
        in_progress=in_progress,
        not_started=not_started,
        items=checklist_items,
    )
