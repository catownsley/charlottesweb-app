"""Assessment workflow endpoints."""
import logging
from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from src.audit import AuditAction, AuditLevel, log_audit_event
from src.compliance_as_code import ComplianceAsCodeEvaluator
from src.config import settings
from src.database import get_db, get_or_404
from src.middleware import get_api_key_optional, limiter
from src.mitre_service import mitre_service
from src.models import Assessment, Control, Evidence, Finding, MetadataProfile, Organization
from src.nvd_service import NVDService
from src.rules_engine import RulesEngine
from src.schemas import (
    AssessmentCreate,
    ComplianceAsCodeResponse,
    AssessmentResponse,
    EvidenceChecklistItem,
    EvidenceChecklistResponse,
    FindingResponse,
    RemediationRoadmapResponse,
    RoadmapItem,
    RoadmapSummary,
)

router = APIRouter(prefix="/assessments", tags=["assessments"])
logger = logging.getLogger(__name__)


CWE_CONTROL_MAP = {
    "CWE-295": "HC.SC-7.1",   # Improper Certificate Validation → TLS/Encryption
    "CWE-311": "HC.SC-4.1",   # Missing Encryption → Data Protection
    "CWE-798": "HC.SC-2.1",   # Hard-coded Credentials → Access Control
    "CWE-347": "HC.SC-12.1",  # Improper Verification of Cryptographic Signature → Key Management
    "CWE-200": "HC.SC-7.2",   # Information Exposure → Network Security
    "CWE-778": "HC.AU-6.1",   # Insufficient Logging → Audit Logging
    "CWE-89": "HC.SC-3.1",    # SQL Injection → Input Validation
    "CWE-79": "HC.SC-3.1",    # Cross-site Scripting → Input Validation
}

# Fallback controls used when CWE mapping is unavailable or unknown.
# Ordered by preference; first existing control in DB is selected.
FALLBACK_CONTROL_CANDIDATES = [
    "HC.SC-7.1",              # Healthcare transmission security
    "HIPAA.164.312(e)(1)",    # HIPAA transmission security
    "HIPAA.164.312(a)(2)(iv)",  # HIPAA encryption/decryption
]


@router.post("", response_model=AssessmentResponse, status_code=201)
@limiter.limit(f"{settings.rate_limit_per_minute}/minute")
def create_assessment(
    request: Request,
    assessment_data: AssessmentCreate,
    db: Session = Depends(get_db),
    api_key: str = Depends(get_api_key_optional),
) -> Assessment:
    """Create and run a new assessment."""
    # Verify organization and metadata profile exist
    org = get_or_404(db, Organization, assessment_data.organization_id, "Organization not found")
    profile = get_or_404(db, MetadataProfile, assessment_data.metadata_profile_id, "Metadata profile not found")

    # Create assessment
    try:
        assessment = Assessment(
            organization_id=assessment_data.organization_id,
            metadata_profile_id=assessment_data.metadata_profile_id,
            status="running",
        )
        db.add(assessment)
        db.commit()
        db.refresh(assessment)
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to create assessment: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="Failed to create assessment. Please try again."
        )

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
        try:
            db.commit()
        except:
            db.rollback()

        logger.error(f"Assessment failed: {str(e)}", exc_info=True)
        # Audit log - assessment failed
        log_audit_event(
            action=AuditAction.ERROR,
            request=request,
            api_key=api_key,
            resource_type="assessment",
            resource_id=assessment.id,  # type: ignore[arg-type] - SQLAlchemy Column unwraps at runtime
            success=False,
            details={"status": "failed"},
        )
        # Return safe error message
        raise HTTPException(
            status_code=500,
            detail="Assessment execution failed. Please try again or contact support."
        )

    db.refresh(assessment)
    return assessment


@router.get("/{assessment_id}", response_model=AssessmentResponse)
def get_assessment(assessment_id: str, db: Session = Depends(get_db)) -> Assessment:
    """Get assessment by ID."""
    assessment = get_or_404(db, Assessment, assessment_id, "Assessment not found")
    return assessment


@router.get("/{assessment_id}/compliance-as-code", response_model=ComplianceAsCodeResponse)
def evaluate_compliance_as_code(
    assessment_id: str,
    persist_findings: bool = Query(False, description="Persist failed policy rules as findings"),
    auto_resolve: bool = Query(True, description="Automatically resolve/remove findings when rules pass"),
    db: Session = Depends(get_db),
) -> ComplianceAsCodeResponse:
    """Evaluate metadata profile against JSON-defined compliance rules.
    
    Args:
        assessment_id: Assessment to evaluate
        persist_findings: If True, create/update findings for failed rules
        auto_resolve: If True, remove findings for rules that now pass (only applies when persist_findings=True)
    """
    assessment = get_or_404(db, Assessment, assessment_id, "Assessment not found")
    metadata = get_or_404(
        db,
        MetadataProfile,
        str(assessment.metadata_profile_id),
        "Metadata profile not found",
    )

    evaluator = ComplianceAsCodeEvaluator()
    output = evaluator.evaluate(metadata)

    persisted_rule_ids: list[str] = []
    persisted_findings = 0
    resolved_findings = 0

    if persist_findings:
        failed_results = [result for result in output["results"] if result["status"] == "fail"]
        passed_results = [result for result in output["results"] if result["status"] == "pass"]

        # Handle failed rules: create or update findings
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
                f"{operator} {expected!r}. Then re-run compliance-as-code evaluation."
            )

            existing_finding = (
                db.query(Finding)
                .filter(Finding.assessment_id == str(assessment.id))
                .filter(Finding.external_id == rule_id)
                .first()
            )

            if existing_finding:
                existing_finding.control_id = result["control_id"]  # type: ignore[attr-defined]
                existing_finding.title = f"[Policy] {result['title']}"  # type: ignore[attr-defined]
                existing_finding.description = failure_description  # type: ignore[attr-defined]
                existing_finding.severity = severity  # type: ignore[attr-defined]
                existing_finding.remediation_guidance = remediation_guidance  # type: ignore[attr-defined]
                existing_finding.priority_window = "immediate" if severity in ["critical", "high"] else "30_days"  # type: ignore[attr-defined]
                existing_finding.owner = "Security"  # type: ignore[attr-defined]
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
                    priority_window="immediate" if severity in ["critical", "high"] else "30_days",
                    owner="Security",
                )
                db.add(finding)

            persisted_rule_ids.append(rule_id)

        # Handle passed rules: remove findings if auto_resolve is enabled
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
                    logger.info(f"Auto-resolving finding for passing rule: {rule_id}")
                    db.delete(existing_finding)
                    resolved_findings += 1

        if failed_results or resolved_findings > 0:
            db.commit()
            persisted_findings = len(failed_results)

    return ComplianceAsCodeResponse(
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


@router.get("/{assessment_id}/findings", response_model=list[FindingResponse])
def get_assessment_findings(assessment_id: str, db: Session = Depends(get_db)) -> List[FindingResponse]:
    """Get findings for an assessment with threat intelligence context."""
    assessment = get_or_404(db, Assessment, assessment_id, "Assessment not found")
    findings: List[Finding] = db.query(Finding).filter(Finding.assessment_id == assessment_id).all()

    # Enrich each finding with MITRE ATT&CK threat context
    enriched_findings = []
    for finding in findings:
        # Build base response from Finding model
        finding_dict = {
            "id": finding.id,
            "assessment_id": finding.assessment_id,
            "control_id": finding.control_id,
            "title": finding.title,
            "description": finding.description,
            "severity": finding.severity,
            "cvss_score": finding.cvss_score,
            "external_id": finding.external_id,
            "cve_ids": finding.cve_ids,
            "cwe_ids": finding.cwe_ids,
            "remediation_guidance": finding.remediation_guidance,
            "priority_window": finding.priority_window,
            "owner": finding.owner,
            "created_at": finding.created_at,
        }

        # Add MITRE threat context if CWEs are present
        if finding.cwe_ids:
            threat_context = mitre_service.enrich_finding_with_threat_context(
                cwe_ids=finding.cwe_ids, control_id=finding.control_id or ""
            )
            if threat_context and threat_context.get("techniques"):
                finding_dict["threat_context"] = threat_context

        enriched_findings.append(FindingResponse(**finding_dict))

    return enriched_findings


@router.get("/{assessment_id}/roadmap", response_model=RemediationRoadmapResponse)
@limiter.limit(f"{settings.rate_limit_per_minute}/minute")
def get_remediation_roadmap(
    request: Request,
    assessment_id: str,
    db: Session = Depends(get_db),
    api_key: str = Depends(get_api_key_optional),
) -> RemediationRoadmapResponse:
    """Generate prioritized remediation roadmap for an assessment."""
    # Verify assessment exists
    assessment = get_or_404(db, Assessment, assessment_id, "Assessment not found")

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


@router.post("/{assessment_id}/analyze-nvd", response_model=list[FindingResponse])
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
    assessment = get_or_404(db, Assessment, assessment_id, "Assessment not found")

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

    # Cache available controls for deterministic and efficient mapping
    available_control_ids = {control_id for (control_id,) in db.query(Control.id).all()}
    if not available_control_ids:
        logger.warning("No controls found in database; NVD findings will be created without control mapping")

    # Create findings from NVD results
    new_findings: list[Finding] = []

    total_cves_processed = 0
    mapped_via_cwe = 0
    mapped_via_fallback = 0
    unmapped_cves = 0

    for component, cves in nvd_results.items():
        for cve in cves:
            total_cves_processed += 1
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

            # Map CWE IDs to applicable controls
            control_id = None
            cwe_ids = cve.get("cwe_ids", [])
            mapping_source = "none"

            if cwe_ids:
                # Check if any CWE maps to a control
                for cwe in cwe_ids:
                    if cwe in CWE_CONTROL_MAP:
                        control_id = CWE_CONTROL_MAP[cwe]
                        mapping_source = "cwe"
                        break

            # Ensure mapped control exists in database
            if control_id and control_id not in available_control_ids:
                control_id = None
                mapping_source = "none"

            # Fallback mapping when no direct CWE mapping is available
            if not control_id:
                for fallback_control in FALLBACK_CONTROL_CANDIDATES:
                    if fallback_control in available_control_ids:
                        control_id = fallback_control
                        mapping_source = "fallback"
                        break

            if mapping_source == "cwe":
                mapped_via_cwe += 1
            elif mapping_source == "fallback":
                mapped_via_fallback += 1
            else:
                unmapped_cves += 1

            # Create finding record
            # NOTE: Do NOT set id manually - let the database generate UUIDs to avoid uniqueness violations
            finding = Finding(
                assessment_id=assessment_id,  # type: ignore[arg-type]
                control_id=control_id,
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

    evidence_created_count = 0

    # Commit findings to database
    if new_findings:
        try:
            db.commit()
            logger.info(f"✓ Committed {len(new_findings)} findings")

            # After committing findings, generate evidence items for controls
            db.refresh(assessment)
            unique_control_ids = set(f.control_id for f in new_findings if f.control_id)
            logger.info(f"✓ Unique control IDs from findings: {unique_control_ids}")

            for control_id in unique_control_ids:
                logger.info(f"  Processing control: {control_id}")
                control = db.query(Control).filter(Control.id == control_id).first()
                logger.info(f"  Control found: {control is not None}")
                if control:
                    logger.info(f"  Control.evidence_types: {control.evidence_types}")

                if control and control.evidence_types:
                    logger.info(f"  Creating evidence items for {len(control.evidence_types)} types")
                    for evidence_type in control.evidence_types:
                        # Check if evidence item already exists
                        existing = db.query(Evidence).filter(
                            Evidence.assessment_id == assessment_id,
                            Evidence.control_id == control_id,
                            Evidence.evidence_type == evidence_type,
                        ).first()

                        if not existing:
                            # Create new evidence item
                            evidence_item = Evidence(
                                assessment_id=assessment_id,
                                control_id=control_id,
                                evidence_type=evidence_type,
                                title=f"{control_id}: {evidence_type}",
                                description=f"Evidence for {control.title}",
                                status="not_started",
                                owner="system",
                            )
                            logger.info(f"    Adding evidence item: {evidence_type}")
                            db.add(evidence_item)
                            evidence_created_count += 1

            db.commit()
            logger.info("✓ Committed all evidence items")
            logger.warning(
                "NVD analysis summary: findings=%s mapped_via_cwe=%s mapped_via_fallback=%s unmapped=%s evidence_created=%s",
                len(new_findings),
                mapped_via_cwe,
                mapped_via_fallback,
                unmapped_cves,
                evidence_created_count,
            )
        except Exception as e:
            db.rollback()
            # Log the actual error server-side but don't expose to user
            logger.error(f"Failed to commit findings: {str(e)}", exc_info=True)
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
            "cves_processed": total_cves_processed,
            "findings_created": len(new_findings),
            "mapped_via_cwe": mapped_via_cwe,
            "mapped_via_fallback": mapped_via_fallback,
            "unmapped_cves": unmapped_cves,
            "evidence_created": evidence_created_count,
            "components_analyzed": list(nvd_results.keys()),
        },
        level=AuditLevel.INFO,
    )

    return new_findings


@router.get("/{assessment_id}/evidence-checklist", response_model=EvidenceChecklistResponse)
def generate_evidence_checklist(
    assessment_id: str,
    db: Session = Depends(get_db),
) -> EvidenceChecklistResponse:
    """Generate evidence checklist for an assessment."""
    from src.models import Evidence

    # Verify assessment exists
    assessment = get_or_404(db, Assessment, assessment_id, "Assessment not found")

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

    # Get existing evidence for these controls, scoped to the organization
    # This allows evidence to persist across assessments for the same org
    existing_evidence: List[Evidence] = (
        db.query(Evidence)
        .join(Assessment, Evidence.assessment_id == Assessment.id)
        .filter(
            Assessment.organization_id == assessment.organization_id,
            Evidence.control_id.in_(control_ids),
        )
        .all()
    )

    # Also get evidence not linked to any assessment but matching controls
    orphan_evidence: List[Evidence] = (
        db.query(Evidence)
        .filter(
            Evidence.assessment_id.is_(None),
            Evidence.control_id.in_(control_ids),
        )
        .all()
    )

    # Merge both lists
    all_evidence = existing_evidence + orphan_evidence

    # Create a map of (control_id, evidence_type) -> evidence
    # Prefer most recently updated evidence for each (control, type) combo
    evidence_map = {}
    for ev in sorted(all_evidence, key=lambda e: e.updated_at):
        evidence_map[(ev.control_id, ev.evidence_type)] = ev

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
                collected_at=evidence.collected_at if evidence else None,
                notes=evidence.notes if evidence else None,
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
