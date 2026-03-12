"""Pydantic schemas for API request/response validation."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


# Organization schemas
class OrganizationCreate(BaseModel):
    """Schema for creating an organization."""

    name: str = Field(..., min_length=1, max_length=255)
    industry: str | None = None
    stage: str | None = None


class OrganizationResponse(BaseModel):
    """Schema for organization response."""

    id: str
    name: str
    industry: str | None = None
    stage: str | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


class OrganizationMemberResponse(BaseModel):
    """Schema for organization member response."""

    id: str
    organization_id: str
    email: str
    full_name: str | None = None
    role: str
    created_at: datetime

    model_config = {"from_attributes": True}


class OrganizationOnboardingCreate(BaseModel):
    """Schema for onboarding a new organization with first member."""

    name: str = Field(..., min_length=1, max_length=255)
    industry: str | None = None
    stage: str | None = None
    admin_email: str = Field(..., min_length=3, max_length=255)
    admin_name: str | None = Field(default=None, max_length=255)
    admin_role: Literal["admin", "member"] = "admin"


class OrganizationOnboardingResponse(BaseModel):
    """Schema for onboarding response."""

    organization: OrganizationResponse
    member: OrganizationMemberResponse


# Metadata Profile schemas
class MetadataProfileCreate(BaseModel):
    """Schema for creating a metadata profile."""

    organization_id: str
    phi_types: list[str] | None = None
    cloud_provider: str | None = None
    infrastructure: dict[str, Any] | None = None
    applications: dict[str, Any] | None = None
    access_controls: dict[str, Any] | None = None
    software_stack: dict[str, Any] | None = None


class MetadataProfileResponse(BaseModel):
    """Schema for metadata profile response."""

    id: str
    organization_id: str
    phi_types: list[str] | None = None
    cloud_provider: str | None = None
    infrastructure: dict[str, Any] | None = None
    applications: dict[str, Any] | None = None
    access_controls: dict[str, Any] | None = None
    software_stack: dict[str, Any] | None = None
    version: str
    created_at: datetime

    model_config = {"from_attributes": True}


class ManifestIngestRequest(BaseModel):
    """Schema for manifest ingestion requests."""

    format: Literal["pom_xml"]
    content: str = Field(..., min_length=1)


class ManifestComponent(BaseModel):
    """Schema for a parsed component/version pair."""

    name: str
    version: str


class ManifestIngestResponse(BaseModel):
    """Schema for manifest ingestion response."""

    format: str
    components: list[ManifestComponent]
    total_components: int


# Control schemas
class ControlResponse(BaseModel):
    """Schema for control response."""

    id: str
    framework: str
    title: str
    requirement: str
    category: str | None = None
    evidence_types: list[str] | None = None

    model_config = {"from_attributes": True}


# Assessment schemas
class AssessmentCreate(BaseModel):
    """Schema for creating an assessment."""

    organization_id: str
    metadata_profile_id: str


class AssessmentResponse(BaseModel):
    """Schema for assessment response."""

    id: str
    organization_id: str
    metadata_profile_id: str
    status: str
    initiated_at: datetime
    completed_at: datetime | None = None

    model_config = {"from_attributes": True}


class AssessmentStatusResponse(BaseModel):
    """Schema for assessment run status and progress."""

    assessment_id: str
    status: str
    progress_percent: int
    current_step: str
    findings_count: int
    updated_at: datetime | None = None


class AssessmentReportCreateResponse(BaseModel):
    """Schema for report generation creation response."""

    report_id: str
    assessment_id: str
    status: str
    generated_at: datetime
    download_token: str


class AssessmentReportStatusResponse(BaseModel):
    """Schema for report generation status response."""

    report_id: str
    assessment_id: str
    status: str
    generated_at: datetime
    download_url: str | None = None


# Threat Intelligence schemas (MITRE ATT&CK)
class ThreatTechniqueBreachExample(BaseModel):
    """Schema for real-world breach example."""

    breach: str = Field(description="Name of healthcare breach")
    impact: str = Field(description="Impact description")
    date: str = Field(description="When breach occurred")


class ThreatTechniqueMitigation(BaseModel):
    """Schema for MITRE mitigation (countermeasure)."""

    id: str = Field(description="Mitigation ID (e.g., M1032)")
    name: str = Field(description="Mitigation name")
    description: str = Field(description="How to mitigate")


class ThreatTechnique(BaseModel):
    """Schema for MITRE ATT&CK technique."""

    id: str = Field(description="Technique ID (e.g., T1078)")
    name: str = Field(description="Technique name")
    description: str = Field(description="What attackers do")
    tactics: list[str] = Field(description="Kill chain phases")
    url: str = Field(description="MITRE ATT&CK URL")
    breach_example: ThreatTechniqueBreachExample | None = None
    primary_mitigation: ThreatTechniqueMitigation | None = None


class ThreatContext(BaseModel):
    """Schema for threat intelligence context added to findings."""

    techniques: list[ThreatTechnique] = Field(
        description="Attack techniques that exploit this gap"
    )
    summary: str = Field(description="Executive summary of threat")


# Finding schemas
class FindingResponse(BaseModel):
    """Schema for finding response."""

    id: str
    assessment_id: str
    control_id: str | None = None
    control_domain: str | None = None
    title: str
    description: str
    severity: str
    cvss_score: float | None = None
    external_id: str | None = None
    cve_ids: list[str] | None = None
    cwe_ids: list[str] | None = None
    remediation_guidance: str | None = None
    priority_window: str | None = None
    owner: str | None = None
    created_at: datetime
    threat_context: ThreatContext | None = Field(
        None, description="Real-world threat intelligence (MITRE ATT&CK)"
    )

    model_config = {"from_attributes": True}


# Evidence schemas
class EvidenceCreate(BaseModel):
    """Schema for creating evidence."""

    control_id: str
    assessment_id: str | None = None
    evidence_type: str  # policy, config, screenshot, logs, report, etc.
    title: str = Field(..., min_length=1, max_length=255)
    description: str | None = None
    owner: str | None = None
    due_date: datetime | None = None


class EvidenceUpdate(BaseModel):
    """Schema for updating evidence."""

    status: str | None = None  # not_started, in_progress, completed, not_applicable
    owner: str | None = None
    due_date: datetime | None = None
    artifact_path: str | None = None
    artifact_url: str | None = None
    artifact_hash: str | None = None
    collected_at: datetime | None = None  # when evidence was actually collected
    notes: str | None = None


class EvidenceResponse(BaseModel):
    """Schema for evidence response."""

    id: str
    control_id: str
    assessment_id: str | None = None
    evidence_type: str
    title: str
    description: str | None = None
    status: str
    owner: str | None = None
    due_date: datetime | None = None
    artifact_path: str | None = None
    artifact_url: str | None = None
    artifact_hash: str | None = None
    uploaded_at: datetime | None = None
    collected_at: datetime | None = None
    version: str
    notes: str | None = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class EvidenceChecklistItem(BaseModel):
    """Schema for a single evidence checklist item."""

    control_id: str
    control_title: str
    evidence_type: str
    required_evidence: str
    status: str
    owner: str | None = None
    due_date: datetime | None = None
    collected_at: datetime | None = None
    notes: str | None = None
    evidence_id: str | None = None


class EvidenceChecklistResponse(BaseModel):
    """Schema for evidence checklist response."""

    assessment_id: str
    organization_id: str
    generated_at: datetime
    total_items: int
    completed: int
    in_progress: int
    not_started: int
    items: list[EvidenceChecklistItem]


class ComplianceRuleResult(BaseModel):
    """Schema for a single compliance intelligence rule evaluation result."""

    rule_id: str
    control_id: str
    title: str
    description: str | None = None
    path: str
    operator: str
    expected: Any
    actual: Any = None
    status: str
    severity_on_fail: str


class ComplianceIntelligenceResponse(BaseModel):
    """Schema for metadata-driven compliance intelligence evaluation response."""

    assessment_id: str
    metadata_profile_id: str
    framework: str
    policy_version: str
    evaluated_at: datetime
    total_rules: int
    passed: int
    failed: int
    persistence_enabled: bool = False
    persisted_findings: int = 0
    persisted_rule_ids: list[str] = Field(default_factory=list)
    resolved_findings: int = 0  # Number of findings auto-resolved when rules now pass
    results: list[ComplianceRuleResult]


# Health check
class HealthResponse(BaseModel):
    """Schema for health check response."""

    status: str
    version: str
    environment: str


# Remediation Roadmap schemas
class RoadmapItem(BaseModel):
    """Schema for a single remediation action."""

    finding_id: str
    control_id: str
    title: str
    severity: str
    cvss_score: float | None = None
    priority_window: str
    owner: str | None = None
    remediation_guidance: str
    cve_ids: list[str] | None = None
    cwe_ids: list[str] | None = None


class RoadmapSummary(BaseModel):
    """Executive summary of remediation roadmap."""

    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    immediate_actions: int
    thirty_day_actions: int
    quarterly_actions: int
    annual_actions: int


class RemediationRoadmapResponse(BaseModel):
    """Schema for remediation roadmap response."""

    assessment_id: str
    organization_id: str
    generated_at: datetime
    summary: RoadmapSummary
    immediate: list[RoadmapItem]
    thirty_days: list[RoadmapItem]
    quarterly: list[RoadmapItem]
    annual: list[RoadmapItem]
