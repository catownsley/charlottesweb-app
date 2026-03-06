"""Pydantic schemas for API request/response validation."""
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


# Organization schemas
class OrganizationCreate(BaseModel):
    """Schema for creating an organization."""

    name: str = Field(..., min_length=1, max_length=255)
    industry: Optional[str] = None
    stage: Optional[str] = None


class OrganizationResponse(BaseModel):
    """Schema for organization response."""

    id: str
    name: str
    industry: Optional[str] = None
    stage: Optional[str] = None
    created_at: datetime

    model_config = {"from_attributes": True}


# Metadata Profile schemas
class MetadataProfileCreate(BaseModel):
    """Schema for creating a metadata profile."""

    organization_id: str
    phi_types: Optional[list[str]] = None
    cloud_provider: Optional[str] = None
    infrastructure: Optional[dict[str, Any]] = None
    applications: Optional[dict[str, Any]] = None
    access_controls: Optional[dict[str, Any]] = None
    software_stack: Optional[dict[str, Any]] = None


class MetadataProfileResponse(BaseModel):
    """Schema for metadata profile response."""

    id: str
    organization_id: str
    phi_types: Optional[list[str]] = None
    cloud_provider: Optional[str] = None
    infrastructure: Optional[dict[str, Any]] = None
    applications: Optional[dict[str, Any]] = None
    access_controls: Optional[dict[str, Any]] = None
    software_stack: Optional[dict[str, Any]] = None
    version: str
    created_at: datetime

    model_config = {"from_attributes": True}


# Control schemas
class ControlResponse(BaseModel):
    """Schema for control response."""

    id: str
    framework: str
    title: str
    requirement: str
    category: Optional[str] = None
    evidence_types: Optional[list[str]] = None

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
    completed_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


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
    breach_example: Optional[ThreatTechniqueBreachExample] = None
    primary_mitigation: Optional[ThreatTechniqueMitigation] = None


class ThreatContext(BaseModel):
    """Schema for threat intelligence context added to findings."""

    techniques: list[ThreatTechnique] = Field(description="Attack techniques that exploit this gap")
    summary: str = Field(description="Executive summary of threat")


# Finding schemas
class FindingResponse(BaseModel):
    """Schema for finding response."""

    id: str
    assessment_id: str
    control_id: Optional[str] = None
    title: str
    description: str
    severity: str
    cvss_score: Optional[float] = None
    external_id: Optional[str] = None
    cve_ids: Optional[list[str]] = None
    cwe_ids: Optional[list[str]] = None
    remediation_guidance: Optional[str] = None
    priority_window: Optional[str] = None
    owner: Optional[str] = None
    created_at: datetime
    threat_context: Optional[ThreatContext] = Field(
        None, description="Real-world threat intelligence (MITRE ATT&CK)"
    )

    model_config = {"from_attributes": True}


# Evidence schemas
class EvidenceCreate(BaseModel):
    """Schema for creating evidence."""

    control_id: str
    assessment_id: Optional[str] = None
    evidence_type: str  # policy, config, screenshot, logs, report, etc.
    title: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    owner: Optional[str] = None
    due_date: Optional[datetime] = None


class EvidenceUpdate(BaseModel):
    """Schema for updating evidence."""

    status: Optional[str] = None  # not_started, in_progress, completed, not_applicable
    owner: Optional[str] = None
    due_date: Optional[datetime] = None
    artifact_path: Optional[str] = None
    artifact_url: Optional[str] = None
    artifact_hash: Optional[str] = None
    collected_at: Optional[datetime] = None  # when evidence was actually collected
    notes: Optional[str] = None


class EvidenceResponse(BaseModel):
    """Schema for evidence response."""

    id: str
    control_id: str
    assessment_id: Optional[str] = None
    evidence_type: str
    title: str
    description: Optional[str] = None
    status: str
    owner: Optional[str] = None
    due_date: Optional[datetime] = None
    artifact_path: Optional[str] = None
    artifact_url: Optional[str] = None
    artifact_hash: Optional[str] = None
    uploaded_at: Optional[datetime] = None
    collected_at: Optional[datetime] = None
    version: str
    notes: Optional[str] = None
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
    owner: Optional[str] = None
    due_date: Optional[datetime] = None
    collected_at: Optional[datetime] = None
    notes: Optional[str] = None
    evidence_id: Optional[str] = None


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
    """Schema for a single compliance-as-code rule evaluation result."""

    rule_id: str
    control_id: str
    title: str
    description: Optional[str] = None
    path: str
    operator: str
    expected: Any
    actual: Any = None
    status: str
    severity_on_fail: str


class ComplianceAsCodeResponse(BaseModel):
    """Schema for metadata-driven compliance-as-code evaluation response."""

    assessment_id: str
    metadata_profile_id: str
    framework: str
    policy_version: str
    evaluated_at: datetime
    total_rules: int
    passed: int
    failed: int
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
    cvss_score: Optional[float] = None
    priority_window: str
    owner: Optional[str] = None
    remediation_guidance: str
    cve_ids: Optional[list[str]] = None
    cwe_ids: Optional[list[str]] = None


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
