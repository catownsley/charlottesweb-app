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


# Finding schemas
class FindingResponse(BaseModel):
    """Schema for finding response."""

    id: str
    assessment_id: str
    control_id: str
    title: str
    description: str
    severity: str
    cvss_score: Optional[float] = None
    cve_ids: Optional[list[str]] = None
    cwe_ids: Optional[list[str]] = None
    remediation_guidance: Optional[str] = None
    priority_window: Optional[str] = None
    owner: Optional[str] = None
    created_at: datetime

    model_config = {"from_attributes": True}


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
