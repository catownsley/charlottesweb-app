"""Database models for CharlottesWeb."""

from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import JSON, Column, DateTime, Float, ForeignKey, Index, String, Text
from sqlalchemy.orm import relationship

from src.database import Base


def generate_uuid() -> str:
    """Generate a UUID string."""
    return str(uuid4())


def utcnow() -> datetime:
    """Return current UTC time with timezone info.

    Returns timezone-aware datetime to prevent ambiguity in conversions.
    SQLAlchemy stores as naive datetime but we can compare and convert safely.
    """
    return datetime.now(UTC)


class Organization(Base):
    """Organization entity."""

    __tablename__ = "organizations"

    id = Column(String, primary_key=True, default=generate_uuid)
    name = Column(String, nullable=False)
    industry = Column(String, nullable=True)
    stage = Column(String, nullable=True)  # seed, series_a, series_b, etc.
    created_at = Column(DateTime, default=utcnow, nullable=False)

    # Relationships
    metadata_profiles = relationship("MetadataProfile", back_populates="organization")
    assessments = relationship("Assessment", back_populates="organization")
    members = relationship("OrganizationMember", back_populates="organization")


class OrganizationMember(Base):
    """Organization member used for onboarding and role assignment."""

    __tablename__ = "organization_members"

    id = Column(String, primary_key=True, default=generate_uuid)
    organization_id = Column(
        String, ForeignKey("organizations.id"), nullable=False, index=True
    )
    email = Column(String, nullable=False)
    full_name = Column(String, nullable=True)
    role = Column(String, nullable=False, default="member", index=True)  # admin, member
    created_at = Column(DateTime, default=utcnow, nullable=False)

    # Relationships
    organization = relationship("Organization", back_populates="members")

    __table_args__ = (
        Index("idx_org_members_org_id", "organization_id"),
        Index("idx_org_members_role", "role"),
    )


class MetadataProfile(Base):
    """Metadata profile - architectural metadata (no PHI)."""

    __tablename__ = "metadata_profiles"

    id = Column(String, primary_key=True, default=generate_uuid)
    organization_id = Column(
        String, ForeignKey("organizations.id"), nullable=False, index=True
    )

    # Metadata fields (stored as JSON for flexibility)
    phi_types = Column(JSON, nullable=True)  # list of PHI categories
    cloud_provider = Column(String, nullable=True)  # aws, azure, gcp
    infrastructure = Column(JSON, nullable=True)  # services used
    applications = Column(JSON, nullable=True)  # app stack details
    access_controls = Column(JSON, nullable=True)  # auth/authz model
    software_stack = Column(JSON, nullable=True)  # technology stack with versions

    version = Column(String, default="1", nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    # Relationships
    organization = relationship("Organization", back_populates="metadata_profiles")
    assessments = relationship("Assessment", back_populates="metadata_profile")

    # Indexes for query performance
    __table_args__ = (
        Index("idx_metadata_profiles_org_id", "organization_id"),
        Index("idx_metadata_profiles_created_at", "created_at"),
    )


class Framework(Base):
    """Regulatory framework (e.g., HIPAA, NIST 800-53, GDPR)."""

    __tablename__ = "frameworks"

    id = Column(String, primary_key=True, default=generate_uuid)
    code = Column(String, nullable=False, unique=True, index=True)
    name = Column(String, nullable=False)
    version = Column(String, nullable=True)
    jurisdiction = Column(String, nullable=True)  # US, EU, AU, US-CA
    source_url = Column(String, nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    # Relationships
    requirements = relationship("FrameworkRequirement", back_populates="framework")


class Control(Base):
    """Canonical security control that maps to requirements across frameworks."""

    __tablename__ = "controls"

    id = Column(String, primary_key=True)  # e.g., "HIPAA.164.312(a)(1)"
    framework = Column(String, nullable=False)  # kept for backward compatibility
    title = Column(String, nullable=False)
    requirement = Column(Text, nullable=False)
    category = Column(String, nullable=True)  # Administrative, Physical, Technical
    evidence_types = Column(JSON, nullable=True)  # list of required evidence

    # Multi-framework support
    canonical_concept = Column(String, nullable=True)  # e.g., "Encryption at Rest"
    source = Column(String, nullable=True, default="seed")  # seed, nist_api, manual
    source_id = Column(String, nullable=True)  # external ID from source system

    created_at = Column(DateTime, default=utcnow, nullable=False)

    # Relationships
    findings = relationship("Finding", back_populates="control")
    framework_requirements = relationship(
        "FrameworkRequirement", back_populates="control"
    )


class FrameworkRequirement(Base):
    """Maps a canonical control to a specific framework citation."""

    __tablename__ = "framework_requirements"

    id = Column(String, primary_key=True, default=generate_uuid)
    control_id = Column(String, ForeignKey("controls.id"), nullable=False, index=True)
    framework_id = Column(
        String, ForeignKey("frameworks.id"), nullable=False, index=True
    )

    citation = Column(String, nullable=False)  # e.g., "SC-28", "Art. 32(1)(a)"
    citation_title = Column(String, nullable=True)
    citation_url = Column(String, nullable=True)
    baseline = Column(String, nullable=True)  # FedRAMP: Low/Moderate/High
    required = Column(String, default="true", nullable=False)

    created_at = Column(DateTime, default=utcnow, nullable=False)

    # Relationships
    control = relationship("Control", back_populates="framework_requirements")
    framework = relationship("Framework", back_populates="requirements")

    __table_args__ = (
        Index("idx_fr_control_id", "control_id"),
        Index("idx_fr_framework_id", "framework_id"),
        Index("idx_fr_control_framework", "control_id", "framework_id"),
    )


class Assessment(Base):
    """Compliance assessment run."""

    __tablename__ = "assessments"

    id = Column(String, primary_key=True, default=generate_uuid)
    organization_id = Column(
        String, ForeignKey("organizations.id"), nullable=False, index=True
    )
    metadata_profile_id = Column(
        String, ForeignKey("metadata_profiles.id"), nullable=False, index=True
    )

    status = Column(
        String, default="pending", nullable=False, index=True
    )  # pending, running, completed, failed
    initiated_at = Column(DateTime, default=utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)

    # Relationships
    organization = relationship("Organization", back_populates="assessments")
    metadata_profile = relationship("MetadataProfile", back_populates="assessments")
    findings = relationship("Finding", back_populates="assessment")

    # Indexes for query performance
    __table_args__ = (
        Index("idx_assessments_org_id", "organization_id"),
        Index("idx_assessments_profile_id", "metadata_profile_id"),
        Index("idx_assessments_status", "status"),
        Index("idx_assessments_created_at", "initiated_at"),
    )


class Finding(Base):
    """Compliance finding (gap or risk)."""

    __tablename__ = "findings"

    id = Column(String, primary_key=True, default=generate_uuid)
    assessment_id = Column(
        String, ForeignKey("assessments.id"), nullable=False, index=True
    )
    control_id = Column(
        String, ForeignKey("controls.id"), nullable=True, index=True
    )  # nullable for NVD findings

    title = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(
        String, nullable=False, index=True
    )  # immediate, high, medium, low
    cvss_score = Column(Float, nullable=True)
    external_id = Column(String, nullable=True)  # CVE ID for NVD findings
    cve_ids = Column(JSON, nullable=True)  # list of CVE IDs
    cwe_ids = Column(JSON, nullable=True)  # list of CWE IDs

    remediation_guidance = Column(Text, nullable=True)
    priority_window = Column(
        String, nullable=True
    )  # immediate, 30_days, quarterly, annual
    owner = Column(String, nullable=True)  # DevOps, Engineering, Security

    created_at = Column(DateTime, default=utcnow, nullable=False)

    # Relationships
    assessment = relationship("Assessment", back_populates="findings")
    control = relationship("Control", back_populates="findings")

    # Indexes for query performance
    __table_args__ = (
        Index("idx_findings_assessment_id", "assessment_id"),
        Index("idx_findings_control_id", "control_id"),
        Index("idx_findings_severity", "severity"),
        Index("idx_findings_created_at", "created_at"),
    )


class Evidence(Base):
    """Evidence artifact for audit compliance."""

    __tablename__ = "evidence"

    id = Column(String, primary_key=True, default=generate_uuid)
    control_id = Column(String, ForeignKey("controls.id"), nullable=False, index=True)
    assessment_id = Column(
        String, ForeignKey("assessments.id"), nullable=True, index=True
    )

    # Evidence classification
    evidence_type = Column(
        String, nullable=False
    )  # policy, config, screenshot, logs, etc.
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)

    # Status tracking
    status = Column(
        String, default="not_started", nullable=False, index=True
    )  # not_started, in_progress, completed, not_applicable
    owner = Column(String, nullable=True)  # responsible party
    due_date = Column(DateTime, nullable=True)

    # Artifact metadata
    artifact_path = Column(String, nullable=True)  # file storage path
    artifact_url = Column(String, nullable=True)  # external URL if applicable
    artifact_hash = Column(String, nullable=True)  # SHA256 for integrity
    uploaded_at = Column(DateTime, nullable=True)
    collected_at = Column(
        DateTime, nullable=True
    )  # when evidence was actually collected

    # Versioning
    version = Column(String, default="1", nullable=False)
    previous_version_id = Column(String, nullable=True)  # self-referential for history

    # Metadata
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    # Relationships
    control = relationship("Control")
    assessment = relationship("Assessment")

    # Indexes for query performance
    __table_args__ = (
        Index("idx_evidence_control_id", "control_id"),
        Index("idx_evidence_assessment_id", "assessment_id"),
        Index("idx_evidence_status", "status"),
        Index("idx_evidence_created_at", "created_at"),
    )
