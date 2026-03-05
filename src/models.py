"""Database models for CharlottesWeb."""
from datetime import datetime
from typing import Optional
from uuid import uuid4

from sqlalchemy import JSON, Column, DateTime, Float, ForeignKey, String, Text
from sqlalchemy.orm import relationship

from src.database import Base


def generate_uuid() -> str:
    """Generate a UUID string."""
    return str(uuid4())


class Organization(Base):
    """Organization entity."""

    __tablename__ = "organizations"

    id = Column(String, primary_key=True, default=generate_uuid)
    name = Column(String, nullable=False)
    industry = Column(String, nullable=True)
    stage = Column(String, nullable=True)  # seed, series_a, series_b, etc.
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    metadata_profiles = relationship("MetadataProfile", back_populates="organization")
    assessments = relationship("Assessment", back_populates="organization")


class MetadataProfile(Base):
    """Metadata profile - architectural metadata (no PHI)."""

    __tablename__ = "metadata_profiles"

    id = Column(String, primary_key=True, default=generate_uuid)
    organization_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    
    # Metadata fields (stored as JSON for flexibility)
    phi_types = Column(JSON, nullable=True)  # list of PHI categories
    cloud_provider = Column(String, nullable=True)  # aws, azure, gcp
    infrastructure = Column(JSON, nullable=True)  # services used
    applications = Column(JSON, nullable=True)  # app stack details
    access_controls = Column(JSON, nullable=True)  # auth/authz model
    software_stack = Column(JSON, nullable=True)  # technology stack with versions
    
    version = Column(String, default="1", nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    organization = relationship("Organization", back_populates="metadata_profiles")
    assessments = relationship("Assessment", back_populates="metadata_profile")


class Control(Base):
    """HIPAA/regulatory control."""

    __tablename__ = "controls"

    id = Column(String, primary_key=True)  # e.g., "HIPAA.164.312(a)(1)"
    framework = Column(String, nullable=False)  # e.g., "HIPAA_Security_Rule"
    title = Column(String, nullable=False)
    requirement = Column(Text, nullable=False)
    category = Column(String, nullable=True)  # Administrative, Physical, Technical
    evidence_types = Column(JSON, nullable=True)  # list of required evidence
    
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    findings = relationship("Finding", back_populates="control")


class Assessment(Base):
    """Compliance assessment run."""

    __tablename__ = "assessments"

    id = Column(String, primary_key=True, default=generate_uuid)
    organization_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    metadata_profile_id = Column(String, ForeignKey("metadata_profiles.id"), nullable=False)
    
    status = Column(String, default="pending", nullable=False)  # pending, running, completed, failed
    initiated_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)

    # Relationships
    organization = relationship("Organization", back_populates="assessments")
    metadata_profile = relationship("MetadataProfile", back_populates="assessments")
    findings = relationship("Finding", back_populates="assessment")


class Finding(Base):
    """Compliance finding (gap or risk)."""

    __tablename__ = "findings"

    id = Column(String, primary_key=True, default=generate_uuid)
    assessment_id = Column(String, ForeignKey("assessments.id"), nullable=False)
    control_id = Column(String, ForeignKey("controls.id"), nullable=True)  # nullable for NVD findings
    
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String, nullable=False)  # immediate, high, medium, low
    cvss_score = Column(Float, nullable=True)
    external_id = Column(String, nullable=True)  # CVE ID for NVD findings
    cve_ids = Column(JSON, nullable=True)  # list of CVE IDs
    cwe_ids = Column(JSON, nullable=True)  # list of CWE IDs
    
    remediation_guidance = Column(Text, nullable=True)
    priority_window = Column(String, nullable=True)  # immediate, 30_days, quarterly, annual
    owner = Column(String, nullable=True)  # DevOps, Engineering, Security
    
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    assessment = relationship("Assessment", back_populates="findings")
    control = relationship("Control", back_populates="findings")
