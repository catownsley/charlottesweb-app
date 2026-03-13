"""Tests for AI-powered threat model generation."""

import json
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.database import Base, get_db
from src.main import app
from src.models import Assessment, Control, Finding, MetadataProfile, Organization


# --- Sample AI response matching the expected schema ---

SAMPLE_AI_RESPONSE = {
    "executive_summary": (
        "This healthcare application handles PHI on AWS infrastructure with a "
        "FastAPI backend and PostgreSQL database. The primary risks are "
        "insufficient access controls at the organization boundary and outdated "
        "dependencies with known vulnerabilities. Immediate priorities are "
        "implementing per-org authentication and updating vulnerable libraries."
    ),
    "stride_analysis": [
        {
            "category": "Spoofing",
            "threat": "API callers can access any organization's data by guessing org IDs",
            "affected_component": "API authentication layer",
            "severity": "CRITICAL",
            "mitigation": (
                "Implement per-user authentication with org membership verification. "
                "Add OrganizationMember lookup before every org-scoped query."
            ),
        },
        {
            "category": "Information Disclosure",
            "threat": "PHI data transmitted without encryption validation",
            "affected_component": "Database connection / API transport",
            "severity": "HIGH",
            "mitigation": (
                "Enforce TLS 1.2+ on all database connections. "
                "Add HSTS header with minimum 1-year max-age."
            ),
        },
        {
            "category": "Denial of Service",
            "threat": "Rate limiting is IP-based only; shared IPs bypass limits",
            "affected_component": "Rate limiting middleware",
            "severity": "MEDIUM",
            "mitigation": (
                "Add per-API-key rate limits (500 req/min). "
                "Implement adaptive rate limiting for repeated violations."
            ),
        },
    ],
    "dependency_finding": {
        "summary": (
            "2 components have known vulnerabilities. "
            "Highest severity is HIGH (CVSS 7.5)."
        ),
        "affected_count": 2,
        "highest_severity": "HIGH",
        "remediation": "Update all affected dependencies to their latest patched versions.",
        "details": [
            {
                "component": "PyJWT",
                "current_version": "2.4.0",
                "cve_ids": ["CVE-2024-23342"],
                "fix_available": True,
                "action": "Upgrade PyJWT from 2.4.0 to 2.11.0",
            },
            {
                "component": "requests",
                "current_version": "2.28.0",
                "cve_ids": ["CVE-2023-32681"],
                "fix_available": True,
                "action": "Upgrade requests from 2.28.0 to 2.32.5",
            },
        ],
    },
    "compound_risks": [
        {
            "vulnerability": "CVE-2024-23342",
            "architectural_threat": "API callers can access any organization's data",
            "escalation": (
                "PyJWT vulnerability allows algorithm confusion attacks. Combined "
                "with missing org-level auth, an attacker could forge tokens to "
                "access any organization's PHI data."
            ),
            "adjusted_severity": "CRITICAL",
            "mitigation": (
                "Upgrade PyJWT immediately AND implement org membership checks. "
                "Neither fix alone is sufficient."
            ),
        }
    ],
    "remediation_roadmap": [
        {
            "priority": 1,
            "action": "Implement per-user authentication with org membership verification",
            "rationale": "Addresses the CRITICAL spoofing and elevation of privilege threats",
        },
        {
            "priority": 2,
            "action": "Update PyJWT to 2.11.0 and requests to 2.32.5",
            "rationale": "Resolves known CVEs and eliminates the compound risk with auth",
        },
        {
            "priority": 3,
            "action": "Add per-API-key rate limiting",
            "rationale": "Prevents abuse from shared IP addresses",
        },
    ],
}


@pytest.fixture(scope="function")
def test_db(tmp_path):
    """Create a test database with seeded data."""
    db_file = tmp_path / "test_ai_tm.db"
    test_db_url = f"sqlite:///{db_file}"

    engine = create_engine(test_db_url, connect_args={"check_same_thread": False})
    testing_session_local = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    Base.metadata.create_all(bind=engine)

    db = testing_session_local()

    # Seed an organization
    org = Organization(id="org-1", name="Test Health Co", industry="digital_health")
    db.add(org)

    # Seed controls
    ctrl = Control(
        id="HIPAA.164.312(a)(1)",
        framework="HIPAA_Security_Rule",
        title="Access Control",
        requirement="Implement technical policies for access to ePHI",
        category="Technical Safeguards",
    )
    db.add(ctrl)

    # Seed metadata profile
    profile = MetadataProfile(
        id="profile-1",
        organization_id="org-1",
        phi_types=["patient_name", "medical_record"],
        cloud_provider="aws",
        software_stack={
            "FastAPI": {"version": "0.135.1"},
            "PyJWT": {"version": "2.4.0"},
            "PostgreSQL": {"version": "15.2"},
        },
        access_controls={"mfa_enabled": False, "auth_type": "api_key"},
    )
    db.add(profile)

    # Seed a completed assessment
    assessment = Assessment(
        id="assess-1",
        organization_id="org-1",
        metadata_profile_id="profile-1",
        status="completed",
    )
    db.add(assessment)

    # Seed findings
    findings = [
        Finding(
            id="f-1",
            assessment_id="assess-1",
            control_id="HIPAA.164.312(a)(1)",
            title="Missing multi-factor authentication",
            description="MFA is not enabled for user access",
            severity="high",
            cwe_ids=["CWE-308"],
            remediation_guidance="Enable MFA for all user accounts",
        ),
        Finding(
            id="f-2",
            assessment_id="assess-1",
            title="PyJWT vulnerability CVE-2024-23342",
            description="Algorithm confusion in PyJWT allows token forgery",
            severity="high",
            cvss_score=7.5,
            cve_ids=["CVE-2024-23342"],
            cwe_ids=["CWE-347"],
            remediation_guidance="Upgrade PyJWT to >= 2.8.0",
        ),
    ]
    for f in findings:
        db.add(f)

    db.commit()
    db.close()

    def override_get_db():
        try:
            session = testing_session_local()
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_get_db
    yield engine
    Base.metadata.drop_all(bind=engine)
    app.dependency_overrides.clear()


@pytest.fixture
def client(test_db):
    return TestClient(app)


def _mock_stream_response(sample_data: dict):
    """Create a mock that simulates the streaming context manager."""
    mock_text_block = MagicMock()
    mock_text_block.type = "text"
    mock_text_block.text = json.dumps(sample_data)

    mock_message = MagicMock()
    mock_message.content = [mock_text_block]

    mock_stream = MagicMock()
    mock_stream.get_final_message.return_value = mock_message
    mock_stream.__enter__ = MagicMock(return_value=mock_stream)
    mock_stream.__exit__ = MagicMock(return_value=False)

    return mock_stream


class TestAIThreatModelService:
    """Tests for the AI threat model service logic."""

    @patch("src.ai_threat_model_service.settings")
    @patch("src.ai_threat_model_service.anthropic.Anthropic")
    def test_generate_ai_threat_model(self, mock_anthropic_cls, mock_settings, test_db):
        """Test that the service produces a structured threat model."""
        from sqlalchemy.orm import sessionmaker

        Session = sessionmaker(bind=test_db)
        db = Session()

        mock_settings.anthropic_api_key = "test-key"
        mock_settings.anthropic_model = "claude-sonnet-4-6"

        mock_client = MagicMock()
        mock_anthropic_cls.return_value = mock_client
        mock_client.messages.stream.return_value = _mock_stream_response(
            SAMPLE_AI_RESPONSE
        )

        from src.ai_threat_model_service import generate_ai_threat_model

        result = generate_ai_threat_model(db=db, organization_id="org-1")

        assert "executive_summary" in result
        assert "stride_analysis" in result
        assert "dependency_finding" in result
        assert "compound_risks" in result
        assert "remediation_roadmap" in result
        assert "metadata" in result

        # STRIDE analysis should have threats
        assert len(result["stride_analysis"]) == 3
        assert result["stride_analysis"][0]["category"] == "Spoofing"
        assert result["stride_analysis"][0]["severity"] == "CRITICAL"

        # Dependency finding is consolidated (one entry, not per-CVE)
        dep = result["dependency_finding"]
        assert dep["affected_count"] == 2
        assert dep["highest_severity"] == "HIGH"
        assert len(dep["details"]) == 2

        # Compound risks only where meaningful
        assert len(result["compound_risks"]) == 1
        assert "CVE-2024-23342" in result["compound_risks"][0]["vulnerability"]

        # Remediation roadmap is prioritized
        assert result["remediation_roadmap"][0]["priority"] == 1

        # Metadata attached
        assert result["metadata"]["organization_id"] == "org-1"
        assert result["metadata"]["findings_analyzed"] == 2

        db.close()

    @patch("src.ai_threat_model_service.settings")
    def test_missing_api_key_raises(self, mock_settings, test_db):
        """Test that missing API key raises a clear error."""
        from sqlalchemy.orm import sessionmaker

        Session = sessionmaker(bind=test_db)
        db = Session()

        mock_settings.anthropic_api_key = ""

        from src.ai_threat_model_service import generate_ai_threat_model

        with pytest.raises(ValueError, match="ANTHROPIC_API_KEY"):
            generate_ai_threat_model(db=db, organization_id="org-1")

        db.close()

    @patch("src.ai_threat_model_service.settings")
    def test_no_assessment_raises(self, mock_settings, test_db):
        """Test error when no assessment exists for org."""
        from sqlalchemy.orm import sessionmaker

        Session = sessionmaker(bind=test_db)
        db = Session()

        mock_settings.anthropic_api_key = "test-key"

        from src.ai_threat_model_service import generate_ai_threat_model

        with pytest.raises(ValueError, match="No completed assessment"):
            generate_ai_threat_model(db=db, organization_id="nonexistent-org")

        db.close()


class TestAIThreatModelEndpoint:
    """Tests for the API endpoint."""

    @patch("src.ai_threat_model_service.settings")
    @patch("src.ai_threat_model_service.anthropic.Anthropic")
    def test_endpoint_returns_threat_model(
        self, mock_anthropic_cls, mock_settings, client
    ):
        """Test the /threat-model/ai/organizations/{id} endpoint."""
        mock_settings.anthropic_api_key = "test-key"
        mock_settings.anthropic_model = "claude-sonnet-4-6"

        mock_client = MagicMock()
        mock_anthropic_cls.return_value = mock_client
        mock_client.messages.stream.return_value = _mock_stream_response(
            SAMPLE_AI_RESPONSE
        )

        response = client.get("/api/v1/threat-model/ai/organizations/org-1")
        assert response.status_code == 200

        data = response.json()
        assert "executive_summary" in data
        assert "stride_analysis" in data
        assert "dependency_finding" in data
        assert "compound_risks" in data
        assert "remediation_roadmap" in data

    @patch("src.ai_threat_model_service.settings")
    def test_endpoint_503_without_api_key(self, mock_settings, client):
        """Test that missing API key returns 503."""
        mock_settings.anthropic_api_key = ""

        response = client.get("/api/v1/threat-model/ai/organizations/org-1")
        assert response.status_code == 503
        assert "ANTHROPIC_API_KEY" in response.json()["detail"]

    def test_endpoint_404_bad_org(self, client):
        """Test that nonexistent org returns 404."""
        with patch("src.ai_threat_model_service.settings") as mock_settings:
            mock_settings.anthropic_api_key = "test-key"

            response = client.get("/api/v1/threat-model/ai/organizations/nonexistent")
            assert response.status_code == 404
