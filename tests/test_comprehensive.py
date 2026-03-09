"""Comprehensive tests for CharlottesWeb API - Phase 3 test coverage expansion."""

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.database import Base, get_db
from src.main import app
from src.models import (
    Control,
)


@pytest.fixture(scope="function")
def test_db(tmp_path):
    """Create a test database with comprehensive seeding."""
    db_file = tmp_path / "test.db"
    test_db_url = f"sqlite:///{db_file}"

    engine = create_engine(test_db_url, connect_args={"check_same_thread": False})
    testing_session_local = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    Base.metadata.create_all(bind=engine)

    # Seed controls comprehensively
    db = testing_session_local()
    controls = [
        Control(
            id="HIPAA.164.312(a)(1)",
            framework="HIPAA_Security_Rule",
            title="Access Control",
            requirement="Establish and implement policies and procedures",
            category="Technical Safeguards",
            evidence_types=["policy_document", "system_configuration"],
        ),
        Control(
            id="HIPAA.164.312(a)(2)(i)",
            framework="HIPAA_Security_Rule",
            title="Encryption and Decryption",
            requirement="Implement encryption and decryption mechanisms",
            category="Technical Safeguards",
            evidence_types=["infrastructure_audit", "certificate"],
        ),
        Control(
            id="HIPAA.164.312(b)",
            framework="HIPAA_Security_Rule",
            title="Audit Controls",
            requirement="Implement hardware, software, and procedural mechanisms",
            category="Technical Safeguards",
            evidence_types=["audit_log", "monitoring_dashboard"],
        ),
        Control(
            id="HIPAA.164.312(a)(2)(iii)",
            framework="HIPAA_Security_Rule",
            title="Transmission Security",
            requirement="Implement security measures for data in transit",
            category="Technical Safeguards",
            evidence_types=["network_diagram", "certificate"],
        ),
    ]
    for c in controls:
        db.add(c)
    db.commit()
    db.close()

    def override_get_db():
        try:
            db = testing_session_local()
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    yield engine

    Base.metadata.drop_all(bind=engine)
    app.dependency_overrides.clear()


@pytest.fixture(scope="function")
def client(test_db):
    """Create test client."""
    return TestClient(app)


@pytest.fixture(scope="function")
def org_data(client):
    """Create and return test organization."""
    response = client.post(
        "/api/v1/organizations",
        json={
            "name": "Test Healthcare Org",
            "industry": "digital_health",
            "stage": "growth",
        },
    )
    assert response.status_code == 201
    return response.json()


@pytest.fixture(scope="function")
def metadata_profile_data(client, org_data):
    """Create and return test metadata profile."""
    response = client.post(
        "/api/v1/metadata-profiles",
        json={
            "organization_id": org_data["id"],
            "phi_types": ["demographic", "clinical", "genetic"],
            "cloud_provider": "aws",
            "infrastructure": {
                "encryption_at_rest": True,
                "tls_enabled": True,
                "logging_enabled": True,
            },
            "access_controls": {
                "mfa_enabled": True,
                "rbac_enabled": True,
            },
            "software_stack": {
                "postgres": "15",
                "nodejs": "20",
                "python": "3.11",
            },
        },
    )
    assert response.status_code == 201
    return response.json()


# ========== Organization Tests ==========


class TestOrganizations:
    """Organization CRUD tests."""

    def test_create_organization(self, client):
        """Test successful organization creation."""
        response = client.post(
            "/api/v1/organizations",
            json={"name": "NewOrg", "industry": "healthcare", "stage": "seed"},
        )
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "NewOrg"
        assert data["industry"] == "healthcare"
        assert "id" in data
        assert "created_at" in data

    def test_create_organization_minimal(self, client):
        """Test organization creation with minimal fields."""
        response = client.post(
            "/api/v1/organizations",
            json={"name": "MinOrg"},
        )
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "MinOrg"

    def test_get_organization(self, client, org_data):
        """Test retrieving organization by ID."""
        response = client.get(f"/api/v1/organizations/{org_data['id']}")
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == org_data["id"]
        assert data["name"] == org_data["name"]

    def test_get_organization_not_found(self, client):
        """Test 404 when organization does not exist."""
        response = client.get("/api/v1/organizations/nonexistent-id")
        assert response.status_code == 404

    def test_onboard_organization_with_member_role(self, client):
        """Test onboarding endpoint supports valid role values."""
        response = client.post(
            "/api/v1/organizations/onboard",
            json={
                "name": "Role Test Org",
                "industry": "healthcare",
                "stage": "growth",
                "admin_email": "member@example.com",
                "admin_name": "Member User",
                "admin_role": "member",
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["organization"]["name"] == "Role Test Org"
        assert data["member"]["role"] == "member"

    def test_onboard_organization_invalid_role(self, client):
        """Test onboarding rejects invalid role values."""
        response = client.post(
            "/api/v1/organizations/onboard",
            json={
                "name": "Invalid Role Org",
                "admin_email": "admin@example.com",
                "admin_role": "owner",
            },
        )
        assert response.status_code == 422


# ========== Metadata Profile Tests ==========


class TestMetadataProfiles:
    """Metadata profile CRUD tests."""

    def test_create_metadata_profile(self, client, org_data):
        """Test successful metadata profile creation."""
        response = client.post(
            "/api/v1/metadata-profiles",
            json={
                "organization_id": org_data["id"],
                "phi_types": ["demographic", "clinical"],
                "cloud_provider": "gcp",
                "infrastructure": {"encryption_at_rest": True},
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["organization_id"] == org_data["id"]
        assert "demographic" in data["phi_types"]

    def test_create_profile_nonexistent_org(self, client):
        """Test 404 when organization does not exist."""
        response = client.post(
            "/api/v1/metadata-profiles",
            json={
                "organization_id": "nonexistent",
                "phi_types": ["demographic"],
            },
        )
        assert response.status_code == 404

    def test_get_metadata_profile(self, client, metadata_profile_data):
        """Test retrieving metadata profile."""
        response = client.get(
            f"/api/v1/metadata-profiles/{metadata_profile_data['id']}"
        )
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == metadata_profile_data["id"]

    def test_get_metadata_profile_not_found(self, client):
        """Test 404 when metadata profile does not exist."""
        response = client.get("/api/v1/metadata-profiles/nonexistent")
        assert response.status_code == 404


# ========== Control Tests ==========


class TestControls:
    """Control listing and retrieval tests."""

    def test_list_controls(self, client):
        """Test listing all controls."""
        response = client.get("/api/v1/controls")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) == 4  # We seeded 4 controls

    def test_get_control(self, client):
        """Test retrieving specific control."""
        response = client.get("/api/v1/controls/HIPAA.164.312(a)(1)")
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == "HIPAA.164.312(a)(1)"
        assert data["title"] == "Access Control"

    def test_get_control_not_found(self, client):
        """Test 404 when control does not exist."""
        response = client.get("/api/v1/controls/nonexistent")
        assert response.status_code == 404


# ========== Assessment Tests ==========


class TestAssessments:
    """Assessment workflow tests."""

    def test_create_assessment(self, client, org_data, metadata_profile_data):
        """Test creating assessment."""
        response = client.post(
            "/api/v1/assessments",
            json={
                "organization_id": org_data["id"],
                "metadata_profile_id": metadata_profile_data["id"],
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["status"] == "completed"

    def test_get_assessment_status_not_found(self, client):
        """Test assessment status endpoint returns 404 for unknown assessment."""
        response = client.get("/api/v1/assessments/nonexistent-assessment/status")
        assert response.status_code == 404

    def test_create_assessment_incomplete_gaps(self, client, org_data):
        """Test assessment with security gaps."""
        # Create profile with gaps
        profile_response = client.post(
            "/api/v1/metadata-profiles",
            json={
                "organization_id": org_data["id"],
                "phi_types": ["demographic"],
                "cloud_provider": "aws",
                "infrastructure": {
                    "encryption_at_rest": False,
                    "tls_enabled": False,
                    "logging_enabled": False,
                },
                "access_controls": {"mfa_enabled": False},
            },
        )
        profile_id = profile_response.json()["id"]

        # Run assessment
        response = client.post(
            "/api/v1/assessments",
            json={
                "organization_id": org_data["id"],
                "metadata_profile_id": profile_id,
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["status"] == "completed"

    def test_create_assessment_nonexistent_org(self, client, metadata_profile_data):
        """Test 404 when organization does not exist."""
        response = client.post(
            "/api/v1/assessments",
            json={
                "organization_id": "nonexistent",
                "metadata_profile_id": metadata_profile_data["id"],
            },
        )
        assert response.status_code == 404

    def test_create_assessment_nonexistent_profile(self, client, org_data):
        """Test 404 when profile does not exist."""
        response = client.post(
            "/api/v1/assessments",
            json={
                "organization_id": org_data["id"],
                "metadata_profile_id": "nonexistent",
            },
        )
        assert response.status_code == 404

    def test_get_assessment(self, client, org_data, metadata_profile_data):
        """Test retrieving assessment."""
        # Create assessment
        create_response = client.post(
            "/api/v1/assessments",
            json={
                "organization_id": org_data["id"],
                "metadata_profile_id": metadata_profile_data["id"],
            },
        )
        assessment_id = create_response.json()["id"]

        # Get assessment
        response = client.get(f"/api/v1/assessments/{assessment_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == assessment_id
        assert data["organization_id"] == org_data["id"]

    def test_get_assessment_not_found(self, client):
        """Test 404 when assessment does not exist."""
        response = client.get("/api/v1/assessments/nonexistent")
        assert response.status_code == 404

    def test_get_assessment_findings(self, client, org_data, metadata_profile_data):
        """Test retrieving findings from assessment."""
        # Create assessment
        create_response = client.post(
            "/api/v1/assessments",
            json={
                "organization_id": org_data["id"],
                "metadata_profile_id": metadata_profile_data["id"],
            },
        )
        assessment_id = create_response.json()["id"]

        # Get findings
        response = client.get(f"/api/v1/assessments/{assessment_id}/findings")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

    def test_get_assessment_findings_invalid_sort(
        self, client, org_data, metadata_profile_data
    ):
        """Test findings endpoint rejects invalid sort field."""
        create_response = client.post(
            "/api/v1/assessments",
            json={
                "organization_id": org_data["id"],
                "metadata_profile_id": metadata_profile_data["id"],
            },
        )
        assessment_id = create_response.json()["id"]

        response = client.get(
            f"/api/v1/assessments/{assessment_id}/findings?sort_by=invalid_field"
        )
        assert response.status_code == 400

    def test_get_report_status_not_found(self, client, org_data, metadata_profile_data):
        """Test report status returns 404 for unknown report id."""
        create_response = client.post(
            "/api/v1/assessments",
            json={
                "organization_id": org_data["id"],
                "metadata_profile_id": metadata_profile_data["id"],
            },
        )
        assessment_id = create_response.json()["id"]

        response = client.get(
            f"/api/v1/assessments/{assessment_id}/reports/missing-report/status"
        )
        assert response.status_code == 404

    def test_get_remediation_roadmap(self, client, org_data, metadata_profile_data):
        """Test remediation roadmap generation."""
        # Create assessment with gaps
        gap_profile_response = client.post(
            "/api/v1/metadata-profiles",
            json={
                "organization_id": org_data["id"],
                "phi_types": ["demographic"],
                "infrastructure": {"encryption_at_rest": False},
                "access_controls": {"mfa_enabled": False},
            },
        )
        profile_id = gap_profile_response.json()["id"]

        create_response = client.post(
            "/api/v1/assessments",
            json={
                "organization_id": org_data["id"],
                "metadata_profile_id": profile_id,
            },
        )
        assessment_id = create_response.json()["id"]

        # Get roadmap
        response = client.get(f"/api/v1/assessments/{assessment_id}/roadmap")
        assert response.status_code == 200
        data = response.json()
        assert "summary" in data
        assert "immediate" in data
        assert "thirty_days" in data
        assert "quarterly" in data
        assert data["summary"]["total_findings"] >= 0


# ========== Evidence Tests ==========


class TestEvidence:
    """Evidence management tests."""

    def test_create_evidence(self, client, org_data):
        """Test creating evidence item."""
        response = client.post(
            "/api/v1/evidence",
            json={
                "control_id": "HIPAA.164.312(a)(1)",
                "evidence_type": "policy_document",
                "title": "Access Control Policy",
                "description": "Our access control policy document",
                "owner": "Security Team",
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["control_id"] == "HIPAA.164.312(a)(1)"
        assert data["title"] == "Access Control Policy"

    def test_create_evidence_with_assessment(
        self, client, org_data, metadata_profile_data
    ):
        """Test creating evidence linked to assessment."""
        # Create assessment
        assess_response = client.post(
            "/api/v1/assessments",
            json={
                "organization_id": org_data["id"],
                "metadata_profile_id": metadata_profile_data["id"],
            },
        )
        assessment_id = assess_response.json()["id"]

        # Create evidence
        response = client.post(
            "/api/v1/evidence",
            json={
                "control_id": "HIPAA.164.312(a)(1)",
                "assessment_id": assessment_id,
                "evidence_type": "system_configuration",
                "title": "System Access Config",
                "description": "Configured RBAC in our system",
                "owner": "DevOps",
            },
        )
        assert response.status_code == 201

    def test_create_evidence_nonexistent_control(self, client):
        """Test 404 when control does not exist."""
        response = client.post(
            "/api/v1/evidence",
            json={
                "control_id": "nonexistent",
                "evidence_type": "policy",
                "title": "Test",
            },
        )
        assert response.status_code == 404

    def test_create_evidence_nonexistent_assessment(self, client):
        """Test 404 when assessment does not exist."""
        response = client.post(
            "/api/v1/evidence",
            json={
                "control_id": "HIPAA.164.312(a)(1)",
                "assessment_id": "nonexistent",
                "evidence_type": "policy",
                "title": "Test",
            },
        )
        assert response.status_code == 404

    def test_get_evidence(self, client):
        """Test retrieving evidence."""
        # Create evidence
        create_response = client.post(
            "/api/v1/evidence",
            json={
                "control_id": "HIPAA.164.312(a)(1)",
                "evidence_type": "policy",
                "title": "Test Evidence",
            },
        )
        evidence_id = create_response.json()["id"]

        # Get evidence
        response = client.get(f"/api/v1/evidence/{evidence_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == evidence_id

    def test_get_evidence_not_found(self, client):
        """Test 404 when evidence does not exist."""
        response = client.get("/api/v1/evidence/nonexistent")
        assert response.status_code == 404

    def test_update_evidence(self, client):
        """Test updating evidence."""
        # Create evidence
        create_response = client.post(
            "/api/v1/evidence",
            json={
                "control_id": "HIPAA.164.312(a)(1)",
                "evidence_type": "policy",
                "title": "Original Title",
                "status": "not_started",
            },
        )
        evidence_id = create_response.json()["id"]

        # Update evidence with supported fields
        response = client.patch(
            f"/api/v1/evidence/{evidence_id}",
            json={
                "status": "in_progress",
                "owner": "Updated Owner",
                "notes": "Progress update",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "in_progress"
        assert data["owner"] == "Updated Owner"

    def test_update_evidence_not_found(self, client):
        """Test 404 when updating nonexistent evidence."""
        response = client.patch(
            "/api/v1/evidence/nonexistent",
            json={"title": "Updated"},
        )
        assert response.status_code == 404

    def test_evidence_checklist(self, client, org_data, metadata_profile_data):
        """Test evidence checklist generation."""
        # Create assessment
        assess_response = client.post(
            "/api/v1/assessments",
            json={
                "organization_id": org_data["id"],
                "metadata_profile_id": metadata_profile_data["id"],
            },
        )
        assessment_id = assess_response.json()["id"]

        # Generate checklist
        response = client.get(f"/api/v1/assessments/{assessment_id}/evidence-checklist")
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert "total_items" in data
        assert "completed" in data


# ========== Component Tests ==========


class TestComponents:
    """Component version discovery tests."""

    @patch("src.routers.components.nvd_service.get_known_versions")
    def test_get_component_versions_known(self, mock_get_versions, client):
        """Test getting versions for known component."""
        # Mock NVD service to return sample versions for java
        mock_get_versions.return_value = ["21.0.1", "20.0.2", "19.0.1"]
        response = client.get("/api/v1/components/java/versions")
        assert response.status_code == 200
        data = response.json()
        assert "versions" in data
        assert isinstance(data["versions"], list)
        assert len(data["versions"]) > 0
        assert "21.0.1" in data["versions"]

    @patch("src.routers.components.nvd_service.get_known_versions")
    def test_get_component_versions_case_insensitive(self, mock_get_versions, client):
        """Test component version lookup is case insensitive."""
        # Mock NVD service to return sample versions for postgres
        mock_get_versions.return_value = ["15.2", "14.7", "13.10"]
        response = client.get("/api/v1/components/POSTGRES/versions")
        assert response.status_code == 200
        data = response.json()
        # Verify the mock was called (confirming case-insensitive lookup works)
        assert mock_get_versions.called
        assert len(data["versions"]) > 0

    def test_get_component_versions_unknown(self, client):
        """Test getting versions for unknown component."""
        response = client.get("/api/v1/components/unknowncomponent/versions")
        assert response.status_code == 200
        data = response.json()
        assert data["versions"] == []


# ========== Health Check Tests ==========


class TestHealth:
    """Health endpoint tests."""

    def test_health_check(self, client):
        """Test health check endpoint."""
        response = client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "version" in data
        assert "environment" in data

    def test_health_check_headers(self, client):
        """Test health check response headers."""
        response = client.get("/api/v1/health")
        assert "X-Request-ID" in response.headers
        assert "X-Process-Time" in response.headers
