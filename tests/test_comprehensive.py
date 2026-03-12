"""Tests for CharlottesWeb API - Phase 3 test coverage expansion."""

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
    """Create a test database with seed data."""
    db_file = tmp_path / "test.db"
    test_db_url = f"sqlite:///{db_file}"

    engine = create_engine(test_db_url, connect_args={"check_same_thread": False})
    testing_session_local = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    Base.metadata.create_all(bind=engine)

    # Seed all controls
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
                "organization_id": org_data["id"],
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
        assert data["organization_id"] == org_data["id"]

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

    def test_create_evidence_nonexistent_assessment(self, client, org_data):
        """Test 404 when assessment does not exist."""
        response = client.post(
            "/api/v1/evidence",
            json={
                "organization_id": org_data["id"],
                "control_id": "HIPAA.164.312(a)(1)",
                "assessment_id": "nonexistent",
                "evidence_type": "policy",
                "title": "Test",
            },
        )
        assert response.status_code == 404

    def test_get_evidence(self, client, org_data):
        """Test retrieving evidence."""
        # Create evidence
        create_response = client.post(
            "/api/v1/evidence",
            json={
                "organization_id": org_data["id"],
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

    def test_update_evidence(self, client, org_data):
        """Test updating evidence."""
        # Create evidence
        create_response = client.post(
            "/api/v1/evidence",
            json={
                "organization_id": org_data["id"],
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

    def test_action_plan(self, client, org_data, metadata_profile_data):
        """Test action plan generation."""
        # Create assessment
        assess_response = client.post(
            "/api/v1/assessments",
            json={
                "organization_id": org_data["id"],
                "metadata_profile_id": metadata_profile_data["id"],
            },
        )
        assessment_id = assess_response.json()["id"]

        # Generate action plan
        response = client.get(f"/api/v1/assessments/{assessment_id}/action-plan")
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert "total_items" in data
        assert "completed" in data

    def test_action_plan_items_include_frameworks_covered(
        self, client, org_data, metadata_profile_data
    ):
        """Test that action plan items include the frameworks_covered field."""
        assess_response = client.post(
            "/api/v1/assessments",
            json={
                "organization_id": org_data["id"],
                "metadata_profile_id": metadata_profile_data["id"],
            },
        )
        assessment_id = assess_response.json()["id"]

        response = client.get(f"/api/v1/assessments/{assessment_id}/action-plan")
        assert response.status_code == 200
        data = response.json()
        assert len(data["items"]) > 0
        for item in data["items"]:
            # frameworks_covered should be present as a key (may be null or a list)
            assert "frameworks_covered" in item

    def test_action_plan_persists_progress_across_assessments(
        self, client, org_data, metadata_profile_data
    ):
        """Evidence updates persist for same org across subsequent assessments."""
        first_assessment_response = client.post(
            "/api/v1/assessments",
            json={
                "organization_id": org_data["id"],
                "metadata_profile_id": metadata_profile_data["id"],
            },
        )
        assert first_assessment_response.status_code == 201
        first_assessment_id = first_assessment_response.json()["id"]

        first_plan_response = client.get(
            f"/api/v1/assessments/{first_assessment_id}/action-plan"
        )
        assert first_plan_response.status_code == 200
        first_items = first_plan_response.json()["items"]
        assert len(first_items) > 0

        target_item = next(
            (item for item in first_items if item.get("evidence_id")),
            None,
        )
        if target_item is None:
            seed_item = first_items[0]
            create_evidence_response = client.post(
                "/api/v1/evidence",
                json={
                    "control_id": seed_item["control_id"],
                    "assessment_id": first_assessment_id,
                    "evidence_type": seed_item["evidence_type"],
                    "title": f"{seed_item['control_id']}: {seed_item['evidence_type']}",
                },
            )
            assert create_evidence_response.status_code == 201

            refreshed_plan_response = client.get(
                f"/api/v1/assessments/{first_assessment_id}/action-plan"
            )
            assert refreshed_plan_response.status_code == 200
            refreshed_items = refreshed_plan_response.json()["items"]
            target_item = next(
                (
                    item
                    for item in refreshed_items
                    if item["control_id"] == seed_item["control_id"]
                    and item["evidence_type"] == seed_item["evidence_type"]
                    and item.get("evidence_id")
                ),
                None,
            )

        assert target_item is not None

        update_response = client.patch(
            f"/api/v1/evidence/{target_item['evidence_id']}",
            json={"status": "completed", "notes": "Persisted progress"},
        )
        assert update_response.status_code == 200

        second_assessment_response = client.post(
            "/api/v1/assessments",
            json={
                "organization_id": org_data["id"],
                "metadata_profile_id": metadata_profile_data["id"],
            },
        )
        assert second_assessment_response.status_code == 201
        second_assessment_id = second_assessment_response.json()["id"]

        second_plan_response = client.get(
            f"/api/v1/assessments/{second_assessment_id}/action-plan"
        )
        assert second_plan_response.status_code == 200
        second_items = second_plan_response.json()["items"]

        matching_item = next(
            (
                item
                for item in second_items
                if item["control_id"] == target_item["control_id"]
                and item["evidence_type"] == target_item["evidence_type"]
            ),
            None,
        )
        assert matching_item is not None
        assert matching_item["status"] == "completed"
        assert matching_item["notes"] == "Persisted progress"


# ========== Evidence Attachment & Sanitization Tests ==========


class TestEvidenceAttachments:
    """Tests for evidence URL attachment and input sanitization."""

    def test_attach_url_to_evidence(self, client, org_data):
        """Test attaching a valid URL to an evidence record."""
        create_response = client.post(
            "/api/v1/evidence",
            json={
                "organization_id": org_data["id"],
                "control_id": "HIPAA.164.312(a)(1)",
                "evidence_type": "policy",
                "title": "Test Evidence",
            },
        )
        evidence_id = create_response.json()["id"]

        response = client.post(
            f"/api/v1/evidence/{evidence_id}/attach",
            json={
                "artifact_url": "https://docs.example.com/encryption-policy.pdf",
                "description": "Encryption policy document",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["artifact_url"] == "https://docs.example.com/encryption-policy.pdf"
        assert data["description"] == "Encryption policy document"
        assert data["uploaded_at"] is not None
        assert data["status"] == "in_progress"  # auto-advanced from not_started

    def test_attach_url_rejects_javascript_scheme(self, client, org_data):
        """Test that javascript: URLs are rejected."""
        create_response = client.post(
            "/api/v1/evidence",
            json={
                "organization_id": org_data["id"],
                "control_id": "HIPAA.164.312(a)(1)",
                "evidence_type": "policy",
                "title": "Test Evidence",
            },
        )
        evidence_id = create_response.json()["id"]

        response = client.post(
            f"/api/v1/evidence/{evidence_id}/attach",
            json={"artifact_url": "javascript:alert(1)"},
        )
        assert response.status_code == 400
        assert "not allowed" in response.json()["detail"].lower()

    def test_attach_url_rejects_data_scheme(self, client, org_data):
        """Test that data: URLs are rejected."""
        create_response = client.post(
            "/api/v1/evidence",
            json={
                "organization_id": org_data["id"],
                "control_id": "HIPAA.164.312(a)(1)",
                "evidence_type": "policy",
                "title": "Test Evidence",
            },
        )
        evidence_id = create_response.json()["id"]

        response = client.post(
            f"/api/v1/evidence/{evidence_id}/attach",
            json={"artifact_url": "data:text/html,<script>alert(1)</script>"},
        )
        assert response.status_code == 400

    def test_attach_url_rejects_empty_url(self, client, org_data):
        """Test that empty URLs are rejected."""
        create_response = client.post(
            "/api/v1/evidence",
            json={
                "organization_id": org_data["id"],
                "control_id": "HIPAA.164.312(a)(1)",
                "evidence_type": "policy",
                "title": "Test Evidence",
            },
        )
        evidence_id = create_response.json()["id"]

        response = client.post(
            f"/api/v1/evidence/{evidence_id}/attach",
            json={"artifact_url": ""},
        )
        assert response.status_code == 422  # Pydantic min_length=1

    def test_attach_url_not_found(self, client):
        """Test 404 when attaching to nonexistent evidence."""
        response = client.post(
            "/api/v1/evidence/nonexistent/attach",
            json={"artifact_url": "https://example.com/doc.pdf"},
        )
        assert response.status_code == 404

    def test_action_plan_includes_artifact_url(
        self, client, org_data, metadata_profile_data
    ):
        """Test that action plan items include artifact_url when evidence has one."""
        assess_response = client.post(
            "/api/v1/assessments",
            json={
                "organization_id": org_data["id"],
                "metadata_profile_id": metadata_profile_data["id"],
            },
        )
        assessment_id = assess_response.json()["id"]

        # Generate action plan to auto-create evidence records
        plan_response = client.get(f"/api/v1/assessments/{assessment_id}/action-plan")
        assert plan_response.status_code == 200
        items = plan_response.json()["items"]
        assert len(items) > 0

        # Find an item with an evidence_id
        target = next((i for i in items if i.get("evidence_id")), None)
        assert target is not None

        # Attach a URL to it
        attach_response = client.post(
            f"/api/v1/evidence/{target['evidence_id']}/attach",
            json={"artifact_url": "https://example.com/evidence.pdf"},
        )
        assert attach_response.status_code == 200

        # Reload action plan and verify artifact_url appears
        plan_response2 = client.get(f"/api/v1/assessments/{assessment_id}/action-plan")
        items2 = plan_response2.json()["items"]
        updated = next(
            (i for i in items2 if i["evidence_id"] == target["evidence_id"]),
            None,
        )
        assert updated is not None
        assert updated["artifact_url"] == "https://example.com/evidence.pdf"

    def test_action_plan_evidence_title_includes_org_name(
        self, client, org_data, metadata_profile_data
    ):
        """Test that auto-created evidence titles include the org name with spaces trimmed."""
        assess_response = client.post(
            "/api/v1/assessments",
            json={
                "organization_id": org_data["id"],
                "metadata_profile_id": metadata_profile_data["id"],
            },
        )
        assessment_id = assess_response.json()["id"]

        plan_response = client.get(f"/api/v1/assessments/{assessment_id}/action-plan")
        assert plan_response.status_code == 200
        items = plan_response.json()["items"]

        # Find an item with an evidence_id and check the evidence title
        target = next((i for i in items if i.get("evidence_id")), None)
        assert target is not None

        evidence_response = client.get(f"/api/v1/evidence/{target['evidence_id']}")
        assert evidence_response.status_code == 200
        title = evidence_response.json()["title"]

        # Org name with spaces removed should be in the title
        org_slug = org_data["name"].replace(" ", "")
        assert org_slug in title

    def test_update_evidence_rejects_javascript_url(self, client, org_data):
        """Test that PATCH rejects javascript: URLs."""
        create_response = client.post(
            "/api/v1/evidence",
            json={
                "organization_id": org_data["id"],
                "control_id": "HIPAA.164.312(a)(1)",
                "evidence_type": "policy",
                "title": "Test Evidence",
            },
        )
        evidence_id = create_response.json()["id"]

        response = client.patch(
            f"/api/v1/evidence/{evidence_id}",
            json={"artifact_url": "javascript:alert('xss')"},
        )
        assert response.status_code == 400


class TestSanitizationUtilities:
    """Unit tests for sanitization functions."""

    def test_sanitize_url_valid_https(self):
        from src.utils import sanitize_url

        assert (
            sanitize_url("https://example.com/doc.pdf") == "https://example.com/doc.pdf"
        )

    def test_sanitize_url_valid_http(self):
        from src.utils import sanitize_url

        assert (
            sanitize_url("http://localhost:8000/test") == "http://localhost:8000/test"
        )

    def test_sanitize_url_rejects_javascript(self):
        import pytest

        from src.utils import sanitize_url

        with pytest.raises(ValueError, match="not allowed"):
            sanitize_url("javascript:alert(1)")

    def test_sanitize_url_rejects_data(self):
        import pytest

        from src.utils import sanitize_url

        with pytest.raises(ValueError, match="not allowed"):
            sanitize_url("data:text/html,<h1>test</h1>")

    def test_sanitize_url_rejects_file(self):
        import pytest

        from src.utils import sanitize_url

        with pytest.raises(ValueError, match="not allowed"):
            sanitize_url("file:///etc/passwd")

    def test_sanitize_url_rejects_empty(self):
        import pytest

        from src.utils import sanitize_url

        with pytest.raises(ValueError, match="empty"):
            sanitize_url("")

    def test_sanitize_url_rejects_no_host(self):
        import pytest

        from src.utils import sanitize_url

        with pytest.raises(ValueError, match="host"):
            sanitize_url("https://")

    def test_sanitize_url_rejects_oversized(self):
        import pytest

        from src.utils import sanitize_url

        with pytest.raises(ValueError, match="maximum length"):
            sanitize_url("https://example.com/" + "a" * 2100)

    def test_sanitize_text_escapes_html(self):
        from src.utils import sanitize_text

        result = sanitize_text("<script>alert('xss')</script>")
        assert "<script>" not in result
        assert "&lt;script&gt;" in result

    def test_sanitize_text_rejects_oversized(self):
        import pytest

        from src.utils import sanitize_text

        with pytest.raises(ValueError, match="maximum length"):
            sanitize_text("a" * 6000)

    def test_sanitize_text_strips_control_chars(self):
        from src.utils import sanitize_text

        result = sanitize_text("hello\x00world\x07test")
        assert "\x00" not in result
        assert "\x07" not in result

    def test_sanitize_filename_strips_path_traversal(self):
        from src.utils import sanitize_filename

        result = sanitize_filename("../../etc/passwd")
        assert result == "passwd"
        assert ".." not in result

    def test_sanitize_filename_rejects_empty(self):
        import pytest

        from src.utils import sanitize_filename

        with pytest.raises(ValueError):
            sanitize_filename("")

    def test_sanitize_filename_rejects_dots_only(self):
        import pytest

        from src.utils import sanitize_filename

        with pytest.raises(ValueError, match="Invalid filename"):
            sanitize_filename("..")


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

    def test_ingest_manifest_pom_xml(self, client):
        """Test parsing pom.xml into normalized components."""
        pom_xml = """
        <project>
          <properties>
            <spring.version>6.1.12</spring.version>
          </properties>
          <dependencyManagement>
            <dependencies>
              <dependency>
                <groupId>org.postgresql</groupId>
                <artifactId>postgresql</artifactId>
                <version>42.7.4</version>
              </dependency>
            </dependencies>
          </dependencyManagement>
          <dependencies>
            <dependency>
              <groupId>org.springframework</groupId>
              <artifactId>spring-core</artifactId>
              <version>${spring.version}</version>
            </dependency>
            <dependency>
              <groupId>org.postgresql</groupId>
              <artifactId>postgresql</artifactId>
            </dependency>
          </dependencies>
        </project>
        """

        response = client.post(
            "/api/v1/components/ingest-manifest",
            json={"format": "pom_xml", "content": pom_xml},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["format"] == "pom_xml"
        assert data["total_components"] == 2

        components = {item["name"]: item["version"] for item in data["components"]}
        assert components["spring-core"] == "6.1.12"
        assert components["postgresql"] == "42.7.4"

    def test_ingest_manifest_invalid_xml(self, client):
        """Test manifest ingestion rejects invalid XML payloads."""
        response = client.post(
            "/api/v1/components/ingest-manifest",
            json={"format": "pom_xml", "content": "<project><dependencies>"},
        )
        assert response.status_code == 400


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


# ========== Framework Tests ==========


class TestFrameworks:
    """Framework listing endpoint tests."""

    def test_list_frameworks(self, client):
        """Test GET /api/v1/frameworks returns a list of frameworks."""
        response = client.get("/api/v1/frameworks")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)


# ========== Tenant Isolation Tests ==========


class TestTenantIsolation:
    """Verify evidence is properly scoped per organization."""

    def _create_org_with_assessment(self, client, name):
        """Helper: create org, profile, and assessment."""
        org = client.post(
            "/api/v1/organizations",
            json={"name": name, "industry": "digital_health", "stage": "seed"},
        ).json()
        profile = client.post(
            "/api/v1/metadata-profiles",
            json={
                "organization_id": org["id"],
                "phi_types": ["demographic"],
                "cloud_provider": "aws",
                "infrastructure": {"encryption_at_rest": False, "tls_enabled": True},
                "access_controls": {"mfa_enabled": False},
            },
        ).json()
        assessment = client.post(
            "/api/v1/assessments",
            json={
                "organization_id": org["id"],
                "metadata_profile_id": profile["id"],
            },
        ).json()
        return org, assessment

    def test_evidence_requires_org_id_or_assessment_id(self, client):
        """Evidence creation fails without organization_id or assessment_id."""
        response = client.post(
            "/api/v1/evidence",
            json={
                "control_id": "HIPAA.164.312(a)(1)",
                "evidence_type": "policy",
                "title": "Orphan Evidence",
            },
        )
        assert response.status_code == 400
        assert "organization_id" in response.json()["detail"].lower()

    def test_evidence_inherits_org_from_assessment(self, client):
        """Evidence created with assessment_id inherits the org."""
        org, assessment = self._create_org_with_assessment(client, "Inherit Org")
        response = client.post(
            "/api/v1/evidence",
            json={
                "control_id": "HIPAA.164.312(a)(1)",
                "assessment_id": assessment["id"],
                "evidence_type": "policy",
                "title": "Inherited Org Evidence",
            },
        )
        assert response.status_code == 201
        assert response.json()["organization_id"] == org["id"]

    def test_evidence_rejects_mismatched_org_and_assessment(self, client):
        """Providing org_id that differs from assessment's org is rejected."""
        org_a, assessment_a = self._create_org_with_assessment(client, "Org A")
        org_b, _ = self._create_org_with_assessment(client, "Org B")

        response = client.post(
            "/api/v1/evidence",
            json={
                "organization_id": org_b["id"],
                "control_id": "HIPAA.164.312(a)(1)",
                "assessment_id": assessment_a["id"],
                "evidence_type": "policy",
                "title": "Mismatch Evidence",
            },
        )
        assert response.status_code == 400
        assert "does not match" in response.json()["detail"]

    def test_action_plan_does_not_leak_cross_tenant_evidence(self, client):
        """Org A's completed evidence must not appear in Org B's action plan."""
        org_a, assessment_a = self._create_org_with_assessment(client, "Isolated A")
        org_b, assessment_b = self._create_org_with_assessment(client, "Isolated B")

        # Generate action plans to auto-create evidence for both orgs
        plan_a = client.get(
            f"/api/v1/assessments/{assessment_a['id']}/action-plan"
        ).json()

        # Mark Org A's first evidence item as completed
        target = next((i for i in plan_a["items"] if i.get("evidence_id")), None)
        assert target is not None
        client.patch(
            f"/api/v1/evidence/{target['evidence_id']}",
            json={"status": "completed", "notes": "Done by Org A"},
        )

        # Get Org B's action plan
        plan_b = client.get(
            f"/api/v1/assessments/{assessment_b['id']}/action-plan"
        ).json()

        # Org B should have NO completed items (all should be not_started)
        for item in plan_b["items"]:
            assert item["status"] != "completed", (
                f"Org B's action plan has a completed item that leaked from Org A: "
                f"{item['control_id']} / {item['evidence_type']}"
            )
        assert plan_b["completed"] == 0
