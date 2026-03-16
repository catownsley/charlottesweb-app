"""Tests for CharlottesWeb API."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.database import Base, get_db
from src.main import app


@pytest.fixture(scope="function")
def test_db(tmp_path):
    """Create a test database in a temporary directory."""
    # Create test database in pytest's tmp_path
    db_file = tmp_path / "test.db"
    test_db_url = f"sqlite:///{db_file}"

    # Create engine and session
    engine = create_engine(test_db_url, connect_args={"check_same_thread": False})
    testing_session_local = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    # Create all tables
    Base.metadata.create_all(bind=engine)

    # Seed controls
    db = testing_session_local()
    from src.models import Control

    controls = [
        Control(
            id="HIPAA.164.312(a)(1)",
            framework="HIPAA_Security_Rule",
            title="Access Control",
            requirement="Test requirement",
            category="Technical Safeguards",
        ),
        Control(
            id="HIPAA.164.312(a)(2)(iv)",
            framework="HIPAA_Security_Rule",
            title="Encryption at Rest",
            requirement="Test requirement",
            category="Technical Safeguards",
        ),
        Control(
            id="HIPAA.164.308(a)(5)(ii)(B)",
            framework="HIPAA_Security_Rule",
            title="Security Awareness and Training",
            requirement="Test requirement",
            category="Administrative Safeguards",
        ),
    ]
    for c in controls:
        db.add(c)
    db.commit()
    db.close()

    # Override get_db dependency
    def override_get_db():
        try:
            db = testing_session_local()
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    yield engine

    # Cleanup
    Base.metadata.drop_all(bind=engine)
    app.dependency_overrides.clear()


@pytest.fixture(scope="function")
def client(test_db):
    """Create test client with database dependency override."""
    return TestClient(app, base_url="https://testserver")


def test_health_check(client):
    """Test health check endpoint."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "version" in data


def test_create_organization(client):
    """Test creating an organization."""
    response = client.post(
        "/api/v1/organizations",
        json={
            "name": "Test Health Startup",
            "industry": "digital_health",
            "stage": "seed",
        },
    )
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "Test Health Startup"
    assert "id" in data


def test_list_organizations_by_name_filter(client):
    """Test listing organizations with case-insensitive exact name filtering."""
    client.post("/api/v1/organizations", json={"name": "Demo Org"})
    client.post("/api/v1/organizations", json={"name": "Another Org"})

    response = client.get("/api/v1/organizations?name=demo%20org")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["name"] == "Demo Org"


def test_onboard_organization(client):
    """Test onboarding organization with initial admin member."""
    response = client.post(
        "/api/v1/organizations/onboard",
        json={
            "name": "Onboarded Health Startup",
            "industry": "digital_health",
            "stage": "seed",
            "admin_email": "founder@example.com",
            "admin_name": "Founder",
            "admin_role": "admin",
        },
    )
    assert response.status_code == 201
    data = response.json()
    assert data["organization"]["name"] == "Onboarded Health Startup"
    assert data["member"]["email"] == "founder@example.com"
    assert data["member"]["role"] == "admin"


def test_create_metadata_profile(client):
    """Test creating a metadata profile."""
    # First create an organization
    org_response = client.post(
        "/api/v1/organizations",
        json={"name": "Test Org"},
    )
    org_id = org_response.json()["id"]

    # Create metadata profile
    response = client.post(
        "/api/v1/metadata-profiles",
        json={
            "organization_id": org_id,
            "phi_types": ["demographic", "clinical"],
            "cloud_provider": "aws",
            "infrastructure": {
                "encryption_at_rest": False,
                "tls_enabled": True,
                "logging_enabled": False,
            },
            "access_controls": {
                "mfa_enabled": False,
            },
        },
    )
    assert response.status_code == 201
    data = response.json()
    assert data["organization_id"] == org_id
    assert data["phi_types"] == ["demographic", "clinical"]


def test_run_assessment(client):
    """Test running a compliance assessment."""
    # Create organization
    org_response = client.post(
        "/api/v1/organizations",
        json={"name": "Test Org"},
    )
    org_id = org_response.json()["id"]

    # Create metadata profile with gaps
    profile_response = client.post(
        "/api/v1/metadata-profiles",
        json={
            "organization_id": org_id,
            "phi_types": ["demographic"],
            "cloud_provider": "aws",
            "infrastructure": {
                "encryption_at_rest": False,  # Gap
                "tls_enabled": False,  # Gap
            },
            "access_controls": {
                "mfa_enabled": False,  # Gap
            },
        },
    )
    profile_id = profile_response.json()["id"]

    # Run assessment
    assessment_response = client.post(
        "/api/v1/assessments",
        json={
            "organization_id": org_id,
            "metadata_profile_id": profile_id,
        },
    )
    assert assessment_response.status_code == 201
    assessment_data = assessment_response.json()
    assert assessment_data["status"] == "completed"
    assessment_id = assessment_data["id"]

    # Get findings
    findings_response = client.get(f"/api/v1/assessments/{assessment_id}/findings")
    assert findings_response.status_code == 200
    findings = findings_response.json()
    assert len(findings) > 0


def test_get_prioritized_risk_backlog(client):
    """Test risk backlog endpoint fuses findings and evidence into sorted risk output."""
    # Create organization + metadata profile + completed assessment
    org_response = client.post("/api/v1/organizations", json={"name": "Risk Org"})
    org_id = org_response.json()["id"]

    profile_response = client.post(
        "/api/v1/metadata-profiles",
        json={
            "organization_id": org_id,
            "software_stack": {
                "openssl": {"version": "1.0.1", "ecosystem": "Alpine"},
                "tomcat": {"version": "9.0.62", "ecosystem": "Maven"},
            },
            "infrastructure": {
                "encryption_at_rest": False,
                "tls_enabled": False,
            },
            "access_controls": {"mfa_enabled": False},
        },
    )
    profile_id = profile_response.json()["id"]

    assessment_response = client.post(
        "/api/v1/assessments",
        json={"organization_id": org_id, "metadata_profile_id": profile_id},
    )
    assessment_id = assessment_response.json()["id"]

    # Create and complete one evidence record to influence control confidence.
    findings_response = client.get(f"/api/v1/assessments/{assessment_id}/findings")
    findings = findings_response.json()
    finding_with_control = next(
        (item for item in findings if item.get("control_id")), None
    )
    assert finding_with_control is not None

    control_id = finding_with_control["control_id"]
    create_evidence_response = client.post(
        "/api/v1/evidence",
        json={
            "control_id": control_id,
            "assessment_id": assessment_id,
            "evidence_type": "policy_document",
            "title": "Integration test evidence",
            "description": "Evidence created by integration test",
        },
    )
    assert create_evidence_response.status_code == 201
    evidence_id = create_evidence_response.json()["id"]

    update_response = client.patch(
        f"/api/v1/evidence/{evidence_id}",
        json={"status": "completed", "notes": "Validated in integration test"},
    )
    assert update_response.status_code == 200

    # Request prioritized risk backlog for the assessment.
    risk_response = client.get(
        f"/api/v1/risk/prioritized-backlog?assessment_id={assessment_id}&top=10"
    )
    assert risk_response.status_code == 200

    data = risk_response.json()
    assert data["assessment_id"] == assessment_id
    assert data["organization_id"] == org_id
    assert data["total_items"] > 0
    assert len(data["items"]) > 0

    # Ensure residual risk is sorted descending for stable backlog execution order.
    residuals = [item["residual_risk"] for item in data["items"]]
    assert residuals == sorted(residuals, reverse=True)

    # Verify key scoring fields are present and bounded.
    first_item = data["items"][0]
    assert 0 <= first_item["control_confidence"] <= 100
    assert 0 <= first_item["threat_pressure"] <= 100
    assert 0 <= first_item["residual_risk"] <= 100

    # Verify we got expected findings
    finding_titles = [f["title"] for f in findings]
    assert "Multi-Factor Authentication (MFA) Not Enabled" in finding_titles
    assert "Encryption at Rest Not Enabled" in finding_titles


def test_get_assessment_status(client):
    """Test assessment status endpoint returns progress details."""
    org_response = client.post("/api/v1/organizations", json={"name": "Status Org"})
    org_id = org_response.json()["id"]

    profile_response = client.post(
        "/api/v1/metadata-profiles",
        json={
            "organization_id": org_id,
            "software_stack": {"openssl": {"version": "1.0.1", "ecosystem": ""}},
        },
    )
    profile_id = profile_response.json()["id"]

    assessment_response = client.post(
        "/api/v1/assessments",
        json={
            "organization_id": org_id,
            "metadata_profile_id": profile_id,
        },
    )
    assert assessment_response.status_code == 201
    assessment_id = assessment_response.json()["id"]

    status_response = client.get(f"/api/v1/assessments/{assessment_id}/status")
    assert status_response.status_code == 200
    status_data = status_response.json()

    assert status_data["assessment_id"] == assessment_id
    assert status_data["status"] == "completed"
    assert status_data["progress_percent"] == 100
    assert "current_step" in status_data
    assert "findings_count" in status_data


def test_evidence_checklist_toggle_ui_wiring_present(client):
    """Test that action plan collapse/expand wiring remains present in the web UI."""
    response = client.get("/")
    assert response.status_code == 200

    html = response.text

    # Top-level action plan toggle link and panel
    assert 'id="viewActionPlanLink"' in html
    assert 'id="actionPlanPanel"' in html

    # Guard against regressions where link only reloads and no longer toggles visibility
    assert "actionPlanPanel.classList.contains('hidden')" in html
    assert "actionPlanPanel.classList.remove('hidden')" in html
    assert "actionPlanPanel.classList.add('hidden')" in html

    # In-panel collapse/expand button wiring should also remain present
    assert 'id="toggleEvidenceBtn"' in html
    assert 'id="evidenceContent"' in html


def test_get_assessment_findings_filters_and_sort(client):
    """Test findings endpoint filtering and sorting options."""
    org_response = client.post("/api/v1/organizations", json={"name": "Filter Org"})
    org_id = org_response.json()["id"]

    profile_response = client.post(
        "/api/v1/metadata-profiles",
        json={
            "organization_id": org_id,
            "infrastructure": {
                "encryption_at_rest": False,
                "tls_enabled": False,
            },
            "access_controls": {"mfa_enabled": False},
        },
    )
    profile_id = profile_response.json()["id"]

    assessment_response = client.post(
        "/api/v1/assessments",
        json={
            "organization_id": org_id,
            "metadata_profile_id": profile_id,
        },
    )
    assert assessment_response.status_code == 201
    assessment_id = assessment_response.json()["id"]

    filtered_response = client.get(
        f"/api/v1/assessments/{assessment_id}/findings"
        "?priority_window=immediate&sort_by=severity&sort_order=desc"
    )
    assert filtered_response.status_code == 200
    filtered_findings = filtered_response.json()
    assert isinstance(filtered_findings, list)
    assert all(f["priority_window"] == "immediate" for f in filtered_findings)

    domain_response = client.get(
        f"/api/v1/assessments/{assessment_id}/findings?control_domain=technical"
    )
    assert domain_response.status_code == 200
    domain_findings = domain_response.json()
    assert isinstance(domain_findings, list)
    assert all(
        "technical" in (f.get("control_domain") or "").lower() for f in domain_findings
    )


def test_generate_report_status_and_download(client):
    """Test report generation lifecycle: create, status, and tokenized download."""
    org_response = client.post("/api/v1/organizations", json={"name": "Report Org"})
    org_id = org_response.json()["id"]

    profile_response = client.post(
        "/api/v1/metadata-profiles",
        json={
            "organization_id": org_id,
            "infrastructure": {"encryption_at_rest": False},
            "access_controls": {"mfa_enabled": False},
        },
    )
    profile_id = profile_response.json()["id"]

    assessment_response = client.post(
        "/api/v1/assessments",
        json={
            "organization_id": org_id,
            "metadata_profile_id": profile_id,
        },
    )
    assessment_id = assessment_response.json()["id"]

    create_report_response = client.post(f"/api/v1/assessments/{assessment_id}/reports")
    assert create_report_response.status_code == 200
    create_data = create_report_response.json()
    report_id = create_data["report_id"]
    token = create_data["download_token"]

    status_response = client.get(
        f"/api/v1/assessments/{assessment_id}/reports/{report_id}/status"
    )
    assert status_response.status_code == 200
    status_data = status_response.json()
    assert status_data["status"] == "completed"
    assert status_data["download_url"] is not None

    forbidden_download = client.get(
        f"/api/v1/assessments/{assessment_id}/reports/{report_id}/download?token=bad-token"
    )
    assert forbidden_download.status_code == 403

    download_response = client.get(
        f"/api/v1/assessments/{assessment_id}/reports/{report_id}/download?token={token}"
    )
    assert download_response.status_code == 200
    assert "CHARLOTTESWEB ASSESSMENT REPORT" in download_response.text
