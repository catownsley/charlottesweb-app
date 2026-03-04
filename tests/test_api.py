"""Tests for CharlottesWeb API."""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.database import Base, get_db
from src.main import app
from src.seed import seed_controls

# Test database (in-memory SQLite)
SQLALCHEMY_TEST_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    SQLALCHEMY_TEST_DATABASE_URL, connect_args={"check_same_thread": False}
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    """Override database dependency for testing."""
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db

client = TestClient(app)


@pytest.fixture(scope="function", autouse=True)
def setup_database():
    """Set up test database before each test."""
    Base.metadata.create_all(bind=engine)
    # Seed controls
    db = TestingSessionLocal()
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
    ]
    for c in controls:
        db.add(c)
    db.commit()
    db.close()
    yield
    Base.metadata.drop_all(bind=engine)


def test_health_check():
    """Test health check endpoint."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "version" in data


def test_create_organization():
    """Test creating an organization."""
    response = client.post(
        "/api/v1/organizations",
        json={"name": "Test Health Startup", "industry": "digital_health", "stage": "seed"},
    )
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "Test Health Startup"
    assert "id" in data


def test_create_metadata_profile():
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


def test_run_assessment():
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

    # Verify we got expected findings
    finding_titles = [f["title"] for f in findings]
    assert "Multi-Factor Authentication (MFA) Not Enabled" in finding_titles
    assert "Encryption at Rest Not Enabled" in finding_titles
