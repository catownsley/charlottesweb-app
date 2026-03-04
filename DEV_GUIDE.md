# CharlottesWeb - Development Guide

## 🚀 Quick Start

### 1. Install Dependencies

```bash
cd /Users/ct/Python/charlottesweb-app

# Create/activate virtual environment (if not already active)
python3 -m venv ../.venv
source ../.venv/bin/activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

### 2. Set Up Environment

```bash
# Copy example env file
cp .env.example .env

# The defaults should work for local development
```

### 3. Seed Database

```bash
# Create tables and seed HIPAA controls
python -m src.seed
```

### 4. Run the API Server

```bash
# Start the development server
python -m src.main
```

The API will be available at:
- **API:** http://localhost:8000
- **Interactive Docs:** http://localhost:8000/docs
- **ReDoc:** http://localhost:8000/redoc

### 5. Run Tests

```bash
pytest tests/ -v
```

---

## 📚 API Usage Examples

### Health Check

```bash
curl http://localhost:8000/api/v1/health
```

### Create an Organization

```bash
curl -X POST http://localhost:8000/api/v1/organizations \
  -H "Content-Type: application/json" \
  -d '{
    "name": "HealthTech Startup",
    "industry": "digital_health",
    "stage": "seed"
  }'
```

Response:
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "HealthTech Startup",
  "industry": "digital_health",
  "stage": "seed",
  "created_at": "2026-03-04T..."
}
```

### Create a Metadata Profile

```bash
curl -X POST http://localhost:8000/api/v1/metadata-profiles \
  -H "Content-Type: application/json" \
  -d '{
    "organization_id": "YOUR_ORG_ID",
    "phi_types": ["demographic", "clinical", "payment"],
    "cloud_provider": "aws",
    "infrastructure": {
      "encryption_at_rest": false,
      "tls_enabled": true,
      "logging_enabled": true,
      "log_retention_days": 90
    },
    "access_controls": {
      "mfa_enabled": false
    },
    "applications": {
      "frameworks": ["Django", "React"],
      "databases": ["PostgreSQL", "Redis"]
    }
  }'
```

### Run a Compliance Assessment

```bash
curl -X POST http://localhost:8000/api/v1/assessments \
  -H "Content-Type: application/json" \
  -d '{
    "organization_id": "YOUR_ORG_ID",
    "metadata_profile_id": "YOUR_PROFILE_ID"
  }'
```

Response:
```json
{
  "id": "assessment-id",
  "organization_id": "org-id",
  "metadata_profile_id": "profile-id",
  "status": "completed",
  "initiated_at": "2026-03-04T...",
  "completed_at": "2026-03-04T..."
}
```

### Get Assessment Findings

```bash
curl http://localhost:8000/api/v1/assessments/YOUR_ASSESSMENT_ID/findings
```

Response:
```json
[
  {
    "id": "finding-id",
    "assessment_id": "assessment-id",
    "control_id": "HIPAA.164.312(a)(1)",
    "title": "Multi-Factor Authentication (MFA) Not Enabled",
    "description": "MFA is not enabled for user authentication...",
    "severity": "high",
    "cvss_score": 7.5,
    "cve_ids": [],
    "cwe_ids": ["CWE-308"],
    "remediation_guidance": "Enable MFA for all users...",
    "priority_window": "immediate",
    "owner": "Security",
    "created_at": "2026-03-04T..."
  }
]
```

### List All HIPAA Controls

```bash
curl http://localhost:8000/api/v1/controls
```

---

## 🧪 Testing the Vertical Slice

### End-to-End Test Scenario

```bash
# 1. Start the server
python -m src.main

# In another terminal:

# 2. Create organization
ORG_RESPONSE=$(curl -X POST http://localhost:8000/api/v1/organizations \
  -H "Content-Type: application/json" \
  -d '{"name": "Test Startup"}')
ORG_ID=$(echo $ORG_RESPONSE | python -c "import sys,json; print(json.load(sys.stdin)['id'])")

# 3. Create metadata profile with security gaps
PROFILE_RESPONSE=$(curl -X POST http://localhost:8000/api/v1/metadata-profiles \
  -H "Content-Type: application/json" \
  -d "{
    \"organization_id\": \"$ORG_ID\",
    \"phi_types\": [\"demographic\", \"clinical\"],
    \"cloud_provider\": \"aws\",
    \"infrastructure\": {
      \"encryption_at_rest\": false,
      \"tls_enabled\": false,
      \"logging_enabled\": false
    },
    \"access_controls\": {
      \"mfa_enabled\": false
    }
  }")
PROFILE_ID=$(echo $PROFILE_RESPONSE | python -c "import sys,json; print(json.load(sys.stdin)['id'])")

# 4. Run assessment
ASSESSMENT_RESPONSE=$(curl -X POST http://localhost:8000/api/v1/assessments \
  -H "Content-Type: application/json" \
  -d "{
    \"organization_id\": \"$ORG_ID\",
    \"metadata_profile_id\": \"$PROFILE_ID\"
  }")
ASSESSMENT_ID=$(echo $ASSESSMENT_RESPONSE | python -c "import sys,json; print(json.load(sys.stdin)['id'])")

# 5. Get findings
curl http://localhost:8000/api/v1/assessments/$ASSESSMENT_ID/findings | python -m json.tool
```

You should see findings for:
- ✅ MFA not enabled → HIGH severity
- ✅ Encryption at rest not enabled → HIGH severity
- ✅ TLS not enabled → HIGH severity
- ✅ Logging insufficient → MEDIUM severity
- ✅ Risk analysis required → MEDIUM severity

---

## 🏗️ Project Structure

```
src/
├── __init__.py          # Package version
├── config.py            # Settings and environment config
├── database.py          # SQLAlchemy engine and session
├── models.py            # Database models (Organization, Control, Finding, etc.)
├── schemas.py           # Pydantic schemas for API validation
├── api.py               # API route handlers
├── rules_engine.py      # Core rules logic (metadata → controls → findings)
├── main.py              # FastAPI application entry point
└── seed.py              # Database seed script for HIPAA controls

tests/
└── test_api.py          # API integration tests

scripts/
├── create_issues.py     # GitHub issue creation
└── fix_existing_issues.py
```

---

## 🔍 What the Vertical Slice Demonstrates

This MVP proves the entire data flow:

1. **Metadata Intake** → Organization + MetadataProfile models
2. **Control Mapping** → 10 seeded HIPAA controls
3. **Rules Engine** → 5 implemented rules that map metadata to findings:
   - Access Control (MFA check)
   - Encryption at Rest
   - Encryption in Transit (TLS)
   - Audit Logging
   - Risk Analysis
4. **Risk Scoring** → CVSS scores + CWE mappings
5. **Prioritization** → immediate / 30_days / quarterly windows
6. **Output** → JSON findings with remediation guidance

---

## 🎯 Next Steps

See [docs/tickets/TICKET_INDEX.md](docs/tickets/TICKET_INDEX.md) for the full roadmap.

### Immediate Enhancements (Phase 1 completion)
- Add more HIPAA controls (currently 10, target 30-50)
- Expand rules engine logic
- Add real CVE/NVD integration (currently mocked)
- Implement remediation roadmap grouping endpoint

### Phase 2: Audit Evidence
- Control-to-evidence mapping
- Policy template generation
- Audit binder export (PDF/zip)

### Phase 3: Web UI
- React/Next.js frontend
- Dashboard for findings visualization
- Assessment history

---

## 🐛 Troubleshooting

### Database Issues

```bash
# Reset database
rm charlottesweb.db
python -m src.seed
```

### Import Errors

```bash
# Ensure you're in the project root and virtualenv is active
cd /Users/ct/Python/charlottesweb-app
source ../.venv/bin/activate
python -m src.main
```

### Port Already in Use

```bash
# Kill process on port 8000
lsof -ti:8000 | xargs kill -9

# Or use a different port
uvicorn src.main:app --port 8001
```

---

## 📖 Additional Resources

- [BUSINESS_PLAN.md](BUSINESS_PLAN.md) - Market strategy and business model
- [ARCHITECTURE.md](ARCHITECTURE.md) - Complete technical architecture
- [FastAPI Docs](https://fastapi.tiangolo.com/)
- [SQLAlchemy Docs](https://docs.sqlalchemy.org/)
- [HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/index.html)
