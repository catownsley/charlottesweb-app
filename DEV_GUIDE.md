# CharlottesWeb: Development Guide

## Quick Start

### 1. Install Dependencies

```bash
cd /Users/ct/Python/charlottesweb-app

# Create/activate virtual environment (if not already active)
python3.14 -m venv ../.venv
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
# Create tables and seed multi-framework controls
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

### 6. Enable Pre-Commit Security Checks

```bash
# Install git hooks
pre-commit install

# Run checks on all files (recommended before first push)
pre-commit run --all-files
```

These checks block common mistakes before commit, including accidental private key commits and merge-conflict artifacts.

---

## Security Configuration

### Managing Secrets Securely

**NEVER** store secrets in code or committed files. CharlottesWeb uses environment variables
for all configuration, following the 12-Factor App methodology.

#### Production (Recommended)
For production deployments, set environment variables via your platform:

```bash
# Heroku
heroku config:set SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
heroku config:set VALID_API_KEYS="your-key-1,your-key-2"

# AWS Lambda / ECS
aws secretsmanager create-secret --name charlottesweb/prod
# Then reference in Lambda environment

# GCP Cloud Run
gcloud run deploy charlottesweb --set-secrets SECRET_KEY=secret-manager-secret

# Docker
docker run -e SECRET_KEY="your-secret" charlottesweb
```

#### Development: Option 1: Environment Variables

Set environment variables directly in your shell:

```bash
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
export VALID_API_KEYS="dev-key-1,dev-key-2"
export API_KEY_REQUIRED=false
python -m src.main
```

#### Development: Option 2: .env File (Automatic Loading)

Create `.env` file with your secrets (it's automatically ignored by git):

```bash
cp .env.example .env
# Edit .env and fill in YOUR OWN values
python -m src.main
```

️ **Important**: `.env` is automatically ignored by git. Check `.gitignore` if concerned.

#### Development: Option 3: Encrypted .env File (Extra Protection)

For additional local security, encrypt your `.env` file:

```bash
# Install cryptography library (one-time)
pip install cryptography

# Encrypt your .env file
python src/encryption.py encrypt .env master-password-here

# This creates .env.encrypted
# Safely delete the plaintext .env
rm .env

# To decrypt and view:
python src/encryption.py decrypt .env.encrypted master-password-here

# To use encrypted .env in code:
# from src.encryption import load_encrypted_env
# env_vars = load_encrypted_env('.env.encrypted', password='master-password')
```

### Generate Strong Secrets

**JWT Secret Key** (for signing tokens):
```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
# Example: JR0S_rNg4vZ2bK8mP9qX5wY1L3c6D7eF8gH9iJ0kL1mN2oP3qR4sT5uV6
```

**API Keys** (for external integrations):
```bash
python -c "from src.security import generate_api_key; print(generate_api_key())"
# Example: ck_live_51H2Y3Z4x5w6v7u8t9s0r1q2p3o4
```

**Database Password**:
```bash
python -c "import secrets; print(secrets.token_urlsafe(24))"
```

### Environment Variables Reference

| Variable | Development | Production | Notes |
|----------|-------------|-----------|-------|
| `SECRET_KEY` | Generated or from .env | **Required** | HS256 JWT key (32+ chars) |
| `VALID_API_KEYS` | Optional | **Required** | Comma-separated list |
| `API_KEY_REQUIRED` | false | **true** | Enforce authentication |
| `DEBUG` | true | **false** | Disable debug info |
| `DATABASE_URL` | SQLite | PostgreSQL | Use strong password in prod |
| `CORS_ORIGINS` | localhost | **Whitelist only** | Never use `*` in production |
| `ANTHROPIC_API_KEY` | Optional | Optional | Required for AI threat model |
| `ANTHROPIC_MODEL` | claude-sonnet-4-6 | claude-sonnet-4-6 | Claude model for AI threat model |
| `NVD_API_KEY` | Optional | Recommended | Higher NVD rate limits (CPE lookups only) |

### Hosting Platform Examples

#### AWS Lambda / API Gateway
Use AWS Secrets Manager:
```python
import boto3
client = boto3.client('secretsmanager')
secret = client.get_secret_value(SecretId='charlottesweb/prod')
```

#### Docker / Docker Compose
```yaml
services:
  app:
    environment:
      SECRET_KEY: ${SECRET_KEY}
      VALID_API_KEYS: ${VALID_API_KEYS}
      DATABASE_URL: ${DATABASE_URL}
```

#### Cloudflare Pages / Workers
```toml
# wrangler.toml
[env.production]
vars = { APP_ENV = "production", DEBUG = "false" }
secrets = ["SECRET_KEY", "VALID_API_KEYS"]
```

#### Google Cloud Run
```bash
gcloud run deploy charlottesweb \
  --set-env-vars APP_ENV=production,DEBUG=false \
  --set-secrets SECRET_KEY=secret-manager-secret-version,VALID_API_KEYS=secret-manager-secret-version
```

### Secret Rotation & Revocation

**When to Rotate:**
- Quarterly (policy)
- After suspected compromise
- After employee departure
- After code disclosure
- When logs show suspicious activity

**How to Rotate:**
1. Generate new secret
2. Add to environment (keep old one temporarily)
3. Update code to accept both (if token-based)
4. Wait 24 hours for in-flight requests to complete
5. Remove old secret from environment
6. Monitor logs for failures

### Audit Logging for Secrets

**What to Log:**
- API key creation/deletion (with owner)
- Authentication failures (rate limit if >5 failures)
- Key rotation events
- Unauthorized access attempts

**What NOT to Log:**
- Secret key values (ever)
- API keys (ever)
- Database passwords (ever)
- Session tokens (only hash if necessary)

### API Key Authentication

For development, API key authentication is optional:

```bash
# In .env file
API_KEY_REQUIRED=false # Development default
VALID_API_KEYS=dev-key-1,dev-key-2
```

To enable (recommended for staging):

```bash
# In .env file
API_KEY_REQUIRED=true
VALID_API_KEYS=$(python -c "from src.security import generate_api_key; print(generate_api_key())")
```

Use the API key in requests:

```bash
curl -H "X-API-Key: your-api-key" http://localhost:8000/api/v1/organizations
```

### Rate Limiting

Rate limiting is **enabled** by default (60 requests/minute per IP). To adjust:

```bash
# In .env file
RATE_LIMIT_PER_MINUTE=120 # Increase limit
RATE_LIMIT_ENABLED=false # Or disable entirely
```

### Audit Logging

All sensitive operations are logged to `audit.log` in JSON format. View logs:

```bash
# View recent audit events
tail -f audit.log

# Search for specific actions
grep "assessment_created" audit.log | python -m json.tool
```

### Security Best Practices

**Development**:
- Store secrets in `.env` file (git-ignored)
- Regenerate secrets frequently
- Use self-signed certificates for HTTPS testing
- Review audit logs periodically

**Before Production Deployment**:
- □ Use platform environment variables (no .env files)
- □ Generate strong `SECRET_KEY` (32+ random characters)
- □ Set `API_KEY_REQUIRED=true`
- □ Set `DEBUG=false`
- □ Set `APP_ENV=production`
- □ Whitelist `CORS_ORIGINS` (no wildcard)
- □ Use PostgreSQL (not SQLite)
- □ Enable HTTPS/TLS
- □ Rotate secrets quarterly
- □ No hardcoded secrets in Python files
- □ Audit logging enabled
- □ Secret rotation policy documented

See [SECURITY.md](SECURITY.md) for complete hardening checklists.

---

## Risk-Convergence API

CharlottesWeb now exposes a convergence endpoint that merges compliance posture
and threat intelligence into an actionable backlog:

```bash
GET /api/v1/risk/prioritized-backlog?assessment_id=<assessment_id>&top=20
```

### Why this endpoint exists
- Converts evidence checklist status into measurable `control_confidence`
- Converts findings/CVEs into measurable `threat_pressure`
- Produces `residual_risk` so engineering can prioritize by true risk reduction

### Secure coding and operational safeguards
- Requires scoped queries (`assessment_id` or `organization_id`)
- Bounds all scores to 0-100 to prevent unstable outputs
- Uses deterministic sorting and output for audit reproducibility
- Logs read access for compliance traceability

### Example usage

```bash
curl "http://localhost:8000/api/v1/risk/prioritized-backlog?assessment_id=<id>&top=10"
```

### Future direction (planned)
- Dynamic regulatory feed ingestion (versioned controls)
- Additional framework adapters (SOC 2, PCI DSS, etc.)
- Data-lifecycle metadata inference for regulation applicability

To run the server with HTTPS using self-signed certificates for local development:

### Generate Self-Signed Certificates

```bash
# Generate development certificates (valid for 365 days)
./scripts/generate_dev_certs.sh
```

This creates:
- `certs/cert.pem`: Self-signed certificate
- `certs/key.pem`: Private key

### Run with HTTPS

```bash
# Quick start with HTTPS
./run_https.sh
```

The API will be available at:
- **API:** https://localhost:8443
- **Interactive Docs:** https://localhost:8443/docs

**Note:** Your browser will show a security warning because this is a self-signed certificate. This is normal for local development. Click "Advanced" → "Proceed to localhost (unsafe)" to continue.

### Manual HTTPS Startup

```bash
# Or run uvicorn directly with TLS options
uvicorn src.main:app \
--host 0.0.0.0 \
--port 8443 \
--ssl-keyfile certs/key.pem \
--ssl-certfile certs/cert.pem \
--reload
```

### Test HTTPS Endpoint

```bash
# Use curl with -k flag to ignore self-signed certificate warnings
curl -k https://localhost:8443/api/v1/health
```

---

## � API Usage Examples

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
"control_id": "ctrl-uuid-here",
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

### List All Controls

```bash
curl http://localhost:8000/api/v1/controls
```

---

## Testing the Vertical Slice

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
- MFA not enabled → HIGH severity
- Encryption at rest not enabled → HIGH severity
- TLS not enabled → HIGH severity
- Logging insufficient → MEDIUM severity
- Risk analysis required → MEDIUM severity

---

## ️ Project Structure

```
src/
├── __init__.py # Package version
├── config.py # Settings and environment config
├── database.py # SQLAlchemy engine and session
├── models.py # Database models (Organization, Control, Finding, etc.)
├── schemas.py # Pydantic schemas for API validation
├── api.py # API route handlers
├── rules_engine.py # Core rules logic (metadata → controls → findings)
├── main.py # FastAPI application entry point
└── seed.py # Database seed script for multi-framework controls

tests/
└── test_api.py # API integration tests

scripts/
├── create_issues.py # GitHub issue creation
└── fix_existing_issues.py
```

---

## End-to-End Data Flow (MVP)

This MVP covers the full request cycle:

1. **Metadata Intake** → Organization + MetadataProfile models
2. **Control Mapping** → 23 canonical controls across 9 frameworks (127 mappings)
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

## Next Steps

See [docs/tickets/TICKET_INDEX.md](docs/tickets/TICKET_INDEX.md) for the full roadmap.

### Immediate Enhancements (Phase 1 completion)
- Expand canonical controls and cross-framework mappings
- Expand rules engine logic
* ~~Add real CVE/NVD integration~~ Done: OSV.dev integrated for ecosystem aware vulnerability scanning
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

## AI Threat Model

CharlottesWeb includes an AI-powered threat model generator that produces comprehensive STRIDE analysis, compound risk detection, and prioritized remediation roadmaps in minutes.

### Setup

1. Get an API key from [Anthropic Console](https://console.anthropic.com/settings/keys)
2. Purchase API credits (prepaid billing, separate from Claude Pro subscription)
3. Add to your `.env` file:
   ```
   ANTHROPIC_API_KEY=sk-ant-api03-your-key-here
   ANTHROPIC_MODEL=claude-sonnet-4-6
   ```

### Usage

1. Run an assessment first (the AI threat model analyzes assessment findings)
2. Go to the **Threat Model** tab
3. Enter the organization name and click **AI Threat Model**
4. Generation takes 1-2 minutes
5. Click **Export Report** to download a text file sorted by severity

### What It Produces

- **Executive summary:** 3-5 sentence security posture overview
- **STRIDE threat analysis:** Architectural threats with specific mitigations (not per-CVE)
- **Consolidated dependency finding:** One finding for all outdated dependencies
- **Compound risks:** Where a CVE escalates an architectural threat (only when causal chain exists)
- **Remediation roadmap:** Prioritized action items

### API Endpoint

```
GET /api/v1/threat-model/ai/organizations/{organization_id}
```

Without an API key configured, this endpoint returns HTTP 503.

### Cost

The AI threat model uses the Claude API (Sonnet 4.6 by default). Typical cost per generation is $0.05-0.15 depending on the number of findings and components analyzed.

---

## Troubleshooting

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

### Python Version Standard

- Project standard is **Python 3.14.3** (`.python-version`)
- Canonical virtual environment is **`/Users/ct/Python/.venv`**
- Remove local project `venv/` if present to avoid conflicts

### Port Already in Use

```bash
# Kill process on port 8000
lsof -ti:8000 | xargs kill -9

# Or use a different port
uvicorn src.main:app --port 8001
```

---

## Additional Resources

- [BUSINESS_PLAN.md](BUSINESS_PLAN.md): Market strategy and business model
- [ARCHITECTURE.md](ARCHITECTURE.md): Complete technical architecture
- [FastAPI Docs](https://fastapi.tiangolo.com/)
- [SQLAlchemy Docs](https://docs.sqlalchemy.org/)
- [NIST 800-53 Rev 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/index.html)
- [SOC 2 Trust Services Criteria](https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2)
- [PCI DSS v4.0](https://www.pcisecuritystandards.org/standards/pci-dss/)
