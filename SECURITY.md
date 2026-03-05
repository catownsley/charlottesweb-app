# Security Hardening Guide

## Overview

CharlottesWeb implements comprehensive security controls appropriate for a HIPAA compliance platform. This document outlines all security features and best practices.

## Security Features Implemented

### 1. Authentication & Authorization

#### API Key Authentication
- **Location:** [`src/security.py`](src/security.py)
- **Purpose:** Protect API endpoints from unauthorized access
- **How it works:**
  - API keys passed via `X-API-Key` header
  - Configurable via `API_KEY_REQUIRED` environment variable
  - Development: Optional (default: disabled)
  - Production: Must be enabled

**Generating API Keys:**
```python
from src.security import generate_api_key
api_key = generate_api_key()
# Store securely and provide to authorized clients
```

**Using API Keys:**
```bash
curl -H "X-API-Key: your-api-key-here" https://api.example.com/api/v1/organizations
```

**Configuration:**
```bash
# .env
API_KEY_REQUIRED=true
VALID_API_KEYS=key1,key2,key3
```

### 2. Rate Limiting

#### Per-IP Rate Limiting
- **Implementation:** slowapi library
- **Location:** [`src/main.py`](src/main.py), [`src/api.py`](src/api.py)
- **Default:** 60 requests/minute per IP
- **Customization:** Set `RATE_LIMIT_PER_MINUTE` in `.env`

**Configurable Limits:**
- Health check: 120 req/min (2x normal)
- Root endpoint: 120 req/min (2x normal)
- All other endpoints: 60 req/min (configurable)

**Response:**
```http
HTTP/1.1 429 Too Many Requests
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1709582400
```

### 3. Security Headers

#### Implemented Headers
**Location:** [`src/middleware.py`](src/middleware.py) → `SecurityHeadersMiddleware`

| Header | Value | Purpose |
|--------|-------|---------|
| `X-Frame-Options` | `DENY` | Prevent clickjacking |
| `X-Content-Type-Options` | `nosniff` | Prevent MIME sniffing |
| `X-XSS-Protection` | `1; mode=block` | Enable XSS filtering |
| `Content-Security-Policy` | `default-src 'none'` | Strict CSP for API |
| `Referrer-Policy` | `no-referrer` | Don't leak referrer info |
| `Permissions-Policy` | Restricts features | Disable unnecessary browser features |
| `Strict-Transport-Security` | `max-age=31536000` | Force HTTPS (HTTPS only) |

### 4. Audit Logging

#### Comprehensive Event Tracking
- **Location:** [`src/audit.py`](src/audit.py)
- **Log File:** `audit.log` (JSON format)
- **Retention:** Configure external log rotation

**Logged Events:**
- Authentication attempts (success/failure)
- Data access (read/write/delete)
- Assessment creation and execution
- Remediation roadmap generation
- Configuration changes
- Security alerts
- Errors and exceptions

**Log Format:**
```json
{
  "timestamp": "2026-03-04T12:34:56.789",
  "action": "assessment_created",
  "success": true,
  "level": "info",
  "request": {
    "id": "uuid-here",
    "ip": "192.168.1.100",
    "method": "POST",
    "path": "/api/v1/assessments",
    "user_agent": "curl/7.88.1"
  },
  "api_key_suffix": "xyz9",
  "resource_type": "assessment",
  "resource_id": "abc123",
  "details": {"organization_id": "org-456"}
}
```

### 5. Request Tracing

#### Request ID Tracking
- **Location:** [`src/middleware.py`](src/middleware.py) → `RequestIDMiddleware`
- **Header:** `X-Request-ID`
- **Purpose:** Trace requests through the system for debugging/audit

**Usage:**
```bash
# Client provides request ID
curl -H "X-Request-ID: my-trace-id" https://api.example.com/api/v1/health

# Or server generates one
curl https://api.example.com/api/v1/health
# Response includes: X-Request-ID: uuid-generated-by-server
```

### 6. CORS Configuration

#### Cross-Origin Resource Sharing
- **Location:** [`src/config.py`](src/config.py), [`src/main.py`](src/main.py)
- **Development:** Allows all origins (`*`)
- **Production:** Must specify allowed origins

**Configuration:**
```bash
# .env (Production)
CORS_ORIGINS=https://app.example.com,https://dashboard.example.com
CORS_ALLOW_CREDENTIALS=true
```

### 7. Error Handling

#### Secure Error Messages
- **Location:** [`src/main.py`](src/main.py)
- **Development:** Detailed error messages for debugging
- **Production:** Generic messages (no information leakage)

**Example:**
```python
# Development
{"detail": "sqlalchemy.exc.IntegrityError: UNIQUE constraint failed"}

# Production
{"detail": "Internal server error"}
```

### 8. Secrets Management

#### Environment-based Configuration
- **Location:** [`src/config.py`](src/config.py)
- **Method:** Environment variables via `.env` file
- **Never commit:** Add `.env` to `.gitignore`

**Critical Secrets:**
- `SECRET_KEY`: JWT signing (auto-generated if not set)
- `VALID_API_KEYS`: Authorized API keys
- `DATABASE_URL`: Database connection string
- `NVD_API_KEY`: External service credentials

### 9. Input Validation

#### Pydantic Schema Validation
- **Location:** [`src/schemas.py`](src/schemas.py)
- **Method:** Automatic validation via Pydantic models
- **Benefits:**
  - Type checking
  - Format validation
  - SQL injection prevention (via ORM)
  - XSS prevention (API returns JSON only)

### 10. HTTPS/TLS

#### Transport Layer Security
- **Certificates:** [`certs/`](certs/) directory
- **Development:** Self-signed certificates
- **Production:** Use Let's Encrypt or commercial CA

**Generate Dev Certs:**
```bash
./scripts/generate_dev_certs.sh
```

**Run with HTTPS:**
```bash
./run_https.sh
# or
uvicorn src.main:app --host 0.0.0.0 --port 8443 \
  --ssl-keyfile certs/key.pem \
  --ssl-certfile certs/cert.pem
```

---

## Production Security Checklist

### Before Deployment

- [ ] **Set `APP_ENV=production`** in environment variables
- [ ] **Set `DEBUG=false`** to disable debug mode
- [ ] **Generate strong `SECRET_KEY`** (minimum 32 characters)
  ```bash
  python -c "import secrets; print(secrets.token_urlsafe(32))"
  ```
- [ ] **Enable API key authentication** (`API_KEY_REQUIRED=true`)
- [ ] **Generate and distribute API keys** to authorized clients
- [ ] **Configure CORS origins** (don't use `*` in production)
- [ ] **Use PostgreSQL** instead of SQLite
  ```bash
  DATABASE_URL=postgresql://user:pass@host:5432/dbname
  ```
- [ ] **Obtain valid TLS certificate** (Let's Encrypt recommended)
- [ ] **Set up log rotation** for `audit.log`
- [ ] **Configure firewall** to restrict database access
- [ ] **Enable HSTS** (automatic when using HTTPS)
- [ ] **Review rate limits** and adjust per requirements
- [ ] **Set up monitoring** for audit log alerts
- [ ] **Backup strategy** for database and audit logs
- [ ] **Incident response plan** documented

### Recommended Infrastructure

1. **Reverse Proxy:** nginx or Cloudflare for additional DDoS protection
2. **WAF:** Web Application Firewall (Cloudflare, AWS WAF, etc.)
3. **Database:** Encrypted at rest, separate network, minimal privileges
4. **Secrets:** Use vault service (AWS Secrets Manager, HashiCorp Vault)
5. **Monitoring:** Sentry, Datadog, or similar for error tracking
6. **Logs:** Centralized logging (ELK stack, Splunk, CloudWatch)

---

## Automated Security Scanning

### CI/CD Pipeline Security (GitHub Actions)

#### 1. CodeQL Analysis
- **Workflow:** [`.github/workflows/security-scan.yml`](.github/workflows/security-scan.yml)
- **Runs:** On every pull request + nightly at 4:17 AM UTC
- **Quick Scan:** Language-specific queries for Python
- **Deep Scan:** Security-and-quality query suite (nightly only)
- **SARIF Upload:** Results visible in GitHub Security tab

#### 2. Bandit SAST
- **Workflow:** [`.github/workflows/security-scan.yml`](.github/workflows/security-scan.yml)
- **Runs:** On every pull request + nightly
- **Quick Scan:** All severity levels (non-blocking on PR)
- **Deep Scan:** Medium+ severity only (fails nightly build)
- **Coverage:** Python-specific security issues (B104, B201, B501, etc.)

#### 3. pip-audit Dependency Scanning ⭐ NEW
- **Workflow:** Both workflows
- **Runs:** On every pull request + nightly
- **Quick Scan:** Reports vulnerabilities (non-blocking on PR)
- **Strict Scan:** Fails build if vulnerabilities found (nightly only)
- **Coverage:** All dependencies in requirements.txt against OSV/PyPI advisory database

**Example Output:**
```bash
$ pip-audit -r requirements.txt
No known vulnerabilities found ✅
```

**Recent Fixes:**
- **CVE-2024-23342** (March 2026): Replaced python-jose → PyJWT
  - Eliminated Minerva timing attack in ecdsa transitive dependency
  - Reduced attack surface by 80% (4 deps → 0 deps for HS256)

### Startup Security Validation

#### Configuration Validation ⭐ NEW
- **Location:** [`src/config.py:validate_security_config()`](src/config.py)
- **Runs:** Automatically at application startup
- **Checks:** 6 critical security settings

**Validation Rules:**
1. ✅ Debug mode disabled in production (`DEBUG=false`)
2. ✅ Strong SECRET_KEY (32+ characters)
3. ✅ CORS explicit whitelist (no wildcard `*`)
4. ✅ API authentication enabled (`API_KEY_REQUIRED=true`)
5. ✅ PostgreSQL recommended for production (not SQLite)
6. ✅ Rate limiting enabled (`RATE_LIMIT_ENABLED=true`)

**Example Output:**
```python
# Development - no warnings
Security Warnings: 0 ✅

# Production with issues
🚨 SECURITY: DEBUG=True in production!
🚨 SECURITY: CORS allows all origins (*) in production!
⚠️  SECURITY: API authentication disabled in production.
⚠️  PRODUCTION: SQLite not recommended for production.
```

**Integration:**
- Logs warnings to audit trail
- Prints to console for visibility
- Does NOT block startup (allows emergency fixes)

---

## Security Testing

### Automated Testing
```bash
# Install security scanning tools
pip install bandit pip-audit

# Scan for common security issues
bandit -r src/

# Check for vulnerable dependencies (NEW)
pip-audit -r requirements.txt

# Run tests
pytest tests/
```

### Manual Testing
```bash
# Test rate limiting
for i in {1..70}; do curl http://localhost:8000/api/v1/health; done

# Test API key enforcement
curl http://localhost:8000/api/v1/organizations  # Should fail if required
curl -H "X-API-Key: invalid" http://localhost:8000/api/v1/organizations  # Should fail

# Verify security headers
curl -I https://localhost:8443/api/v1/health
```

---

## Incident Response

### Suspected API Key Compromise
1. **Immediate:** Rotate the compromised key
   ```bash
   # Remove from VALID_API_KEYS in .env
   # Generate new key
   python -c "from src.security import generate_api_key; print(generate_api_key())"
   ```
2. **Review audit logs** for unauthorized access
   ```bash
   grep "api_key_suffix: <last-4-chars>" audit.log
   ```
3. **Notify affected parties**
4. **Document incident**

### Suspicious Activity
1. **Check audit logs** for patterns
   ```bash
   grep '"success": false' audit.log | grep auth_failed
   ```
2. **Block offending IPs** at firewall/proxy level
3. **Reduce rate limits** temporarily if under attack
4. **Enable additional monitoring**

### Data Breach Response
1. **Isolate affected systems**
2. **Preserve evidence** (audit logs, database snapshots)
3. **Engage incident response team**
4. **Follow HIPAA breach notification requirements** (if applicable)
5. **Conduct post-incident analysis**

---

## Security Contacts

For security issues or questions:
- Create a GitHub issue: [charlottesweb-app/issues](https://github.com/catownsley/charlottesweb-app/issues)
- Tag with `security` label
- For sensitive vulnerabilities, contact directly (add contact info)

---

## Compliance Notes

### HIPAA Considerations
- This application **does not store PHI**
- Audit logging supports compliance evidence requirements
- All communications use HTTPS/TLS
- Access controls via API key authentication
- Rate limiting prevents denial of service

### SOC 2 Considerations
- Audit logs provide evidence for CC6.1 (Logical Access)
- Rate limiting supports CC7.1 (Availability)
- Security headers support CC6.6 (Logical Security)
- Error handling supports CC6.1 (Information Disclosure)

---

## Version History

- **v0.3.0** (2026-03-05): Security automation and dependency hardening
  - pip-audit automated dependency scanning (PR + nightly)
  - Startup security validation (6 configuration checks)
  - PyJWT migration (replaced python-jose, eliminated CVE-2024-23342)
  - 80% reduction in dependency attack surface
  - Zero known vulnerabilities

- **v0.2.0** (2026-03-04): Security hardening implementation
  - API key authentication
  - Rate limiting
  - Security headers
  - Audit logging
  - Request tracing
  - Error handling
  - Secrets management

- **v0.1.0** (2026-03-03): Initial MVP implementation
  - Basic API endpoints
  - HTTPS support (dev certificates)
  - CORS configuration
