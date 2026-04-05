# Security Guide

This guide covers the security controls built into CharlottesWeb, including configuration, testing, and incident response.

---

## Quick Reference

| Feature | Purpose | Status |
|---------|---------|--------|
| **API Key Authentication** | Verify request origin with cryptographic keys | Active |
| **JWT Token Auth** | Secure session handling with HS256 signing (PyJWT) | Active |
| **Rate Limiting** | Prevent abuse with per-IP throttling (60 req/min) | Active |
| **Security Headers** | 7 HTTP headers protecting against common attacks | Active |
| **Audit Logging** | JSON structured logs with structured event tracking | Active |
| **Request Tracing** | UUID per request for incident investigation | Active |
| **Password Hashing** | Automatic bcrypt with dynamic salt | Active |
| **TLS Enforcement** | HTTPS redirect middleware, HSTS headers, port 8443 only | Active |
| **Secrets Management** | Environment-based configuration, zero secrets in code | Active |
| **CodeQL + Bandit SAST** | Automated code scanning in CI/CD pipeline | Active |
| **pip-audit Scanning** | Dependency vulnerability detection (blocks CVEs) | Active |
| **Dependency Hash Verification** | SHA256 hash pinning prevents supply chain tampering | Active |
| **OAuth/OIDC** | External IdP token validation for enterprise deployment | Ready |
| **Startup Validation** | Configuration security checks at boot | Active |

---

## Detailed Feature Documentation

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

#### OAuth/OIDC Authentication (Enterprise, Ready for Integration)
- **Location:** [`src/security.py`](src/security.py), [`src/config.py`](src/config.py)
- **Purpose:** Enable token-based auth via external identity providers for customer deployments
- **Status:** Infrastructure built and tested; no IdP configured in the prototype. Activate by setting environment variables when deploying to a customer environment with an IdP.
- **How it works:**
- Set `OAUTH_ENABLED=true` and configure IdP settings
- App fetches IdP public keys (JWKS) and caches them
- Bearer tokens validated: RS256 signature, expiration, issuer, audience
- All auth errors return generic "Authentication failed" to prevent information leakage
- Specific failure reasons (expired, wrong audience, wrong issuer) logged server-side
- Exception chains suppressed (`raise from None`) to prevent token data in tracebacks

**Supported Providers:** Okta, Azure AD, Google Workspace, or any OIDC-compliant IdP

**Configuration:**
```bash
# .env
OAUTH_ENABLED=true
OAUTH_ISSUER_URL=https://your-org.okta.com/oauth2/default
OAUTH_CLIENT_ID=your-app-client-id
OAUTH_AUDIENCE=api://charlottesweb
```

**Using Bearer Tokens:**
```bash
curl -H "Authorization: Bearer <token>" https://api.example.com/api/v1/organizations
```

**Pluggable Auth:** The `get_current_auth()` dependency automatically routes to OAuth or API key validation based on configuration. Endpoints do not need to change.

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

#### Event Tracking
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
- [ ] **Configure PostgreSQL** with password authentication
```bash
DATABASE_URL=postgresql://user:password@host/charlottesweb
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
No known vulnerabilities found
```

**Recent Fixes:**
- **CVE-2024-23342** (March 2026): Replaced python-jose → PyJWT
- Eliminated Minerva timing attack in ecdsa transitive dependency
- Reduced attack surface by 80% (4 deps → 0 deps for HS256)

#### 4. Dependency Hash Verification (Supply Chain Security)
- **File:** [`requirements.lock`](requirements.lock)
- **Workflow:** Security Scan (PR Quick)
- **Purpose:** Prevent supply chain attacks by verifying SHA256 hashes of all dependencies
- **How it works:** `requirements.lock` contains pinned versions AND cryptographic hashes for every package (including transitive dependencies). CI runs `pip install --no-deps --require-hashes --dry-run` to verify that packages on PyPI match the expected hashes. The `--no-deps` flag prevents pip from resolving platform specific transitive dependencies not in the lock file (e.g., `greenlet` on Linux). If a package has been tampered with or swapped, the hash won't match and the build fails.

**Regenerating after dependency changes:**
```bash
pip-compile --generate-hashes --output-file=requirements.lock requirements.txt
```

**What this protects against:**
- Compromised package on PyPI (supply chain attack)
- Dependency confusion (attacker publishes a package with the same name on a public registry)
- Unauthorized modification of packages after publication

### Startup Security Validation

#### Configuration Validation ⭐ NEW
- **Location:** [`src/config.py:validate_security_config()`](src/config.py)
- **Runs:** Automatically at application startup
- **Checks:** 6 critical security settings

**Validation Rules:**
1. Debug mode disabled in production (`DEBUG=false`)
2. Strong SECRET_KEY (32+ characters)
3. CORS explicit whitelist (no wildcard `*`)
4. API authentication enabled (`API_KEY_REQUIRED=true`)
5. PostgreSQL with password authentication required
6. Rate limiting enabled (`RATE_LIMIT_ENABLED=true`)

**Example Output:**
```python
# Development - no warnings
Security Warnings: 0

# Production with issues
SECURITY: DEBUG=True in production!
SECURITY: CORS allows all origins (*) in production!
️ SECURITY: API authentication disabled in production.
️ PRODUCTION: PostgreSQL is required.
```

**Integration:**
- Logs warnings to audit trail
- Prints to console for visibility
- Does NOT block startup (allows emergency fixes)

---

## Security Controls for Regulated Environments

Charlotte's Web ingests only software metadata (component names, versions, infrastructure details). It does not process, store, or transmit PHI, PII, or other regulated data. However, if you deploy this application in a regulated environment, the following security controls are in place and can be referenced in your compliance documentation.

### Authentication and Access Control

| Control | Implementation | Relevant Frameworks |
|---|---|---|
| API key authentication | Cryptographically secure key generation, constant time comparison | SOC 2 CC6.1, NIST AC-3, PCI DSS 7/8 |
| OAuth/OIDC (ready for integration) | RS256 token validation via JWKS, issuer/audience verification | SOC 2 CC6.1, NIST IA-2, PCI DSS 8 |
| JWT session tokens | HS256 signed, configurable expiry | SOC 2 CC6.1, NIST IA-5 |
| Password hashing | bcrypt with dynamic salt rounds | NIST IA-5, PCI DSS 8.3 |
| Rate limiting | Per-IP throttling (60 req/min default) via slowapi | SOC 2 CC6.1, NIST SC-5 |

### Audit and Monitoring

| Control | Implementation | Relevant Frameworks |
|---|---|---|
| Structured audit logging | JSON formatted, all auth and CRUD events recorded | SOC 2 CC7.1, NIST AU-2/AU-3, HIPAA 164.312(b) |
| Request tracing | Unique request ID propagated across log entries | SOC 2 CC7.1, NIST AU-3 |
| Authentication event logging | Login attempts, failures, key usage (last 4 chars only) | NIST AU-2, PCI DSS 10.2 |
| Startup configuration validation | 7 security checks run at boot, warnings logged for misconfigurations | NIST CM-6, SOC 2 CC8.1 |

### Data Protection

| Control | Implementation | Relevant Frameworks |
|---|---|---|
| TLS/HTTPS enforcement | All connections require TLS, HSTS header enabled | NIST SC-8, PCI DSS 4.1, HIPAA 164.312(e)(1) |
| Security headers | CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy | OWASP A05 |
| Input validation | Pydantic schema validation on all API inputs | NIST SI-10, OWASP A03 |
| Parameterized queries | SQLAlchemy ORM prevents SQL injection | OWASP A03, NIST SI-10 |
| Secrets management | Environment variable based, never hardcoded or logged | NIST SC-28, PCI DSS 6.5 |

### Supply Chain and Dependency Security

| Control | Implementation | Relevant Frameworks |
|---|---|---|
| Static analysis (SAST) | Bandit + CodeQL on every PR | NIST SA-11, PCI DSS 6.3 |
| Dependency vulnerability scanning | pip-audit against OSV.dev database | NIST SI-2, SOC 2 CC7.1 |
| Dependency hash pinning | SHA256 hashes in requirements.lock, verified in CI | NIST SI-7, OWASP A06 |
| Pinned dependency versions | All direct and transitive dependencies version locked | NIST CM-7, OWASP A06 |

### OWASP Top 10 2021 Coverage

| Vulnerability | Mitigation |
|---|---|
| **A01 Broken Access Control** | API keys, JWT, OAuth/OIDC ready, rate limiting |
| **A02 Cryptographic Failures** | bcrypt hashing, RS256/HS256 tokens, TLS enforcement |
| **A03 Injection** | Pydantic validation, parameterized queries (SQLAlchemy) |
| **A05 Security Misconfiguration** | Startup validation, secure defaults, security headers |
| **A06 Vulnerable Components** | pip-audit, CodeQL, Bandit, hash pinned dependencies |
| **A08 Software and Data Integrity** | SHA256 hash verification, SAST in CI pipeline |
| **A09 Logging and Monitoring** | Structured audit logs, request tracing, auth event tracking |

---

## Threat Model

For the full threat model, STRIDE analysis, CVE dispositions, and dependency vulnerability assessment, see [THREAT_MODEL.md](THREAT_MODEL.md).

---

## Emergency Procedures

### Disable API Key Requirement (Emergency Access)
```bash
# In .env
API_KEY_REQUIRED=false

# Restart application - all requests now allowed
# ️ IMMEDIATELY re-enable authentication after restoring service
```

### Block Suspicious IP Address
```bash
# Implement at reverse proxy / firewall level (recommended)
# Or temporarily throttle: RATE_LIMIT_PER_MINUTE=1
```

### Rotate All Secrets (Security Incident)
1. Generate new `SECRET_KEY`:
```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```
2. Update `.env` file
3. Restart application
4. **Impact:** All existing JWT tokens become invalid
5. Users must re-authenticate

### Audit Log Breach Response
1. Export `audit.log` for forensics
2. Cross-reference `request_id` values across entries
3. Identify compromised resources via `resource_id`
4. Reset access tokens/API keys for affected users
5. Check `details` field for suspicious patterns
6. Engage incident response team if sensitive data potentially exposed

---

## Security Testing

### Automated Testing
```bash
# Install security scanning tools
pip install bandit pip-audit

# Scan for common security issues
bandit -r src/

# Check for vulnerable dependencies
pip-audit -r requirements.txt

# Run unit tests
pytest tests/ -v
```

### Manual Testing

#### Test API Key Enforcement
```bash
# Should fail (missing key) when API_KEY_REQUIRED=true
curl https://localhost:8443/api/v1/organizations

# Should succeed with valid key
curl -H "X-API-Key: YOUR_KEY" https://localhost:8443/api/v1/organizations
```

#### Test Rate Limiting
```bash
# Run 65 requests in rapid succession
for i in {1..65}; do
curl -H "X-API-Key: YOUR_KEY" https://localhost:8443/api/v1/health
done
# First 60 return 200 OK, requests 61-65 return 429 Too Many Requests
```

#### Test Security Headers
```bash
# Verify all security headers are present
curl -I https://localhost:8443/api/v1/health

# Expected headers include:
# Strict-Transport-Security: max-age=31536000; includeSubDomains
# Content-Security-Policy: default-src 'none'; ...
# X-Frame-Options: DENY
# X-Content-Type-Options: nosniff
# X-XSS-Protection: 1; mode=block
# Referrer-Policy: no-referrer
```

#### Test Audit Logging
```bash
# Trigger an action
curl -X POST -H "X-API-Key: YOUR_KEY" \
-H "Content-Type: application/json" \
-d '{"name": "Test Org"}' \
https://localhost:8443/api/v1/organizations

# Check audit log for the event
tail -10 audit.log | python3 -m json.tool
```

#### Test Request Tracing
```bash
# Verify request ID in response headers
curl -v https://localhost:8443/api/v1/health 2>&1 | grep "X-Request-ID"

# Or provide your own request ID
curl -H "X-Request-ID: my-trace-123" https://localhost:8443/api/v1/health

# Cross-reference with audit log
grep "my-trace-123" audit.log
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
4. **Follow applicable breach notification requirements**
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
- **Status: Not Applicable.** See [THREAT_MODEL.md, Section 10.1](THREAT_MODEL.md#101-hipaa-not-applicable) for the full determination.

### SOC 2 Considerations
- Audit logs provide evidence for CC6.1 (Logical Access)
- Rate limiting supports CC7.1 (Availability)
- Security headers support CC6.6 (Logical Security)
- Error handling supports CC6.1 (Information Disclosure)

---

## Version History

**v0.4.0 (2026-03-14):** Threat model assessment and TLS enforcement
- STRIDE-based threat model analysis with 27 findings mapped to dispositions
- HTTPS enforcement middleware (HTTP 301 redirect to HTTPS)
- TLS-only dev server (port 8443, requires certificates)
- PyJWT upgraded to 2.12.1 (patches CVE-2026-32597)
- Dependency vulnerability assessment with false positive identification
- HIPAA formally documented as Not Applicable (no PHI in scope)
- Compound risk analysis with residual risk ratings

**v0.3.0 (2026-03-05):** Security automation and dependency hardening
- pip-audit automated dependency scanning (PR non-blocking + nightly strict)
- Startup security validation with 6 configuration checks
- PyJWT migration (eliminated CVE-2024-23342 in python-jose dependency)
- 80% reduction in dependency attack surface for HS256 algorithm
- Zero known vulnerabilities

**v0.2.0 (2026-03-04):** Security hardening
- API key authentication with configurable enforcement
- Per-IP rate limiting with slowapi
- 7 security headers (including CSP, HSTS, X-Frame-Options)
- Audit logging with 22+ event types
- Request ID tracing for incident investigation
- Secure error handling (environment-aware)
- Environment-based secrets management

**v0.1.0 (2026-03-03):** Initial MVP
- FastAPI foundation with CRUD endpoints
- HTTPS support with self-signed dev certificates
- Basic CORS configuration

---

## Additional Resources

- **[DEV_GUIDE.md](DEV_GUIDE.md):** Development setup and local testing
- **[src/security.py](src/security.py):** Authentication utilities
- **[src/audit.py](src/audit.py):** Logging implementation
- **[src/middleware.py](src/middleware.py):** Security headers & rate limiting
- **[OWASP Top 10](https://owasp.org/www-project-top-ten/):** Web security fundamentals
- **[HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/index.html):** Compliance framework

---

**Last Updated:** March 14, 2026
**Status:** Production Ready
**Security Posture:** See [THREAT_MODEL.md](THREAT_MODEL.md) for current threat model status
