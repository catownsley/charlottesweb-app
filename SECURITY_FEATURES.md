# Security Features Overview

A quick reference guide to CharlottesWeb's security capabilities. For detailed implementation, see [SECURITY.md](SECURITY.md) and [SECURITY_IMPLEMENTATION.md](SECURITY_IMPLEMENTATION.md).

---

## Feature Summary (8 Total)

| Feature | Purpose | Status |
|---------|---------|--------|
| **API Key Authentication** | Verify request origin with cryptographic keys | ✅ Active |
| **JWT Token Auth** | Secure session handling with HS256 signing | ✅ Active |
| **Rate Limiting** | Prevent abuse with per-IP throttling (60 req/min) | ✅ Active |
| **Security Headers** | 7 HTTP headers protecting against common attacks | ✅ Active |
| **Audit Logging** | JSON structured logs with 22 action types | ✅ Active |
| **Request Tracing** | UUID per request for incident investigation | ✅ Active |
| **Password Hashing** | Automatic bcrypt with dynamic salt | ✅ Active |
| **Secrets Management** | Environment-based configuration, zero secrets in code | ✅ Active |

---

## How Features Work Together

### Authentication Flow
```
Request → API Key Check (x-api-key header)
        → JWT Token Validation (if session-based)
        → Password Verification (if login)
        → Request logged to audit.log
        → Response returned with X-Request-ID
```

### Attack Prevention
```
Rate Limiting          → Blocks brute force / DDoS
Security Headers       → Blocks XSS, clickjacking, MIME sniffing
CSP Policy            → Blocks unauthorized script injection
Audit Logging         → Records all actions for forensics
Request Tracing       → Links requests to user actions
```

---

## Quick Configuration

### Enable/Disable Features (in `.env`)
```bash
# Authentication
API_KEY_REQUIRED=true                    # Require API key on all requests
VALID_API_KEYS=key1,key2,key3           # Comma-separated valid keys

# Rate Limiting
RATE_LIMIT_ENABLED=true                 # Per-IP throttling
RATE_LIMIT_PER_MINUTE=60                # Requests per minute per IP

# Security Headers
APP_ENV=production                       # Triggers strict CSP
CORS_ORIGINS=https://yourapp.com        # Whitelist domains

# JWT
JWT_ALGORITHM=HS256                      # Token signing algorithm
ACCESS_TOKEN_EXPIRE_MINUTES=30           # Session timeout (30 min = 330 min total)
```

---

## Audit Log Format

Every action is logged with:
- **Timestamp**: ISO 8601 with timezone
- **Action**: One of 22 types (LOGIN, DATA_CREATE, DATA_READ, etc.)
- **User**: Authenticated user ID or "unknown"
- **Request ID**: UUID for tracing
- **Resource**: What was accessed (org, assessment, control, etc.)
- **Details**: Context about the action
- **Severity**: INFO, WARNING, ERROR, CRITICAL

**Example log entry:**
```json
{
  "timestamp": "2026-03-04T10:23:45.123456+00:00",
  "action": "ORG_CREATED",
  "user_id": "admin-001",
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "resource_type": "organization",
  "resource_id": "org-12345",
  "api_key_last_4": "...x7k2",
  "details": "New organization registered",
  "level": "INFO"
}
```

---

## Security Headers Explained

| Header | Blocks | Example |
|--------|--------|---------|
| **Strict-Transport-Security** | HTTP downgrade attacks | Forces HTTPS for 1 year |
| **Content-Security-Policy** | XSS, inline script injection | Blocks external scripts (strict) or allows CDN (docs only) |
| **X-Frame-Options** | Clickjacking | DENY for APIs, SAMEORIGIN for docs |
| **X-Content-Type-Options** | MIME sniffing | Prevents browser from guessing file type |
| **X-XSS-Protection** | Legacy browsers | Blocks inline scripts |
| **Referrer-Policy** | Information leakage | No referrer on inter-site navigation |
| **Permissions-Policy** | Unauthorized feature access | Disables camera, microphone, geolocation |

---

## API Key Usage

### Generating a Key
```python
from src.security import generate_api_key

key = generate_api_key()  # Returns cryptographically secure 32-char string
# Output example: "sk_prod_7a4c8f2e9b1d3c6e5a2f8g7h4i9j0k"
```

### Using in Requests
```bash
# Include in every request header
curl -H "X-API-Key: sk_prod_7a4c8f2e9b1d3c6e5a2f8g7h4i9j0k" \
     https://api.example.com/api/v1/organizations
```

### Key Rotation
1. Generate new key via `generate_api_key()`
2. Add to `VALID_API_KEYS` in `.env`
3. Update clients to use new key
4. Remove old key from `VALID_API_KEYS`
5. Old key access is blocked immediately

---

## JWT Token Usage

### Creating a Token
```python
from src.security import create_access_token
from datetime import timedelta

token = create_access_token(
    data={"sub": "user123"},
    expires_delta=timedelta(minutes=30)
)
```

### Using in Requests
```bash
curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIs..." \
     https://api.example.com/api/v1/assessments
```

### Token Expiration
- Default: 30 minutes (`ACCESS_TOKEN_EXPIRE_MINUTES`)
- Expired tokens return **401 Unauthorized**
- Tokens are **not** stored server-side (stateless auth)

---

## Rate Limiting in Action

```
Client A: Requests 1-60 ✅ Allowed
Client A: Request 61    ❌ Blocked (429 Too Many Requests)
Client B: Request 1-60  ✅ Allowed (separate IP)
```

**Bypassing is NOT possible with valid requests** - limits are per IP address and enforced at middleware level.

Health check endpoint has **2x limit** (120/min) for monitoring systems.

---

## Compliance Mapping

### HIPAA 164.312(b) - Audit Controls
✅ **Met by**: Audit logging with 22 action types, JSON structured logs, request tracing

### SOC 2 CC6.1 - Logical Access Controls
✅ **Met by**: API key auth, JWT tokens, password hashing, role checking (via requests)

### SOC 2 CC7.1 - System Monitoring
✅ **Met by**: Audit logs, security alerts, request tracing, rate limiting

### OWASP Top 10 Coverage
| Vulnerability | Mitigation |
|---|---|
| **A01:2021 - Broken Access Control** | API keys, JWT, rate limiting |
| **A02:2021 - Cryptographic Failures** | bcrypt hashing, HS256 tokens, TLS/HTTPS |
| **A03:2021 - Injection** | Pydantic validation, parameterized queries |
| **A06:2021 - Vulnerable Components** | Dependencies in requirements.txt pinned |
| **A09:2021 - Logging & Monitoring** | Audit logs with request tracing |

---

## Emergency Procedures

### Disable API Key Requirement (If Service Down)
```bash
# In .env
API_KEY_REQUIRED=false

# Restart app - all requests now allowed
# ⚠️ Immediately add API keys back after restoring service
```

### Block Suspicious IP
```bash
# Implement at reverse proxy / WAF level (not in app)
# Or temporarily set RATE_LIMIT_PER_MINUTE=1 for emergency throttle
```

### Rotate All Secrets
1. Generate new `SECRET_KEY` (any random 32+ char string)
2. All existing JWT tokens become invalid
3. Users must re-authenticate
4. All new tokens signed with new key

### Audit Log Breach
1. Export audit.log for forensics
2. Cross-reference `request_id` values
3. Identify compromised resources via `resource_id`
4. Reset access tokens/API keys for affected users
5. Check `details` field for suspicious patterns

---

## Testing Security Features

### Test API Key Enforcement
```bash
# Should fail (missing key)
curl https://localhost:8443/api/v1/organizations

# Should succeed (valid key)
curl -H "X-API-Key: YOUR_KEY" https://localhost:8443/api/v1/organizations
```

### Test Rate Limiting
```bash
# Run 65 requests in rapid succession
for i in {1..65}; do
  curl -H "X-API-Key: YOUR_KEY" https://localhost:8443/api/v1/health
done
# First 60 return 200 OK, requests 61-65 return 429 Too Many Requests
```

### Test Security Headers
```bash
curl -I https://localhost:8443/api/v1/health

# Should include headers:
# Strict-Transport-Security: max-age=31536000; includeSubDomains
# Content-Security-Policy: default-src 'none'; ... (strict)
# X-Frame-Options: DENY
```

### Test Audit Logging
```bash
# Trigger action (e.g., create organization)
curl -X POST -H "X-API-Key: YOUR_KEY" \
     -H "Content-Type: application/json" \
     -d '{"name": "Test Org"}' \
     https://localhost:8443/api/v1/organizations

# Check audit log
tail -10 audit.log | python3 -m json.tool
```

### Test Request Tracing
```bash
# Check response headers
curl -v https://localhost:8443/api/v1/health 2>&1 | grep "X-Request-ID"

# Cross-reference with audit log to trace action
```

---

## What's NOT Included (Intentional Gaps)

| Item | Reason | Recommendation |
|------|--------|-----------------|
| **Password Manager** | Database design only; auth is API/JWT | Use environment-based secrets |
| **Multi-factor Auth (MFA)** | Requires user registration system | Implement in frontend/auth service |
| **Role-Based Access Control (RBAC)** | Future enhancement | Model in Phase 3 |
| **End-to-End Encryption** | Handles metadata only (no PHI) | Add for production use |
| **Web Application Firewall (WAF)** | Infrastructure concern | Deploy Cloudflare/AWS WAF |
| **Key Management Service (KMS)** | Infrastructure concern | Use AWS KMS, HashiCorp Vault |

---

## Next Steps

### Before Production
- [ ] Review SECURITY.md for detailed configuration
- [ ] Rotate `SECRET_KEY` in `.env`
- [ ] Set `APP_ENV=production` (enforces strict CSP)
- [ ] Whitelist CORS origins (remove `*`)
- [ ] Generate strong `VALID_API_KEYS`
- [ ] Set `API_KEY_REQUIRED=true`
- [ ] Configure log rotation for `audit.log`
- [ ] Enable monitoring/alerting on audit logs

### Ongoing
- [ ] Review audit logs weekly for suspicious patterns
- [ ] Rotate API keys quarterly
- [ ] Update dependencies monthly (`pip install --upgrade`)
- [ ] Monitor rate limiting metrics
- [ ] Test emergency procedures quarterly

---

## Support & Questions

For detailed implementation:
- **[SECURITY.md](SECURITY.md)** - 10 features, usage examples, production checklist
- **[SECURITY_IMPLEMENTATION.md](SECURITY_IMPLEMENTATION.md)** - 500+ lines of code comments, compliance mapping

For code examples:
- **[src/security.py](src/security.py)** - Authentication utilities
- **[src/audit.py](src/audit.py)** - Logging implementation
- **[src/middleware.py](src/middleware.py)** - Security headers & rate limiting

---

**Last Updated**: March 4, 2026  
**Version**: 1.0.0  
**Status**: Production Ready ✅
