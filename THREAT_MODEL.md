# Threat-Model Architecture Diagram

This diagram is designed for security review and threat modeling (DFD-style with trust boundaries).

## Full Solution Architecture (Threat Modeling View)

```mermaid
flowchart LR
    %% =====================
    %% Trust Boundaries
    %% =====================

    subgraph TB1[Trust Boundary 1: End User Environment]
        U[Security/Compliance User]
        B[Browser UI\nstatic/index.html + JS]
        U -->|1. Enter org + stack/manifest| B
    end

    subgraph TB2[Trust Boundary 2: Application Service]
        GW[FastAPI App\nmain.py]
        MW[Security Middleware\nHeaders, Request ID, Rate Limit, CORS, GZip]
        API[API Router\n/api/v1]

        R_ORG[organizations router]
        R_META[metadata_profiles router]
        R_COMP[components router]
        R_ASSESS[assessments router]
        R_EVID[evidence router]
        R_RISK[risk router]

        RE[Rules/Assessment Engine]
        CE[Compliance Mapping + CWE Mapping]
        RS[Risk Scoring Engine]
        MP[Manifest Parser\npom.xml ingestion]
    end

    subgraph TB3[Trust Boundary 3: Persistence Layer]
        DB[(SQLite/PostgreSQL\nOrganizations, Profiles, Assessments,\nFindings, Evidence, Controls)]
    end

    subgraph TB4[Trust Boundary 4: External Intel Services]
        OSV[OSV.dev API\nVulnerability advisories]
        NVD[NVD API\nCPE version intelligence]
        MITRE[MITRE ATT&CK mappings]
    end

    subgraph TB5[Trust Boundary 5: Operational Artifacts]
        AUDIT[(Audit Logs)]
        CERTS[(Local TLS Certs\n/dev cert.pem + key.pem)]
    end

    %% =====================
    %% Main Request Path
    %% =====================

    B -->|2. HTTPS API calls| GW
    GW --> MW --> API

    API --> R_ORG
    API --> R_META
    API --> R_COMP
    API --> R_ASSESS
    API --> R_EVID
    API --> R_RISK

    %% Component/manifest workflows
    R_COMP --> MP
    R_COMP -->|3a. versions/suggestions lookup| NVD

    %% Assessment workflows
    R_ASSESS --> RE
    RE --> CE
    RE -->|3b. vulnerability enrichment| OSV
    RE -->|3c. threat context| MITRE
    RE --> DB

    %% Evidence + risk workflows
    R_EVID --> DB
    R_RISK --> RS --> DB

    %% Persistence reads/writes
    R_ORG --> DB
    R_META --> DB
    R_COMP --> DB
    R_ASSESS --> DB

    %% Observability / security artifacts
    GW --> AUDIT
    MW --> AUDIT
    GW -. local HTTPS startup .-> CERTS

    %% Response path
    DB --> API
    API --> GW
    GW -->|4. Findings, checklist, backlog, reports| B

```

## STRIDE Threat Model (Per Diagram)

### Key Entry Points (from diagram)
* **TB1 → TB2:** Browser HTTPS API calls (label "2")
* **TB2 → TB3:** Data persistence (organizations, assessments, findings writes)
* **TB2 → TB4:** Outbound OSV.dev/NVD/MITRE queries (labels "3a", "3b", "3c")
* **TB2 → TB5:** Audit logging + TLS cert loading
* **TB3 ← → TB2:** Assessment/finding reads and writes

### Sensitive Assets
* Organization metadata (TB1 → TB2 → TB3)
* Software stack + manifest content (R_META, R_COMP, MP in TB2)
* Assessment findings + evidence (R_ASSESS, R_EVID writes to TB3)
* Audit logs (TB5)
* API keys (request auth)
* OSV.dev/NVD query results (TB4 ← TB2)

---

## 1. SPOOFING (Identity & Auth)

**Threat Actors:** Attackers claim to be legitimate users or internal services to bypass authentication.

### 1.1 API Caller Impersonation (TB1 → TB2 boundary)
**Attack:** Attacker sends requests without valid API key or forges authentication.

| Component | Current Risk | Mitigation |
|-----------|-------------|-----------|
| TB1 Browser sends HTTPS requests (label "2") | MEDIUM | HTTPS prevents tampering in transit |
| TB2 Middleware validates API keys | MEDIUM | Optional in dev; required in prod |
| All routers check `get_api_key_optional()` | MEDIUM | Config-driven; not database-backed |
| Rate limiting: 60 req/min per IP | **LOW** | Slows brute force |

**Recommended Hardening (⚠️ High):**
* Implement per-API-key rate limits (500 req/min per key)
* Move valid keys to database with versioning
* Hash stored keys; rotate every 30 days
* Log all auth attempts (success/failure)

---

### 1.2 Cross-Organization Access (TB2 ↔ TB3 boundary)
**Attack:** Attacker reads/modifies Organization A's assessments despite having no membership in Org A.

| Component | Current Risk | Mitigation |
|-----------|-------------|-----------|
| TB2 R_ORG routes accept `organization_id` as parameter | **CRITICAL** | No caller identity check; any org_id accepted |
| TB2 R_ASSESS, R_EVID filter by org_id | MEDIUM | SQL-level filtering works; but caller verification missing |
| TB3 Database has no row-level security (RLS) | **HIGH** | Database doesn't enforce org boundaries |
| No user authentication layer | **CRITICAL** | No way to associate caller with org membership |

**Recommended Hardening (⚠️ CRITICAL):**
* Implement user authentication (JWT or session tokens)
* Add `OrganizationMember` table with roles (admin, analyst, viewer)
* Verify caller's org membership before every org-scoped query:
```python
member = db.query(OrganizationMember).filter_by(
    organization_id=requested_org_id,
    user_id=current_user.id
).first()
if not member:
    raise 403 "Not authorized for this organization"
```
* Add database row-level security (PostgreSQL RLS) as defense-in-depth

---

## 2. TAMPERING (Integrity)

**Threat Actors:** Attackers modify data in flight, at rest, or during processing.

### 2.1 Manifest Input Tampering (TB1 → TB2, specifically MP - Manifest Parser)
**Attack:** Attacker modifies manifest content (pom.xml) to inject malicious component names or bypass filtering.

| Component | Current Risk | Mitigation |
|-----------|-------------|-----------|
| Browser uploads manifest to R_COMP router | MEDIUM | HTTPS protects transit |
| MP (Manifest Parser) in TB2 parses XML | **HIGH** | No content validation or checksums |
| No schema validation | **HIGH** | Accepts any well-formed XML |
| No integrity check stored | **HIGH** | Can't detect post-storage modifications |

**Recommended Hardening (⚠️ High):**
* Validate manifest content-type: `application/xml` or `text/xml` only
* Enforce manifest size limit: 5 MB max
* Store manifest SHA-256 hash in TB3 database
* Validate XML schema against whitelist of allowed elements
* Re-verify hash on retrieval to detect tampering

---

### 2.2 Finding/Evidence Modification (TB2 R_EVID ↔ TB3 boundary)
**Attack:** Attacker modifies assessments or findings after creation to hide vulnerabilities or cover tracks.

| Component | Current Risk | Mitigation |
|-----------|-------------|-----------|
| TB2 R_EVID PATCH endpoint allows updates | **HIGH** | Any authenticated caller can modify findings |
| TB3 Database stores findings in-place (no versions) | **HIGH** | No history of changes; modifications cover tracks |
| TB5 Audit logging captures action but not diffs | MEDIUM | Can't see what was changed |

**Recommended Hardening (⚠️ High):**
* Implement finding versioning (immutable storage):
  * Create new `FindingVersion` record on each update (don't modify original)
  * Mark old version as "superseded"
  * Store change summary + modifier identity
* Implement approval workflow for high-severity finding changes
* Require audit sign-off layer before findings marked "resolved"

---

### 2.3 Vulnerability API Cache Poisoning (TB2 ← → TB4 boundary)
**Attack:** Attacker intercepts or modifies OSV.dev/NVD responses before caching in TB2.

| Component | Current Risk | Mitigation |
|-----------|-------------|-----------|
| TB2 caches vulnerability responses in memory | **MEDIUM** | Cache not persisted; resets on restart |
| HTTPS validation on API calls | **LOW** | OSV.dev and NVD use TLS; requests library validates certs |
| Cache keyed by component name | **MEDIUM** | Attacker learns what's cached |
| No cache entry signature | **HIGH** | Can't detect tampering if cache compromised |

**Recommended Hardening:**
* Implement cache entry signing (HMAC over response data)
* Cache expiration: 24 hours (TTL)
* Monitor cache hit/miss ratio for anomalies

---

## 3. REPUDIATION (Accountability & Audit Trail)

**Threat Actors:** Attackers deny their actions or the system can't prove who did what.

### 3.1 Audit Log Gaps or Tampering (TB2 ↔ TB5 boundary)
**Attack:** Attacker performs action that goes unlogged, or deletes/modifies logs after the fact.

| Component | Current Risk | Mitigation |
|-----------|-------------|-----------|
| TB2 Middleware + all routers log to TB5 AUDIT | **LOW** | Good coverage of critical actions |
| Request IDs (from RequestIDMiddleware) enable correlation | **LOW** | Helps trace requests across logs |
| TB5 Audit logs stored in local file (audit.log) | **HIGH** | File system access can read/modify logs |
| No encryption on audit log file | **HIGH** | Plain-text content visible if compromised |
| No remote log shipping | **HIGH** | Logs not redundantly stored; single point of failure |

**Recommended Hardening (⚠️ High):**
* Ship logs to centralized SIEM immediately (Splunk, ELK, Datadog)
* Implement hash chain on audit records (each entry includes hash of previous)
* Encrypt audit logs at rest: AES-256-GCM
* Set file permissions: 600 (read-only to app user)
* Implement 90-day retention policy + archive older logs

---

### 3.2 Request Tracing Gaps (TB2 Middleware)
**Attack:** Attacker makes requests without identifiable correlation; audit log can't link events.

| Component | Current Risk | Mitigation |
|-----------|-------------|-----------|
| RequestIDMiddleware generates UUID per request | **LOW** | All requests traced |
| Request ID available to all route handlers | **LOW** | Included in logs |
| TB5 Audit logs include request ID | **LOW** | Full correlation chain present |

**Recommended Hardening:**
* Ensure request ID included in all structured log lines
* Continue propagating context for async tasks

---

## 4. INFORMATION DISCLOSURE (Confidentiality & Data Leakage)

**Threat Actors:** Attackers read data they shouldn't: org data, findings, metadata, audit logs, etc.

### 4.1 Cross-Organization Data Leakage (TB2 ↔ TB3 boundary)
**Attack:** Attacker reads findings, evidence, or profiles from other organizations.

| Component | Current Risk | Mitigation |
|-----------|-------------|-----------|
| TB2 routers filter queries by `organization_id` | MEDIUM | SQL filtering works if caller has legitimate org_id |
| TB3 Database has no row-level security | **HIGH** | DB doesn't enforce org boundaries |
| TB2 API routes accept `organization_id` parameter | **CRITICAL** | No verification caller can access that org (see Spoofing 1.2) |
| Audit logs capture org_id but not user identity | MEDIUM | Hard to attribute who accessed what |

**Recommended Hardening (⚠️ CRITICAL):**
* Implement user authentication + per-org membership checks (see Spoofing 1.2)
* Add database RLS: every query automatically filtered by `user_accessible_orgs`
* Implement per-role response filtering (admin sees all fields; analyst sees findings only; viewer sees read-only)

---

### 4.2 Error Message Information Leakage (TB2 Exception Handlers)
**Attack:** Attacker extracts system details (stack traces, schema info) from verbose error responses.

| Component | Current Risk | Mitigation |
|-----------|-------------|-----------|
| Production mode returns generic errors | **LOW** | Safe in production |
| Debug mode returns detailed errors | **LOW** | Only in development |
| Stack traces logged server-side, not returned | **LOW** | Good practice |
| Validation errors in dev expose schema hints | **MEDIUM** | Dev-only; low risk but worth hardening |

**Recommended Hardening:**
* Ensure `debug=false` and `APP_ENV=production` always in production
* Add startup check: warn if debug enabled in prod

---

### 4.3 OSV.dev/MITRE Data Leakage (TB2 ↔ TB4 boundary)
**Attack:** Attacker learns what components/vulnerabilities are cached by timing analysis or unintended responses.

| Component | Current Risk | Mitigation |
|-----------|-------------|-----------|
| TB2 caches vulnerability responses in memory | **MEDIUM** | Cache keys leaked if process memory readable |
| Cache keyed by component name | **MEDIUM** | Attacker learns what's being assessed |
| No cache access control | **MEDIUM** | Any process thread can read cache |

**Recommended Hardening:**
* Encrypt sensitive cache entries (AES-256)
* Implement cache entry time-to-live (TTL): 24 hours
* Monitor cache usage for anomalies
* Don't expose cache stats in debug endpoints

---

### 4.4 Audit Log Exposure (TB5 Storage)
**Attack:** Attacker reads audit logs to learn about other orgs' vulnerabilities or activities.

| Component | Current Risk | Mitigation |
|-----------|-------------|-----------|
| TB5 Audit logs stored in local file | **HIGH** | File system access can read logs |
| No access control on audit.log | **HIGH** | Process owner + others can read |
| No encryption | **HIGH** | Plain-text if store accessed |
| Logs not archived securely | **HIGH** | No separation between current + historical logs |

**Recommended Hardening (⚠️ High):**
* Encrypt logs at rest: AES-256-GCM
* Ship to remote SIEM immediately
* Set file permissions: 600 (read-only to app user)
* Implement retention: 90 days current + archived securely
* Separate audit database credentials from app credentials

---

## 5. DENIAL OF SERVICE (Availability)

**Threat Actors:** Attackers make the system unavailable through resource exhaustion or dependency failures.

### 5.1 Rate Limit Bypass (TB2 Middleware)
**Attack:** Attacker circumvents rate limits to perform brute force, resource exhaustion, or scanning.

| Component | Current Risk | Mitigation |
|-----------|-------------|-----------|
| Global rate limit: 60 req/min per IP (Middleware) | **MEDIUM** | In-memory; resets on restart |
| No per-endpoint customization | **MEDIUM** | R_ASSESS expensive; R_COMP cheap (same limit) |
| No per-API-key limits | **HIGH** | Only IP-based; VPN users share limits |
| No adaptive rate limiting | **MEDIUM** | No escalation on repeated violations |

**Recommended Hardening (⚠️ High):**
* Switch to Redis-backed rate limiting (survives restarts)
* Implement per-endpoint limits:
  * R_COMP (cheap): 300/min
  * R_ASSESS (expensive): 5/min
  * R_ORG (moderate): 100/min
* Add per-API-key limits: 500/min
* Implement adaptive rate limiting: tighter on repeated 429 responses

---

### 5.2 OSV.dev API Dependency Failure (TB2 ↔ TB4 boundary)
**Attack:** OSV.dev becomes unavailable; system can't fetch vulnerabilities, blocking assessments.

| Component | Current Risk | Mitigation |
|-----------|-------------|-----------|
| TB2 Assessment routers call OSV.dev directly | **MEDIUM** | OSV service has retry with backoff (max 3 attempts) |
| 30 second timeout on OSV.dev requests | **LOW** | Implemented in OSVService._request() |
| No cached fallback data | **HIGH** | No vulnerabilities returned if OSV.dev down |
| No circuit breaker pattern | **HIGH** | Cascading failures on repeated OSV.dev outages |

**Recommended Hardening:**
* Cache OSV.dev responses with TTL: 24 hours
* Implement circuit breaker:
  * After 5 failed OSV.dev calls in 1 minute → return cached data
  * Prevent cascading failures
* Return response: "Vulnerability data temporarily unavailable; using cached data"

---

### 5.3 Expensive Assessment Computation (TB2 R_ASSESS ↔ RE engine)
**Attack:** Attacker triggers expensive correlation + risk scoring repeatedly, consuming CPU.

| Component | Current Risk | Mitigation |
|-----------|-------------|-----------|
| TB2 R_ASSESS synchronously runs RE (Rules Engine) + CE + RS | **MEDIUM** | Expensive computation; ties up worker |
| No job queue or async processing | **HIGH** | Blocking request; no horizontal scaling |
| No result caching | **HIGH** | Same assessment run twice = wasted work |
| No timeout on engine execution | **HIGH** | Runaway computation can hang worker indefinitely |

**Recommended Hardening (⚠️ High):**
* Implement async job queue (Celery + Redis):
  * POST `/assessments` returns job_id immediately (202 Accepted)
  * Client polls GET `/assessments/{job_id}` for status/results
  * Job runs in background worker
* Cache assessment results: 1 hour (if metadata unchanged)
* Add timeout to correlation engine: 30 seconds max
* Implement job priorities (user-initiated = high; batch = low)

---

### 5.4 Large Manifest Parsing (TB1 → TB2 MP component)
**Attack:** Attacker uploads huge manifest (10+ MB pom.xml) to exhaust memory/CPU.

| Component | Current Risk | Mitigation |
|-----------|-------------|-----------|
| TB1 Browser uploads manifest to TB2 R_COMP | **MEDIUM** | No size limit enforced |
| TB2 MP (Manifest Parser) parses entire file into memory | **HIGH** | Large files = memory spike + slow parse |
| No streaming parser (loads all into memory) | **HIGH** | DoS via memory exhaustion |
| No parsing timeout | **MEDIUM** | Runaway parser can hang worker |

**Recommended Hardening:**
* Enforce manifest size limit: 5 MB max
* Return 413 Payload Too Large if exceeded
* Implement streaming XML parser (lxml iterparse)
* Add parsing timeout: 10 seconds

---

### 5.5 Database Connection Exhaustion (TB2 ↔ TB3 boundary)
**Attack:** Attacker opens many concurrent requests, exhausting DB connection pool.

| Component | Current Risk | Mitigation |
|-----------|-------------|-----------|
| SQLAlchemy connection pool (default: 10 connections) | **MEDIUM** | Small pool; easy to exhaust |
| No connection pool monitoring | **HIGH** | No visibility into pool usage |
| DB queries may run long (TB2 correlation engine) | **MEDIUM** | Holds connection while processing |

**Recommended Hardening:**
* Configure pool with overflow: `pool_size=20, max_overflow=40` (total 60)
* Add connection pool monitoring: log checkedout; alert > 80% utilized
* Implement per-query timeout: 30 seconds
* Current `pool_pre_ping=True` helps (already enabled)

---

## 6. ELEVATION OF PRIVILEGE (Authorization & Access Control)

**Threat Actors:** Attackers gain access or permissions they shouldn't have.

### 6.1 Organization Access Bypass (TB2 ↔ TB3, all routers)
**Attack:** Attacker accesses Organization A's assessments despite no membership in Org A.

| Component | Current Risk | Mitigation |
|-----------|-------------|-----------|
| TB2 routers (R_ORG, R_ASSESS, R_EVID) accept org_id parameter | **CRITICAL** | No verification caller can access org |
| No user authentication layer | **CRITICAL** | Can't associate caller with org membership |
| TB3 Database has no RLS | **CRITICAL** | DB doesn't enforce boundaries |

**Recommended Hardening (⚠️ CRITICAL):**
* See **Spoofing 1.2** and **Information Disclosure 4.1** for full mitigation

---

### 6.2 API Key Privilege Escalation (TB1 → TB2, all routes)
**Attack:** Attacker uses API key to modify/delete data despite having only read access.

| Component | Current Risk | Mitigation |
|-----------|-------------|-----------|
| All API keys equivalent; same access level | **HIGH** | No fine-grained permissions |
| No key scoping (read-only, write, admin) | **HIGH** | Key compromise = full access |
| No per-org key binding | **HIGH** | Single key accesses all orgs |
| DELETE endpoints not restricted | **HIGH** | Dangerous operations allowed freely |

**Recommended Hardening (⚠️ High):**
* Implement API key scopes:
  * `read`: GET only
  * `write`: GET + POST + PATCH
  * `admin`: GET + POST + PATCH + DELETE (rare)
* Implement per-org key binding:
  * Key can only access Organization X
  * Requesting Org Y → 403 "Key not authorized"
* Implement key expiration + auto-rotation

---

### 6.3 Middleware Bypass (TB2 Middleware stack)
**Attack:** Attacker bypasses security headers, rate limiting, or request tracking.

| Component | Current Risk | Mitigation |
|-----------|-------------|-----------|
| Middleware stack properly layered (SecurityHeaders → RequestID → ResponseTime) | **LOW** | Good architecture |
| CORS restricted to explicit TLS origins (no wildcard) | **LOW** | TLS-only origins in dev and prod |
| All routes go through middleware | **LOW** | No bypass paths |

**Recommended Hardening:**
* Ensure `CORS_ORIGINS` explicitly set in production (whitelist)
* Add startup validation: verify middleware applied to all routes
* Test middleware enforcement with security scanning

---

## AI-Generated STRIDE Findings (2026-03-14)

The following threats were identified by running Charlotte's Web against its own stack. They supplement the manual STRIDE analysis in sections 1-6 with findings specific to the current deployment.

### S-AI.1 JWT Without Transport Security [HIGH] — Spoofing
**Threat:** JWT tokens issued without confirmed transport security can be intercepted and replayed.
**Component:** PyJWT token issuance and validation in FastAPI
**Mitigation:** Enforce HTTPS-only via uvicorn SSL certificates or TLS-terminating reverse proxy. Set Secure flag on all auth cookies. Reject plaintext HTTP requests.
**Cross-reference:** See section 8.2 (TLS Enforcement) — currently mitigated with HTTPSEnforcementMiddleware + HSTS.

### S-AI.2 Secret Exposure via Logging or Config [MEDIUM] — Information Disclosure
**Threat:** Anthropic API key, JWT secret, and database credentials stored as environment variables may be exposed through misconfigured logging, error responses, or container inspection.
**Component:** pydantic-settings configuration, Anthropic client, PyJWT secret
**Current controls:** Audit logging already masks API keys to last 4 characters and never logs passwords or PHI. Production mode hides stack traces and detailed errors. `.env` files excluded from git. Optional Fernet encryption for `.env` files available (`src/encryption.py`).
**Remaining gap:** Config fields do not use pydantic `SecretStr` type, so accidental serialization of the full config object could leak secrets. No external secrets manager integrated.
**Mitigation:** Adopt `SecretStr` for secret config fields. Integrate a secrets manager (AWS Secrets Manager, HashiCorp Vault) for production.
**Current Disposition:** Partially mitigated. Secrets management upgrade planned.

### S-AI.3 JWT Secret Key Weakness [MEDIUM] — Elevation of Privilege
**Threat:** Weak or predictable JWT secret key allows an attacker to forge tokens with elevated role claims.
**Component:** PyJWT token signing, FastAPI dependency injection for auth
**Current controls:** Development auto-generates secret via `secrets.token_urlsafe(32)` (256-bit entropy). Production requires explicitly set `SECRET_KEY` (startup validation fails without it). Algorithm strictly set to HS256 (no `none` accepted). Token expiry enforced (default 60 minutes). JWT infrastructure built but not yet wired to user session flow.
**Remaining gap:** No refresh token rotation. No minimum key length enforcement beyond startup check. Secret stored in environment variable, not a secrets manager.
**Mitigation:** Increase to 512-bit secret. Add refresh token rotation. Store in secrets manager for production.
**Cross-reference:** See section 6.2 (API Key Privilege Escalation).

### S-AI.4 Alembic Migration Integrity [MEDIUM] — Tampering
**Threat:** Migration scripts run during deployment without integrity verification. A supply-chain or insider threat could introduce schema changes that exfiltrate or corrupt data.
**Component:** Alembic migration pipeline
**Mitigation:** Store migration files in version control with signed commits (GPG-signed tags). Run migrations only from CI/CD with a dedicated least-privilege database account.

### S-AI.5 SQLite Write Contention [MEDIUM] — Denial of Service
**Threat:** SQLite does not support concurrent write access. Under moderate load, write contention causes SQLITE_BUSY errors, resulting in effective denial of service for write operations.
**Component:** SQLite database, SQLAlchemy connection pool
**Mitigation:** Enable WAL mode (`PRAGMA journal_mode=WAL`) to improve read/write concurrency. For production workloads with >1 uvicorn worker, migrate to PostgreSQL.
**Current Disposition:** Accepted risk for development. Production PostgreSQL migration planned.

### S-AI.6 File Upload Validation [LOW] — Elevation of Privilege
**Threat:** python-multipart file upload handling without strict content-type and size validation can be abused to upload malicious files.
**Component:** python-multipart file upload endpoints in FastAPI
**Current controls:** No file upload endpoints currently exist. Evidence attachment accepts HTTPS URLs only (validated and sanitized). Security scaffolding for future file uploads is documented in `src/routers/evidence.py` (allowed extensions, 25MB limit, UUID-based filenames, path traversal prevention, ClamAV integration points).
**Remaining gap:** When file uploads are enabled, the scaffolding must be implemented before going live.
**Mitigation:** Implement the scaffolded security controls before enabling any file upload endpoint.
**Cross-reference:** See section 5.4 (Large Manifest Parsing).

---

## AI-Generated Remediation Roadmap (2026-03-14)

Priority-ordered remediation steps from the AI threat model analysis:

| Step | Action | Rationale |
|------|--------|-----------|
| 1 | **Enable TLS 1.2+ on all endpoints:** configure uvicorn with SSL certificates or deploy nginx/Caddy as TLS-terminating reverse proxy. Redirect HTTP to HTTPS. Disable TLS 1.0/1.1 and weak ciphers. | Plaintext HTTP undermines every other control. Direct HIPAA 164.312(e)(1) violation. **Status: Mitigated** (HTTPSEnforcementMiddleware + HSTS + port 8443 TLS binding) |
| 2 | **Encrypt data at rest:** SQLCipher for SQLite or migrate to PostgreSQL with native encryption. Set database file permissions to 600. Deploy as non-root user. | Unencrypted data at rest violates HIPAA 164.312(a)(2)(iv). |
| 3 | **Harden JWT secret key:** increase to 512-bit secret via `secrets.token_hex(64)`, store in secrets manager, add refresh token rotation. | Forgeable JWT enables full authentication bypass. **Partially mitigated:** strict HS256 validation, 60-min expiry, and production startup validation already enforced. |
| 4 | **Ship audit logs to append-only store:** integrate SIEM (Splunk, ELK, Datadog) with 180-day retention. Add hash chain for tamper evidence. Encrypt audit log at rest. | Audit log tampering/loss undermines forensics. HIPAA 164.312(b). **Partially mitigated:** comprehensive JSON structured audit logging already in place (auth, data access, assessments, security alerts, request ID correlation, API key masking). Gap is file-based storage without SIEM or encryption. |
| 5 | **Implement TOTP-based MFA (pyotp):** enforce before JWT issuance. Provide backup codes. | Most effective single control against credential compromise. HIPAA access control requirement. |
| 6 | **Centralize secrets management:** move JWT secret, Anthropic API key, and database credentials to a secrets manager. Use `SecretStr` in pydantic-settings. | Prevents secret leakage via logs or error responses. **Partially mitigated:** 12-factor env-based config, `.env` excluded from git, optional Fernet encryption for `.env` files, audit logger already masks API keys. Gap is no `SecretStr` types and no external secrets manager. |
| 7 | **Replace passlib with argon2-cffi:** configure Argon2id with OWASP parameters (memory=64MB, iterations=3, parallelism=4). Migrate existing hashes on next login via rehash-on-verify. | passlib is minimally maintained; Argon2id is OWASP-recommended. |
| 8 | **Document formal HIPAA Risk Analysis:** asset inventory, threat identification, vulnerability assessment, impact/likelihood analysis, risk determination. Use this threat model as input artifact. | HIPAA 164.308(a)(1)(ii)(A) requires documented risk analysis. |

---

## Self-Assessment Summary

Sections 7-10 were added after running Charlotte's Web against itself, using the platform's own threat modeling feature to analyze its own dependency stack. Updated 2026-03-14 using OSV.dev ecosystem-aware vulnerability scanning (replaced NVD keyword matching which produced false positives). AI-generated findings were verified against the actual codebase to correct assumptions about absent controls that are in fact implemented (TLS, audit logging, error handling, CORS, algorithm validation).

**AI Threat Model Summary (2026-03-14):** 5 compliance findings analyzed, 13 STRIDE threats identified (7 HIGH, 6 MEDIUM), 0 CVEs across all 16 components. All risk is architectural and configuration driven. After verification against the actual codebase, several AI-reported gaps were found to be already mitigated (TLS enforcement, audit logging, error handling, CORS). See the AI-Generated STRIDE Findings and Remediation Roadmap sections above for the corrected analysis.

| Disposition | Count | Description |
|-------------|-------|-------------|
| **Mitigated** | 4 | TLS enforcement + HSTS, comprehensive audit logging, error handling (no stack traces in prod), strict CORS (no wildcard) |
| **Partially Mitigated** | 3 | JWT hardening (strict algo + expiry, needs 512-bit key + refresh rotation), secret management (env-based + masking, needs SecretStr + secrets manager), rate limiting (60/min per IP, needs per-endpoint + Redis) |
| **Accepted Risk (Dev)** | 3 | SQLite encryption, SQLite write contention, SSRF (hardcoded URLs) |
| **Not Applicable** | 1 | File upload validation (no upload endpoints exist; security scaffolding ready) |
| **Remediation Planned** | 3 | MFA (pyotp), passlib→argon2-cffi migration, HIPAA risk analysis documentation |

---

## 7. Dependency Vulnerabilities (Supply Chain)

**Threat Actors:** Attackers exploit known CVEs in third-party dependencies to compromise the application.

### 7.1 Known CVEs in Dependencies (TB2 Application Service)
**Attack:** Attacker exploits publicly disclosed vulnerabilities in installed packages.

**OSV.dev Scan Results (2026-03-14):** 0 known CVEs across all 16 components (14 PyPI packages + Python 3.14.3 + SQLite 3.43.2). All versions are current releases as of mid-2025. The dependency posture is healthy.

**Previous NVD keyword search results (now deprecated):** Earlier scans using NVD keyword matching flagged 11 CVEs, of which 7 were false positives due to incorrect package attribution (CVEs assigned to third-party plugins like fastapi-opa, fastapi-admin-pro, Odoo, Django, Strawberry GraphQL — none of which are installed). The migration to OSV.dev eliminated these false positives through ecosystem-aware, version-specific querying.

### 7.2 Maintenance and Monitoring Notes

| Component | Version | Risk | Action |
|-----------|---------|------|--------|
| passlib | 1.7.4 | **Maintenance risk** | Minimally maintained project. Migrate password hashing to argon2-cffi (Argon2id algorithm, OWASP recommended). Passlib can wrap argon2-cffi as a transitional step. |
| SQLite | 3.43.2 | **Version age** | Released September 2023. Verify Python 3.14 distribution bundles an up-to-date SQLite version. Monitor for upstream CVEs. |
| python-multipart | 0.0.22 | **Monitor** | No known CVEs at this version. Previous versions (0.0.5-0.0.6) had critical ReDoS vulnerabilities. Ensure input validation is enforced at the application layer. |

**Recommended cadence:** Weekly `pip-audit` or Dependabot scanning. Pin all dependencies with exact versions and validate hashes.

---

## 8. Data Protection Gaps

### 8.1 Data at Rest: Unencrypted SQLite Database (TB3 Persistence Layer)
**Attack:** Attacker with filesystem access reads or exfiltrates the entire database without needing application credentials.

| Component | Current Risk | Mitigation |
|-----------|-------------|-----------|
| TB3 SQLite database stored as plaintext file | **HIGH** | No encryption at rest |
| Single file contains all org data, assessments, findings | **HIGH** | Full data exposure on file compromise |
| File permissions may allow broader access | **MEDIUM** | OS-level access control only |

**Current Disposition:** Accepted risk for development. Production guidance requires PostgreSQL with storage-level encryption.

**Recommended Hardening:**
* Development: Restrict file permissions (`chmod 600`, owned by app service account)
* Production: Migrate to PostgreSQL with encrypted storage (AWS RDS encryption, Azure TDE)
* Alternative: SQLCipher for encrypted SQLite if single-file deployment is required

### 8.2 Data in Transit: TLS Enforcement (TB1 ↔ TB2 boundary)
**Status: Mitigated**

| Component | Current Risk | Mitigation |
|-----------|-------------|-----------|
| `HTTPSEnforcementMiddleware` redirects HTTP → HTTPS (301) | **LOW** | All requests forced to TLS |
| HSTS header: `max-age=31536000; includeSubDomains; preload` | **LOW** | Browsers enforce HTTPS on return visits |
| Dev server binds exclusively on port 8443 with TLS certificates | **LOW** | No plaintext listener available |

---

## 9. Authentication Gaps

### 9.1 Absent Multi-Factor Authentication (TB1 → TB2 boundary)
**Attack:** Credential stuffing or phishing against single-factor authentication provides full account takeover.

| Component | Current Risk | Mitigation |
|-----------|-------------|-----------|
| Authentication relies on API keys and JWT tokens only | **HIGH** | No second factor |
| JWT compromise = full access (no MFA challenge) | **HIGH** | Single point of failure |

**Current Disposition:** Remediation planned. TOTP-based MFA (e.g., `pyotp`) is planned for a future release when user login flows are added.

---

## 10. Compliance Determination

### 10.1 HIPAA: Not Applicable
This application processes software component metadata and vulnerability data. It does not store, transmit, or process Protected Health Information (PHI). HIPAA requirements do not apply.

If the application scope changes to include PHI, a full HIPAA gap analysis must be conducted before deployment.

### 10.2 SSRF Risk (TB2 → TB4 boundary)
**Attack:** If user-controlled URLs are passed to python-requests, an attacker could pivot to internal network resources or cloud metadata endpoints.

| Component | Current Risk | Mitigation |
|-----------|-------------|-----------|
| python requests makes outbound calls to OSV.dev and NVD APIs | **LOW** | Base URLs are hardcoded, not user supplied |
| No user-supplied URL input currently exists | **LOW** | No SSRF vector present |

**Current Disposition:** Accepted risk. URL allowlisting recommended if user-controlled URLs are added in the future.

---

## Summary: Prioritized Mitigations

| Priority | Threat | Mitigation | Trust Boundary | Status |
|----------|--------|-----------|-----------------|--------|
| **CRITICAL** | Spoofing 1.2, Elevation 6.1 | User auth + org membership checks | TB1 ↔ TB2 ↔ TB3 | Open |
| **CRITICAL** | Information Disclosure 4.1 | Row-level security + caller auth | TB2 ↔ TB3 | Open |
| ⚠️ **HIGH** | Data at Rest 8.1 | SQLite encryption or PostgreSQL migration | TB3 | Accepted (Dev) |
| ⚠️ **HIGH** | Authentication 9.1 | MFA implementation (pyotp/TOTP) | TB1 → TB2 | Planned |
| ⚠️ **HIGH** | Tampering 2.2 | Finding audit trail + versioning | TB2 ↔ TB3 | Open |
| ⚠️ **HIGH** | Repudiation 3.1 | SIEM + log encryption + hash chain | TB2 ↔ TB5 | Partial (logging exists, needs SIEM) |
| ⚠️ **HIGH** | DoS 5.1 | Redis rate limiting + per-endpoint tuning | TB2 Middleware | Partial (60/min per IP exists) |
| ⚠️ **HIGH** | DoS 5.2 | OSV.dev circuit breaker + caching + timeout | TB2 ↔ TB4 | Partial (retry + 30s timeout exists) |
| ⚠️ **HIGH** | DoS 5.3 | Async job queue (Celery) | TB2 R_ASSESS | Open |
| ⚠️ **HIGH** | Elevation 6.2 | API key scopes + per-org binding | TB1 → TB2 | Open |
| **MEDIUM** | Secret Exposure S-AI.2 | SecretStr + secrets manager | TB2 Config | Partial (key masking exists) |
| **MEDIUM** | JWT Key Weakness S-AI.3 | 512-bit secret + refresh rotation | TB2 Auth | Partial (strict algo + expiry exists) |
| **MEDIUM** | Alembic Integrity S-AI.4 | Signed commits + CI-only migrations | TB2 Deploy | Open |
| **MEDIUM** | SQLite Contention S-AI.5 | WAL mode + PostgreSQL migration | TB3 | Accepted (Dev) |
| **LOW** | File Upload S-AI.6 | Implement scaffolded controls when enabled | TB2 R_COMP | N/A (no upload endpoints) |
| **MITIGATED** | Data in Transit 8.2 | TLS enforcement + HSTS + port 8443 | TB1 ↔ TB2 | Mitigated |
| **MITIGATED** | Error Handling 4.2 | Debug disabled in prod, generic errors | TB2 | Mitigated |
| **MITIGATED** | CORS 6.3 | Strict whitelist, no wildcard, TLS-only origins | TB2 Middleware | Mitigated |
| **MITIGATED** | Request Tracing 3.2 | UUID per request, X-Request-ID header | TB2 Middleware | Mitigated |
| **CLEAN** | Supply Chain 7.1 | 0 CVEs across 16 components (OSV.dev scan) | TB2 | No action needed |

---

## Threat Model Review Cadence

* **Monthly:** Review critical/high-priority mitigations for completeness
* **Quarterly:** Full threat model refresh (new features, architecture changes)
* **Post-Incident:** Immediate update if any issue exploits a gap
* **Last Review:** 2026-03-14 (self-assessment using Charlotte's Web threat modeling feature)

## ASCII Diagram Fallback

Use this if your Markdown viewer cannot render Mermaid.

[User]
    |
    v
[Browser UI: static/index.html + JS]
    |
    | HTTPS requests
    v
[FastAPI App: main.py]
    |
    +--> [Middleware: Security headers, request-id, rate-limit, CORS, gzip]
    |
    v
[API Router /api/v1]
    |
    +--> organizations
    +--> metadata_profiles
    +--> components --> [Manifest Parser] --> [NVD CPE]
    +--> assessments --> [Rules Engine] --> [Compliance/CWE Mapping]
    |                    |                    |
    |                    +--> [OSV.dev]       +--> [MITRE]
    |                    +--> [Findings/Assessment writes]
    +--> evidence
    +--> risk --> [Risk Scoring Engine]
    |
    v
[Database: orgs, profiles, assessments, findings, evidence, controls]

[Audit Logs] <- App + middleware events
[Dev TLS certs] <- local HTTPS startup path

## Detailed DFD: Assessment Execution Workflow

Use this when you want to threat model a single high-value path in depth.

```mermaid
flowchart TD
    %% External Actor
    A[Analyst/User]

    %% Trust Boundary: Browser
    subgraph B1[Boundary: Browser]
        UI[Web UI\nCollect org + stack]
    end

    %% Trust Boundary: API Service
    subgraph B2[Boundary: FastAPI Service]
        EP1[POST /organizations]
        EP2[POST /metadata-profiles]
        EP3[POST /assessments]
        EP4[POST analyze-nvd]
        EP5[GET findings]

        VAL[Validation + auth/rate-limit middleware]
        RULES[Rules engine + control mapping]
        CORR[Correlation logic\ncomponent version to CVE/CWE/control]
        SCORE[Risk prioritization\n(priority window/severity)]
        AUD[Audit logger]
    end

    %% Trust Boundary: Data Store
    subgraph B3[Boundary: Database]
        ORGT[(Organizations)]
        PROFT[(MetadataProfiles)]
        ASST[(Assessments)]
        FINDT[(Findings)]
        CTRLT[(Controls)]
    end

    %% Trust Boundary: External Intel
    subgraph B4[Boundary: External Threat Intel]
        OSV2[OSV.dev API]
        NVD2[NVD CPE API]
        MITRE2[MITRE mapping data]
    end

    %% User flow
    A --> UI
    UI --> EP1
    UI --> EP2
    UI --> EP3
    UI --> EP4
    UI --> EP5

    %% API internals
    EP1 --> VAL
    EP2 --> VAL
    EP3 --> VAL
    EP4 --> VAL
    EP5 --> VAL

    VAL --> ORGT
    VAL --> PROFT
    VAL --> ASST

    EP4 --> RULES
    RULES --> CTRLT
    EP4 --> CORR
    CORR --> OSV2
    CORR --> MITRE2
    CORR --> SCORE
    SCORE --> FINDT
    SCORE --> ASST

    %% Audit everywhere
    EP1 --> AUD
    EP2 --> AUD
    EP3 --> AUD
    EP4 --> AUD
    EP5 --> AUD

    %% Response
    FINDT --> EP5
    EP5 --> UI
```

### Threat-Model Prompts for This DFD

* Input validation: How is malformed stack/manifest input rejected before correlation logic?
* External dependency trust: What happens if OSV.dev is unavailable or returns partial data?
* Authorization scope: Can one org read another org's assessments/findings?
* Integrity: How do we prevent tampering of assessment/finding records between creation and display?
* DoS controls: Which endpoints are rate-limited and where are expensive calls cached?

## AI-Generated Data Flow Diagram (2026-03-14)

Simplified DFD generated by the AI threat model analysis, focused on component-level data flows and security boundaries.

```mermaid
graph LR
    subgraph End User Environment
        end_user(("End User / Client"))
    end
    subgraph Application Tier
        fastapi_app["FastAPI Application (uvicorn)"]
        auth_middleware["Auth Middleware (PyJWT + passlib)"]
        rate_limiter["Rate Limiter (slowapi)"]
        file_handler["File Upload Handler (python-multipart)"]
        anthropic_client["Anthropic API Client"]
        sqlalchemy_orm["SQLAlchemy ORM / Alembic"]
    end
    subgraph Data Layer
        sqlite_db[("SQLite Database")]
    end
    subgraph External Services
        anthropic_api{"Anthropic Claude API"}
    end
    end_user -->|HTTPS TLS 1.2+| rate_limiter
    rate_limiter -->|HTTP internal routing| auth_middleware
    auth_middleware -->|Validated JWT context| fastapi_app
    fastapi_app -->|Multipart form data| file_handler
    fastapi_app -->|REST/JSON prompt payload| anthropic_client
    anthropic_client -->|HTTPS REST API Anthropic SDK| anthropic_api
    anthropic_api -->|HTTPS REST API response| anthropic_client
    fastapi_app -->|ORM method calls| sqlalchemy_orm
    sqlalchemy_orm -->|SQLite file I/O unencrypted at rest| sqlite_db
```
