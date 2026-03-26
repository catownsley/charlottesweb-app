# Product Architecture & Vision

## Core Product Philosophy

CharlottesWeb transforms compliance from a manual exercise into **exploitability-driven regulatory intelligence**. We don't just tell you what controls you need. We tell you which vulnerabilities in your actual stack create regulatory risk.

---

## System Architecture

### High-Level Flow

```
Metadata Input → Rules Engine → Vulnerability Correlation → Risk Scoring → Remediation Roadmap + Evidence Package
```

### Core Components

#### 1. Metadata Intake Layer
**Purpose:** Collect architectural metadata without touching PHI.

**Inputs:**
- Organization profile (industry, size, stage)
- Data classification (PHI types: demographic, clinical, payment, etc.)
- Data lifecycle (collection → storage → processing → deletion)
- Infrastructure (cloud provider, services used, network topology)
- Application stack (languages, frameworks, dependencies)
- Access controls (authentication, authorization model, MFA)
- Logging and monitoring (retention, alerting, SIEM)
- Third-party integrations (APIs, vendors with data access)
- AI/ML components (training data, model hosting, inference endpoints)

**Key Principle:** Zero PHI ingestion. We analyze the *architecture*, not the data.

#### 2. Multi-Framework Rules Engine
**Purpose:** Map organizational profile to applicable regulatory requirements across frameworks.

**Logic:**
- Parse applicable regulatory frameworks (HIPAA, NIST 800-53, GDPR, SOX, SOC 2, PCI DSS, FedRAMP, APRA CPS 234, CCPA)
- Map framework-specific requirements to canonical controls
- Apply conditional logic based on metadata (e.g., "handles payment data" → PCI-relevant considerations, "EU data subjects" → GDPR)
- Generate cross-framework control applicability matrix

**Data Model:**
```python
Control:
- id: "ctrl-uuid-here"
- title: "Risk Analysis"
- category: "Administrative Safeguards"
- requirement: "Conduct an accurate and thorough assessment..."
- applicability_conditions: [...]
- evidence_required: ["risk_assessment_documentation", "asset_inventory"]
```

#### 3. Vulnerability Intelligence Layer
**Purpose:** Correlate stack components with known exploitable vulnerabilities.

**Data Sources:**
* **OSV.dev:** Ecosystem aware vulnerability advisories (PyPI, Maven, npm, etc.)
- **CWE (Common Weakness Enumeration):** Vulnerability patterns
- **CIS Benchmarks:** Configuration baselines
- **NIST CSF:** Framework crosswalk
- **Cloud provider security bulletins:** AWS, Azure, GCP advisories

**Correlation Logic:**
```
IF stack contains "Django 3.2.10"
AND CVE-2022-XXXX affects Django < 3.2.11
AND exploitability score > 7.5
AND vulnerability impacts "data confidentiality"
THEN map to canonical control "Access Control" (mapped across HIPAA, NIST, GDPR, etc.)
AND severity = HIGH
```

#### 4. Risk Scoring Engine
**Purpose:** Prioritize findings by exploitability × regulatory impact.

**Scoring Formula:**
```
Risk Score = (CVSS Base Score) × (Regulatory Severity) × (PHI Exposure Likelihood)

Prioritization Buckets:
- IMMEDIATE (9.0-10.0): Exploitable + PHI access + public exploit exists
- 30 DAYS (7.0-8.9): High CVSS + regulatory control failure
- QUARTERLY (4.0-6.9): Medium risk + technical debt
- ANNUAL (0.0-3.9): Low severity + defense-in-depth gaps
```

**Output:**
- Finding ID
- Affected control(s)
- Vulnerability details (CVE, CWE, description)
- Exploitability context (CVSS, exploit availability)
- Remediation guidance
- Priority window
- Responsible team (DevOps, Engineering, Security)

#### 4.1 Compliance + Threat Convergence Layer
**Purpose:** Produce an engineering backlog that reflects both regulatory posture and exploitability pressure.

**Implemented Pattern (v1):**
- Reuse existing `Assessment`, `Finding`, `Evidence`, and `Control` records.
- Compute per-control:
	- `control_confidence` from evidence status + freshness
	- `threat_pressure` from severity/CVSS + signal volume
	- `residual_risk` as the risk remaining after control confidence
- Return a deterministic prioritized backlog for execution sequencing.

**Why this matters:**
- Compliance state directly influences technical prioritization.
- Threat signal volume directly influences control hardening urgency.
- Reduces the traditional gap where compliance and AppSec operate independently.

**v1 Formula:**
```
residual_risk = threat_pressure × (1 - control_confidence/100) × blast_radius
```

#### 4.2 Future Dynamic Regulatory Feed (Planned)
**Purpose:** Move from static regulation catalogs to versioned, machine-readable, continuously updated regulatory mappings.

**Target capabilities:**
- Dynamic regulatory feed ingestion (rule updates, interpretations, mapping changes)
- Additional frameworks (SOC 2, PCI DSS, state privacy laws) via provider adapters
- Versioned control catalog with effective dates and migration diffs
- Policy impact notifications when regulatory mappings change

**Long-term Product Direction:**
- Customer describes data sourcing, processing, storage, destruction, and geolocation.
- System infers applicable regulations and required controls automatically.
- Multi-framework mapping (HIPAA, NIST 800-53, GDPR, SOX, SOC 2, PCI DSS, FedRAMP, APRA CPS 234, CCPA) is supported in current releases.

#### 4.3 Interactive Threat Modeling
**Purpose:** Generate STRIDE-based threat models with interactive data flow diagrams from assessment data.

**How it works:**
- Derives graph nodes from the organization's software stack, cloud provider, and infrastructure metadata
- Assigns components to trust boundaries (End User, Application, Persistence, External Services, Operational)
- Generates data flow edges with PHI sensitivity classification
- Maps findings to STRIDE categories (Spoofing, Tampering, Repudiation, Information Disclosure, DoS, Elevation of Privilege) via CWE mappings
- Enriches each STRIDE threat with MITRE ATT&CK techniques and recommended mitigations

**Frontend visualization:**
- Interactive Cytoscape.js graph with drag, zoom, pan
- Nodes color-coded by severity (red=critical, orange=high, yellow=medium, green=clean)
- Trust boundaries as dashed compound nodes
- Click any node for finding details, severity, and PHI exposure
- STRIDE analysis table with technique-level detail
- PNG export for reports and presentations

**No new database tables.** The threat model is computed on the fly from existing Assessment, MetadataProfile, and Finding records.

#### 5. Evidence Automation Layer
**Purpose:** Generate audit-ready documentation.

**Artifacts Generated:**
- **Control-to-Evidence Mapping:** What evidence satisfies each control
- **Policy Templates:** Access control policy, incident response plan, logging retention policy
- **Action Plans:** Required documentation by audit phase
- **Evidence Binder:** Organized package for auditors (PDF/zip export)

**Example Mapping:**
```
Control: HIPAA.164.308(a)(6)(ii) - Response and Reporting
Evidence Required:
- Incident response plan document
- IR tabletop exercise records (annual)
- Breach notification procedures
- Historical incident logs
Status: [Complete | Partial | Missing]
Owner: [Security Team]
```

---

## Domain Model

### Core Entities

```python
Organization:
- id: UUID
- name: str
- industry: str
- stage: str (seed, series_a, etc.)
- created_at: datetime

MetadataProfile:
- id: UUID
- organization_id: FK
- phi_types: list[str]
- cloud_provider: str
- infrastructure: dict
- applications: list[dict]
- access_controls: dict
- version: int
- created_at: datetime

Control:
- id: str (UUID)
- canonical_concept: str (e.g., "Access Control", "Encryption at Rest")
- title: str
- requirement: text
- category: str
- evidence_types: list[str]

Assessment:
- id: UUID
- organization_id: FK
- metadata_profile_id: FK
- status: str (pending, running, completed, failed)
- initiated_at: datetime
- completed_at: datetime

Finding:
- id: UUID
- assessment_id: FK
- control_id: FK
- title: str
- description: text
- severity: str (immediate, high, medium, low)
- cvss_score: float
- cve_ids: list[str]
- cwe_ids: list[str]
- remediation_guidance: text
- priority_window: str
- owner: str

EvidenceArtifact:
- id: UUID
- organization_id: FK
- assessment_id: FK
- control_id: FK
- artifact_type: str (policy, action_plan, report)
- content: text | blob
- status: str (generated, reviewed, approved)
- generated_at: datetime

RemediationTask:
- id: UUID
- finding_id: FK
- title: str
- description: text
- priority: str
- due_date: date
- assigned_to: str
- status: str (open, in_progress, completed)
```

---

## Technology Decisions

### Backend (Current)
- **Language:** Python 3.14+
- **Framework:** FastAPI (async, OpenAPI auto-generation, type hints)
- **Database:** SQLite (development), PostgreSQL planned for production
- **ORM:** SQLAlchemy 2.0
- **Migrations:** Alembic
- **Security:** PyJWT, passlib, slowapi (rate limiting)
- **CI/CD:** GitHub Actions (CodeQL, Bandit, pip-audit)

### Backend (Planned)
- **Database:** PostgreSQL (JSONB for metadata flexibility)
- **Task Queue:** Celery + Redis (long-running assessments)

### Frontend (Planned, Phase 3)
- **Framework:** React + TypeScript or Next.js
- **State Management:** React Query (server state) + Zustand (client state)
- **UI Components:** shadcn/ui or Radix UI
- **Charts:** Recharts or Nivo

### Infrastructure (Planned)
- **Deployment:** Docker + Kubernetes or fly.io/Render
- **Secrets:** 1Password/Vault or cloud-native (AWS Secrets Manager, etc.)
- **Observability:** Sentry (errors) + Datadog/Grafana (metrics)

### Data Sources
* **OSV.dev:** REST API (no auth required, ecosystem aware queries). Integrated for vulnerability scanning.
* **NVD:** REST API (rate limited, cache locally). Integrated for CPE based component suggestions and version autocomplete only.
- **CWE:** XML dataset (periodic sync). Integrated.
- **MITRE ATT&CK:** STIX data via GitHub. Translates technical weaknesses (CWEs) into real-world attack techniques with healthcare breach examples. Integrated.
- **CIS Benchmarks:** Manual ingestion (licensed content). Planned.

---

## Security & Compliance Design Principles

### Zero PHI Ingestion
- No patient names, SSNs, medical records, or payment card data
- Only architectural metadata and configuration details
- Input validation rejects PHI-like patterns

### Tenant Isolation
- Row-level security on all queries
- Organization ID required on every authenticated request
- API authorization checks enforce boundaries

### Audit Logging
- All assessment runs logged with timestamp + user
- Evidence generation tracked for reproducibility
- Finding acknowledgment and remediation tracked

### Data Retention
- Assessment results retained per customer preference
- Vulnerability feed data refreshed weekly
- Historical posture trends retained for continuous monitoring tier

---

## API Design Principles

### RESTful Endpoints
```
POST /api/v1/organizations
GET /api/v1/organizations/{org_id}

POST /api/v1/organizations/{org_id}/metadata-profiles
GET /api/v1/organizations/{org_id}/metadata-profiles/{profile_id}

POST /api/v1/organizations/{org_id}/assessments
GET /api/v1/organizations/{org_id}/assessments/{assessment_id}
GET /api/v1/organizations/{org_id}/assessments/{assessment_id}/findings
GET /api/v1/organizations/{org_id}/assessments/{assessment_id}/evidence

GET /api/v1/controls
GET /api/v1/controls/{control_id}
```

### Authentication
- JWT-based (Auth0, Supabase, or custom)
- Role-based access control (admin, member, viewer)

### Rate Limiting
- Per-org assessment runs (prevent abuse)
* OSV.dev and NVD API caching (respect upstream limits)

---

## Deployment Architecture

```
┌─────────────────┐
│ Frontend │ (React/Next.js)
│ Static Site │
└────────┬────────┘
│
┌────────▼────────┐
│ API Gateway │ (FastAPI)
│ /api/v1/* │
└────────┬────────┘
│
┌────┴────┐
│ │
┌───▼───┐ ┌──▼──────────┐
│ DB │ │ Task Queue │ (Celery + Redis)
│ (PG) │ │ Background │
└───────┘ │ Assessments │
└──────┬──────┘
│
┌──────▼──────┐
│ OSV.dev/CWE │
│ Ingestion  │
└─────────────┘
```

---

## Development Workflow

### Phase 0: Foundation
1. Define domain models and migrations
2. Scaffold FastAPI project structure
3. Add health check and basic CRUD endpoints
4. Set up test fixtures and CI pipeline

### Phase 1: Intelligence Engine
1. Implement metadata intake validation
2. Seed multi-framework control catalog
3. Build rules mapping engine (metadata → applicable controls)
4. Add vulnerability correlation service (CVE/CWE lookup)
5. Implement risk scoring algorithm
6. Generate remediation roadmap output

### Phase 2: Evidence Layer
1. Add control-to-evidence mapping table
2. Build action plan generation logic
3. Create policy/template rendering engine
4. Implement audit binder export (PDF/zip)

### Phase 3: Web Interface
1. Authentication and org onboarding
2. Metadata profile intake form
3. Assessment run workflow
4. Findings dashboard with filters
5. Report download and sharing

### Phase 4: Production Readiness
1. Tenant isolation enforcement
2. Structured logging and error tracking
3. Performance optimization
4. Sample data and pilot scripts

### Phase 5: Continuous Monitoring
1. Scheduled background assessment jobs
2. Delta detection (posture changes over time)
3. Alert/notification system
4. Trend visualization

---

## Success Metrics

### Product Metrics
- Time to first assessment: < 10 minutes
- Findings accuracy: > 90% relevant (no false positives on exploitability)
- Audit readiness: Evidence package completeness score

### Business Metrics
- Tier 1 → Tier 2 conversion rate
- Customer compliance posture improvement (trend over time)
- Advisory engagement attach rate

---

## Open Questions & Future Considerations

1. **Multi-framework support:** Implemented via `Framework` and `FrameworkRequirement` tables with 9 frameworks (HIPAA, NIST 800-53, GDPR, SOX, SOC 2, PCI DSS, FedRAMP, APRA CPS 234, CCPA) and 127 cross-framework mappings.
2. **Evidence ingestion:** Should we pull evidence automatically via API (e.g., AWS IAM snapshots) or require manual upload?
3. **AI/ML risk module:** How to assess AI model bias, training data privacy, and inference security?
4. **Global expansion:** GDPR, PIPEDA, LGPD. Different data privacy frameworks require localized rule engines.
5. **Continuous monitoring cadence:** Daily, weekly, or monthly re-assessments? User-configurable?

---

## References

- [HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/index.html)
- [NIST 800-53 Rev 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [GDPR](https://gdpr-info.eu/)
- [SOX](https://www.congress.gov/bill/107th-congress/house-bill/3763)
- [SOC 2 Trust Services Criteria](https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2)
- [PCI DSS v4.0](https://www.pcisecuritystandards.org/standards/pci-dss/)
- [FedRAMP](https://www.fedramp.gov/)
- [APRA CPS 234](https://www.apra.gov.au/information-security)
- [CCPA](https://oag.ca.gov/privacy/ccpa)
* [OSV.dev (Open Source Vulnerabilities)](https://osv.dev/)
* [NVD (National Vulnerability Database)](https://nvd.nist.gov/)
- [CWE (Common Weakness Enumeration)](https://cwe.mitre.org/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)

---

## Getting Started Today

See [BUSINESS_PLAN.md](BUSINESS_PLAN.md) for market strategy and business context.

See [docs/tickets/TICKET_INDEX.md](docs/tickets/TICKET_INDEX.md) for implementation roadmap and detailed tickets.

Start with ticket **[CW-001]**: Define domain model and architecture decisions.
