# CharlottesWeb

> **HIPAA Compliance-as-Code platform for AI-enabled health applications**

CharlottesWeb automates regulatory mapping by correlating HIPAA requirements with real-world exploitable vulnerabilities (CVE/CWE), producing prioritized remediation roadmaps and audit-ready evidence packages.

## 🔒 Security First

**Production-ready security controls:**
- API key authentication
- Rate limiting (60 req/min default)
- Comprehensive audit logging
- Security headers (HSTS, CSP, etc.)
- Request tracing
- Environment-based secrets management

See [SECURITY.md](SECURITY.md) for complete security documentation.

## Quick Links

- 📋 **[Business Plan](BUSINESS_PLAN.md)** - Market strategy, competitive landscape, go-to-market, team hiring
- 🏗️ **[Architecture & Product Vision](ARCHITECTURE.md)** - Technical design, domain model, system architecture, API design
- 🔒 **[Security Documentation](SECURITY.md)** - Security features, configuration, and best practices
- 🎫 **[Ticket Index](docs/tickets/TICKET_INDEX.md)** - Phased execution roadmap with detailed tickets
- 🐛 **[GitHub Issues](https://github.com/catownsley/charlottesweb-app/issues)** - Active implementation backlog

## Core Value Proposition

**Compliance mapped to real exploitability.**

Most tools tell you what controls you need. We tell you which vulnerabilities in your actual stack create regulatory risk.

### What We Build

- **Metadata-only intake** (zero PHI ingestion)
- **HIPAA rule mapping** (Security/Privacy/Breach Notification)
- **CVE/CWE correlation** (exploitability-aware risk scoring)
- **Prioritized remediation roadmap** (Immediate / 30 Days / Quarterly / Annual)
- **Audit evidence automation** (control-to-evidence mapping, policy templates, audit binders)

## Project Structure

```
charlottesweb-app/
├── BUSINESS_PLAN.md          # Complete business strategy and market analysis
├── ARCHITECTURE.md            # Technical design and implementation guide
├── README.md                  # This file
├── docs/
│   └── tickets/              # Phased execution backlog
│       ├── TICKET_INDEX.md
│       ├── phase-0-foundation.md
│       ├── phase-1-intelligence-engine.md
│       ├── phase-2-audit-evidence.md
│       ├── phase-3-web-app-workflows.md
│       ├── phase-4-pilot-readiness.md
│       └── phase-5-continuous-monitoring.md
├── src/                      # Application code (to be implemented)
├── scripts/                  # Automation scripts
└── .github/
    └── ISSUE_TEMPLATE/       # GitHub issue templates
```

## Getting Started

### For New Contributors or AI Agents

1. **Read the context:**
   - [BUSINESS_PLAN.md](BUSINESS_PLAN.md) - Understand the market, problem, and business model
   - [ARCHITECTURE.md](ARCHITECTURE.md) - Understand the technical vision and domain model

2. **Review the roadmap:**
   - [docs/tickets/TICKET_INDEX.md](docs/tickets/TICKET_INDEX.md) - See all planned phases
   - [GitHub Issues](https://github.com/catownsley/charlottesweb-app/issues) - Check active tickets

3. **Start building:**
   - Begin with **[CW-001]** Define domain model and architecture decisions
   - Follow Phase 0 → Phase 1 → Phase 2 → Phase 3 → Phase 4 → Phase 5

### Technology Stack (Current MVP)

- **Runtime:** Python 3.14.3
- **Backend API:** FastAPI 0.135.1, Uvicorn 0.41.0, Pydantic 2.12.5
- **Config:** pydantic-settings 2.13.1, `.env`-based configuration
- **Database:** SQLite + SQLAlchemy 2.0.48, Alembic 1.18.4
- **Security:** PyJWT 2.11.0, passlib 1.7.4, slowapi 0.1.9
- **Testing:** pytest 9.0.2, pytest-asyncio 1.3.0, httpx 0.28.1
- **CI/CD Security:** CodeQL, Bandit, pip-audit

## Development Phases

| Phase | Focus | Status |
|-------|-------|--------|
| **Phase 0** | Foundation (domain model, backend skeleton, schema) | ✅ **Complete** |
| **Phase 1** | HIPAA Intelligence Engine (intake, mapping, correlation, scoring) | ✅ **Complete** |
| **Phase 2** | Audit Evidence Automation (templates, checklists, binder export) | 🚧 **In Progress** (50%) |
| **Phase 3** | Web App Workflows (auth, UI, dashboard, reports) | 🔄 Not Started |
| **Phase 4** | Pilot Readiness (isolation, observability, onboarding) | 🔄 Not Started |
| **Phase 5** | Continuous Monitoring (scheduled jobs, delta alerts, trends) | 🔄 Not Started |

### ✅ Phase 0 - Foundation (Complete)
- FastAPI application with health check and CRUD endpoints
- SQLite database with SQLAlchemy models (Organization, MetadataProfile, Control, Assessment, Finding, Evidence)
- Pydantic schemas for API validation
- Security controls: API key auth, rate limiting, audit logging, HTTPS
- Development guide and E2E test scripts

### ✅ Phase 1 - Intelligence Engine (Complete)
- 22 HIPAA Security Rule controls seeded (10 baseline + 12 healthcare-specific)
- Rules engine with NVD vulnerability correlation
- Finding generation with CVSS scores, CWE IDs, and prioritization
- Metadata intake workflow (no PHI ingestion)
- Remediation guidance and priority windows (immediate/30_days/quarterly)
- Metadata-driven compliance evaluation endpoint (JSON policy rules → deterministic pass/fail)
- Optional finding persistence via `GET /api/v1/assessments/{assessment_id}/compliance-as-code?persist_findings=true`
- Auto-resolve: findings automatically removed when policy rules pass (`auto_resolve=true` by default)

### 🚧 Phase 2 - Audit Evidence (In Progress)
- ✅ Evidence model with artifact tracking and status workflow
- ✅ Evidence CRUD API endpoints with audit logging
- ✅ Evidence checklist generation endpoint (24 evidence requirements across controls)
- ✅ Evidence persistence across assessments for the same organization (status updates carry over)
- ✅ UI integration: clickable evidence checklist link with inline panel rendering
- ⏳ Policy templates (CW-203 - not started)
- ⏳ Audit binder export to PDF/ZIP (CW-204 - not started)

## Why This Exists

Digital health startups face a compliance paradox:
- HIPAA violations carry real financial penalties
- Security leadership is expensive
- Existing tools are checklist-based, not exploitability-aware
- Audit preparation is manual and chaotic

CharlottesWeb automates the hard parts: vulnerability correlation, risk prioritization, and evidence generation—turning compliance from a manual burden into automated intelligence.

## License

_To be determined._

## Contact

- **GitHub:** [catownsley/charlottesweb-app](https://github.com/catownsley/charlottesweb-app)
- **Issues:** [Report bugs or request features](https://github.com/catownsley/charlottesweb-app/issues/new/choose)
