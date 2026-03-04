# CharlottesWeb

> **HIPAA Compliance-as-Code platform for AI-enabled health applications**

CharlottesWeb automates regulatory mapping by correlating HIPAA requirements with real-world exploitable vulnerabilities (CVE/CWE), producing prioritized remediation roadmaps and audit-ready evidence packages.

## Quick Links

- 📋 **[Business Plan](BUSINESS_PLAN.md)** - Market strategy, competitive landscape, go-to-market, team hiring
- 🏗️ **[Architecture & Product Vision](ARCHITECTURE.md)** - Technical design, domain model, system architecture, API design
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

### Technology Stack (Planned)

- **Backend:** Python 3.11+, FastAPI, PostgreSQL, SQLAlchemy, Celery + Redis
- **Frontend:** React/Next.js, TypeScript, shadcn/ui
- **Infrastructure:** Docker, GitHub Actions, cloud deployment (AWS/Azure/Render/fly.io)
- **Data Sources:** NVD (CVE), CWE, CIS Benchmarks, NIST CSF

## Development Phases

| Phase | Focus | Status |
|-------|-------|--------|
| **Phase 0** | Foundation (domain model, backend skeleton, schema) | 🔄 Not Started |
| **Phase 1** | HIPAA Intelligence Engine (intake, mapping, correlation, scoring) | 🔄 Not Started |
| **Phase 2** | Audit Evidence Automation (templates, checklists, binder export) | 🔄 Not Started |
| **Phase 3** | Web App Workflows (auth, UI, dashboard, reports) | 🔄 Not Started |
| **Phase 4** | Pilot Readiness (isolation, observability, onboarding) | 🔄 Not Started |
| **Phase 5** | Continuous Monitoring (scheduled jobs, delta alerts, trends) | 🔄 Not Started |

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
