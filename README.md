# Charlotte's Web

> AI-Powered Threat Modeling and Automated Compliance for Applications that Protect Regulated Data

Charlotte's Web combines AI-driven threat analysis with multi-framework compliance automation**. Use metadata about your software stack (applications and infrastructure) to get a complete STRIDE threat model in minutes, while simultaneously mapping your stack against HIPAA, NIST 800-53, GDPR, SOX, FedRAMP, APRA CPS 234, and CCPA. Real vulnerabilities from your actual software stack are correlated with regulatory controls to produce prioritized, actionable remediation roadmaps.

## AI Threat Model

Use metadata about your software stack to generate a comprehensive threat model in minutes. Add your components, versions, and infrastructure details, then click **AI Threat Model** to get:

- **Executive summary** of your security posture
- **STRIDE threat analysis:** specific threats to your architecture with actionable mitigations
- **Consolidated dependency findings:** not a line-item per CVE, but a prioritized view of what matters
- **Compound risk detection:** where a known CVE escalates an architectural threat (e.g., an unpatched deserialization flaw + a public-facing API = critical)
- **Prioritized remediation roadmap:** what to fix first, second, third, with rationale

Export the full report as a text file sorted by severity. Results are cached (7-day TTL) to minimize API cost. Use **Force Regenerate** when your assessment data changes.

Requires an Anthropic API key. See [DEV_GUIDE.md](DEV_GUIDE.md) for setup.

## Automated Compliance

**Compliance mapped to real exploitability.** Most tools tell you what controls you need. We tell you which vulnerabilities in your actual stack create regulatory risk.

- **Metadata-only intake:** zero PHI ingestion
- **Multi-framework regulatory mapping:** HIPAA, NIST 800-53, GDPR, SOX, FedRAMP, APRA CPS 234, CCPA
- **CVE/CWE correlation:** exploitability-aware risk scoring via NVD and Dependabot
- **Interactive data flow diagrams:** editable Cytoscape.js diagrams with trust boundaries, drag-and-drop nodes, and labeled data flows
- **Prioritized remediation roadmap:** Immediate / 30 Days / Quarterly / Annual
- **Audit evidence automation:** control-to-evidence mapping, policy templates, audit binders

## Security First

**Production-ready security controls:**
- API key authentication
- Rate limiting (60 req/min default)
- Audit logging
- Security headers (HSTS, CSP, etc.)
- Request tracing
- Environment-based secrets management

See [SECURITY.md](SECURITY.md) for complete security documentation.

## Quick Links

- **[DEV_GUIDE](DEV_GUIDE.md):** Setup, security configuration, API examples
- **[Architecture & Product Vision](ARCHITECTURE.md):** Technical design, domain model, API design
- **[Business Plan](BUSINESS_PLAN.md):** Market strategy, competitive landscape, go-to-market
- **[Documentation Index](docs/INDEX.md):** Full navigation guide to all project docs
- **[Security Documentation](SECURITY.md):** Security features, configuration, and best practices
- **[Ticket Index](docs/tickets/TICKET_INDEX.md):** Phased execution roadmap with detailed tickets
- **[GitHub Issues](https://github.com/catownsley/charlottesweb-app/issues):** Active implementation backlog

## Project Structure

```
charlottesweb-app/
├── BUSINESS_PLAN.md # Complete business strategy and market analysis
├── ARCHITECTURE.md # Technical design and implementation guide
├── OPERATIONS.md # Consolidated status + performance + runbook notes
├── README.md # This file
├── docs/
│ ├── INDEX.md # Documentation navigation guide
│ └── tickets/ # Phased execution backlog
│   └── TICKET_INDEX.md
├── src/ # Application code
├── scripts/ # Automation scripts
└── .github/
└── ISSUE_TEMPLATE/ # GitHub issue templates
```

## Getting Started

### For New Contributors

1. **Read the context:**
- [BUSINESS_PLAN.md](BUSINESS_PLAN.md): Understand the market, problem, and business model
- [ARCHITECTURE.md](ARCHITECTURE.md): Understand the technical vision and domain model

2. **Review the roadmap:**
- [docs/tickets/TICKET_INDEX.md](docs/tickets/TICKET_INDEX.md): See all planned phases
- [GitHub Issues](https://github.com/catownsley/charlottesweb-app/issues): Check active tickets

3. **Start building:**
- Begin with **[CW-001]** Define domain model and architecture decisions
- Follow Phase 0 > Phase 1 > Phase 2 > Phase 3 > Phase 4 > Phase 5

### Technology Stack (Current MVP)

- **Runtime:** Python 3.14.3
- **Backend API:** FastAPI 0.135.1, Uvicorn 0.41.0, Pydantic 2.12.5
- **Config:** pydantic-settings 2.13.1, `.env`-based configuration
- **Database:** SQLite + SQLAlchemy 2.0.48, Alembic 1.18.4
- **Security:** PyJWT 2.11.0, passlib 1.7.4, slowapi 0.1.9
- **Testing:** pytest 9.0.2, pytest-asyncio 1.3.0, httpx 0.28.1
- **CI/CD Security:** CodeQL, Bandit, pip-audit

## Development Phases

See [Ticket Index](docs/tickets/TICKET_INDEX.md) for detailed phase status and individual tickets.

**Current focus:** Phase 2 (Audit Evidence) and Phase 3 (Web App Workflows) are in progress. Phases 0 and 1 are complete.

## Why This Exists

Digital health startups face a security and compliance paradox:
- Threat modeling takes weeks of expert time, so most startups skip it entirely
- HIPAA violations carry real financial penalties
- Security leadership is expensive
- Existing tools lack exploitability-aware action plans
- Audit preparation is manual and chaotic

CharlottesWeb automates both sides: AI generates your threat model in minutes while the compliance engine handles vulnerability correlation, risk prioritization, and evidence generation, turning security and compliance from a manual burden into automated intelligence.

## License

_To be determined._

## Contact

- **GitHub:** [catownsley/charlottesweb-app](https://github.com/catownsley/charlottesweb-app)
- **Issues:** [Report bugs or request features](https://github.com/catownsley/charlottesweb-app/issues/new/choose)
