# CharlottesWeb Business Plan

**Multi-Framework Compliance Intelligence Platform for Applications that Protect Regulated Data**

## Document Purpose

This document outlines the complete business plan for CharlottesWeb, a multi-framework Compliance Intelligence platform for applications that protect regulated data. Its core objective is to shift compliance from manual processes to automated, exploitability-driven regulatory intelligence with actionable remediation plans.

---

## 1. Executive Summary

CharlottesWeb is a Compliance Intelligence platform for organizations handling regulated data (PHI, PII, financial records). Companies processing sensitive data often lack in-house security leadership yet face significant regulatory, financial, and reputational risk in the event of a breach.

CharlottesWeb automates regulatory mapping by ingesting structured metadata about an organization's data types, data flows, infrastructure, and application stack. The platform correlates applicable regulatory requirements (HIPAA, NIST 800-53, GDPR, SOX, FedRAMP, APRA CPS 234, CCPA) with real-world exploitable vulnerabilities (via NVD/CVE/CWE), secure coding risk patterns, and infrastructure misconfigurations to produce a prioritized remediation roadmap and audit-ready evidence package.

**Our goal:** Become the automated compliance intelligence and audit preparation layer for modern companies building on AWS, Azure, and AI-enabled stacks that handle regulated data.

---

## 2. Company Overview & Value Proposition

### The Shift

We shift compliance from **manual spreadsheets + expensive consultants** to **automated, continuously updated regulatory intelligence**.

### Core Unique Value Proposition (UVP)

**Compliance mapped to real exploitability.**

Most compliance tools map controls to frameworks. CharlottesWeb maps:

- Regulatory requirements (HIPAA, NIST 800-53, GDPR, SOX, FedRAMP, APRA CPS 234, CCPA)
- Infrastructure components
- Known vulnerabilities (CVE via NVD)
- Common weakness patterns (CWE)
- Application-layer risk patterns
- Misconfiguration exposure
- Breach notification obligations

### Output

- Exploitable regulatory gap analysis
- Risk severity scoring
- Prioritized remediation sequencing (Immediate / 30 Days / Quarterly / Annual)
- Executive-level summary for founders and boards

### Future Expansion Verticals

- SOC2 automation layer
- PCI stack risk correlation (Stripe-heavy SaaS)
- AI + PHI risk mapping module
- Continuous compliance monitoring subscription
- Advisory tier (Founder / Board readiness consulting)
- Expansion to global regulatory frameworks

---

## 3. Market Analysis & Competitive Landscape

### Target Market

- Early to mid-stage digital health startups (Seed–Series B)
- AI-enabled healthcare SaaS platforms
- Telehealth providers
- Health data analytics companies
- Founders without dedicated compliance teams

### Core Problem

- Regulatory enforcement carries real financial penalties (HIPAA, GDPR, SOX, etc.)
- Startups underestimate breach exposure
- Security leadership is expensive
- Existing tools lack exploitability-aware action plans
- Audit preparation is chaotic and manual

### Competitive Landscape

| Competitor Type | Examples | Weakness | CharlottesWeb Edge |
|----------------|----------|----------|-------------------|
| **Static Compliance Platforms** | Drata, Vanta | Framework-based, not exploit-based | We correlate CVEs/CWEs to regulatory exposure |
| **Traditional Consultants** | Boutique firms | Expensive, episodic, manual | Automated + optional advisory tier |
| **Enterprise GRC Platforms** | Archer, ServiceNow | Heavy, enterprise-focused | Startup-focused, lightweight deployment |
| **Security Scanners** | Snyk, Prisma, etc. | Findings lack compliance translation | We translate technical findings into regulatory impact across 7 frameworks |

---

## 4. Product & Technology

### Phase 1: Multi-Framework Compliance Intelligence Engine

#### Input (Metadata-Driven Model)

- Data classification (PHI types)
- Data collection methods
- Data storage and processing flows
- Cloud provider (AWS/Azure/GCP)
- CI/CD stack
- Access control model
- Logging & monitoring systems
- Third-party integrations
- AI/ML components (if applicable)

**Important:** CharlottesWeb does not ingest PHI. Only architectural metadata is collected to reduce liability.

#### Processing Layer

- Multi-framework regulatory mapping (HIPAA, NIST 800-53, GDPR, SOX, FedRAMP, APRA CPS 234, CCPA)
- Cross-framework control correlation
- NVD ingestion (CVE correlation)
- CWE ingestion
- CIS Benchmark alignment
- NIST CSF crosswalk
- SAST relevance mapping
- Exploitability scoring model

#### Output

- Regulatory Gap Report
- Exploitable Risk Matrix
- Remediation Roadmap (Yesterday / 30 Days / Quarterly / Annual)
- Executive Summary for leadership
- Technical appendix for engineers

---

## 5. Audit Evidence Automation Layer

Most startups fail audits not due to lack of controls, but due to **lack of organized evidence**.

CharlottesWeb generates:

- Control-to-evidence mapping
- Required documentation action plan
- Logging retention verification report
- Access review documentation templates
- Incident response tabletop documentation templates
- Risk assessment artifact generation
- Policy skeletons tailored to stack architecture
- Pre-formatted audit-ready evidence binder

### Optional Enhancements

- API-based infrastructure evidence ingestion (IAM snapshots, encryption states, logging configs)
- Time-stamped compliance posture reports
- Continuous evidence tracking for audit readiness

This transforms CharlottesWeb from a compliance scanner into a **compliance operating system**.

---

## 6. Business Model & Monetization

### Revenue Tiers

| Tier | Description | Key Features | Pricing Model |
|------|-------------|--------------|---------------|
| **Tier 1 – Automated Scan** | One-time initial compliance assessment | Multi-framework compliance gap analysis, Downloadable report | One-time fee |
| **Tier 2 – Continuous Monitoring Subscription** | Ongoing, automated compliance maintenance | Monthly vulnerability correlation, Alerting on new CVEs, Ongoing compliance posture updates, Evidence tracking updates | Monthly SaaS Subscription |
| **Tier 3 – Advisory Premium** | Expert consultation and strategic guidance | Direct consultation (security & compliance strategy), Remediation prioritization, Board readiness preparation, Audit readiness strategy, Incident response simulation guidance | High-Margin Service Fee (Add-on) |

### Revenue Model

Recurring SaaS subscription + high-margin advisory services.

---

## 7. Go-to-Market Strategy

### Initial Wedge

Digital health startups building AI-enabled health platforms that process PHI.

### Acquisition Channels

- Founder communities (YC, Techstars, health accelerators)
- VC portfolio risk programs
- LinkedIn thought leadership (Founder credibility)
- Security webinars for health tech
- Health tech Slack communities
- Partnerships with boutique law firms

### The Hook

> "Is your startup one breach away from a regulatory investigation?"

### The Aha Moment

User uploads architecture metadata. Within minutes, they receive:

- Mapped exploitable compliance gaps
- Real CVE correlations
- Audit preparation action plan

### Upsell Path

- Upgrade to continuous monitoring subscription
- Engage founder for compliance advisory strategy

---

## 8. Team & Hiring Plan

### Phase 1 (Lean Build)

- **Founder** (Domain Expert, Advisory Lead)
- **Backend Engineer** (Python, NVD ingestion, API design)
- **Frontend Engineer** (Dashboard + reporting interface)
- **Security Research Contributor** (CWE/CVE correlation logic)

### Phase 2

- Compliance researcher
- DevRel / Security marketing lead
- Sales lead for health vertical

---

## Implementation Roadmap

See [docs/tickets/TICKET_INDEX.md](docs/tickets/TICKET_INDEX.md) for detailed execution phases and tickets.

### Quick Phase Overview

- **Phase 0:** Foundation (architecture decisions, domain model, backend skeleton)
- **Phase 1:** Multi-Framework Compliance Intelligence Engine (metadata intake, rule mapping, CVE/CWE correlation, risk scoring)
- **Phase 2:** Audit Evidence Automation (control-to-evidence mapping, template generation, audit binder export)
- **Phase 3:** Web App Workflows (auth, assessment UI, findings dashboard, report downloads)
- **Phase 4:** Pilot Readiness (tenant isolation, observability, onboarding)
- **Phase 5:** Continuous Monitoring (scheduled re-assessments, delta detection, trend reporting)

---

## Contact & Repository

- **GitHub:** [catownsley/charlottesweb-app](https://github.com/catownsley/charlottesweb-app)
- **Issues:** [View open tickets](https://github.com/catownsley/charlottesweb-app/issues)
