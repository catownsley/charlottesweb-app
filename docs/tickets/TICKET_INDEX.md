# Ticket Index

This file is the single roadmap and ticket source for phase-based execution.

## Phase Summary

## Phase 0 - Foundation ✅ COMPLETE
- CW-001: Define domain model and architecture decisions
- CW-002: Bootstrap backend service skeleton
- CW-003: Create initial persistence schema

## Phase 1 - HIPAA Intelligence Engine ✅ COMPLETE
- CW-101: Build metadata intake API
- CW-102: Implement HIPAA control catalog seed
- CW-103: Implement rules mapping engine
- CW-104: Add CVE/CWE correlation service abstraction
- CW-105: Add risk scoring and prioritization
- CW-106: Generate remediation roadmap output
- CW-107: Add compliance-threat fused prioritized backlog endpoint

## Phase 2 - Audit Evidence Automation 🚧 IN PROGRESS
- CW-201: Control-to-evidence mapping model
- CW-202: Evidence checklist generation
- CW-203: Policy/document templates generation
- CW-204: Audit binder export endpoint

## Phase 3 - Web App Workflows 🚧 IN PROGRESS
- CW-301: Auth and organization onboarding ✅ COMPLETE
- CW-302: Assessment run workflow UI ✅ COMPLETE
- CW-303: Findings dashboard and filters ✅ COMPLETE
- CW-304: Report download and share flow 🎯 NEXT FOCUS

## Phase 4 - Pilot Readiness ⏸️ NOT STARTED
- CW-401: Tenant isolation guardrails
- CW-402: Observability and audit logging
- CW-403: Pilot onboarding scripts and sample data

## Phase 5 - Continuous Monitoring ⏸️ NOT STARTED
- CW-501: Scheduled re-assessment jobs
- CW-502: Delta risk detection and alerts
- CW-503: Posture timeline and trend reporting

## Phase 5.5 - Dynamic Regulatory Intelligence ⏸️ PLANNED
- CW-504: Dynamic HIPAA feed ingestion and versioning
- CW-505: Regulation adapter framework (SOC 2, PCI DSS, GDPR, etc.)
- CW-506: Data-lifecycle based regulation applicability inference

---

## Detailed Tickets

## Phase 0: Foundation

### CW-001 Define domain model and architecture decisions
- Type: Architecture
- Priority: P0
- Outcome: Written ADRs for API style, database, queue/jobs, and deployment target.
- Acceptance:
	- Core entities documented (Organization, MetadataProfile, Control, Finding, EvidenceArtifact, RemediationTask)
	- Technology choices captured with rationale

### CW-002 Bootstrap backend service skeleton
- Type: Backend
- Priority: P0
- Outcome: Running API service with health endpoint and basic project layout.
- Acceptance:
	- App starts locally
	- `/health` endpoint returns status
	- Lint/test scaffolding added

### CW-003 Create initial persistence schema
- Type: Backend/Data
- Priority: P0
- Outcome: First migration with core tables and indexes.
- Acceptance:
	- Migration applies and rolls back
	- Seed command exists for local dev data

## Phase 1: HIPAA Compliance Intelligence Engine

### CW-101 Build metadata intake API
- Type: Backend
- Priority: P0
- Outcome: Endpoint to ingest architecture metadata only (no PHI).
- Acceptance:
	- Request validation blocks PHI fields
	- Metadata profile persisted per organization

### CW-102 Implement HIPAA control catalog seed
- Type: Compliance/Backend
- Priority: P0
- Outcome: Seeded machine-readable HIPAA controls and mappings.
- Acceptance:
	- Controls versioned
	- Seed script idempotent

### CW-103 Implement rules mapping engine
- Type: Backend
- Priority: P0
- Outcome: Deterministic mapping from metadata profile to applicable controls.
- Acceptance:
	- Unit tests cover base rule scenarios
	- Output includes rationale per mapping

### CW-104 Add CVE/CWE correlation service abstraction
- Type: Security/Backend
- Priority: P1
- Outcome: Adapter interface for vulnerability intelligence sources.
- Acceptance:
	- Provider abstraction with mocked implementation
	- Correlation output linked to controls/findings

### CW-105 Add risk scoring and prioritization
- Type: Backend
- Priority: P0
- Outcome: Findings scored and grouped into Immediate / 30 Days / Quarterly / Annual.
- Acceptance:
	- Scoring formula documented
	- Deterministic test fixtures pass

### CW-106 Generate remediation roadmap output
- Type: Backend/Reporting
- Priority: P0
- Outcome: Structured remediation roadmap JSON for dashboard/reporting.
- Acceptance:
	- Endpoint returns grouped actions with owner and due window
	- Includes executive summary fields

### CW-107 Add compliance-threat fused prioritized backlog endpoint
- Type: Backend/Security/Compliance
- Priority: P0
- Outcome: Residual-risk prioritized engineering backlog that combines control posture and threat pressure.
- Acceptance:
	- Endpoint `GET /api/v1/risk/prioritized-backlog` supports assessment and organization scope
	- Output includes `control_confidence`, `threat_pressure`, `residual_risk`, and execution bucket
	- Scoring is deterministic and bounded (0-100) with documented formulas
	- Reuses existing domain entities without breaking schema migrations

## Phase 2: Audit Evidence Automation

### CW-201 Control-to-evidence mapping model
- Type: Backend/Data
- Priority: P0
- Outcome: Evidence requirements linked to mapped controls.
- Acceptance:
	- Evidence artifact schema supports status and owner
	- Per-control evidence checklist generated

### CW-202 Evidence checklist generation
- Type: Backend
- Priority: P0
- Outcome: Endpoint generating audit checklist from findings + controls.
- Acceptance:
	- Checklist includes required docs, source, and due date
	- Supports regeneration/versioning

### CW-203 Policy/document templates generation
- Type: Backend/Docs
- Priority: P1
- Outcome: Stack-tailored templates for policies and procedures.
- Acceptance:
	- Template set for access review, incident response, logging retention
	- Variables populated from metadata profile

### CW-204 Audit binder export endpoint
- Type: Backend/Reporting
- Priority: P1
- Outcome: Downloadable audit binder package.
- Acceptance:
	- Exports evidence checklist + generated templates + summary
	- Produces reproducible artifact version

## Phase 3: Web App Workflows

### CW-301 Auth and organization onboarding
- Type: Fullstack
- Priority: P0
- Status: ✅ Complete (PR #31)
- Outcome: User auth and organization setup flow.
- Acceptance:
	- New org can register and create profile
	- Role model supports admin/member

### CW-302 Assessment run workflow UI
- Type: Frontend
- Priority: P0
- Status: ✅ Complete (PR #32)
- Outcome: Guided form to submit metadata and run assessment.
- Acceptance:
	- Validation mirrors backend schema
	- Run status/progress visible

### CW-303 Findings dashboard and filters
- Type: Frontend
- Priority: P0
- Status: ✅ Complete (PR #34)
- Outcome: Display findings by severity/control/domain.
- Acceptance:
	- Supports sorting/filtering by priority window
	- Links findings to remediation actions

### CW-304 Report download and share flow
- Type: Frontend/Backend
- Priority: P1
- Status: 🎯 Next Focus
- Outcome: Download executive report and technical appendix.
- Acceptance:
	- Report generation status visible
	- Access control enforced for downloads

## Phase 4: Pilot Readiness

### CW-401 Tenant isolation guardrails
- Type: Security/Backend
- Priority: P0
- Outcome: Strict org-level data isolation controls.
- Acceptance:
	- Authorization checks enforce tenant boundaries
	- Security tests cover cross-tenant access attempts

### CW-402 Observability and audit logging
- Type: Platform
- Priority: P0
- Outcome: Structured logs, metrics, and key audit trail events.
- Acceptance:
	- All critical actions emit audit events
	- Error and latency dashboards available

### CW-403 Pilot onboarding scripts and sample data
- Type: Platform/Operations
- Priority: P1
- Outcome: Repeatable setup for pilot customers.
- Acceptance:
	- Scripted org bootstrap
	- Sample data pack available for reference scenarios

## Phase 5: Continuous Monitoring

### CW-501 Scheduled re-assessment jobs
- Type: Backend
- Priority: P0
- Outcome: Monthly/weekly reassessment jobs by tier.
- Acceptance:
	- Scheduler configurable per organization
	- Job history visible in API

### CW-502 Delta risk detection and alerts
- Type: Backend/Notifications
- Priority: P1
- Outcome: Detect risk posture changes and notify users.
- Acceptance:
	- Delta report compares current vs previous assessment
	- Alert triggers on threshold breaches

### CW-503 Posture timeline and trend reporting
- Type: Fullstack
- Priority: P1
- Outcome: Trend visualization for compliance posture over time.
- Acceptance:
	- Timeline supports severity and control trends
	- Exportable trend summary report

### CW-504 Dynamic HIPAA feed ingestion and control versioning
- Type: Backend/Compliance Intelligence
- Priority: P0
- Outcome: Ingest versioned HIPAA rule/control updates from a trusted feed source.
- Acceptance:
	- Feed ingestion stores effective dates and version metadata
	- Control diffs are generated and reviewable
	- Existing assessments remain reproducible against historical control versions

### CW-505 Regulation adapter framework for non-HIPAA domains
- Type: Backend/Architecture
- Priority: P1
- Outcome: Pluggable adapter model for additional regulations (SOC 2, PCI DSS, GDPR, state privacy laws).
- Acceptance:
	- Common adapter interface for parsing, normalization, and mapping
	- HIPAA remains default adapter; at least one secondary adapter proof-of-concept

### CW-506 Data-lifecycle based regulation applicability inference
- Type: Fullstack/Intelligence
- Priority: P1
- Outcome: Infer required regulations from customer-described data lifecycle and geolocation context.
- Acceptance:
	- Input model supports sourcing/processing/storage/destruction/geolocation dimensions
	- Inference output returns applicable regulation set with rationale
	- HIPAA path remains deterministic and backward-compatible with current workflows
