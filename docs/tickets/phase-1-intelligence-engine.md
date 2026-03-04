# Phase 1: HIPAA Compliance Intelligence Engine

## CW-101 Build metadata intake API
- Type: Backend
- Priority: P0
- Outcome: Endpoint to ingest architecture metadata only (no PHI).
- Acceptance:
  - Request validation blocks PHI fields
  - Metadata profile persisted per organization

## CW-102 Implement HIPAA control catalog seed
- Type: Compliance/Backend
- Priority: P0
- Outcome: Seeded machine-readable HIPAA controls and mappings.
- Acceptance:
  - Controls versioned
  - Seed script idempotent

## CW-103 Implement rules mapping engine
- Type: Backend
- Priority: P0
- Outcome: Deterministic mapping from metadata profile to applicable controls.
- Acceptance:
  - Unit tests cover base rule scenarios
  - Output includes rationale per mapping

## CW-104 Add CVE/CWE correlation service abstraction
- Type: Security/Backend
- Priority: P1
- Outcome: Adapter interface for vulnerability intelligence sources.
- Acceptance:
  - Provider abstraction with mocked implementation
  - Correlation output linked to controls/findings

## CW-105 Add risk scoring and prioritization
- Type: Backend
- Priority: P0
- Outcome: Findings scored and grouped into Immediate / 30 Days / Quarterly / Annual.
- Acceptance:
  - Scoring formula documented
  - Deterministic test fixtures pass

## CW-106 Generate remediation roadmap output
- Type: Backend/Reporting
- Priority: P0
- Outcome: Structured remediation roadmap JSON for dashboard/reporting.
- Acceptance:
  - Endpoint returns grouped actions with owner and due window
  - Includes executive summary fields
