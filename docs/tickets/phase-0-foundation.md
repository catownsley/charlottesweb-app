# Phase 0: Foundation

## CW-001 Define domain model and architecture decisions
- Type: Architecture
- Priority: P0
- Outcome: Written ADRs for API style, database, queue/jobs, and deployment target.
- Acceptance:
- Core entities documented (Organization, MetadataProfile, Control, Finding, EvidenceArtifact, RemediationTask)
- Technology choices captured with rationale

## CW-002 Bootstrap backend service skeleton
- Type: Backend
- Priority: P0
- Outcome: Running API service with health endpoint and basic project layout.
- Acceptance:
- App starts locally
- `/health` endpoint returns status
- Lint/test scaffolding added

## CW-003 Create initial persistence schema
- Type: Backend/Data
- Priority: P0
- Outcome: First migration with core tables and indexes.
- Acceptance:
- Migration applies and rolls back
- Seed command exists for local dev data
