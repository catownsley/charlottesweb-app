# Phase 2: Audit Evidence Automation

## CW-201 Control-to-evidence mapping model
- Type: Backend/Data
- Priority: P0
- Outcome: Evidence requirements linked to mapped controls.
- Acceptance:
- Evidence artifact schema supports status and owner
- Per-control evidence checklist generated

## CW-202 Evidence checklist generation
- Type: Backend
- Priority: P0
- Outcome: Endpoint generating audit checklist from findings + controls.
- Acceptance:
- Checklist includes required docs, source, and due date
- Supports regeneration/versioning

## CW-203 Policy/document templates generation
- Type: Backend/Docs
- Priority: P1
- Outcome: Stack-tailored templates for policies and procedures.
- Acceptance:
- Template set for access review, incident response, logging retention
- Variables populated from metadata profile

## CW-204 Audit binder export endpoint
- Type: Backend/Reporting
- Priority: P1
- Outcome: Downloadable audit binder package.
- Acceptance:
- Exports evidence checklist + generated templates + summary
- Produces reproducible artifact version
