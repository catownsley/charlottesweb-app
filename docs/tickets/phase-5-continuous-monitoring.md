# Phase 5: Continuous Monitoring

## CW-501 Scheduled re-assessment jobs
- Type: Backend
- Priority: P0
- Outcome: Monthly/weekly reassessment jobs by tier.
- Acceptance:
- Scheduler configurable per organization
- Job history visible in API

## CW-502 Delta risk detection and alerts
- Type: Backend/Notifications
- Priority: P1
- Outcome: Detect risk posture changes and notify users.
- Acceptance:
- Delta report compares current vs previous assessment
- Alert triggers on threshold breaches

## CW-503 Posture timeline and trend reporting
- Type: Fullstack
- Priority: P1
- Outcome: Trend visualization for compliance posture over time.
- Acceptance:
- Timeline supports severity and control trends
- Exportable trend summary report

## CW-504 Dynamic HIPAA feed ingestion and control versioning
- Type: Backend/Compliance Intelligence
- Priority: P0
- Outcome: Ingest versioned HIPAA rule/control updates from a trusted feed source.
- Acceptance:
- Feed ingestion stores effective dates and version metadata
- Control diffs are generated and reviewable
- Existing assessments remain reproducible against historical control versions

## CW-505 Regulation adapter framework for non-HIPAA domains
- Type: Backend/Architecture
- Priority: P1
- Outcome: Pluggable adapter model for additional regulations (SOC 2, PCI DSS, GDPR, state privacy laws).
- Acceptance:
- Common adapter interface for parsing, normalization, and mapping
- HIPAA remains default adapter; at least one secondary adapter proof-of-concept

## CW-506 Data-lifecycle based regulation applicability inference
- Type: Fullstack/Intelligence
- Priority: P1
- Outcome: Infer required regulations from customer-described data lifecycle and geolocation context.
- Acceptance:
- Input model supports sourcing/processing/storage/destruction/geolocation dimensions
- Inference output returns applicable regulation set with rationale
- HIPAA path remains deterministic and backward-compatible with current workflows
