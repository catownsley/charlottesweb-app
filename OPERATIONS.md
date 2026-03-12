# Operations Guide

This file consolidates runtime status, performance strategy, and operational priorities.

## Delivery Status (March 2026)

### Overall Progress
- Project is about **52% complete**.
- Foundation and core intelligence paths are operational.

### Phase Status
See [Ticket Index](docs/tickets/TICKET_INDEX.md) for current phase status and ticket details.

---

## Performance Strategy

### 1) Caching
- In-memory TTL caches reduce repeated reads for frequently requested data.
- Main implementation: [src/cache.py](src/cache.py).
- Typical TTLs:
  - Controls: 1 hour
  - Assessments: 30 minutes

### 2) Pagination
- Offset-based pagination for large result sets.
- Main implementation: [src/pagination.py](src/pagination.py), [src/routers/controls.py](src/routers/controls.py).
- Request params: `skip`, `limit`.

### 3) Indexing
- Query-heavy columns and foreign keys are indexed to reduce scan-heavy queries.
- Focus areas: assessments, findings, evidence, metadata profiles.

### 4) Compression
- Gzip middleware is enabled for responses larger than 1KB.
- Main implementation: [src/main.py](src/main.py).

---

## Operational Notes

### Logging and Auditability
- Structured audit logging is enabled for key CRUD and security actions.
- Main implementation: [src/audit.py](src/audit.py).

### Security Controls in Runtime
- API key auth, rate limiting, security headers, request tracing.
- See [SECURITY.md](SECURITY.md) for full control-level details.

### Test Health
- Integration/API tests are passing in current baseline.
- Test suites are under [tests](tests).

---

## Related Docs
- Architecture: [ARCHITECTURE.md](ARCHITECTURE.md)
- Security controls: [SECURITY.md](SECURITY.md)
- Threat model + trust boundaries: [THREAT_MODEL.md](THREAT_MODEL.md)
- Dev setup and workflows: [DEV_GUIDE.md](DEV_GUIDE.md)
- Execution roadmap: [docs/tickets/TICKET_INDEX.md](docs/tickets/TICKET_INDEX.md)
