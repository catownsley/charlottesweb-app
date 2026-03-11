# Architecture Diagram (Viewer-Safe)

If your Markdown viewer fails to render Mermaid, use the ASCII diagram below.

## Mermaid Diagram

```mermaid
flowchart LR
    subgraph TB1[Trust Boundary 1: End User Environment]
        U[Security/Compliance User]
        B[Browser UI\nstatic/index.html + JS]
        U -->|Enter org + stack/manifest| B
    end

    subgraph TB2[Trust Boundary 2: Application Service]
        GW[FastAPI App\nmain.py]
        MW[Security Middleware\nHeaders, Request ID, Rate Limit, CORS, GZip]
        API[API Router\n/api/v1]

        R_ORG[organizations router]
        R_META[metadata_profiles router]
        R_COMP[components router]
        R_ASSESS[assessments router]
        R_EVID[evidence router]
        R_RISK[risk router]

        RE[Rules/Assessment Engine]
        CE[Compliance Mapping + CWE Mapping]
        RS[Risk Scoring Engine]
        MP[Manifest Parser\npom.xml ingestion]
    end

    subgraph TB3[Trust Boundary 3: Persistence Layer]
        DB[(SQLite/PostgreSQL\nOrganizations, Profiles, Assessments,\nFindings, Evidence, Controls)]
    end

    subgraph TB4[Trust Boundary 4: External Intel Services]
        NVD[NVD API\nCVE + version intelligence]
        MITRE[MITRE ATT&CK mappings]
    end

    subgraph TB5[Trust Boundary 5: Operational Artifacts]
        AUDIT[(Audit Logs)]
        CERTS[(Local TLS Certs\n/dev cert.pem + key.pem)]
    end

    B -->|HTTPS API calls| GW
    GW --> MW --> API

    API --> R_ORG
    API --> R_META
    API --> R_COMP
    API --> R_ASSESS
    API --> R_EVID
    API --> R_RISK

    R_COMP --> MP
    R_COMP -->|versions/suggestions lookup| NVD

    R_ASSESS --> RE
    RE --> CE
    RE -->|vulnerability enrichment| NVD
    RE -->|threat context| MITRE
    RE --> DB

    R_EVID --> DB
    R_RISK --> RS --> DB

    R_ORG --> DB
    R_META --> DB
    R_COMP --> DB
    R_ASSESS --> DB

    GW --> AUDIT
    MW --> AUDIT
    GW -. local HTTPS startup .-> CERTS

    DB --> API
    API --> GW
    GW -->|Findings, checklist, backlog, reports| B
```

## ASCII Fallback (Always Visible)

[User]
   |
   v
[Browser UI: static/index.html + JS]
   |
   | HTTPS requests
   v
[FastAPI App: main.py]
   |
   +--> [Middleware: Security headers, request-id, rate-limit, CORS, gzip]
   |
   v
[API Router /api/v1]
   |
   +--> organizations
   +--> metadata_profiles
   +--> components --> [Manifest Parser] --> [NVD]
   +--> assessments --> [Rules Engine] --> [Compliance/CWE Mapping]
   |                    |                    |
   |                    +--> [NVD]           +--> [MITRE]
   |                    +--> [Findings/Assessment writes]
   +--> evidence
   +--> risk --> [Risk Scoring Engine]
   |
   v
[Database: orgs, profiles, assessments, findings, evidence, controls]

[Audit Logs] <- App + middleware events
[Dev TLS certs] <- local HTTPS startup path
