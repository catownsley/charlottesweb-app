# Real-Time Medical AI Translation - Architecture & Audit Evidence Framework

## Executive Summary

This example describes a real-time, AI-enabled medical translation product for provider-patient conversations. The system intercepts live audio, transcribes speech, understands medical context (e.g., "hacked all night" = "coughed all night"), and provides real-time translation. This document maps a typical healthcare AI company's technology stack, data flow risks, and HIPAA audit evidence requirements.

## Likely Technology Architecture

### 1. Audio Ingestion Layer

**Components:**
- **Client SDK** deployed on provider side (browser or mobile)
- **WebSocket Ingestion Gateway** on AWS ALB/NLB with TLS 1.2+
- **API Gateway** for rate limiting, authentication, mTLS verification
- **Message Queue** (AWS SQS or Kafka) for reliable async processing

**Data Flow:**
```
Provider-Patient Audio Stream
  → Client SDK (end-to-end encryption?)
  → WebSocket over TLS 1.2+
  → AWS ALB (certificate pinning)
  → API Gateway (OAuth + API key validation)
  → SQS Queue (encrypted payloads with KMS)
```

**Audit Concerns:**
- Proof of TLS encryption in transit
- Certificate validation and pinning
- API authentication logs (who connected, when, from where, success/failure)
- Rate limiting to prevent replay attacks

---

### 2. Audio Processing Layer

**Components:**
- **Audio Processing Pod** (Kubernetes on EKS)
- **Automatic Speech Recognition (ASR)** - likely cloud provider (AWS Transcribe, Google Cloud Speech, or self-hosted Whisper)
- **Medical Context Understanding** - LLM fine-tuned on medical terminology
- **Translation Service** - Another LLM or specialized translation model
- **Temporary Storage** - Ephemeral volumes (10-30 min TTL)

**Data Flow:**
```
SQS Message (encrypted audio)
  → Audio Processing Pod (KMS decryption)
  → ASR Service (audio stays in memory, NOT persisted)
  → Context LLM (transcription + context tokenized)
  → Translation LLM (generates translation)
  → Metadata saved to RDS
  → Audio deleted immediately after processing
```

**Critical Audit Points:**
- Proof that audio is NOT persisted to disk
- Proof that models are NOT fine-tuned on patient audio
- Encryption keys managed via AWS KMS or HashiCorp Vault
- Access logs to model endpoints (who accessed, IP, timestamp)
- Network egress controls (models can't call unknown endpoints)

---

### 3. Storage Layer

**Components:**
- **RDS PostgreSQL** for metadata: conversation ID, provider ID, patient context (no names/MRN in plaintext)
- **S3 Buckets** (encrypted with KMS, versioning disabled, MFA delete enabled)
  - `healthcare-org-audit-logs/` - CloudTrail logs
  - `healthcare-org-database-backups/` - encrypted snapshots
- **DynamoDB** (optional) for session state, caching
- **VPC Endpoints** for S3/RDS to avoid internet egress

**Encryption:**
- **At Rest:** AES-256 (S3, RDS, DynamoDB)
- **In Transit:** TLS 1.2+ everywhere
- **Key Management:** AWS KMS with key rotation every 90 days
- **Backups:** Encrypted RDS snapshots, encrypted S3 backups

**Audit Evidence:**
- KMS key audit logs (who accessed, when)
- RDS encryption status + backup encryption
- S3 bucket policies (block public access, versioning, MFA delete)
- Database access logs (slow query logs, authentication attempts)

---

### 4. Data Scrubbing & Deletion

**Components:**
- **Retention Policy Engine** - Cronjob to TTL audio/metadata
- **Cryptographic Key Rotation** - Delete old encryption keys after 180 days
- **De-identification Service** - Before any data archived to cold storage
- **Deletion Audit Logger** - Record every deletion with timestamp, user, reason

**Policy:**
- Audio: Deleted 24 hours after processing (or immediately if processing fails)
- Transcription: Kept as metadata for translation, deleted after 90 days unless needed for dispute
- Translation: Kept indefinitely (clinical record)
- Encryption keys: Rotated every 90 days, old keys deleted after 180 days (unrecoverable after this point)

**Audit Evidence:**
- Audit logs showing audio deletion timestamps
- Proof of key rotation (KMS audit log)
- Deletion confirmation records
- RTO/RPO documentation

---

### 5. Network & Infrastructure Security

**Components:**
- **VPC** with public/private/database subnets
- **Security Groups** enforcing least privilege (only ALB → Pod traffic, Pod → RDS traffic, etc.)
- **VPC Flow Logs** to CloudWatch/S3
- **WAF** on ALB blocking OWASP top 10
- **NAT Gateway** for outbound traffic (single point for egress logs)

**Audit Evidence:**
- VPC Flow Logs (ingress/egress, denied connections)
- Security group rules (least privilege enforcement)
- WAF rules and block logs
- Egress allowlist (where pods can connect)

---

### 6. Access Control & Identity

**Components:**
- **IAM Roles** for pods, developers, cross-account access
- **RBAC** in Kubernetes (namespaces, service accounts)
- **MFA** enforced for all human access to AWS console, databases
- **Secrets Manager** for API keys, database passwords (rotated every 30 days)

**Audit Evidence:**
- IAM policy audit (who has what permissions)
- MFA enforcement logs
- Database user creation/deletion audit
- API key rotation logs

---

### 7. Monitoring & Incident Response

**Components:**
- **CloudWatch** for application logs
- **Prometheus + Grafana** for infrastructure metrics
- **Splunk/ELK** for centralized logging and SIEM
- **GuardDuty** for threat detection (AWS)
- **Slack alerts** for security events

**Audit Evidence:**
- Alert rules and thresholds
- Incident logs (what, when, action taken, root cause)
- Backup test results (RTO achieved?)
- Disaster recovery drills

---

## HIPAA Security Rule Controls Mapped to Healthcare Organization

| Control ID | Title | Example Evidence | Audit Expectation |
|---|---|---|---|
| SC-2.1 | Access Controls | IAM policies limiting who can modify encryption keys, access RDS, deploy pods | Least privilege enforcement; no overpermissioned service accounts |
| SC-4.1 | Encryption & Decryption | KMS key audit logs, S3/RDS encryption status, TLS certificates | All data encrypted at rest (AES-256) and in transit (TLS 1.2+) |
| SC-7.1 | Transmission Security | TLS 1.2+ certs, certificate pinning, VPC Flow Logs | No unencrypted sensitive data in transit |
| SC-12.1 | Key Management | KMS key rotation logs, key policy audit, old key deletion proof | Keys rotated every 90 days, audit trail of access |
| AU-6.1 | Audit Controls - Integrity | CloudTrail logs for API calls, database audit logs | All actions logged; audit log tampering detectable |
| AU-2.1 | Audit Controls - Logging | Application-level audit logs (who accessed translations, when), S3 audit logs | Comprehensive logging of data access |
| UI-1.1 | Data De-identification | De-identification rules, proof of PII removal before archival | Confirmation that archived data is properly de-identified |
| PII Retention | Data Retention & Deletion | Deletion audit logs, cron job logs for TTL enforcement | Proof that audio is deleted per policy (24 hrs, then cryptographic erasure) |

---

## Evidence Collection Strategy

For each control, we collect **4 types of evidence:**

1. **Configuration Evidence** - "Is encryption enabled?" (S3 bucket policy, RDS encryption status)
2. **Access Evidence** - "Who accessed what and when?" (IAM logs, database logs, API logs)
3. **Operational Evidence** - "Did the process execute as expected?" (Deletion logs, key rotation logs, backup verification)
4. **Compliance Evidence** - "Do you have a policy for this?" (Data Retention Policy, Encryption Policy, Incident Response Plan)

---

## Audit Checklist Example

When an auditor reviews such a healthcare AI organization, they'd want:

**Week 1: Ingestion & Authentication**
- [ ] Proof of TLS 1.2+ on all ingestion endpoints
- [ ] API key rotation logs (last 90 days)
- [ ] Failed authentication attempts log
- [ ] Rate limiting configuration + block logs

**Week 2: Audio Processing & Storage**
- [ ] Proof audio is NOT persisted to pod disks (ephemeral volume config)
- [ ] Proof models are NOT fine-tuned on patient audio (GitHub repo scan, model access logs)
- [ ] Encryption key rotation logs (last 180 days)
- [ ] Database encryption status + certificate details

**Week 3: Data Deletion & Retention**
- [ ] Audio deletion logs (every file deleted, timestamp, reason)
- [ ] Cryptographic key destruction logs
- [ ] De-identification rules and execution logs
- [ ] Disaster recovery test results (RTO achieved?)

**Week 4: Access Control & Incident Response**
- [ ] IAM policy review (least privilege)
- [ ] MFA enforcement for human access
- [ ] Incident log for last 12 months (any data breaches? How handled?)
- [ ] Security patch application log

---

## Next Steps

1. **Ingestion Evidence** - Seed controls for audio intake, API auth, encryption in transit
2. **Processing Evidence** - Controls for model usage, ephemeral storage, key management
3. **Storage Evidence** - Controls for encryption at rest, backup security, database hardening
4. **Deletion Evidence** - Controls for TTL enforcement, cryptographic erasure, audit logging
5. **Access Control Evidence** - IAM, RBAC, MFA, API key rotation
6. **Incident Response Evidence** - Breach logs, remediation proof, drill results

This framework is **realistic but aspirational**—a healthcare AI company may not have all of these controls yet, but the automation tool helps them **track what they have, what they're missing, and what the auditor will ask for**.

---

## Definitions

- **Ephemeral Volume**: Kubernetes persistent storage that is deleted when the pod terminates (audio stays in memory only)
- **Cryptographic Erasure**: Deleting the encryption key, making ciphertext unrecoverable (preferred over file overwrite)
- **KMS**: AWS Key Management Service (manages encryption keys)
- **CloudTrail**: AWS API audit logging (who called what API, when, from where, success/failure)
- **RTO/RPO**: Recovery Time Objective (how long to restore) / Recovery Point Objective (how much data loss acceptable)
