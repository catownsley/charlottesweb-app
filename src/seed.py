"""Seed database with initial HIPAA controls and healthcare-specific evidence requirements."""
from datetime import datetime, timedelta

from src.database import Base, SessionLocal, engine
from src.models import (
    Assessment,
    Control,
    Evidence,
    Finding,
    MetadataProfile,
    Organization,
)


def seed_controls():
    """Seed database with HIPAA + healthcare-specific controls and sample evidence."""
    # Create all tables
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()

    # HIPAA Security Rule controls (original 10)
    controls = [
        Control(
            id="HIPAA.164.308(a)(1)(ii)(A)",
            framework="HIPAA_Security_Rule",
            title="Risk Analysis",
            requirement=(
                "Conduct an accurate and thorough assessment of the potential risks and "
                "vulnerabilities to the confidentiality, integrity, and availability of "
                "electronic protected health information held by the covered entity or business associate."
            ),
            category="Administrative Safeguards",
            evidence_types=["risk_assessment_documentation", "asset_inventory"],
        ),
        Control(
            id="HIPAA.164.312(a)(1)",
            framework="HIPAA_Security_Rule",
            title="Access Control - Unique User Identification",
            requirement=(
                "Assign a unique name and/or number for identifying and tracking user identity."
            ),
            category="Technical Safeguards",
            evidence_types=["user_access_logs", "mfa_configuration"],
        ),
        Control(
            id="HIPAA.164.312(a)(2)(iv)",
            framework="HIPAA_Security_Rule",
            title="Encryption and Decryption (Addressable)",
            requirement=(
                "Implement a mechanism to encrypt and decrypt electronic protected health information."
            ),
            category="Technical Safeguards",
            evidence_types=["encryption_at_rest_configuration", "encryption_key_management"],
        ),
        Control(
            id="HIPAA.164.312(e)(1)",
            framework="HIPAA_Security_Rule",
            title="Transmission Security",
            requirement=(
                "Implement technical security measures to guard against unauthorized access "
                "to electronic protected health information that is being transmitted over an "
                "electronic communications network."
            ),
            category="Technical Safeguards",
            evidence_types=["tls_configuration", "network_security_policy"],
        ),
        Control(
            id="HIPAA.164.312(b)",
            framework="HIPAA_Security_Rule",
            title="Audit Controls",
            requirement=(
                "Implement hardware, software, and/or procedural mechanisms that record and "
                "examine activity in information systems that contain or use electronic protected "
                "health information."
            ),
            category="Technical Safeguards",
            evidence_types=["audit_logs", "log_retention_policy", "log_review_records"],
        ),
        Control(
            id="HIPAA.164.308(a)(5)(ii)(B)",
            framework="HIPAA_Security_Rule",
            title="Protection from Malicious Software",
            requirement=(
                "Implement procedures for guarding against, detecting, and reporting malicious software."
            ),
            category="Administrative Safeguards",
            evidence_types=["antivirus_configuration", "malware_scan_logs"],
        ),
        Control(
            id="HIPAA.164.308(a)(7)(ii)(A)",
            framework="HIPAA_Security_Rule",
            title="Data Backup Plan",
            requirement=(
                "Establish and implement procedures to create and maintain retrievable exact "
                "copies of electronic protected health information."
            ),
            category="Administrative Safeguards",
            evidence_types=["backup_configuration", "backup_test_records"],
        ),
        Control(
            id="HIPAA.164.308(a)(6)(ii)",
            framework="HIPAA_Security_Rule",
            title="Response and Reporting",
            requirement=(
                "Identify and respond to suspected or known security incidents; mitigate, to "
                "the extent practicable, harmful effects of security incidents that are known "
                "to the covered entity or business associate; and document security incidents "
                "and their outcomes."
            ),
            category="Administrative Safeguards",
            evidence_types=["incident_response_plan", "incident_logs", "breach_notification_procedures"],
        ),
        Control(
            id="HIPAA.164.310(a)(1)",
            framework="HIPAA_Security_Rule",
            title="Facility Access Controls",
            requirement=(
                "Implement policies and procedures to limit physical access to its electronic "
                "information systems and the facility or facilities in which they are housed, "
                "while ensuring that properly authorized access is allowed."
            ),
            category="Physical Safeguards",
            evidence_types=["physical_access_logs", "facility_access_policy"],
        ),
        Control(
            id="HIPAA.164.308(a)(3)(ii)(A)",
            framework="HIPAA_Security_Rule",
            title="Authorization and/or Supervision",
            requirement=(
                "Implement procedures for the authorization and/or supervision of workforce "
                "members who work with electronic protected health information or in locations "
                "where it might be accessed."
            ),
            category="Administrative Safeguards",
            evidence_types=["workforce_authorization_records", "access_review_documentation"],
        ),
        # Healthcare-specific controls (real-time medical AI translation)
        Control(
            id="HC.SC-2.1",
            framework="HIPAA_Security_Rule",
            title="Audio Ingestion - API Authentication & Access Control",
            requirement=(
                "Implement strong authentication (mTLS, API key rotation) for all audio ingestion endpoints. "
                "Enforce rate limiting and track all API calls with unique identifiers and timestamps."
            ),
            category="Technical Safeguards - Audio Ingestion",
            evidence_types=[
                "api_key_rotation_logs",
                "mfa_enforcement_policy",
                "api_authentication_audit_logs",
                "rate_limit_configuration",
            ],
        ),
        Control(
            id="HC.SC-7.1",
            framework="HIPAA_Security_Rule",
            title="Transmission Security - TLS Encryption for Audio Streams",
            requirement=(
                "Enforce TLS 1.2+ for all audio streams in transit. Implement certificate pinning on client SDKs. "
                "Validate and rotate TLS certificates every 90 days."
            ),
            category="Technical Safeguards - Transmission Security",
            evidence_types=[
                "tls_certificate_configuration",
                "certificate_rotation_logs",
                "ssl_lab_test_results",
                "network_traffic_encryption_proof",
            ],
        ),
        Control(
            id="HC.SC-4.1",
            framework="HIPAA_Security_Rule",
            title="Encryption at Rest - RDS, S3, and Key Management",
            requirement=(
                "All PHI storage (RDS metadata, S3 backups) must use AES-256 encryption at rest. "
                "Encryption keys must be managed via AWS KMS with annual rotation and access audit logging."
            ),
            category="Technical Safeguards - Encryption",
            evidence_types=[
                "rds_encryption_configuration",
                "s3_encryption_status",
                "kms_key_rotation_audit_logs",
                "encryption_key_policy_documentation",
            ],
        ),
        Control(
            id="HC.SC-12.1",
            framework="HIPAA_Security_Rule",
            title="Key Management - KMS Key Rotation & Access Control",
            requirement=(
                "Rotate encryption keys every 90 days. Archive old keys for 180 days before destruction. "
                "Log all key access and maintain segregation of duties (no single person can rotate and approve)."
            ),
            category="Technical Safeguards - Key Management",
            evidence_types=[
                "kms_key_rotation_schedule",
                "key_access_audit_logs",
                "key_destruction_certificates",
                "key_policy_segregation_of_duties",
            ],
        ),
        Control(
            id="HC.SC-7.2",
            framework="HIPAA_Security_Rule",
            title="Ephemeral Storage - Audio NOT Persisted to Pod Disks",
            requirement=(
                "Audio streams must be processed entirely in memory and not persisted to pod ephemeral volumes. "
                "Kubernetes configuration must enforce ephemeral-only volumes with TTL < 5 minutes."
            ),
            category="Technical Safeguards - Data Minimization",
            evidence_types=[
                "kubernetes_pod_configuration_audit",
                "ephemeral_volume_policy",
                "storage_class_definition",
                "pod_startup_script_review",
            ],
        ),
        Control(
            id="HC.AU-6.1",
            framework="HIPAA_Security_Rule",
            title="Access Logging - Model API Calls & Translation Requests",
            requirement=(
                "Log all calls to translation models, including requester IP, API key fingerprint, "
                "conversation ID, timestamp, and success/failure. Retain logs for 12 months."
            ),
            category="Technical Safeguards - Audit Controls",
            evidence_types=[
                "model_api_access_logs",
                "translation_request_audit_trail",
                "log_retention_policy_documentation",
                "log_integrity_verification_proof",
            ],
        ),
        Control(
            id="HC.SC-13.1",
            framework="HIPAA_Security_Rule",
            title="Secure Deletion - Audio TTL & Cryptographic Erasure",
            requirement=(
                "Audio files must be deleted 24 hours after ingestion or immediately upon processing failure. "
                "Use cryptographic key rotation (not file overwrite) for deletion. Log every deletion with timestamp."
            ),
            category="Technical Safeguards - Data Deletion",
            evidence_types=[
                "audio_deletion_audit_logs",
                "ttl_policy_configuration",
                "cryptographic_erasure_procedure",
                "deletion_verification_records",
            ],
        ),
        Control(
            id="HC.UI-1.1",
            framework="HIPAA_Security_Rule",
            title="De-identification - PII Removal Before Archival",
            requirement=(
                "Before archiving transcriptions or translations, remove all identifying information (patient name, MRN, DOB). "
                "Document the de-identification rules and maintain audit log of de-identification process."
            ),
            category="Administrative Safeguards - De-identification",
            evidence_types=[
                "de_identification_ruleset",
                "pii_removal_audit_logs",
                "regex_patterns_for_pii_detection",
                "de_identification_verification_proof",
            ],
        ),
        Control(
            id="HC.SC-2.2",
            framework="HIPAA_Security_Rule",
            title="IAM Least Privilege - Pod & Database Access Control",
            requirement=(
                "Kubernetes service accounts must have minimal IAM permissions. Database users must be role-based "
                "with least privilege enforcement. Review and audit quarterly."
            ),
            category="Technical Safeguards - Access Control",
            evidence_types=[
                "iam_role_policy_documentation",
                "kubernetes_rbac_configuration",
                "service_account_audit_log",
                "quarterly_access_review_records",
            ],
        ),
        Control(
            id="HC.SC-3.1",
            framework="HIPAA_Security_Rule",
            title="Input Validation - SQL Injection & XSS Prevention",
            requirement=(
                "Implement input validation and output encoding to prevent SQL injection and cross-site scripting attacks. "
                "Use parameterized queries and HTML/URL encoding for all user inputs."
            ),
            category="Technical Safeguards - Input Validation",
            evidence_types=[
                "input_validation_policy",
                "parameterized_query_examples",
                "security_testing_results",
                "code_review_records",
            ],
        ),
        Control(
            id="HC.SC-12.2",
            framework="HIPAA_Security_Rule",
            title="Secret Management - API Key & Database Password Rotation",
            requirement=(
                "All API keys, database passwords, and secrets must be stored in AWS Secrets Manager. "
                "Rotate every 30 days. Audit all secret access."
            ),
            category="Technical Safeguards - Secret Management",
            evidence_types=[
                "secrets_manager_configuration",
                "password_rotation_schedule",
                "secret_access_audit_logs",
                "secret_policy_documentation",
            ],
        ),
        Control(
            id="HC.AU-2.1",
            framework="HIPAA_Security_Rule",
            title="Incident & Breach Response - Security Event Logging & Procedures",
            requirement=(
                "Maintain incident response playbook. Log all security events to SIEM. "
                "Conduct breach response drill annually. Document all incidents with root cause analysis."
            ),
            category="Administrative Safeguards - Incident Response",
            evidence_types=[
                "incident_response_plan",
                "security_event_log",
                "breach_notification_procedure",
                "incident_drill_results",
                "root_cause_analysis_documentation",
            ],
        ),
        Control(
            id="HC.SC-7.3",
            framework="HIPAA_Security_Rule",
            title="Network Segmentation & WAF - VPC Security Groups & Egress Controls",
            requirement=(
                "Implement VPC with public/private subnets. Security groups enforce least privilege. "
                "WAF blocks OWASP top 10. All outbound traffic logged via NAT gateway."
            ),
            category="Technical Safeguards - Network Security",
            evidence_types=[
                "vpc_configuration_diagram",
                "security_group_rules_audit",
                "waf_rule_configuration",
                "vpc_flow_logs",
                "nat_gateway_traffic_logs",
            ],
        ),
    ]

    # Add controls to database
    for control in controls:
        db.add(control)

    db.commit()
    print(f"✓ Successfully seeded {len(controls)} controls (10 HIPAA + 11 healthcare-specific).")

    # First, create an organization and metadata profile for the sample assessment
    org = Organization(
        id="org-example-audit",
        name="Example Healthcare Organization",
    )
    db.add(org)
    db.flush()

    # Create a metadata profile (required for assessment)
    profile = MetadataProfile(
        id="profile-example",
        organization_id=org.id,
        phi_types=["audio_recordings", "patient_context", "translations"],
        cloud_provider="AWS",
        infrastructure={
            "platform": "Kubernetes on EKS",
            "database": "RDS PostgreSQL",
            "transcription": "AWS Transcribe or Whisper",
            "llm": "Self-hosted or AWS Bedrock",
        },
        applications={"primary": "Medical Translation AI"},
        access_controls={"auth": "mTLS + API Keys", "rbac": "Kubernetes role-based"},
        software_stack={
            "backend": "FastAPI 0.135.1",
            "database": "SQLAlchemy 2.0.48",
            "security": "python-jose 3.5.0",
            "deployment": "Docker + K8s",
        },
    )
    db.add(profile)
    db.flush()

    # Create sample assessment for "Example Organization - Q1 2026"
    assessment = Assessment(
        id="org-sample-q1-2026",
        organization_id=org.id,
        metadata_profile_id=profile.id,
        status="in_progress",
    )
    db.add(assessment)
    db.commit()
    print(f"✓ Created sample assessment: {assessment.id}")

    # Create sample findings (vulnerabilities from analysis)
    sample_findings = [
        Finding(
            assessment_id=assessment.id,
            control_id="HC.SC-2.1",
            severity="high",
            cvss_score=7.5,
            title="API Key Rotation Not Enforced",
            description="API keys have no automatic rotation policy. Manual rotation occurs irregularly.",
            remediation_guidance="Implement AWS Secrets Manager with 30-day rotation policy",
            cwe_ids=["CWE-798"],
            priority_window="immediate",
        ),
        Finding(
            assessment_id=assessment.id,
            control_id="HC.SC-7.1",
            severity="medium",
            cvss_score=5.0,
            title="TLS Certificate Expiration Not Monitored",
            description="No automated monitoring for TLS certificate expiration dates.",
            remediation_guidance="Enable AWS Certificate Manager automatic renewal; add CloudWatch alarm for cert expiration",
            cwe_ids=["CWE-295"],
            priority_window="30_days",
        ),
        Finding(
            assessment_id=assessment.id,
            control_id="HC.SC-4.1",
            severity="high",
            cvss_score=8.2,
            title="S3 Backups Not Encrypted",
            description="Database backups to S3 are unencrypted. KMS encryption not enabled.",
            remediation_guidance="Enable S3 default encryption with AWS KMS customer-managed keys",
            cwe_ids=["CWE-311"],
            priority_window="immediate",
        ),
        Finding(
            assessment_id=assessment.id,
            control_id="HC.SC-12.1",
            severity="high",
            cvss_score=6.8,
            title="KMS Key Rotation Manual, Not Automatic",
            description="Key rotation handled manually. No audit trail of approvals.",
            remediation_guidance="Configure automatic annual rotation in KMS console; document segregation of duties",
            cwe_ids=["CWE-347"],
            priority_window="30_days",
        ),
        Finding(
            assessment_id=assessment.id,
            control_id="HC.SC-7.2",
            severity="medium",
            cvss_score=4.5,
            title="Ephemeral Storage TTL Unclear",
            description="Pod configuration doesn't explicitly enforce TTL < 5 minutes. Review needed.",
            remediation_guidance="Document ephemeral storage TTL in pod spec; add storage class enforcement",
            cwe_ids=["CWE-200"],
            priority_window="quarterly",
        ),
        Finding(
            assessment_id=assessment.id,
            control_id="HC.AU-6.1",
            severity="high",
            cvss_score=7.0,
            title="Model API Call Logging Incomplete",
            description="Successful requests logged, but failed requests and denials not captured.",
            remediation_guidance="Implement request/response interceptor logging; log all API calls regardless of status",
            cwe_ids=["CWE-778"],
            priority_window="30_days",
        ),
    ]

    for finding in sample_findings:
        db.add(finding)
    db.commit()
    print(f"✓ Created {len(sample_findings)} sample findings for assessment")

    # Create sample evidence records (what auditor would collect)
    sample_evidence = [
        Evidence(
            assessment_id=assessment.id,
            control_id="HC.SC-2.1",
            evidence_type="api_key_rotation_logs",
            title="API Key Rotation Logs",
            description="CloudTrail logs showing API key lifecycle events",
            status="not_started",
            owner="security-team",
            due_date=datetime.now() + timedelta(days=14),
            notes="Need CloudTrail logs showing API key creation/rotation events from last 90 days",
        ),
        Evidence(
            assessment_id=assessment.id,
            control_id="HC.SC-2.1",
            evidence_type="mfa_enforcement_policy",
            title="MFA Enforcement Policy",
            description="Written policy requiring MFA for all user accounts",
            status="in_progress",
            owner="security-team",
            due_date=datetime.now() + timedelta(days=7),
            artifact_path="docs/mfa-policy.md",
            notes="Draft policy created, awaiting CISO sign-off",
        ),
        Evidence(
            assessment_id=assessment.id,
            control_id="HC.SC-7.1",
            evidence_type="tls_certificate_configuration",
            title="TLS Certificate Configuration",
            description="Infrastructure configuration demonstrating TLS 1.2+ enforcement",
            status="completed",
            owner="devops-team",
            due_date=datetime.now() - timedelta(days=5),
            artifact_path="terraform/tls-config.tf",
            artifact_url="https://github.com/org-infra/artifact/blob/main/terraform/tls-config.tf",
            notes="TLS 1.2+ enforced on all ALB listeners. Certificate pinning in client SDK.",
        ),
        Evidence(
            assessment_id=assessment.id,
            control_id="HC.SC-4.1",
            evidence_type="rds_encryption_configuration",
            title="RDS Encryption Configuration",
            description="AWS RDS encryption-at-rest settings",
            status="not_started",
            owner="devops-team",
            due_date=datetime.now() + timedelta(days=21),
            notes="Need to verify RDS encryption status and get screenshot from AWS console",
        ),
        Evidence(
            assessment_id=assessment.id,
            control_id="HC.SC-4.1",
            evidence_type="kms_key_rotation_audit_logs",
            title="KMS Key Rotation Audit Logs",
            description="AWS KMS key management audit trail",
            status="not_started",
            owner="security-team",
            due_date=datetime.now() + timedelta(days=30),
            notes="CloudTrail logs for KMS key operations (create, rotate, schedule deletion)",
        ),
        Evidence(
            assessment_id=assessment.id,
            control_id="HC.SC-12.1",
            evidence_type="kms_key_rotation_schedule",
            title="KMS Key Rotation Schedule",
            description="Configuration demonstrating automatic key rotation",
            status="in_progress",
            owner="devops-team",
            due_date=datetime.now() + timedelta(days=10),
            notes="Configuration review in progress. Automatic rotation to be enabled next sprint.",
        ),
        Evidence(
            assessment_id=assessment.id,
            control_id="HC.SC-7.2",
            evidence_type="kubernetes_pod_configuration_audit",
            title="Kubernetes Pod Configuration Audit",
            description="K8s pod manifests showing ephemeral storage configuration",
            status="not_started",
            owner="devops-team",
            due_date=datetime.now() + timedelta(days=7),
            artifact_path="k8s/pods/audio-processor.yaml",
            notes="Need to verify no persistent volumes in audio processing pods",
        ),
        Evidence(
            assessment_id=assessment.id,
            control_id="HC.AU-6.1",
            evidence_type="model_api_access_logs",
            title="Model API Access Logs",
            description="Application logs showing API access patterns to translation models",
            status="in_progress",
            owner="platform-team",
            due_date=datetime.now() + timedelta(days=14),
            notes="API logs being aggregated to CloudWatch; query templates being documented",
        ),
        Evidence(
            assessment_id=assessment.id,
            control_id="HC.SC-13.1",
            evidence_type="audio_deletion_audit_logs",
            title="Audio Deletion Audit Logs",
            description="Logs demonstrating automatic audio deletion after processing",
            status="not_started",
            owner="platform-team",
            due_date=datetime.now() + timedelta(days=21),
            notes="Need logs from past 90 days showing successful audio deletion with timestamps",
        ),
        Evidence(
            assessment_id=assessment.id,
            control_id="HC.UI-1.1",
            evidence_type="de_identification_ruleset",
            title="De-identification Ruleset",
            description="PII detection and de-identification rules for medical translation output",
            status="not_started",
            owner="data-eng-team",
            due_date=datetime.now() + timedelta(days=30),
            notes="Design de-identification rules for PII patterns (names, MRNs, DOB, SSN, phone)",
        ),
    ]

    for evidence in sample_evidence:
        db.add(evidence)
    db.commit()
    print(f"✓ Created {len(sample_evidence)} sample evidence records")

    db.close()
    print(
        "\n✅ Seed complete! Assessment 'org-sample-q1-2026' ready for testing."
        "\nAccess the evidence checklist at /api/v1/assessments/org-sample-q1-2026/evidence-checklist"
    )


if __name__ == "__main__":
    seed_controls()
