"""Seed database with compliance frameworks, controls, and healthcare-specific evidence requirements."""

from datetime import datetime, timedelta

from sqlalchemy import inspect, text
from sqlalchemy.orm import Session

from src.database import Base, SessionLocal, engine
from src.models import (
    Assessment,
    Control,
    Evidence,
    Finding,
    Framework,
    FrameworkRequirement,
    MetadataProfile,
    Organization,
)


def _migrate_control_columns() -> None:
    """Add new nullable columns to controls table if they don't exist (SQLite compat)."""
    inspector = inspect(engine)
    if "controls" not in inspector.get_table_names():
        return
    existing = {col["name"] for col in inspector.get_columns("controls")}
    with engine.begin() as conn:
        if "canonical_concept" not in existing:
            conn.execute(text("ALTER TABLE controls ADD COLUMN canonical_concept TEXT"))
        if "source" not in existing:
            conn.execute(
                text("ALTER TABLE controls ADD COLUMN source TEXT DEFAULT 'seed'")
            )
        if "source_id" not in existing:
            conn.execute(text("ALTER TABLE controls ADD COLUMN source_id TEXT"))


def _seed_frameworks(db: Session) -> None:  # noqa: C901
    """Seed regulatory frameworks and cross-framework requirement mappings."""
    frameworks = [
        Framework(
            code="HIPAA",
            name="HIPAA Security Rule",
            version="2013",
            jurisdiction="US",
            source_url="https://www.hhs.gov/hipaa/for-professionals/security/index.html",
        ),
        Framework(
            code="NIST_800_53",
            name="NIST 800-53",
            version="Rev 5",
            jurisdiction="US",
            source_url="https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
        ),
        Framework(
            code="GDPR",
            name="General Data Protection Regulation",
            version="2016/679",
            jurisdiction="EU",
            source_url="https://gdpr-info.eu/",
        ),
        Framework(
            code="SOX",
            name="Sarbanes-Oxley Act",
            version="2002",
            jurisdiction="US",
            source_url="https://www.congress.gov/bill/107th-congress/house-bill/3763",
        ),
        Framework(
            code="FedRAMP",
            name="FedRAMP",
            version="Rev 5",
            jurisdiction="US",
            source_url="https://www.fedramp.gov/",
        ),
        Framework(
            code="APRA_CPS_234",
            name="APRA CPS 234",
            version="2019",
            jurisdiction="AU",
            source_url="https://www.apra.gov.au/sites/default/files/cps_234_july_2019_for_public_release.pdf",
        ),
        Framework(
            code="CCPA",
            name="California Consumer Privacy Act",
            version="2020",
            jurisdiction="US-CA",
            source_url="https://oag.ca.gov/privacy/ccpa",
        ),
    ]

    for fw in frameworks:
        db.add(fw)
    db.flush()
    print(f"Seeded {len(frameworks)} regulatory frameworks.")

    # Build lookup for framework IDs
    fw_by_code: dict[str, str] = {str(fw.code): str(fw.id) for fw in frameworks}

    # Cross-framework requirement mappings
    # Each tuple: (control_id, framework_code, citation, citation_title, baseline)
    mappings = [
        # --- Risk Analysis ---
        (
            "HIPAA.164.308(a)(1)(ii)(A)",
            "HIPAA",
            "164.308(a)(1)(ii)(A)",
            "Risk Analysis",
            None,
        ),
        ("HIPAA.164.308(a)(1)(ii)(A)", "NIST_800_53", "RA-3", "Risk Assessment", None),
        ("HIPAA.164.308(a)(1)(ii)(A)", "FedRAMP", "RA-3", "Risk Assessment", "Low"),
        (
            "HIPAA.164.308(a)(1)(ii)(A)",
            "GDPR",
            "Art. 35",
            "Data Protection Impact Assessment",
            None,
        ),
        (
            "HIPAA.164.308(a)(1)(ii)(A)",
            "APRA_CPS_234",
            "Section 15",
            "Information Security Risk Assessment",
            None,
        ),
        # --- Access Control ---
        ("HIPAA.164.312(a)(1)", "HIPAA", "164.312(a)(1)", "Access Control", None),
        ("HIPAA.164.312(a)(1)", "NIST_800_53", "AC-2", "Account Management", None),
        ("HIPAA.164.312(a)(1)", "FedRAMP", "AC-2", "Account Management", "Low"),
        (
            "HIPAA.164.312(a)(1)",
            "GDPR",
            "Art. 32(1)(b)",
            "Access Controls for Processing Systems",
            None,
        ),
        ("HIPAA.164.312(a)(1)", "SOX", "ITGC-1", "Logical Access Controls", None),
        (
            "HIPAA.164.312(a)(1)",
            "APRA_CPS_234",
            "Section 25",
            "Access Management",
            None,
        ),
        # --- Encryption at Rest ---
        (
            "HIPAA.164.312(a)(2)(iv)",
            "HIPAA",
            "164.312(a)(2)(iv)",
            "Encryption and Decryption",
            None,
        ),
        (
            "HIPAA.164.312(a)(2)(iv)",
            "NIST_800_53",
            "SC-28",
            "Protection of Information at Rest",
            None,
        ),
        (
            "HIPAA.164.312(a)(2)(iv)",
            "FedRAMP",
            "SC-28",
            "Protection of Information at Rest",
            "Moderate",
        ),
        (
            "HIPAA.164.312(a)(2)(iv)",
            "GDPR",
            "Art. 32(1)(a)",
            "Encryption of Personal Data",
            None,
        ),
        ("HIPAA.164.312(a)(2)(iv)", "SOX", "ITGC-4", "Data Protection Controls", None),
        (
            "HIPAA.164.312(a)(2)(iv)",
            "APRA_CPS_234",
            "Section 23",
            "Cryptographic Controls",
            None,
        ),
        # --- Transmission Security ---
        (
            "HIPAA.164.312(e)(1)",
            "HIPAA",
            "164.312(e)(1)",
            "Transmission Security",
            None,
        ),
        (
            "HIPAA.164.312(e)(1)",
            "NIST_800_53",
            "SC-8",
            "Transmission Confidentiality and Integrity",
            None,
        ),
        (
            "HIPAA.164.312(e)(1)",
            "FedRAMP",
            "SC-8",
            "Transmission Confidentiality and Integrity",
            "Moderate",
        ),
        ("HIPAA.164.312(e)(1)", "GDPR", "Art. 32(1)(a)", "Encryption in Transit", None),
        (
            "HIPAA.164.312(e)(1)",
            "APRA_CPS_234",
            "Section 23",
            "Cryptographic Techniques - Transit",
            None,
        ),
        # --- Audit Controls ---
        ("HIPAA.164.312(b)", "HIPAA", "164.312(b)", "Audit Controls", None),
        ("HIPAA.164.312(b)", "NIST_800_53", "AU-2", "Event Logging", None),
        ("HIPAA.164.312(b)", "FedRAMP", "AU-2", "Event Logging", "Low"),
        (
            "HIPAA.164.312(b)",
            "GDPR",
            "Art. 30",
            "Records of Processing Activities",
            None,
        ),
        ("HIPAA.164.312(b)", "SOX", "ITGC-3", "IT Operations and Monitoring", None),
        ("HIPAA.164.312(b)", "APRA_CPS_234", "Section 33", "Testing of Controls", None),
        # --- Malware Protection ---
        (
            "HIPAA.164.308(a)(5)(ii)(B)",
            "HIPAA",
            "164.308(a)(5)(ii)(B)",
            "Protection from Malicious Software",
            None,
        ),
        (
            "HIPAA.164.308(a)(5)(ii)(B)",
            "NIST_800_53",
            "SI-3",
            "Malicious Code Protection",
            None,
        ),
        (
            "HIPAA.164.308(a)(5)(ii)(B)",
            "FedRAMP",
            "SI-3",
            "Malicious Code Protection",
            "Low",
        ),
        # --- Data Backup ---
        (
            "HIPAA.164.308(a)(7)(ii)(A)",
            "HIPAA",
            "164.308(a)(7)(ii)(A)",
            "Data Backup Plan",
            None,
        ),
        ("HIPAA.164.308(a)(7)(ii)(A)", "NIST_800_53", "CP-9", "System Backup", None),
        ("HIPAA.164.308(a)(7)(ii)(A)", "FedRAMP", "CP-9", "System Backup", "Low"),
        ("HIPAA.164.308(a)(7)(ii)(A)", "SOX", "ITGC-5", "Backup and Recovery", None),
        # --- Incident Response ---
        (
            "HIPAA.164.308(a)(6)(ii)",
            "HIPAA",
            "164.308(a)(6)(ii)",
            "Response and Reporting",
            None,
        ),
        ("HIPAA.164.308(a)(6)(ii)", "NIST_800_53", "IR-6", "Incident Reporting", None),
        ("HIPAA.164.308(a)(6)(ii)", "FedRAMP", "IR-6", "Incident Reporting", "Low"),
        (
            "HIPAA.164.308(a)(6)(ii)",
            "GDPR",
            "Art. 33",
            "Notification to Supervisory Authority",
            None,
        ),
        (
            "HIPAA.164.308(a)(6)(ii)",
            "APRA_CPS_234",
            "Section 35",
            "Notification of Security Incidents",
            None,
        ),
        # --- Physical Access ---
        (
            "HIPAA.164.310(a)(1)",
            "HIPAA",
            "164.310(a)(1)",
            "Facility Access Controls",
            None,
        ),
        (
            "HIPAA.164.310(a)(1)",
            "NIST_800_53",
            "PE-2",
            "Physical Access Authorizations",
            None,
        ),
        (
            "HIPAA.164.310(a)(1)",
            "FedRAMP",
            "PE-2",
            "Physical Access Authorizations",
            "Low",
        ),
        # --- Workforce Authorization ---
        (
            "HIPAA.164.308(a)(3)(ii)(A)",
            "HIPAA",
            "164.308(a)(3)(ii)(A)",
            "Authorization and Supervision",
            None,
        ),
        (
            "HIPAA.164.308(a)(3)(ii)(A)",
            "NIST_800_53",
            "PS-2",
            "Position Risk Designation",
            None,
        ),
        (
            "HIPAA.164.308(a)(3)(ii)(A)",
            "GDPR",
            "Art. 32(4)",
            "Authorized Personnel Controls",
            None,
        ),
        # --- Healthcare: API Auth ---
        ("HC.SC-2.1", "HIPAA", "164.312(d)", "Person or Entity Authentication", None),
        ("HC.SC-2.1", "NIST_800_53", "IA-2", "Identification and Authentication", None),
        ("HC.SC-2.1", "FedRAMP", "IA-2", "Identification and Authentication", "Low"),
        # --- Healthcare: TLS ---
        ("HC.SC-7.1", "HIPAA", "164.312(e)(1)", "Transmission Security", None),
        ("HC.SC-7.1", "NIST_800_53", "SC-8", "Transmission Confidentiality", None),
        ("HC.SC-7.1", "FedRAMP", "SC-8", "Transmission Confidentiality", "Moderate"),
        # --- Healthcare: Encryption at Rest ---
        ("HC.SC-4.1", "HIPAA", "164.312(a)(2)(iv)", "Encryption at Rest", None),
        (
            "HC.SC-4.1",
            "NIST_800_53",
            "SC-28",
            "Protection of Information at Rest",
            None,
        ),
        (
            "HC.SC-4.1",
            "GDPR",
            "Art. 32(1)(a)",
            "Encryption of Personal Data at Rest",
            None,
        ),
        # --- Healthcare: Key Management ---
        ("HC.SC-12.1", "HIPAA", "164.312(a)(2)(iv)", "Encryption Key Management", None),
        ("HC.SC-12.1", "NIST_800_53", "SC-12", "Cryptographic Key Management", None),
        # --- Healthcare: Ephemeral Storage ---
        ("HC.SC-7.2", "HIPAA", "164.312(a)(1)", "Data Minimization", None),
        (
            "HC.SC-7.2",
            "NIST_800_53",
            "SC-28(1)",
            "Cryptographic Protection - Ephemeral",
            None,
        ),
        ("HC.SC-7.2", "GDPR", "Art. 5(1)(e)", "Storage Limitation Principle", None),
        # --- Healthcare: Access Logging ---
        ("HC.AU-6.1", "HIPAA", "164.312(b)", "Audit Controls", None),
        ("HC.AU-6.1", "NIST_800_53", "AU-6", "Audit Record Review", None),
        ("HC.AU-6.1", "FedRAMP", "AU-6", "Audit Record Review", "Low"),
        ("HC.AU-6.1", "SOX", "ITGC-3", "IT Operations Monitoring", None),
        # --- Healthcare: Secure Deletion ---
        ("HC.SC-13.1", "HIPAA", "164.310(d)(2)(i)", "Disposal of ePHI", None),
        ("HC.SC-13.1", "NIST_800_53", "MP-6", "Media Sanitization", None),
        ("HC.SC-13.1", "GDPR", "Art. 17", "Right to Erasure", None),
        # --- Healthcare: De-identification ---
        ("HC.UI-1.1", "HIPAA", "164.514(a)", "De-identification Standard", None),
        (
            "HC.UI-1.1",
            "GDPR",
            "Art. 11",
            "Processing Not Requiring Identification",
            None,
        ),
        # --- Healthcare: IAM Least Privilege ---
        (
            "HC.SC-2.2",
            "HIPAA",
            "164.312(a)(1)",
            "Access Control - Least Privilege",
            None,
        ),
        ("HC.SC-2.2", "NIST_800_53", "AC-6", "Least Privilege", None),
        ("HC.SC-2.2", "FedRAMP", "AC-6", "Least Privilege", "Low"),
        (
            "HC.SC-2.2",
            "APRA_CPS_234",
            "Section 25",
            "Access Management - Least Privilege",
            None,
        ),
        # --- Healthcare: Input Validation ---
        (
            "HC.SC-3.1",
            "HIPAA",
            "164.312(a)(1)",
            "Access Control - Input Validation",
            None,
        ),
        ("HC.SC-3.1", "NIST_800_53", "SI-10", "Information Input Validation", None),
        ("HC.SC-3.1", "FedRAMP", "SI-10", "Information Input Validation", "Moderate"),
        # --- Healthcare: Secret Management ---
        (
            "HC.SC-12.2",
            "HIPAA",
            "164.312(a)(2)(iv)",
            "Encryption - Secret Management",
            None,
        ),
        ("HC.SC-12.2", "NIST_800_53", "SC-12", "Cryptographic Key Establishment", None),
        # --- Healthcare: Incident Response ---
        ("HC.AU-2.1", "HIPAA", "164.308(a)(6)(ii)", "Security Incident Response", None),
        ("HC.AU-2.1", "NIST_800_53", "IR-4", "Incident Handling", None),
        ("HC.AU-2.1", "FedRAMP", "IR-4", "Incident Handling", "Low"),
        ("HC.AU-2.1", "GDPR", "Art. 33", "Breach Notification - 72 Hours", None),
        (
            "HC.AU-2.1",
            "APRA_CPS_234",
            "Section 35",
            "Notification of Security Incidents",
            None,
        ),
        # --- Healthcare: Network Segmentation ---
        ("HC.SC-7.3", "HIPAA", "164.312(e)(1)", "Network Security", None),
        ("HC.SC-7.3", "NIST_800_53", "SC-7", "Boundary Protection", None),
        ("HC.SC-7.3", "FedRAMP", "SC-7", "Boundary Protection", "Low"),
        ("HC.SC-7.3", "APRA_CPS_234", "Section 23", "Network Security Controls", None),
    ]

    for control_id, fw_code, citation, citation_title, baseline in mappings:
        fw_id = fw_by_code.get(fw_code)
        if not fw_id:
            continue
        db.add(
            FrameworkRequirement(
                control_id=control_id,
                framework_id=fw_id,
                citation=citation,
                citation_title=citation_title,
                baseline=baseline,
            )
        )

    db.flush()
    print(f"Seeded {len(mappings)} cross-framework requirement mappings.")


def _migrate_evidence_org_column() -> None:
    """Add organization_id column to evidence table and backfill from assessments."""
    inspector = inspect(engine)
    if "evidence" not in inspector.get_table_names():
        return
    existing = {col["name"] for col in inspector.get_columns("evidence")}
    if "organization_id" in existing:
        return
    with engine.begin() as conn:
        conn.execute(
            text(
                "ALTER TABLE evidence ADD COLUMN organization_id TEXT "
                "REFERENCES organizations(id)"
            )
        )
        # Backfill from linked assessments
        conn.execute(
            text(
                "UPDATE evidence SET organization_id = "
                "(SELECT a.organization_id FROM assessments a "
                "WHERE a.id = evidence.assessment_id) "
                "WHERE assessment_id IS NOT NULL"
            )
        )
        # Delete orphaned evidence with no org — these are the tenant leak vectors
        result = conn.execute(
            text("DELETE FROM evidence WHERE organization_id IS NULL")
        )
        deleted = result.rowcount
        if deleted:
            print(f"  Deleted {deleted} orphaned evidence records (no organization).")
    print("Migrated evidence table: added organization_id column and backfilled data.")


def seed_controls() -> None:
    """Seed database with frameworks, controls, and sample evidence."""
    # Create all tables
    Base.metadata.create_all(bind=engine)
    _migrate_control_columns()
    _migrate_evidence_org_column()

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
            evidence_types=[
                "encryption_at_rest_configuration",
                "encryption_key_management",
            ],
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
            evidence_types=[
                "incident_response_plan",
                "incident_logs",
                "breach_notification_procedures",
            ],
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
            evidence_types=[
                "workforce_authorization_records",
                "access_review_documentation",
            ],
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
    print(
        f"Successfully seeded {len(controls)} controls (10 HIPAA + 11 healthcare-specific)."
    )

    # Seed regulatory frameworks and cross-framework mappings
    _seed_frameworks(db)
    db.commit()

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
    print(f"Created sample assessment: {assessment.id}")

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
    print(f"Created {len(sample_findings)} sample findings for assessment")

    # Create sample evidence records (what auditor would collect)
    sample_evidence = [
        Evidence(
            organization_id=org.id,
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
            organization_id=org.id,
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
            organization_id=org.id,
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
            organization_id=org.id,
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
            organization_id=org.id,
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
            organization_id=org.id,
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
            organization_id=org.id,
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
            organization_id=org.id,
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
            organization_id=org.id,
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
            organization_id=org.id,
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
    print(f"Created {len(sample_evidence)} sample evidence records")

    db.close()
    print(
        "\nSeed complete! Assessment 'org-sample-q1-2026' ready for testing."
        "\nAccess the action plan at /api/v1/assessments/org-sample-q1-2026/action-plan"
    )


if __name__ == "__main__":
    seed_controls()
