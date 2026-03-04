"""Seed database with initial HIPAA controls."""
from src.database import Base, SessionLocal, engine
from src.models import Control


def seed_controls():
    """Seed database with starter set of HIPAA controls."""
    # Create all tables
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()

    # Check if controls already exist
    existing = db.query(Control).count()
    if existing > 0:
        print(f"Database already contains {existing} controls. Skipping seed.")
        db.close()
        return

    # Starter set of 10 HIPAA Security Rule controls
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
    ]

    # Add controls to database
    for control in controls:
        db.add(control)

    db.commit()
    print(f"Successfully seeded {len(controls)} HIPAA controls.")
    db.close()


if __name__ == "__main__":
    seed_controls()
