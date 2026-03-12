"""Rules engine for mapping metadata to HIPAA controls and generating findings."""

import logging
from typing import Any

from sqlalchemy.orm import Session

from src.models import Assessment, Control, Finding, MetadataProfile
from src.nvd_service import NVDApiError, NVDService

logger = logging.getLogger(__name__)


class RulesEngine:
    """Maps metadata profiles to applicable controls and generates findings."""

    def __init__(self, db: Session, nvd_api_key: str | None = None):
        """Initialize the rules engine.

        Args:
            db: Database session
            nvd_api_key: Optional NVD API key for higher rate limits
        """
        self.db = db
        # Use max_retries=1 during assessment creation to avoid blocking.
        # The dedicated analyze-nvd endpoint uses full retries.
        self.nvd_service = NVDService(api_key=nvd_api_key, max_retries=1)

    def run_assessment(self, assessment_id: str) -> list[Finding]:
        """
        Run compliance assessment by applying rules to metadata profile.

        Returns list of findings (gaps and risks).
        """
        # Load assessment and metadata
        assessment = (
            self.db.query(Assessment).filter(Assessment.id == assessment_id).first()
        )
        if not assessment:
            raise ValueError(f"Assessment {assessment_id} not found")

        metadata = (
            self.db.query(MetadataProfile)
            .filter(MetadataProfile.id == assessment.metadata_profile_id)
            .first()
        )
        if not metadata:
            raise ValueError(
                f"Metadata profile {assessment.metadata_profile_id} not found"
            )

        # Get all controls
        controls = self.db.query(Control).all()

        # Apply rules and generate findings
        findings: list[Finding] = []
        for control in controls:
            finding = self._evaluate_control(assessment, metadata, control)
            if finding:
                findings.append(finding)

        # Check software stack for vulnerabilities (if provided)
        if metadata.software_stack:
            software_findings = self._check_software_vulnerabilities(
                assessment, metadata
            )
            findings.extend(software_findings)

        return findings

    def _evaluate_control(
        self,
        assessment: Assessment,
        metadata: MetadataProfile,
        control: Control,
    ) -> Finding | None:
        """
        Evaluate a single control against metadata profile.

        Returns a Finding if there's a gap, None if compliant.
        """
        # Rule 1: Access Control - Check if MFA is enabled
        if (
            control.id == "HIPAA.164.312(a)(1)"
            and control.framework == "HIPAA_Security_Rule"
        ):
            return self._check_access_control(assessment, metadata, control)

        # Rule 2: Encryption at Rest - Check if encryption is enabled
        if (
            control.id == "HIPAA.164.312(a)(2)(iv)"
            and control.framework == "HIPAA_Security_Rule"
        ):
            return self._check_encryption_at_rest(assessment, metadata, control)

        # Rule 3: Encryption in Transit - Check TLS/SSL
        if (
            control.id == "HIPAA.164.312(e)(1)"
            and control.framework == "HIPAA_Security_Rule"
        ):
            return self._check_encryption_in_transit(assessment, metadata, control)

        # Rule 4: Audit Controls - Check logging is enabled
        if (
            control.id == "HIPAA.164.312(b)"
            and control.framework == "HIPAA_Security_Rule"
        ):
            return self._check_audit_controls(assessment, metadata, control)

        # Rule 5: Risk Analysis - Always required
        if (
            control.id == "HIPAA.164.308(a)(1)(ii)(A)"
            and control.framework == "HIPAA_Security_Rule"
        ):
            return self._check_risk_analysis(assessment, metadata, control)

        # No finding = compliant or not applicable
        return None

    def _check_access_control(
        self, assessment: Assessment, metadata: MetadataProfile, control: Control
    ) -> Finding | None:
        """Check if access controls (MFA) are properly configured."""
        access_controls: dict[str, Any] = metadata.access_controls or {}
        mfa_enabled = access_controls.get("mfa_enabled", False)

        if not mfa_enabled:
            return Finding(
                assessment_id=assessment.id,
                control_id=control.id,
                title="Multi-Factor Authentication (MFA) Not Enabled",
                description=(
                    "MFA is not enabled for user authentication. HIPAA requires "
                    "unique user identification and authentication mechanisms to "
                    "verify user identity before granting access to PHI."
                ),
                severity="high",
                cvss_score=7.5,  # Mock score
                cve_ids=[],
                cwe_ids=["CWE-308"],  # Missing Authentication for Critical Function
                remediation_guidance=(
                    "Enable MFA for all users with access to PHI. Implement MFA "
                    "using authenticator apps, SMS codes, or hardware tokens."
                ),
                priority_window="immediate",
                owner="Security",
            )
        return None

    def _check_encryption_at_rest(
        self, assessment: Assessment, metadata: MetadataProfile, control: Control
    ) -> Finding | None:
        """Check if data at rest encryption is enabled."""
        infrastructure: dict[str, Any] = metadata.infrastructure or {}
        encryption_at_rest = infrastructure.get("encryption_at_rest", False)

        if not encryption_at_rest:
            return Finding(
                assessment_id=assessment.id,
                control_id=control.id,
                title="Encryption at Rest Not Enabled",
                description=(
                    "Data at rest encryption is not enabled for databases or storage "
                    "containing PHI. HIPAA requires encryption of PHI stored electronically."
                ),
                severity="high",
                cvss_score=8.2,
                cve_ids=[],
                cwe_ids=["CWE-311"],  # Missing Encryption of Sensitive Data
                remediation_guidance=(
                    "Enable encryption at rest for all databases and storage systems "
                    "containing PHI. Use AES-256 encryption or equivalent."
                ),
                priority_window="immediate",
                owner="DevOps",
            )
        return None

    def _check_encryption_in_transit(
        self, assessment: Assessment, metadata: MetadataProfile, control: Control
    ) -> Finding | None:
        """Check if data in transit encryption (TLS) is enabled."""
        infrastructure: dict[str, Any] = metadata.infrastructure or {}
        tls_enabled = infrastructure.get("tls_enabled", False)

        if not tls_enabled:
            return Finding(
                assessment_id=assessment.id,
                control_id=control.id,
                title="TLS/SSL Encryption Not Enabled",
                description=(
                    "TLS/SSL encryption is not enabled for data in transit. HIPAA "
                    "requires encryption of PHI transmitted over networks."
                ),
                severity="high",
                cvss_score=7.4,
                cve_ids=[],
                cwe_ids=["CWE-319"],  # Cleartext Transmission of Sensitive Information
                remediation_guidance=(
                    "Enable TLS 1.2 or higher for all API endpoints and data "
                    "transmission channels. Disable older SSL/TLS versions."
                ),
                priority_window="immediate",
                owner="Engineering",
            )
        return None

    def _check_audit_controls(
        self, assessment: Assessment, metadata: MetadataProfile, control: Control
    ) -> Finding | None:
        """Check if audit logging is properly configured."""
        infrastructure: dict[str, Any] = metadata.infrastructure or {}
        logging_enabled = infrastructure.get("logging_enabled", False)
        log_retention_days = infrastructure.get("log_retention_days", 0)

        if (
            not logging_enabled or log_retention_days < 180
        ):  # HIPAA recommends 6+ years, but 180 days minimum
            return Finding(
                assessment_id=assessment.id,
                control_id=control.id,
                title="Audit Logging Insufficient",
                description=(
                    f"Audit logging is {'not enabled' if not logging_enabled else 'enabled but retention is too short'}. "
                    "HIPAA requires comprehensive audit controls to record and examine access "
                    "to PHI. Log retention should be at least 180 days (6 years recommended)."
                ),
                severity="medium",
                cvss_score=5.3,
                cve_ids=[],
                cwe_ids=["CWE-778"],  # Insufficient Logging
                remediation_guidance=(
                    "Enable comprehensive audit logging for all PHI access events. "
                    "Configure log retention for at least 180 days, preferably 6 years."
                ),
                priority_window="30_days",
                owner="DevOps",
            )
        return None

    def _check_risk_analysis(
        self, assessment: Assessment, metadata: MetadataProfile, control: Control
    ) -> Finding | None:
        """Check if risk analysis has been performed (always generates a finding initially)."""
        # In real implementation, this would check for evidence of a risk analysis document
        # For the MVP, we always flag this as needed
        return Finding(
            assessment_id=assessment.id,
            control_id=control.id,
            title="Risk Analysis Required",
            description=(
                "HIPAA requires covered entities to conduct an accurate and thorough "
                "assessment of the potential risks and vulnerabilities to the confidentiality, "
                "integrity, and availability of electronic PHI."
            ),
            severity="medium",
            cvss_score=None,  # Not a technical finding
            cve_ids=[],
            cwe_ids=[],
            remediation_guidance=(
                "Document a comprehensive risk analysis covering: (1) asset inventory, "
                "(2) threat identification, (3) vulnerability assessment, (4) impact analysis, "
                "(5) likelihood determination, (6) risk determination, (7) documentation."
            ),
            priority_window="quarterly",
            owner="Security",
        )

    def _check_software_vulnerabilities(
        self, assessment: Assessment, metadata: MetadataProfile
    ) -> list[Finding]:
        """Check software stack for known vulnerabilities using NVD API.

        Args:
            assessment: Current assessment
            metadata: Metadata profile with software_stack

        Returns:
            List of findings for vulnerable software components
        """
        findings: list[Finding] = []
        software_stack: dict[str, Any] = metadata.software_stack or {}

        if not software_stack:
            logger.info("No software stack provided, skipping NVD check")
            return findings

        logger.info(f"Analyzing software stack: {software_stack}")

        # Analyze stack for vulnerabilities
        try:
            vulnerabilities = self.nvd_service.analyze_software_stack(software_stack)
        except NVDApiError as e:
            logger.error(f"NVD API unavailable during assessment: {e}")
            return findings

        # Look up relevant control for software vulnerabilities
        # We'll map to "Malware Protection" control as a proxy for vuln management
        control = (
            self.db.query(Control)
            .filter(Control.id == "HIPAA.164.308(a)(5)(ii)(B)")
            .first()
        )

        if not control:
            # Fallback: create findings without control mapping
            control_id = "HIPAA.164.308(a)(5)(ii)(B)"
        else:
            control_id = control.id

        for component, cves in vulnerabilities.items():
            for cve_data in cves:
                severity = self.nvd_service.get_severity_from_cvss(
                    cve_data["cvss_score"]
                )
                priority_window = self.nvd_service.get_priority_window_from_cvss(
                    cve_data["cvss_score"]
                )

                finding = Finding(
                    assessment_id=assessment.id,
                    control_id=control_id,
                    title=f"Vulnerable Software Detected: {component} ({cve_data['cve_id']})",
                    description=(
                        f"Known vulnerability found in {component}: {cve_data['description'][:200]}...\n\n"
                        f"CVE ID: {cve_data['cve_id']}\n"
                        f"Published: {cve_data['published_date']}"
                    ),
                    severity=severity,
                    cvss_score=cve_data["cvss_score"],
                    cve_ids=[cve_data["cve_id"]],
                    cwe_ids=cve_data["cwe_ids"],
                    remediation_guidance=(
                        f"Update {component} to a patched version that addresses {cve_data['cve_id']}. "
                        f"Review NVD  (https://nvd.nist.gov/vuln/detail/{cve_data['cve_id']}) for "
                        f"specific remediation guidance."
                    ),
                    priority_window=priority_window,
                    owner="DevOps",
                )
                findings.append(finding)
                logger.info(f"Created finding for {cve_data['cve_id']} in {component}")

        return findings
