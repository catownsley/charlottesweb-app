"""Rules engine for mapping metadata to HIPAA controls and generating findings."""

import logging
from typing import Any

from sqlalchemy.orm import Session

from src.models import Assessment, Control, Finding, MetadataProfile
from src.osv_service import OSVApiError, OSVService
from src.utils import sanitize_log_value

logger = logging.getLogger(__name__)


def normalize_software_stack(
    raw_stack: dict[str, Any],
) -> list[dict[str, str]]:
    """Normalize a software_stack dict into a list of component dicts.

    Handles three formats:
      1. Dict with version key: {"django": {"version": "4.2"}}
      2. Flat with name as key: {"python": "3.11"}
      3. Flat with label as key: {"backend": "FastAPI 0.135.1"}

    For flat values containing a space (format 3), the last whitespace-
    delimited token is treated as the version and everything before it as
    the package name.  If there is no space, the dict key is the name and
    the value is the version (format 2).

    Returns:
        List of dicts with keys: name, version, and optionally ecosystem
    """
    components: list[dict[str, str]] = []
    for key, value in raw_stack.items():
        key = str(key).strip()
        if not key:
            continue

        if isinstance(value, dict):
            name = str(value.get("name", key)).strip() or key
            version = str(value.get("version", "")).strip()
            ecosystem = str(value.get("ecosystem", "")).strip()
        else:
            raw_value = str(value).strip() if value is not None else ""
            if " " in raw_value:
                # "FastAPI 0.135.1" -> name="FastAPI", version="0.135.1"
                parts = raw_value.rsplit(" ", 1)
                name = parts[0].strip()
                version = parts[1].strip()
            else:
                # "3.11" -> key is the name, value is the version
                name = key
                version = raw_value
            ecosystem = ""

        if not name or not version:
            continue

        comp: dict[str, str] = {"name": name, "version": version}
        if ecosystem:
            comp["ecosystem"] = ecosystem
        components.append(comp)

    return components


class RulesEngine:
    """Maps metadata profiles to applicable controls and generates findings."""

    def __init__(self, db: Session, nvd_api_key: str | None = None):
        """Initialize the rules engine.

        Args:
            db: Database session
            nvd_api_key: Unused (kept for backward compatibility)
        """
        self.db = db
        # Use max_retries=1 during assessment creation to avoid blocking.
        # The dedicated analyze endpoint uses full retries.
        self.osv_service = OSVService(max_retries=1)

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
        """Check software stack for known vulnerabilities using OSV API.

        Args:
            assessment: Current assessment
            metadata: Metadata profile with software_stack

        Returns:
            List of findings for vulnerable software components
        """
        findings: list[Finding] = []
        raw_stack: dict[str, Any] = metadata.software_stack or {}

        if not raw_stack:
            logger.info("No software stack provided, skipping vulnerability check")
            return findings

        components = normalize_software_stack(raw_stack)
        if not components:
            return findings

        logger.info("Analyzing software stack: %d components", len(components))

        try:
            vulnerabilities = self.osv_service.analyze_software_stack(components)
        except OSVApiError as e:
            logger.error("OSV API unavailable during assessment: %s", e)
            return findings

        # Look up relevant control for software vulnerabilities
        control = (
            self.db.query(Control)
            .filter(Control.id == "HIPAA.164.308(a)(5)(ii)(B)")
            .first()
        )
        control_id = control.id if control else "HIPAA.164.308(a)(5)(ii)(B)"

        for component_key, vulns in vulnerabilities.items():
            for vuln in vulns:
                vuln_id = vuln["vuln_id"]
                # Use CVE alias if available, otherwise the OSV ID
                cve_ids = [a for a in vuln["aliases"] if a.startswith("CVE-")]
                display_id = cve_ids[0] if cve_ids else vuln_id

                severity = self.osv_service.get_severity_from_cvss(vuln["cvss_score"])
                priority_window = self.osv_service.get_priority_window_from_cvss(
                    vuln["cvss_score"]
                )

                description_text = vuln["summary"] or vuln["details"][:200]
                fixed_str = (
                    ", ".join(vuln["fixed_versions"][:3])
                    if vuln["fixed_versions"]
                    else "unknown"
                )

                finding = Finding(
                    assessment_id=assessment.id,
                    control_id=control_id,
                    external_id=display_id,
                    title=f"Vulnerable Software: {component_key} ({display_id})",
                    description=(
                        f"{description_text}\n\n"
                        f"Vulnerability: {vuln_id}\n"
                        f"Published: {vuln['published_date']}\n"
                        f"Fixed in: {fixed_str}"
                    ),
                    severity=severity,
                    cvss_score=vuln["cvss_score"],
                    cve_ids=cve_ids or [vuln_id],
                    cwe_ids=vuln["cwe_ids"],
                    remediation_guidance=(
                        f"Update {component_key.split('@')[0]} to a patched version "
                        f"(fixed in: {fixed_str}). "
                        f"See https://osv.dev/vulnerability/{vuln_id}"
                    ),
                    priority_window=priority_window,
                    owner="DevOps",
                )
                findings.append(finding)
                logger.info(
                    "Created finding for %s in %s",
                    sanitize_log_value(display_id),
                    sanitize_log_value(component_key),
                )

        return findings
