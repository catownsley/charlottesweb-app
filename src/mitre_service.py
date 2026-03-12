"""MITRE ATT&CK API integration for threat intelligence.

Integrates with MITRE ATT&CK Framework to add threat context to compliance findings.
Maps technical gaps (CWEs) to real-world attack techniques used in healthcare breaches.

Design Philosophy:
- Real-time API: Fetch from GitHub (auto-updated, no manual downloads)
- Healthcare focus: Prioritize ICS/Healthcare matrix techniques
- Narrative power: Link compliance gaps to actual breaches
- Executive-friendly: "This gap enabled [breach name]"

Data Source: https://github.com/mitre-attack/attack-stix-data
API: GitHub raw content (always latest)
"""

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

import requests

logger = logging.getLogger(__name__)


class MITREService:
    """Service for querying MITRE ATT&CK framework for threat intelligence."""

    # MITRE ATT&CK STIX 2.0 data from GitHub
    ENTERPRISE_ATTACK_URL = (
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
        "master/enterprise-attack/enterprise-attack.json"
    )

    # CWE → MITRE Technique mapping (common healthcare vulnerabilities)
    # Based on MITRE ATT&CK and OWASP Top 10 for healthcare
    CWE_TO_TECHNIQUE_MAP = {
        "CWE-287": ["T1078"],  # Improper Auth → Valid Accounts
        "CWE-306": ["T1078"],  # Missing Auth → Valid Accounts
        "CWE-308": [
            "T1078",
            "T1556",
        ],  # Missing Auth for Critical → Valid Accounts, Modify Auth
        "CWE-285": [
            "T1078",
            "T1134",
        ],  # Improper Authorization → Valid Accounts, Access Token
        "CWE-862": ["T1078"],  # Missing Authorization → Valid Accounts
        "CWE-798": [
            "T1078",
            "T1552",
        ],  # Hard-coded Credentials → Valid Accounts, Unsecured Creds
        "CWE-261": ["T1552"],  # Weak Password → Unsecured Credentials
        "CWE-312": ["T1005", "T1074"],  # Cleartext Storage → Data from Local System
        "CWE-319": [
            "T1040",
            "T1557",
        ],  # Cleartext Transmission → Network Sniffing, MitM
        "CWE-311": ["T1005"],  # Missing Encryption → Data from Local System
        "CWE-326": ["T1040"],  # Weak Encryption → Network Sniffing
        "CWE-327": ["T1040"],  # Broken Crypto → Network Sniffing
        "CWE-778": ["T1562"],  # Insufficient Logging → Impair Defenses
        "CWE-532": ["T1552"],  # Info in Log Files → Unsecured Credentials
        "CWE-89": ["T1190"],  # SQL Injection → Exploit Public-Facing Application
        "CWE-79": ["T1189"],  # XSS → Drive-by Compromise
        "CWE-352": ["T1189"],  # CSRF → Drive-by Compromise
    }

    # Notable healthcare breaches mapped to techniques
    HEALTHCARE_BREACHES = {
        "T1078": {
            "breach": "Change Healthcare (2024)",
            "impact": "Compromised credentials led to ransomware attack affecting 100M+ patients",
            "date": "February 2024",
        },
        "T1190": {
            "breach": "MOVEit Transfer Exploit (2023)",
            "impact": "Healthcare organizations exposed millions of patient records via SQL injection",
            "date": "May 2023",
        },
        "T1552": {
            "breach": "Baptist Health (2023)",
            "impact": "Exposed AWS keys leaked 1M+ patient PHI records",
            "date": "September 2023",
        },
        "T1005": {
            "breach": "Shields Health (2022)",
            "impact": "Unencrypted patient data on compromised systems",
            "date": "March 2022",
        },
        "T1040": {
            "breach": "Community Health Systems (2014)",
            "impact": "Unencrypted network traffic exposed 4.5M patient records",
            "date": "August 2014",
        },
    }

    def __init__(self) -> None:
        """Initialize MITRE ATT&CK service."""
        # In-memory cache (24-hour TTL, framework updates infrequently)
        self._cache: dict[str, Any] = {}
        self._cache_ttl = timedelta(hours=24)
        self._attack_data: dict[str, Any] | None = None

    def _fetch_attack_data(self) -> dict[str, Any]:
        """Fetch MITRE ATT&CK STIX data from GitHub.

        Returns:
            Parsed STIX bundle with techniques, mitigations, relationships

        Raises:
            requests.exceptions.RequestException: If API call fails
        """
        cache_key = "attack_data"

        # Check cache
        if cache_key in self._cache:
            cached_data, cached_time = self._cache[cache_key]
            if datetime.now(UTC) - cached_time < self._cache_ttl:
                logger.debug("MITRE ATT&CK cache hit")
                return cached_data

        try:
            logger.info("Fetching MITRE ATT&CK data from GitHub")
            response = requests.get(self.ENTERPRISE_ATTACK_URL, timeout=30)
            response.raise_for_status()

            data = response.json()

            # Cache the full STIX bundle
            self._cache[cache_key] = (data, datetime.now(UTC))
            logger.info(
                f"Fetched MITRE ATT&CK data: {len(data.get('objects', []))} objects"
            )

            return data

        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to fetch MITRE ATT&CK data: {e}")
            # Return empty structure if fetch fails
            return {"objects": []}

    def get_technique_by_id(self, technique_id: str) -> dict[str, Any] | None:
        """Get MITRE ATT&CK technique by ID.

        Args:
            technique_id: Technique ID (e.g., "T1078", "T1078.001")

        Returns:
            Technique object with name, description, detection, etc.
            None if not found
        """
        if self._attack_data is None:
            self._attack_data = self._fetch_attack_data()

        for obj in self._attack_data.get("objects", []):
            if obj.get("type") == "attack-pattern":
                # Check external references for technique ID
                for ref in obj.get("external_references", []):
                    if ref.get("external_id") == technique_id:
                        # Extract tactic names from kill chain phases
                        tactics = []
                        for phase in obj.get("kill_chain_phases", []):
                            if isinstance(phase, dict):
                                phase_name = phase.get("phase_name", "")
                                if phase_name:
                                    tactics.append(phase_name)

                        return {
                            "id": technique_id,
                            "name": obj.get("name", ""),
                            "description": obj.get("description", ""),
                            "tactics": tactics,
                            "detection": obj.get("x_mitre_detection", ""),
                            "url": ref.get("url", ""),
                        }

        return None

    def get_mitigations_for_technique(self, technique_id: str) -> list[dict[str, Any]]:
        """Get mitigations (countermeasures) for a technique.

        Args:
            technique_id: Technique ID (e.g., "T1078")

        Returns:
            List of mitigation dictionaries with id, name, description
        """
        if self._attack_data is None:
            self._attack_data = self._fetch_attack_data()

        # Find relationships between techniques and mitigations
        mitigation_ids = []
        for obj in self._attack_data.get("objects", []):
            if obj.get("type") == "relationship":
                if obj.get("relationship_type") == "mitigates":
                    # Find target technique
                    target_refs = obj.get("target_ref", "")
                    if technique_id in str(target_refs):
                        mitigation_ids.append(obj.get("source_ref"))

        # Get mitigation details
        mitigations = []
        for obj in self._attack_data.get("objects", []):
            if obj.get("type") == "course-of-action":
                if obj.get("id") in mitigation_ids:
                    mitigations.append(
                        {
                            "id": obj.get("external_references", [{}])[0].get(
                                "external_id", ""
                            ),
                            "name": obj.get("name", ""),
                            "description": obj.get("description", ""),
                        }
                    )

        return mitigations

    def get_techniques_for_cwe(self, cwe_id: str) -> list[str]:
        """Map CWE to MITRE ATT&CK techniques.

        Args:
            cwe_id: CWE ID (e.g., "CWE-308")

        Returns:
            List of technique IDs that exploit this weakness
        """
        return self.CWE_TO_TECHNIQUE_MAP.get(cwe_id, [])

    def get_healthcare_breach_context(self, technique_id: str) -> dict[str, Any] | None:
        """Get healthcare breach context for a technique.

        Args:
            technique_id: Technique ID (e.g., "T1078")

        Returns:
            Breach context with name, impact, date
            None if no notable breach mapped
        """
        return self.HEALTHCARE_BREACHES.get(technique_id)

    def enrich_finding_with_threat_context(
        self, cwe_ids: list[str], control_id: str
    ) -> dict[str, Any]:
        """Enrich a compliance finding with threat intelligence.

        Adds real-world threat context to help explain "why this matters."

        Args:
            cwe_ids: List of CWE IDs from the finding
            control_id: HIPAA control ID

        Returns:
            Threat context dictionary with techniques, breaches, mitigations
        """
        if not cwe_ids:
            return {}

        # Map CWEs to techniques
        techniques = []
        for cwe_id in cwe_ids[:3]:  # Limit to 3 CWEs to avoid overwhelming
            technique_ids = self.get_techniques_for_cwe(cwe_id)
            for tech_id in technique_ids:
                technique = self.get_technique_by_id(tech_id)
                if technique:
                    # Add healthcare breach context if available
                    breach = self.get_healthcare_breach_context(tech_id)
                    if breach:
                        technique["breach_example"] = breach

                    # Add primary mitigation
                    mitigations = self.get_mitigations_for_technique(tech_id)
                    if mitigations:
                        technique["primary_mitigation"] = mitigations[0]

                    techniques.append(technique)

        # Deduplicate by technique ID
        unique_techniques = {t["id"]: t for t in techniques}.values()

        return {
            "techniques": list(unique_techniques),
            "summary": self._generate_threat_summary(list(unique_techniques)),
        }

    def _generate_threat_summary(self, techniques: list[dict[str, Any]]) -> str:
        """Generate executive summary of threat context.

        Args:
            techniques: List of technique dictionaries

        Returns:
            Human-readable threat summary
        """
        if not techniques:
            return "No known attack techniques mapped to this weakness."

        primary = techniques[0]
        summary = f"This gap could enable {primary['name']} attacks."

        # Add breach context if available
        if "breach_example" in primary:
            breach = primary["breach_example"]
            summary += (
                f" A similar vulnerability was exploited in the {breach['breach']}, "
                f"which {breach['impact'].lower()}"
            )

        return summary


# Global service instance
mitre_service = MITREService()
