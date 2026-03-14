"""OSV.dev API integration for ecosystem-aware vulnerability intelligence."""

import logging
import re
import time
from typing import Any, TypedDict

import requests

logger = logging.getLogger(__name__)


class OSVApiError(Exception):
    """Raised when the OSV API returns an error or is unreachable."""

    pass


class VulnerabilityResult(TypedDict):
    """Type definition for a vulnerability search result."""

    vuln_id: str
    aliases: list[str]
    summary: str
    details: str
    cvss_score: float | None
    cvss_severity: str | None
    cwe_ids: list[str]
    published_date: str
    fixed_versions: list[str]


# Configuration constants
REQUEST_TIMEOUT_SECONDS = 30
MAX_RETRIES = 3
RETRY_BACKOFF_SECONDS = 2

# CVSS severity thresholds (same as NVD service for consistency)
CVSS_CRITICAL_THRESHOLD = 9.0
CVSS_HIGH_THRESHOLD = 7.0
CVSS_MEDIUM_THRESHOLD = 4.0

# CVSS v3 base score weights for vector string parsing
_CVSS_V3_METRIC_WEIGHTS: dict[str, dict[str, float]] = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {
        "N": 0.85,
        "L": 0.62,  # scope unchanged
        "H": 0.27,  # scope unchanged
        "L_changed": 0.68,
        "H_changed": 0.50,
    },
    "UI": {"N": 0.85, "R": 0.62},
    "S": {"U": 0, "C": 1},  # 0=unchanged, 1=changed
    "C": {"H": 0.56, "L": 0.22, "N": 0},
    "I": {"H": 0.56, "L": 0.22, "N": 0},
    "A": {"H": 0.56, "L": 0.22, "N": 0},
}


def parse_cvss_v3_score(vector: str) -> float | None:
    """Parse a CVSS v3.x vector string into a numeric base score.

    Implements the CVSS v3.0/v3.1 base score calculation per the FIRST
    specification. Returns None if the vector cannot be parsed.

    Args:
        vector: CVSS vector string, e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    """
    if not vector or not vector.startswith("CVSS:3"):
        return None

    parts = vector.split("/")
    metrics: dict[str, str] = {}
    for part in parts[1:]:  # skip "CVSS:3.x"
        if ":" in part:
            key, value = part.split(":", 1)
            metrics[key] = value

    required = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
    if not required.issubset(metrics.keys()):
        return None

    try:
        w = _CVSS_V3_METRIC_WEIGHTS
        scope_changed = metrics["S"] == "C"

        # Exploitability sub-score
        av = w["AV"][metrics["AV"]]
        ac = w["AC"][metrics["AC"]]

        pr_key = metrics["PR"]
        if scope_changed:
            pr_key = f"{metrics['PR']}_changed"
        pr = w["PR"].get(pr_key, w["PR"].get(metrics["PR"], 0))

        ui = w["UI"][metrics["UI"]]

        exploitability = 8.22 * av * ac * pr * ui

        # Impact sub-score
        isc_base = 1 - (
            (1 - w["C"][metrics["C"]])
            * (1 - w["I"][metrics["I"]])
            * (1 - w["A"][metrics["A"]])
        )

        if scope_changed:
            impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
        else:
            impact = 6.42 * isc_base

        if impact <= 0:
            return 0.0

        if scope_changed:
            base = min(1.08 * (impact + exploitability), 10.0)
        else:
            base = min(impact + exploitability, 10.0)

        # Round up to one decimal place per CVSS spec
        return float(int(base * 10 + 0.5) / 10)

    except (KeyError, ValueError, TypeError):
        return None


class OSVService:
    """Service for querying OSV.dev API for vulnerability information."""

    BASE_URL = "https://api.osv.dev/v1"

    def __init__(self, max_retries: int = MAX_RETRIES) -> None:
        self.max_retries = max_retries

    def _request(
        self,
        method: str,
        path: str,
        json_body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Make an OSV API request with retry on transient failures."""
        url = f"{self.BASE_URL}/{path}"
        last_error: Exception | None = None
        attempts = max(1, self.max_retries)

        for attempt in range(attempts):
            try:
                response = requests.request(
                    method,
                    url,
                    json=json_body,
                    timeout=REQUEST_TIMEOUT_SECONDS,
                )

                if response.status_code >= 500:
                    last_error = OSVApiError(f"OSV API returned {response.status_code}")
                    if attempt < attempts - 1:
                        time.sleep(RETRY_BACKOFF_SECONDS * (attempt + 1))
                        continue
                    raise last_error

                if response.status_code == 400:
                    raise OSVApiError(f"OSV API bad request: {response.text}")

                response.raise_for_status()
                return response.json()

            except requests.exceptions.RequestException as e:
                last_error = e
                logger.warning(
                    "OSV API request failed (attempt %d/%d): %s",
                    attempt + 1,
                    attempts,
                    e,
                )
                if attempt < attempts - 1:
                    time.sleep(RETRY_BACKOFF_SECONDS * (attempt + 1))

        raise OSVApiError(f"OSV API failed after {attempts} attempts: {last_error}")

    def _parse_vulnerability(self, vuln: dict[str, Any]) -> VulnerabilityResult:
        """Parse an OSV vulnerability record into our standard format."""
        vuln_id = vuln.get("id", "")
        aliases = vuln.get("aliases", [])
        summary = vuln.get("summary", "")
        details = vuln.get("details", "")
        published = vuln.get("published", "")

        # Extract CVSS score from severity array
        cvss_score: float | None = None
        cvss_severity: str | None = None
        for sev in vuln.get("severity", []):
            sev_type = sev.get("type", "")
            score_str = sev.get("score", "")

            if sev_type == "CVSS_V3":
                cvss_score = parse_cvss_v3_score(score_str)
                if cvss_score is not None:
                    cvss_severity = self.get_severity_from_cvss(cvss_score)
                    break
            elif sev_type == "CVSS_V4" and cvss_score is None:
                # CVSS v4 vector parsing is complex; extract score if
                # embedded in the vector as a rough fallback.
                match = re.search(r"(\d+\.\d+)", score_str)
                if match:
                    cvss_score = float(match.group(1))
                    if cvss_score > 10:
                        cvss_score = None

        # Also check affected[].ecosystem_specific.severity as fallback
        if cvss_severity is None:
            for affected in vuln.get("affected", []):
                eco_specific = affected.get("ecosystem_specific", {})
                if isinstance(eco_specific, dict):
                    sev_str = eco_specific.get("severity", "")
                    if isinstance(sev_str, str) and sev_str:
                        cvss_severity = sev_str.lower()
                        break

        # Extract CWE IDs from database_specific or aliases
        cwe_ids: list[str] = []
        db_specific = vuln.get("database_specific", {})
        if isinstance(db_specific, dict):
            for cwe in db_specific.get("cwe_ids", []):
                if isinstance(cwe, str) and cwe.startswith("CWE-"):
                    cwe_ids.append(cwe)

        # Extract fixed versions from affected ranges
        fixed_versions: list[str] = []
        for affected in vuln.get("affected", []):
            for range_info in affected.get("ranges", []):
                for event in range_info.get("events", []):
                    if "fixed" in event:
                        fixed_versions.append(event["fixed"])

        return VulnerabilityResult(
            vuln_id=vuln_id,
            aliases=aliases,
            summary=summary,
            details=details,
            cvss_score=cvss_score,
            cvss_severity=cvss_severity,
            cwe_ids=list(set(cwe_ids)),
            published_date=published,
            fixed_versions=fixed_versions,
        )

    def query_package(
        self,
        name: str,
        ecosystem: str,
        version: str,
    ) -> list[VulnerabilityResult]:
        """Query OSV for vulnerabilities affecting a specific package version.

        Args:
            name: Package name (e.g., "django", "kafka-clients")
            ecosystem: Package ecosystem (e.g., "PyPI", "Maven")
            version: Package version string

        Returns:
            List of vulnerability results
        """
        body: dict[str, Any] = {
            "version": version,
            "package": {
                "name": name,
                "ecosystem": ecosystem,
            },
        }

        all_vulns: list[VulnerabilityResult] = []
        page_token: str | None = None

        while True:
            if page_token:
                body["page_token"] = page_token

            data = self._request("POST", "query", json_body=body)
            vulns_raw = data.get("vulns", [])

            for vuln_raw in vulns_raw:
                all_vulns.append(self._parse_vulnerability(vuln_raw))

            page_token = data.get("next_page_token")
            if not page_token:
                break

        logger.info(
            "OSV query: %s/%s@%s → %d vulnerabilities",
            ecosystem,
            name,
            version,
            len(all_vulns),
        )
        return all_vulns

    def analyze_software_stack(
        self,
        components: list[dict[str, str]],
    ) -> dict[str, list[VulnerabilityResult]]:
        """Analyze a software stack for known vulnerabilities.

        Args:
            components: List of component dicts with keys:
                name, version, ecosystem

        Returns:
            Dictionary mapping "name@version" to list of vulnerabilities

        Raises:
            OSVApiError: If the OSV API is unreachable for all components.
        """
        results: dict[str, list[VulnerabilityResult]] = {}
        failed: list[str] = []

        for comp in components:
            name = comp.get("name", "")
            version = comp.get("version", "")
            ecosystem = comp.get("ecosystem", "")

            if not name or not version or not ecosystem:
                logger.warning("Skipping component with missing fields: %s", comp)
                continue

            component_key = f"{name}@{version}"

            try:
                vulns = self.query_package(name, ecosystem, version)
                if vulns:
                    results[component_key] = vulns
            except OSVApiError:
                failed.append(component_key)
                logger.error("OSV API failed for: %s", component_key)

        if failed and not results:
            raise OSVApiError(
                f"OSV API unavailable. Failed to analyze: {', '.join(failed)}. "
                "Try again in a few minutes."
            )

        if failed:
            logger.warning(
                "Partial OSV results: %d failed (%s), %d succeeded",
                len(failed),
                ", ".join(failed),
                len(results),
            )

        return results

    @staticmethod
    def get_severity_from_cvss(cvss_score: float | None) -> str:
        """Convert CVSS score to severity level."""
        if cvss_score is None:
            return "medium"

        if cvss_score >= CVSS_CRITICAL_THRESHOLD:
            return "critical"
        elif cvss_score >= CVSS_HIGH_THRESHOLD:
            return "high"
        elif cvss_score >= CVSS_MEDIUM_THRESHOLD:
            return "medium"
        else:
            return "low"

    @staticmethod
    def get_priority_window_from_cvss(cvss_score: float | None) -> str:
        """Determine remediation priority window based on CVSS score."""
        if cvss_score is None:
            return "quarterly"

        if cvss_score >= CVSS_HIGH_THRESHOLD:
            return "immediate"
        elif cvss_score >= CVSS_MEDIUM_THRESHOLD:
            return "30_days"
        else:
            return "quarterly"
