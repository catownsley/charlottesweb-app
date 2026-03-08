"""GitHub Dependabot integration for supply chain vulnerability intelligence."""
import logging
from typing import Any, Optional
from datetime import datetime, timedelta, timezone

import requests

logger = logging.getLogger(__name__)


class DependabotService:
    """Service for querying GitHub Dependabot alerts as threat intelligence."""

    BASE_URL = "https://api.github.com"

    # Map common dependency advisory advisories to CWE IDs
    # Based on GitHub's advisory database classifications
    ADVISORY_CWE_MAP = {
        "cryptography": ["CWE-327", "CWE-328", "CWE-347"],  # Weak crypto
        "jwt": ["CWE-347", "CWE-295"],  # Signature verification, cert validation
        "sql": ["CWE-89"],  # SQL Injection
        "injection": ["CWE-94", "CWE-95", "CWE-96"],  # Code/command injection
        "xss": ["CWE-79"],  # Cross-site scripting
        "csrf": ["CWE-352"],  # Cross-site request forgery
        "xxe": ["CWE-611"],  # XML External Entity
        "deserialization": ["CWE-502"],  # Unsafe deserialization
        "outdated": ["CWE-1104"],  # Use of outdated library
        "authentication": ["CWE-287", "CWE-306"],  # Auth issues
        "authorization": ["CWE-285", "CWE-862"],  # Authz issues
        "denial": ["CWE-400"],  # Uncontrolled resource consumption
    }

    def __init__(self, repo_owner: str, repo_name: str, github_token: Optional[str] = None):
        """Initialize Dependabot service.

        Args:
            repo_owner: GitHub repository owner (e.g., "catownsley")
            repo_name: GitHub repository name (e.g., "charlottesweb-app")
            github_token: GitHub personal access token (optional, for private repos)
        """
        self.repo_owner = repo_owner
        self.repo_name = repo_name
        self.github_token = github_token

        self.headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if github_token:
            self.headers["Authorization"] = f"Bearer {github_token}"

        # Simple in-memory cache
        self._cache: dict[str, tuple[list[dict[str, Any]], datetime]] = {}
        self._cache_ttl = timedelta(hours=24)

    def get_alerts(
        self, 
        state: str = "open",
        ecosystem: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """Fetch Dependabot alerts from GitHub repository.

        Args:
            state: Alert state ("open", "fixed", or "dismissed")
            ecosystem: Filter by ecosystem ("pip", "maven", "npm", etc.)

        Returns:
            List of alert dictionaries with vulnerability details
        """
        cache_key = f"alerts:{state}:{ecosystem or 'all'}"

        # Check cache
        if cache_key in self._cache:
            cached_data, cached_time = self._cache[cache_key]
            if datetime.now(timezone.utc) - cached_time < self._cache_ttl:
                logger.info(f"Cache hit for dependabot alerts: {state}")
                return cached_data

        try:
            url = f"{self.BASE_URL}/repos/{self.repo_owner}/{self.repo_name}/dependabot/alerts"

            params = {"state": state}
            if ecosystem:
                params["ecosystem"] = ecosystem

            response = requests.get(
                url,
                params=params,
                headers=self.headers,
                timeout=10,
            )
            response.raise_for_status()

            alerts = response.json()
            if not isinstance(alerts, list):
                alerts = []

            results = []
            for alert in alerts:
                try:
                    parsed = self._parse_alert(alert)
                    if parsed:
                        results.append(parsed)
                except Exception as e:
                    logger.warning(f"Failed to parse dependabot alert: {e}")
                    continue

            # Cache results
            self._cache[cache_key] = (results, datetime.now(timezone.utc))
            logger.info(f"Fetched {len(results)} Dependabot alerts (state: {state})")
            return results

        except requests.exceptions.RequestException as e:
            logger.error(f"GitHub API request failed: {e}")
            return []
        except Exception as e:
            logger.error(f"Error processing Dependabot response: {e}")
            return []

    def _parse_alert(self, alert: dict[str, Any]) -> Optional[dict[str, Any]]:
        """Parse a GitHub Dependabot alert into standardized format.

        Args:
            alert: Raw GitHub Dependabot alert object

        Returns:
            Parsed alert with vulnerability details or None if parsing fails
        """
        try:
            # Extract core fields
            number = alert.get("number")
            state = alert.get("state", "unknown")
            dependency = alert.get("dependency", {})
            package_name = dependency.get("package", {}).get("name", "unknown")
            ecosystem = dependency.get("package", {}).get("ecosystem", "unknown")

            # Extract security advisory
            advisory = alert.get("security_advisory", {})
            cve_id = advisory.get("cve_id", f"GITHUB-{number}")
            cvss_score = advisory.get("cvss", {}).get("score")
            cvss_severity = advisory.get("cvss", {}).get("rating", "unknown").lower()
            description = advisory.get("description", advisory.get("summary", ""))
            published_at = advisory.get("published_at", "")

            # Extract CWE IDs
            cwe_ids = []
            cwes = advisory.get("cwes", [])
            for cwe in cwes:
                cwe_id = cwe.get("cwe_id")
                if cwe_id:
                    cwe_ids.append(cwe_id)

            # Fallback: infer CWE from description and package name
            if not cwe_ids:
                cwe_ids = self._infer_cwes(package_name, description)

            return {
                "alert_number": number,
                "state": state,
                "cve_id": cve_id,
                "package_name": package_name,
                "ecosystem": ecosystem,
                "description": description,
                "cvss_score": cvss_score,
                "cvss_severity": cvss_severity,
                "cwe_ids": cwe_ids,
                "published_date": published_at,
                "url": alert.get("url"),
            }

        except Exception as e:
            logger.warning(f"Error parsing dependabot alert: {e}")
            return None

    def _infer_cwes(self, package_name: str, description: str) -> list[str]:
        """Infer CWE IDs from package name and description.

        Args:
            package_name: Name of vulnerable package
            description: Description of vulnerability

        Returns:
            List of inferred CWE IDs
        """
        inferred = []
        search_text = f"{package_name} {description}".lower()

        for keyword, cwe_list in self.ADVISORY_CWE_MAP.items():
            if keyword in search_text:
                inferred.extend(cwe_list)

        # Return unique CWE IDs
        return list(set(inferred)) if inferred else ["CWE-1104"]  # Default: outdated library

    def get_severity_from_cvss(self, cvss_score: Optional[float]) -> str:
        """Convert CVSS score to severity level.

        Args:
            cvss_score: CVSS v3.0 or v3.1 base score (0-10)

        Returns:
            Severity level as string
        """
        if cvss_score is None:
            return "unknown"

        if cvss_score >= 9.0:
            return "critical"
        elif cvss_score >= 7.0:
            return "high"
        elif cvss_score >= 4.0:
            return "medium"
        else:
            return "low"

    def get_alerts_for_ecosystem(self, ecosystem: str = "pip") -> list[dict[str, Any]]:
        """Convenience method: get all open alerts for specific package ecosystem.

        Args:
            ecosystem: Package ecosystem ("pip", "npm", "maven", etc.)

        Returns:
            List of parsed alerts
        """
        return self.get_alerts(state="open", ecosystem=ecosystem)


# Singleton instance (created when needed)
dependabot_service: Optional[DependabotService] = None


def get_dependabot_service(
    repo_owner: str = "catownsley",
    repo_name: str = "charlottesweb-app",
    github_token: Optional[str] = None,
) -> DependabotService:
    """Get or create Dependabot service instance.

    Args:
        repo_owner: GitHub repository owner
        repo_name: GitHub repository name
        github_token: GitHub personal access token

    Returns:
        DependabotService instance
    """
    global dependabot_service

    if dependabot_service is None:
        dependabot_service = DependabotService(repo_owner, repo_name, github_token)

    return dependabot_service
