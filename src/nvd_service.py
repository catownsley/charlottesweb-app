"""NVD CPE dictionary integration for component and version discovery.

Vulnerability lookups are handled by osv_service.py (OSV.dev).
This module provides component name suggestions and version autocomplete
via the NVD CPE (Common Platform Enumeration) API.
"""

import logging
import time
from datetime import UTC, datetime, timedelta
from typing import Any

import requests

from src.utils import sanitize_log_value

logger = logging.getLogger(__name__)


class NVDApiError(Exception):
    """Raised when the NVD API returns an error or is unreachable."""

    pass


# Configuration constants
CACHE_TTL_HOURS = 0  # Disabled during development; re-enable with Redis in production
DEFAULT_MAX_RESULTS = 10
VERSION_SEARCH_MAX_RESULTS = 100
REQUEST_TIMEOUT_SECONDS = 30
RATE_LIMIT_RETRY_ATTEMPTS = 3
RATE_LIMIT_BACKOFF_SECONDS = 6  # NVD rate limit resets every 30s; 6s * 3 retries = 18s


class NVDService:
    """Service for querying NVD CPE dictionary for component/version discovery."""

    CPE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
    CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(
        self, api_key: str | None = None, max_retries: int = RATE_LIMIT_RETRY_ATTEMPTS
    ) -> None:
        self.api_key = api_key
        self.max_retries = max_retries
        self.headers: dict[str, str] = {}
        if api_key:
            self.headers["apiKey"] = api_key

        self._cache: dict[str, tuple[list[str], datetime]] = {}
        self._cache_ttl = timedelta(hours=CACHE_TTL_HOURS)

    def _request_with_retry(
        self, params: dict[str, str | int], *, url: str | None = None
    ) -> dict[str, Any]:
        """Make an NVD API request with retry on rate limit (429)."""
        target_url = url or self.CPE_URL
        last_error: Exception | None = None
        attempts = max(1, self.max_retries)

        for attempt in range(attempts):
            try:
                response = requests.get(
                    target_url,
                    params=params,
                    headers=self.headers,
                    timeout=REQUEST_TIMEOUT_SECONDS,
                )

                if response.status_code == 429:
                    wait = RATE_LIMIT_BACKOFF_SECONDS * (attempt + 1)
                    logger.warning(
                        "NVD rate limited (429), waiting %ds (attempt %d/%d)",
                        wait,
                        attempt + 1,
                        attempts,
                    )
                    time.sleep(wait)
                    continue

                response.raise_for_status()
                return response.json()

            except requests.exceptions.RequestException as e:
                last_error = e
                logger.warning(
                    "NVD API request failed (attempt %d/%d): %s",
                    attempt + 1,
                    attempts,
                    sanitize_log_value(str(e)),
                )
                if attempt < attempts - 1:
                    time.sleep(RATE_LIMIT_BACKOFF_SECONDS)

        raise NVDApiError(f"NVD API failed after {attempts} attempts: {last_error}")

    # Common CPE naming mismatches: user-friendly names → NVD vendor:product.
    _CPE_ALIASES: dict[str, list[tuple[str, str, str]]] = {
        # Operating systems
        "ubuntu": [("o", "canonical", "ubuntu_linux")],
        "debian": [("o", "debian", "debian_linux")],
        "centos": [("o", "centos", "centos")],
        "rhel": [("o", "redhat", "enterprise_linux")],
        "red hat": [("o", "redhat", "enterprise_linux")],
        "windows": [
            ("o", "microsoft", "windows_10"),
            ("o", "microsoft", "windows_11"),
            ("o", "microsoft", "windows_server_2022"),
        ],
        "macos": [("o", "apple", "macos")],
        "linux": [("o", "linux", "linux_kernel")],
        # Languages / runtimes
        "python": [("a", "python", "python")],
        "php": [("a", "php", "php")],
        "ruby": [("a", "ruby", "ruby")],
        "perl": [("a", "perl", "perl")],
        "go": [("a", "golang", "go")],
        "golang": [("a", "golang", "go")],
        "rust": [("a", "rust-lang", "rust")],
        "java": [("a", "oracle", "jdk"), ("a", "oracle", "jre")],
        "openjdk": [("a", "oracle", "openjdk")],
        "node": [("a", "nodejs", "node.js")],
        "nodejs": [("a", "nodejs", "node.js")],
        "node.js": [("a", "nodejs", "node.js")],
        # Databases
        "postgresql": [("a", "postgresql", "postgresql")],
        "postgres": [("a", "postgresql", "postgresql")],
        "mysql": [("a", "oracle", "mysql")],
        "mariadb": [("a", "mariadb", "mariadb")],
        "sqlite": [("a", "sqlite", "sqlite")],
        "redis": [("a", "redis", "redis")],
        "mongodb": [("a", "mongodb", "mongodb")],
        # Web servers / frameworks
        "nginx": [("a", "f5", "nginx")],
        "apache": [("a", "apache", "http_server")],
        "httpd": [("a", "apache", "http_server")],
        "tomcat": [("a", "apache", "tomcat")],
        "django": [("a", "djangoproject", "django")],
        "fastapi": [("a", "fastapi_project", "fastapi")],
        "flask": [("a", "palletsprojects", "flask")],
        "rails": [("a", "rubyonrails", "rails")],
        "spring": [("a", "vmware", "spring_framework")],
        "express": [("a", "expressjs", "express")],
        # Other common software
        "openssl": [("a", "openssl", "openssl")],
        "curl": [("a", "haxx", "curl")],
        "git": [("a", "git-scm", "git")],
        "docker": [("a", "docker", "docker")],
        "kubernetes": [("a", "kubernetes", "kubernetes")],
        "wordpress": [("a", "wordpress", "wordpress")],
        "jquery": [("a", "jquery", "jquery")],
        "react": [("a", "facebook", "react")],
        "angular": [("a", "google", "angular")],
        "vue": [("a", "vuejs", "vue.js")],
        "vue.js": [("a", "vuejs", "vue.js")],
        # Python libraries
        "uvicorn": [("a", "encode", "uvicorn")],
        "pydantic": [("a", "pydantic_project", "pydantic")],
        "sqlalchemy": [("a", "sqlalchemy", "sqlalchemy")],
        "pyjwt": [("a", "pyjwt_project", "pyjwt")],
        "requests": [("a", "python-requests", "requests")],
        "python-requests": [("a", "python-requests", "requests")],
    }

    @staticmethod
    def _parse_version(version_str: str) -> tuple[int, ...]:
        """Parse version string for sorting."""
        try:
            parts = version_str.split(".")
            return tuple(int(p) if p.isdigit() else 0 for p in parts)
        except (ValueError, AttributeError):
            return (0,)

    def _discover_cpe_identity(
        self, component_name: str
    ) -> tuple[str, str, str] | None:
        """Discover the real CPE type:vendor:product for a component name.

        Uses NVD keywordSearch to find the actual CPE entry, then extracts
        the vendor and product fields. Caches the result as a runtime alias
        so subsequent lookups are instant.

        Args:
            component_name: Lowercase component name (e.g., 'javamail')

        Returns:
            Tuple of (cpe_type, vendor, product) or None if not found
        """
        cache_key = f"cpe_identity:{component_name}"
        if cache_key in self._cache:
            cached_data, cached_time = self._cache[cache_key]
            if datetime.now(UTC) - cached_time < self._cache_ttl:
                return cached_data  # type: ignore[return-value]

        try:
            params: dict[str, str | int] = {
                "keywordSearch": component_name,
                "resultsPerPage": VERSION_SEARCH_MAX_RESULTS,
            }
            data = self._request_with_retry(params, url=self.CPE_URL)

            for product_entry in data.get("products", []):
                cpe = product_entry.get("cpe", {})
                cpe_name = cpe.get("cpeName", "")
                parts = cpe_name.split(":")
                if len(parts) < 6:
                    continue

                cpe_type = parts[2].strip().lower()
                vendor = parts[3].strip().lower()
                product = parts[4].strip().lower()

                if product == component_name or vendor == component_name:
                    result = (cpe_type, vendor, product)
                    self._cache[cache_key] = (result, datetime.now(UTC))  # type: ignore[assignment]
                    logger.info(
                        "Discovered CPE identity for %s: %s:%s:%s",
                        sanitize_log_value(component_name),
                        cpe_type,
                        sanitize_log_value(vendor),
                        sanitize_log_value(product),
                    )
                    return result

            logger.warning(
                "Could not discover CPE identity for: %s",
                sanitize_log_value(component_name),
            )
            return None

        except NVDApiError:
            logger.warning(
                "NVD API unavailable for CPE discovery: %s",
                sanitize_log_value(component_name),
            )
            return None

    def get_known_versions(
        self, component_name: str, max_versions: int = DEFAULT_MAX_RESULTS
    ) -> list[str]:
        """Get known versions of a component from NVD CPE dictionary.

        Args:
            component_name: Name of the component (e.g., 'python', 'postgresql')
            max_versions: Maximum number of versions to return

        Returns:
            List of version strings, newest first
        """
        cache_key = f"versions:{component_name}"

        if cache_key in self._cache:
            cached_data, cached_time = self._cache[cache_key]
            if datetime.now(UTC) - cached_time < self._cache_ttl:
                logger.info(
                    "Cache hit for component versions: %s",
                    sanitize_log_value(component_name),
                )
                return cached_data

        try:
            comp_lower = component_name.lower()
            aliases = self._CPE_ALIASES.get(comp_lower)
            if aliases:
                cpe_type, cpe_vendor, cpe_product = aliases[0]
            else:
                # Discover the real vendor:product via keywordSearch
                discovered = self._discover_cpe_identity(comp_lower)
                if discovered:
                    cpe_type, cpe_vendor, cpe_product = discovered
                else:
                    cpe_type, cpe_vendor, cpe_product = "a", comp_lower, comp_lower

            cpe_match = f"cpe:2.3:{cpe_type}:{cpe_vendor}:{cpe_product}:*"

            params: dict[str, str | int] = {
                "cpeMatchString": cpe_match,
                "resultsPerPage": 10000,
            }
            data = self._request_with_retry(params, url=self.CPE_URL)
            products = data.get("products", [])

            versions_set: set[str] = set()
            for product in products:
                cpe_name = product.get("cpe", {}).get("cpeName", "")
                parts = cpe_name.split(":")
                if len(parts) >= 6:
                    ver = parts[5]
                    if ver and ver not in ("*", "-", ""):
                        versions_set.add(ver)

            sorted_versions = sorted(
                list(versions_set), key=self._parse_version, reverse=True
            )
            top_versions = sorted_versions[:max_versions]

            self._cache[cache_key] = (top_versions, datetime.now(UTC))
            logger.info(
                "Found %d versions for %s from CPE dictionary",
                len(top_versions),
                sanitize_log_value(component_name),
            )
            return top_versions

        except NVDApiError:
            logger.error(
                "NVD API unavailable for version lookup: %s",
                sanitize_log_value(component_name),
            )
            return []
        except Exception as e:
            logger.error(
                "Error fetching versions from NVD: %s", sanitize_log_value(str(e))
            )
            return []

    def get_component_suggestions(
        self, prefix: str, max_components: int = DEFAULT_MAX_RESULTS
    ) -> list[str]:
        """Get component name suggestions from the NVD CPE dictionary.

        Uses the CPE API's keywordSearch (which searches human-readable CPE
        titles like "Apache HTTP Server") instead of the CVE keyword API.
        Also includes known alias names so common names like "apache",
        "nginx", "node" always appear even though NVD uses different CPE
        product names internally.

        Args:
            prefix: Starting characters typed by user
            max_components: Maximum number of component names to return

        Returns:
            Sorted component names matching the provided prefix
        """
        normalized_prefix = prefix.lower().strip()
        if len(normalized_prefix) < 2:
            return []

        cache_key = f"component_suggestions:{normalized_prefix}:{max_components}"

        if cache_key in self._cache:
            cached_data, cached_time = self._cache[cache_key]
            if datetime.now(UTC) - cached_time < self._cache_ttl:
                logger.info(
                    "Cache hit for component suggestions: %s",
                    sanitize_log_value(normalized_prefix),
                )
                return cached_data

        try:
            components: set[str] = set()

            for alias_key in self._CPE_ALIASES:
                if alias_key.startswith(normalized_prefix):
                    components.add(alias_key)

            params: dict[str, str | int] = {
                "keywordSearch": normalized_prefix,
                "resultsPerPage": VERSION_SEARCH_MAX_RESULTS,
            }
            data = self._request_with_retry(params, url=self.CPE_URL)

            for product_entry in data.get("products", []):
                cpe = product_entry.get("cpe", {})
                cpe_name = cpe.get("cpeName", "")
                parts = cpe_name.split(":")
                if len(parts) < 6:
                    continue

                vendor = parts[3].strip().lower()
                product = parts[4].strip().lower()
                if not product or product in {"*", "-"}:
                    continue

                if product.startswith(normalized_prefix) or (
                    vendor
                    and vendor not in {"*", "-"}
                    and vendor.startswith(normalized_prefix)
                ):
                    components.add(product)

            sorted_components = sorted(components, key=lambda name: (len(name), name))
            top_components = sorted_components[:max_components]

            self._cache[cache_key] = (top_components, datetime.now(UTC))
            logger.info(
                "Extracted %d component suggestions for prefix: %s",
                len(top_components),
                sanitize_log_value(normalized_prefix),
            )
            return top_components

        except NVDApiError:
            logger.error(
                "NVD API unavailable for component suggestions: %s",
                sanitize_log_value(normalized_prefix),
            )
            return []
        except Exception as e:
            logger.error(
                "Error extracting component suggestions from NVD: %s",
                sanitize_log_value(str(e)),
            )
            return []

    @staticmethod
    def _parse_nvd_cve(cve: dict[str, Any]) -> dict[str, Any]:
        """Parse a single NVD CVE record into VulnerabilityResult format."""
        cve_id = cve.get("id", "")

        # Extract description (English)
        summary = ""
        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                summary = desc.get("value", "")
                break

        # Extract CVSS score and severity
        cvss_score = None
        cvss_severity = None
        metrics = cve.get("metrics", {})
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            for metric in metrics.get(metric_key, []):
                if metric.get("type") == "Primary":
                    cvss_data = metric.get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore")
                    cvss_severity = cvss_data.get(
                        "baseSeverity", metric.get("baseSeverity")
                    )
                    break
            if cvss_score is not None:
                break

        # Extract CWE IDs
        cwe_ids: list[str] = []
        for weakness in cve.get("weaknesses", []):
            for desc in weakness.get("description", []):
                val = desc.get("value", "")
                if val.startswith("CWE-"):
                    cwe_ids.append(val)

        return {
            "vuln_id": cve_id,
            "aliases": [cve_id],
            "summary": summary,
            "details": summary,
            "cvss_score": cvss_score,
            "cvss_severity": ((cvss_severity or "").upper() if cvss_severity else None),
            "cwe_ids": list(set(cwe_ids)),
            "published_date": cve.get("published", ""),
            "fixed_versions": [],
            "source": "NVD",
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        }

    def get_cves_for_component(
        self,
        component_name: str,
        version: str = "",
        max_results: int = 50,
    ) -> list[dict[str, Any]]:
        """Query NVD CVE API for vulnerabilities affecting a component.

        Used as a fallback when OSV has no data (e.g., proprietary software).
        Resolves the component to its CPE identity, then queries for CVEs.

        Args:
            component_name: Component name (e.g., 'bams', 'java')
            version: Optional version string
            max_results: Maximum CVEs to return

        Returns:
            List of vulnerability dicts matching VulnerabilityResult format
        """
        comp_lower = component_name.lower()
        aliases = self._CPE_ALIASES.get(comp_lower)
        if aliases:
            cpe_type, cpe_vendor, cpe_product = aliases[0]
        else:
            discovered = self._discover_cpe_identity(comp_lower)
            if discovered:
                cpe_type, cpe_vendor, cpe_product = discovered
            else:
                logger.warning(
                    "Cannot query NVD CVEs: unknown CPE for %s",
                    sanitize_log_value(component_name),
                )
                return []

        cpe_name = f"cpe:2.3:{cpe_type}:{cpe_vendor}:{cpe_product}:{version or '*'}:*:*:*:*:*:*:*"

        try:
            # cpeName requires exact values; virtualMatchString supports wildcards
            param_key = "cpeName" if version else "virtualMatchString"
            params: dict[str, str | int] = {
                param_key: cpe_name,
                "resultsPerPage": max_results,
            }
            data = self._request_with_retry(params, url=self.CVE_URL)

            results = [
                self._parse_nvd_cve(entry.get("cve", {}))
                for entry in data.get("vulnerabilities", [])
            ]

            logger.info(
                "NVD CVE query: %s → %d vulnerabilities",
                sanitize_log_value(
                    f"{component_name}@{version}" if version else component_name
                ),
                len(results),
            )
            return results

        except NVDApiError:
            logger.error(
                "NVD CVE API unavailable for: %s",
                sanitize_log_value(component_name),
            )
            return []
        except Exception as e:
            logger.error(
                "Error querying NVD CVEs: %s",
                sanitize_log_value(str(e)),
            )
            return []
