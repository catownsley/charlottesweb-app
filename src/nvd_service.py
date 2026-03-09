"""NVD API integration for CVE vulnerability intelligence."""

import logging
from datetime import UTC, datetime, timedelta
from typing import Any, TypedDict, cast

import requests

logger = logging.getLogger(__name__)


class CVEResult(TypedDict):
    """Type definition for CVE search result."""

    cve_id: str
    description: str
    cvss_score: float | None
    cvss_severity: str | None
    cwe_ids: list[str]
    published_date: str


# Configuration constants
CACHE_TTL_HOURS = 24
DEFAULT_MAX_RESULTS = 10
VERSION_SEARCH_MAX_RESULTS = 100
REQUEST_TIMEOUT_SECONDS = 10

# Version filtering constants
MAX_VALID_SINGLE_DIGIT_VERSION = 50  # Filter out build numbers like 382, 3802

# CVSS severity thresholds
CVSS_CRITICAL_THRESHOLD = 9.0
CVSS_HIGH_THRESHOLD = 7.0
CVSS_MEDIUM_THRESHOLD = 4.0


class NVDService:
    """Service for querying NVD API for CVE information."""

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, api_key: str | None = None) -> None:
        """Initialize NVD service.

        Args:
            api_key: NVD API key for higher rate limits (optional)
        """
        self.api_key = api_key
        self.headers: dict[str, str] = {}
        if api_key:
            self.headers["apiKey"] = api_key

        # Simple in-memory cache (in production, use Redis)
        self._cache: dict[str, tuple[list[CVEResult] | list[str], datetime]] = {}
        self._cache_ttl = timedelta(hours=CACHE_TTL_HOURS)

    def search_cves_by_keyword(
        self, keyword: str, max_results: int = DEFAULT_MAX_RESULTS
    ) -> list[CVEResult]:
        """Search for CVEs by keyword (e.g., product name).

        Args:
            keyword: Search term (e.g., "postgresql", "nginx")
            max_results: Maximum number of results to return

        Returns:
            List of CVE dictionaries with id, description, cvss, cwe
        """
        cache_key = f"keyword:{keyword}:{max_results}"

        # Check cache
        if cache_key in self._cache:
            cached_data, cached_time = self._cache[cache_key]
            if datetime.now(UTC) - cached_time < self._cache_ttl:
                logger.info(f"Cache hit for keyword: {keyword}")
                return cached_data  # type: ignore[return-value]

        try:
            params: dict[str, str | int] = {
                "keywordSearch": keyword,
                "resultsPerPage": max_results,
            }

            response = requests.get(
                self.BASE_URL,
                params=params,
                headers=self.headers,
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
            response.raise_for_status()

            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])

            results: list[CVEResult] = []
            for vuln in vulnerabilities:
                cve = vuln.get("cve", {})
                cve_id = cve.get("id", "")

                # Extract description
                descriptions = cve.get("descriptions", [])
                description = ""
                if descriptions:
                    description = descriptions[0].get("value", "")

                # Extract CVSS score
                metrics = cve.get("metrics", {})
                cvss_score: float | None = None
                cvss_severity: str | None = None

                # Try CVSS v3.1 first, then v3.0, then v2.0
                for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if version in metrics and metrics[version]:
                        cvss_data = metrics[version][0].get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore")
                        cvss_severity = cvss_data.get("baseSeverity", "").lower()
                        break

                # Extract CWE IDs
                weaknesses = cve.get("weaknesses", [])
                cwe_ids: list[str] = []
                for weakness in weaknesses:
                    for desc in weakness.get("description", []):
                        cwe_value = desc.get("value", "")
                        if cwe_value.startswith("CWE-"):
                            cwe_ids.append(cwe_value)

                results.append(
                    CVEResult(
                        cve_id=cve_id,
                        description=description,
                        cvss_score=cvss_score,
                        cvss_severity=cvss_severity,
                        cwe_ids=list(set(cwe_ids)),  # Deduplicate
                        published_date=cve.get("published", ""),
                    )
                )

            # Cache results
            self._cache[cache_key] = (results, datetime.now(UTC))
            logger.info(f"Fetched {len(results)} CVEs for keyword: {keyword}")
            return results

        except requests.exceptions.RequestException as e:
            logger.error(f"NVD API request failed: {e}")
            return []
        except Exception as e:
            logger.error(f"Error processing NVD response: {e}")
            return []

    def analyze_software_stack(
        self, software_stack: dict[str, str]
    ) -> dict[str, list[CVEResult]]:
        """Analyze a software stack for known vulnerabilities.

        Args:
            software_stack: Dictionary of component: version pairs
                Example: {"postgresql": "13.2", "nginx": "1.19.0", "python": "3.9.5"}

        Returns:
            Dictionary mapping component names to lists of CVEs
        """
        results: dict[str, list[CVEResult]] = {}

        for component, version in software_stack.items():
            # Search for CVEs mentioning this component
            # Search by component name only, not version string
            # NVD API uses AND logic for multiple keywords, so "java 21" searches for CVEs
            # mentioning BOTH java AND "21", which is too restrictive.
            # Instead, search for component name alone to get all CVEs affecting that component.
            search_term = component  # Just component name, no version
            cves = self.search_cves_by_keyword(search_term, max_results=5)

            if cves:
                results[component] = cves
                logger.info(
                    f"Found {len(cves)} CVEs for {component} (version {version})"
                )

        return results

    def get_severity_from_cvss(self, cvss_score: float | None) -> str:
        """Convert CVSS score to severity level.

        Args:
            cvss_score: CVSS base score (0.0-10.0)

        Returns:
            Severity level: critical, high, medium, low
        """
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

    def get_priority_window_from_cvss(self, cvss_score: float | None) -> str:
        """Determine remediation priority window based on CVSS score.

        Args:
            cvss_score: CVSS base score (0.0-10.0)

        Returns:
            Priority window: immediate, 30_days, quarterly, annual
        """
        if cvss_score is None:
            return "quarterly"

        if cvss_score >= CVSS_HIGH_THRESHOLD:
            return "immediate"
        elif cvss_score >= CVSS_MEDIUM_THRESHOLD:
            return "30_days"
        else:
            return "quarterly"

    def get_known_versions(
        self, component_name: str, max_versions: int = DEFAULT_MAX_RESULTS
    ) -> list[str]:
        """Get known versions of a component from NVD CVE records.

        Queries NVD for CVEs affecting the component and extracts all unique versions
        mentioned in the vulnerability data.

        Args:
            component_name: Name of the component (e.g., 'postgresql', 'nginx')
            max_versions: Maximum number of versions to return

        Returns:
            List of version strings found in NVD records, sorted by recency
        """
        cache_key = f"versions:{component_name}"

        # Check cache
        if cache_key in self._cache:
            cached_data, cached_time = self._cache[cache_key]
            if datetime.now(UTC) - cached_time < self._cache_ttl:
                logger.info(f"Cache hit for component versions: {component_name}")
                return cached_data  # type: ignore[return-value]

        try:
            params: dict[str, str | int] = {
                "keywordSearch": component_name,
                "resultsPerPage": VERSION_SEARCH_MAX_RESULTS,
            }

            response = requests.get(
                self.BASE_URL,
                params=params,
                headers=self.headers,
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
            response.raise_for_status()

            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])

            versions_set: set[str] = set()

            # Extract version information from CVE configurations
            for vuln in vulnerabilities:
                cve = vuln.get("cve", {})
                configurations = cve.get("configurations", [])

                for config in configurations:
                    nodes = config.get("nodes", [])
                    for node in nodes:
                        cpe_match = node.get("cpeMatch", [])
                        for match in cpe_match:
                            # Extract version from CPE URI
                            cpe23uri = match.get("criteria", "")
                            # CPE format: cpe:2.3:part:vendor:product:version:...
                            # [0]=cpe, [1]=2.3, [2]=part, [3]=vendor, [4]=product, [5]=version
                            if cpe23uri:
                                parts = cpe23uri.split(":")
                                if len(parts) >= 6:
                                    version = parts[5]
                                    # Filter out wildcards, generic versions, and invalid formats
                                    # Valid versions should contain dots (e.g., "21.0.1") or be simple numbers
                                    # This filters out update/build numbers that aren't valid versions
                                    if version and version not in ["*", "-", ""]:
                                        # Accept versions with dots or reasonable single numbers
                                        if "." in version or (
                                            version.isdigit()
                                            and int(version)
                                            <= MAX_VALID_SINGLE_DIGIT_VERSION
                                        ):
                                            versions_set.add(version)

                            # Also check version ranges
                            version_start_including = match.get("versionStartIncluding")
                            if version_start_including:
                                versions_set.add(version_start_including)

                            version_end_including = match.get("versionEndIncluding")
                            if version_end_including:
                                versions_set.add(version_end_including)

            # Sort versions (try numeric sort, fallback to string sort)
            sorted_versions = sorted(
                list(versions_set), key=lambda v: self._parse_version(v), reverse=True
            )
            top_versions = sorted_versions[:max_versions]

            # Cache results
            self._cache[cache_key] = (top_versions, datetime.now(UTC))
            logger.info(
                f"Extracted {len(top_versions)} versions for {component_name} from NVD"
            )
            return top_versions

        except requests.exceptions.RequestException as e:
            logger.error(f"NVD API request failed for versions: {e}")
            return []
        except Exception as e:
            logger.error(f"Error extracting versions from NVD: {e}")
            return []

    def get_component_suggestions(
        self, prefix: str, max_components: int = DEFAULT_MAX_RESULTS
    ) -> list[str]:
        """Get component name suggestions from NVD CVE CPE metadata.

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
                logger.info(f"Cache hit for component suggestions: {normalized_prefix}")
                return cached_data  # type: ignore[return-value]

        try:
            params: dict[str, str | int] = {
                "keywordSearch": normalized_prefix,
                "resultsPerPage": VERSION_SEARCH_MAX_RESULTS,
            }
            response = requests.get(
                self.BASE_URL,
                params=params,
                headers=self.headers,
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
            response.raise_for_status()

            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])

            components: set[str] = set()
            for vuln in vulnerabilities:
                cve = vuln.get("cve", {})
                configurations = cve.get("configurations", [])

                for config in configurations:
                    nodes_raw = config.get("nodes", [])
                    if not isinstance(nodes_raw, list):
                        continue

                    nodes_raw_list = cast(list[object], nodes_raw)
                    nodes: list[dict[str, Any]] = []
                    for node_item in nodes_raw_list:
                        if isinstance(node_item, dict):
                            nodes.append(cast(dict[str, Any], node_item))

                    self._collect_component_names_from_nodes(
                        nodes=nodes,
                        prefix=normalized_prefix,
                        components=components,
                    )

            sorted_components = sorted(components, key=lambda name: (len(name), name))
            top_components = sorted_components[:max_components]

            self._cache[cache_key] = (top_components, datetime.now(UTC))
            logger.info(
                f"Extracted {len(top_components)} component suggestions for prefix: {normalized_prefix}"
            )
            return top_components

        except requests.exceptions.RequestException as e:
            logger.error(f"NVD API request failed for component suggestions: {e}")
            return []
        except Exception as e:
            logger.error(f"Error extracting component suggestions from NVD: {e}")
            return []

    def _collect_component_names_from_nodes(
        self, nodes: list[dict[str, Any]], prefix: str, components: set[str]
    ) -> None:
        """Recursively collect matching component names from NVD configuration nodes."""
        for node in nodes:
            cpe_match = node.get("cpeMatch", [])
            if not isinstance(cpe_match, list):
                cpe_match = []

            cpe_match_list = cast(list[object], cpe_match)
            for match_item in cpe_match_list:
                if not isinstance(match_item, dict):
                    continue

                match = cast(dict[str, Any], match_item)
                cpe23uri = str(match.get("criteria", ""))
                if not cpe23uri:
                    continue

                # CPE format: cpe:2.3:part:vendor:product:version:...
                parts = cpe23uri.split(":")
                if len(parts) < 6:
                    continue

                product = str(parts[4]).strip().lower()
                if product and product not in {"*", "-"} and product.startswith(prefix):
                    components.add(product)

            child_nodes_raw = node.get("children", [])
            if isinstance(child_nodes_raw, list) and child_nodes_raw:
                child_nodes_raw_list = cast(list[object], child_nodes_raw)
                child_nodes: list[dict[str, Any]] = []
                for child_item in child_nodes_raw_list:
                    if isinstance(child_item, dict):
                        child_nodes.append(cast(dict[str, Any], child_item))
                self._collect_component_names_from_nodes(
                    nodes=child_nodes,
                    prefix=prefix,
                    components=components,
                )

    @staticmethod
    def _parse_version(version_str: str) -> tuple[int, ...]:
        """Parse version string for sorting.

        Converts "1.2.3" to (1, 2, 3) for proper numerical sorting.
        Falls back to string comparison for non-numeric versions.

        Args:
            version_str: Version string to parse

        Returns:
            Tuple of parsed version numbers for comparison
        """
        try:
            # Try to parse as dot-separated numbers
            parts = version_str.split(".")
            return tuple(int(p) if p.isdigit() else 0 for p in parts)
        except (ValueError, AttributeError):
            # Fallback to string comparison
            return (0,)
