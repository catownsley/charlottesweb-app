"""NVD API integration for CVE vulnerability intelligence."""

import logging
import time
from datetime import UTC, datetime, timedelta
from typing import Any, TypedDict, cast

import requests

logger = logging.getLogger(__name__)


class NVDApiError(Exception):
    """Raised when the NVD API returns an error or is unreachable."""

    pass


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
REQUEST_TIMEOUT_SECONDS = 30
RATE_LIMIT_RETRY_ATTEMPTS = 3
RATE_LIMIT_BACKOFF_SECONDS = 6  # NVD rate limit resets every 30s; 6s * 3 retries = 18s

# Version filtering constants
MAX_VALID_SINGLE_DIGIT_VERSION = 50  # Filter out build numbers like 382, 3802

# CVSS severity thresholds
CVSS_CRITICAL_THRESHOLD = 9.0
CVSS_HIGH_THRESHOLD = 7.0
CVSS_MEDIUM_THRESHOLD = 4.0


class NVDService:
    """Service for querying NVD API for CVE information."""

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(
        self, api_key: str | None = None, max_retries: int = RATE_LIMIT_RETRY_ATTEMPTS
    ) -> None:
        """Initialize NVD service.

        Args:
            api_key: NVD API key for higher rate limits (optional)
            max_retries: Number of retry attempts on rate limit (0 to disable retries)
        """
        self.api_key = api_key
        self.max_retries = max_retries
        self.headers: dict[str, str] = {}
        if api_key:
            self.headers["apiKey"] = api_key

        # Simple in-memory cache (in production, use Redis)
        self._cache: dict[str, tuple[list[CVEResult] | list[str], datetime]] = {}
        self._cache_ttl = timedelta(hours=CACHE_TTL_HOURS)

    def _request_with_retry(self, params: dict[str, str | int]) -> dict[str, Any]:
        """Make an NVD API request with retry on rate limit (429).

        Retries up to self.max_retries times with backoff.
        Raises NVDApiError on persistent failure so callers can handle it.
        """
        last_error: Exception | None = None
        attempts = max(self.max_retries, 1)

        for attempt in range(attempts):
            try:
                response = requests.get(
                    self.BASE_URL,
                    params=params,
                    headers=self.headers,
                    timeout=REQUEST_TIMEOUT_SECONDS,
                )

                if response.status_code == 429:
                    wait = RATE_LIMIT_BACKOFF_SECONDS * (attempt + 1)
                    logger.warning(
                        "NVD rate limit hit (attempt %d/%d), retrying in %ds",
                        attempt + 1,
                        attempts,
                        wait,
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
                    e,
                )
                if attempt < attempts - 1:
                    time.sleep(RATE_LIMIT_BACKOFF_SECONDS)

        raise NVDApiError(f"NVD API failed after {attempts} attempts: {last_error}")

    # Common CPE naming mismatches: user-friendly names → NVD vendor:product
    _CPE_ALIASES: dict[str, list[tuple[str, str, str]]] = {
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
        "node": [("a", "*", "node.js")],
        "nodejs": [("a", "*", "node.js")],
        "node.js": [("a", "*", "node.js")],
    }

    @staticmethod
    def _parse_cve_to_result(cve: dict[str, Any]) -> CVEResult:
        """Parse a single NVD CVE dict into a CVEResult."""
        descriptions = cve.get("descriptions", [])
        description = descriptions[0].get("value", "") if descriptions else ""

        metrics = cve.get("metrics", {})
        cvss_score: float | None = None
        cvss_severity: str | None = None
        for metric_ver in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if metric_ver in metrics and metrics[metric_ver]:
                cvss_data = metrics[metric_ver][0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_severity = cvss_data.get("baseSeverity", "").lower()
                break

        cwe_ids: list[str] = []
        for weakness in cve.get("weaknesses", []):
            for desc in weakness.get("description", []):
                cwe_value = desc.get("value", "")
                if cwe_value.startswith("CWE-"):
                    cwe_ids.append(cwe_value)

        return CVEResult(
            cve_id=cve.get("id", ""),
            description=description,
            cvss_score=cvss_score,
            cvss_severity=cvss_severity,
            cwe_ids=list(set(cwe_ids)),
            published_date=cve.get("published", ""),
        )

    @staticmethod
    def _version_candidates(version: str) -> list[str]:
        """Generate version strings to try against NVD CPE entries."""
        candidates = [version]
        if version.count(".") == 1:
            candidates.append(f"{version}.0")
        elif version.count(".") == 0 and version.replace(".", "").isdigit():
            candidates.append(f"{version}.0.0")
        return candidates

    def _search_by_cpe(
        self, component: str, version: str, max_results: int
    ) -> list[CVEResult]:
        """Search NVD for CVEs matching a specific component and version via CPE."""
        ver_candidates = self._version_candidates(version)
        comp_lower = component.lower()
        cpe_candidates = self._CPE_ALIASES.get(comp_lower, [("a", "*", comp_lower)])

        cache_key = f"cpe:{comp_lower}:{version}:{max_results}"
        if cache_key in self._cache:
            cached_data, cached_time = self._cache[cache_key]
            if datetime.now(UTC) - cached_time < self._cache_ttl:
                logger.info("CPE cache hit for %s %s", component, version)
                return cached_data  # type: ignore[return-value]

        for cpe_type, cpe_vendor, cpe_product in cpe_candidates:
            for ver_candidate in ver_candidates:
                cpe_match = f"cpe:2.3:{cpe_type}:{cpe_vendor}:{cpe_product}:{ver_candidate}:*:*:*:*:*:*:*"
                params: dict[str, str | int] = {
                    "virtualMatchString": cpe_match,
                    "resultsPerPage": max_results,
                }

                try:
                    data = self._request_with_retry(params)
                except NVDApiError:
                    continue

                vulnerabilities = data.get("vulnerabilities", [])
                if not vulnerabilities:
                    continue

                results = [
                    self._parse_cve_to_result(vuln.get("cve", {}))
                    for vuln in vulnerabilities
                ]
                self._cache[cache_key] = (results, datetime.now(UTC))
                logger.info(
                    "CPE search found %d CVEs for %s %s",
                    len(results),
                    component,
                    ver_candidate,
                )
                return results

        logger.info(
            "No CPE results for %s %s, falling back to keyword",
            component,
            version,
        )
        return []

    def _cve_affects_version(
        self, cve_data: dict[str, Any], component: str, user_version: str
    ) -> bool:
        """Check if a CVE affects a specific component version.

        Inspects CPE match entries for the component and checks whether
        the user's version falls within any affected range.

        Args:
            cve_data: Raw CVE object from NVD API
            component: Component name (lowercase)
            user_version: User-specified version string

        Returns:
            True if the CVE affects the given version (or cannot be determined)
        """
        user_parts = self._parse_version(user_version)
        configurations = cve_data.get("configurations", [])

        # If no configuration data, assume it could affect any version
        if not configurations:
            return True

        for config in configurations:
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    cpe = match.get("criteria", "")
                    parts = cpe.split(":")
                    if len(parts) < 6:
                        continue

                    # Only check CPE entries for this component
                    cpe_product = parts[4].lower()
                    if cpe_product != component:
                        continue

                    # Check exact version match in CPE URI
                    cpe_version = parts[5]
                    if cpe_version not in ("*", "-", ""):
                        if self._parse_version(cpe_version) == user_parts:
                            return True

                    # Check version ranges
                    v_start_inc = match.get("versionStartIncluding")
                    v_start_exc = match.get("versionStartExcluding")
                    v_end_inc = match.get("versionEndIncluding")
                    v_end_exc = match.get("versionEndExcluding")

                    # If no range constraints at all and wildcard version,
                    # this CPE matches all versions of the product
                    if cpe_version in ("*", "-") and not any(
                        [v_start_inc, v_start_exc, v_end_inc, v_end_exc]
                    ):
                        return True

                    # Check if user version falls within the range
                    in_range = True
                    if v_start_inc:
                        in_range = in_range and user_parts >= self._parse_version(
                            v_start_inc
                        )
                    if v_start_exc:
                        in_range = in_range and user_parts > self._parse_version(
                            v_start_exc
                        )
                    if v_end_inc:
                        in_range = in_range and user_parts <= self._parse_version(
                            v_end_inc
                        )
                    if v_end_exc:
                        in_range = in_range and user_parts < self._parse_version(
                            v_end_exc
                        )

                    if in_range and any(
                        [v_start_inc, v_start_exc, v_end_inc, v_end_exc]
                    ):
                        return True

        return False

    def search_cves_by_keyword(
        self,
        keyword: str,
        max_results: int = DEFAULT_MAX_RESULTS,
        version: str | None = None,
    ) -> list[CVEResult]:
        """Search for CVEs by keyword (e.g., product name).

        Args:
            keyword: Search term (e.g., "postgresql", "nginx")
            max_results: Maximum number of results to return
            version: If provided, filter results to CVEs affecting this version

        Returns:
            List of CVE dictionaries with id, description, cvss, cwe

        Raises:
            NVDApiError: If the NVD API is unreachable after retries.
        """
        # When a version is provided, use NVD's virtualMatchString API to
        # search for CVEs by CPE, which targets the exact product+version.
        # Falls back to keyword search if no CPE results are found.
        if version:
            cpe_results = self._search_by_cpe(keyword, version, max_results)
            if cpe_results:
                return cpe_results

        fetch_count = max_results
        cache_key = f"keyword:{keyword}:{fetch_count}"

        # Check cache
        if cache_key in self._cache:
            cached_data, cached_time = self._cache[cache_key]
            if datetime.now(UTC) - cached_time < self._cache_ttl:
                logger.info("Cache hit for keyword: %s", keyword)
                cached_results: list[CVEResult] = cached_data[0]  # type: ignore[assignment]
                return cached_results[:max_results]

        params: dict[str, str | int] = {
            "keywordSearch": keyword,
            "resultsPerPage": fetch_count,
        }

        # Let NVDApiError propagate so callers know the API failed
        data = self._request_with_retry(params)
        vulnerabilities = data.get("vulnerabilities", [])

        results: list[CVEResult] = []
        raw_cve_data: list[dict[str, Any]] = []
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
            for metric_ver in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if metric_ver in metrics and metrics[metric_ver]:
                    cvss_data = metrics[metric_ver][0].get("cvssData", {})
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
            raw_cve_data.append(cve)

        # Cache both parsed results and raw data for version filtering
        self._cache[cache_key] = ((results, raw_cve_data), datetime.now(UTC))
        logger.info("Fetched %d CVEs for keyword: %s", len(results), keyword)

        if version:
            return self._filter_cves_by_version(
                results, raw_cve_data, keyword, version, max_results
            )
        return results[:max_results]

    def _filter_cves_by_version(
        self,
        results: list[CVEResult],
        raw_cve_data: list[dict[str, Any]],
        component: str,
        version: str,
        max_results: int,
    ) -> list[CVEResult]:
        """Filter CVE results to only those affecting the specified version."""
        filtered: list[CVEResult] = []
        component_lower = component.lower()
        for cve_result, raw_cve in zip(results, raw_cve_data, strict=False):
            if self._cve_affects_version(raw_cve, component_lower, version):
                filtered.append(cve_result)
                if len(filtered) >= max_results:
                    break
        logger.info(
            "Version filter: %d/%d CVEs match %s %s",
            len(filtered),
            len(results),
            component,
            version,
        )
        return filtered

    def analyze_software_stack(
        self, software_stack: dict[str, str]
    ) -> dict[str, list[CVEResult]]:
        """Analyze a software stack for known vulnerabilities.

        Args:
            software_stack: Dictionary of component: version pairs
                Example: {"postgresql": "13.2", "nginx": "1.19.0", "python": "3.9.5"}

        Returns:
            Dictionary mapping component names to lists of CVEs

        Raises:
            NVDApiError: If the NVD API is unreachable for any component.
                Partial results are not returned; the caller should show
                the error to the user rather than displaying empty results.
        """
        results: dict[str, list[CVEResult]] = {}
        failed_components: list[str] = []

        for component, version in software_stack.items():
            # Search NVD by component name, then filter results to only CVEs
            # whose CPE version ranges actually affect the user's version.
            try:
                cves = self.search_cves_by_keyword(
                    component, max_results=5, version=version
                )
            except NVDApiError:
                failed_components.append(component)
                logger.error("NVD API failed for component: %s", component)
                continue

            if cves:
                results[component] = cves
                logger.info(
                    "Found %d CVEs for %s (version %s)",
                    len(cves),
                    component,
                    version,
                )

        if failed_components and not results:
            raise NVDApiError(
                f"NVD API unavailable. Failed to analyze: {', '.join(failed_components)}. "
                "This may be due to rate limiting. Try again in a few minutes, "
                "or configure an NVD API key for higher rate limits."
            )

        if failed_components:
            logger.warning(
                "Partial NVD results: %d components failed (%s), %d succeeded",
                len(failed_components),
                ", ".join(failed_components),
                len(results),
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

    @staticmethod
    def _extract_versions_from_vulns(
        vulnerabilities: list[dict[str, Any]], component_name: str
    ) -> set[str]:
        """Extract unique version strings from NVD vulnerability data."""
        versions_set: set[str] = set()
        for vuln in vulnerabilities:
            cve = vuln.get("cve", {})
            for config in cve.get("configurations", []):
                for node in config.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        cpe23uri = match.get("criteria", "")
                        if cpe23uri:
                            parts = cpe23uri.split(":")
                            if len(parts) >= 6:
                                if parts[4].lower() != component_name:
                                    continue
                                version = parts[5]
                                if version and version not in ("*", "-", ""):
                                    if "." in version or (
                                        version.isdigit()
                                        and int(version)
                                        <= MAX_VALID_SINGLE_DIGIT_VERSION
                                    ):
                                        versions_set.add(version)
                        for range_key in (
                            "versionStartIncluding",
                            "versionEndIncluding",
                        ):
                            range_ver = match.get(range_key)
                            if range_ver:
                                versions_set.add(range_ver)
        return versions_set

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
                logger.info("Cache hit for component versions: %s", component_name)
                return cached_data  # type: ignore[return-value]

        try:
            # CPE product names use underscores (e.g., "sql_server") but NVD
            # keyword search matches description text which uses spaces.
            search_term = component_name.replace("_", " ")
            params: dict[str, str | int] = {
                "keywordSearch": search_term,
                "resultsPerPage": VERSION_SEARCH_MAX_RESULTS,
            }

            data = self._request_with_retry(params)
            vulnerabilities = data.get("vulnerabilities", [])

            versions_set = self._extract_versions_from_vulns(
                vulnerabilities, component_name
            )

            # Sort versions (try numeric sort, fallback to string sort)
            sorted_versions = sorted(
                list(versions_set), key=self._parse_version, reverse=True
            )
            top_versions = sorted_versions[:max_versions]

            # Cache results
            self._cache[cache_key] = (top_versions, datetime.now(UTC))
            logger.info(
                "Extracted %d versions for %s from NVD",
                len(top_versions),
                component_name,
            )
            return top_versions

        except NVDApiError:
            logger.error("NVD API unavailable for version lookup: %s", component_name)
            return []
        except Exception as e:
            logger.error("Error extracting versions from NVD: %s", e)
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
                logger.info(
                    "Cache hit for component suggestions: %s", normalized_prefix
                )
                return cached_data  # type: ignore[return-value]

        try:
            params: dict[str, str | int] = {
                "keywordSearch": normalized_prefix,
                "resultsPerPage": VERSION_SEARCH_MAX_RESULTS,
            }
            data = self._request_with_retry(params)
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
                "Extracted %d component suggestions for prefix: %s",
                len(top_components),
                normalized_prefix,
            )
            return top_components

        except NVDApiError:
            logger.error(
                "NVD API unavailable for component suggestions: %s",
                normalized_prefix,
            )
            return []
        except Exception as e:
            logger.error("Error extracting component suggestions from NVD: %s", e)
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
