"""NVD API integration for CVE vulnerability intelligence."""
import logging
from typing import Any, Optional
from datetime import datetime, timedelta
import requests

logger = logging.getLogger(__name__)


class NVDService:
    """Service for querying NVD API for CVE information."""

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def __init__(self, api_key: Optional[str] = None):
        """Initialize NVD service.
        
        Args:
            api_key: NVD API key for higher rate limits (optional)
        """
        self.api_key = api_key
        self.headers = {}
        if api_key:
            self.headers["apiKey"] = api_key
        
        # Simple in-memory cache (in production, use Redis)
        self._cache: dict[str, Any] = {}
        self._cache_ttl = timedelta(hours=24)
    
    def search_cves_by_keyword(self, keyword: str, max_results: int = 10) -> list[dict]:
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
            if datetime.utcnow() - cached_time < self._cache_ttl:
                logger.info(f"Cache hit for keyword: {keyword}")
                return cached_data
        
        try:
            params = {
                "keywordSearch": keyword,
                "resultsPerPage": max_results,
            }
            
            response = requests.get(
                self.BASE_URL,
                params=params,
                headers=self.headers,
                timeout=10,
            )
            response.raise_for_status()
            
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            
            results = []
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
                cvss_score = None
                cvss_severity = None
                
                # Try CVSS v3.1 first, then v3.0, then v2.0
                for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if version in metrics and metrics[version]:
                        cvss_data = metrics[version][0].get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore")
                        cvss_severity = cvss_data.get("baseSeverity", "").lower()
                        break
                
                # Extract CWE IDs
                weaknesses = cve.get("weaknesses", [])
                cwe_ids = []
                for weakness in weaknesses:
                    for desc in weakness.get("description", []):
                        cwe_value = desc.get("value", "")
                        if cwe_value.startswith("CWE-"):
                            cwe_ids.append(cwe_value)
                
                results.append({
                    "cve_id": cve_id,
                    "description": description,
                    "cvss_score": cvss_score,
                    "cvss_severity": cvss_severity,
                    "cwe_ids": list(set(cwe_ids)),  # Deduplicate
                    "published_date": cve.get("published", ""),
                })
            
            # Cache results
            self._cache[cache_key] = (results, datetime.utcnow())
            logger.info(f"Fetched {len(results)} CVEs for keyword: {keyword}")
            return results
            
        except requests.exceptions.RequestException as e:
            logger.error(f"NVD API request failed: {e}")
            return []
        except Exception as e:
            logger.error(f"Error processing NVD response: {e}")
            return []
    
    def analyze_software_stack(self, software_stack: dict[str, str]) -> dict[str, list[dict]]:
        """Analyze a software stack for known vulnerabilities.
        
        Args:
            software_stack: Dictionary of component: version pairs
                Example: {"postgresql": "13.2", "nginx": "1.19.0", "python": "3.9.5"}
        
        Returns:
            Dictionary mapping component names to lists of CVEs
        """
        results = {}
        
        for component, version in software_stack.items():
            # Search for CVEs mentioning this component
            # NOTE: Search by component name only, not version string
            # NVD API uses AND logic for multiple keywords, so "java 21" searches for CVEs
            # mentioning BOTH java AND "21", which is too restrictive.
            # Instead, search for component name alone to get all CVEs affecting that component.
            search_term = component  # Just component name, no version
            cves = self.search_cves_by_keyword(search_term, max_results=5)
            
            if cves:
                results[component] = cves
                logger.info(f"Found {len(cves)} CVEs for {component} (version {version})")
        
        return results
    
    def get_severity_from_cvss(self, cvss_score: Optional[float]) -> str:
        """Convert CVSS score to severity level.
        
        Args:
            cvss_score: CVSS base score (0.0-10.0)
            
        Returns:
            Severity level: critical, high, medium, low
        """
        if cvss_score is None:
            return "medium"
        
        if cvss_score >= 9.0:
            return "critical"
        elif cvss_score >= 7.0:
            return "high"
        elif cvss_score >= 4.0:
            return "medium"
        else:
            return "low"
    
    def get_priority_window_from_cvss(self, cvss_score: Optional[float]) -> str:
        """Determine remediation priority window based on CVSS score.
        
        Args:
            cvss_score: CVSS base score (0.0-10.0)
            
        Returns:
            Priority window: immediate, 30_days, quarterly, annual
        """
        if cvss_score is None:
            return "quarterly"
        
        if cvss_score >= 9.0:
            return "immediate"
        elif cvss_score >= 7.0:
            return "immediate"
        elif cvss_score >= 4.0:
            return "30_days"
        else:
            return "quarterly"
