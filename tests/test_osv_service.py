"""Tests for OSV service and related utilities."""

from unittest.mock import MagicMock, patch

import pytest

from src.osv_service import OSVApiError, OSVService, parse_cvss_v3_score
from src.rules_engine import normalize_software_stack

# ========== CVSS Parser Tests ==========


class TestCVSSParser:
    """Test CVSS v3 vector string → numeric score parsing."""

    def test_critical_score(self):
        """CVSS:3.1 all-high vector should produce 10.0."""
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        score = parse_cvss_v3_score(vector)
        assert score == 10.0

    def test_high_score(self):
        """Classic network/no-auth RCE should be high severity."""
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        score = parse_cvss_v3_score(vector)
        assert score is not None
        assert score >= 9.0

    def test_medium_score(self):
        """Requires user interaction and local access → medium range."""
        vector = "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N"
        score = parse_cvss_v3_score(vector)
        assert score is not None
        assert 0.0 < score < 7.0

    def test_zero_impact(self):
        """No impact = 0.0 score."""
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
        score = parse_cvss_v3_score(vector)
        assert score == 0.0

    def test_v30_prefix(self):
        """CVSS:3.0 prefix should also be accepted."""
        vector = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        score = parse_cvss_v3_score(vector)
        assert score is not None
        assert score >= 9.0

    def test_invalid_prefix(self):
        """Non-v3 prefix returns None."""
        assert parse_cvss_v3_score("CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C") is None

    def test_empty_string(self):
        assert parse_cvss_v3_score("") is None

    def test_none(self):
        assert parse_cvss_v3_score(None) is None

    def test_missing_metrics(self):
        """Incomplete vector returns None."""
        assert parse_cvss_v3_score("CVSS:3.1/AV:N/AC:L") is None


# ========== normalize_software_stack Tests ==========


class TestNormalizeSoftwareStack:
    """Test the backward-compatible software stack normalizer."""

    def test_legacy_flat_format(self):
        """Flat {'name': 'version'} format should normalize correctly."""
        raw = {"python": "3.11", "postgres": "15"}
        result = normalize_software_stack(raw)
        assert len(result) == 2
        names = {c["name"] for c in result}
        assert "python" in names
        assert "postgres" in names
        # Legacy format has no ecosystem
        for c in result:
            assert c["ecosystem"] == ""

    def test_ecosystem_aware_format(self):
        """Object format with version+ecosystem should normalize correctly."""
        raw = {
            "django": {"version": "4.2", "ecosystem": "PyPI"},
            "kafka-clients": {"version": "3.6.0", "ecosystem": "Maven"},
        }
        result = normalize_software_stack(raw)
        assert len(result) == 2
        django = next(c for c in result if c["name"] == "django")
        assert django["version"] == "4.2"
        assert django["ecosystem"] == "PyPI"
        kafka = next(c for c in result if c["name"] == "kafka-clients")
        assert kafka["version"] == "3.6.0"
        assert kafka["ecosystem"] == "Maven"

    def test_mixed_format(self):
        """Mix of legacy and ecosystem-aware entries."""
        raw = {
            "openssl": "1.1.1",
            "fastapi": {"version": "0.100.0", "ecosystem": "PyPI"},
        }
        result = normalize_software_stack(raw)
        assert len(result) == 2

    def test_empty_stack(self):
        assert normalize_software_stack({}) == []

    def test_skips_empty_versions(self):
        raw = {"python": "", "java": "17"}
        result = normalize_software_stack(raw)
        assert len(result) == 1
        assert result[0]["name"] == "java"

    def test_skips_blank_names(self):
        raw = {"": "1.0", "  ": "2.0"}
        result = normalize_software_stack(raw)
        assert len(result) == 0


# ========== OSVService Tests ==========


class TestOSVService:
    """Test OSV service methods with mocked HTTP."""

    def test_severity_from_cvss(self):
        svc = OSVService()
        assert svc.get_severity_from_cvss(10.0) == "critical"
        assert svc.get_severity_from_cvss(9.0) == "critical"
        assert svc.get_severity_from_cvss(8.5) == "high"
        assert svc.get_severity_from_cvss(7.0) == "high"
        assert svc.get_severity_from_cvss(5.0) == "medium"
        assert svc.get_severity_from_cvss(4.0) == "medium"
        assert svc.get_severity_from_cvss(2.0) == "low"
        assert svc.get_severity_from_cvss(None) == "medium"

    def test_priority_window_from_cvss(self):
        svc = OSVService()
        assert svc.get_priority_window_from_cvss(9.0) == "immediate"
        assert svc.get_priority_window_from_cvss(7.0) == "immediate"
        assert svc.get_priority_window_from_cvss(5.0) == "30_days"
        assert svc.get_priority_window_from_cvss(2.0) == "quarterly"
        assert svc.get_priority_window_from_cvss(None) == "quarterly"

    @patch("src.osv_service.requests.request")
    def test_query_package_returns_parsed_vulns(self, mock_request):
        """Mocked OSV response should be parsed into VulnerabilityResult list."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulns": [
                {
                    "id": "GHSA-test-1234",
                    "aliases": ["CVE-2024-99999"],
                    "summary": "Test vulnerability",
                    "details": "Detailed description of test vuln.",
                    "published": "2024-01-15T00:00:00Z",
                    "severity": [
                        {
                            "type": "CVSS_V3",
                            "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        }
                    ],
                    "database_specific": {"cwe_ids": ["CWE-79"]},
                    "affected": [
                        {
                            "ranges": [
                                {
                                    "type": "ECOSYSTEM",
                                    "events": [
                                        {"introduced": "0"},
                                        {"fixed": "2.0.1"},
                                    ],
                                }
                            ]
                        }
                    ],
                }
            ]
        }
        mock_response.raise_for_status = MagicMock()
        mock_request.return_value = mock_response

        svc = OSVService()
        results = svc.query_package("django", "PyPI", "1.11")

        assert len(results) == 1
        r = results[0]
        assert r["vuln_id"] == "GHSA-test-1234"
        assert "CVE-2024-99999" in r["aliases"]
        assert r["cvss_score"] is not None
        assert r["cvss_score"] >= 9.0
        assert r["fixed_versions"] == ["2.0.1"]
        assert "CWE-79" in r["cwe_ids"]

    @patch("src.osv_service.requests.request")
    def test_query_package_no_vulns(self, mock_request):
        """Clean package should return empty list."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {}
        mock_response.raise_for_status = MagicMock()
        mock_request.return_value = mock_response

        svc = OSVService()
        results = svc.query_package("safe-lib", "PyPI", "99.0.0")
        assert results == []

    @patch("src.osv_service.requests.request")
    def test_analyze_software_stack_skips_no_ecosystem(self, mock_request):
        """Components without ecosystem should be skipped."""
        svc = OSVService()
        components = [
            {"name": "openssl", "version": "1.0.1", "ecosystem": ""},
        ]
        results = svc.analyze_software_stack(components)
        assert results == {}
        mock_request.assert_not_called()

    @patch("src.osv_service.requests.request")
    def test_analyze_software_stack_success(self, mock_request):
        """Components with ecosystem should be queried."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulns": [
                {
                    "id": "PYSEC-2024-001",
                    "aliases": [],
                    "summary": "Test",
                    "details": "",
                    "published": "2024-01-01",
                    "severity": [],
                    "affected": [],
                }
            ]
        }
        mock_response.raise_for_status = MagicMock()
        mock_request.return_value = mock_response

        svc = OSVService()
        components = [
            {"name": "django", "version": "1.11", "ecosystem": "PyPI"},
        ]
        results = svc.analyze_software_stack(components)
        assert "django@1.11" in results
        assert len(results["django@1.11"]) == 1

    @patch("src.osv_service.requests.request")
    def test_api_error_raises(self, mock_request):
        """500 errors should raise OSVApiError after retries."""
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        mock_request.return_value = mock_response

        svc = OSVService(max_retries=1)
        with pytest.raises(OSVApiError):
            svc.query_package("test", "PyPI", "1.0")
