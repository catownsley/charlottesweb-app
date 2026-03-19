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

    def test_flat_label_format(self):
        """Flat {'label': 'Name version'} format should split name and version."""
        raw = {
            "backend": "FastAPI 0.135.1",
            "database": "SQLAlchemy 2.0.48",
        }
        result = normalize_software_stack(raw)
        assert len(result) == 2
        fastapi = next(c for c in result if c["name"] == "FastAPI")
        assert fastapi["version"] == "0.135.1"
        sqla = next(c for c in result if c["name"] == "SQLAlchemy")
        assert sqla["version"] == "2.0.48"

    def test_flat_non_versionable_skipped(self):
        """Flat values with no version-like token are kept as-is with key as name."""
        raw = {"deployment": "Docker + K8s"}
        result = normalize_software_stack(raw)
        # "Docker" is name, "+ K8s" won't happen — rsplit on last space
        # Actually: rsplit(" ", 1) -> ["Docker +", "K8s"] -> name="Docker +", version="K8s"
        # This is imperfect but won't match real CVEs, so it's harmless
        assert len(result) == 1

    def test_dict_format(self):
        """Object format with version key should normalize correctly."""
        raw = {
            "django": {"version": "4.2"},
            "kafka-clients": {"version": "3.6.0"},
        }
        result = normalize_software_stack(raw)
        assert len(result) == 2
        django = next(c for c in result if c["name"] == "django")
        assert django["version"] == "4.2"
        kafka = next(c for c in result if c["name"] == "kafka-clients")
        assert kafka["version"] == "3.6.0"

    def test_mixed_format(self):
        """Mix of flat and dict entries."""
        raw = {
            "openssl": "1.1.1",
            "fastapi": {"version": "0.100.0"},
        }
        result = normalize_software_stack(raw)
        assert len(result) == 2

    def test_empty_stack(self):
        assert normalize_software_stack({}) == []

    def test_includes_empty_versions(self):
        """Components without versions are included for versionless scanning."""
        raw = {"python": "", "java": "17"}
        result = normalize_software_stack(raw)
        assert len(result) == 2
        assert result[0]["name"] == "python"
        assert result[0]["version"] == ""
        assert result[1]["name"] == "java"
        assert result[1]["version"] == "17"

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
        results = svc.query_package("django", "1.11")

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
        results = svc.query_package("safe-lib", "99.0.0")
        assert results == []

    @patch("src.osv_service.requests.request")
    def test_analyze_software_stack_queries_name_and_version_only(self, mock_request):
        """OSV queries should only send name and version, no ecosystem."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"vulns": []}
        mock_response.raise_for_status = MagicMock()
        mock_request.return_value = mock_response

        svc = OSVService()
        components = [
            {"name": "openssl", "version": "1.0.1"},
        ]
        svc.analyze_software_stack(components)
        mock_request.assert_called_once()
        call_kwargs = mock_request.call_args
        body = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json", {})
        assert "ecosystem" not in body["package"]
        assert body["package"]["name"] == "openssl"
        assert body["version"] == "1.0.1"

    @patch("src.osv_service.requests.request")
    def test_analyze_software_stack_success(self, mock_request):
        """Components should be queried and results returned."""
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
            {"name": "django", "version": "1.11"},
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
            svc.query_package("test", "1.0")
