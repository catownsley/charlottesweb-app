"""Metadata-driven compliance intelligence evaluator."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypedDict, cast

from src.models import MetadataProfile


class MetadataPayload(TypedDict, total=False):
    """Type definition for metadata profile payload."""

    phi_types: list[str]
    cloud_provider: str | None
    infrastructure: dict[str, Any]
    applications: dict[str, Any]
    access_controls: dict[str, Any]
    software_stack: dict[str, Any]


# Supported operators for rule evaluation
SUPPORTED_OPERATORS = {"equals", "gte"}


class ComplianceIntelligenceEvaluator:
    """Evaluate metadata profiles against machine-readable policy rules."""

    def __init__(self, policy_file: str | None = None) -> None:
        default_policy = (
            Path(__file__).parent / "policy_rules" / "hipaa_security_rule.v1.json"
        )
        self.policy_path = Path(policy_file) if policy_file else default_policy

    def evaluate(self, metadata: MetadataProfile) -> dict[str, Any]:
        """Run policy evaluation and return deterministic rule results."""
        policy = self._load_policy()

        # Build metadata payload - type documented by MetadataPayload TypedDict
        metadata_payload: dict[str, Any] = {
            "phi_types": cast(list[str], metadata.phi_types or []),
            "cloud_provider": cast(str | None, metadata.cloud_provider),
            "infrastructure": cast(dict[str, Any], metadata.infrastructure or {}),
            "applications": cast(dict[str, Any], metadata.applications or {}),
            "access_controls": cast(dict[str, Any], metadata.access_controls or {}),
            "software_stack": cast(dict[str, Any], metadata.software_stack or {}),
        }

        results: list[dict[str, Any]] = []
        passed = 0
        failed = 0

        for rule in policy["rules"]:
            actual = self._resolve_path(metadata_payload, rule["path"])
            is_pass = self._evaluate_operator(
                actual, rule["operator"], rule["expected"]
            )
            status = "pass" if is_pass else "fail"

            if is_pass:
                passed += 1
            else:
                failed += 1

            results.append(
                {
                    "rule_id": rule["rule_id"],
                    "control_id": rule["control_id"],
                    "title": rule["title"],
                    "description": rule.get("description"),
                    "path": rule["path"],
                    "operator": rule["operator"],
                    "expected": rule["expected"],
                    "actual": actual,
                    "status": status,
                    "severity_on_fail": rule["severity_on_fail"],
                }
            )

        return {
            "framework": policy["framework"],
            "policy_version": policy["policy_version"],
            "evaluated_at": datetime.now(UTC),
            "total_rules": len(results),
            "passed": passed,
            "failed": failed,
            "results": results,
        }

    def _load_policy(self) -> dict[str, Any]:
        with self.policy_path.open("r", encoding="utf-8") as file_obj:
            return json.load(file_obj)

    def _resolve_path(self, payload: dict[str, Any], path: str) -> Any:
        current: Any = payload
        for segment in path.split("."):
            if not isinstance(current, dict):
                return None
            typed_current = cast(dict[str, Any], current)
            current = typed_current.get(segment)
        return current

    def _evaluate_operator(self, actual: Any, operator: str, expected: Any) -> bool:
        """Evaluate actual value against expected using specified operator.

        Args:
            actual: The actual value from metadata
            operator: Comparison operator (equals, gte)
            expected: The expected value

        Returns:
            True if evaluation passes, False otherwise

        Raises:
            ValueError: If operator is not supported
        """
        match operator:
            case "equals":
                return actual == expected
            case "gte":
                if actual is None:
                    return False
                try:
                    return float(actual) >= float(expected)
                except (TypeError, ValueError):
                    return False
            case _:
                raise ValueError(
                    f"Unsupported operator: {operator}. "
                    f"Supported operators: {', '.join(SUPPORTED_OPERATORS)}"
                )
