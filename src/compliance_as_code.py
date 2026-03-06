"""Metadata-driven compliance-as-code evaluator."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.models import MetadataProfile


class ComplianceAsCodeEvaluator:
    """Evaluate metadata profiles against machine-readable policy rules."""

    def __init__(self, policy_file: str | None = None) -> None:
        default_policy = Path(__file__).parent / "policy_rules" / "hipaa_security_rule.v1.json"
        self.policy_path = Path(policy_file) if policy_file else default_policy

    def evaluate(self, metadata: MetadataProfile) -> dict[str, Any]:
        """Run policy evaluation and return deterministic rule results."""
        policy = self._load_policy()

        metadata_payload = {
            "phi_types": metadata.phi_types or [],
            "cloud_provider": metadata.cloud_provider,
            "infrastructure": metadata.infrastructure or {},
            "applications": metadata.applications or {},
            "access_controls": metadata.access_controls or {},
            "software_stack": metadata.software_stack or {},
        }

        results: list[dict[str, Any]] = []
        passed = 0
        failed = 0

        for rule in policy["rules"]:
            actual = self._resolve_path(metadata_payload, rule["path"])
            is_pass = self._evaluate_operator(actual, rule["operator"], rule["expected"])
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
            "evaluated_at": datetime.now(timezone.utc),
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
            current = current.get(segment)
        return current

    def _evaluate_operator(self, actual: Any, operator: str, expected: Any) -> bool:
        if operator == "equals":
            return actual == expected
        if operator == "gte":
            if actual is None:
                return False
            try:
                return float(actual) >= float(expected)
            except (TypeError, ValueError):
                return False
        raise ValueError(f"Unsupported operator: {operator}")
