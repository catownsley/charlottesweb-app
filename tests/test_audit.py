"""Tests for audit log hardening: caller slot lookup and log line scrubbing."""

import json
import logging

from src.audit import (
    AuditAction,
    _sanitize_details,
    log_audit_event,
    resolve_caller_slot,
)
from src.config import settings

KEY_ONE = "cw_live_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1111"
KEY_TWO = "cw_live_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb9876"


def test_resolve_caller_slot_returns_position_or_none(monkeypatch) -> None:
    monkeypatch.setattr(settings, "valid_api_keys", [KEY_ONE, KEY_TWO])
    assert resolve_caller_slot(KEY_ONE) == 1
    assert resolve_caller_slot(KEY_TWO) == 2
    assert resolve_caller_slot("cw_live_not_configured") is None


def test_sanitize_details_scrubs_nested_strings_and_keeps_scalars() -> None:
    details = {
        "name": "acme\ninjected line",
        "count": 3,
        "ok": True,
        "nested": {"k": "a\rb", "items": ["x\n", 1, None]},
    }
    cleaned = _sanitize_details(details)
    assert cleaned["name"] == "acme\\ninjected line"
    assert cleaned["count"] == 3
    assert cleaned["ok"] is True
    assert cleaned["nested"]["k"] == "a\\rb"
    assert cleaned["nested"]["items"] == ["x\\n", 1, None]


def test_log_audit_event_writes_one_line_without_key_material(
    caplog, monkeypatch
) -> None:
    monkeypatch.setattr(settings, "valid_api_keys", [KEY_ONE, KEY_TWO])
    with caplog.at_level(logging.INFO, logger="audit"):
        log_audit_event(
            action=AuditAction.DATA_UPDATED,
            api_key=KEY_TWO,
            user_id="user\n1",
            resource_type="evidence",
            resource_id="ev-1",
            details={"artifact_url_domain": 'evil.example\n{"forged": true}'},
        )
    records = [r for r in caplog.records if r.name == "audit"]
    assert len(records) == 1
    line = records[0].getMessage()
    assert "\n" not in line and "\r" not in line
    entry = json.loads(line)
    assert entry["caller_slot"] == 2
    assert "api_key_suffix" not in entry
    assert "9876" not in line
    assert "bbbb" not in line
    assert entry["user_id"] == "user\\n1"
    assert "forged" in entry["details"]["artifact_url_domain"]
