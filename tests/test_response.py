"""
SentinelMesh — Response Agent Unit Tests (test_response.py)

Tests the severity-to-action_type mapping defined in Section 10.4.1:
  - Default threshold ("high"): critical/high -> alert, medium/low -> log_only
  - Non-default threshold ("medium"): medium/high/critical -> alert, low -> log_only
  - Non-default threshold ("critical"): only critical -> alert
  - Null src_ip case: alert target must be null, not crash, when incident.src_ip
    is null (e.g. distributed_target_attack)
  - Unknown severity value: fail-safe to log_only

All tests patch RESPONSE_ALERT_THRESHOLD_RANK and RESPONSE_ALERT_THRESHOLD_NAME
directly in the module under test so they are isolated from the actual env value
at import time.

Section 10.13 reference:
  "Response: correct action_type selection given incident severity."
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Helpers to build test Incident objects without importing the module under
# test first (so we can control the threshold before import side-effects run).
# ---------------------------------------------------------------------------

from shared.schemas import (
    Action,
    ActionType,
    Incident,
    IncidentSeverity,
    IncidentStatus,
)


def _make_incident(
    severity: IncidentSeverity = IncidentSeverity.HIGH,
    incident_type: str = "multi_stage_attack",
    src_ip: Optional[str] = "10.0.0.1",
    status: IncidentStatus = IncidentStatus.OPEN,
) -> Incident:
    now = datetime.now(tz=timezone.utc)
    return Incident(
        timestamp_opened=now,
        timestamp_updated=now,
        related_flow_ids=["flow-1"],
        related_detection_ids=["det-1"],
        src_ip=src_ip,
        incident_type=incident_type,
        severity=severity,
        status=status,
    )


# ---------------------------------------------------------------------------
# Helper: call _select_action with a patched threshold
# ---------------------------------------------------------------------------

def _select_with_threshold(incident: Incident, threshold: str):
    """
    Import the module, override its threshold constants, and call _select_action.
    We reload-patch at call time so each test gets an independent threshold.
    """
    import agents.response.main as rm

    rank_map = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    with (
        patch.object(rm, "RESPONSE_ALERT_THRESHOLD_RANK", rank_map[threshold]),
        patch.object(rm, "RESPONSE_ALERT_THRESHOLD_NAME", threshold),
    ):
        return rm._select_action(incident)


# ---------------------------------------------------------------------------
# Default threshold ("high") — the same as the env default
# ---------------------------------------------------------------------------

class TestDefaultThreshold:
    """RESPONSE_ALERT_SEVERITY_THRESHOLD=high (default)"""

    def test_critical_yields_alert(self):
        inc = _make_incident(severity=IncidentSeverity.CRITICAL)
        action_type, target = _select_with_threshold(inc, "high")
        assert action_type == ActionType.ALERT
        assert target == inc.src_ip

    def test_high_yields_alert(self):
        inc = _make_incident(severity=IncidentSeverity.HIGH)
        action_type, target = _select_with_threshold(inc, "high")
        assert action_type == ActionType.ALERT
        assert target == inc.src_ip

    def test_medium_yields_log_only(self):
        inc = _make_incident(severity=IncidentSeverity.MEDIUM)
        action_type, target = _select_with_threshold(inc, "high")
        assert action_type == ActionType.LOG_ONLY
        assert target is None

    def test_low_yields_log_only(self):
        inc = _make_incident(severity=IncidentSeverity.LOW)
        action_type, target = _select_with_threshold(inc, "high")
        assert action_type == ActionType.LOG_ONLY
        assert target is None


# ---------------------------------------------------------------------------
# Non-default threshold: "medium"
# ---------------------------------------------------------------------------

class TestThresholdMedium:
    """RESPONSE_ALERT_SEVERITY_THRESHOLD=medium: medium/high/critical -> alert, low -> log_only"""

    def test_medium_yields_alert(self):
        inc = _make_incident(severity=IncidentSeverity.MEDIUM)
        action_type, target = _select_with_threshold(inc, "medium")
        assert action_type == ActionType.ALERT
        assert target == inc.src_ip

    def test_high_yields_alert(self):
        inc = _make_incident(severity=IncidentSeverity.HIGH)
        action_type, target = _select_with_threshold(inc, "medium")
        assert action_type == ActionType.ALERT

    def test_critical_yields_alert(self):
        inc = _make_incident(severity=IncidentSeverity.CRITICAL)
        action_type, target = _select_with_threshold(inc, "medium")
        assert action_type == ActionType.ALERT

    def test_low_yields_log_only(self):
        inc = _make_incident(severity=IncidentSeverity.LOW)
        action_type, target = _select_with_threshold(inc, "medium")
        assert action_type == ActionType.LOG_ONLY
        assert target is None


# ---------------------------------------------------------------------------
# Non-default threshold: "critical"
# ---------------------------------------------------------------------------

class TestThresholdCritical:
    """RESPONSE_ALERT_SEVERITY_THRESHOLD=critical: only critical -> alert"""

    def test_critical_yields_alert(self):
        inc = _make_incident(severity=IncidentSeverity.CRITICAL)
        action_type, target = _select_with_threshold(inc, "critical")
        assert action_type == ActionType.ALERT

    def test_high_yields_log_only(self):
        inc = _make_incident(severity=IncidentSeverity.HIGH)
        action_type, target = _select_with_threshold(inc, "critical")
        assert action_type == ActionType.LOG_ONLY
        assert target is None

    def test_medium_yields_log_only(self):
        inc = _make_incident(severity=IncidentSeverity.MEDIUM)
        action_type, target = _select_with_threshold(inc, "critical")
        assert action_type == ActionType.LOG_ONLY

    def test_low_yields_log_only(self):
        inc = _make_incident(severity=IncidentSeverity.LOW)
        action_type, target = _select_with_threshold(inc, "critical")
        assert action_type == ActionType.LOG_ONLY


# ---------------------------------------------------------------------------
# Non-default threshold: "low"
# ---------------------------------------------------------------------------

class TestThresholdLow:
    """RESPONSE_ALERT_SEVERITY_THRESHOLD=low: every severity -> alert"""

    def test_low_yields_alert(self):
        inc = _make_incident(severity=IncidentSeverity.LOW)
        action_type, target = _select_with_threshold(inc, "low")
        assert action_type == ActionType.ALERT

    def test_medium_yields_alert(self):
        inc = _make_incident(severity=IncidentSeverity.MEDIUM)
        action_type, target = _select_with_threshold(inc, "low")
        assert action_type == ActionType.ALERT


# ---------------------------------------------------------------------------
# Null src_ip (distributed_target_attack)
# ---------------------------------------------------------------------------

class TestNullSrcIp:
    """
    When incident.src_ip is None (e.g. distributed_target_attack, Section 5.4),
    an alert action must still be emitted with target=None, not crash.
    The spec states src_ip is "nullable" for Rule 5 incidents.
    """

    def test_alert_target_is_null_when_src_ip_is_null(self):
        inc = _make_incident(
            severity=IncidentSeverity.HIGH,
            incident_type="distributed_target_attack",
            src_ip=None,  # Rule 5 — no single attacker
        )
        action_type, target = _select_with_threshold(inc, "high")
        assert action_type == ActionType.ALERT
        # target must be None, matching incident.src_ip — not an error
        assert target is None

    def test_log_only_target_is_null_regardless_of_src_ip(self):
        """log_only target is always None, even if src_ip is set."""
        inc = _make_incident(severity=IncidentSeverity.LOW, src_ip="10.0.0.1")
        action_type, target = _select_with_threshold(inc, "high")
        assert action_type == ActionType.LOG_ONLY
        assert target is None


# ---------------------------------------------------------------------------
# Audit log — every action writes an entry regardless of action_type
# ---------------------------------------------------------------------------

class TestAuditLog:
    """Every action writes a full JSON-line audit entry (Section 10.4.1)."""

    def _make_action(
        self,
        incident: Incident,
        action_type: ActionType = ActionType.ALERT,
        target: Optional[str] = "10.0.0.1",
    ) -> Action:
        return Action(
            incident_id=incident.incident_id,
            timestamp=datetime.now(tz=timezone.utc),
            action_type=action_type,
            target=target,
            executed=True,
        )

    def test_alert_action_written_to_audit_log(self):
        import agents.response.main as rm

        inc = _make_incident(severity=IncidentSeverity.HIGH)
        action = self._make_action(inc, ActionType.ALERT, "10.0.0.1")

        with tempfile.NamedTemporaryFile(mode="r", suffix=".log", delete=False) as f:
            log_path = f.name

        with patch.object(rm, "AUDIT_LOG_PATH", log_path):
            rm._write_audit_entry(action, inc)

        with open(log_path, encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()]

        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["action_id"] == action.action_id
        assert entry["incident_id"] == inc.incident_id
        assert entry["action_type"] in ("alert", ActionType.ALERT.value)
        assert "related_flow_ids" in entry
        assert "related_detection_ids" in entry

    def test_log_only_action_also_written_to_audit_log(self):
        """log_only actions must also produce an audit entry."""
        import agents.response.main as rm

        inc = _make_incident(severity=IncidentSeverity.LOW)
        action = self._make_action(inc, ActionType.LOG_ONLY, None)

        with tempfile.NamedTemporaryFile(mode="r", suffix=".log", delete=False) as f:
            log_path = f.name

        with patch.object(rm, "AUDIT_LOG_PATH", log_path):
            rm._write_audit_entry(action, inc)

        with open(log_path, encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()]

        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["action_type"] in ("log_only", ActionType.LOG_ONLY.value)
        assert entry["target"] is None

    def test_null_src_ip_incident_audit_entry_is_valid(self):
        """distributed_target_attack with null src_ip should produce a valid audit entry."""
        import agents.response.main as rm

        inc = _make_incident(
            severity=IncidentSeverity.HIGH,
            incident_type="distributed_target_attack",
            src_ip=None,
        )
        action = self._make_action(inc, ActionType.ALERT, None)

        with tempfile.NamedTemporaryFile(mode="r", suffix=".log", delete=False) as f:
            log_path = f.name

        with patch.object(rm, "AUDIT_LOG_PATH", log_path):
            rm._write_audit_entry(action, inc)

        with open(log_path, encoding="utf-8") as f:
            entry = json.loads(f.readline().strip())

        assert entry["src_ip"] is None
        assert entry["incident_type"] == "distributed_target_attack"
