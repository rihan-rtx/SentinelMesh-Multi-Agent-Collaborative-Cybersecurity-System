"""
SentinelMesh — Detection Agent Unit Tests (test_detection.py)

Tests each of the 5 detection rules in Section 10.3 against constructed
flow-event/dpi-finding fixtures. Also tests:
  - Priority/conflict resolution (fixtures matching multiple rules at once)
  - Redis graceful degradation (rules 2 & 3 skipped when Redis is None)

Uses fakeredis for all Redis interactions — no real Redis required.

Section 10.13 testing plan reference:
  "each rule tested against constructed flow-event/dpi-finding fixtures;
   priority/conflict resolution verified with fixtures designed to match
   multiple rules at once."
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
from typing import List, Optional
from unittest.mock import patch

import fakeredis
import pytest

from agents.detection.rules import (
    DETECTION_EXFIL_BYTES_THRESHOLD,
    DETECTION_PORTSCAN_DISTINCT_PORTS,
    DETECTION_PORTSCAN_WINDOW_S,
    DETECTION_SYNFLOOD_THRESHOLD,
    DETECTION_SYNFLOOD_WINDOW_S,
    evaluate,
)
from shared.schemas import (
    Classification,
    DPIFinding,
    DPIMatchType,
    FlowEvent,
    ProtocolType,
    Severity,
)

# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------

def _make_flow(
    src_ip: str = "10.0.0.1",
    dst_ip: str = "192.168.1.1",
    src_port: int = 54321,
    dst_port: int = 80,
    protocol: str = "TCP",
    packet_count: int = 10,
    byte_count: int = 1024,
    tcp_flags_seen: Optional[List[str]] = None,
    payload_sample: Optional[str] = None,
    duration_ms: int = 500,
) -> FlowEvent:
    """Build a FlowEvent with sensible defaults for testing."""
    now = datetime.now(tz=timezone.utc)
    return FlowEvent(
        timestamp_start=now,
        timestamp_last=now,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        packet_count=packet_count,
        byte_count=byte_count,
        tcp_flags_seen=tcp_flags_seen or [],
        payload_sample=payload_sample,
        duration_ms=duration_ms,
    )


def _make_dpi_finding(
    flow_id: str = "test-flow-id",
    severity: Severity = Severity.HIGH,
    match_type: DPIMatchType = DPIMatchType.SIGNATURE,
    signature_name: Optional[str] = "SQLI_PATTERN",
) -> DPIFinding:
    """Build a DPIFinding with sensible defaults for testing."""
    return DPIFinding(
        flow_id=flow_id,
        match_type=match_type,
        signature_name=signature_name,
        anomaly_reason=None if match_type == DPIMatchType.SIGNATURE else "high payload entropy",
        severity=severity,
        raw_evidence="test evidence",
    )


def _fresh_redis() -> fakeredis.FakeRedis:
    """Return a fresh, in-memory fake Redis instance."""
    return fakeredis.FakeRedis(decode_responses=True)


# ---------------------------------------------------------------------------
# Rule 1a: DPI high-severity match
# ---------------------------------------------------------------------------

class TestDPIHighSeverityRule:
    """Priority 1a: Any high-severity DPI finding → malicious/0.90/exploit_attempt."""

    def test_high_severity_finding_yields_malicious(self):
        flow = _make_flow()
        findings = [_make_dpi_finding(flow_id=flow.flow_id, severity=Severity.HIGH)]
        result = evaluate(flow, findings, _fresh_redis())

        assert result.classification == Classification.MALICIOUS.value
        assert result.confidence == 0.90
        assert result.attack_type == "exploit_attempt"
        assert findings[0].finding_id in result.contributing_findings

    def test_multiple_high_findings_all_referenced(self):
        flow = _make_flow()
        findings = [
            _make_dpi_finding(flow_id=flow.flow_id, severity=Severity.HIGH,
                              signature_name="SQLI_PATTERN"),
            _make_dpi_finding(flow_id=flow.flow_id, severity=Severity.HIGH,
                              signature_name="SHELLCODE_NOPSLED"),
        ]
        result = evaluate(flow, findings, _fresh_redis())

        assert result.classification == Classification.MALICIOUS.value
        assert len(result.contributing_findings) == 2

    def test_no_findings_does_not_trigger_dpi_rule(self):
        flow = _make_flow()
        result = evaluate(flow, [], _fresh_redis())
        # Falls through to default (benign) since no other rules fire
        assert result.classification == Classification.BENIGN.value

    def test_low_severity_finding_does_not_trigger_high_rule(self):
        flow = _make_flow()
        findings = [_make_dpi_finding(flow_id=flow.flow_id, severity=Severity.LOW)]
        result = evaluate(flow, findings, _fresh_redis())
        # Low severity shouldn't hit Rule 1a or 3 — goes to default
        assert result.classification == Classification.BENIGN.value


# ---------------------------------------------------------------------------
# Rule 1b: SYN flood
# ---------------------------------------------------------------------------

class TestSynFloodRule:
    """Priority 1b: SYN-only flows to same dst_ip:dst_port > threshold → malicious/0.85."""

    def test_syn_flood_triggers_above_threshold(self):
        redis = _fresh_redis()
        dst_ip = "192.168.1.100"
        dst_port = 80
        flood_key = f"det:synflood:{dst_ip}:{dst_port}"

        # Pre-populate the counter just below trigger (101 total including this flow)
        redis.set(flood_key, str(DETECTION_SYNFLOOD_THRESHOLD), ex=DETECTION_SYNFLOOD_WINDOW_S)

        flow = _make_flow(
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol="TCP",
            tcp_flags_seen=["SYN"],
        )
        result = evaluate(flow, [], redis)

        assert result.classification == Classification.MALICIOUS.value
        assert result.confidence == 0.85
        assert result.attack_type == "syn_flood"

    def test_syn_flood_does_not_trigger_below_threshold(self):
        redis = _fresh_redis()
        # Counter starts at 0 — first SYN flow won't cross threshold
        flow = _make_flow(
            dst_ip="192.168.1.100",
            dst_port=80,
            protocol="TCP",
            tcp_flags_seen=["SYN"],
        )
        result = evaluate(flow, [], redis)
        # Should not be flagged as syn_flood (counter = 1 < threshold)
        assert result.attack_type != "syn_flood"

    def test_non_syn_only_flow_does_not_trigger_syn_flood(self):
        """SYN+ACK (established connection) should not count as SYN flood."""
        redis = _fresh_redis()
        dst_ip = "192.168.1.100"
        dst_port = 80
        # Pre-populate counter above threshold
        redis.set(f"det:synflood:{dst_ip}:{dst_port}",
                  str(DETECTION_SYNFLOOD_THRESHOLD + 10), ex=5)

        flow = _make_flow(
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol="TCP",
            tcp_flags_seen=["SYN", "ACK"],  # Not SYN-only
        )
        result = evaluate(flow, [], redis)
        assert result.attack_type != "syn_flood"

    def test_syn_flood_disabled_when_redis_none(self):
        """When Redis is None, SYN flood rule must be silently skipped."""
        flow = _make_flow(
            dst_ip="192.168.1.100",
            dst_port=80,
            protocol="TCP",
            tcp_flags_seen=["SYN"],
        )
        result = evaluate(flow, [], redis_client=None)
        # Should fall through to default benign — not crash
        assert result.classification == Classification.BENIGN.value


# ---------------------------------------------------------------------------
# Rule 2: Port scan
# ---------------------------------------------------------------------------

class TestPortScanRule:
    """Priority 2: src_ip touches ≥15 distinct dst_ports within window → suspicious/0.70."""

    def test_port_scan_triggers_at_threshold(self):
        redis = _fresh_redis()
        src_ip = "10.0.0.99"

        # Add DETECTION_PORTSCAN_DISTINCT_PORTS - 1 ports to the set
        for port in range(1, DETECTION_PORTSCAN_DISTINCT_PORTS):
            redis.sadd(f"det:portscan:{src_ip}", port)
        redis.expire(f"det:portscan:{src_ip}", DETECTION_PORTSCAN_WINDOW_S)

        # This flow's dst_port is the Nth distinct port that triggers the rule
        flow = _make_flow(
            src_ip=src_ip,
            dst_port=DETECTION_PORTSCAN_DISTINCT_PORTS + 100,
        )
        result = evaluate(flow, [], redis)

        assert result.classification == Classification.SUSPICIOUS.value
        assert result.confidence == 0.70
        assert result.attack_type == "port_scan"

    def test_port_scan_does_not_trigger_below_threshold(self):
        redis = _fresh_redis()
        src_ip = "10.0.0.99"
        # Add only 5 ports — below the 15-port threshold
        for port in range(1, 6):
            redis.sadd(f"det:portscan:{src_ip}", port)
        redis.expire(f"det:portscan:{src_ip}", DETECTION_PORTSCAN_WINDOW_S)

        flow = _make_flow(src_ip=src_ip, dst_port=9999)
        result = evaluate(flow, [], redis)
        assert result.attack_type != "port_scan"

    def test_port_scan_disabled_when_redis_none(self):
        flow = _make_flow(src_ip="10.0.0.99", dst_port=80)
        result = evaluate(flow, [], redis_client=None)
        # Must not crash; falls to default
        assert result.classification == Classification.BENIGN.value


# ---------------------------------------------------------------------------
# Rule 3: DPI medium-severity match (alone)
# ---------------------------------------------------------------------------

class TestDPIMediumSeverityRule:
    """Priority 3: medium-severity DPI finding, no higher rule matched → suspicious/0.60."""

    def test_medium_severity_finding_yields_suspicious(self):
        flow = _make_flow()
        findings = [_make_dpi_finding(flow_id=flow.flow_id, severity=Severity.MEDIUM,
                                       signature_name="MALICIOUS_USER_AGENT")]
        result = evaluate(flow, findings, _fresh_redis())

        assert result.classification == Classification.SUSPICIOUS.value
        assert result.confidence == 0.60
        assert result.attack_type == "suspicious_payload"
        assert findings[0].finding_id in result.contributing_findings

    def test_medium_severity_finding_with_no_redis(self):
        """Medium-severity DPI rule is per-event and does not need Redis."""
        flow = _make_flow()
        findings = [_make_dpi_finding(flow_id=flow.flow_id, severity=Severity.MEDIUM)]
        result = evaluate(flow, findings, redis_client=None)

        assert result.classification == Classification.SUSPICIOUS.value
        assert result.attack_type == "suspicious_payload"


# ---------------------------------------------------------------------------
# Rule 4: Possible exfiltration
# ---------------------------------------------------------------------------

class TestExfiltrationRule:
    """Priority 4: large byte_count to external IP on non-standard port → suspicious/0.50."""

    def test_exfil_triggers_for_large_flow_to_external(self):
        flow = _make_flow(
            dst_ip="8.8.8.8",       # External IP
            dst_port=4444,           # Non-standard port
            byte_count=DETECTION_EXFIL_BYTES_THRESHOLD + 1,
        )
        result = evaluate(flow, [], _fresh_redis())

        assert result.classification == Classification.SUSPICIOUS.value
        assert result.confidence == 0.50
        assert result.attack_type == "possible_exfiltration"

    def test_exfil_does_not_trigger_on_internal_ip(self):
        flow = _make_flow(
            dst_ip="192.168.1.1",   # Internal — RFC 1918
            dst_port=4444,
            byte_count=DETECTION_EXFIL_BYTES_THRESHOLD + 1,
        )
        result = evaluate(flow, [], _fresh_redis())
        assert result.attack_type != "possible_exfiltration"

    def test_exfil_does_not_trigger_on_standard_port(self):
        flow = _make_flow(
            dst_ip="8.8.8.8",
            dst_port=443,            # Standard (HTTPS) — excluded
            byte_count=DETECTION_EXFIL_BYTES_THRESHOLD + 1,
        )
        result = evaluate(flow, [], _fresh_redis())
        assert result.attack_type != "possible_exfiltration"

    def test_exfil_does_not_trigger_below_threshold(self):
        flow = _make_flow(
            dst_ip="8.8.8.8",
            dst_port=4444,
            byte_count=DETECTION_EXFIL_BYTES_THRESHOLD - 1,
        )
        result = evaluate(flow, [], _fresh_redis())
        assert result.attack_type != "possible_exfiltration"


# ---------------------------------------------------------------------------
# Rule 5 (default): Benign
# ---------------------------------------------------------------------------

class TestBenignDefault:
    """Priority 5: no rule matched → benign/0.95."""

    def test_normal_flow_is_benign(self):
        flow = _make_flow(
            src_ip="192.168.1.10",
            dst_ip="93.184.216.34",
            dst_port=443,
            byte_count=2048,
            tcp_flags_seen=["SYN", "ACK", "FIN"],
        )
        result = evaluate(flow, [], _fresh_redis())

        assert result.classification == Classification.BENIGN.value
        assert result.confidence == 0.95
        assert result.attack_type is None
        assert result.contributing_findings == []


# ---------------------------------------------------------------------------
# Priority / conflict resolution
# ---------------------------------------------------------------------------

class TestPriorityResolution:
    """
    Verify that when multiple rules match, the highest-priority rule wins.
    Section 10.3: 'picks the highest-priority match.'
    """

    def test_high_dpi_beats_port_scan(self):
        """High DPI (priority 1) beats port scan (priority 2)."""
        redis = _fresh_redis()
        src_ip = "10.0.0.99"

        # Pre-load redis to trigger port scan rule
        for port in range(1, DETECTION_PORTSCAN_DISTINCT_PORTS + 1):
            redis.sadd(f"det:portscan:{src_ip}", port)
        redis.expire(f"det:portscan:{src_ip}", DETECTION_PORTSCAN_WINDOW_S)

        flow = _make_flow(src_ip=src_ip, dst_port=9999)
        high_finding = _make_dpi_finding(flow_id=flow.flow_id, severity=Severity.HIGH)

        result = evaluate(flow, [high_finding], redis)

        # DPI high (priority 1) beats port scan (priority 2)
        assert result.classification == Classification.MALICIOUS.value
        assert result.attack_type == "exploit_attempt"

    def test_medium_dpi_loses_to_port_scan(self):
        """Port scan (priority 2) beats medium DPI (priority 3)."""
        redis = _fresh_redis()
        src_ip = "10.0.0.99"

        for port in range(1, DETECTION_PORTSCAN_DISTINCT_PORTS + 1):
            redis.sadd(f"det:portscan:{src_ip}", port)
        redis.expire(f"det:portscan:{src_ip}", DETECTION_PORTSCAN_WINDOW_S)

        flow = _make_flow(src_ip=src_ip, dst_port=9999)
        medium_finding = _make_dpi_finding(flow_id=flow.flow_id, severity=Severity.MEDIUM)

        result = evaluate(flow, [medium_finding], redis)

        # Port scan (priority 2) wins over medium DPI (priority 3)
        assert result.attack_type == "port_scan"
        assert result.confidence == 0.70

    def test_exfil_loses_to_medium_dpi(self):
        """Medium DPI (priority 3) beats exfiltration (priority 4)."""
        flow = _make_flow(
            dst_ip="8.8.8.8",
            dst_port=4444,
            byte_count=DETECTION_EXFIL_BYTES_THRESHOLD + 1,
        )
        medium_finding = _make_dpi_finding(flow_id=flow.flow_id, severity=Severity.MEDIUM)
        result = evaluate(flow, [medium_finding], _fresh_redis())

        assert result.attack_type == "suspicious_payload"
        assert result.confidence == 0.60

    def test_high_dpi_beats_exfil(self):
        """High DPI (priority 1) beats exfiltration (priority 4)."""
        flow = _make_flow(
            dst_ip="8.8.8.8",
            dst_port=4444,
            byte_count=DETECTION_EXFIL_BYTES_THRESHOLD + 1,
        )
        high_finding = _make_dpi_finding(flow_id=flow.flow_id, severity=Severity.HIGH)
        result = evaluate(flow, [high_finding], _fresh_redis())

        assert result.classification == Classification.MALICIOUS.value
        assert result.attack_type == "exploit_attempt"

    def test_syn_flood_beats_port_scan(self):
        """SYN flood (priority 1b) beats port scan (priority 2)."""
        redis = _fresh_redis()
        src_ip = "10.0.0.99"
        dst_ip = "192.168.1.100"
        dst_port = 80

        # Trigger both rules simultaneously
        for port in range(1, DETECTION_PORTSCAN_DISTINCT_PORTS + 1):
            redis.sadd(f"det:portscan:{src_ip}", port)
        redis.expire(f"det:portscan:{src_ip}", DETECTION_PORTSCAN_WINDOW_S)

        redis.set(
            f"det:synflood:{dst_ip}:{dst_port}",
            str(DETECTION_SYNFLOOD_THRESHOLD),
            ex=DETECTION_SYNFLOOD_WINDOW_S,
        )

        flow = _make_flow(
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol="TCP",
            tcp_flags_seen=["SYN"],
        )
        result = evaluate(flow, [], redis)

        # SYN flood (priority 1b / 0.85) should win over port scan (priority 2 / 0.70)
        assert result.attack_type == "syn_flood"
        assert result.confidence == 0.85
