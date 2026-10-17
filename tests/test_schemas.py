"""
SentinelMesh — Unit Tests for shared/schemas.py

Tests that all 6 Pydantic models conform exactly to Section 5 data contracts.
Validates field names, types, constraints, enum values, defaults, and
serialization/deserialization round-trips.
"""

from datetime import datetime
from uuid import UUID

import pytest
from pydantic import ValidationError

from shared.schemas import (
    Action,
    ActionType,
    AgentHealthPing,
    AgentStatus,
    Classification,
    DPIFinding,
    DPIMatchType,
    DetectionResult,
    FlowEvent,
    Incident,
    IncidentSeverity,
    IncidentStatus,
    ProtocolType,
    Severity,
)


# ======================================================================
# Helper fixtures
# ======================================================================

@pytest.fixture
def valid_flow_event_data() -> dict:
    """Minimal valid FlowEvent data matching Section 5.1."""
    return {
        "flow_id": "550e8400-e29b-41d4-a716-446655440000",
        "timestamp_start": "2024-01-15T10:30:00",
        "timestamp_last": "2024-01-15T10:30:05",
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.1",
        "src_port": 54321,
        "dst_port": 80,
        "protocol": "TCP",
        "packet_count": 12,
        "byte_count": 1500,
        "tcp_flags_seen": ["SYN", "ACK"],
        "payload_sample": "R0VUIC8gSFRUUC8xLjENCg==",
        "duration_ms": 5000,
    }


@pytest.fixture
def valid_dpi_finding_data() -> dict:
    """Minimal valid DPIFinding data matching Section 5.2."""
    return {
        "finding_id": "660e8400-e29b-41d4-a716-446655440001",
        "flow_id": "550e8400-e29b-41d4-a716-446655440000",
        "timestamp": "2024-01-15T10:30:01",
        "match_type": "signature",
        "signature_name": "SQLI_PATTERN",
        "anomaly_reason": None,
        "severity": "high",
        "raw_evidence": "Matched: union select",
    }


@pytest.fixture
def valid_detection_result_data() -> dict:
    """Minimal valid DetectionResult data matching Section 5.3."""
    return {
        "detection_id": "770e8400-e29b-41d4-a716-446655440002",
        "flow_id": "550e8400-e29b-41d4-a716-446655440000",
        "timestamp": "2024-01-15T10:30:02",
        "classification": "malicious",
        "confidence": 0.90,
        "attack_type": "exploit_attempt",
        "contributing_findings": ["660e8400-e29b-41d4-a716-446655440001"],
    }


@pytest.fixture
def valid_incident_data() -> dict:
    """Minimal valid Incident data matching Section 5.4."""
    return {
        "incident_id": "880e8400-e29b-41d4-a716-446655440003",
        "timestamp_opened": "2024-01-15T10:30:03",
        "timestamp_updated": "2024-01-15T10:30:10",
        "related_flow_ids": ["550e8400-e29b-41d4-a716-446655440000"],
        "related_detection_ids": ["770e8400-e29b-41d4-a716-446655440002"],
        "src_ip": "192.168.1.100",
        "incident_type": "multi_stage_attack",
        "severity": "critical",
        "status": "open",
    }


@pytest.fixture
def valid_action_data() -> dict:
    """Minimal valid Action data matching Section 5.5."""
    return {
        "action_id": "990e8400-e29b-41d4-a716-446655440004",
        "incident_id": "880e8400-e29b-41d4-a716-446655440003",
        "timestamp": "2024-01-15T10:30:15",
        "action_type": "alert",
        "target": "192.168.1.100",
        "executed": True,
        "operator_note": "Escalated to SOC team",
    }


@pytest.fixture
def valid_health_ping_data() -> dict:
    """Minimal valid AgentHealthPing data matching Section 5.6."""
    return {
        "agent_name": "sniffer",
        "timestamp": "2024-01-15T10:30:20",
        "status": "healthy",
        "throughput_last_interval": 150,
        "queue_depth": 0,
    }


# ======================================================================
# 5.1 FlowEvent tests
# ======================================================================

class TestFlowEvent:
    """Tests for Section 5.1 FlowEvent schema."""

    def test_valid_construction(self, valid_flow_event_data: dict) -> None:
        """A valid FlowEvent should construct without errors."""
        event = FlowEvent(**valid_flow_event_data)
        assert event.flow_id == valid_flow_event_data["flow_id"]
        assert event.src_ip == "192.168.1.100"
        assert event.dst_port == 80
        assert event.protocol == "TCP"
        assert event.packet_count == 12
        assert event.byte_count == 1500
        assert event.tcp_flags_seen == ["SYN", "ACK"]
        assert event.duration_ms == 5000

    def test_auto_generated_flow_id(self) -> None:
        """flow_id should auto-generate a valid UUID if not provided."""
        data = {
            "timestamp_start": "2024-01-15T10:30:00",
            "timestamp_last": "2024-01-15T10:30:05",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "src_port": 1234,
            "dst_port": 80,
            "protocol": "TCP",
            "packet_count": 1,
            "byte_count": 100,
            "duration_ms": 100,
        }
        event = FlowEvent(**data)
        # Should be a valid UUID-4
        UUID(event.flow_id)

    def test_protocol_enum_values(self) -> None:
        """All four protocol values from Section 5.1 must be accepted."""
        for proto in ["TCP", "UDP", "ICMP", "OTHER"]:
            assert proto in [e.value for e in ProtocolType]

    def test_invalid_protocol_rejected(self, valid_flow_event_data: dict) -> None:
        """An invalid protocol value must be rejected."""
        valid_flow_event_data["protocol"] = "INVALID"
        with pytest.raises(ValidationError):
            FlowEvent(**valid_flow_event_data)

    def test_payload_sample_nullable(self, valid_flow_event_data: dict) -> None:
        """payload_sample may be null per Section 5.1."""
        valid_flow_event_data["payload_sample"] = None
        event = FlowEvent(**valid_flow_event_data)
        assert event.payload_sample is None

    def test_negative_packet_count_rejected(self, valid_flow_event_data: dict) -> None:
        """packet_count must be non-negative."""
        valid_flow_event_data["packet_count"] = -1
        with pytest.raises(ValidationError):
            FlowEvent(**valid_flow_event_data)

    def test_port_range_validation(self, valid_flow_event_data: dict) -> None:
        """Ports must be in range 0-65535."""
        valid_flow_event_data["src_port"] = 70000
        with pytest.raises(ValidationError):
            FlowEvent(**valid_flow_event_data)

    def test_serialization_round_trip(self, valid_flow_event_data: dict) -> None:
        """Serialization to JSON and back should preserve all fields."""
        event = FlowEvent(**valid_flow_event_data)
        json_str = event.model_dump_json()
        restored = FlowEvent.model_validate_json(json_str)
        assert restored.flow_id == event.flow_id
        assert restored.src_ip == event.src_ip
        assert restored.protocol == event.protocol
        assert restored.packet_count == event.packet_count

    def test_empty_tcp_flags_default(self) -> None:
        """tcp_flags_seen defaults to empty list."""
        data = {
            "timestamp_start": "2024-01-15T10:30:00",
            "timestamp_last": "2024-01-15T10:30:05",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "src_port": 1234,
            "dst_port": 53,
            "protocol": "UDP",
            "packet_count": 1,
            "byte_count": 64,
            "duration_ms": 10,
        }
        event = FlowEvent(**data)
        assert event.tcp_flags_seen == []


# ======================================================================
# 5.2 DPIFinding tests
# ======================================================================

class TestDPIFinding:
    """Tests for Section 5.2 DPIFinding schema."""

    def test_valid_signature_finding(self, valid_dpi_finding_data: dict) -> None:
        """A valid signature-based DPI finding should construct correctly."""
        finding = DPIFinding(**valid_dpi_finding_data)
        assert finding.match_type == "signature"
        assert finding.signature_name == "SQLI_PATTERN"
        assert finding.anomaly_reason is None
        assert finding.severity == "high"

    def test_valid_anomaly_finding(self) -> None:
        """A valid anomaly-based DPI finding should construct correctly."""
        finding = DPIFinding(
            flow_id="some-flow-id",
            match_type="anomaly",
            signature_name=None,
            anomaly_reason="high payload entropy for plaintext port",
            severity="medium",
            raw_evidence="Shannon entropy 7.45 on port 80",
        )
        assert finding.match_type == "anomaly"
        assert finding.anomaly_reason is not None
        assert finding.signature_name is None

    def test_match_type_enum(self) -> None:
        """Only 'signature' and 'anomaly' are valid match types."""
        assert "signature" in [e.value for e in DPIMatchType]
        assert "anomaly" in [e.value for e in DPIMatchType]

    def test_severity_enum(self) -> None:
        """Severity must be low, medium, or high."""
        for sev in ["low", "medium", "high"]:
            assert sev in [e.value for e in Severity]

    def test_invalid_severity_rejected(self, valid_dpi_finding_data: dict) -> None:
        """Invalid severity values must be rejected."""
        valid_dpi_finding_data["severity"] = "critical"  # Not valid for DPI findings
        with pytest.raises(ValidationError):
            DPIFinding(**valid_dpi_finding_data)

    def test_auto_generated_finding_id(self) -> None:
        """finding_id should auto-generate if not provided."""
        finding = DPIFinding(
            flow_id="test-flow",
            match_type="signature",
            signature_name="TEST",
            severity="low",
            raw_evidence="test",
        )
        UUID(finding.finding_id)

    def test_serialization_round_trip(self, valid_dpi_finding_data: dict) -> None:
        """JSON round-trip must preserve all fields."""
        finding = DPIFinding(**valid_dpi_finding_data)
        json_str = finding.model_dump_json()
        restored = DPIFinding.model_validate_json(json_str)
        assert restored.finding_id == finding.finding_id
        assert restored.severity == finding.severity


# ======================================================================
# 5.3 DetectionResult tests
# ======================================================================

class TestDetectionResult:
    """Tests for Section 5.3 DetectionResult schema."""

    def test_valid_malicious_detection(self, valid_detection_result_data: dict) -> None:
        """A valid malicious detection should construct correctly."""
        det = DetectionResult(**valid_detection_result_data)
        assert det.classification == "malicious"
        assert det.confidence == 0.90
        assert det.attack_type == "exploit_attempt"
        assert len(det.contributing_findings) == 1

    def test_valid_benign_detection(self) -> None:
        """A benign detection should have null attack_type and empty findings."""
        det = DetectionResult(
            flow_id="test-flow",
            classification="benign",
            confidence=0.95,
            attack_type=None,
            contributing_findings=[],
        )
        assert det.classification == "benign"
        assert det.attack_type is None
        assert det.contributing_findings == []

    def test_classification_enum(self) -> None:
        """Classification must be benign, suspicious, or malicious."""
        for cls in ["benign", "suspicious", "malicious"]:
            assert cls in [e.value for e in Classification]

    def test_confidence_out_of_range_rejected(self, valid_detection_result_data: dict) -> None:
        """Confidence > 1.0 must be rejected."""
        valid_detection_result_data["confidence"] = 1.5
        with pytest.raises(ValidationError):
            DetectionResult(**valid_detection_result_data)

    def test_confidence_negative_rejected(self, valid_detection_result_data: dict) -> None:
        """Confidence < 0.0 must be rejected."""
        valid_detection_result_data["confidence"] = -0.1
        with pytest.raises(ValidationError):
            DetectionResult(**valid_detection_result_data)

    def test_serialization_round_trip(self, valid_detection_result_data: dict) -> None:
        """JSON round-trip must preserve all fields."""
        det = DetectionResult(**valid_detection_result_data)
        json_str = det.model_dump_json()
        restored = DetectionResult.model_validate_json(json_str)
        assert restored.detection_id == det.detection_id
        assert restored.confidence == det.confidence
        assert restored.contributing_findings == det.contributing_findings


# ======================================================================
# 5.4 Incident tests
# ======================================================================

class TestIncident:
    """Tests for Section 5.4 Incident schema."""

    def test_valid_incident(self, valid_incident_data: dict) -> None:
        """A valid incident should construct correctly."""
        inc = Incident(**valid_incident_data)
        assert inc.incident_type == "multi_stage_attack"
        assert inc.severity == "critical"
        assert inc.status == "open"
        assert inc.src_ip == "192.168.1.100"

    def test_src_ip_nullable(self, valid_incident_data: dict) -> None:
        """src_ip may be null (e.g. distributed_target_attack per Section 10.4)."""
        valid_incident_data["src_ip"] = None
        inc = Incident(**valid_incident_data)
        assert inc.src_ip is None

    def test_incident_severity_includes_critical(self) -> None:
        """Incident severity must include 'critical' (unlike DPI Severity)."""
        assert "critical" in [e.value for e in IncidentSeverity]

    def test_incident_status_enum(self) -> None:
        """All 4 incident statuses from Section 10.4 must be valid."""
        for status in ["open", "escalated", "resolved", "false_positive"]:
            assert status in [e.value for e in IncidentStatus]

    def test_default_status_is_open(self) -> None:
        """Default status should be 'open' per Section 10.4."""
        inc = Incident(
            timestamp_opened="2024-01-15T10:30:00",
            timestamp_updated="2024-01-15T10:30:00",
            incident_type="test",
            severity="low",
        )
        assert inc.status == "open"

    def test_serialization_round_trip(self, valid_incident_data: dict) -> None:
        """JSON round-trip must preserve all fields."""
        inc = Incident(**valid_incident_data)
        json_str = inc.model_dump_json()
        restored = Incident.model_validate_json(json_str)
        assert restored.incident_id == inc.incident_id
        assert restored.severity == inc.severity
        assert restored.related_flow_ids == inc.related_flow_ids


# ======================================================================
# 5.5 Action tests
# ======================================================================

class TestAction:
    """Tests for Section 5.5 Action schema."""

    def test_valid_alert_action(self, valid_action_data: dict) -> None:
        """A valid alert action should construct correctly."""
        action = Action(**valid_action_data)
        assert action.action_type == "alert"
        assert action.target == "192.168.1.100"
        assert action.executed is True

    def test_valid_log_only_action(self) -> None:
        """A log_only action should construct correctly with null target."""
        action = Action(
            incident_id="test-incident",
            action_type="log_only",
            target=None,
            executed=True,
        )
        assert action.action_type == "log_only"
        assert action.target is None

    def test_action_type_enum(self) -> None:
        """Only log_only and alert are valid (Section 5.5 scope note)."""
        assert "log_only" in [e.value for e in ActionType]
        assert "alert" in [e.value for e in ActionType]
        assert len(ActionType) == 2  # No recommend_block etc.

    def test_executed_defaults_true(self) -> None:
        """executed defaults to True per Section 5.5."""
        action = Action(
            incident_id="test-incident",
            action_type="log_only",
        )
        assert action.executed is True

    def test_serialization_round_trip(self, valid_action_data: dict) -> None:
        """JSON round-trip must preserve all fields."""
        action = Action(**valid_action_data)
        json_str = action.model_dump_json()
        restored = Action.model_validate_json(json_str)
        assert restored.action_id == action.action_id
        assert restored.action_type == action.action_type
        assert restored.operator_note == action.operator_note


# ======================================================================
# 5.6 AgentHealthPing tests
# ======================================================================

class TestAgentHealthPing:
    """Tests for Section 5.6 AgentHealthPing schema."""

    def test_valid_health_ping(self, valid_health_ping_data: dict) -> None:
        """A valid health ping should construct correctly."""
        ping = AgentHealthPing(**valid_health_ping_data)
        assert ping.agent_name == "sniffer"
        assert ping.status == "healthy"
        assert ping.throughput_last_interval == 150
        assert ping.queue_depth == 0

    def test_agent_status_enum(self) -> None:
        """All 3 statuses from Section 5.6 must be valid."""
        for status in ["healthy", "degraded", "down"]:
            assert status in [e.value for e in AgentStatus]

    def test_negative_throughput_rejected(self, valid_health_ping_data: dict) -> None:
        """Throughput must be non-negative."""
        valid_health_ping_data["throughput_last_interval"] = -1
        with pytest.raises(ValidationError):
            AgentHealthPing(**valid_health_ping_data)

    def test_queue_depth_defaults_to_zero(self) -> None:
        """queue_depth defaults to 0."""
        ping = AgentHealthPing(
            agent_name="dpi",
            status="healthy",
            throughput_last_interval=100,
        )
        assert ping.queue_depth == 0

    def test_degraded_status(self) -> None:
        """An agent can report 'degraded' status (Section 10.12, Redis unavailable)."""
        ping = AgentHealthPing(
            agent_name="detection",
            status="degraded",
            throughput_last_interval=50,
            queue_depth=10,
        )
        assert ping.status == "degraded"

    def test_serialization_round_trip(self, valid_health_ping_data: dict) -> None:
        """JSON round-trip must preserve all fields."""
        ping = AgentHealthPing(**valid_health_ping_data)
        json_str = ping.model_dump_json()
        restored = AgentHealthPing.model_validate_json(json_str)
        assert restored.agent_name == ping.agent_name
        assert restored.status == ping.status


# ======================================================================
# Cross-schema contract tests
# ======================================================================

class TestCrossSchemaContracts:
    """
    Tests that cross-schema references work correctly — e.g. a DetectionResult's
    flow_id can reference a FlowEvent, and contributing_findings can reference
    DPIFinding finding_ids.
    """

    def test_detection_references_flow(
        self,
        valid_flow_event_data: dict,
        valid_detection_result_data: dict,
    ) -> None:
        """DetectionResult.flow_id should match FlowEvent.flow_id."""
        flow = FlowEvent(**valid_flow_event_data)
        valid_detection_result_data["flow_id"] = flow.flow_id
        det = DetectionResult(**valid_detection_result_data)
        assert det.flow_id == flow.flow_id

    def test_dpi_finding_references_flow(
        self,
        valid_flow_event_data: dict,
        valid_dpi_finding_data: dict,
    ) -> None:
        """DPIFinding.flow_id should match FlowEvent.flow_id."""
        flow = FlowEvent(**valid_flow_event_data)
        valid_dpi_finding_data["flow_id"] = flow.flow_id
        finding = DPIFinding(**valid_dpi_finding_data)
        assert finding.flow_id == flow.flow_id

    def test_detection_references_dpi_finding(
        self,
        valid_dpi_finding_data: dict,
        valid_detection_result_data: dict,
    ) -> None:
        """DetectionResult.contributing_findings should contain DPIFinding.finding_id."""
        finding = DPIFinding(**valid_dpi_finding_data)
        valid_detection_result_data["contributing_findings"] = [finding.finding_id]
        det = DetectionResult(**valid_detection_result_data)
        assert finding.finding_id in det.contributing_findings

    def test_incident_references_flow_and_detection(
        self,
        valid_flow_event_data: dict,
        valid_detection_result_data: dict,
        valid_incident_data: dict,
    ) -> None:
        """Incident should reference both flow_ids and detection_ids."""
        flow = FlowEvent(**valid_flow_event_data)
        det = DetectionResult(**valid_detection_result_data)
        valid_incident_data["related_flow_ids"] = [flow.flow_id]
        valid_incident_data["related_detection_ids"] = [det.detection_id]
        inc = Incident(**valid_incident_data)
        assert flow.flow_id in inc.related_flow_ids
        assert det.detection_id in inc.related_detection_ids

    def test_action_references_incident(
        self,
        valid_incident_data: dict,
        valid_action_data: dict,
    ) -> None:
        """Action.incident_id should match Incident.incident_id."""
        inc = Incident(**valid_incident_data)
        valid_action_data["incident_id"] = inc.incident_id
        action = Action(**valid_action_data)
        assert action.incident_id == inc.incident_id

    def test_full_pipeline_chain(
        self,
        valid_flow_event_data: dict,
        valid_dpi_finding_data: dict,
        valid_detection_result_data: dict,
        valid_incident_data: dict,
        valid_action_data: dict,
    ) -> None:
        """
        Verify the full data pipeline chain: FlowEvent → DPIFinding →
        DetectionResult → Incident → Action, with consistent cross-references.
        """
        flow = FlowEvent(**valid_flow_event_data)

        valid_dpi_finding_data["flow_id"] = flow.flow_id
        finding = DPIFinding(**valid_dpi_finding_data)

        valid_detection_result_data["flow_id"] = flow.flow_id
        valid_detection_result_data["contributing_findings"] = [finding.finding_id]
        det = DetectionResult(**valid_detection_result_data)

        valid_incident_data["related_flow_ids"] = [flow.flow_id]
        valid_incident_data["related_detection_ids"] = [det.detection_id]
        inc = Incident(**valid_incident_data)

        valid_action_data["incident_id"] = inc.incident_id
        action = Action(**valid_action_data)

        # Verify the chain
        assert det.flow_id == flow.flow_id
        assert finding.flow_id == flow.flow_id
        assert finding.finding_id in det.contributing_findings
        assert flow.flow_id in inc.related_flow_ids
        assert det.detection_id in inc.related_detection_ids
        assert action.incident_id == inc.incident_id
