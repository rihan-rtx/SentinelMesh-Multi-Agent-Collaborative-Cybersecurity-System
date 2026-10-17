"""
SentinelMesh — Shared Data Schemas (Section 5 Data Contracts)

Single source of truth for all inter-agent message schemas.
Every agent imports from here; no agent may redefine any of these models.

All field names, types, and constraints match Section 5 of the project
specification exactly. Enum values are taken verbatim from the spec.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Enumerations — constrained value sets from Section 5
# ---------------------------------------------------------------------------

class ProtocolType(str, Enum):
    """Network protocol, Section 5.1."""
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    OTHER = "OTHER"


class DPIMatchType(str, Enum):
    """DPI finding match type, Section 5.2."""
    SIGNATURE = "signature"
    ANOMALY = "anomaly"


class Severity(str, Enum):
    """Severity levels used by DPI findings and incidents."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class IncidentSeverity(str, Enum):
    """Incident severity — extends base Severity with 'critical', Section 5.4."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Classification(str, Enum):
    """Flow classification, Section 5.3."""
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class ActionType(str, Enum):
    """Action types, Section 5.5.  Only log_only and alert are implemented."""
    LOG_ONLY = "log_only"
    ALERT = "alert"


class AgentStatus(str, Enum):
    """Agent health status, Section 5.6."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    DOWN = "down"


class IncidentStatus(str, Enum):
    """Incident lifecycle status, Section 10.4."""
    OPEN = "open"
    ESCALATED = "escalated"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


# ---------------------------------------------------------------------------
# Helper for UUID generation
# ---------------------------------------------------------------------------

def _uuid_factory() -> str:
    """Generate a new UUID-4 as a string."""
    return str(uuid.uuid4())


def _now_iso() -> datetime:
    """Return current UTC datetime."""
    return datetime.utcnow()


# ---------------------------------------------------------------------------
# 5.1 Flow Event (Sniffer Agent output → flow-events topic)
# ---------------------------------------------------------------------------

class FlowEvent(BaseModel):
    """
    Represents an assembled network flow emitted by the Sniffer Agent.
    Schema per Section 5.1.
    """
    flow_id: str = Field(default_factory=_uuid_factory, description="Unique flow identifier (UUID)")
    timestamp_start: datetime = Field(..., description="ISO8601 timestamp of first packet in flow")
    timestamp_last: datetime = Field(..., description="ISO8601 timestamp of most recent packet in flow")
    src_ip: str = Field(..., description="Source IP address (flow initiator)")
    dst_ip: str = Field(..., description="Destination IP address")
    src_port: int = Field(..., ge=0, le=65535, description="Source port")
    dst_port: int = Field(..., ge=0, le=65535, description="Destination port")
    protocol: ProtocolType = Field(..., description="Network protocol")
    packet_count: int = Field(..., ge=0, description="Number of packets observed in this flow")
    byte_count: int = Field(..., ge=0, description="Total bytes observed in this flow")
    tcp_flags_seen: List[str] = Field(default_factory=list, description="TCP flags observed (e.g. SYN, ACK, FIN, RST)")
    payload_sample: Optional[str] = Field(
        default=None,
        description="Base64-encoded first 256 bytes of first payload-bearing packet, may be null",
    )
    duration_ms: int = Field(..., ge=0, description="Flow duration in milliseconds")

    model_config = ConfigDict(use_enum_values=True)


# ---------------------------------------------------------------------------
# 5.2 DPI Finding (DPI Agent output → dpi-findings topic)
# ---------------------------------------------------------------------------

class DPIFinding(BaseModel):
    """
    A single DPI finding emitted by the DPI Agent.
    Schema per Section 5.2.
    """
    finding_id: str = Field(default_factory=_uuid_factory, description="Unique finding identifier (UUID)")
    flow_id: str = Field(..., description="References FlowEvent.flow_id")
    timestamp: datetime = Field(default_factory=_now_iso, description="ISO8601 timestamp of finding")
    match_type: DPIMatchType = Field(..., description="Type of DPI match")
    signature_name: Optional[str] = Field(
        default=None,
        description="Signature name if match_type is signature, null if anomaly-based",
    )
    anomaly_reason: Optional[str] = Field(
        default=None,
        description="Human-readable anomaly reason if match_type is anomaly, null if signature-based",
    )
    severity: Severity = Field(..., description="Finding severity")
    raw_evidence: str = Field(..., description="Short human-readable evidence description, NOT full payload dump")

    model_config = ConfigDict(use_enum_values=True)


# ---------------------------------------------------------------------------
# 5.3 Detection Result (Detection Agent output → detections topic)
# ---------------------------------------------------------------------------

class DetectionResult(BaseModel):
    """
    Classification result for a flow, emitted by the Detection Agent.
    Schema per Section 5.3.
    """
    detection_id: str = Field(default_factory=_uuid_factory, description="Unique detection identifier (UUID)")
    flow_id: str = Field(..., description="References FlowEvent.flow_id")
    timestamp: datetime = Field(default_factory=_now_iso, description="ISO8601 timestamp of detection")
    classification: Classification = Field(..., description="Flow classification")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score 0.0–1.0")
    attack_type: Optional[str] = Field(
        default=None,
        description="Attack type (e.g. port_scan, syn_flood, exfiltration), null if benign",
    )
    contributing_findings: List[str] = Field(
        default_factory=list,
        description="List of DPI finding_ids that contributed to this detection",
    )

    model_config = ConfigDict(use_enum_values=True)


# ---------------------------------------------------------------------------
# 5.4 Incident (Correlation Agent output → incidents topic)
# ---------------------------------------------------------------------------

class Incident(BaseModel):
    """
    A correlated incident grouping multiple detections/flows.
    Schema per Section 5.4.
    """
    incident_id: str = Field(default_factory=_uuid_factory, description="Unique incident identifier (UUID)")
    timestamp_opened: datetime = Field(..., description="ISO8601 timestamp when incident was first opened")
    timestamp_updated: datetime = Field(..., description="ISO8601 timestamp of last update")
    related_flow_ids: List[str] = Field(default_factory=list, description="Flow IDs involved in this incident")
    related_detection_ids: List[str] = Field(
        default_factory=list,
        description="Detection IDs involved in this incident",
    )
    src_ip: Optional[str] = Field(
        default=None,
        description="Primary suspected actor IP, null if not applicable (e.g. distributed target attack)",
    )
    incident_type: str = Field(..., description="Incident type (e.g. coordinated_scan, multi_stage_attack)")
    severity: IncidentSeverity = Field(..., description="Incident severity")
    status: IncidentStatus = Field(default=IncidentStatus.OPEN, description="Incident lifecycle status")

    model_config = ConfigDict(use_enum_values=True)


# ---------------------------------------------------------------------------
# 5.5 Action (Response Agent output → actions topic + audit log)
# ---------------------------------------------------------------------------

class Action(BaseModel):
    """
    An action taken (or logged) in response to an incident.
    Schema per Section 5.5.
    """
    action_id: str = Field(default_factory=_uuid_factory, description="Unique action identifier (UUID)")
    incident_id: str = Field(..., description="References Incident.incident_id")
    timestamp: datetime = Field(default_factory=_now_iso, description="ISO8601 timestamp of action")
    action_type: ActionType = Field(..., description="Type of action taken")
    target: Optional[str] = Field(
        default=None,
        description="IP under investigation, null if log_only",
    )
    executed: bool = Field(
        default=True,
        description="Always true for log_only/alert since neither requires external execution",
    )
    operator_note: Optional[str] = Field(default=None, description="Optional operator note")

    model_config = ConfigDict(use_enum_values=True)


# ---------------------------------------------------------------------------
# 5.6 Agent Health Ping (all agents → Coordinator)
# ---------------------------------------------------------------------------

class AgentHealthPing(BaseModel):
    """
    Health ping sent by every agent to the Coordinator.
    Schema per Section 5.6.
    """
    agent_name: str = Field(..., description="Name of the reporting agent")
    timestamp: datetime = Field(default_factory=_now_iso, description="ISO8601 timestamp of this ping")
    status: AgentStatus = Field(..., description="Agent health status")
    throughput_last_interval: int = Field(
        ...,
        ge=0,
        description="Events processed in the last reporting window",
    )
    queue_depth: int = Field(
        default=0,
        ge=0,
        description="Consumer lag, if applicable",
    )

    model_config = ConfigDict(use_enum_values=True)
