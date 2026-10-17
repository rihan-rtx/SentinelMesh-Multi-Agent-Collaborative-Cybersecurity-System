"""
SentinelMesh — Correlation Agent: Redis-Backed Sliding Window Manager

Encapsulates all Redis state management for the Correlation Agent as described
in Sections 10.4 and 10.5.

Redis key schema (Section 10.5):
  corr:src:{src_ip}:events          Sorted Set, score=epoch, member=event_id
  corr:detection:{detection_id}     Hash — full detection JSON
  corr:finding:{finding_id}         Hash — full DPI finding JSON
  corr:active_incident:{src_ip}     String — incident_id (TTL 600s)
  corr:active_incident_dst:{dst_ip} String — incident_id for Rule 5 (TTL 600s)
  corr:dst:{dst_ip}:sources         Set — distinct src_ips (TTL 60s)
  corr:incident:{incident_id}       Hash — canonical incident JSON (TTL 600s)
  flow:ctx:{flow_id}                Hash — src_ip, dst_ip, src_port, dst_port, protocol

Incident lifecycle (Section 10.4):
  open → escalated (on new evidence) → resolved (on inactivity timeout)
  false_positive is reserved for manual marking; never set automatically.
"""

from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from shared.schemas import (
    Classification,
    DetectionResult,
    DPIFinding,
    Incident,
    IncidentSeverity,
    IncidentStatus,
    Severity,
)

logger = logging.getLogger("correlation.window")

# ---------------------------------------------------------------------------
# Config (Section 10.11)
# ---------------------------------------------------------------------------

CORRELATION_WINDOW_S: int = int(os.getenv("CORRELATION_WINDOW_S", "60"))
CORRELATION_MAX_INCIDENT_LIFETIME_S: int = int(
    os.getenv("CORRELATION_MAX_INCIDENT_LIFETIME_S", "600")
)
CORRELATION_COORD_SCAN_DISTINCT_DST: int = int(
    os.getenv("CORRELATION_COORD_SCAN_DISTINCT_DST", "5")
)
CORRELATION_REPEATED_MALICIOUS_COUNT: int = int(
    os.getenv("CORRELATION_REPEATED_MALICIOUS_COUNT", "3")
)


# ---------------------------------------------------------------------------
# Flow context cache
# ---------------------------------------------------------------------------

def cache_flow_context(redis_client, flow_id: str, src_ip: str, dst_ip: str,
                        src_port: int, dst_port: int, protocol: str) -> None:
    """
    Store flow context so Correlation Agent can resolve src/dst IPs from
    detection or finding messages that only carry flow_id (Section 10.6).
    TTL 300s — deliberately longer than the correlation window.
    """
    key = f"flow:ctx:{flow_id}"
    redis_client.hset(key, mapping={
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": str(src_port),
        "dst_port": str(dst_port),
        "protocol": protocol,
    })
    redis_client.expire(key, 300)


def get_flow_context(redis_client, flow_id: str) -> Optional[dict]:
    """
    Resolve flow context from Redis cache.
    Returns a dict with src_ip, dst_ip, src_port, dst_port, protocol,
    or None if not found.
    """
    key = f"flow:ctx:{flow_id}"
    ctx = redis_client.hgetall(key)
    if not ctx:
        return None
    return ctx


# ---------------------------------------------------------------------------
# Event tracking (sliding window)
# ---------------------------------------------------------------------------

def add_detection_to_window(
    redis_client,
    src_ip: str,
    detection_id: str,
    detection_json: str,
    epoch: float,
) -> None:
    """
    Add a detection to the sliding-window sorted set for the given src_ip.
    Also caches the full detection JSON for later lookup.
    """
    # Sorted set: score = epoch timestamp for range queries
    redis_client.zadd(f"corr:src:{src_ip}:events", {detection_id: epoch})
    # Detail cache
    redis_client.set(
        f"corr:detection:{detection_id}",
        detection_json,
        ex=CORRELATION_MAX_INCIDENT_LIFETIME_S * 2,  # 120s buffer
    )


def add_finding_to_window(
    redis_client,
    src_ip: str,
    finding_id: str,
    finding_json: str,
    epoch: float,
) -> None:
    """Add a DPI finding to the sliding-window sorted set for the given src_ip."""
    redis_client.zadd(f"corr:src:{src_ip}:events", {f"dpi:{finding_id}": epoch})
    redis_client.set(
        f"corr:finding:{finding_id}",
        finding_json,
        ex=CORRELATION_MAX_INCIDENT_LIFETIME_S * 2,
    )


def sweep_expired_window_entries(redis_client, src_ip: str) -> None:
    """
    Remove entries older than CORRELATION_WINDOW_S from the sorted set.
    Redis ZSET members don't expire individually, so we sweep manually.
    """
    cutoff = time.time() - CORRELATION_WINDOW_S
    redis_client.zremrangebyscore(f"corr:src:{src_ip}:events", "-inf", cutoff)


def get_window_event_ids(redis_client, src_ip: str) -> List[str]:
    """
    Return all event IDs (detection_id / 'dpi:{finding_id}') within the
    current 60-second window for a given src_ip.
    """
    sweep_expired_window_entries(redis_client, src_ip)
    cutoff = time.time() - CORRELATION_WINDOW_S
    members = redis_client.zrangebyscore(
        f"corr:src:{src_ip}:events", cutoff, "+inf"
    )
    return members or []


def get_window_detections(redis_client, src_ip: str) -> List[DetectionResult]:
    """Return all DetectionResult objects in the current window for src_ip."""
    event_ids = get_window_event_ids(redis_client, src_ip)
    results = []
    for eid in event_ids:
        if eid.startswith("dpi:"):
            continue  # Skip DPI findings
        raw = redis_client.get(f"corr:detection:{eid}")
        if raw:
            try:
                results.append(DetectionResult.model_validate_json(raw))
            except Exception:
                logger.warning("Failed to deserialize cached detection: %s", eid)
    return results


def get_window_dpi_findings(redis_client, src_ip: str) -> List[DPIFinding]:
    """Return all DPIFinding objects in the current window for src_ip."""
    event_ids = get_window_event_ids(redis_client, src_ip)
    results = []
    for eid in event_ids:
        if not eid.startswith("dpi:"):
            continue
        finding_id = eid[4:]  # strip "dpi:" prefix
        raw = redis_client.get(f"corr:finding:{finding_id}")
        if raw:
            try:
                results.append(DPIFinding.model_validate_json(raw))
            except Exception:
                logger.warning("Failed to deserialize cached DPI finding: %s", finding_id)
    return results


# ---------------------------------------------------------------------------
# Distributed-target tracking (Rule 5)
# ---------------------------------------------------------------------------

def add_src_to_dst_sources(redis_client, dst_ip: str, src_ip: str) -> int:
    """
    Track distinct source IPs attacking a given destination.
    Returns the current count of distinct sources.
    TTL 60s, refreshed on each add.
    """
    key = f"corr:dst:{dst_ip}:sources"
    redis_client.sadd(key, src_ip)
    redis_client.expire(key, CORRELATION_WINDOW_S)
    return redis_client.scard(key)


# ---------------------------------------------------------------------------
# Incident lifecycle
# ---------------------------------------------------------------------------

def get_active_incident_id(redis_client, key_suffix: str) -> Optional[str]:
    """Look up an existing open incident ID for a src_ip or dst_ip."""
    return redis_client.get(f"corr:active_incident:{key_suffix}")


def get_incident(redis_client, incident_id: str) -> Optional[Incident]:
    """Load a full Incident from the Redis hash."""
    raw = redis_client.get(f"corr:incident:{incident_id}")
    if not raw:
        return None
    try:
        return Incident.model_validate_json(raw)
    except Exception:
        logger.warning("Failed to deserialize incident: %s", incident_id)
        return None


def save_incident(redis_client, incident: Incident, key_suffix: str) -> None:
    """
    Persist an incident to Redis and refresh the active-incident lookup key.
    Both keys use CORRELATION_MAX_INCIDENT_LIFETIME_S as TTL.
    """
    incident_json = incident.model_dump_json()
    redis_client.set(
        f"corr:incident:{incident.incident_id}",
        incident_json,
        ex=CORRELATION_MAX_INCIDENT_LIFETIME_S,
    )
    redis_client.set(
        f"corr:active_incident:{key_suffix}",
        incident.incident_id,
        ex=CORRELATION_MAX_INCIDENT_LIFETIME_S,
    )


def create_or_update_incident(
    redis_client,
    key_suffix: str,
    incident_type: str,
    severity: IncidentSeverity,
    src_ip: Optional[str],
    new_flow_ids: List[str],
    new_detection_ids: List[str],
    producer,
    output_topic: str,
) -> Incident:
    """
    Retrieve an existing open incident for key_suffix and append to it, or
    create a new incident. Emits the incident to Kafka after update/creation.

    Severity escalates (never de-escalates) — e.g. medium → high if new
    evidence warrants it.

    Returns the created or updated Incident.
    """
    _SEVERITY_ORDER = {
        IncidentSeverity.LOW.value: 0,
        IncidentSeverity.MEDIUM.value: 1,
        IncidentSeverity.HIGH.value: 2,
        IncidentSeverity.CRITICAL.value: 3,
    }

    now = datetime.now(tz=timezone.utc)
    existing_id = get_active_incident_id(redis_client, key_suffix)

    if existing_id:
        incident = get_incident(redis_client, existing_id)
    else:
        incident = None

    if incident is None:
        # Create new incident
        incident = Incident(
            timestamp_opened=now,
            timestamp_updated=now,
            related_flow_ids=list(set(new_flow_ids)),
            related_detection_ids=list(set(new_detection_ids)),
            src_ip=src_ip,
            incident_type=incident_type,
            severity=severity,
            status=IncidentStatus.OPEN,
        )
        logger.info(
            "New incident created",
            extra={
                "incident_id": incident.incident_id,
                "incident_type": incident_type,
                "severity": severity,
                "src_ip": src_ip,
            },
        )
    else:
        # Append to existing — update flows, detections, severity, timestamp
        combined_flows = list(set(incident.related_flow_ids + new_flow_ids))
        combined_detections = list(set(incident.related_detection_ids + new_detection_ids))

        # Severity only escalates
        current_rank = _SEVERITY_ORDER.get(incident.severity, 0)
        new_rank = _SEVERITY_ORDER.get(severity.value if hasattr(severity, "value") else severity, 0)
        new_severity = severity if new_rank > current_rank else incident.severity

        # Mark escalated if severity changed or incident_type changed
        new_status = (
            IncidentStatus.ESCALATED
            if (new_severity != incident.severity or incident_type != incident.incident_type)
            else incident.status
        )

        incident = Incident(
            incident_id=incident.incident_id,
            timestamp_opened=incident.timestamp_opened,
            timestamp_updated=now,
            related_flow_ids=combined_flows,
            related_detection_ids=combined_detections,
            src_ip=src_ip if src_ip else incident.src_ip,
            incident_type=incident_type,
            severity=new_severity,
            status=new_status,
        )
        logger.info(
            "Incident updated",
            extra={
                "incident_id": incident.incident_id,
                "incident_type": incident_type,
                "severity": str(new_severity),
                "status": str(new_status),
            },
        )

    save_incident(redis_client, incident, key_suffix)

    # Emit to Kafka
    try:
        producer.produce(
            topic=output_topic,
            value=incident,
            key=incident.incident_id,
        )
    except Exception:
        logger.exception(
            "Failed to produce incident",
            extra={"incident_id": incident.incident_id},
        )

    return incident
