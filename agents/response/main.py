"""
SentinelMesh — Response Agent (main.py)

Consumes incidents from the incidents topic and decides the appropriate action
(log_only or alert), writes a structured JSON audit log entry, and emits an
Action message to the actions topic.

Architecture (Section 2.1):
  Consumes: incidents   (group: response-agent-group)
  Produces: actions

Action selection (Section 10.4.1):
  Only log_only and alert are implemented. recommend_block is intentionally
  not implemented in this version (see Section 8 / production gap).

  Severity rank (low to high): low(0) < medium(1) < high(2) < critical(3).
  RESPONSE_ALERT_SEVERITY_THRESHOLD (env, default "high") sets the minimum
  severity rank that produces action_type="alert". Incidents below the
  threshold produce action_type="log_only".

  Default (threshold="high"): critical/high -> alert, medium/low -> log_only.
  target = incident.src_ip for alert (null when src_ip is itself null, e.g.
  distributed_target_attack incidents where src_ip is not applicable).

Audit log (Section 1.5 output requirement):
  Every action is written as a JSON line to AUDIT_LOG_PATH (default
  /var/log/sentinelmesh/audit.log). Each entry includes the full action
  schema plus a reference to the incident, making the audit trail fully
  traceable back to the specific incident that triggered it.

Section 9 acceptance: validates input schema, emits valid output schema,
reports health pings, logs every decision.
Section 10.7: consumer group response-agent-group.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

load_dotenv()

from pythonjsonlogger import jsonlogger  # type: ignore

_log_level = os.getenv("LOG_LEVEL", "INFO").upper()
_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(
    jsonlogger.JsonFormatter(
        fmt="%(asctime)s %(name)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )
)
logging.basicConfig(level=_log_level, handlers=[_handler])
logger = logging.getLogger("response")

# Prometheus metrics (Section 10.10) — imported from shared single-source definitions
from prometheus_client import start_http_server

from shared.metrics import (
    AGENT_UP,
    ERRORS_TOTAL,
    EVENTS_CONSUMED,
    EVENTS_PRODUCED,
    PROCESSING_LATENCY,
)

try:
    prom_port = int(os.getenv("PROMETHEUS_PORT_RESPONSE", "9105"))
    start_http_server(prom_port)
    logger.info("Prometheus metrics server started", extra={"port": prom_port})
except Exception as exc:
    logger.warning("Could not start Prometheus server: %s", exc)

import redis as redis_lib

from shared.kafka_client import SentinelConsumer, SentinelProducer, wait_for_kafka
from shared.schemas import (
    Action,
    ActionType,
    AgentHealthPing,
    AgentStatus,
    Incident,
    IncidentSeverity,
)

AGENT_NAME = "response"
INPUT_TOPIC = "incidents"
OUTPUT_TOPIC = "actions"
CONSUMER_GROUP = "response-agent-group"  # Section 10.7

KAFKA_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
HEALTH_PING_INTERVAL_S = int(os.getenv("HEALTH_PING_INTERVAL_S", "5"))
HEALTH_KEY_TTL_S = int(os.getenv("HEALTH_KEY_TTL_S", "15"))
AUDIT_LOG_PATH = os.getenv("AUDIT_LOG_PATH", "/var/log/sentinelmesh/audit.log")

_producer: Optional[SentinelProducer] = None
_redis: Optional[redis_lib.Redis] = None
_events_consumed: int = 0
_events_produced: int = 0

# ---------------------------------------------------------------------------
# Section 10.4.1 — Severity rank table and configurable alert threshold
# ---------------------------------------------------------------------------

# Canonical rank mapping (low to high). Used for comparison only;
# the string values in the schema remain unchanged.
_SEVERITY_RANK: dict = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}

_RAW_THRESHOLD = os.getenv("RESPONSE_ALERT_SEVERITY_THRESHOLD", "high").lower().strip()
if _RAW_THRESHOLD not in _SEVERITY_RANK:
    raise ValueError(
        f"RESPONSE_ALERT_SEVERITY_THRESHOLD='{_RAW_THRESHOLD}' is not a valid severity. "
        f"Must be one of: {list(_SEVERITY_RANK)}"
    )
RESPONSE_ALERT_THRESHOLD_RANK: int = _SEVERITY_RANK[_RAW_THRESHOLD]
RESPONSE_ALERT_THRESHOLD_NAME: str = _RAW_THRESHOLD

logger.info(
    "Response Agent alert threshold configured",
    extra={
        "threshold": RESPONSE_ALERT_THRESHOLD_NAME,
        "rank": RESPONSE_ALERT_THRESHOLD_RANK,
    },
)


# ---------------------------------------------------------------------------
# Audit log writer
# ---------------------------------------------------------------------------

def _ensure_audit_log_dir() -> None:
    """Create the audit log directory if it doesn't exist."""
    log_dir = Path(AUDIT_LOG_PATH).parent
    log_dir.mkdir(parents=True, exist_ok=True)


def _write_audit_entry(action: Action, incident: Incident) -> None:
    """
    Write one JSON-line audit entry for the given action + incident.
    Each entry is a self-contained record that links action → incident →
    detection IDs, making the audit trail fully traceable (Section 1.5).
    """
    entry = {
        "audit_timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "action_id": action.action_id,
        "action_type": action.action_type,
        "target": action.target,
        "executed": action.executed,
        "incident_id": incident.incident_id,
        "incident_type": incident.incident_type,
        "incident_severity": str(incident.severity),
        "incident_status": str(incident.status),
        "src_ip": incident.src_ip,
        "related_flow_ids": incident.related_flow_ids,
        "related_detection_ids": incident.related_detection_ids,
        "operator_note": action.operator_note,
    }
    try:
        with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
    except Exception:
        logger.exception(
            "Failed to write audit log entry",
            extra={"action_id": action.action_id},
        )
        ERRORS_TOTAL.labels(agent=AGENT_NAME, error_type="audit_log_write_error").inc()


# ---------------------------------------------------------------------------
# Action selection (Section 10.4.1)
# ---------------------------------------------------------------------------

def _select_action(incident: Incident) -> tuple[ActionType, Optional[str]]:
    """
    Compare incident severity rank to RESPONSE_ALERT_THRESHOLD_RANK.

    If incident_rank >= threshold_rank  -> alert,  target = incident.src_ip
                                                    (null when src_ip is null,
                                                     e.g. distributed_target_attack)
    Otherwise                           -> log_only, target = null

    Returns (action_type, target).
    """
    sev_str = (
        incident.severity
        if isinstance(incident.severity, str)
        else incident.severity.value
    )
    incident_rank = _SEVERITY_RANK.get(sev_str, -1)
    if incident_rank == -1:
        # Unknown severity value — fail safe: log_only and record an error
        logger.error(
            "Unknown incident severity — defaulting to log_only",
            extra={"severity": sev_str, "incident_id": incident.incident_id},
        )
        ERRORS_TOTAL.labels(agent=AGENT_NAME, error_type="unknown_severity").inc()
        return ActionType.LOG_ONLY, None

    if incident_rank >= RESPONSE_ALERT_THRESHOLD_RANK:
        # src_ip may be null for distributed_target_attack — pass through as-is
        return ActionType.ALERT, incident.src_ip
    return ActionType.LOG_ONLY, None


# ---------------------------------------------------------------------------
# Incident handler
# ---------------------------------------------------------------------------

def _process_incident(incident: Incident) -> None:
    """
    Core response logic for one incident:
    1. Decide action_type and target.
    2. Build and emit an Action to Kafka.
    3. Write to structured audit log.
    """
    global _events_consumed, _events_produced

    _events_consumed += 1
    EVENTS_CONSUMED.labels(agent=AGENT_NAME, topic=INPUT_TOPIC).inc()

    with PROCESSING_LATENCY.labels(agent=AGENT_NAME).time():
        action_type, target = _select_action(incident)

        action = Action(
            incident_id=incident.incident_id,
            timestamp=datetime.now(tz=timezone.utc),
            action_type=action_type,
            target=target,
            executed=True,
            operator_note=None,
        )

    # Emit to actions topic
    try:
        _producer.produce(  # type: ignore[union-attr]
            topic=OUTPUT_TOPIC,
            value=action,
            key=incident.incident_id,  # Section 10.7: message key = incident_id
        )
        _events_produced += 1
        EVENTS_PRODUCED.labels(agent=AGENT_NAME, topic=OUTPUT_TOPIC).inc()
    except Exception:
        ERRORS_TOTAL.labels(agent=AGENT_NAME, error_type="produce_error").inc()
        logger.exception("Failed to produce action", extra={"incident_id": incident.incident_id})

    # Write audit log
    _write_audit_entry(action, incident)

    logger.info(
        "Action taken",
        extra={
            "action_id": action.action_id,
            "action_type": str(action.action_type),
            "incident_id": incident.incident_id,
            "incident_type": incident.incident_type,
            "severity": str(incident.severity),
            "target": target,
        },
    )


# ---------------------------------------------------------------------------
# Health ping loop (Section 5.6)
# ---------------------------------------------------------------------------

def _health_ping_loop(redis_client: redis_lib.Redis) -> None:
    global _events_consumed
    interval_start = 0

    while True:
        time.sleep(HEALTH_PING_INTERVAL_S)
        try:
            throughput = _events_consumed - interval_start
            interval_start = _events_consumed

            ping = AgentHealthPing(
                agent_name=AGENT_NAME,
                timestamp=datetime.now(tz=timezone.utc),
                status=AgentStatus.HEALTHY,
                throughput_last_interval=throughput,
                queue_depth=0,
            )
            redis_client.set(
                f"health:{AGENT_NAME}",
                ping.model_dump_json(),
                ex=HEALTH_KEY_TTL_S,
            )
            AGENT_UP.labels(agent=AGENT_NAME).set(1)
        except Exception:
            AGENT_UP.labels(agent=AGENT_NAME).set(0)
            logger.exception("Failed to send health ping")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    global _producer, _redis

    logger.info("Response Agent starting")

    _ensure_audit_log_dir()

    wait_for_kafka(bootstrap_servers=KAFKA_SERVERS)

    try:
        _redis = redis_lib.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
        _redis.ping()
        logger.info("Redis connected")
    except Exception:
        logger.warning("Redis unavailable — health pings disabled")
        _redis = None

    _producer = SentinelProducer(bootstrap_servers=KAFKA_SERVERS)

    if _redis:
        threading.Thread(
            target=_health_ping_loop,
            args=(_redis,),
            name="health-ping",
            daemon=True,
        ).start()

    consumer = SentinelConsumer(
        group_id=CONSUMER_GROUP,
        topics=[INPUT_TOPIC],
        bootstrap_servers=KAFKA_SERVERS,
        redis_client=_redis,
        producer=_producer,
    )

    logger.info("Response Agent consume loop starting", extra={"topic": INPUT_TOPIC})
    consumer.consume_loop(
        schema=Incident,
        callback=_process_incident,
    )


if __name__ == "__main__":
    main()
