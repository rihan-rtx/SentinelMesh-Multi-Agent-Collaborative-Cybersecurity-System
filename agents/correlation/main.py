"""
SentinelMesh — Correlation Agent (main.py)

Groups detections and DPI findings across time and source IPs to identify
multi-stage attack incidents. Backed by Redis for sliding-window state.

Architecture (Section 2.1):
  Consumes: detections       (group: correlation-agent-group)
            dpi-findings     (group: correlation-agent-group)
            flow-events      (group: correlation-flow-context-group)  ← context only
  Produces: incidents

Three consumer threads:
  1. flow-context-thread   — populates flow:ctx:{flow_id} in Redis (read-only
                             for context resolution, Section 10.6). Never
                             evaluates flows for detection purposes.
  2. dpi-findings-thread   — adds findings to the per-src_ip window in Redis
                             so Rule 4 can combine them with detection signals.
  3. main-detections-thread— evaluates Rules 1–5 on each incoming detection
                             after resolving src/dst IPs from flow context.

Context late-arrival retry (Section 10.6):
  If flow context is not yet cached when a detection/finding arrives, the
  event is held in a short retry buffer (up to 2 seconds, 3 attempts) before
  being dropped with a warning.

Correlation rules (Section 10.4):
  1. Coordinated scan     — src_ip port_scan to ≥5 distinct dst_ips
  2. Multi-stage attack   — port_scan followed by malicious hit on same dst_ip
  3. Repeated malicious   — ≥3 malicious detections from same src_ip
  4. DPI-confirmed scan   — port_scan + DPI finding on same dst_ip
  5. Distributed target   — ≥3 distinct src_ips → same dst_ip (groups by dst)

Redis keys: see window_manager.py (Section 10.5).
"""

from __future__ import annotations

import logging
import os
import sys
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Deque, Dict, List, Optional, Tuple

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
logger = logging.getLogger("correlation")

# Prometheus metrics (Section 10.10) — imported from shared single-source definitions
from prometheus_client import start_http_server

from shared.metrics import (
    AGENT_UP,
    ERRORS_TOTAL,
    EVENTS_CONSUMED,
    EVENTS_PRODUCED,
    PROCESSING_LATENCY,
    QUEUE_DEPTH,
)

try:
    prom_port = int(os.getenv("PROMETHEUS_PORT_CORRELATION", "9104"))
    start_http_server(prom_port)
    logger.info("Prometheus metrics server started", extra={"port": prom_port})
except Exception as exc:
    logger.warning("Could not start Prometheus server: %s", exc)

import redis as redis_lib

from agents.correlation.window_manager import (
    CORRELATION_COORD_SCAN_DISTINCT_DST,
    CORRELATION_REPEATED_MALICIOUS_COUNT,
    CORRELATION_WINDOW_S,
    add_detection_to_window,
    add_finding_to_window,
    add_src_to_dst_sources,
    cache_flow_context,
    create_or_update_incident,
    get_active_incident_id,
    get_flow_context,
    get_window_detections,
    get_window_dpi_findings,
)
from shared.kafka_client import SentinelConsumer, SentinelProducer, wait_for_kafka
from shared.schemas import (
    AgentHealthPing,
    AgentStatus,
    Classification,
    DetectionResult,
    DPIFinding,
    FlowEvent,
    Incident,
    IncidentSeverity,
    Severity,
)

AGENT_NAME = "correlation"
INPUT_TOPIC_DETECTIONS = "detections"
INPUT_TOPIC_DPI = "dpi-findings"
INPUT_TOPIC_FLOWS = "flow-events"
OUTPUT_TOPIC = "incidents"
CONSUMER_GROUP = "correlation-agent-group"          # Section 10.7
CONTEXT_GROUP = "correlation-flow-context-group"    # Section 10.6 / 10.7

KAFKA_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
HEALTH_PING_INTERVAL_S = int(os.getenv("HEALTH_PING_INTERVAL_S", "5"))
HEALTH_KEY_TTL_S = int(os.getenv("HEALTH_KEY_TTL_S", "15"))

# Context retry settings (Section 10.6)
CONTEXT_RETRY_MAX_ATTEMPTS = 3
CONTEXT_RETRY_INTERVAL_S = 0.7  # ≈2s total across 3 attempts

_producer: Optional[SentinelProducer] = None
_redis: Optional[redis_lib.Redis] = None
_events_consumed: int = 0
_events_produced: int = 0


# ---------------------------------------------------------------------------
# Flow context resolution with retry (Section 10.6)
# ---------------------------------------------------------------------------

def _resolve_flow_context(flow_id: str) -> Optional[dict]:
    """
    Attempt to resolve flow context from Redis with up to 3 retries
    spaced ~0.7s apart (≈2s total). Logs a warning if unresolvable.
    """
    for attempt in range(1, CONTEXT_RETRY_MAX_ATTEMPTS + 1):
        ctx = get_flow_context(_redis, flow_id)
        if ctx:
            return ctx
        if attempt < CONTEXT_RETRY_MAX_ATTEMPTS:
            time.sleep(CONTEXT_RETRY_INTERVAL_S)

    logger.warning(
        "Flow context unresolvable after %d attempts — event skipped",
        CONTEXT_RETRY_MAX_ATTEMPTS,
        extra={"flow_id": flow_id},
    )
    ERRORS_TOTAL.labels(agent=AGENT_NAME, error_type="context_unresolvable").inc()
    return None


# ---------------------------------------------------------------------------
# Correlation rules (Section 10.4)
# ---------------------------------------------------------------------------

def _evaluate_detection(detection: DetectionResult, ctx: dict) -> None:
    """
    Apply all five correlation rules to a newly arrived detection, using the
    current Redis window state for the detection's src_ip / dst_ip.
    """
    src_ip: str = ctx["src_ip"]
    dst_ip: str = ctx["dst_ip"]
    now = time.time()

    # Cache the detection in the sliding window
    add_detection_to_window(
        _redis, src_ip,
        detection.detection_id,
        detection.model_dump_json(),
        now,
    )

    # Track distinct src_ips hitting dst_ip (for Rule 5)
    n_sources = add_src_to_dst_sources(_redis, dst_ip, src_ip)

    # Retrieve current window state
    window_detections = get_window_detections(_redis, src_ip)
    window_findings = get_window_dpi_findings(_redis, src_ip)

    # ---- Rule 5: Distributed target attack (group by dst_ip) ---------------
    # Check independently of src_ip-grouped rules.
    if n_sources >= 3:
        _trigger_incident(
            key_suffix=f"dst:{dst_ip}",
            incident_type="distributed_target_attack",
            severity=IncidentSeverity.HIGH,
            src_ip=None,        # Section 5.4: src_ip nullable for this rule
            detection_ids=[detection.detection_id],
            flow_ids=[detection.flow_id],
        )

    # ---- Rule 2: Multi-stage attack ----------------------------------------
    if detection.classification == Classification.MALICIOUS.value:
        scan_detections = [d for d in window_detections if d.attack_type == "port_scan"]
        if scan_detections:
            # Check if the malicious hit is against a dst_ip that was part of a
            # prior scan. We use the flow context cache for each scan detection.
            for scan_det in scan_detections:
                scan_ctx = get_flow_context(_redis, scan_det.flow_id)
                if scan_ctx and scan_ctx.get("dst_ip") == dst_ip:
                    severity = (
                        IncidentSeverity.CRITICAL
                        if detection.confidence >= 0.85
                        else IncidentSeverity.HIGH
                    )
                    _trigger_incident(
                        key_suffix=src_ip,
                        incident_type="multi_stage_attack",
                        severity=severity,
                        src_ip=src_ip,
                        detection_ids=[detection.detection_id, scan_det.detection_id],
                        flow_ids=[detection.flow_id, scan_det.flow_id],
                    )
                    return  # Highest-priority match for this src_ip
    elif detection.attack_type == "port_scan":
        # Alternate path: port_scan arrives after the malicious detection has already been cached
        malicious_detections = [
            d for d in window_detections
            if d.classification == Classification.MALICIOUS.value
        ]
        if malicious_detections:
            for mal_det in malicious_detections:
                mal_ctx = get_flow_context(_redis, mal_det.flow_id)
                if mal_ctx and mal_ctx.get("dst_ip") == dst_ip:
                    severity = (
                        IncidentSeverity.CRITICAL
                        if mal_det.confidence >= 0.85
                        else IncidentSeverity.HIGH
                    )
                    _trigger_incident(
                        key_suffix=src_ip,
                        incident_type="multi_stage_attack",
                        severity=severity,
                        src_ip=src_ip,
                        detection_ids=[detection.detection_id, mal_det.detection_id],
                        flow_ids=[detection.flow_id, mal_det.flow_id],
                    )
                    return  # Highest-priority match for this src_ip

    # ---- Rule 3: Repeated malicious ----------------------------------------
    malicious_detections = [
        d for d in window_detections
        if d.classification == Classification.MALICIOUS.value
    ]
    if len(malicious_detections) >= CORRELATION_REPEATED_MALICIOUS_COUNT:
        _trigger_incident(
            key_suffix=src_ip,
            incident_type="repeated_malicious",
            severity=IncidentSeverity.HIGH,
            src_ip=src_ip,
            detection_ids=[d.detection_id for d in malicious_detections],
            flow_ids=[d.flow_id for d in malicious_detections],
        )
        return

    # ---- Rule 1: Coordinated scan ------------------------------------------
    if detection.attack_type == "port_scan":
        # Count distinct dst_ips across all port_scan detections in window
        distinct_dst_ips: set = set()
        for d in window_detections:
            if d.attack_type == "port_scan":
                dctx = get_flow_context(_redis, d.flow_id)
                if dctx:
                    distinct_dst_ips.add(dctx["dst_ip"])
        distinct_dst_ips.add(dst_ip)  # include current detection's dst

        if len(distinct_dst_ips) >= CORRELATION_COORD_SCAN_DISTINCT_DST:
            _trigger_incident(
                key_suffix=src_ip,
                incident_type="coordinated_scan",
                severity=IncidentSeverity.MEDIUM,
                src_ip=src_ip,
                detection_ids=[detection.detection_id],
                flow_ids=[detection.flow_id],
            )
            return

    # ---- Rule 4: DPI-confirmed scan ----------------------------------------
    if detection.attack_type == "port_scan" and window_findings:
        # Check if any DPI finding's flow resolves to a dst_ip in the scan set
        for finding in window_findings:
            fctx = get_flow_context(_redis, finding.flow_id)
            if fctx and fctx.get("dst_ip") == dst_ip:
                dpi_severity = (
                    finding.severity if hasattr(finding.severity, "value")
                    else finding.severity
                )
                sev = (
                    IncidentSeverity.HIGH
                    if (dpi_severity == Severity.HIGH or dpi_severity == "high")
                    else IncidentSeverity.MEDIUM
                )
                _trigger_incident(
                    key_suffix=src_ip,
                    incident_type="dpi_confirmed_scan",
                    severity=sev,
                    src_ip=src_ip,
                    detection_ids=[detection.detection_id],
                    flow_ids=[detection.flow_id, finding.flow_id],
                )
                return


def _evaluate_dpi_finding(finding: DPIFinding, ctx: dict) -> None:
    """
    Cache the DPI finding in the per-src_ip window so Rule 4 can use it when
    a port_scan detection later arrives. No immediate rule evaluation here —
    Rule 4 is triggered from the detection path.
    """
    src_ip: str = ctx["src_ip"]
    add_finding_to_window(
        _redis, src_ip,
        finding.finding_id,
        finding.model_dump_json(),
        time.time(),
    )


def _trigger_incident(
    key_suffix: str,
    incident_type: str,
    severity: IncidentSeverity,
    src_ip: Optional[str],
    detection_ids: List[str],
    flow_ids: List[str],
) -> None:
    """Create or update an incident and emit it to Kafka."""
    global _events_produced
    incident = create_or_update_incident(
        redis_client=_redis,
        key_suffix=key_suffix,
        incident_type=incident_type,
        severity=severity,
        src_ip=src_ip,
        new_flow_ids=flow_ids,
        new_detection_ids=detection_ids,
        producer=_producer,
        output_topic=OUTPUT_TOPIC,
    )
    _events_produced += 1
    EVENTS_PRODUCED.labels(agent=AGENT_NAME, topic=OUTPUT_TOPIC).inc()


# ---------------------------------------------------------------------------
# Consumer callbacks
# ---------------------------------------------------------------------------

def _handle_flow_event(flow: FlowEvent) -> None:
    """Context-only handler: caches flow context in Redis, no detection logic."""
    EVENTS_CONSUMED.labels(agent=AGENT_NAME, topic=INPUT_TOPIC_FLOWS).inc()
    cache_flow_context(
        _redis,
        flow_id=flow.flow_id,
        src_ip=flow.src_ip,
        dst_ip=flow.dst_ip,
        src_port=flow.src_port,
        dst_port=flow.dst_port,
        protocol=str(flow.protocol),
    )


def _handle_detection(detection: DetectionResult) -> None:
    """Main detection handler: resolve context, run rules."""
    global _events_consumed
    _events_consumed += 1
    EVENTS_CONSUMED.labels(agent=AGENT_NAME, topic=INPUT_TOPIC_DETECTIONS).inc()

    with PROCESSING_LATENCY.labels(agent=AGENT_NAME).time():
        ctx = _resolve_flow_context(detection.flow_id)
        if ctx is None:
            return
        _evaluate_detection(detection, ctx)


def _handle_dpi_finding(finding: DPIFinding) -> None:
    """DPI finding handler: resolve context, cache in window for Rule 4."""
    EVENTS_CONSUMED.labels(agent=AGENT_NAME, topic=INPUT_TOPIC_DPI).inc()
    ctx = _resolve_flow_context(finding.flow_id)
    if ctx is None:
        return
    _evaluate_dpi_finding(finding, ctx)


# ---------------------------------------------------------------------------
# Consumer threads
# ---------------------------------------------------------------------------

def _flow_context_consumer_loop() -> None:
    """Thread 1: Consumes flow-events purely for context caching."""
    consumer = SentinelConsumer(
        group_id=CONTEXT_GROUP,
        topics=[INPUT_TOPIC_FLOWS],
        bootstrap_servers=KAFKA_SERVERS,
        redis_client=_redis,
        producer=_producer,
    )
    logger.info("Flow context consumer started")
    consumer.consume_loop(
        schema=FlowEvent,
        callback=_handle_flow_event,
    )


def _dpi_findings_consumer_loop() -> None:
    """Thread 2: Consumes dpi-findings and caches them for Rule 4."""
    consumer = SentinelConsumer(
        group_id=CONSUMER_GROUP,
        topics=[INPUT_TOPIC_DPI],
        bootstrap_servers=KAFKA_SERVERS,
        redis_client=_redis,
        producer=_producer,
    )
    logger.info("DPI findings consumer started")
    consumer.consume_loop(
        schema=DPIFinding,
        callback=_handle_dpi_finding,
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

            status = AgentStatus.HEALTHY if _redis else AgentStatus.DEGRADED
            ping = AgentHealthPing(
                agent_name=AGENT_NAME,
                timestamp=datetime.now(tz=timezone.utc),
                status=status,
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

    logger.info("Correlation Agent starting")

    wait_for_kafka(bootstrap_servers=KAFKA_SERVERS)

    try:
        _redis = redis_lib.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
        _redis.ping()
        logger.info("Redis connected")
    except Exception:
        logger.warning(
            "Redis unavailable — correlation rules disabled (degraded mode)"
        )
        _redis = None

    _producer = SentinelProducer(bootstrap_servers=KAFKA_SERVERS)

    if _redis is None:
        logger.error(
            "Correlation Agent requires Redis for sliding-window state. "
            "Running in degraded mode — no incidents will be emitted."
        )

    # Health ping
    if _redis:
        threading.Thread(
            target=_health_ping_loop,
            args=(_redis,),
            name="health-ping",
            daemon=True,
        ).start()

    # Thread 1: flow context cache
    threading.Thread(
        target=_flow_context_consumer_loop,
        name="flow-context",
        daemon=True,
    ).start()

    # Thread 2: DPI findings cache
    threading.Thread(
        target=_dpi_findings_consumer_loop,
        name="dpi-findings",
        daemon=True,
    ).start()

    # Thread 3 (main): detections consumer — blocks
    consumer = SentinelConsumer(
        group_id=CONSUMER_GROUP,
        topics=[INPUT_TOPIC_DETECTIONS],
        bootstrap_servers=KAFKA_SERVERS,
        redis_client=_redis,
        producer=_producer,
    )
    logger.info("Correlation Agent consume loop starting",
                extra={"topic": INPUT_TOPIC_DETECTIONS})
    consumer.consume_loop(
        schema=DetectionResult,
        callback=_handle_detection,
    )


if __name__ == "__main__":
    main()
