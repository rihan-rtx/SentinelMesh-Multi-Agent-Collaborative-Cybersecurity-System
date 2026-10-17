"""
SentinelMesh — Detection Agent (main.py)

Classifies network flows as benign / suspicious / malicious by applying the
rule engine (rules.py) to each FlowEvent, optionally enriched with any DPI
findings that arrived for the same flow_id.

Architecture (Section 2.1):
  Consumes: flow-events, dpi-findings
  Produces: detections
  Consumer group: detection-agent-group   (Section 10.7)

Dual-consumer design:
  Thread 1 — DPI findings listener: continuously polls dpi-findings and
    stores each finding in an in-memory cache keyed by flow_id. Findings
    expire after DPI_FINDING_CACHE_TTL_S (default 120s) to bound memory.

  Thread 2 (main) — Flow event consumer: for each flow-event, looks up any
    cached DPI findings for the same flow_id, runs the rule engine, and emits
    a DetectionResult.

Redis usage (Section 10.5):
  det:portscan:{src_ip}             — port scan tracking (rules.py)
  det:synflood:{dst_ip}:{dst_port}  — SYN flood tracking (rules.py)
  Degraded gracefully if Redis is unavailable (Section 10.12).

Section 9 acceptance criteria: validates input schema, emits valid output
schema, reports health pings, logs decisions.
"""

from __future__ import annotations

import logging
import os
import sys
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Optional

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
logger = logging.getLogger("detection")

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
    prom_port = int(os.getenv("PROMETHEUS_PORT_DETECTION", "9103"))
    start_http_server(prom_port)
    logger.info("Prometheus metrics server started", extra={"port": prom_port})
except Exception as exc:  # noqa: BLE001
    logger.warning("Could not start Prometheus server: %s", exc)

import redis as redis_lib

from agents.detection.rules import evaluate
from shared.kafka_client import SentinelConsumer, SentinelProducer, wait_for_kafka
from shared.schemas import (
    AgentHealthPing,
    AgentStatus,
    DetectionResult,
    DPIFinding,
    FlowEvent,
)

AGENT_NAME = "detection"
INPUT_TOPIC_FLOWS = "flow-events"
INPUT_TOPIC_DPI = "dpi-findings"
OUTPUT_TOPIC = "detections"
CONSUMER_GROUP = "detection-agent-group"  # Section 10.7

# ---------------------------------------------------------------------------
# Environment config (Section 10.11)
# ---------------------------------------------------------------------------

KAFKA_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
HEALTH_PING_INTERVAL_S = int(os.getenv("HEALTH_PING_INTERVAL_S", "5"))
HEALTH_KEY_TTL_S = int(os.getenv("HEALTH_KEY_TTL_S", "15"))

# How long to keep DPI findings in memory before evicting (seconds).
# Set to 2× the correlation window so findings are available even for
# slow-arriving flow events.
DPI_FINDING_CACHE_TTL_S: int = 120

# ---------------------------------------------------------------------------
# In-memory DPI finding cache
# ---------------------------------------------------------------------------
# { flow_id → [(DPIFinding, expiry_epoch_float)] }
_dpi_cache_lock = threading.Lock()
_dpi_cache: Dict[str, List] = defaultdict(list)

_events_consumed_flows: int = 0
_events_consumed_dpi: int = 0
_events_produced: int = 0

# Shared state
_producer: Optional[SentinelProducer] = None
_redis: Optional[redis_lib.Redis] = None


# ---------------------------------------------------------------------------
# DPI finding cache helpers
# ---------------------------------------------------------------------------

def _cache_dpi_finding(finding: DPIFinding) -> None:
    """Store a DPI finding in the in-memory cache with an expiry timestamp."""
    expiry = time.monotonic() + DPI_FINDING_CACHE_TTL_S
    with _dpi_cache_lock:
        _dpi_cache[finding.flow_id].append((finding, expiry))


def _get_dpi_findings(flow_id: str) -> List[DPIFinding]:
    """Return all non-expired DPI findings for the given flow_id."""
    now = time.monotonic()
    with _dpi_cache_lock:
        entries = _dpi_cache.get(flow_id, [])
        valid = [f for f, exp in entries if exp > now]
        if valid:
            # Keep only valid entries to avoid unbounded growth
            _dpi_cache[flow_id] = [(f, exp) for f, exp in entries if exp > now]
        else:
            _dpi_cache.pop(flow_id, None)
        return valid


def _evict_expired_cache_entries() -> None:
    """Periodic sweep to evict all expired cache entries."""
    now = time.monotonic()
    with _dpi_cache_lock:
        expired_keys = [
            fid for fid, entries in _dpi_cache.items()
            if all(exp <= now for _, exp in entries)
        ]
        for key in expired_keys:
            del _dpi_cache[key]


# ---------------------------------------------------------------------------
# DPI findings consumer thread
# ---------------------------------------------------------------------------

def _dpi_findings_consumer_loop() -> None:
    """
    Background thread: continuously consumes dpi-findings and caches them
    in memory so the main flow-event processor can look them up.
    """
    global _events_consumed_dpi

    dpi_consumer = SentinelConsumer(
        group_id=CONSUMER_GROUP,
        topics=[INPUT_TOPIC_DPI],
        bootstrap_servers=KAFKA_SERVERS,
        redis_client=_redis,
        producer=_producer,
    )

    logger.info("DPI findings listener started", extra={"topic": INPUT_TOPIC_DPI})

    def _handle_finding(finding: DPIFinding) -> None:
        global _events_consumed_dpi
        _events_consumed_dpi += 1
        EVENTS_CONSUMED.labels(agent=AGENT_NAME, topic=INPUT_TOPIC_DPI).inc()
        _cache_dpi_finding(finding)
        logger.debug(
            "DPI finding cached",
            extra={"finding_id": finding.finding_id, "flow_id": finding.flow_id},
        )

    dpi_consumer.consume_loop(
        schema=DPIFinding,
        callback=_handle_finding,
    )


# ---------------------------------------------------------------------------
# Cache eviction background thread
# ---------------------------------------------------------------------------

def _cache_eviction_loop() -> None:
    """Periodically sweep expired entries from the DPI finding cache."""
    while True:
        time.sleep(30)
        _evict_expired_cache_entries()
        logger.debug("DPI finding cache eviction sweep complete")


# ---------------------------------------------------------------------------
# Flow event processing (main classification path)
# ---------------------------------------------------------------------------

def _process_flow_event(flow: FlowEvent) -> None:
    """
    Core detection path for one FlowEvent.
    Enriches with cached DPI findings, runs the rule engine, emits a
    DetectionResult to the detections topic.
    """
    global _events_consumed_flows, _events_produced

    _events_consumed_flows += 1
    EVENTS_CONSUMED.labels(agent=AGENT_NAME, topic=INPUT_TOPIC_FLOWS).inc()

    with PROCESSING_LATENCY.labels(agent=AGENT_NAME).time():
        dpi_findings = _get_dpi_findings(flow.flow_id)

        result = evaluate(
            flow=flow,
            dpi_findings=dpi_findings,
            redis_client=_redis,
        )

    detection = DetectionResult(
        flow_id=flow.flow_id,
        timestamp=datetime.now(tz=timezone.utc),
        classification=result.classification,
        confidence=result.confidence,
        attack_type=result.attack_type,
        contributing_findings=result.contributing_findings,
    )

    try:
        _producer.produce(  # type: ignore[union-attr]
            topic=OUTPUT_TOPIC,
            value=detection,
            key=flow.flow_id,  # Section 10.7: message key = flow_id
        )
        _events_produced += 1
        EVENTS_PRODUCED.labels(agent=AGENT_NAME, topic=OUTPUT_TOPIC).inc()

        logger.info(
            "Detection emitted",
            extra={
                "detection_id": detection.detection_id,
                "flow_id": detection.flow_id,
                "classification": detection.classification,
                "confidence": detection.confidence,
                "attack_type": detection.attack_type,
                "contributing_findings": detection.contributing_findings,
            },
        )
    except Exception:
        ERRORS_TOTAL.labels(agent=AGENT_NAME, error_type="produce_error").inc()
        logger.exception(
            "Failed to produce detection",
            extra={"flow_id": flow.flow_id},
        )


# ---------------------------------------------------------------------------
# Health ping loop (Section 5.6)
# ---------------------------------------------------------------------------

def _health_ping_loop(redis_client: redis_lib.Redis) -> None:
    global _events_consumed_flows
    interval_start = 0

    while True:
        time.sleep(HEALTH_PING_INTERVAL_S)
        try:
            throughput = _events_consumed_flows - interval_start
            interval_start = _events_consumed_flows

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

    logger.info("Detection Agent starting")

    wait_for_kafka(bootstrap_servers=KAFKA_SERVERS)

    # Redis (graceful degradation per Section 10.12)
    try:
        _redis = redis_lib.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
        _redis.ping()
        logger.info("Redis connected")
    except Exception:
        logger.warning(
            "Redis unavailable — port scan and SYN flood rules disabled "
            "(operating in degraded mode)"
        )
        _redis = None

    _producer = SentinelProducer(bootstrap_servers=KAFKA_SERVERS)

    # Health ping daemon
    if _redis:
        threading.Thread(
            target=_health_ping_loop,
            args=(_redis,),
            name="health-ping",
            daemon=True,
        ).start()

    # DPI findings listener daemon
    threading.Thread(
        target=_dpi_findings_consumer_loop,
        name="dpi-findings-listener",
        daemon=True,
    ).start()

    # Cache eviction daemon
    threading.Thread(
        target=_cache_eviction_loop,
        name="cache-eviction",
        daemon=True,
    ).start()

    # Main flow-event consumer loop (blocks)
    consumer = SentinelConsumer(
        group_id=CONSUMER_GROUP,
        topics=[INPUT_TOPIC_FLOWS],
        bootstrap_servers=KAFKA_SERVERS,
        redis_client=_redis,
        producer=_producer,
    )

    logger.info(
        "Detection Agent consume loop starting",
        extra={"topic": INPUT_TOPIC_FLOWS},
    )
    consumer.consume_loop(
        schema=FlowEvent,
        callback=_process_flow_event,
    )


if __name__ == "__main__":
    main()
