"""
SentinelMesh — DPI Agent (main.py)

Consumes flow-events from Kafka, runs the DPI signature engine (Section 10.2)
against each flow's payload_sample, and emits DPIFinding messages for each
match to the dpi-findings topic.

Section 2.1: Consumes flow-events, produces dpi-findings.
Section 9 acceptance: validates input schema, emits valid output schema,
  reports health pings, logs decisions.
Section 10.7: consumer group dpi-agent-group.
"""

from __future__ import annotations

import logging
import os
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Optional

from dotenv import load_dotenv

load_dotenv()

# Structured logging
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
logger = logging.getLogger("dpi")

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
    prom_port = int(os.getenv("PROMETHEUS_PORT_DPI", "9102"))
    start_http_server(prom_port)
    logger.info("Prometheus metrics server started", extra={"port": prom_port})
except Exception as exc:  # noqa: BLE001
    logger.warning("Could not start Prometheus server: %s", exc)

import redis as redis_lib

from agents.dpi.signatures.engine import FindingResult, evaluate_payload
from shared.kafka_client import SentinelConsumer, SentinelProducer, wait_for_kafka
from shared.schemas import (
    AgentHealthPing,
    AgentStatus,
    DPIFinding,
    DPIMatchType,
    FlowEvent,
    Severity,
)

AGENT_NAME = "dpi"
INPUT_TOPIC = "flow-events"
OUTPUT_TOPIC = "dpi-findings"
CONSUMER_GROUP = "dpi-agent-group"  # Section 10.7

# ---------------------------------------------------------------------------
# Environment config
# ---------------------------------------------------------------------------

KAFKA_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
HEALTH_PING_INTERVAL_S = int(os.getenv("HEALTH_PING_INTERVAL_S", "5"))
HEALTH_KEY_TTL_S = int(os.getenv("HEALTH_KEY_TTL_S", "15"))
DPI_ENTROPY_THRESHOLD = float(os.getenv("DPI_ENTROPY_THRESHOLD", "7.2"))
DPI_MIN_SAMPLE_BYTES = int(os.getenv("DPI_MIN_SAMPLE_BYTES", "64"))

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

_producer: Optional[SentinelProducer] = None
_redis: Optional[redis_lib.Redis] = None
_events_consumed: int = 0
_events_produced: int = 0


# ---------------------------------------------------------------------------
# FlowEvent → DPI findings pipeline
# ---------------------------------------------------------------------------

def _severity_value(severity_str: str) -> str:
    """Map engine severity string to Severity enum value."""
    mapping = {"low": Severity.LOW, "medium": Severity.MEDIUM, "high": Severity.HIGH}
    return mapping.get(severity_str, Severity.LOW).value


def _process_flow_event(flow_event: FlowEvent) -> None:
    """
    Core DPI processing for one flow event.
    Runs all signatures against the payload_sample, emits one DPIFinding
    per match.
    """
    global _events_consumed, _events_produced

    _events_consumed += 1
    EVENTS_CONSUMED.labels(agent=AGENT_NAME, topic=INPUT_TOPIC).inc()

    if not flow_event.payload_sample:
        logger.debug(
            "No payload sample — skipping DPI",
            extra={"flow_id": flow_event.flow_id},
        )
        return

    with PROCESSING_LATENCY.labels(agent=AGENT_NAME).time():
        findings = evaluate_payload(
            payload_b64=flow_event.payload_sample,
            src_port=flow_event.src_port,
            dst_port=flow_event.dst_port,
            entropy_threshold=DPI_ENTROPY_THRESHOLD,
            min_sample_bytes=DPI_MIN_SAMPLE_BYTES,
        )

    if not findings:
        logger.debug(
            "No DPI findings",
            extra={"flow_id": flow_event.flow_id},
        )
        return

    for result in findings:
        _emit_finding(flow_event, result)


def _emit_finding(flow_event: FlowEvent, result: FindingResult) -> None:
    """Serialize one FindingResult into a DPIFinding and produce to Kafka."""
    global _events_produced

    finding = DPIFinding(
        flow_id=flow_event.flow_id,
        timestamp=datetime.now(tz=timezone.utc),
        match_type=result.match_type,
        signature_name=result.signature_name,
        anomaly_reason=result.anomaly_reason,
        severity=result.severity,
        raw_evidence=result.raw_evidence,
    )

    try:
        _producer.produce(  # type: ignore[union-attr]
            topic=OUTPUT_TOPIC,
            value=finding,
            key=flow_event.flow_id,  # Message key = flow_id per Section 10.7
        )
        _events_produced += 1
        EVENTS_PRODUCED.labels(agent=AGENT_NAME, topic=OUTPUT_TOPIC).inc()

        logger.info(
            "DPI finding emitted",
            extra={
                "finding_id": finding.finding_id,
                "flow_id": finding.flow_id,
                "match_type": finding.match_type,
                "signature_name": finding.signature_name,
                "anomaly_reason": finding.anomaly_reason,
                "severity": finding.severity,
            },
        )
    except Exception:
        ERRORS_TOTAL.labels(agent=AGENT_NAME, error_type="produce_error").inc()
        logger.exception(
            "Failed to produce DPI finding",
            extra={"flow_id": flow_event.flow_id},
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
                queue_depth=0,  # updated by consumer lag metric
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

    logger.info("DPI Agent starting")

    wait_for_kafka(bootstrap_servers=KAFKA_SERVERS)

    try:
        _redis = redis_lib.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
        _redis.ping()
        logger.info("Redis connected")
    except Exception:
        logger.warning("Redis unavailable — health pings disabled")
        _redis = None

    _producer = SentinelProducer(bootstrap_servers=KAFKA_SERVERS)

    # Health ping daemon thread
    if _redis:
        threading.Thread(
            target=_health_ping_loop,
            args=(_redis,),
            name="health-ping",
            daemon=True,
        ).start()

    # Main consume loop
    consumer = SentinelConsumer(
        group_id=CONSUMER_GROUP,
        topics=[INPUT_TOPIC],
        bootstrap_servers=KAFKA_SERVERS,
        redis_client=_redis,
        producer=_producer,
    )

    logger.info("DPI Agent consume loop starting", extra={"topic": INPUT_TOPIC})
    consumer.consume_loop(
        schema=FlowEvent,
        callback=_process_flow_event,
    )


if __name__ == "__main__":
    main()
