"""
SentinelMesh — Dashboard Writer Agent (main.py)

Consumes detections, incidents, and actions from Kafka and upserts each
message into the matching PostgreSQL table (Section 10.9), so Grafana panels
have live data.

Architecture (Section 2.1):
  Consumes: detections  (group: dashboard-writer-group)
            incidents   (group: dashboard-writer-group)
            actions     (group: dashboard-writer-group)
  Produces: nothing (pure sink)

Three consumer threads — one per topic — all sharing the same consumer group
so each message is processed exactly once across the group.

Upsert strategy:
  INSERT ... ON CONFLICT (pk) DO UPDATE
  Incident updates/escalations overwrite the existing row rather than creating
  duplicates, matching the test harness's own dedup-by-incident_id logic.

FK ordering and retry (actions → incidents FK):
  The actions table has a FK constraint on incident_id. On a fresh replay from
  offset 0 (every e2e test run), an action message can arrive at the actions
  thread before the parent incident row has been committed by the incidents
  thread. Rather than immediately DLQ-ing this real action row (which would
  permanently lose it from the dashboard), we apply a targeted FK-violation
  retry: up to FK_RETRY_MAX_ATTEMPTS attempts with exponential backoff
  (FK_RETRY_BACKOFF_S * 2^attempt) before falling back to raising and letting
  the shared consumer's DLQ logic handle it.

Section 10.7: consumer group dashboard-writer-group.
"""

from __future__ import annotations

import logging
import os
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Optional

import psycopg2
import psycopg2.errorcodes
import psycopg2.extras
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
logger = logging.getLogger("dashboard_writer")

import redis as redis_lib

from shared.kafka_client import SentinelConsumer, SentinelProducer, wait_for_kafka
from shared.schemas import (
    Action,
    AgentHealthPing,
    AgentStatus,
    DetectionResult,
    Incident,
)

AGENT_NAME = "dashboard-writer"
CONSUMER_GROUP = "dashboard-writer-group"  # Section 10.7

KAFKA_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
HEALTH_PING_INTERVAL_S = int(os.getenv("HEALTH_PING_INTERVAL_S", "5"))
HEALTH_KEY_TTL_S = int(os.getenv("HEALTH_KEY_TTL_S", "15"))

# Postgres connection config (Section 10.11 / .env)
POSTGRES_HOST = os.getenv("POSTGRES_HOST", "postgres")
POSTGRES_PORT = int(os.getenv("POSTGRES_PORT", "5432"))
POSTGRES_DB = os.getenv("POSTGRES_DB", "sentinelmesh")
POSTGRES_USER = os.getenv("POSTGRES_USER", "sentinelmesh")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "changeme")

# FK-violation retry config — targeted retry for actions-before-incident race.
# 3 attempts at 0.5s, 1s, 2s -> 3.5s total before falling back to DLQ.
FK_RETRY_MAX_ATTEMPTS: int = 3
FK_RETRY_BACKOFF_S: float = 0.5

_redis: Optional[redis_lib.Redis] = None
_producer: Optional[SentinelProducer] = None
_events_consumed: int = 0


# ---------------------------------------------------------------------------
# Postgres connection
# ---------------------------------------------------------------------------

def _get_pg_conn() -> psycopg2.extensions.connection:
    """
    Open and return a new psycopg2 connection.
    Each upsert opens its own short-lived connection (no pool needed at this
    throughput; avoids cross-thread connection sharing issues).
    """
    return psycopg2.connect(
        host=POSTGRES_HOST,
        port=POSTGRES_PORT,
        dbname=POSTGRES_DB,
        user=POSTGRES_USER,
        password=POSTGRES_PASSWORD,
    )


def _wait_for_postgres(max_retries: int = 30, backoff_s: float = 2.0) -> None:
    """Block until Postgres is reachable, mirroring wait_for_kafka pattern."""
    for attempt in range(1, max_retries + 1):
        try:
            conn = _get_pg_conn()
            conn.close()
            logger.info("Postgres is available at %s:%d", POSTGRES_HOST, POSTGRES_PORT)
            return
        except Exception as exc:
            logger.warning(
                "Postgres not available (attempt %d/%d), retrying in %.1fs: %s",
                attempt, max_retries, backoff_s, exc,
            )
            time.sleep(backoff_s)
    raise RuntimeError(
        f"Postgres not available at {POSTGRES_HOST}:{POSTGRES_PORT} after {max_retries} attempts"
    )


# ---------------------------------------------------------------------------
# Upsert helpers
# ---------------------------------------------------------------------------

def _upsert_detection(detection: DetectionResult) -> None:
    """
    INSERT INTO detections ... ON CONFLICT (detection_id) DO UPDATE.
    Detections are immutable after emission — the DO UPDATE is a no-op in
    practice but ensures idempotent replay from offset 0.
    """
    sql = """
        INSERT INTO detections (detection_id, flow_id, ts, classification, confidence, attack_type)
        VALUES (%s, %s, %s, %s, %s, %s)
        ON CONFLICT (detection_id) DO UPDATE SET
            flow_id        = EXCLUDED.flow_id,
            ts             = EXCLUDED.ts,
            classification = EXCLUDED.classification,
            confidence     = EXCLUDED.confidence,
            attack_type    = EXCLUDED.attack_type
    """
    with _get_pg_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (
                detection.detection_id,
                detection.flow_id,
                detection.timestamp,
                detection.classification,
                detection.confidence,
                detection.attack_type,
            ))
        conn.commit()
    logger.debug(
        "Upserted detection",
        extra={"detection_id": detection.detection_id, "classification": detection.classification},
    )


def _upsert_incident(incident: Incident) -> None:
    """
    INSERT INTO incidents ... ON CONFLICT (incident_id) DO UPDATE.
    Escalated incidents overwrite all mutable columns so the dashboard always
    shows the latest state — mirrors the test harness's dedup-by-incident_id.
    """
    sql = """
        INSERT INTO incidents (incident_id, ts_opened, ts_updated, src_ip, incident_type, severity, status)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (incident_id) DO UPDATE SET
            ts_updated    = EXCLUDED.ts_updated,
            src_ip        = EXCLUDED.src_ip,
            incident_type = EXCLUDED.incident_type,
            severity      = EXCLUDED.severity,
            status        = EXCLUDED.status
    """
    with _get_pg_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (
                incident.incident_id,
                incident.timestamp_opened,
                incident.timestamp_updated,
                incident.src_ip,
                incident.incident_type,
                incident.severity,
                incident.status,
            ))
        conn.commit()
    logger.debug(
        "Upserted incident",
        extra={
            "incident_id": incident.incident_id,
            "incident_type": incident.incident_type,
            "severity": incident.severity,
            "status": incident.status,
        },
    )


def _upsert_action_with_fk_retry(action: Action) -> None:
    """
    INSERT INTO actions ... ON CONFLICT (action_id) DO UPDATE.

    FK retry: if the insert fails with a FOREIGN KEY VIOLATION (23503) because
    the parent incident row hasn't been committed yet, retry up to
    FK_RETRY_MAX_ATTEMPTS times with exponential backoff before re-raising.
    This handles the realistic race on fresh replay from offset 0 where the
    actions consumer thread outpaces the incidents consumer thread.
    """
    sql = """
        INSERT INTO actions (action_id, incident_id, ts, action_type, target)
        VALUES (%s, %s, %s, %s, %s)
        ON CONFLICT (action_id) DO UPDATE SET
            incident_id = EXCLUDED.incident_id,
            ts          = EXCLUDED.ts,
            action_type = EXCLUDED.action_type,
            target      = EXCLUDED.target
    """
    params = (
        action.action_id,
        action.incident_id,
        action.timestamp,
        action.action_type,
        action.target,
    )

    last_exc: Optional[Exception] = None
    for attempt in range(FK_RETRY_MAX_ATTEMPTS):
        try:
            with _get_pg_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(sql, params)
                conn.commit()
            logger.debug(
                "Upserted action",
                extra={"action_id": action.action_id, "incident_id": action.incident_id},
            )
            return  # success

        except psycopg2.Error as exc:
            # pgcode 23503 = FOREIGN KEY VIOLATION
            if exc.pgcode == psycopg2.errorcodes.FOREIGN_KEY_VIOLATION:
                backoff = FK_RETRY_BACKOFF_S * (2 ** attempt)
                logger.warning(
                    "FK violation on action upsert — parent incident not yet committed "
                    "(attempt %d/%d), retrying in %.1fs",
                    attempt + 1, FK_RETRY_MAX_ATTEMPTS, backoff,
                    extra={"action_id": action.action_id, "incident_id": action.incident_id},
                )
                last_exc = exc
                time.sleep(backoff)
            else:
                # Non-FK Postgres error — don't retry, raise immediately
                raise

    # All FK retries exhausted — re-raise so the shared consumer DLQ logic
    # routes this message for manual inspection
    raise RuntimeError(
        f"FK retry exhausted for action {action.action_id} "
        f"(incident {action.incident_id} not found after {FK_RETRY_MAX_ATTEMPTS} attempts)"
    ) from last_exc


# ---------------------------------------------------------------------------
# Consumer callbacks
# ---------------------------------------------------------------------------

def _handle_detection(detection: DetectionResult) -> None:
    global _events_consumed
    _events_consumed += 1
    _upsert_detection(detection)


def _handle_incident(incident: Incident) -> None:
    global _events_consumed
    _events_consumed += 1
    _upsert_incident(incident)


def _handle_action(action: Action) -> None:
    global _events_consumed
    _events_consumed += 1
    _upsert_action_with_fk_retry(action)


# ---------------------------------------------------------------------------
# Consumer threads
# ---------------------------------------------------------------------------

def _detections_consumer_loop() -> None:
    """Thread: consumes detections topic and upserts into Postgres."""
    consumer = SentinelConsumer(
        group_id=CONSUMER_GROUP,
        topics=["detections"],
        bootstrap_servers=KAFKA_SERVERS,
        redis_client=_redis,
        producer=_producer,
    )
    logger.info("Detections consumer started")
    consumer.consume_loop(schema=DetectionResult, callback=_handle_detection)


def _incidents_consumer_loop() -> None:
    """Thread: consumes incidents topic and upserts into Postgres."""
    consumer = SentinelConsumer(
        group_id=CONSUMER_GROUP,
        topics=["incidents"],
        bootstrap_servers=KAFKA_SERVERS,
        redis_client=_redis,
        producer=_producer,
    )
    logger.info("Incidents consumer started")
    consumer.consume_loop(schema=Incident, callback=_handle_incident)


def _actions_consumer_loop() -> None:
    """Thread: consumes actions topic and upserts into Postgres."""
    consumer = SentinelConsumer(
        group_id=CONSUMER_GROUP,
        topics=["actions"],
        bootstrap_servers=KAFKA_SERVERS,
        redis_client=_redis,
        producer=_producer,
    )
    logger.info("Actions consumer started")
    consumer.consume_loop(schema=Action, callback=_handle_action)


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
        except Exception:
            logger.exception("Failed to send health ping")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    global _redis, _producer

    logger.info("Dashboard Writer Agent starting")

    wait_for_kafka(bootstrap_servers=KAFKA_SERVERS)
    _wait_for_postgres()

    try:
        _redis = redis_lib.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
        _redis.ping()
        logger.info("Redis connected")
    except Exception:
        logger.warning("Redis unavailable — dedup guard and health pings disabled")
        _redis = None

    # Producer is required for DLQ routing on persistent failures
    _producer = SentinelProducer(bootstrap_servers=KAFKA_SERVERS)

    if _redis:
        threading.Thread(
            target=_health_ping_loop,
            args=(_redis,),
            name="health-ping",
            daemon=True,
        ).start()

    # Start incidents thread first, then detections, then actions last.
    # This ordering gives the incidents thread a head-start so parent rows
    # are more likely committed before FK-constrained action rows arrive,
    # reducing (not eliminating) the need for FK retries on fast replays.
    threading.Thread(
        target=_incidents_consumer_loop,
        name="incidents-consumer",
        daemon=True,
    ).start()

    threading.Thread(
        target=_detections_consumer_loop,
        name="detections-consumer",
        daemon=True,
    ).start()

    # Actions thread starts last — see FK ordering note above
    threading.Thread(
        target=_actions_consumer_loop,
        name="actions-consumer",
        daemon=True,
    ).start()

    logger.info("Dashboard Writer Agent running — consuming detections, incidents, actions")
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        logger.info("Dashboard Writer Agent shutting down")


if __name__ == "__main__":
    main()
