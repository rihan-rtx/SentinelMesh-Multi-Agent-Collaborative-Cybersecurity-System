"""
SentinelMesh — Coordinator Agent (main.py)

Monitors the health of all other agents by polling their Redis health keys
(Section 10.5: health:{agent_name}) and exposes per-agent liveness as
Prometheus metrics.

Design (Section 2.1 / Section 10.12):
  - Does NOT consume from any Kafka topic.
  - Polls Redis for health:{agent_name} keys every HEALTH_PING_INTERVAL_S.
  - If a key is present (not expired) → agent is UP → sentinelmesh_agent_up=1
  - If a key is absent (expired or never set) → agent is DOWN → agent_up=0
  - Restart-on-failure is handled entirely by Docker Compose
    (restart: on-failure), not by this agent — this agent only observes.
  - Logs status changes at INFO level so the change is visible in the
    aggregated log stream.

Section 10.5 key:  health:{agent_name}   String (JSON), TTL = HEALTH_KEY_TTL_S
Section 10.10:     sentinelmesh_agent_up  Gauge, label=agent, set by Coordinator.

The Coordinator also reports its own health ping to Redis so it is itself
visible on the Grafana dashboard.
"""

from __future__ import annotations

import logging
import os
import sys
import time
from datetime import datetime, timezone
from typing import Dict, Optional, Set

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
logger = logging.getLogger("coordinator")

# Prometheus metrics (Section 10.10) — imported from shared single-source definitions
from prometheus_client import start_http_server

from shared.metrics import AGENT_UP, ERRORS_TOTAL

try:
    prom_port = int(os.getenv("PROMETHEUS_PORT_COORDINATOR", "9106"))
    start_http_server(prom_port)
    logger.info("Prometheus metrics server started", extra={"port": prom_port})
except Exception as exc:
    logger.warning("Could not start Prometheus server: %s", exc)

import redis as redis_lib

from shared.schemas import AgentHealthPing, AgentStatus

AGENT_NAME = "coordinator"

KAFKA_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
HEALTH_PING_INTERVAL_S = int(os.getenv("HEALTH_PING_INTERVAL_S", "5"))
HEALTH_KEY_TTL_S = int(os.getenv("HEALTH_KEY_TTL_S", "15"))

# All agents the Coordinator tracks (must match AGENT_NAME values used by
# each agent's health ping — Section 5.6).
TRACKED_AGENTS: tuple = (
    "sniffer",
    "dpi",
    "detection",
    "correlation",
    "response",
)


# ---------------------------------------------------------------------------
# Health polling loop
# ---------------------------------------------------------------------------

def _poll_health(redis_client: redis_lib.Redis) -> None:
    """
    Main polling loop. Runs forever, checking each tracked agent's health
    key once per HEALTH_PING_INTERVAL_S and updating AGENT_UP accordingly.
    Logs state changes (up→down or down→up) at INFO level.
    """
    # Track last-known state to avoid log spam on repeated same-state polls
    last_known: Dict[str, bool] = {agent: True for agent in TRACKED_AGENTS}

    # Initialise all metrics to 0 on startup (until we confirm liveness)
    for agent in TRACKED_AGENTS:
        AGENT_UP.labels(agent=agent).set(0)

    while True:
        try:
            for agent in TRACKED_AGENTS:
                key = f"health:{agent}"
                raw = redis_client.get(key)
                is_up = raw is not None

                AGENT_UP.labels(agent=agent).set(1 if is_up else 0)

                # Log only on state transitions
                if is_up != last_known[agent]:
                    if is_up:
                        logger.info(
                            "Agent came online",
                            extra={"agent": agent},
                        )
                    else:
                        logger.warning(
                            "Agent is DOWN — health key expired",
                            extra={"agent": agent},
                        )
                    last_known[agent] = is_up

            # Publish coordinator's own health ping
            ping = AgentHealthPing(
                agent_name=AGENT_NAME,
                timestamp=datetime.now(tz=timezone.utc),
                status=AgentStatus.HEALTHY,
                throughput_last_interval=0,
                queue_depth=0,
            )
            redis_client.set(
                f"health:{AGENT_NAME}",
                ping.model_dump_json(),
                ex=HEALTH_KEY_TTL_S,
            )
            AGENT_UP.labels(agent=AGENT_NAME).set(1)

        except redis_lib.RedisError as exc:
            logger.error(
                "Redis error during health poll — will retry",
                extra={"error": str(exc)},
            )
            ERRORS_TOTAL.labels(agent=AGENT_NAME, error_type="redis_error").inc()

        time.sleep(HEALTH_PING_INTERVAL_S)


# ---------------------------------------------------------------------------
# Redis connection with retry
# ---------------------------------------------------------------------------

def _connect_redis(max_retries: int = 30) -> redis_lib.Redis:
    """Block until Redis is reachable, with exponential backoff."""
    backoff = 1.0
    for attempt in range(1, max_retries + 1):
        try:
            client = redis_lib.Redis(
                host=REDIS_HOST, port=REDIS_PORT, decode_responses=True
            )
            client.ping()
            logger.info("Redis connected")
            return client
        except redis_lib.RedisError as exc:
            logger.warning(
                "Redis not available (attempt %d/%d), retrying in %.1fs…",
                attempt,
                max_retries,
                backoff,
                extra={"error": str(exc)},
            )
            time.sleep(backoff)
            backoff = min(backoff * 2, 30.0)

    raise RuntimeError(
        f"Redis at {REDIS_HOST}:{REDIS_PORT} not available after {max_retries} attempts"
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    logger.info("Coordinator Agent starting", extra={"tracked_agents": list(TRACKED_AGENTS)})

    redis_client = _connect_redis()

    # Initialise AGENT_UP for coordinator itself
    AGENT_UP.labels(agent=AGENT_NAME).set(1)

    logger.info("Starting health poll loop",
                extra={"interval_s": HEALTH_PING_INTERVAL_S})
    _poll_health(redis_client)


if __name__ == "__main__":
    main()
