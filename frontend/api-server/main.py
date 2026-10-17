"""
SentinelMesh — FastAPI Bridge Server

Read-only API bridge that connects the Next.js frontend to SentinelMesh
backend data sources (PostgreSQL, Redis, Prometheus). This server:

- SELECTs from PostgreSQL (detections, incidents, actions tables)
- GETs from Redis (health:{agent} keys written by Coordinator)
- Proxies Prometheus HTTP API (GET only, for agent metrics)
- Performs TCP connectivity checks (service status)

Constraints:
- No writes to any backend data store
- No Kafka consume/publish
- No imports from shared/ or agents/
- Never exposes stack traces to clients
- All errors return structured JSON with 'detail' field

Environment:
- Loads config from the project root .env file
- Bridge-only defaults: PROMETHEUS_URL, GRAFANA_URL
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import sys
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator, Optional

import httpx
import psycopg2
import psycopg2.extras
import redis as redis_lib
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

# ---------------------------------------------------------------------------
# Configuration — load from project root .env
# ---------------------------------------------------------------------------

_project_root = Path(__file__).resolve().parent.parent.parent
_env_path = _project_root / ".env"
load_dotenv(dotenv_path=_env_path)

# Logging — module-level, no print() statements
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("sentinelmesh.bridge")

# PostgreSQL
POSTGRES_HOST = os.getenv("POSTGRES_HOST", "localhost")
POSTGRES_PORT = int(os.getenv("POSTGRES_PORT", "5432"))
POSTGRES_DB = os.getenv("POSTGRES_DB", "sentinelmesh")
POSTGRES_USER = os.getenv("POSTGRES_USER", "sentinelmesh")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "changeme")

# Redis
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

# Prometheus & Grafana (bridge-only defaults)
PROMETHEUS_URL = os.getenv("PROMETHEUS_URL", "http://localhost:9090")
GRAFANA_URL = os.getenv("GRAFANA_URL", "http://localhost:3000")

# Known agents (matches prometheus.yml scrape targets)
KNOWN_AGENTS = [
    "sniffer", "dpi", "detection", "correlation",
    "response", "coordinator", "dashboard-writer",
]

# Services to check connectivity for
SERVICE_CHECKS = {
    "kafka": ("localhost", 29092),
    "redis": (REDIS_HOST, REDIS_PORT),
    "postgres": (POSTGRES_HOST, POSTGRES_PORT),
    "grafana": ("localhost", 3000),
    "prometheus": ("localhost", 9090),
    "zookeeper": ("localhost", 2181),
}


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(
    title="SentinelMesh Bridge API",
    description="Read-only API bridge for the SentinelMesh frontend dashboard.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

@contextmanager
def get_pg_connection() -> Generator[psycopg2.extensions.connection, None, None]:
    """Open a short-lived PostgreSQL connection. Yields a connection, closes on exit.

    Raises:
        psycopg2.OperationalError: If PostgreSQL is unreachable.
    """
    conn = psycopg2.connect(
        host=POSTGRES_HOST,
        port=POSTGRES_PORT,
        dbname=POSTGRES_DB,
        user=POSTGRES_USER,
        password=POSTGRES_PASSWORD,
    )
    try:
        yield conn
    finally:
        conn.close()


def get_redis_client() -> redis_lib.Redis:
    """Create a Redis client instance.

    Returns:
        A redis.Redis client with decode_responses enabled.

    Raises:
        redis.ConnectionError: If Redis is unreachable.
    """
    return redis_lib.Redis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        decode_responses=True,
        socket_connect_timeout=3,
    )


# ---------------------------------------------------------------------------
# REST Endpoints
# ---------------------------------------------------------------------------

# ---- /api/health ----

@app.get("/api/health")
async def get_health() -> list[dict[str, Any]]:
    """Return agent health data from Redis.

    Reads all health:{agent} keys from Redis and returns the parsed JSON.

    Returns:
        List of agent health objects.

    Raises:
        HTTPException(503): If Redis is unavailable.
    """
    try:
        client = get_redis_client()
        client.ping()
    except Exception as exc:
        logger.error("Redis unavailable: %s", exc)
        raise HTTPException(status_code=503, detail="Redis unavailable")

    results: list[dict[str, Any]] = []
    try:
        for agent in KNOWN_AGENTS:
            key = f"health:{agent}"
            raw = client.get(key)
            if raw:
                results.append(json.loads(raw))
    except Exception as exc:
        logger.error("Error reading health keys: %s", exc)
        raise HTTPException(status_code=503, detail="Redis unavailable")

    return results


# ---- /api/stats ----

@app.get("/api/stats")
async def get_stats() -> dict[str, Any]:
    """Return aggregate statistics from PostgreSQL.

    Returns:
        Dict with total_detections, open_incidents, active_agents,
        and detections_by_classification breakdown.

    Raises:
        HTTPException(503): If PostgreSQL is unavailable.
    """
    try:
        with get_pg_connection() as conn:
            with conn.cursor() as cur:
                # Total detections
                cur.execute("SELECT COUNT(*) FROM detections")
                total_detections = cur.fetchone()[0]

                # Open incidents
                cur.execute(
                    "SELECT COUNT(*) FROM incidents WHERE status = 'open'"
                )
                open_incidents = cur.fetchone()[0]

                # Detections by classification
                cur.execute(
                    "SELECT classification, COUNT(*) FROM detections GROUP BY classification"
                )
                classification_rows = cur.fetchall()
                detections_by_classification = {
                    "benign": 0, "suspicious": 0, "malicious": 0,
                }
                for row in classification_rows:
                    if row[0] in detections_by_classification:
                        detections_by_classification[row[0]] = row[1]
    except psycopg2.OperationalError as exc:
        logger.error("PostgreSQL unavailable: %s", exc)
        raise HTTPException(status_code=503, detail="Database unavailable")
    except Exception as exc:
        logger.error("Unexpected error in /api/stats: %s", exc)
        raise HTTPException(status_code=500, detail="Internal server error")

    # Active agents from Redis (best-effort, don't fail stats if Redis is down)
    active_agents = 0
    try:
        client = get_redis_client()
        for agent in KNOWN_AGENTS:
            if client.exists(f"health:{agent}"):
                active_agents += 1
    except Exception as exc:
        logger.warning("Redis unavailable for active_agents count: %s", exc)

    return {
        "total_detections": total_detections,
        "open_incidents": open_incidents,
        "active_agents": active_agents,
        "detections_by_classification": detections_by_classification,
    }


# ---- /api/detections ----

@app.get("/api/detections")
async def get_detections(
    limit: int = Query(20, ge=1, le=100, description="Page size"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    classification: Optional[str] = Query(None, description="Filter by classification"),
    attack_type: Optional[str] = Query(None, description="Filter by attack type"),
) -> dict[str, Any]:
    """Return paginated detections from PostgreSQL.

    Args:
        limit: Number of items per page (1-100).
        offset: Pagination offset.
        classification: Optional filter (benign, suspicious, malicious).
        attack_type: Optional filter by attack type string.

    Returns:
        Paginated response with items, total, limit, offset.

    Raises:
        HTTPException(503): If PostgreSQL is unavailable.
    """
    try:
        with get_pg_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                # Build query with optional filters
                where_clauses: list[str] = []
                params: list[Any] = []

                if classification:
                    where_clauses.append("classification = %s")
                    params.append(classification)
                if attack_type:
                    where_clauses.append("attack_type = %s")
                    params.append(attack_type)

                where_sql = ""
                if where_clauses:
                    where_sql = "WHERE " + " AND ".join(where_clauses)

                # Total count
                cur.execute(f"SELECT COUNT(*) as cnt FROM detections {where_sql}", params)
                total = cur.fetchone()["cnt"]

                # Paginated items
                cur.execute(
                    f"SELECT detection_id, flow_id, ts, classification, confidence, attack_type "
                    f"FROM detections {where_sql} "
                    f"ORDER BY ts DESC LIMIT %s OFFSET %s",
                    params + [limit, offset],
                )
                rows = cur.fetchall()
    except psycopg2.OperationalError as exc:
        logger.error("PostgreSQL unavailable: %s", exc)
        raise HTTPException(status_code=503, detail="Database unavailable")
    except Exception as exc:
        logger.error("Unexpected error in /api/detections: %s", exc)
        raise HTTPException(status_code=500, detail="Internal server error")

    items = []
    for row in rows:
        items.append({
            "detection_id": str(row["detection_id"]),
            "flow_id": str(row["flow_id"]),
            "timestamp": row["ts"].isoformat() if row["ts"] else None,
            "classification": row["classification"],
            "confidence": float(row["confidence"]) if row["confidence"] is not None else 0.0,
            "attack_type": row["attack_type"],
        })

    return {"items": items, "total": total, "limit": limit, "offset": offset}


# ---- /api/incidents ----

@app.get("/api/incidents")
async def get_incidents(
    limit: int = Query(20, ge=1, le=100, description="Page size"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    status: Optional[str] = Query(None, description="Filter by status"),
    incident_type: Optional[str] = Query(None, description="Filter by incident type"),
) -> dict[str, Any]:
    """Return paginated incidents from PostgreSQL.

    Args:
        limit: Number of items per page (1-100).
        offset: Pagination offset.
        severity: Optional filter (low, medium, high, critical).
        status: Optional filter (open, escalated, resolved, false_positive).
        incident_type: Optional filter by incident type string.

    Returns:
        Paginated response with items, total, limit, offset.

    Raises:
        HTTPException(503): If PostgreSQL is unavailable.
    """
    try:
        with get_pg_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                where_clauses: list[str] = []
                params: list[Any] = []

                if severity:
                    where_clauses.append("severity = %s")
                    params.append(severity)
                if status:
                    where_clauses.append("status = %s")
                    params.append(status)
                if incident_type:
                    where_clauses.append("incident_type = %s")
                    params.append(incident_type)

                where_sql = ""
                if where_clauses:
                    where_sql = "WHERE " + " AND ".join(where_clauses)

                cur.execute(f"SELECT COUNT(*) as cnt FROM incidents {where_sql}", params)
                total = cur.fetchone()["cnt"]

                cur.execute(
                    f"SELECT incident_id, ts_opened, ts_updated, src_ip, incident_type, severity, status "
                    f"FROM incidents {where_sql} "
                    f"ORDER BY ts_updated DESC LIMIT %s OFFSET %s",
                    params + [limit, offset],
                )
                rows = cur.fetchall()
    except psycopg2.OperationalError as exc:
        logger.error("PostgreSQL unavailable: %s", exc)
        raise HTTPException(status_code=503, detail="Database unavailable")
    except Exception as exc:
        logger.error("Unexpected error in /api/incidents: %s", exc)
        raise HTTPException(status_code=500, detail="Internal server error")

    items = []
    for row in rows:
        items.append({
            "incident_id": str(row["incident_id"]),
            "timestamp_opened": row["ts_opened"].isoformat() if row["ts_opened"] else None,
            "timestamp_updated": row["ts_updated"].isoformat() if row["ts_updated"] else None,
            "src_ip": row["src_ip"],
            "incident_type": row["incident_type"],
            "severity": row["severity"],
            "status": row["status"],
        })

    return {"items": items, "total": total, "limit": limit, "offset": offset}


# ---- /api/incidents/{incident_id} ----

@app.get("/api/incidents/{incident_id}")
async def get_incident_detail(incident_id: str) -> dict[str, Any]:
    """Return a single incident with its associated actions.

    Args:
        incident_id: UUID of the incident to retrieve.

    Returns:
        Incident object with nested actions array.

    Raises:
        HTTPException(404): If the incident is not found.
        HTTPException(503): If PostgreSQL is unavailable.
    """
    try:
        with get_pg_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    "SELECT incident_id, ts_opened, ts_updated, src_ip, incident_type, severity, status "
                    "FROM incidents WHERE incident_id = %s",
                    (incident_id,),
                )
                incident_row = cur.fetchone()

                if not incident_row:
                    raise HTTPException(
                        status_code=404,
                        detail=f"Incident {incident_id} not found",
                    )

                cur.execute(
                    "SELECT action_id, incident_id, ts, action_type, target "
                    "FROM actions WHERE incident_id = %s ORDER BY ts ASC",
                    (incident_id,),
                )
                action_rows = cur.fetchall()
    except HTTPException:
        raise
    except psycopg2.OperationalError as exc:
        logger.error("PostgreSQL unavailable: %s", exc)
        raise HTTPException(status_code=503, detail="Database unavailable")
    except Exception as exc:
        logger.error("Unexpected error in /api/incidents/{id}: %s", exc)
        raise HTTPException(status_code=500, detail="Internal server error")

    actions = []
    for row in action_rows:
        actions.append({
            "action_id": str(row["action_id"]),
            "incident_id": str(row["incident_id"]),
            "timestamp": row["ts"].isoformat() if row["ts"] else None,
            "action_type": row["action_type"],
            "target": row["target"],
        })

    return {
        "incident_id": str(incident_row["incident_id"]),
        "timestamp_opened": incident_row["ts_opened"].isoformat() if incident_row["ts_opened"] else None,
        "timestamp_updated": incident_row["ts_updated"].isoformat() if incident_row["ts_updated"] else None,
        "src_ip": incident_row["src_ip"],
        "incident_type": incident_row["incident_type"],
        "severity": incident_row["severity"],
        "status": incident_row["status"],
        "actions": actions,
    }


# ---- /api/metrics ----

@app.get("/api/metrics")
async def get_metrics() -> list[dict[str, Any]]:
    """Return agent metrics from Prometheus.

    Queries Prometheus for key agent metrics:
    - sentinelmesh_events_consumed_total
    - sentinelmesh_events_produced_total
    - sentinelmesh_queue_depth
    - sentinelmesh_processing_latency_seconds (p50)

    Returns:
        List of AgentMetrics objects, one per agent.

    Raises:
        HTTPException(503): If Prometheus is unavailable.
    """
    queries = {
        "events_consumed": "sentinelmesh_events_consumed_total",
        "events_produced": "sentinelmesh_events_produced_total",
        "queue_depth": "sentinelmesh_queue_depth",
        "processing_latency_p50": 'histogram_quantile(0.5, rate(sentinelmesh_processing_latency_seconds_bucket[5m]))',
    }

    agent_metrics: dict[str, dict[str, Any]] = {
        agent: {
            "agent": agent,
            "events_consumed": 0,
            "events_produced": 0,
            "queue_depth": 0,
            "processing_latency_p50": None,
        }
        for agent in KNOWN_AGENTS
    }

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            for metric_name, query in queries.items():
                resp = await client.get(
                    f"{PROMETHEUS_URL}/api/v1/query",
                    params={"query": query},
                )
                resp.raise_for_status()
                data = resp.json()

                if data.get("status") == "success":
                    for result in data.get("data", {}).get("result", []):
                        agent_label = result.get("metric", {}).get("agent", "")
                        if agent_label in agent_metrics:
                            value = result.get("value", [None, None])
                            if len(value) >= 2 and value[1] != "NaN":
                                try:
                                    parsed = float(value[1])
                                    if metric_name == "processing_latency_p50":
                                        agent_metrics[agent_label][metric_name] = parsed
                                    else:
                                        agent_metrics[agent_label][metric_name] = int(parsed)
                                except (ValueError, TypeError):
                                    pass
    except httpx.ConnectError as exc:
        logger.error("Prometheus unavailable: %s", exc)
        raise HTTPException(status_code=503, detail="Prometheus unavailable")
    except httpx.HTTPStatusError as exc:
        logger.error("Prometheus error: %s", exc)
        raise HTTPException(status_code=503, detail="Prometheus unavailable")
    except Exception as exc:
        logger.error("Unexpected error in /api/metrics: %s", exc)
        raise HTTPException(status_code=503, detail="Prometheus unavailable")

    return list(agent_metrics.values())


# ---- /api/services ----

@app.get("/api/services")
async def get_services() -> list[dict[str, Any]]:
    """Return connectivity status for all infrastructure services.

    Performs TCP connect checks against each known service.
    This endpoint always returns HTTP 200; individual services
    are marked as reachable or unreachable.

    Returns:
        List of ServiceStatus objects.
    """
    results: list[dict[str, Any]] = []

    for name, (host, port) in SERVICE_CHECKS.items():
        start = time.monotonic()
        reachable = False
        latency_ms: Optional[float] = None

        try:
            sock = socket.create_connection((host, port), timeout=2)
            sock.close()
            reachable = True
            latency_ms = round((time.monotonic() - start) * 1000, 1)
        except (socket.timeout, socket.error, OSError):
            reachable = False
            latency_ms = None

        results.append({
            "name": name,
            "reachable": reachable,
            "latency_ms": latency_ms,
            "last_checked": datetime.now(tz=timezone.utc).isoformat(),
        })

    return results


# ---- /api/events/stream (SSE — Phase B-4) ----

@app.get("/api/events/stream")
async def events_stream() -> StreamingResponse:
    """Server-Sent Events stream for live detection/incident events.

    Polls PostgreSQL for new detections and incidents since the last
    check and streams them as SSE events.

    Returns:
        StreamingResponse with text/event-stream content type.

    Raises:
        HTTPException(503): If PostgreSQL is unavailable.
    """
    async def event_generator():
        """Generate SSE events by polling PostgreSQL for new records."""
        last_detection_ts: Optional[str] = None
        last_incident_ts: Optional[str] = None

        while True:
            try:
                with get_pg_connection() as conn:
                    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                        # New detections
                        if last_detection_ts:
                            cur.execute(
                                "SELECT detection_id, flow_id, ts, classification, confidence, attack_type "
                                "FROM detections WHERE ts > %s ORDER BY ts ASC LIMIT 50",
                                (last_detection_ts,),
                            )
                        else:
                            cur.execute(
                                "SELECT detection_id, flow_id, ts, classification, confidence, attack_type "
                                "FROM detections ORDER BY ts DESC LIMIT 10"
                            )
                        detection_rows = cur.fetchall()

                        for row in detection_rows:
                            event_data = {
                                "type": "detection",
                                "detection_id": str(row["detection_id"]),
                                "flow_id": str(row["flow_id"]),
                                "timestamp": row["ts"].isoformat() if row["ts"] else None,
                                "classification": row["classification"],
                                "confidence": float(row["confidence"]) if row["confidence"] is not None else 0.0,
                                "attack_type": row["attack_type"],
                            }
                            yield f"data: {json.dumps(event_data)}\n\n"
                            last_detection_ts = row["ts"].isoformat()

                        # New incidents
                        if last_incident_ts:
                            cur.execute(
                                "SELECT incident_id, ts_opened, ts_updated, src_ip, incident_type, severity, status "
                                "FROM incidents WHERE ts_updated > %s ORDER BY ts_updated ASC LIMIT 50",
                                (last_incident_ts,),
                            )
                        else:
                            cur.execute(
                                "SELECT incident_id, ts_opened, ts_updated, src_ip, incident_type, severity, status "
                                "FROM incidents ORDER BY ts_updated DESC LIMIT 10"
                            )
                        incident_rows = cur.fetchall()

                        for row in incident_rows:
                            event_data = {
                                "type": "incident",
                                "incident_id": str(row["incident_id"]),
                                "timestamp_opened": row["ts_opened"].isoformat() if row["ts_opened"] else None,
                                "timestamp_updated": row["ts_updated"].isoformat() if row["ts_updated"] else None,
                                "src_ip": row["src_ip"],
                                "incident_type": row["incident_type"],
                                "severity": row["severity"],
                                "status": row["status"],
                            }
                            yield f"data: {json.dumps(event_data)}\n\n"
                            last_incident_ts = row["ts_updated"].isoformat()

            except psycopg2.OperationalError as exc:
                logger.error("SSE: PostgreSQL unavailable: %s", exc)
                yield f"data: {json.dumps({'type': 'error', 'detail': 'Database unavailable'})}\n\n"
            except Exception as exc:
                logger.error("SSE: Unexpected error: %s", exc)
                yield f"data: {json.dumps({'type': 'error', 'detail': 'Internal server error'})}\n\n"

            # Heartbeat to keep connection alive
            yield ": heartbeat\n\n"

            await asyncio.sleep(3)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
    )
