# SentinelMesh Bridge — Test Suite

## Overview

This directory contains pytest tests for the FastAPI bridge server. Tests are organized by endpoint, with shared fixtures in `conftest.py`.

## Test Files

| File | Endpoint | Coverage |
|---|---|---|
| `test_health.py` | `GET /api/health` | Redis data, empty state, 503, response shape |
| `test_stats.py` | `GET /api/stats` | Counts, zero counts, 503, classification keys, active agents |
| `test_detections.py` | `GET /api/detections` | Pagination, filters, empty state, 503, no stack traces |
| `test_incidents.py` | `GET /api/incidents` | Pagination, filters, detail view, 404, empty state, 503 |
| `test_metrics.py` | `GET /api/metrics` | Prometheus data, 503, response shape, agent coverage |
| `test_services.py` | `GET /api/services` | Always 200, 6 items, boolean reachable, null latency, timestamps |
| `test_events_stream.py` | `GET /api/events/stream` | Content type, SSE format (Phase B-4) |

## Shared Fixtures (`conftest.py`)

| Fixture | Purpose |
|---|---|
| `client` | FastAPI TestClient |
| `mock_pg_conn` | Replaces psycopg2.connect with mock cursor (single result) |
| `mock_pg_multi` | Replaces psycopg2.connect with mock cursor (multi-result) |
| `pg_unavailable` | Makes psycopg2.connect raise OperationalError |
| `mock_redis` | Replaces redis.Redis with in-memory fake |
| `redis_unavailable` | Makes redis.Redis raise ConnectionError |
| `mock_prometheus` | Replaces httpx.AsyncClient with controlled mock |
| `prometheus_unavailable` | Makes Prometheus requests raise ConnectError |

## Running Tests

```bash
cd frontend/api-server
pytest tests/ -v
```
