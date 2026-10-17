# SentinelMesh — FastAPI Bridge Server

Read-only API bridge that connects the Next.js frontend to SentinelMesh backend data sources.

## Purpose

This server acts as a **presentation-layer bridge** — it reads data from PostgreSQL, Redis, and Prometheus and serves it via a clean REST API to the frontend. It never writes to any backend data store.

## Endpoints

| Endpoint | Source | Description |
|---|---|---|
| `GET /api/health` | Redis | Agent health data from `health:{agent}` keys |
| `GET /api/stats` | PostgreSQL + Redis | Aggregate stats (detection counts, open incidents, active agents) |
| `GET /api/detections` | PostgreSQL | Paginated detections with optional filters |
| `GET /api/incidents` | PostgreSQL | Paginated incidents with optional filters |
| `GET /api/incidents/{id}` | PostgreSQL | Single incident with associated actions |
| `GET /api/metrics` | Prometheus | Agent metrics (events consumed/produced, queue depth, latency) |
| `GET /api/services` | TCP checks | Service connectivity status |
| `GET /api/events/stream` | PostgreSQL (SSE) | Server-Sent Events stream for live events |

## Environment Variables

The bridge loads configuration from the project root `.env` file. Bridge-specific defaults:

| Variable | Default | Description |
|---|---|---|
| `PROMETHEUS_URL` | `http://localhost:9090` | Prometheus base URL |
| `GRAFANA_URL` | `http://localhost:3000` | Grafana base URL |

All other variables (`POSTGRES_*`, `REDIS_*`) are read from the shared `.env`.

## Run Locally

```bash
cd frontend/api-server
pip install -r requirements.txt
python main.py
# or
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

The API docs are available at:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## Run Tests

```bash
cd frontend/api-server
pytest tests/ -v
```

## Architecture Constraints

- **No writes** to PostgreSQL, Redis, or Kafka
- **No imports** from `shared/` or `agents/`
- **No stack traces** exposed to clients — all errors return `{"detail": "..."}`
- **No hardcoded mock data** — every response comes from a real data source
