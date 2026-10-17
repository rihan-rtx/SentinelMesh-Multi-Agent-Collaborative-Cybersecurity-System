# SentinelMesh Frontend

This directory contains the complete SentinelMesh frontend, consisting of two services:

## Folder Structure

```
frontend/
├── api-server/       FastAPI bridge — read-only REST API for the dashboard
│   ├── main.py       Bridge server (all endpoints)
│   ├── tests/        pytest test suite
│   └── README.md
│
└── web/              Next.js frontend — dashboard UI
    ├── src/
    │   ├── app/      Pages (Next.js App Router)
    │   ├── components/  React components
    │   ├── hooks/    Data fetching hooks
    │   ├── lib/      Utilities, constants, API client
    │   ├── types/    TypeScript type definitions
    │   └── __tests__/  Vitest + RTL test suite
    └── README.md
```

## Quick Start

### 1. Start the API Bridge

```bash
cd frontend/api-server
pip install -r requirements.txt
python main.py
# API available at http://localhost:8000
# Docs at http://localhost:8000/docs
```

### 2. Start the Frontend

```bash
cd frontend/web
npm install
npm run dev
# Dashboard available at http://localhost:3001
```

## Architecture

The frontend is a **pure presentation layer**:

- The **API bridge** reads from PostgreSQL, Redis, and Prometheus — it never writes to any backend
- The **Next.js app** fetches data only from the bridge API — it never talks to backend services directly
- Both services are designed for graceful degradation — if a backend service is down, only the affected widgets show errors

## Data Flow

```
PostgreSQL ─┐
Redis ──────┤──→ FastAPI Bridge (port 8000) ──→ Next.js App (port 3001)
Prometheus ─┘
```
