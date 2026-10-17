"""
Shared pytest fixtures for SentinelMesh FastAPI bridge tests.

Provides isolated, deterministic test doubles for PostgreSQL, Redis,
and Prometheus. Each fixture replaces real I/O with controlled in-memory
mocks so tests run without any external services.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Optional
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# FastAPI TestClient
# ---------------------------------------------------------------------------

@pytest.fixture
def client():
    """Provide a FastAPI TestClient for the bridge app."""
    from main import app
    return TestClient(app)


# ---------------------------------------------------------------------------
# Mock PostgreSQL
# ---------------------------------------------------------------------------

class MockCursor:
    """In-memory mock cursor that returns controlled data."""

    def __init__(self, rows: list[Any] | None = None, dict_rows: list[dict] | None = None):
        self._rows = rows or []
        self._dict_rows = dict_rows or []
        self._use_dict = dict_rows is not None
        self.description = None
        self._executed = []

    def execute(self, sql: str, params: Any = None):
        """Record the executed SQL."""
        self._executed.append((sql, params))

    def fetchone(self):
        """Return the first row."""
        if self._use_dict:
            return self._dict_rows[0] if self._dict_rows else None
        return self._rows[0] if self._rows else None

    def fetchall(self):
        """Return all rows."""
        if self._use_dict:
            return self._dict_rows
        return self._rows

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


class MockConnection:
    """In-memory mock connection."""

    def __init__(self, cursor: MockCursor):
        self._cursor = cursor

    def cursor(self, cursor_factory=None):
        """Return the mock cursor."""
        return self._cursor

    def close(self):
        """No-op close."""
        pass

    def commit(self):
        """No-op commit."""
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


@pytest.fixture
def mock_pg_conn(monkeypatch):
    """Replace psycopg2.connect with a factory that returns MockConnection.

    Returns a function that the test can call to set up specific return data.
    Usage:
        setup = mock_pg_conn
        setup(rows=[(5,)])  # for fetchone returning (5,)
        setup(dict_rows=[{"id": 1, "name": "test"}])  # for RealDictCursor
    """
    state = {"conn": MockConnection(MockCursor())}

    def _setup(rows=None, dict_rows=None):
        cursor = MockCursor(rows=rows, dict_rows=dict_rows)
        state["conn"] = MockConnection(cursor)

    monkeypatch.setattr(
        "main.psycopg2.connect",
        lambda **kwargs: state["conn"],
    )

    return _setup


class MultiResultCursor:
    """Mock cursor that returns different results for sequential execute() calls."""

    def __init__(self, results: list[list[Any] | list[dict]]):
        self._results = results
        self._call_index = 0
        self.description = None
        self._executed = []

    def execute(self, sql: str, params: Any = None):
        """Record the executed SQL."""
        self._executed.append((sql, params))

    def fetchone(self):
        """Return the first item from the current result set."""
        if self._call_index < len(self._results):
            result = self._results[self._call_index]
            self._call_index += 1
            return result[0] if result else None
        return None

    def fetchall(self):
        """Return all items from the current result set."""
        if self._call_index < len(self._results):
            result = self._results[self._call_index]
            self._call_index += 1
            return result
        return []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


@pytest.fixture
def mock_pg_multi(monkeypatch):
    """Replace psycopg2.connect for endpoints that call execute() multiple times.

    Returns a function that accepts a list of result sets, one per execute() call.
    Usage:
        mock_pg_multi([
            [(42,)],          # first execute → fetchone returns (42,)
            [(10,)],          # second execute → fetchone returns (10,)
            [row1, row2],     # third execute → fetchall returns [row1, row2]
        ])
    """
    def _setup(results: list):
        cursor = MultiResultCursor(results)
        conn = MockConnection(cursor)
        monkeypatch.setattr(
            "main.psycopg2.connect",
            lambda **kwargs: conn,
        )
        return cursor

    return _setup


@pytest.fixture
def pg_unavailable(monkeypatch):
    """Make psycopg2.connect raise OperationalError."""
    import psycopg2

    def _raise(**kwargs):
        raise psycopg2.OperationalError("connection refused")

    monkeypatch.setattr("main.psycopg2.connect", _raise)


# ---------------------------------------------------------------------------
# Mock Redis
# ---------------------------------------------------------------------------

class MockRedis:
    """In-memory Redis fake with controlled data."""

    def __init__(self, data: dict[str, str] | None = None, fail: bool = False):
        self._data = data or {}
        self._fail = fail

    def ping(self):
        """Simulate ping."""
        if self._fail:
            raise ConnectionError("Redis unavailable")
        return True

    def get(self, key: str) -> str | None:
        """Return value for key."""
        if self._fail:
            raise ConnectionError("Redis unavailable")
        return self._data.get(key)

    def exists(self, key: str) -> int:
        """Check if key exists."""
        if self._fail:
            raise ConnectionError("Redis unavailable")
        return 1 if key in self._data else 0


SAMPLE_HEALTH_DATA = {
    "agent_name": "sniffer",
    "timestamp": "2026-08-01T12:00:00+00:00",
    "status": "healthy",
    "throughput_last_interval": 150,
    "queue_depth": 0,
}


@pytest.fixture
def mock_redis(monkeypatch):
    """Replace redis.Redis with a fake that returns controlled data.

    Returns a function that accepts a dict of key->value pairs.
    Usage:
        mock_redis({"health:sniffer": json.dumps({...})})
    """
    def _setup(data: dict[str, str] | None = None):
        fake = MockRedis(data=data)
        monkeypatch.setattr("main.get_redis_client", lambda: fake)
        return fake

    return _setup


@pytest.fixture
def redis_unavailable(monkeypatch):
    """Make redis.Redis raise ConnectionError."""
    def _create_failing():
        return MockRedis(fail=True)

    monkeypatch.setattr("main.get_redis_client", _create_failing)


# ---------------------------------------------------------------------------
# Mock Prometheus (httpx)
# ---------------------------------------------------------------------------

class MockHttpxResponse:
    """Mock httpx response."""

    def __init__(self, json_data: dict, status_code: int = 200):
        self._json_data = json_data
        self.status_code = status_code

    def json(self):
        return self._json_data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise Exception(f"HTTP {self.status_code}")


class MockAsyncClient:
    """Mock httpx.AsyncClient."""

    def __init__(self, responses: dict[str, MockHttpxResponse] | None = None, fail: bool = False):
        self._responses = responses or {}
        self._fail = fail

    async def get(self, url: str, params: dict | None = None) -> MockHttpxResponse:
        if self._fail:
            import httpx
            raise httpx.ConnectError("Prometheus unavailable")

        query = params.get("query", "") if params else ""
        if query in self._responses:
            return self._responses[query]

        return MockHttpxResponse({"status": "success", "data": {"result": []}})

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass


SAMPLE_PROMETHEUS_RESPONSE = {
    "status": "success",
    "data": {
        "result": [
            {
                "metric": {"agent": "sniffer"},
                "value": [1234567890, "100"],
            }
        ]
    },
}


@pytest.fixture
def mock_prometheus(monkeypatch):
    """Replace httpx.AsyncClient with a mock that returns controlled data.

    Returns a function that accepts a dict of query->response mappings.
    Usage:
        mock_prometheus({"sentinelmesh_events_consumed_total": {...}})
    """
    def _setup(responses: dict[str, dict] | None = None, fail: bool = False):
        mock_responses = {}
        if responses:
            for query, data in responses.items():
                mock_responses[query] = MockHttpxResponse(data)

        mock_client = MockAsyncClient(responses=mock_responses, fail=fail)
        monkeypatch.setattr("main.httpx.AsyncClient", lambda **kwargs: mock_client)
        return mock_client

    return _setup


@pytest.fixture
def prometheus_unavailable(monkeypatch):
    """Make Prometheus requests raise ConnectError."""
    mock_client = MockAsyncClient(fail=True)
    monkeypatch.setattr("main.httpx.AsyncClient", lambda **kwargs: mock_client)
