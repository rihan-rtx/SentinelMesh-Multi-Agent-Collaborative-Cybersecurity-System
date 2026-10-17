"""
Tests for GET /api/services endpoint.

Verifies:
- Always returns HTTP 200
- Returns 6 ServiceStatus items
- reachable field is boolean
- latency_ms is null when service is unreachable
- last_checked is a valid ISO timestamp
"""

from datetime import datetime
from unittest.mock import patch


def test_services_always_returns_200(client):
    """Always returns HTTP 200 (never 503 from this endpoint itself)."""
    # Even if all services are down, this endpoint returns 200
    with patch("main.socket.create_connection", side_effect=OSError("refused")):
        resp = client.get("/api/services")
        assert resp.status_code == 200


def test_services_returns_6_items(client):
    """Returns 6 ServiceStatus items."""
    with patch("main.socket.create_connection", side_effect=OSError("refused")):
        resp = client.get("/api/services")
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) == 6


def test_services_reachable_is_boolean(client):
    """reachable field is boolean."""
    with patch("main.socket.create_connection", side_effect=OSError("refused")):
        resp = client.get("/api/services")
        data = resp.json()

        for item in data:
            assert isinstance(item["reachable"], bool)


def test_services_latency_null_when_unreachable(client):
    """latency_ms is null when service is unreachable."""
    with patch("main.socket.create_connection", side_effect=OSError("refused")):
        resp = client.get("/api/services")
        data = resp.json()

        for item in data:
            assert item["reachable"] is False
            assert item["latency_ms"] is None


def test_services_last_checked_is_iso_timestamp(client):
    """last_checked is a valid ISO timestamp."""
    with patch("main.socket.create_connection", side_effect=OSError("refused")):
        resp = client.get("/api/services")
        data = resp.json()

        for item in data:
            assert "last_checked" in item
            # Should not raise ValueError
            datetime.fromisoformat(item["last_checked"])


def test_services_contains_expected_names(client):
    """Contains all expected service names."""
    with patch("main.socket.create_connection", side_effect=OSError("refused")):
        resp = client.get("/api/services")
        data = resp.json()

        service_names = {item["name"] for item in data}
        expected = {"kafka", "redis", "postgres", "grafana", "prometheus", "zookeeper"}
        assert service_names == expected
