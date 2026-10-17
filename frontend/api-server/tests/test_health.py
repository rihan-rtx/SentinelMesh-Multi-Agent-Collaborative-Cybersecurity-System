"""
Tests for GET /api/health endpoint.

Verifies:
- Returns agent health objects when Redis has data
- Returns empty list when no health keys exist
- Returns 503 when Redis is unavailable
- Response shape matches AgentHealth schema
- agent_name field is present and non-empty
"""

import json

from tests.conftest import SAMPLE_HEALTH_DATA


def test_health_returns_agents_when_redis_has_data(client, mock_redis):
    """Returns list of agent health objects when Redis is available."""
    mock_redis({
        "health:sniffer": json.dumps(SAMPLE_HEALTH_DATA),
        "health:dpi": json.dumps({
            **SAMPLE_HEALTH_DATA,
            "agent_name": "dpi",
            "status": "degraded",
        }),
    })

    resp = client.get("/api/health")
    assert resp.status_code == 200

    data = resp.json()
    assert isinstance(data, list)
    assert len(data) == 2

    agent_names = {item["agent_name"] for item in data}
    assert "sniffer" in agent_names
    assert "dpi" in agent_names


def test_health_returns_empty_list_when_no_keys(client, mock_redis):
    """Returns empty list (not 503) when no health keys exist in Redis."""
    mock_redis({})

    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json() == []


def test_health_returns_503_when_redis_unavailable(client, redis_unavailable):
    """Returns 503 with structured JSON when Redis is unavailable."""
    resp = client.get("/api/health")
    assert resp.status_code == 503

    body = resp.json()
    assert "detail" in body
    assert "Redis" in body["detail"]


def test_health_response_shape(client, mock_redis):
    """Response shape matches AgentHealth schema for each item."""
    mock_redis({"health:sniffer": json.dumps(SAMPLE_HEALTH_DATA)})

    resp = client.get("/api/health")
    data = resp.json()
    assert len(data) == 1

    item = data[0]
    assert "agent_name" in item
    assert "timestamp" in item
    assert "status" in item
    assert "throughput_last_interval" in item
    assert "queue_depth" in item


def test_health_agent_name_present_and_nonempty(client, mock_redis):
    """agent_name field is present and non-empty for each item."""
    mock_redis({"health:sniffer": json.dumps(SAMPLE_HEALTH_DATA)})

    resp = client.get("/api/health")
    data = resp.json()

    for item in data:
        assert "agent_name" in item
        assert isinstance(item["agent_name"], str)
        assert len(item["agent_name"]) > 0
