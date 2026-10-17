"""
Tests for GET /api/metrics endpoint.

Verifies:
- Returns AgentMetrics list when Prometheus is available
- Returns 503 when Prometheus is unavailable
- Response shape matches AgentMetrics schema
- All 7 tracked agents are represented in the response
"""

from tests.conftest import SAMPLE_PROMETHEUS_RESPONSE


def _make_prometheus_response(agent: str, metric: str, value: str) -> dict:
    """Helper to create a Prometheus query response for a given agent and value."""
    return {
        "status": "success",
        "data": {
            "result": [
                {
                    "metric": {"agent": agent},
                    "value": [1234567890, value],
                }
            ]
        },
    }


def test_metrics_returns_agent_list(client, mock_prometheus):
    """Returns AgentMetrics list when Prometheus is available."""
    mock_prometheus()

    resp = client.get("/api/metrics")
    assert resp.status_code == 200

    data = resp.json()
    assert isinstance(data, list)
    assert len(data) == 7  # all known agents


def test_metrics_returns_503_when_prometheus_unavailable(client, prometheus_unavailable):
    """Returns 503 with structured JSON when Prometheus is unavailable."""
    resp = client.get("/api/metrics")
    assert resp.status_code == 503

    body = resp.json()
    assert "detail" in body
    assert "Prometheus" in body["detail"]


def test_metrics_response_shape(client, mock_prometheus):
    """Response shape matches AgentMetrics schema."""
    mock_prometheus({
        "sentinelmesh_events_consumed_total": _make_prometheus_response("sniffer", "events_consumed", "150"),
    })

    resp = client.get("/api/metrics")
    data = resp.json()

    for item in data:
        assert "agent" in item
        assert "events_consumed" in item
        assert "events_produced" in item
        assert "queue_depth" in item
        assert "processing_latency_p50" in item


def test_metrics_all_agents_represented(client, mock_prometheus):
    """All 7 tracked agents are represented in the response."""
    mock_prometheus()

    resp = client.get("/api/metrics")
    data = resp.json()

    agent_names = {item["agent"] for item in data}
    expected_agents = {
        "sniffer", "dpi", "detection", "correlation",
        "response", "coordinator", "dashboard-writer",
    }
    assert agent_names == expected_agents
