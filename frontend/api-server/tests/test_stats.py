"""
Tests for GET /api/stats endpoint.

Verifies:
- Returns correct counts when PostgreSQL has data
- Returns zero counts when tables are empty
- Returns 503 when PostgreSQL is unavailable
- detections_by_classification contains all three keys
- active_agents count reflects healthy Redis keys
"""

import json

from tests.conftest import SAMPLE_HEALTH_DATA


def test_stats_returns_correct_counts(client, mock_pg_multi, mock_redis):
    """Returns correct counts when PostgreSQL has data."""
    mock_pg_multi([
        [(42,)],                              # total detections
        [(7,)],                               # open incidents
        [("benign", 20), ("suspicious", 15), ("malicious", 7)],  # by classification
    ])
    mock_redis({
        "health:sniffer": json.dumps(SAMPLE_HEALTH_DATA),
        "health:dpi": json.dumps(SAMPLE_HEALTH_DATA),
    })

    resp = client.get("/api/stats")
    assert resp.status_code == 200

    data = resp.json()
    assert data["total_detections"] == 42
    assert data["open_incidents"] == 7
    assert data["active_agents"] == 2
    assert data["detections_by_classification"]["benign"] == 20
    assert data["detections_by_classification"]["suspicious"] == 15
    assert data["detections_by_classification"]["malicious"] == 7


def test_stats_returns_zero_counts_when_empty(client, mock_pg_multi, mock_redis):
    """Returns zero counts (not error) when tables are empty."""
    mock_pg_multi([
        [(0,)],   # total detections
        [(0,)],   # open incidents
        [],       # no classification rows
    ])
    mock_redis({})

    resp = client.get("/api/stats")
    assert resp.status_code == 200

    data = resp.json()
    assert data["total_detections"] == 0
    assert data["open_incidents"] == 0
    assert data["active_agents"] == 0


def test_stats_returns_503_when_pg_unavailable(client, pg_unavailable):
    """Returns 503 with structured JSON when PostgreSQL is unavailable."""
    resp = client.get("/api/stats")
    assert resp.status_code == 503

    body = resp.json()
    assert "detail" in body
    assert "Database" in body["detail"] or "unavailable" in body["detail"].lower()


def test_stats_classification_has_all_three_keys(client, mock_pg_multi, mock_redis):
    """detections_by_classification contains all three keys (benign, suspicious, malicious)."""
    mock_pg_multi([
        [(10,)],
        [(2,)],
        [("benign", 5)],  # only one classification present
    ])
    mock_redis({})

    resp = client.get("/api/stats")
    data = resp.json()

    classification = data["detections_by_classification"]
    assert "benign" in classification
    assert "suspicious" in classification
    assert "malicious" in classification
    assert classification["benign"] == 5
    assert classification["suspicious"] == 0
    assert classification["malicious"] == 0


def test_stats_active_agents_reflects_redis_keys(client, mock_pg_multi, mock_redis):
    """active_agents count reflects number of healthy Redis keys."""
    mock_pg_multi([
        [(0,)],
        [(0,)],
        [],
    ])
    mock_redis({
        "health:sniffer": json.dumps(SAMPLE_HEALTH_DATA),
        "health:dpi": json.dumps(SAMPLE_HEALTH_DATA),
        "health:detection": json.dumps(SAMPLE_HEALTH_DATA),
    })

    resp = client.get("/api/stats")
    data = resp.json()
    assert data["active_agents"] == 3
