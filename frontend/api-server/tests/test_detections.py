"""
Tests for GET /api/detections endpoint.

Verifies:
- Returns paginated response with correct shape
- limit and offset parameters work correctly
- classification filter returns only matching rows
- attack_type filter returns only matching rows
- Returns empty items list when table is empty
- Returns 503 when PostgreSQL is unavailable
- Response never contains stack trace in detail field
"""

from datetime import datetime, timezone


SAMPLE_DETECTION_ROW = {
    "detection_id": "11111111-1111-1111-1111-111111111111",
    "flow_id": "22222222-2222-2222-2222-222222222222",
    "ts": datetime(2026, 8, 1, 12, 0, 0, tzinfo=timezone.utc),
    "classification": "malicious",
    "confidence": 0.95,
    "attack_type": "port_scan",
}


def test_detections_returns_paginated_response(client, mock_pg_multi):
    """Returns paginated response with correct shape."""
    mock_pg_multi([
        [{"cnt": 1}],
        [SAMPLE_DETECTION_ROW],
    ])

    resp = client.get("/api/detections")
    assert resp.status_code == 200

    data = resp.json()
    assert "items" in data
    assert "total" in data
    assert "limit" in data
    assert "offset" in data
    assert isinstance(data["items"], list)
    assert data["total"] == 1
    assert data["limit"] == 20
    assert data["offset"] == 0


def test_detections_limit_and_offset(client, mock_pg_multi):
    """limit and offset parameters work correctly."""
    mock_pg_multi([
        [{"cnt": 50}],
        [SAMPLE_DETECTION_ROW],
    ])

    resp = client.get("/api/detections?limit=5&offset=10")
    assert resp.status_code == 200

    data = resp.json()
    assert data["limit"] == 5
    assert data["offset"] == 10


def test_detections_classification_filter(client, mock_pg_multi):
    """classification filter returns only matching rows."""
    mock_pg_multi([
        [{"cnt": 1}],
        [{**SAMPLE_DETECTION_ROW, "classification": "benign"}],
    ])

    resp = client.get("/api/detections?classification=benign")
    assert resp.status_code == 200

    data = resp.json()
    for item in data["items"]:
        assert item["classification"] == "benign"


def test_detections_attack_type_filter(client, mock_pg_multi):
    """attack_type filter returns only matching rows."""
    mock_pg_multi([
        [{"cnt": 1}],
        [SAMPLE_DETECTION_ROW],
    ])

    resp = client.get("/api/detections?attack_type=port_scan")
    assert resp.status_code == 200

    data = resp.json()
    for item in data["items"]:
        assert item["attack_type"] == "port_scan"


def test_detections_empty_table(client, mock_pg_multi):
    """Returns empty items list (not error) when table is empty."""
    mock_pg_multi([
        [{"cnt": 0}],
        [],
    ])

    resp = client.get("/api/detections")
    assert resp.status_code == 200

    data = resp.json()
    assert data["items"] == []
    assert data["total"] == 0


def test_detections_returns_503_when_pg_unavailable(client, pg_unavailable):
    """Returns 503 with structured JSON when PostgreSQL is unavailable."""
    resp = client.get("/api/detections")
    assert resp.status_code == 503

    body = resp.json()
    assert "detail" in body


def test_detections_no_stack_trace_in_response(client, pg_unavailable):
    """Response never contains stack trace in detail field."""
    resp = client.get("/api/detections")
    body = resp.json()

    detail = body.get("detail", "")
    assert "Traceback" not in detail
    assert "File " not in detail
    assert "line " not in detail


def test_detections_item_shape(client, mock_pg_multi):
    """Each detection item has the correct fields."""
    mock_pg_multi([
        [{"cnt": 1}],
        [SAMPLE_DETECTION_ROW],
    ])

    resp = client.get("/api/detections")
    data = resp.json()

    item = data["items"][0]
    assert "detection_id" in item
    assert "flow_id" in item
    assert "timestamp" in item
    assert "classification" in item
    assert "confidence" in item
    assert "attack_type" in item
