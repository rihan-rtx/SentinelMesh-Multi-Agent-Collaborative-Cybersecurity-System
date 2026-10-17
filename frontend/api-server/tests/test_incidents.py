"""
Tests for GET /api/incidents and GET /api/incidents/{id} endpoints.

Verifies:
- Returns paginated response with correct shape
- severity filter works
- status filter works
- incident_type filter works
- GET /api/incidents/{id} returns incident + actions array
- GET /api/incidents/{nonexistent-id} returns 404
- Returns empty items list when table is empty
- Returns 503 when PostgreSQL is unavailable
- Response never contains stack trace in detail field
"""

from datetime import datetime, timezone


SAMPLE_INCIDENT_ROW = {
    "incident_id": "33333333-3333-3333-3333-333333333333",
    "ts_opened": datetime(2026, 8, 1, 12, 0, 0, tzinfo=timezone.utc),
    "ts_updated": datetime(2026, 8, 1, 12, 5, 0, tzinfo=timezone.utc),
    "src_ip": "192.168.1.100",
    "incident_type": "coordinated_scan",
    "severity": "high",
    "status": "open",
}

SAMPLE_ACTION_ROW = {
    "action_id": "44444444-4444-4444-4444-444444444444",
    "incident_id": "33333333-3333-3333-3333-333333333333",
    "ts": datetime(2026, 8, 1, 12, 6, 0, tzinfo=timezone.utc),
    "action_type": "alert",
    "target": "192.168.1.100",
}


def test_incidents_returns_paginated_response(client, mock_pg_multi):
    """Returns paginated response with correct shape."""
    mock_pg_multi([
        [{"cnt": 1}],
        [SAMPLE_INCIDENT_ROW],
    ])

    resp = client.get("/api/incidents")
    assert resp.status_code == 200

    data = resp.json()
    assert "items" in data
    assert "total" in data
    assert "limit" in data
    assert "offset" in data
    assert isinstance(data["items"], list)


def test_incidents_severity_filter(client, mock_pg_multi):
    """severity filter works."""
    mock_pg_multi([
        [{"cnt": 1}],
        [{**SAMPLE_INCIDENT_ROW, "severity": "critical"}],
    ])

    resp = client.get("/api/incidents?severity=critical")
    assert resp.status_code == 200

    data = resp.json()
    for item in data["items"]:
        assert item["severity"] == "critical"


def test_incidents_status_filter(client, mock_pg_multi):
    """status filter works."""
    mock_pg_multi([
        [{"cnt": 1}],
        [{**SAMPLE_INCIDENT_ROW, "status": "resolved"}],
    ])

    resp = client.get("/api/incidents?status=resolved")
    assert resp.status_code == 200

    data = resp.json()
    for item in data["items"]:
        assert item["status"] == "resolved"


def test_incidents_type_filter(client, mock_pg_multi):
    """incident_type filter works."""
    mock_pg_multi([
        [{"cnt": 1}],
        [SAMPLE_INCIDENT_ROW],
    ])

    resp = client.get("/api/incidents?incident_type=coordinated_scan")
    assert resp.status_code == 200


def test_incident_detail_returns_incident_with_actions(client, mock_pg_multi):
    """GET /api/incidents/{id} returns incident + actions array."""
    mock_pg_multi([
        [SAMPLE_INCIDENT_ROW],
        [SAMPLE_ACTION_ROW],
    ])

    resp = client.get("/api/incidents/33333333-3333-3333-3333-333333333333")
    assert resp.status_code == 200

    data = resp.json()
    assert data["incident_id"] == "33333333-3333-3333-3333-333333333333"
    assert "actions" in data
    assert isinstance(data["actions"], list)
    assert len(data["actions"]) == 1
    assert data["actions"][0]["action_type"] == "alert"


def test_incident_detail_nonexistent_returns_404(client, mock_pg_multi):
    """GET /api/incidents/{nonexistent-id} returns 404 with structured JSON."""
    mock_pg_multi([
        [],  # no incident found
    ])

    resp = client.get("/api/incidents/99999999-9999-9999-9999-999999999999")
    assert resp.status_code == 404

    body = resp.json()
    assert "detail" in body


def test_incidents_empty_table(client, mock_pg_multi):
    """Returns empty items list when table is empty."""
    mock_pg_multi([
        [{"cnt": 0}],
        [],
    ])

    resp = client.get("/api/incidents")
    assert resp.status_code == 200

    data = resp.json()
    assert data["items"] == []
    assert data["total"] == 0


def test_incidents_returns_503_when_pg_unavailable(client, pg_unavailable):
    """Returns 503 when PostgreSQL is unavailable."""
    resp = client.get("/api/incidents")
    assert resp.status_code == 503

    body = resp.json()
    assert "detail" in body


def test_incident_detail_returns_503_when_pg_unavailable(client, pg_unavailable):
    """Incident detail returns 503 when PostgreSQL is unavailable."""
    resp = client.get("/api/incidents/33333333-3333-3333-3333-333333333333")
    assert resp.status_code == 503


def test_incidents_no_stack_trace(client, pg_unavailable):
    """Response never contains stack trace in detail field."""
    resp = client.get("/api/incidents")
    body = resp.json()
    detail = body.get("detail", "")
    assert "Traceback" not in detail
    assert "File " not in detail


def test_incident_detail_shape(client, mock_pg_multi):
    """Incident detail has correct field names matching TypeScript types."""
    mock_pg_multi([
        [SAMPLE_INCIDENT_ROW],
        [],  # no actions
    ])

    resp = client.get("/api/incidents/33333333-3333-3333-3333-333333333333")
    data = resp.json()

    assert "incident_id" in data
    assert "timestamp_opened" in data
    assert "timestamp_updated" in data
    assert "src_ip" in data
    assert "incident_type" in data
    assert "severity" in data
    assert "status" in data
    assert "actions" in data
