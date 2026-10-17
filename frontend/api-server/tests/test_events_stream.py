"""
Tests for GET /api/events/stream (SSE) endpoint.

Basic tests for the SSE endpoint — full integration testing
is deferred to Phase B-4 when the frontend consumer is built.

Verifies:
- Returns streaming response with correct content type
"""

import pytest


@pytest.mark.skip(reason="SSE streaming tests require async test infrastructure — deferred to Phase B-4")
def test_events_stream_returns_sse_content_type(client):
    """Returns streaming response with text/event-stream content type.

    Note: Full SSE tests require reading from an infinite generator.
    This test is a placeholder to be expanded in Phase B-4.
    """
    pass
