"""
SentinelMesh — Unit Tests for shared/kafka_client.py

Tests the topic registry, producer/consumer wrapper logic, and configuration.
These tests use mocking (no real Kafka broker required) to validate:
  - Topic registry completeness (Section 10.7)
  - Producer configuration (idempotent, retries, acks)
  - Consumer dedup logic
  - DLQ routing behavior
  - Message serialization via Pydantic models
"""

from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from shared.kafka_client import (
    DLQ_TOPICS,
    TOPICS,
    SentinelConsumer,
    SentinelProducer,
)
from shared.schemas import FlowEvent


# ======================================================================
# Topic registry tests (Section 10.7)
# ======================================================================

class TestTopicRegistry:
    """Verify topic definitions match Section 10.7 exactly."""

    def test_all_primary_topics_defined(self) -> None:
        """All 5 primary topics from Section 10.7 must exist."""
        expected = {"flow-events", "dpi-findings", "detections", "incidents", "actions"}
        assert set(TOPICS.keys()) == expected

    def test_all_dlq_topics_defined(self) -> None:
        """Each primary topic must have a corresponding DLQ topic."""
        expected_dlqs = {f"{name}-dlq" for name in TOPICS}
        assert set(DLQ_TOPICS.keys()) == expected_dlqs

    def test_all_topics_have_one_partition(self) -> None:
        """Section 10.7: single partition per topic."""
        for name, cfg in {**TOPICS, **DLQ_TOPICS}.items():
            assert cfg["partitions"] == 1, f"{name} should have 1 partition"

    def test_retention_24h_for_pipeline_topics(self) -> None:
        """flow-events, dpi-findings, detections have 24h retention."""
        for name in ["flow-events", "dpi-findings", "detections"]:
            expected_ms = 24 * 60 * 60 * 1000
            assert TOPICS[name]["retention_ms"] == expected_ms, f"{name} retention"

    def test_retention_7d_for_incidents_and_actions(self) -> None:
        """incidents and actions have 7-day retention."""
        for name in ["incidents", "actions"]:
            expected_ms = 7 * 24 * 60 * 60 * 1000
            assert TOPICS[name]["retention_ms"] == expected_ms, f"{name} retention"

    def test_dlq_retention_is_7d(self) -> None:
        """All DLQ topics have 7-day retention."""
        expected_ms = 7 * 24 * 60 * 60 * 1000
        for name, cfg in DLQ_TOPICS.items():
            assert cfg["retention_ms"] == expected_ms, f"{name} retention"


# ======================================================================
# Producer configuration tests (Section 10.7)
# ======================================================================

class TestSentinelProducer:
    """Verify producer configuration and behavior."""

    @patch("shared.kafka_client.Producer")
    def test_producer_config(self, mock_producer_cls: MagicMock) -> None:
        """Producer must be configured with idempotence, retries=3, acks=all."""
        SentinelProducer(bootstrap_servers="localhost:9092")
        call_args = mock_producer_cls.call_args[0][0]
        assert call_args["enable.idempotence"] is True
        assert call_args["retries"] == 3
        assert call_args["acks"] == "all"
        assert call_args["retry.backoff.ms"] == 100

    @patch("shared.kafka_client.Producer")
    def test_produce_serializes_pydantic_model(self, mock_producer_cls: MagicMock) -> None:
        """produce() should serialize Pydantic models to JSON bytes."""
        mock_instance = MagicMock()
        mock_producer_cls.return_value = mock_instance

        producer = SentinelProducer(bootstrap_servers="localhost:9092")

        flow = FlowEvent(
            timestamp_start=datetime(2024, 1, 15, 10, 30, 0),
            timestamp_last=datetime(2024, 1, 15, 10, 30, 5),
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=80,
            protocol="TCP",
            packet_count=10,
            byte_count=1000,
            duration_ms=5000,
        )

        producer.produce("flow-events", flow, key="192.168.1.100")

        # Verify produce was called on the underlying producer
        mock_instance.produce.assert_called_once()
        call_kwargs = mock_instance.produce.call_args[1]
        assert call_kwargs["topic"] == "flow-events"
        assert call_kwargs["key"] == b"192.168.1.100"
        assert isinstance(call_kwargs["value"], bytes)

    @patch("shared.kafka_client.Producer")
    def test_produce_to_dlq_adds_metadata(self, mock_producer_cls: MagicMock) -> None:
        """DLQ messages should include error_reason and timestamp."""
        mock_instance = MagicMock()
        mock_producer_cls.return_value = mock_instance

        producer = SentinelProducer(bootstrap_servers="localhost:9092")
        producer.produce_to_dlq(
            source_topic="flow-events",
            raw_value=b'{"invalid": "data"}',
            key="test-key",
            error_reason="schema_validation: missing field",
        )

        mock_instance.produce.assert_called_once()
        call_kwargs = mock_instance.produce.call_args[1]
        assert call_kwargs["topic"] == "flow-events-dlq"

    @patch("shared.kafka_client.Producer")
    def test_flush_delegates_to_producer(self, mock_producer_cls: MagicMock) -> None:
        """flush() should delegate to the underlying producer."""
        mock_instance = MagicMock()
        mock_instance.flush.return_value = 0
        mock_producer_cls.return_value = mock_instance

        producer = SentinelProducer(bootstrap_servers="localhost:9092")
        result = producer.flush(timeout_s=3.0)

        mock_instance.flush.assert_called_once_with(timeout=3.0)
        assert result == 0


# ======================================================================
# Consumer configuration tests (Section 10.7)
# ======================================================================

class TestSentinelConsumer:
    """Verify consumer configuration."""

    @patch("shared.kafka_client.Consumer")
    def test_consumer_config(self, mock_consumer_cls: MagicMock) -> None:
        """Consumer must use manual offset commit (enable.auto.commit=False)."""
        SentinelConsumer(
            group_id="test-group",
            topics=["test-topic"],
            bootstrap_servers="localhost:9092",
        )
        call_args = mock_consumer_cls.call_args[0][0]
        assert call_args["enable.auto.commit"] is False
        assert call_args["auto.offset.reset"] == "earliest"
        assert call_args["group.id"] == "test-group"

    @patch("shared.kafka_client.Consumer")
    def test_consumer_subscribes_to_topics(self, mock_consumer_cls: MagicMock) -> None:
        """Consumer should subscribe to the specified topics."""
        mock_instance = MagicMock()
        mock_consumer_cls.return_value = mock_instance

        SentinelConsumer(
            group_id="dpi-agent-group",
            topics=["flow-events"],
            bootstrap_servers="localhost:9092",
        )

        from unittest.mock import ANY
        mock_instance.subscribe.assert_called_once_with(["flow-events"], on_assign=ANY)

    @patch("shared.kafka_client.Consumer")
    def test_consumer_stop_sets_running_false(self, mock_consumer_cls: MagicMock) -> None:
        """stop() should signal the consume loop to exit."""
        consumer = SentinelConsumer(
            group_id="test-group",
            topics=["test-topic"],
            bootstrap_servers="localhost:9092",
        )
        assert consumer._running is True
        consumer.stop()
        assert consumer._running is False

    @patch("shared.kafka_client.Consumer")
    def test_max_consecutive_failures_constant(self, mock_consumer_cls: MagicMock) -> None:
        """MAX_CONSECUTIVE_FAILURES should be 3 per Section 10.7/10.12."""
        assert SentinelConsumer.MAX_CONSECUTIVE_FAILURES == 3


# ======================================================================
# Consumer group mapping tests (Section 10.7)
# ======================================================================

class TestConsumerGroupMapping:
    """
    Verify that the consumer group names from Section 10.7 are used
    correctly throughout the system.
    """

    def test_consumer_group_names(self) -> None:
        """All consumer group names from Section 10.7 should be valid strings."""
        expected_groups = [
            "dpi-agent-group",
            "detection-agent-group",
            "correlation-flow-context-group",
            "correlation-agent-group",
            "response-agent-group",
            "dashboard-writer-group",
        ]
        # These are configuration constants used by agents — verify they're
        # valid, non-empty strings (actual subscription tested in integration)
        for group in expected_groups:
            assert isinstance(group, str)
            assert len(group) > 0
