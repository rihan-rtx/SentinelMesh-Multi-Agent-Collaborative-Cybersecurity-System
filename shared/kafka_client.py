"""
SentinelMesh — Shared Kafka Client Wrapper

Provides a thin, opinionated wrapper around confluent-kafka for all agents.
Implements the producer and consumer configuration specified in Section 10.7:
  - Producer: enable.idempotence=true, retries=3, acks=all, exponential backoff
  - Consumer: manual offset commit (after successful processing), dedup guard via Redis
  - Dead-letter queue (DLQ) routing after 3 consecutive failures per message

All agents import and use this module; no agent should instantiate its own
raw Kafka producer/consumer.
"""

from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Type

from confluent_kafka import Consumer, KafkaError, KafkaException, Producer
from confluent_kafka.admin import AdminClient, NewTopic
from pydantic import BaseModel, ValidationError

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Topic registry — Section 10.7
# ---------------------------------------------------------------------------

TOPICS: Dict[str, Dict[str, Any]] = {
    "flow-events": {"partitions": 1, "retention_ms": 24 * 60 * 60 * 1000},
    "dpi-findings": {"partitions": 1, "retention_ms": 24 * 60 * 60 * 1000},
    "detections": {"partitions": 1, "retention_ms": 24 * 60 * 60 * 1000},
    "incidents": {"partitions": 1, "retention_ms": 7 * 24 * 60 * 60 * 1000},
    "actions": {"partitions": 1, "retention_ms": 7 * 24 * 60 * 60 * 1000},
}

# DLQ topics — one per source topic, Section 10.7
DLQ_TOPICS: Dict[str, Dict[str, Any]] = {
    f"{name}-dlq": {"partitions": 1, "retention_ms": 7 * 24 * 60 * 60 * 1000}
    for name in TOPICS
}


def _get_bootstrap_servers() -> str:
    """Resolve Kafka bootstrap servers from environment."""
    return os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")


# ---------------------------------------------------------------------------
# Topic creation utility
# ---------------------------------------------------------------------------

def ensure_topics_exist(
    bootstrap_servers: Optional[str] = None,
    timeout_s: float = 10.0,
) -> None:
    """
    Create all required topics (primary + DLQ) if they don't already exist.
    Called once during system bootstrap (e.g. from docker-compose entrypoint
    or a setup script).
    """
    servers = bootstrap_servers or _get_bootstrap_servers()
    admin = AdminClient({"bootstrap.servers": servers})

    all_topics = {**TOPICS, **DLQ_TOPICS}
    new_topics: List[NewTopic] = []

    existing = admin.list_topics(timeout=timeout_s).topics

    for topic_name, cfg in all_topics.items():
        if topic_name not in existing:
            new_topics.append(
                NewTopic(
                    topic=topic_name,
                    num_partitions=cfg["partitions"],
                    replication_factor=1,
                    config={"retention.ms": str(cfg["retention_ms"])},
                )
            )
            logger.info("Scheduling topic creation: %s", topic_name)

    if not new_topics:
        logger.info("All topics already exist.")
        return

    futures = admin.create_topics(new_topics)
    for topic_name, future in futures.items():
        try:
            future.result()
            logger.info("Created topic: %s", topic_name)
        except KafkaException as exc:
            logger.error("Failed to create topic %s: %s", topic_name, exc)
            raise


# ---------------------------------------------------------------------------
# Producer wrapper — Section 10.7 producer config
# ---------------------------------------------------------------------------

class SentinelProducer:
    """
    Kafka producer with idempotent writes, retries, and acks=all.
    Wraps confluent-kafka Producer for consistent configuration.
    """

    def __init__(
        self,
        bootstrap_servers: Optional[str] = None,
        extra_config: Optional[Dict[str, Any]] = None,
    ) -> None:
        servers = bootstrap_servers or _get_bootstrap_servers()
        config: Dict[str, Any] = {
            "bootstrap.servers": servers,
            "enable.idempotence": True,
            "retries": 3,
            "acks": "all",
            "retry.backoff.ms": 100,
        }
        if extra_config:
            config.update(extra_config)

        self._producer = Producer(config)
        logger.info("SentinelProducer initialized (servers=%s)", servers)

    def produce(
        self,
        topic: str,
        value: BaseModel,
        key: Optional[str] = None,
        on_delivery: Optional[Callable] = None,
    ) -> None:
        """
        Serialize a Pydantic model to JSON and produce it to the given topic.

        Args:
            topic: Kafka topic name.
            value: Pydantic model instance to serialize.
            key: Message key (Section 10.7 defines the key per topic).
            on_delivery: Optional callback for delivery reports.
        """
        payload = value.model_dump_json()
        self._producer.produce(
            topic=topic,
            value=payload.encode("utf-8"),
            key=key.encode("utf-8") if key else None,
            callback=on_delivery or self._default_delivery_callback,
        )
        self._producer.poll(0)  # Trigger delivery callbacks

    def produce_to_dlq(
        self,
        source_topic: str,
        raw_value: bytes,
        key: Optional[str] = None,
        error_reason: str = "",
    ) -> None:
        """
        Route a failed message to the corresponding dead-letter queue.
        Adds error metadata as per Section 10.7.
        """
        dlq_topic = f"{source_topic}-dlq"
        envelope = {
            "original_value": raw_value.decode("utf-8", errors="replace"),
            "error_reason": error_reason,
            "timestamp": datetime.utcnow().isoformat(),
        }
        self._producer.produce(
            topic=dlq_topic,
            value=json.dumps(envelope).encode("utf-8"),
            key=key.encode("utf-8") if key else None,
            callback=self._default_delivery_callback,
        )
        self._producer.poll(0)

    def flush(self, timeout_s: float = 5.0) -> int:
        """Flush pending messages, returning the number still in the queue."""
        return self._producer.flush(timeout=timeout_s)

    @staticmethod
    def _default_delivery_callback(err: Optional[KafkaError], msg: Any) -> None:
        if err is not None:
            logger.error("Delivery failed for %s: %s", msg.topic(), err)
        else:
            logger.debug("Delivered to %s [%d] @ %d", msg.topic(), msg.partition(), msg.offset())


# ---------------------------------------------------------------------------
# Consumer wrapper — Section 10.7 consumer config
# ---------------------------------------------------------------------------

class SentinelConsumer:
    """
    Kafka consumer with manual offset commit, Pydantic validation, dedup
    guard (via Redis), and DLQ routing after 3 consecutive failures.

    Usage:
        consumer = SentinelConsumer(
            group_id="dpi-agent-group",
            topics=["flow-events"],
        )
        for flow_event in consumer.consume_loop(FlowEvent):
            process(flow_event)
    """

    MAX_CONSECUTIVE_FAILURES: int = 3

    def __init__(
        self,
        group_id: str,
        topics: List[str],
        bootstrap_servers: Optional[str] = None,
        redis_client: Optional[Any] = None,
        producer: Optional[SentinelProducer] = None,
        extra_config: Optional[Dict[str, Any]] = None,
        poll_timeout_s: float = 1.0,
    ) -> None:
        servers = bootstrap_servers or _get_bootstrap_servers()
        config: Dict[str, Any] = {
            "bootstrap.servers": servers,
            "group.id": group_id,
            "auto.offset.reset": "earliest",
            "enable.auto.commit": False,
        }
        if extra_config:
            config.update(extra_config)

        self._group_id = group_id
        self._topics = topics
        self._consumer = Consumer(config)

        def _on_assign(consumer, partitions):
            logger.info(
                "DEBUG_LOG: Group ID: %s, Assigned Partitions: %s",
                self._group_id,
                [f"{p.topic}-{p.partition}" for p in partitions],
            )
            consumer.assign(partitions)

        self._consumer.subscribe(topics, on_assign=_on_assign)
        self._redis = redis_client
        self._producer = producer
        self._poll_timeout = poll_timeout_s
        self._running = True

        logger.info(
            "SentinelConsumer initialized (group=%s, topics=%s, servers=%s)",
            group_id,
            topics,
            servers,
        )

    def consume_loop(
        self,
        schema: Type[BaseModel],
        callback: Optional[Callable[[BaseModel], None]] = None,
    ) -> None:
        """
        Main consume loop.  Polls messages, validates against the Pydantic
        schema, performs dedup check, and calls the callback.

        Args:
            schema: Pydantic model class to validate incoming messages against.
            callback: Function to call with each validated model instance.
                      If None, the loop simply validates and commits.
        """
        consecutive_failures: Dict[str, int] = {}

        while self._running:
            msg = self._consumer.poll(timeout=self._poll_timeout)
            if msg is None:
                continue

            err = msg.error()
            if err:
                if err.code() == KafkaError._PARTITION_EOF:
                    logger.debug("Reached end of partition %s [%d]", msg.topic(), msg.partition())
                    continue
                logger.error("Consumer error: %s", err)
                continue

            # Successful poll
            logger.info(
                "DEBUG_LOG: Group ID: %s, Successful poll()",
                self._group_id,
            )

            raw_value = msg.value()
            msg_key = msg.key().decode("utf-8") if msg.key() else None
            topic = msg.topic()
            partition = msg.partition()
            offset = msg.offset()

            logger.info(
                "DEBUG_LOG: Group ID: %s, Received message - Topic: %s, Partition: %d, Offset: %d",
                self._group_id,
                topic,
                partition,
                offset,
            )

            # --- Pydantic validation (Section 10.12) ---
            try:
                parsed = schema.model_validate_json(raw_value)
            except ValidationError as exc:
                logger.error(
                    "Schema validation failed on %s: %s",
                    topic,
                    exc.error_count(),
                )
                self._route_to_dlq(topic, raw_value, msg_key, f"schema_validation: {exc}")
                self._consumer.commit(message=msg)
                continue

            # --- Dedup guard (Section 10.5, 10.7) ---
            if self._redis:
                dedup_key = f"dedupe:{self._group_id}:{topic}:{msg.partition()}:{msg.offset()}"
                if self._redis.get(dedup_key):
                    logger.debug("Duplicate skipped: %s", dedup_key)
                    self._consumer.commit(message=msg)
                    continue
                self._redis.set(dedup_key, "1", ex=60)

            # --- Processing with DLQ on repeated failure ---
            if callback:
                failure_key = f"{topic}:{msg.offset()}"
                try:
                    logger.info(
                        "DEBUG_LOG: Group ID: %s, Invoking callback for Topic: %s, Partition: %d, Offset: %d",
                        self._group_id,
                        topic,
                        partition,
                        offset,
                    )
                    callback(parsed)
                    consecutive_failures.pop(failure_key, None)
                except Exception:
                    count = consecutive_failures.get(failure_key, 0) + 1
                    consecutive_failures[failure_key] = count
                    logger.exception(
                        "Processing failed (%d/%d) on %s offset %d",
                        count,
                        self.MAX_CONSECUTIVE_FAILURES,
                        topic,
                        msg.offset(),
                    )
                    if count >= self.MAX_CONSECUTIVE_FAILURES:
                        self._route_to_dlq(
                            topic,
                            raw_value,
                            msg_key,
                            f"max_consecutive_failures_exceeded ({count})",
                        )
                        consecutive_failures.pop(failure_key, None)
                    else:
                        # Don't commit — will retry on next poll
                        continue

            # --- Manual offset commit (Section 10.7) ---
            self._consumer.commit(message=msg)

    def stop(self) -> None:
        """Signal the consume loop to stop."""
        self._running = False

    def close(self) -> None:
        """Stop and close the underlying consumer."""
        self.stop()
        self._consumer.close()
        logger.info("SentinelConsumer closed (group=%s)", self._group_id)

    def _route_to_dlq(
        self,
        source_topic: str,
        raw_value: bytes,
        key: Optional[str],
        error_reason: str,
    ) -> None:
        """Route a failed message to the topic's DLQ."""
        if self._producer:
            self._producer.produce_to_dlq(source_topic, raw_value, key, error_reason)
            logger.warning(
                "Routed message to DLQ: %s-dlq (reason: %s)",
                source_topic,
                error_reason,
            )
        else:
            logger.error(
                "Cannot route to DLQ (no producer configured): %s (reason: %s)",
                source_topic,
                error_reason,
            )


# ---------------------------------------------------------------------------
# Connection utilities
# ---------------------------------------------------------------------------

def wait_for_kafka(
    bootstrap_servers: Optional[str] = None,
    max_retries: int = 30,
    initial_backoff_s: float = 1.0,
    max_backoff_s: float = 30.0,
) -> None:
    """
    Block until Kafka is reachable, with exponential backoff.
    Section 10.12: reconnect with exponential backoff (1s, 2s, 4s… capped at 30s).
    """
    servers = bootstrap_servers or _get_bootstrap_servers()
    backoff = initial_backoff_s

    for attempt in range(1, max_retries + 1):
        try:
            admin = AdminClient({"bootstrap.servers": servers})
            admin.list_topics(timeout=5.0)
            logger.info("Kafka is available at %s", servers)
            return
        except KafkaException:
            logger.warning(
                "Kafka not available (attempt %d/%d), retrying in %.1fs…",
                attempt,
                max_retries,
                backoff,
            )
            time.sleep(backoff)
            backoff = min(backoff * 2, max_backoff_s)

    raise RuntimeError(f"Kafka not available at {servers} after {max_retries} attempts")
