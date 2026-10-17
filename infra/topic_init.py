"""
SentinelMesh — Topic Initializer

One-shot script that creates all Kafka topics defined in Section 10.7.
Runs as a container in Docker Compose, exits 0 after topics are created.
"""

import logging
import sys

from shared.kafka_client import ensure_topics_exist, wait_for_kafka

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

logger = logging.getLogger(__name__)


def main() -> None:
    """Wait for Kafka to be available, then create all topics."""
    logger.info("Topic initializer starting…")
    try:
        wait_for_kafka()
        ensure_topics_exist()
        logger.info("All topics created successfully. Exiting.")
    except Exception:
        logger.exception("Topic initialization failed.")
        sys.exit(1)


if __name__ == "__main__":
    main()
