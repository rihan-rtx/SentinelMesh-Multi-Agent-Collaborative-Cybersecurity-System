"""
SentinelMesh — Shared Prometheus Metrics (shared/metrics.py)

Canonical, single-source definitions for all six Prometheus metric objects
specified in Section 10.10 of the project specification.

By defining every metric exactly once here — rather than in each agent's
main.py — we guarantee that the prometheus_client CollectorRegistry never
sees duplicate registrations, regardless of how many agent modules are
imported into a single Python process (as happens during combined pytest
runs, Jupyter notebooks, or any multi-agent tooling).

NOTE (Spec Clarification):
    Section 10.10 specifies the six metric *names*, types, and label sets,
    but does not prescribe where in the codebase they are defined.  This
    module is an implementation decision — placing them in ``shared/`` —
    so that the single-registry constraint of prometheus_client is satisfied
    and every agent can import the same objects.

Metric inventory (Section 10.10):
    1. sentinelmesh_events_consumed_total    Counter   [agent, topic]
    2. sentinelmesh_events_produced_total    Counter   [agent, topic]
    3. sentinelmesh_processing_latency_seconds  Histogram  [agent]
    4. sentinelmesh_errors_total             Counter   [agent, error_type]
    5. sentinelmesh_queue_depth              Gauge     [agent]
    6. sentinelmesh_agent_up                 Gauge     [agent]
"""

from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram

# 1. Events consumed — Counter
EVENTS_CONSUMED = Counter(
    "sentinelmesh_events_consumed_total",
    "Messages successfully consumed",
    ["agent", "topic"],
)

# 2. Events produced — Counter
EVENTS_PRODUCED = Counter(
    "sentinelmesh_events_produced_total",
    "Messages successfully produced",
    ["agent", "topic"],
)

# 3. Processing latency — Histogram
PROCESSING_LATENCY = Histogram(
    "sentinelmesh_processing_latency_seconds",
    "Time to process one message, consume-to-produce",
    ["agent"],
)

# 4. Errors — Counter
ERRORS_TOTAL = Counter(
    "sentinelmesh_errors_total",
    "Processing failures, by category",
    ["agent", "error_type"],
)

# 5. Queue depth — Gauge
QUEUE_DEPTH = Gauge(
    "sentinelmesh_queue_depth",
    "Consumer lag on the agent's input topic(s)",
    ["agent"],
)

# 6. Agent liveness — Gauge
AGENT_UP = Gauge(
    "sentinelmesh_agent_up",
    "1/0, set by the Coordinator based on health key freshness (Section 10.5)",
    ["agent"],
)
