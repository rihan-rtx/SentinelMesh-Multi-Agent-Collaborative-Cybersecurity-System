"""
SentinelMesh — Sniffer Agent: Flow Assembler (Section 10.1)

Assembles individual packets into directional network flows keyed by 5-tuple.
Implements the exact flow lifecycle from Section 10.1:

  OPENING → ACTIVE → CLOSING → CLOSED  (natural TCP close via FIN+ACK / RST)
  OPENING → ACTIVE → EXPIRED           (idle timeout expiry)

Key behaviours implemented:
  - Direction-normalized flow key: lower IP:port pair always first internally;
    emitted src_ip/dst_ip still reflect actual initiator (first packet seen).
  - Per-protocol idle timeouts: TCP 120s, UDP 60s, ICMP 30s (env-configurable).
  - TCP hard max duration: 300s (FLOW_TCP_MAX_DURATION_S).
  - Background sweep thread every 10s expiring stale flows.
  - Interim emit every 30s for long-lived active flows (same flow_id).
  - payload_sample: base64-encoded first 256 bytes of first payload-bearing packet.
"""

from __future__ import annotations

import base64
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Flow state (internal only — never emitted)
# ---------------------------------------------------------------------------

class FlowState(Enum):
    OPENING = auto()
    ACTIVE = auto()
    CLOSING = auto()
    CLOSED = auto()
    EXPIRED = auto()


# ---------------------------------------------------------------------------
# Internal flow record
# ---------------------------------------------------------------------------

@dataclass
class FlowRecord:
    """
    In-memory flow record held in the Sniffer Agent's flow table.
    All fields that appear in FlowEvent (Section 5.1) are kept here and
    emitted when the flow is closed or expires.
    """
    flow_id: str
    # Actual initiator (first packet seen)
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str  # "TCP" | "UDP" | "ICMP" | "OTHER"

    timestamp_start: datetime
    timestamp_last: datetime

    packet_count: int = 0
    byte_count: int = 0
    tcp_flags_seen: Set[str] = field(default_factory=set)
    payload_sample: Optional[bytes] = None  # Raw bytes; base64-encoded on emit

    state: FlowState = FlowState.OPENING

    # Track whether a FIN has been seen from each side for TCP natural close
    fin_seen_initiator: bool = False
    fin_seen_responder: bool = False

    # For interim emit tracking (Section 10.1)
    last_interim_emit: Optional[datetime] = None


def _normalize_tuple(
    src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str
) -> Tuple[str, str, int, int, str]:
    """
    Return a direction-normalized 5-tuple for use as the flow table key.
    Lower IP:port pair always comes first.
    This makes A→B and B→A map to the same key, per Section 10.1.
    """
    import ipaddress
    try:
        # Use ipaddress to ensure numeric comparison is correct
        ip_a = ipaddress.ip_address(src_ip)
        ip_b = ipaddress.ip_address(dst_ip)
        pair_a = (ip_a, src_port)
        pair_b = (ip_b, dst_port)
    except ValueError:
        # Fallback to string comparison if not valid IPs
        pair_a = (src_ip, src_port)
        pair_b = (dst_ip, dst_port)

    if pair_a <= pair_b:
        return (src_ip, dst_ip, src_port, dst_port, protocol)
    else:
        return (dst_ip, src_ip, dst_port, src_port, protocol)


# ---------------------------------------------------------------------------
# Configuration helpers
# ---------------------------------------------------------------------------

def _int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        logger.warning("Invalid value for %s, using default %d", name, default)
        return default


# ---------------------------------------------------------------------------
# Flow Assembler
# ---------------------------------------------------------------------------

class FlowAssembler:
    """
    Assembles raw packets into flow records (Section 10.1).

    Usage:
        def on_flow_complete(flow: FlowRecord) -> None:
            # serialize and emit to Kafka
            ...

        assembler = FlowAssembler(on_flow_complete=on_flow_complete)
        assembler.start_sweep_thread()

        # For each packet:
        assembler.process_packet(
            src_ip="1.2.3.4", dst_ip="5.6.7.8",
            src_port=54321, dst_port=80, protocol="TCP",
            payload=b"GET / HTTP/1.1...",
            tcp_flags={"SYN"},
            pkt_size=1500,
        )
    """

    PAYLOAD_SAMPLE_BYTES: int = 256  # Section 10.2: first 256 bytes

    def __init__(
        self,
        on_flow_complete: Callable[[FlowRecord], None],
        sweep_interval_s: float = 10.0,
    ) -> None:
        self._on_flow_complete = on_flow_complete
        self._sweep_interval = sweep_interval_s

        # Per-protocol idle timeouts (Section 10.1, all env-configurable)
        self._tcp_idle = _int_env("FLOW_TCP_IDLE_TIMEOUT_S", 120)
        self._tcp_max = _int_env("FLOW_TCP_MAX_DURATION_S", 300)
        self._udp_idle = _int_env("FLOW_UDP_IDLE_TIMEOUT_S", 60)
        self._icmp_idle = _int_env("FLOW_ICMP_IDLE_TIMEOUT_S", 30)
        self._interim_interval = _int_env("FLOW_INTERIM_EMIT_INTERVAL_S", 30)

        # Flow table: normalized_5_tuple → FlowRecord
        self._flows: Dict[Tuple, FlowRecord] = {}
        self._lock = threading.Lock()

        # Background sweep thread
        self._sweep_thread: Optional[threading.Thread] = None
        self._running = False

        logger.info(
            "FlowAssembler initialized (tcp_idle=%ds, tcp_max=%ds, "
            "udp_idle=%ds, icmp_idle=%ds, interim=%ds)",
            self._tcp_idle, self._tcp_max, self._udp_idle,
            self._icmp_idle, self._interim_interval,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start_sweep_thread(self) -> None:
        """Start the background expiry sweep thread."""
        if self._sweep_thread and self._sweep_thread.is_alive():
            return
        self._running = True
        self._sweep_thread = threading.Thread(
            target=self._sweep_loop,
            name="flow-sweep",
            daemon=True,
        )
        self._sweep_thread.start()
        logger.info("Flow sweep thread started (interval=%ds)", int(self._sweep_interval))

    def stop_sweep_thread(self) -> None:
        """Signal the sweep thread to stop and join it."""
        self._running = False
        if self._sweep_thread:
            self._sweep_thread.join(timeout=self._sweep_interval + 1)

    def process_packet(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str,
        payload: bytes,
        tcp_flags: Optional[Set[str]] = None,
        pkt_size: int = 0,
        timestamp: Optional[datetime] = None,
    ) -> None:
        """
        Process a single packet. Updates the flow table and emits a flow
        event if the flow closes naturally (TCP FIN+ACK both directions,
        or TCP RST).

        Args:
            src_ip: Source IP of this packet (actual direction).
            dst_ip: Destination IP.
            src_port: Source port.
            dst_port: Destination port.
            protocol: "TCP" | "UDP" | "ICMP" | "OTHER"
            payload: Raw payload bytes (may be empty b"").
            tcp_flags: Set of TCP flag names seen on this packet.
            pkt_size: Total packet size in bytes.
            timestamp: Packet timestamp; defaults to now if None.
        """
        ts = timestamp or datetime.now(tz=timezone.utc)
        tcp_flags = tcp_flags or set()
        key = _normalize_tuple(src_ip, dst_ip, src_port, dst_port, protocol)

        with self._lock:
            if key not in self._flows:
                # New flow — check TCP: only opens on SYN
                if protocol == "TCP" and "SYN" not in tcp_flags:
                    logger.debug(
                        "Dropping mid-stream TCP packet (no SYN, no existing flow): %s",
                        key,
                    )
                    return
                flow = self._new_flow(
                    key, src_ip, dst_ip, src_port, dst_port, protocol, ts
                )
                self._flows[key] = flow
                logger.debug("New flow opened: %s (id=%s)", key, flow.flow_id)

            flow = self._flows[key]

            # Update running counters
            flow.packet_count += 1
            flow.byte_count += pkt_size
            flow.timestamp_last = ts

            # Capture first payload sample
            if payload and flow.payload_sample is None:
                flow.payload_sample = payload[: self.PAYLOAD_SAMPLE_BYTES]

            # TCP flag tracking
            if protocol == "TCP":
                for flag in tcp_flags:
                    flow.tcp_flags_seen.add(flag)

            flow.state = FlowState.ACTIVE

            # Check for natural TCP close conditions
            closed = False
            if protocol == "TCP":
                closed = self._handle_tcp_flags(flow, src_ip, tcp_flags)

            if closed:
                logger.debug("Flow closed naturally: %s (id=%s)", key, flow.flow_id)
                self._emit_and_remove(key, flow)

    def flush_all(self) -> None:
        """
        Force-emit all remaining open flows. Called on Sniffer Agent shutdown.
        """
        with self._lock:
            keys = list(self._flows.keys())
        for key in keys:
            with self._lock:
                if key in self._flows:
                    flow = self._flows.pop(key)
            self._on_flow_complete(flow)

    def active_flow_count(self) -> int:
        """Return the current number of open flows (for health/metrics)."""
        with self._lock:
            return len(self._flows)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _new_flow(
        self,
        key: Tuple,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str,
        ts: datetime,
    ) -> FlowRecord:
        """Create a new FlowRecord for the given 5-tuple."""
        import uuid
        return FlowRecord(
            flow_id=str(uuid.uuid4()),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            timestamp_start=ts,
            timestamp_last=ts,
        )

    def _handle_tcp_flags(self, flow: FlowRecord, pkt_src_ip: str, flags: Set[str]) -> bool:
        """
        Handle TCP state transitions.  Returns True if the flow should be closed.

        Natural close: FIN+ACK seen from both directions, or RST seen.
        RST closes immediately regardless of direction.
        """
        if "RST" in flags:
            flow.state = FlowState.CLOSING
            return True

        if "FIN" in flags:
            # Determine direction: initiator = flow.src_ip
            if pkt_src_ip == flow.src_ip:
                flow.fin_seen_initiator = True
            else:
                flow.fin_seen_responder = True

            if flow.fin_seen_initiator and flow.fin_seen_responder:
                flow.state = FlowState.CLOSING
                return True

        return False

    def _emit_and_remove(self, key: Tuple, flow: FlowRecord) -> None:
        """Emit the flow event and remove from the table. Lock must be held."""
        del self._flows[key]
        self._on_flow_complete(flow)

    def _sweep_loop(self) -> None:
        """
        Background thread: runs every sweep_interval_s.
        Expires idle and max-duration flows; emits interim events for
        long-lived active flows (Section 10.1).
        """
        while self._running:
            time.sleep(self._sweep_interval)
            self._run_sweep()

    def _run_sweep(self) -> None:
        """
        Core sweep logic, separated for testability.
        Iterates the flow table, handles expiry and interim emission.
        """
        now = datetime.now(tz=timezone.utc)
        to_expire: List[Tuple] = []
        to_interim: List[Tuple] = []

        with self._lock:
            for key, flow in self._flows.items():
                idle_s = (now - flow.timestamp_last).total_seconds()
                age_s = (now - flow.timestamp_start).total_seconds()

                idle_timeout = self._idle_timeout_for(flow.protocol)

                # TCP hard max duration (Section 10.1)
                if flow.protocol == "TCP" and age_s >= self._tcp_max:
                    logger.debug(
                        "Flow hit TCP max duration (%ds): %s (id=%s)",
                        self._tcp_max, key, flow.flow_id,
                    )
                    flow.state = FlowState.EXPIRED
                    to_expire.append(key)
                    continue

                # Idle timeout
                if idle_s >= idle_timeout:
                    logger.debug(
                        "Flow idle timeout (%ds) expired: %s (id=%s)",
                        idle_timeout, key, flow.flow_id,
                    )
                    flow.state = FlowState.EXPIRED
                    to_expire.append(key)
                    continue

                # Interim emit for long-lived active flows (Section 10.1)
                last_interim = flow.last_interim_emit or flow.timestamp_start
                since_interim = (now - last_interim).total_seconds()
                if since_interim >= self._interim_interval:
                    to_interim.append(key)

        # Emit interim events (without holding lock — on_flow_complete may block)
        for key in to_interim:
            with self._lock:
                if key in self._flows:
                    flow = self._flows[key]
                    flow.last_interim_emit = now
            logger.debug("Interim emit for long-lived flow: %s (id=%s)", key, flow.flow_id)
            self._on_flow_complete(flow)  # same flow_id, cumulative counters

        # Expire and remove flows
        for key in to_expire:
            with self._lock:
                if key in self._flows:
                    flow = self._flows.pop(key)
            logger.info(
                "Flow expired: %s (id=%s, pkts=%d, bytes=%d)",
                key, flow.flow_id, flow.packet_count, flow.byte_count,
            )
            self._on_flow_complete(flow)

    def _idle_timeout_for(self, protocol: str) -> int:
        """Return the idle timeout in seconds for a given protocol (Section 10.1)."""
        return {
            "TCP": self._tcp_idle,
            "UDP": self._udp_idle,
            "ICMP": self._icmp_idle,
        }.get(protocol, self._udp_idle)  # OTHER uses UDP timeout as fallback


# ---------------------------------------------------------------------------
# Packet-to-flow-fields extraction (Scapy-agnostic helpers)
# ---------------------------------------------------------------------------

def payload_to_b64(raw_bytes: Optional[bytes]) -> Optional[str]:
    """
    Base64-encode raw payload bytes for inclusion in FlowEvent.payload_sample.
    Returns None if raw_bytes is None or empty.
    """
    if not raw_bytes:
        return None
    return base64.b64encode(raw_bytes).decode("ascii")


def flow_record_duration_ms(flow: FlowRecord) -> int:
    """Compute flow duration in milliseconds from start to last packet."""
    delta = flow.timestamp_last - flow.timestamp_start
    return max(0, int(delta.total_seconds() * 1000))
