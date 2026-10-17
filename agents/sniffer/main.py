"""
SentinelMesh — Sniffer Agent (main.py)

Captures packets (live NIC via Scapy, or pcap file replay) and emits
flow-events to Kafka via the flow assembler.

Supports:
  - SNIFFER_MODE=live  : real-time capture via Scapy sniff()
  - SNIFFER_MODE=pcap  : offline replay from SNIFFER_PCAP_PATH

Both modes produce identical FlowEvent output (Section 5.1).
Section 9 acceptance: consumes raw traffic, produces flow-events, reports health.
Section 10.11 env vars drive all configuration.
"""

from __future__ import annotations

import logging
import os
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Optional, Set

from dotenv import load_dotenv

load_dotenv()

# Configure structured logging early
from pythonjsonlogger import jsonlogger  # type: ignore

_log_level = os.getenv("LOG_LEVEL", "INFO").upper()
_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(
    jsonlogger.JsonFormatter(
        fmt="%(asctime)s %(name)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )
)
logging.basicConfig(level=_log_level, handlers=[_handler])
logger = logging.getLogger("sniffer")

# Prometheus metrics (Section 10.10) — imported from shared single-source definitions
from prometheus_client import start_http_server

from shared.metrics import (
    AGENT_UP,
    ERRORS_TOTAL,
    EVENTS_PRODUCED,
    PROCESSING_LATENCY,
    QUEUE_DEPTH,
)

try:
    prom_port = int(os.getenv("PROMETHEUS_PORT_SNIFFER", "9101"))
    start_http_server(prom_port)
    logger.info("Prometheus metrics server started", extra={"port": prom_port})
except Exception as exc:  # noqa: BLE001
    logger.warning("Could not start Prometheus server: %s", exc)

import redis as redis_lib

from agents.sniffer.flow_assembler import (
    FlowAssembler,
    FlowRecord,
    flow_record_duration_ms,
    payload_to_b64,
)
from shared.kafka_client import SentinelProducer, wait_for_kafka
from shared.schemas import AgentHealthPing, AgentStatus, FlowEvent

AGENT_NAME = "sniffer"
TOPIC = "flow-events"

# ---------------------------------------------------------------------------
# Environment config
# ---------------------------------------------------------------------------

KAFKA_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
SNIFFER_MODE = os.getenv("SNIFFER_MODE", "live").lower()
SNIFFER_INTERFACE = os.getenv("SNIFFER_INTERFACE", "eth0")
SNIFFER_PCAP_PATH = os.getenv("SNIFFER_PCAP_PATH", "/pcaps/demo_scenario.pcap")
HEALTH_PING_INTERVAL_S = int(os.getenv("HEALTH_PING_INTERVAL_S", "5"))
HEALTH_KEY_TTL_S = int(os.getenv("HEALTH_KEY_TTL_S", "15"))


# ---------------------------------------------------------------------------
# Scapy import (graceful — may not be available in test environments)
# ---------------------------------------------------------------------------

try:
    from scapy.all import (  # type: ignore
        IP, IPv6, TCP, UDP, ICMP,
        Raw, sniff, rdpcap,
        Ether,
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("Scapy not available — capture functionality disabled")


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

_producer: Optional[SentinelProducer] = None
_redis: Optional[redis_lib.Redis] = None
_assembler: Optional[FlowAssembler] = None
_events_produced: int = 0  # for health ping throughput


# ---------------------------------------------------------------------------
# Flow completion callback
# ---------------------------------------------------------------------------

def _on_flow_complete(flow: FlowRecord) -> None:
    """
    Called by FlowAssembler when a flow is closed or expired.
    Serializes the FlowRecord into a FlowEvent and produces it to Kafka.
    """
    global _events_produced
    if _producer is None:
        return

    event = FlowEvent(
        flow_id=flow.flow_id,
        timestamp_start=flow.timestamp_start,
        timestamp_last=flow.timestamp_last,
        src_ip=flow.src_ip,
        dst_ip=flow.dst_ip,
        src_port=flow.src_port,
        dst_port=flow.dst_port,
        protocol=flow.protocol,
        packet_count=flow.packet_count,
        byte_count=flow.byte_count,
        tcp_flags_seen=sorted(flow.tcp_flags_seen),
        payload_sample=payload_to_b64(flow.payload_sample),
        duration_ms=flow_record_duration_ms(flow),
    )

    try:
        _producer.produce(topic=TOPIC, value=event, key=flow.src_ip)
        _events_produced += 1
        EVENTS_PRODUCED.labels(agent=AGENT_NAME, topic=TOPIC).inc()
        logger.info(
            "Flow emitted",
            extra={
                "flow_id": event.flow_id,
                "src": f"{event.src_ip}:{event.src_port}",
                "dst": f"{event.dst_ip}:{event.dst_port}",
                "protocol": event.protocol,
                "packets": event.packet_count,
                "bytes": event.byte_count,
            },
        )
    except Exception:
        ERRORS_TOTAL.labels(agent=AGENT_NAME, error_type="produce_error").inc()
        logger.exception("Failed to produce flow event for flow_id=%s", flow.flow_id)


# ---------------------------------------------------------------------------
# Packet extraction from Scapy packet object
# ---------------------------------------------------------------------------

def _extract_fields_from_scapy_pkt(pkt: object) -> Optional[dict]:
    """
    Extract normalized fields from a Scapy packet.
    Returns None if the packet should be ignored (e.g. non-IP).
    """
    if not SCAPY_AVAILABLE:
        return None

    if not pkt.haslayer(IP) and not pkt.haslayer(IPv6):  # type: ignore
        return None

    ip_layer = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]  # type: ignore
    src_ip: str = str(ip_layer.src)
    dst_ip: str = str(ip_layer.dst)

    tcp_flags: Set[str] = set()
    payload = b""
    pkt_size: int = len(bytes(pkt))  # type: ignore

    if pkt.haslayer(TCP):  # type: ignore
        tcp = pkt[TCP]  # type: ignore
        src_port = int(tcp.sport)
        dst_port = int(tcp.dport)
        protocol = "TCP"
        # Parse Scapy flags object into named strings
        flag_map = {"S": "SYN", "A": "ACK", "F": "FIN", "R": "RST", "P": "PSH", "U": "URG"}
        tcp_flags = {name for char, name in flag_map.items() if char in str(tcp.flags)}
        if pkt.haslayer(Raw):  # type: ignore
            payload = bytes(pkt[Raw].load)  # type: ignore
    elif pkt.haslayer(UDP):  # type: ignore
        udp = pkt[UDP]  # type: ignore
        src_port = int(udp.sport)
        dst_port = int(udp.dport)
        protocol = "UDP"
        if pkt.haslayer(Raw):  # type: ignore
            payload = bytes(pkt[Raw].load)  # type: ignore
    elif pkt.haslayer(ICMP):  # type: ignore
        icmp = pkt[ICMP]  # type: ignore
        src_port = int(icmp.type)  # ICMP type as pseudo-port
        dst_port = int(icmp.code)
        protocol = "ICMP"
    else:
        src_port = 0
        dst_port = 0
        protocol = "OTHER"

    ts_epoch = float(getattr(pkt, "time", time.time()))
    ts = datetime.fromtimestamp(ts_epoch, tz=timezone.utc)

    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "payload": payload,
        "tcp_flags": tcp_flags,
        "pkt_size": pkt_size,
        "timestamp": ts,
    }


def _process_scapy_packet(pkt: object) -> None:
    """Scapy callback: extract fields and feed into the flow assembler."""
    if _assembler is None:
        return
    try:
        with PROCESSING_LATENCY.labels(agent=AGENT_NAME).time():
            fields = _extract_fields_from_scapy_pkt(pkt)
            if fields:
                _assembler.process_packet(**fields)
        QUEUE_DEPTH.labels(agent=AGENT_NAME).set(_assembler.active_flow_count())
    except Exception:
        ERRORS_TOTAL.labels(agent=AGENT_NAME, error_type="packet_processing").inc()
        logger.exception("Error processing packet")


# ---------------------------------------------------------------------------
# Health ping loop (Section 5.6, 10.11)
# ---------------------------------------------------------------------------

def _health_ping_loop(redis_client: redis_lib.Redis) -> None:
    """
    Emits Section 5.6 health pings to Redis every HEALTH_PING_INTERVAL_S.
    Coordinator reads `health:{agent_name}` key; TTL = HEALTH_KEY_TTL_S.
    """
    global _events_produced
    interval_start_count = 0

    while True:
        time.sleep(HEALTH_PING_INTERVAL_S)
        try:
            throughput = _events_produced - interval_start_count
            interval_start_count = _events_produced

            ping = AgentHealthPing(
                agent_name=AGENT_NAME,
                timestamp=datetime.now(tz=timezone.utc),
                status=AgentStatus.HEALTHY,
                throughput_last_interval=throughput,
                queue_depth=_assembler.active_flow_count() if _assembler else 0,
            )
            redis_client.set(
                f"health:{AGENT_NAME}",
                ping.model_dump_json(),
                ex=HEALTH_KEY_TTL_S,
            )
            AGENT_UP.labels(agent=AGENT_NAME).set(1)
            logger.debug("Health ping sent", extra={"throughput": throughput})
        except Exception:
            AGENT_UP.labels(agent=AGENT_NAME).set(0)
            logger.exception("Failed to send health ping")


# ---------------------------------------------------------------------------
# Capture modes
# ---------------------------------------------------------------------------

def run_live_capture() -> None:
    """Live capture from the configured network interface (Section 6, Phase 2)."""
    if not SCAPY_AVAILABLE:
        logger.error(
            "Scapy is not installed; cannot run live capture. "
            "Install scapy and ensure capture permissions."
        )
        sys.exit(1)

    logger.info("Starting live capture", extra={"interface": SNIFFER_INTERFACE})
    try:
        sniff(  # type: ignore
            iface=SNIFFER_INTERFACE,
            prn=_process_scapy_packet,
            store=False,  # Section 3: store=False to avoid memory bloat
        )
    except PermissionError:
        # Section 10.12: if capture permission denied, log and exit non-zero
        logger.error(
            "Permission denied for interface %s. "
            "Run as root or grant CAP_NET_RAW capability.",
            SNIFFER_INTERFACE,
        )
        sys.exit(1)
    except OSError as exc:
        # Section 10.12: interface down — log clear actionable error and exit
        logger.error(
            "Cannot capture on interface %s: %s. "
            "Verify the interface exists and is up.",
            SNIFFER_INTERFACE, exc,
        )
        sys.exit(1)


def run_pcap_replay() -> None:
    """Replay packets from a pcap file (Section 1.5, Section 6 Phase 2)."""
    if not SCAPY_AVAILABLE:
        logger.error("Scapy is not installed; cannot replay pcap.")
        sys.exit(1)

    if not os.path.exists(SNIFFER_PCAP_PATH):
        logger.error(
            "pcap file not found: %s. "
            "Set SNIFFER_PCAP_PATH to a valid .pcap file.",
            SNIFFER_PCAP_PATH,
        )
        sys.exit(1)

    logger.info("Replaying pcap file", extra={"path": SNIFFER_PCAP_PATH})
    try:
        packets = rdpcap(SNIFFER_PCAP_PATH)  # type: ignore
    except Exception:
        logger.exception("Failed to read pcap file: %s", SNIFFER_PCAP_PATH)
        sys.exit(1)

    for pkt in packets:
        _process_scapy_packet(pkt)

    # Flush remaining open flows after replay ends
    logger.info("pcap replay complete — flushing %d open flows", _assembler.active_flow_count() if _assembler else 0)
    if _assembler:
        _assembler.flush_all()
    if _producer:
        _producer.flush()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    global _producer, _redis, _assembler

    logger.info("Sniffer Agent starting", extra={"mode": SNIFFER_MODE})

    # Wait for Kafka (Section 10.12: exponential backoff, never crash on transient)
    wait_for_kafka(bootstrap_servers=KAFKA_SERVERS)

    # Redis for health pings
    try:
        _redis = redis_lib.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
        _redis.ping()
        logger.info("Redis connected", extra={"host": REDIS_HOST, "port": REDIS_PORT})
    except Exception:
        logger.warning("Redis unavailable — health pings will fail until Redis recovers")
        _redis = None

    # Kafka producer
    _producer = SentinelProducer(bootstrap_servers=KAFKA_SERVERS)

    # Flow assembler
    _assembler = FlowAssembler(on_flow_complete=_on_flow_complete)
    _assembler.start_sweep_thread()

    # Health ping thread (daemon)
    if _redis:
        health_thread = threading.Thread(
            target=_health_ping_loop,
            args=(_redis,),
            name="health-ping",
            daemon=True,
        )
        health_thread.start()

    # Run the appropriate capture mode
    if SNIFFER_MODE == "pcap":
        run_pcap_replay()
    else:
        run_live_capture()

    _assembler.stop_sweep_thread()


if __name__ == "__main__":
    main()
