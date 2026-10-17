"""
SentinelMesh — Unit Tests for Sniffer Agent (Section 10.13)

Tests per Section 10.13:
  - Flow assembly correctness against synthetic packet sequences
  - Correct bidirectional 5-tuple normalization
  - Idle-timeout and max-duration expiry logic
  - Interim-emit behaviour for long-lived flows
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Set
from unittest.mock import MagicMock, patch

import pytest

from agents.sniffer.flow_assembler import (
    FlowAssembler,
    FlowRecord,
    FlowState,
    _normalize_tuple,
    flow_record_duration_ms,
    payload_to_b64,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


def _ts(seconds_ago: float = 0) -> datetime:
    return datetime.now(tz=timezone.utc) - timedelta(seconds=seconds_ago)


class FlowCollector:
    """Collects flow events emitted by FlowAssembler for assertions."""

    def __init__(self) -> None:
        self.flows: List[FlowRecord] = []

    def on_flow(self, flow: FlowRecord) -> None:
        self.flows.append(flow)

    def clear(self) -> None:
        self.flows.clear()


# ---------------------------------------------------------------------------
# 5-tuple normalization tests (Section 10.1)
# ---------------------------------------------------------------------------

class TestNormalizeTuple:
    """Verify bidirectional 5-tuple normalization from Section 10.1."""

    def test_lower_ip_first_when_src_lower(self) -> None:
        """If src_ip < dst_ip, tuple stays in src→dst order."""
        result = _normalize_tuple("10.0.0.1", "10.0.0.2", 1000, 80, "TCP")
        assert result == ("10.0.0.1", "10.0.0.2", 1000, 80, "TCP")

    def test_lower_ip_first_when_dst_lower(self) -> None:
        """If dst_ip < src_ip, tuple is reversed so lower IP comes first."""
        result = _normalize_tuple("192.168.1.100", "10.0.0.1", 54321, 80, "TCP")
        assert result == ("10.0.0.1", "192.168.1.100", 80, 54321, "TCP")

    def test_same_ip_lower_port_first(self) -> None:
        """When IPs are equal, lower port comes first."""
        result = _normalize_tuple("10.0.0.1", "10.0.0.1", 9000, 80, "TCP")
        assert result == ("10.0.0.1", "10.0.0.1", 80, 9000, "TCP")

    def test_ab_and_ba_produce_same_key(self) -> None:
        """A→B and B→A packets must produce the same normalized key."""
        forward = _normalize_tuple("10.0.0.1", "10.0.0.2", 1000, 80, "TCP")
        reverse = _normalize_tuple("10.0.0.2", "10.0.0.1", 80, 1000, "TCP")
        assert forward == reverse

    def test_protocol_preserved(self) -> None:
        """Protocol string is preserved in normalized tuple."""
        result = _normalize_tuple("1.1.1.1", "2.2.2.2", 53, 1234, "UDP")
        assert result[4] == "UDP"

    def test_initiator_ip_preserved_in_flow_record(self) -> None:
        """
        After normalization, the FlowRecord.src_ip must still reflect the
        actual initiator (first packet's src_ip), not the normalized order.
        """
        collector = FlowCollector()
        assembler = FlowAssembler(on_flow_complete=collector.on_flow)

        # Send a single SYN from the "high" IP (would be reversed in key)
        assembler.process_packet(
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=80,
            protocol="TCP",
            payload=b"",
            tcp_flags={"SYN"},
            pkt_size=60,
            timestamp=_now(),
        )
        # Now send RST to close the flow
        assembler.process_packet(
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=80,
            protocol="TCP",
            payload=b"",
            tcp_flags={"RST"},
            pkt_size=40,
            timestamp=_now(),
        )

        assert len(collector.flows) == 1
        flow = collector.flows[0]
        # Initiator is the 192.168 address (sent first SYN)
        assert flow.src_ip == "192.168.1.100"
        assert flow.dst_ip == "10.0.0.1"


# ---------------------------------------------------------------------------
# Flow assembly correctness (Section 10.13)
# ---------------------------------------------------------------------------

class TestFlowAssembly:
    """Core flow assembly correctness tests."""

    def test_tcp_flow_opens_on_syn(self) -> None:
        """TCP flow only opens on SYN packet."""
        collector = FlowCollector()
        assembler = FlowAssembler(on_flow_complete=collector.on_flow)

        # Non-SYN packet first — should be ignored
        assembler.process_packet(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=1000, dst_port=80, protocol="TCP",
            payload=b"data", tcp_flags={"ACK"}, pkt_size=100,
            timestamp=_now(),
        )
        assert assembler.active_flow_count() == 0

        # SYN packet — flow should open
        assembler.process_packet(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=1000, dst_port=80, protocol="TCP",
            payload=b"", tcp_flags={"SYN"}, pkt_size=60,
            timestamp=_now(),
        )
        assert assembler.active_flow_count() == 1

    def test_udp_flow_opens_on_first_packet(self) -> None:
        """UDP flow opens immediately on first packet (no SYN concept)."""
        collector = FlowCollector()
        assembler = FlowAssembler(on_flow_complete=collector.on_flow)

        assembler.process_packet(
            src_ip="10.0.0.1", dst_ip="8.8.8.8",
            src_port=54321, dst_port=53, protocol="UDP",
            payload=b"\x00\x01", tcp_flags=None, pkt_size=42,
            timestamp=_now(),
        )
        assert assembler.active_flow_count() == 1

    def test_tcp_flow_closes_on_rst(self) -> None:
        """TCP RST immediately closes the flow."""
        collector = FlowCollector()
        assembler = FlowAssembler(on_flow_complete=collector.on_flow)

        ts = _now()
        assembler.process_packet(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=1001, dst_port=80, protocol="TCP",
            payload=b"", tcp_flags={"SYN"}, pkt_size=60, timestamp=ts,
        )
        assembler.process_packet(
            src_ip="10.0.0.2", dst_ip="10.0.0.1",
            src_port=80, dst_port=1001, protocol="TCP",
            payload=b"", tcp_flags={"RST"}, pkt_size=40,
            timestamp=ts + timedelta(milliseconds=100),
        )

        assert assembler.active_flow_count() == 0
        assert len(collector.flows) == 1

    def test_tcp_flow_closes_on_fin_both_directions(self) -> None:
        """TCP flow closes naturally after FIN from both directions."""
        collector = FlowCollector()
        assembler = FlowAssembler(on_flow_complete=collector.on_flow)

        ts = _now()
        # SYN
        assembler.process_packet(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=1002, dst_port=80, protocol="TCP",
            payload=b"", tcp_flags={"SYN"}, pkt_size=60, timestamp=ts,
        )
        # Data exchange
        assembler.process_packet(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=1002, dst_port=80, protocol="TCP",
            payload=b"GET / HTTP/1.1\r\n\r\n", tcp_flags={"ACK", "PSH"},
            pkt_size=200, timestamp=ts + timedelta(seconds=1),
        )
        # FIN from initiator
        assembler.process_packet(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=1002, dst_port=80, protocol="TCP",
            payload=b"", tcp_flags={"FIN", "ACK"}, pkt_size=40,
            timestamp=ts + timedelta(seconds=2),
        )
        # Flow should still be open (waiting for responder FIN)
        assert assembler.active_flow_count() == 1

        # FIN from responder
        assembler.process_packet(
            src_ip="10.0.0.2", dst_ip="10.0.0.1",
            src_port=80, dst_port=1002, protocol="TCP",
            payload=b"", tcp_flags={"FIN", "ACK"}, pkt_size=40,
            timestamp=ts + timedelta(seconds=3),
        )
        # Flow should now be closed
        assert assembler.active_flow_count() == 0
        assert len(collector.flows) == 1

    def test_packet_counters_accumulate(self) -> None:
        """packet_count and byte_count accumulate across packets in the same flow."""
        collector = FlowCollector()
        assembler = FlowAssembler(on_flow_complete=collector.on_flow)

        ts = _now()
        assembler.process_packet(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=1003, dst_port=80, protocol="TCP",
            payload=b"", tcp_flags={"SYN"}, pkt_size=60, timestamp=ts,
        )
        assembler.process_packet(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=1003, dst_port=80, protocol="TCP",
            payload=b"Hello", tcp_flags={"ACK", "PSH"}, pkt_size=200,
            timestamp=ts + timedelta(seconds=1),
        )
        assembler.process_packet(
            src_ip="10.0.0.2", dst_ip="10.0.0.1",
            src_port=80, dst_port=1003, protocol="TCP",
            payload=b"World", tcp_flags={"ACK"}, pkt_size=150,
            timestamp=ts + timedelta(seconds=2),
        )
        assembler.process_packet(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=1003, dst_port=80, protocol="TCP",
            payload=b"", tcp_flags={"RST"}, pkt_size=40,
            timestamp=ts + timedelta(seconds=3),
        )

        assert len(collector.flows) == 1
        flow = collector.flows[0]
        assert flow.packet_count == 4
        assert flow.byte_count == 60 + 200 + 150 + 40

    def test_tcp_flags_accumulated(self) -> None:
        """All TCP flags seen across the flow are accumulated."""
        collector = FlowCollector()
        assembler = FlowAssembler(on_flow_complete=collector.on_flow)

        ts = _now()
        for flags in [{"SYN"}, {"ACK"}, {"PSH", "ACK"}, {"FIN", "ACK"}]:
            assembler.process_packet(
                src_ip="10.0.0.1", dst_ip="10.0.0.2",
                src_port=1004, dst_port=80, protocol="TCP",
                payload=b"", tcp_flags=flags, pkt_size=60, timestamp=ts,
            )
            ts += timedelta(milliseconds=100)
        assembler.process_packet(
            src_ip="10.0.0.2", dst_ip="10.0.0.1",
            src_port=80, dst_port=1004, protocol="TCP",
            payload=b"", tcp_flags={"FIN", "ACK"}, pkt_size=60,
            timestamp=ts,
        )

        assert len(collector.flows) == 1
        assert {"SYN", "ACK", "PSH", "FIN"} <= collector.flows[0].tcp_flags_seen

    def test_payload_sample_first_256_bytes(self) -> None:
        """Only the first 256 bytes of the first payload packet are captured."""
        collector = FlowCollector()
        assembler = FlowAssembler(on_flow_complete=collector.on_flow)

        big_payload = b"A" * 500
        ts = _now()
        assembler.process_packet(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=1005, dst_port=80, protocol="TCP",
            payload=big_payload, tcp_flags={"SYN"}, pkt_size=560, timestamp=ts,
        )
        assembler.process_packet(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=1005, dst_port=80, protocol="TCP",
            payload=b"B" * 300, tcp_flags={"RST"}, pkt_size=340,
            timestamp=ts + timedelta(seconds=1),
        )

        flow = collector.flows[0]
        assert flow.payload_sample == b"A" * 256  # Exactly 256 bytes

    def test_payload_sample_only_first_payload_packet(self) -> None:
        """Subsequent payloads don't overwrite the first sample."""
        collector = FlowCollector()
        assembler = FlowAssembler(on_flow_complete=collector.on_flow)

        ts = _now()
        assembler.process_packet(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=1006, dst_port=80, protocol="TCP",
            payload=b"FIRST", tcp_flags={"SYN"}, pkt_size=65, timestamp=ts,
        )
        assembler.process_packet(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=1006, dst_port=80, protocol="TCP",
            payload=b"SECOND", tcp_flags={"RST"}, pkt_size=46,
            timestamp=ts + timedelta(seconds=1),
        )

        flow = collector.flows[0]
        assert flow.payload_sample == b"FIRST"

    def test_bidirectional_packets_same_flow(self) -> None:
        """Packets from both directions belong to the same flow."""
        collector = FlowCollector()
        assembler = FlowAssembler(on_flow_complete=collector.on_flow)

        ts = _now()
        # Forward
        assembler.process_packet(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=2000, dst_port=80, protocol="TCP",
            payload=b"", tcp_flags={"SYN"}, pkt_size=60, timestamp=ts,
        )
        # Reverse (same 5-tuple but reversed)
        assembler.process_packet(
            src_ip="10.0.0.2", dst_ip="10.0.0.1",
            src_port=80, dst_port=2000, protocol="TCP",
            payload=b"", tcp_flags={"ACK"}, pkt_size=60,
            timestamp=ts + timedelta(milliseconds=50),
        )
        # RST to close
        assembler.process_packet(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=2000, dst_port=80, protocol="TCP",
            payload=b"", tcp_flags={"RST"}, pkt_size=40,
            timestamp=ts + timedelta(milliseconds=100),
        )

        # Should be exactly ONE flow, not two
        assert len(collector.flows) == 1
        assert collector.flows[0].packet_count == 3


# ---------------------------------------------------------------------------
# Timeout expiry tests (Section 10.1, 10.13)
# ---------------------------------------------------------------------------

class TestTimeoutExpiry:
    """Idle timeout and max duration expiry per Section 10.1."""

    def test_udp_idle_timeout_expires_flow(self) -> None:
        """UDP flow expires after idle timeout."""
        collector = FlowCollector()
        assembler = FlowAssembler(on_flow_complete=collector.on_flow)
        assembler._udp_idle = 1  # Override to 1s for test speed

        ts = _now()
        assembler.process_packet(
            src_ip="10.0.0.1", dst_ip="8.8.8.8",
            src_port=54000, dst_port=53, protocol="UDP",
            payload=b"\x00\x01", tcp_flags=None, pkt_size=42, timestamp=ts,
        )

        # Manually run sweep with a "now" 2s in the future
        future = ts + timedelta(seconds=2)
        with patch("agents.sniffer.flow_assembler.datetime") as mock_dt:
            mock_dt.now.return_value = future
            assembler._run_sweep()

        assert len(collector.flows) == 1
        assert collector.flows[0].state == FlowState.EXPIRED

    def test_tcp_idle_timeout_expires_flow(self) -> None:
        """TCP flow expires after idle timeout."""
        collector = FlowCollector()
        assembler = FlowAssembler(on_flow_complete=collector.on_flow)
        assembler._tcp_idle = 1  # Override to 1s for test speed

        ts = _now()
        assembler.process_packet(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=3000, dst_port=8080, protocol="TCP",
            payload=b"", tcp_flags={"SYN"}, pkt_size=60, timestamp=ts,
        )

        future = ts + timedelta(seconds=2)
        with patch("agents.sniffer.flow_assembler.datetime") as mock_dt:
            mock_dt.now.return_value = future
            assembler._run_sweep()

        assert len(collector.flows) == 1
        assert collector.flows[0].state == FlowState.EXPIRED

    def test_icmp_idle_timeout(self) -> None:
        """ICMP flow expires after 30s idle (configurable)."""
        collector = FlowCollector()
        assembler = FlowAssembler(on_flow_complete=collector.on_flow)
        assembler._icmp_idle = 1  # Override for speed

        ts = _now()
        assembler.process_packet(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=8, dst_port=0, protocol="ICMP",
            payload=b"", tcp_flags=None, pkt_size=64, timestamp=ts,
        )

        future = ts + timedelta(seconds=2)
        with patch("agents.sniffer.flow_assembler.datetime") as mock_dt:
            mock_dt.now.return_value = future
            assembler._run_sweep()

        assert len(collector.flows) == 1

    def test_tcp_max_duration_expires_flow(self) -> None:
        """TCP flow expires after max duration even if still active."""
        collector = FlowCollector()
        assembler = FlowAssembler(on_flow_complete=collector.on_flow)
        assembler._tcp_max = 5   # Override to 5s for test speed
        assembler._tcp_idle = 300  # High idle timeout — should NOT be the trigger

        ts = _now()
        assembler.process_packet(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=4000, dst_port=80, protocol="TCP",
            payload=b"", tcp_flags={"SYN"}, pkt_size=60, timestamp=ts,
        )

        # Simulate time passing beyond max duration
        # timestamp_last is recent (not idle), but flow is old
        with assembler._lock:
            flow = list(assembler._flows.values())[0]
            flow.timestamp_start = _now() - timedelta(seconds=6)
            # Keep timestamp_last recent to avoid idle timeout
            flow.timestamp_last = _now() - timedelta(seconds=1)

        assembler._run_sweep()

        assert len(collector.flows) == 1
        assert assembler.active_flow_count() == 0

    def test_expired_flow_removed_from_table(self) -> None:
        """After expiry, the flow is removed from the active flow table."""
        collector = FlowCollector()
        assembler = FlowAssembler(on_flow_complete=collector.on_flow)
        assembler._udp_idle = 1

        ts = _now()
        assembler.process_packet(
            src_ip="10.0.0.1", dst_ip="8.8.8.8",
            src_port=55000, dst_port=53, protocol="UDP",
            payload=b"\x00", tcp_flags=None, pkt_size=40, timestamp=ts,
        )
        assert assembler.active_flow_count() == 1

        future = ts + timedelta(seconds=2)
        with patch("agents.sniffer.flow_assembler.datetime") as mock_dt:
            mock_dt.now.return_value = future
            assembler._run_sweep()

        assert assembler.active_flow_count() == 0


# ---------------------------------------------------------------------------
# Interim emit tests (Section 10.1, 10.13)
# ---------------------------------------------------------------------------

class TestInterimEmit:
    """Long-lived flow interim emission per Section 10.1."""

    def test_interim_emit_preserves_flow_id(self) -> None:
        """
        An interim emit uses the same flow_id as the original flow
        (not a new UUID).
        """
        collector = FlowCollector()
        assembler = FlowAssembler(on_flow_complete=collector.on_flow)
        assembler._interim_interval = 1  # 1s for test speed
        assembler._tcp_idle = 300  # No expiry during test

        ts = _now()
        assembler.process_packet(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=5000, dst_port=80, protocol="TCP",
            payload=b"data", tcp_flags={"SYN"}, pkt_size=60, timestamp=ts,
        )

        original_flow_id = list(assembler._flows.values())[0].flow_id

        # Simulate time passing beyond interim interval
        future = ts + timedelta(seconds=2)
        with patch("agents.sniffer.flow_assembler.datetime") as mock_dt:
            mock_dt.now.return_value = future
            assembler._run_sweep()

        assert len(collector.flows) >= 1
        # The interim-emitted flow must have the same flow_id
        assert all(f.flow_id == original_flow_id for f in collector.flows)

    def test_interim_emit_does_not_remove_flow(self) -> None:
        """After interim emit, the flow remains in the table and keeps accumulating."""
        collector = FlowCollector()
        assembler = FlowAssembler(on_flow_complete=collector.on_flow)
        assembler._interim_interval = 1
        assembler._tcp_idle = 300

        ts = _now()
        assembler.process_packet(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=5001, dst_port=80, protocol="TCP",
            payload=b"", tcp_flags={"SYN"}, pkt_size=60, timestamp=ts,
        )

        future = ts + timedelta(seconds=2)
        with patch("agents.sniffer.flow_assembler.datetime") as mock_dt:
            mock_dt.now.return_value = future
            assembler._run_sweep()

        # Flow should still be in the table
        assert assembler.active_flow_count() == 1
        # One interim emit happened
        assert len(collector.flows) == 1

    def test_no_interim_emit_before_interval(self) -> None:
        """No interim emit fires if the interval hasn't elapsed."""
        collector = FlowCollector()
        assembler = FlowAssembler(on_flow_complete=collector.on_flow)
        assembler._interim_interval = 60  # Long interval
        assembler._tcp_idle = 300

        ts = _now()
        assembler.process_packet(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=5002, dst_port=80, protocol="TCP",
            payload=b"", tcp_flags={"SYN"}, pkt_size=60, timestamp=ts,
        )

        # Only 5 seconds passed — no interim emit
        future = ts + timedelta(seconds=5)
        with patch("agents.sniffer.flow_assembler.datetime") as mock_dt:
            mock_dt.now.return_value = future
            assembler._run_sweep()

        assert len(collector.flows) == 0  # No emit yet


# ---------------------------------------------------------------------------
# Utility function tests
# ---------------------------------------------------------------------------

class TestUtilityFunctions:
    """Tests for payload_to_b64 and flow_record_duration_ms."""

    def test_payload_to_b64_encodes_correctly(self) -> None:
        """Raw bytes are base64-encoded correctly."""
        import base64
        raw = b"GET / HTTP/1.1\r\n"
        result = payload_to_b64(raw)
        assert result is not None
        assert base64.b64decode(result) == raw

    def test_payload_to_b64_none_for_empty(self) -> None:
        """None is returned for empty or None input."""
        assert payload_to_b64(None) is None
        assert payload_to_b64(b"") is None

    def test_flow_duration_ms_zero_for_same_timestamps(self) -> None:
        """Duration is 0 when start == last."""
        ts = _now()
        flow = FlowRecord(
            flow_id="test", src_ip="1.1.1.1", dst_ip="2.2.2.2",
            src_port=80, dst_port=1234, protocol="TCP",
            timestamp_start=ts, timestamp_last=ts,
        )
        assert flow_record_duration_ms(flow) == 0

    def test_flow_duration_ms_correct(self) -> None:
        """Duration correctly reflects elapsed milliseconds."""
        start = _now()
        end = start + timedelta(milliseconds=1500)
        flow = FlowRecord(
            flow_id="test", src_ip="1.1.1.1", dst_ip="2.2.2.2",
            src_port=80, dst_port=1234, protocol="TCP",
            timestamp_start=start, timestamp_last=end,
        )
        assert flow_record_duration_ms(flow) == 1500
