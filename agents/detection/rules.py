"""
SentinelMesh — Detection Agent: Rule Engine (rules.py)

Implements the five detection rules from Section 10.3, evaluated in priority
order. The highest-priority match wins; ties are broken by higher confidence.

Priority table (Section 10.3):
  1. DPI high-severity match    → malicious / 0.90 / exploit_attempt
  1. SYN flood                  → malicious / 0.85 / syn_flood          (Redis)
  2. Port scan                  → suspicious / 0.70 / port_scan         (Redis)
  3. DPI medium-severity match  → suspicious / 0.60 / suspicious_payload
  4. Possible exfiltration      → suspicious / 0.50 / possible_exfiltration
  5. Default (no rule matched)  → benign    / 0.95 / null

Redis keys (Section 10.5):
  det:portscan:{src_ip}              Set of dst_ports, TTL 10s
  det:synflood:{dst_ip}:{dst_port}   Counter, TTL 5s

Graceful degradation (Section 10.12): if Redis is unavailable, rules 2
(SYN flood) and 3 (port scan) are skipped; only per-event rules fire.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import List, Optional

from shared.schemas import Classification, DPIFinding, FlowEvent, Severity

logger = logging.getLogger("detection.rules")

# ---------------------------------------------------------------------------
# Config (from env, matching Section 10.11)
# ---------------------------------------------------------------------------

DETECTION_PORTSCAN_DISTINCT_PORTS: int = int(os.getenv("DETECTION_PORTSCAN_DISTINCT_PORTS", "15"))
DETECTION_PORTSCAN_WINDOW_S: int = int(os.getenv("DETECTION_PORTSCAN_WINDOW_S", "10"))
DETECTION_SYNFLOOD_THRESHOLD: int = int(os.getenv("DETECTION_SYNFLOOD_THRESHOLD", "100"))
DETECTION_SYNFLOOD_WINDOW_S: int = int(os.getenv("DETECTION_SYNFLOOD_WINDOW_S", "5"))
DETECTION_EXFIL_BYTES_THRESHOLD: int = int(os.getenv("DETECTION_EXFIL_BYTES_THRESHOLD", "52428800"))

# Ports considered "internal" or RFC 1918 — used to identify external IPs.
_RFC1918_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                     "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                     "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                     "172.30.", "172.31.", "192.168.", "127.", "::1")

# Standard ports — exfil rule only fires on *non-standard* ports.
_STANDARD_PORTS = frozenset({80, 443, 8080, 8443, 21, 22, 25, 110, 143, 993, 995, 53})


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class RuleResult:
    """Outcome of evaluating the rule engine against one flow event."""
    classification: str
    confidence: float
    attack_type: Optional[str]
    contributing_findings: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_syn_only(flow: FlowEvent) -> bool:
    """Return True if the flow's TCP flags are SYN-only (no ACK, FIN, RST)."""
    flags = {f.upper() for f in flow.tcp_flags_seen}
    return "SYN" in flags and flags.isdisjoint({"ACK", "FIN", "RST"})


def _is_external_ip(ip: str) -> bool:
    """Return True if the IP address is NOT an RFC 1918 / loopback address."""
    return not any(ip.startswith(prefix) for prefix in _RFC1918_PREFIXES)


# ---------------------------------------------------------------------------
# Rule engine
# ---------------------------------------------------------------------------

def evaluate(
    flow: FlowEvent,
    dpi_findings: List[DPIFinding],
    redis_client,  # Optional[redis.Redis] — typed as Any to avoid hard dep
) -> RuleResult:
    """
    Evaluate all detection rules against a single FlowEvent + its DPI findings.

    Rules are evaluated in priority order (1 = highest). The first rule that
    matches determines the final classification. Priority-1 rules are both
    evaluated; if both fire the one with higher confidence wins (SYN flood at
    0.85 loses to DPI-high at 0.90 — but the logic below handles ties cleanly
    by simply checking both and keeping the max-confidence result).

    Args:
        flow:          The assembled FlowEvent to classify.
        dpi_findings:  All DPI findings already cached for this flow_id.
        redis_client:  Live redis.Redis client, or None if Redis is unavailable.

    Returns:
        A RuleResult with classification, confidence, attack_type, and any
        contributing finding IDs.
    """
    redis_ok = redis_client is not None

    # -- Priority 1a: DPI high-severity match --------------------------------
    high_findings = [f for f in dpi_findings if f.severity == Severity.HIGH or
                     f.severity == Severity.HIGH.value]
    if high_findings:
        logger.info(
            "Rule matched: DPI high-severity",
            extra={"flow_id": flow.flow_id,
                   "finding_ids": [f.finding_id for f in high_findings]},
        )
        return RuleResult(
            classification=Classification.MALICIOUS.value,
            confidence=0.90,
            attack_type="exploit_attempt",
            contributing_findings=[f.finding_id for f in high_findings],
        )

    # -- Priority 1b: SYN flood (Redis-backed) --------------------------------
    if redis_ok and _is_syn_only(flow) and flow.protocol == "TCP":
        flood_key = f"det:synflood:{flow.dst_ip}:{flow.dst_port}"
        try:
            count = redis_client.incr(flood_key)
            redis_client.expire(flood_key, DETECTION_SYNFLOOD_WINDOW_S)
            if count > DETECTION_SYNFLOOD_THRESHOLD:
                logger.info(
                    "Rule matched: SYN flood",
                    extra={"flow_id": flow.flow_id, "count": count,
                           "dst_ip": flow.dst_ip, "dst_port": flow.dst_port},
                )
                return RuleResult(
                    classification=Classification.MALICIOUS.value,
                    confidence=0.85,
                    attack_type="syn_flood",
                )
        except Exception:
            logger.warning("Redis error checking SYN flood counter — skipping rule",
                           extra={"flow_id": flow.flow_id}, exc_info=True)

    # -- Priority 2: Port scan (Redis-backed) ---------------------------------
    if redis_ok:
        scan_key = f"det:portscan:{flow.src_ip}"
        try:
            redis_client.sadd(scan_key, flow.dst_port)
            redis_client.expire(scan_key, DETECTION_PORTSCAN_WINDOW_S)
            distinct_ports = redis_client.scard(scan_key)
            if distinct_ports >= DETECTION_PORTSCAN_DISTINCT_PORTS:
                logger.info(
                    "Rule matched: port scan",
                    extra={"flow_id": flow.flow_id,
                           "src_ip": flow.src_ip,
                           "distinct_ports": distinct_ports},
                )
                return RuleResult(
                    classification=Classification.SUSPICIOUS.value,
                    confidence=0.70,
                    attack_type="port_scan",
                )
        except Exception:
            logger.warning("Redis error checking port scan set — skipping rule",
                           extra={"flow_id": flow.flow_id}, exc_info=True)

    # -- Priority 3: DPI medium-severity match (alone) -------------------------
    medium_findings = [f for f in dpi_findings if f.severity == Severity.MEDIUM or
                       f.severity == Severity.MEDIUM.value]
    if medium_findings:
        logger.info(
            "Rule matched: DPI medium-severity",
            extra={"flow_id": flow.flow_id,
                   "finding_ids": [f.finding_id for f in medium_findings]},
        )
        return RuleResult(
            classification=Classification.SUSPICIOUS.value,
            confidence=0.60,
            attack_type="suspicious_payload",
            contributing_findings=[f.finding_id for f in medium_findings],
        )

    # -- Priority 4: Possible exfiltration ------------------------------------
    if (
        flow.byte_count > DETECTION_EXFIL_BYTES_THRESHOLD
        and _is_external_ip(flow.dst_ip)
        and flow.dst_port not in _STANDARD_PORTS
    ):
        logger.info(
            "Rule matched: possible exfiltration",
            extra={"flow_id": flow.flow_id,
                   "byte_count": flow.byte_count,
                   "dst_ip": flow.dst_ip,
                   "dst_port": flow.dst_port},
        )
        return RuleResult(
            classification=Classification.SUSPICIOUS.value,
            confidence=0.50,
            attack_type="possible_exfiltration",
        )

    # -- Priority 5: Default — benign -----------------------------------------
    return RuleResult(
        classification=Classification.BENIGN.value,
        confidence=0.95,
        attack_type=None,
    )
