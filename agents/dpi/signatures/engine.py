"""
SentinelMesh — DPI Agent: Signature Engine (Section 10.2)

Implements exactly 5 signature rules and 2 anomaly checks as specified.
All algorithms are canonical — no deviation from Section 10.2.

CRITICAL: The shared preprocessing and evaluation order are fixed:
  SQLI_PATTERN → MALICIOUS_USER_AGENT → PLAINTEXT_CRED_LEAK →
  SHELLCODE_NOPSLED → DNS_TUNNELING

Each check is independent; a flow can produce multiple findings.
"""

from __future__ import annotations

import logging
import math
import re
from typing import Iterator, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Signature port sets (Section 10.2)
# ---------------------------------------------------------------------------

SQLI_PORTS: frozenset = frozenset({80, 8080, 8000})
USER_AGENT_PORTS: frozenset = frozenset({80, 8080, 443})
SHELLCODE_PORTS: frozenset = frozenset()   # "any" — empty means all ports
DNS_PORTS: frozenset = frozenset({53})
CRED_PORTS: frozenset = frozenset({21, 23, 80, 110})

# Entropy anomaly: plaintext ports to check (Section 10.2)
ENTROPY_PLAINTEXT_PORTS: frozenset = frozenset({80, 21, 23, 25, 110})
# Known-encrypted ports: skip entropy check (Section 10.2)
ENTROPY_SKIP_PORTS: frozenset = frozenset({443, 22, 993, 995})

# ---------------------------------------------------------------------------
# Canonical regexes (Section 10.2 — verbatim)
# ---------------------------------------------------------------------------

SQLI_REGEX = re.compile(
    r"(\bunion\s+select\b)|('\s*or\s*'1'\s*=\s*'1)|(\bor\s+1\s*=\s*1\s*--)",
    re.IGNORECASE,
)

CRED_REGEX = re.compile(
    r"(\bpassword\s*=)|(\bpasswd\s*=)|(\bpwd\s*=)|(\bauthorization:\s*basic\b)",
    re.IGNORECASE,
)

# Protocol mismatch: HTTP verb present in first line (Section 10.2 anomaly)
HTTP_VERB_REGEX = re.compile(r"GET |POST |PUT |HEAD ")

# Malicious user-agent substrings in exact spec order (Section 10.2)
MALICIOUS_UA_SUBSTRINGS: List[str] = [
    "sqlmap",
    "nikto",
    "nmap scripting engine",
    "masscan",
    "nessus",
]

# Shellcode NOP-sled constant (Section 10.2 — must be exactly 16 bytes)
NOP_RUN: bytes = b"\x90" * 16


# ---------------------------------------------------------------------------
# Shared preprocessing (Section 10.2, step 1-3)
# ---------------------------------------------------------------------------

def preprocess_payload(payload_b64: Optional[str]) -> Optional[dict]:
    """
    Decode and classify the base64-encoded payload_sample.

    Returns a dict with:
        raw_bytes      (bytes)
        printable_ratio (float)
        text           (str | None — None if printable_ratio < 0.9)

    Returns None if payload_b64 is None or empty.
    """
    if not payload_b64:
        return None

    import base64
    try:
        raw_bytes = base64.b64decode(payload_b64)
    except Exception:
        logger.debug("Failed to base64-decode payload_sample")
        return None

    if not raw_bytes:
        return None

    # Printable byte count: 0x09 (HT), 0x0A (LF), 0x0D (CR), 0x20–0x7E
    printable_count = sum(
        1 for b in raw_bytes
        if b == 0x09 or b == 0x0A or b == 0x0D or (0x20 <= b <= 0x7E)
    )
    printable_ratio = printable_count / len(raw_bytes)

    text: Optional[str] = None
    if printable_ratio >= 0.9:
        text = raw_bytes.decode("utf-8", errors="ignore")

    return {
        "raw_bytes": raw_bytes,
        "printable_ratio": printable_ratio,
        "text": text,
    }


# ---------------------------------------------------------------------------
# Signature checks (Section 10.2, each as a standalone pure function)
# ---------------------------------------------------------------------------

def check_sqli_pattern(text: str) -> Optional[str]:
    """
    Section 10.2 — SQLI_PATTERN.
    Uses re.search (not re.match) with IGNORECASE.
    Returns matched substring or None.
    """
    match = SQLI_REGEX.search(text)
    if match:
        return match.group(0)
    return None


def check_malicious_user_agent(text: str) -> Optional[str]:
    """
    Section 10.2 — MALICIOUS_USER_AGENT.
    Deterministic extraction: split on \\r\\n (fallback \\n), find
    the User-Agent header line, check fixed substring list in order.
    Returns matching substring or None.
    """
    # Step 1: split on \\r\\n, fallback to \\n
    if "\r\n" in text:
        lines = text.split("\r\n")
    else:
        lines = text.split("\n")

    # Step 2: find first User-Agent header line
    ua_value: Optional[str] = None
    for line in lines:
        if re.match(r"^user-agent:\s*", line, re.IGNORECASE):
            # Remainder of line after "User-Agent: "
            colon_idx = line.index(":")
            ua_value = line[colon_idx + 1:].strip()
            break

    # Step 3: no header found → no match
    if ua_value is None:
        return None

    # Step 4: check canonical substring list in exact spec order
    ua_lower = ua_value.lower()
    for substring in MALICIOUS_UA_SUBSTRINGS:
        if substring in ua_lower:
            return substring

    return None


def check_plaintext_cred_leak(text: str) -> Optional[str]:
    """
    Section 10.2 — PLAINTEXT_CRED_LEAK.
    Uses re.search with IGNORECASE.
    Returns matched substring or None.
    """
    match = CRED_REGEX.search(text)
    if match:
        return match.group(0)
    return None


def check_shellcode_nopsled(raw_bytes: bytes) -> bool:
    """
    Section 10.2 — SHELLCODE_NOPSLED.
    Canonical single Python 'in' check on raw_bytes (not a loop).
    Returns True if 16 consecutive 0x90 bytes are present.
    """
    return NOP_RUN in raw_bytes


def check_dns_tunneling(raw_bytes: bytes) -> bool:
    """
    Section 10.2 — DNS_TUNNELING.
    Must use dnspython dns.message.from_wire (canonical, not hand-rolled).
    On any parse error → no match, log DEBUG.
    """
    try:
        import dns.message  # type: ignore

        msg = dns.message.from_wire(raw_bytes)
        qname = str(msg.question[0].name) if msg.question else ""
        labels = qname.strip(".").split(".")
        max_label_len = max((len(lbl) for lbl in labels), default=0)
        return max_label_len > 50 or len(qname) > 150
    except Exception as exc:
        logger.debug("DNS parse failed (not a match): %s", exc)
        return False


# ---------------------------------------------------------------------------
# Entropy anomaly check (Section 10.2)
# ---------------------------------------------------------------------------

def compute_shannon_entropy(raw_bytes: bytes) -> float:
    """
    Compute Shannon entropy H = -Σ p(x)·log2(p(x)) over byte histogram.
    Returns 0.0 for empty input.
    """
    if not raw_bytes:
        return 0.0

    length = len(raw_bytes)
    counts: dict = {}
    for byte in raw_bytes:
        counts[byte] = counts.get(byte, 0) + 1

    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)

    return entropy


def check_high_entropy(
    raw_bytes: bytes,
    port: int,
    entropy_threshold: float,
    min_sample_bytes: int,
) -> bool:
    """
    Section 10.2 — entropy anomaly.
    Returns True if entropy > threshold on a conventionally-plaintext port.
    Skips if sample < min_sample_bytes, or port is in ENTROPY_SKIP_PORTS.
    """
    if port in ENTROPY_SKIP_PORTS:
        return False
    if port not in ENTROPY_PLAINTEXT_PORTS:
        return False
    if len(raw_bytes) < min_sample_bytes:
        return False
    return compute_shannon_entropy(raw_bytes) > entropy_threshold


def check_protocol_mismatch_http(text: Optional[str], port: int) -> bool:
    """
    Section 10.2 — protocol mismatch anomaly.
    For port 80: payload should start with an HTTP verb.
    Returns True if it doesn't (potential mismatch).
    """
    if port != 80 or not text:
        return False
    first_line = text.split("\n", 1)[0]
    return not HTTP_VERB_REGEX.match(first_line)


# ---------------------------------------------------------------------------
# Port selection helper (Section 10.2, step 5)
# ---------------------------------------------------------------------------

def well_known_port(src_port: int, dst_port: int) -> int:
    """
    Return the well-known-side port for signature port matching.
    The well-known side is whichever port is ≤ 1023, or dst_port if both
    are above 1023 (since the client initiates to a service port).
    """
    if src_port <= 1023:
        return src_port
    return dst_port


# ---------------------------------------------------------------------------
# Finding result dataclass
# ---------------------------------------------------------------------------

from dataclasses import dataclass


@dataclass
class FindingResult:
    """
    A single DPI finding produced by the signature engine.
    Directly maps onto DPIFinding (Section 5.2) fields.
    """
    match_type: str           # "signature" | "anomaly"
    signature_name: Optional[str]  # None for anomaly findings
    anomaly_reason: Optional[str]  # None for signature findings
    severity: str             # "low" | "medium" | "high"
    raw_evidence: str


# ---------------------------------------------------------------------------
# Main evaluation pipeline (Section 10.2)
# ---------------------------------------------------------------------------

def evaluate_payload(
    payload_b64: Optional[str],
    src_port: int,
    dst_port: int,
    entropy_threshold: float = 7.2,
    min_sample_bytes: int = 64,
) -> List[FindingResult]:
    """
    Run all DPI checks against a flow's payload_sample.

    Args:
        payload_b64: Base64-encoded payload_sample from FlowEvent (Section 5.1).
        src_port: Source port of the flow.
        dst_port: Destination port of the flow.
        entropy_threshold: DPI_ENTROPY_THRESHOLD env var (default 7.2).
        min_sample_bytes: DPI_MIN_SAMPLE_BYTES env var (default 64).

    Returns:
        List of FindingResult objects (may be empty, may have multiple).
    """
    findings: List[FindingResult] = []

    if not payload_b64:
        return findings

    preprocessed = preprocess_payload(payload_b64)
    if not preprocessed:
        return findings

    raw_bytes: bytes = preprocessed["raw_bytes"]
    text: Optional[str] = preprocessed["text"]
    check_port = well_known_port(src_port, dst_port)

    # ---------------------------------------------------------------
    # Fixed evaluation order (Section 10.2 step 4):
    # SQLI_PATTERN → MALICIOUS_USER_AGENT → PLAINTEXT_CRED_LEAK →
    # SHELLCODE_NOPSLED → DNS_TUNNELING
    # ---------------------------------------------------------------

    # 1. SQLI_PATTERN — text-based, applicable ports: 80, 8080, 8000
    if text is not None and check_port in SQLI_PORTS:
        evidence = check_sqli_pattern(text)
        if evidence:
            findings.append(FindingResult(
                match_type="signature",
                signature_name="SQLI_PATTERN",
                anomaly_reason=None,
                severity="high",
                raw_evidence=f"SQLi match: {evidence!r}",
            ))

    # 2. MALICIOUS_USER_AGENT — text-based, applicable ports: 80, 8080, 443
    if text is not None and check_port in USER_AGENT_PORTS:
        evidence = check_malicious_user_agent(text)
        if evidence:
            findings.append(FindingResult(
                match_type="signature",
                signature_name="MALICIOUS_USER_AGENT",
                anomaly_reason=None,
                severity="medium",
                raw_evidence=f"Malicious User-Agent detected: {evidence!r}",
            ))

    # 3. PLAINTEXT_CRED_LEAK — text-based, applicable ports: 21, 23, 80, 110
    if text is not None and check_port in CRED_PORTS:
        evidence = check_plaintext_cred_leak(text)
        if evidence:
            findings.append(FindingResult(
                match_type="signature",
                signature_name="PLAINTEXT_CRED_LEAK",
                anomaly_reason=None,
                severity="high",
                raw_evidence=f"Plaintext credential pattern: {evidence!r}",
            ))

    # 4. SHELLCODE_NOPSLED — raw bytes, any port
    if check_shellcode_nopsled(raw_bytes):
        findings.append(FindingResult(
            match_type="signature",
            signature_name="SHELLCODE_NOPSLED",
            anomaly_reason=None,
            severity="high",
            raw_evidence="16+ consecutive NOP bytes (0x90) detected in payload",
        ))

    # 5. DNS_TUNNELING — raw bytes, port 53 only
    if check_port in DNS_PORTS:
        if check_dns_tunneling(raw_bytes):
            findings.append(FindingResult(
                match_type="signature",
                signature_name="DNS_TUNNELING",
                anomaly_reason=None,
                severity="medium",
                raw_evidence="DNS query label > 50 chars or total qname > 150 chars",
            ))

    # ---------------------------------------------------------------
    # Anomaly checks (after all signatures)
    # ---------------------------------------------------------------

    # High entropy on plaintext port
    if check_high_entropy(raw_bytes, check_port, entropy_threshold, min_sample_bytes):
        h = compute_shannon_entropy(raw_bytes)
        findings.append(FindingResult(
            match_type="anomaly",
            signature_name=None,
            anomaly_reason="high payload entropy for plaintext port",
            severity="medium",
            raw_evidence=f"Shannon entropy={h:.4f} > {entropy_threshold} on port {check_port}",
        ))

    # Protocol mismatch on port 80
    if check_protocol_mismatch_http(text, check_port):
        findings.append(FindingResult(
            match_type="anomaly",
            signature_name=None,
            anomaly_reason="protocol mismatch on declared port",
            severity="medium",
            raw_evidence=f"Payload on port 80 does not begin with HTTP verb",
        ))

    return findings
