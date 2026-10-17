"""
SentinelMesh — Unit Tests for DPI Agent (Section 10.13)

Per Section 10.13:
  - Each of the 5 signatures tested against both a known-positive
    and a known-negative payload sample
  - Entropy calculation verified against payloads with known,
    hand-computed entropy values
  - Preprocessing (printable_ratio, binary skip logic) tested
  - Evaluation order verified
  - Port filtering verified per Section 10.2 port tables
"""

from __future__ import annotations

import base64
import math
from typing import Optional

import pytest

from agents.dpi.signatures.engine import (
    MALICIOUS_UA_SUBSTRINGS,
    NOP_RUN,
    FindingResult,
    check_dns_tunneling,
    check_high_entropy,
    check_malicious_user_agent,
    check_plaintext_cred_leak,
    check_shellcode_nopsled,
    check_sqli_pattern,
    compute_shannon_entropy,
    evaluate_payload,
    preprocess_payload,
    well_known_port,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _b64(data: bytes) -> str:
    """Base64-encode bytes for use as payload_sample."""
    return base64.b64encode(data).decode("ascii")


def _b64str(s: str) -> str:
    """Base64-encode a string (UTF-8) for use as payload_sample."""
    return _b64(s.encode("utf-8"))


# ---------------------------------------------------------------------------
# Preprocessing tests (Section 10.2, steps 1–3)
# ---------------------------------------------------------------------------

class TestPreprocessPayload:
    """Shared preprocessing tests."""

    def test_printable_text_decoded(self) -> None:
        """Pure ASCII text → printable_ratio == 1.0, text is populated."""
        payload = _b64str("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        result = preprocess_payload(payload)
        assert result is not None
        assert result["printable_ratio"] == 1.0
        assert result["text"] is not None
        assert "GET" in result["text"]

    def test_binary_payload_no_text(self) -> None:
        """Binary payload → printable_ratio < 0.9, text is None."""
        binary = bytes(range(0, 256))  # all byte values including non-printable
        payload = _b64(binary)
        result = preprocess_payload(payload)
        assert result is not None
        assert result["printable_ratio"] < 0.9
        assert result["text"] is None

    def test_none_payload_returns_none(self) -> None:
        """None payload_sample returns None."""
        assert preprocess_payload(None) is None

    def test_empty_string_payload_returns_none(self) -> None:
        """Empty string payload_sample returns None."""
        assert preprocess_payload("") is None

    def test_printable_ratio_boundary(self) -> None:
        """Exactly 90% printable → text is populated (≥ 0.9 threshold)."""
        # 9 printable + 1 non-printable = exactly 0.9
        data = b"AAAAAAAAA\x00"  # 9 printable (A) + 1 null
        payload = _b64(data)
        result = preprocess_payload(payload)
        assert result is not None
        assert abs(result["printable_ratio"] - 0.9) < 1e-9
        assert result["text"] is not None  # >= 0.9 qualifies

    def test_below_printable_ratio_no_text(self) -> None:
        """89% printable → text is None."""
        data = b"AAAAAAAA\x00\x01"  # 8 printable, 2 non-printable = 0.8
        payload = _b64(data)
        result = preprocess_payload(payload)
        assert result is not None
        assert result["printable_ratio"] == 0.8
        assert result["text"] is None


# ---------------------------------------------------------------------------
# SQLI_PATTERN tests (Section 10.2, known-positive + known-negative)
# ---------------------------------------------------------------------------

class TestSQLIPattern:
    """SQLI_PATTERN signature — canonical regex tests."""

    def test_positive_union_select(self) -> None:
        """Known positive: UNION SELECT (case-insensitive)."""
        assert check_sqli_pattern("GET /?id=1 UNION SELECT * FROM users") is not None
        assert check_sqli_pattern("GET /?id=1 union select * from users") is not None

    def test_positive_or_1_equals_1(self) -> None:
        """Known positive: OR 1=1 --"""
        assert check_sqli_pattern("admin' OR 1=1 --") is not None

    def test_positive_or_quoted_equality(self) -> None:
        """Known positive: ' OR '1'='1"""
        assert check_sqli_pattern("' or '1'='1") is not None

    def test_negative_normal_http_request(self) -> None:
        """Known negative: ordinary HTTP GET."""
        assert check_sqli_pattern("GET /index.html HTTP/1.1\r\nHost: example.com") is None

    def test_negative_select_without_union(self) -> None:
        """SELECT alone does not match — must have UNION SELECT."""
        assert check_sqli_pattern("I need to select a color") is None

    def test_evidence_is_matched_substring(self) -> None:
        """raw_evidence should be the matched substring, not full payload."""
        text = "GET /?q=1 UNION SELECT password FROM users"
        result = check_sqli_pattern(text)
        assert result is not None
        assert len(result) < len(text)
        assert "union" in result.lower()

    def test_port_filtering_sqli_not_on_dns_port(self) -> None:
        """SQLI check does not run for port 53 — no finding emitted."""
        sqli_payload = _b64str("GET /?id=1 UNION SELECT * FROM users")
        findings = evaluate_payload(sqli_payload, src_port=12345, dst_port=53)
        sig_names = [f.signature_name for f in findings]
        assert "SQLI_PATTERN" not in sig_names

    def test_port_filtering_sqli_runs_on_port_80(self) -> None:
        """SQLI check runs for port 80."""
        sqli_payload = _b64str("GET /?id=1 UNION SELECT * FROM users HTTP/1.1\r\n")
        findings = evaluate_payload(sqli_payload, src_port=12345, dst_port=80)
        sig_names = [f.signature_name for f in findings]
        assert "SQLI_PATTERN" in sig_names

    def test_sqli_severity_is_high(self) -> None:
        """SQLI finding must have severity=high per Section 10.2."""
        sqli_payload = _b64str("GET /?id=1 UNION SELECT * FROM users HTTP/1.1\r\n")
        findings = evaluate_payload(sqli_payload, src_port=12345, dst_port=80)
        sqli_findings = [f for f in findings if f.signature_name == "SQLI_PATTERN"]
        assert sqli_findings
        assert sqli_findings[0].severity == "high"


# ---------------------------------------------------------------------------
# MALICIOUS_USER_AGENT tests (Section 10.2)
# ---------------------------------------------------------------------------

class TestMaliciousUserAgent:
    """MALICIOUS_USER_AGENT signature tests."""

    def test_positive_sqlmap(self) -> None:
        """Known positive: sqlmap User-Agent."""
        text = "GET / HTTP/1.1\r\nHost: victim.com\r\nUser-Agent: sqlmap/1.7.2\r\n\r\n"
        assert check_malicious_user_agent(text) == "sqlmap"

    def test_positive_nikto(self) -> None:
        """Known positive: Nikto scanner."""
        text = "GET / HTTP/1.1\r\nUser-Agent: Nikto/2.1.6\r\n"
        result = check_malicious_user_agent(text)
        assert result == "nikto"

    def test_positive_nmap_scripting_engine(self) -> None:
        """Known positive: Nmap Scripting Engine."""
        text = "GET / HTTP/1.1\r\nUser-Agent: Mozilla/5.0 (compatible; Nmap Scripting Engine)\r\n"
        result = check_malicious_user_agent(text)
        assert result == "nmap scripting engine"

    def test_positive_masscan(self) -> None:
        """Known positive: masscan."""
        text = "GET / HTTP/1.1\r\nUser-Agent: masscan/1.0\r\n"
        assert check_malicious_user_agent(text) == "masscan"

    def test_positive_nessus(self) -> None:
        """Known positive: Nessus scanner."""
        text = "GET / HTTP/1.1\r\nUser-Agent: Nessus XMLRPC\r\n"
        assert check_malicious_user_agent(text) == "nessus"

    def test_negative_normal_browser(self) -> None:
        """Known negative: Chrome user-agent."""
        text = (
            "GET / HTTP/1.1\r\n"
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\n"
        )
        assert check_malicious_user_agent(text) is None

    def test_negative_no_user_agent_header(self) -> None:
        """No User-Agent header → no match (must not scan whole payload)."""
        text = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        assert check_malicious_user_agent(text) is None

    def test_fallback_to_newline_split(self) -> None:
        """Fallback to \\n splitting when no \\r\\n present."""
        text = "GET / HTTP/1.1\nUser-Agent: sqlmap/1.7\n"
        result = check_malicious_user_agent(text)
        assert result == "sqlmap"

    def test_case_insensitive_header_match(self) -> None:
        """Header matching is case-insensitive."""
        text = "GET / HTTP/1.1\r\nUSER-AGENT: sqlmap/1.7\r\n"
        result = check_malicious_user_agent(text)
        assert result == "sqlmap"

    def test_severity_is_medium(self) -> None:
        """MALICIOUS_USER_AGENT severity is medium per Section 10.2."""
        payload = _b64str("GET / HTTP/1.1\r\nUser-Agent: sqlmap/1.7\r\n\r\n")
        findings = evaluate_payload(payload, src_port=12345, dst_port=80)
        ua_findings = [f for f in findings if f.signature_name == "MALICIOUS_USER_AGENT"]
        assert ua_findings
        assert ua_findings[0].severity == "medium"


# ---------------------------------------------------------------------------
# SHELLCODE_NOPSLED tests (Section 10.2)
# ---------------------------------------------------------------------------

class TestShellcodeNopSled:
    """SHELLCODE_NOPSLED canonical byte check tests."""

    def test_positive_16_consecutive_nops(self) -> None:
        """Known positive: exactly 16 0x90 bytes."""
        assert check_shellcode_nopsled(b"\x90" * 16) is True

    def test_positive_nops_in_larger_payload(self) -> None:
        """Known positive: NOP sled embedded in larger payload."""
        payload = b"\x00\x01\x02" + b"\x90" * 20 + b"\xcc\xcd"
        assert check_shellcode_nopsled(payload) is True

    def test_negative_only_15_nops(self) -> None:
        """Known negative: only 15 consecutive 0x90 bytes (below threshold)."""
        assert check_shellcode_nopsled(b"\x90" * 15) is False

    def test_negative_non_consecutive_nops(self) -> None:
        """Known negative: 0x90 bytes separated by other bytes."""
        payload = b"\x90\x00" * 16  # alternating — never 16 consecutive
        assert check_shellcode_nopsled(payload) is False

    def test_negative_plain_text(self) -> None:
        """Known negative: normal HTTP payload."""
        assert check_shellcode_nopsled(b"GET / HTTP/1.1\r\nHost: example.com\r\n") is False

    def test_runs_on_binary_payload_regardless_of_printable_ratio(self) -> None:
        """SHELLCODE_NOPSLED runs even when printable_ratio < 0.9 (binary payload)."""
        # Binary payload with NOP sled
        binary = bytes(range(0, 128)) + b"\x90" * 16
        payload = _b64(binary)
        findings = evaluate_payload(payload, src_port=12345, dst_port=443)
        # Should find shellcode even on encrypted port (any port)
        shellcode_findings = [f for f in findings if f.signature_name == "SHELLCODE_NOPSLED"]
        assert shellcode_findings

    def test_severity_is_high(self) -> None:
        """SHELLCODE_NOPSLED severity is high per Section 10.2."""
        payload = _b64(b"A" * 10 + b"\x90" * 16 + b"B" * 10)
        findings = evaluate_payload(payload, src_port=12345, dst_port=9999)
        sc_findings = [f for f in findings if f.signature_name == "SHELLCODE_NOPSLED"]
        assert sc_findings
        assert sc_findings[0].severity == "high"


# ---------------------------------------------------------------------------
# DNS_TUNNELING tests (Section 10.2 — requires dnspython)
# ---------------------------------------------------------------------------

class TestDNSTunneling:
    """DNS_TUNNELING canonical dnspython parse tests."""

    def _build_dns_query(self, qname: str) -> bytes:
        """Build a minimal DNS query wire-format message for the given qname."""
        try:
            import dns.message
            import dns.name
            import dns.rdatatype
            import dns.query

            msg = dns.message.make_query(qname, dns.rdatatype.A)
            return msg.to_wire()
        except Exception:
            pytest.skip("dnspython not available")

    def test_positive_long_label(self) -> None:
        """Known positive: single label > 50 characters."""
        long_label = "A" * 51 + ".example.com"
        raw = self._build_dns_query(long_label)
        assert check_dns_tunneling(raw) is True

    def test_positive_long_qname(self) -> None:
        """Known positive: total qname > 150 characters."""
        # Each label is 35 chars; 5 labels = 175 chars + dots > 150
        label = "a" * 35
        qname = f"{label}.{label}.{label}.{label}.{label}.com"
        assert len(qname) > 150, f"Test fixture qname too short: {len(qname)}"
        raw = self._build_dns_query(qname)
        assert check_dns_tunneling(raw) is True

    def test_negative_normal_dns_query(self) -> None:
        """Known negative: ordinary A record query."""
        raw = self._build_dns_query("www.google.com")
        assert check_dns_tunneling(raw) is False

    def test_malformed_packet_no_crash(self) -> None:
        """Malformed DNS data → no match, no crash."""
        assert check_dns_tunneling(b"\x00\x01\x02\x03") is False

    def test_empty_bytes_no_crash(self) -> None:
        """Empty payload → no match, no crash."""
        assert check_dns_tunneling(b"") is False

    def test_port_filtering_dns_only_on_port_53(self) -> None:
        """DNS tunneling check only runs on port 53."""
        long_label = "B" * 51 + ".evil.com"
        raw = self._build_dns_query(long_label)
        payload = _b64(raw)
        # Port 80 — DNS check should NOT run
        findings_80 = evaluate_payload(payload, src_port=12345, dst_port=80)
        dns_80 = [f for f in findings_80 if f.signature_name == "DNS_TUNNELING"]
        assert not dns_80

        # Port 53 — DNS check SHOULD run
        findings_53 = evaluate_payload(payload, src_port=12345, dst_port=53)
        dns_53 = [f for f in findings_53 if f.signature_name == "DNS_TUNNELING"]
        assert dns_53

    def test_severity_is_medium(self) -> None:
        """DNS_TUNNELING severity is medium per Section 10.2."""
        long_label = "C" * 51 + ".tunnel.net"
        raw = self._build_dns_query(long_label)
        payload = _b64(raw)
        findings = evaluate_payload(payload, src_port=12345, dst_port=53)
        dns_findings = [f for f in findings if f.signature_name == "DNS_TUNNELING"]
        assert dns_findings
        assert dns_findings[0].severity == "medium"


# ---------------------------------------------------------------------------
# PLAINTEXT_CRED_LEAK tests (Section 10.2)
# ---------------------------------------------------------------------------

class TestPlaintextCredLeak:
    """PLAINTEXT_CRED_LEAK signature tests."""

    def test_positive_password_equals(self) -> None:
        """Known positive: password= in FTP payload."""
        assert check_plaintext_cred_leak("USER admin\r\nPASS password=letmein") is not None

    def test_positive_passwd_equals(self) -> None:
        """Known positive: passwd= variant."""
        assert check_plaintext_cred_leak("passwd=secret123") is not None

    def test_positive_pwd_equals(self) -> None:
        """Known positive: pwd= variant."""
        assert check_plaintext_cred_leak("pwd=abc123") is not None

    def test_positive_authorization_basic(self) -> None:
        """Known positive: Authorization: Basic header."""
        assert check_plaintext_cred_leak(
            "GET /private HTTP/1.1\r\nAuthorization: Basic dXNlcjpwYXNz\r\n"
        ) is not None

    def test_negative_no_credentials(self) -> None:
        """Known negative: normal HTTP traffic without credentials."""
        assert check_plaintext_cred_leak(
            "GET / HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n"
        ) is None

    def test_negative_unrelated_equals(self) -> None:
        """Known negative: = sign in unrelated context."""
        assert check_plaintext_cred_leak("Content-Type: application/x-www-form-urlencoded") is None

    def test_port_filtering_cred_on_port_21(self) -> None:
        """PLAINTEXT_CRED_LEAK runs on FTP port 21."""
        payload = _b64str("USER admin\r\npassword=letmein\r\n")
        findings = evaluate_payload(payload, src_port=12345, dst_port=21)
        cred = [f for f in findings if f.signature_name == "PLAINTEXT_CRED_LEAK"]
        assert cred

    def test_port_filtering_cred_not_on_port_443(self) -> None:
        """PLAINTEXT_CRED_LEAK does NOT run on HTTPS port 443."""
        payload = _b64str("password=letmein")
        findings = evaluate_payload(payload, src_port=12345, dst_port=443)
        cred = [f for f in findings if f.signature_name == "PLAINTEXT_CRED_LEAK"]
        assert not cred

    def test_severity_is_high(self) -> None:
        """PLAINTEXT_CRED_LEAK severity is high per Section 10.2."""
        payload = _b64str("GET / HTTP/1.1\r\npassword=test\r\n")
        findings = evaluate_payload(payload, src_port=12345, dst_port=80)
        cred = [f for f in findings if f.signature_name == "PLAINTEXT_CRED_LEAK"]
        assert cred
        assert cred[0].severity == "high"


# ---------------------------------------------------------------------------
# Shannon entropy tests (Section 10.2, Section 10.13: hand-computed values)
# ---------------------------------------------------------------------------

class TestShannonEntropy:
    """Entropy calculation verified against hand-computed values per §10.13."""

    def test_uniform_byte_distribution_max_entropy(self) -> None:
        """
        256 distinct bytes each appearing once → H = log2(256) = 8.0 bits/byte.
        Hand-computed: p(x) = 1/256 for all x, H = -256 * (1/256 * log2(1/256)) = 8.0
        """
        data = bytes(range(256))
        h = compute_shannon_entropy(data)
        assert abs(h - 8.0) < 1e-10

    def test_single_byte_value_zero_entropy(self) -> None:
        """
        All bytes identical → H = 0.0 bits/byte.
        Hand-computed: p(0x41) = 1.0, H = -(1.0 * log2(1.0)) = 0.0
        """
        data = b"A" * 100
        h = compute_shannon_entropy(data)
        assert h == 0.0

    def test_two_equal_probability_bytes(self) -> None:
        """
        Two byte values with equal probability → H = 1.0 bits/byte.
        Hand-computed: p(A) = 0.5, p(B) = 0.5
        H = -(0.5*log2(0.5) + 0.5*log2(0.5)) = -(-0.5 - 0.5) = 1.0
        """
        data = b"AB" * 50
        h = compute_shannon_entropy(data)
        assert abs(h - 1.0) < 1e-10

    def test_empty_returns_zero(self) -> None:
        """Empty input returns 0.0."""
        assert compute_shannon_entropy(b"") == 0.0

    def test_plaintext_http_low_entropy(self) -> None:
        """Normal HTTP text has low entropy (well below 7.2 threshold)."""
        data = b"GET / HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n" * 5
        h = compute_shannon_entropy(data)
        assert h < 5.0  # Realistic plaintext entropy

    def test_high_entropy_triggers_on_plaintext_port(self) -> None:
        """Uniform byte distribution (H=8.0) triggers anomaly on plaintext port 80."""
        data = bytes(range(256))  # H = 8.0
        assert check_high_entropy(data, port=80, entropy_threshold=7.2, min_sample_bytes=64)

    def test_high_entropy_skipped_on_encrypted_port(self) -> None:
        """High entropy is NOT flagged on port 443 (TLS is expected to be high entropy)."""
        data = bytes(range(256))  # H = 8.0
        assert not check_high_entropy(data, port=443, entropy_threshold=7.2, min_sample_bytes=64)

    def test_high_entropy_skipped_on_port_22(self) -> None:
        """High entropy is NOT flagged on port 22 (SSH)."""
        data = bytes(range(256))
        assert not check_high_entropy(data, port=22, entropy_threshold=7.2, min_sample_bytes=64)

    def test_below_min_sample_bytes_skipped(self) -> None:
        """Sample below DPI_MIN_SAMPLE_BYTES (64) is skipped regardless of entropy."""
        data = bytes(range(63))  # 63 bytes, H > 7.2 but below minimum
        assert not check_high_entropy(data, port=80, entropy_threshold=7.2, min_sample_bytes=64)

    def test_entropy_just_below_threshold_no_match(self) -> None:
        """Entropy just below 7.2 does not trigger."""
        # 4 equal-probability bytes → H = 2.0 (well below)
        data = (b"ABCD" * 20)
        assert not check_high_entropy(data, port=80, entropy_threshold=7.2, min_sample_bytes=64)

    def test_entropy_anomaly_in_evaluate_payload(self) -> None:
        """Full evaluate_payload emits entropy anomaly for high-entropy plaintext payload."""
        data = bytes(range(256))  # H = 8.0, uniform distribution
        payload = _b64(data)
        findings = evaluate_payload(payload, src_port=12345, dst_port=80,
                                    entropy_threshold=7.2, min_sample_bytes=64)
        entropy_findings = [f for f in findings if f.anomaly_reason == "high payload entropy for plaintext port"]
        assert entropy_findings
        assert entropy_findings[0].match_type == "anomaly"
        assert entropy_findings[0].severity == "medium"


# ---------------------------------------------------------------------------
# Evaluation order tests (Section 10.2, step 4)
# ---------------------------------------------------------------------------

class TestEvaluationOrder:
    """Verify fixed evaluation order: SQLI → UA → CRED → SHELLCODE → DNS."""

    def test_multiple_findings_in_correct_order(self) -> None:
        """
        A payload matching both SQLI and PLAINTEXT_CRED_LEAK on port 80
        should have SQLI finding before CRED finding in the results list.
        """
        # Payload with both SQLi and credential leak
        text = "GET /?id=1 UNION SELECT * FROM users HTTP/1.1\r\npassword=letmein\r\n"
        payload = _b64str(text)
        findings = evaluate_payload(payload, src_port=12345, dst_port=80)
        sig_names = [f.signature_name for f in findings if f.signature_name]
        # Both should be present
        assert "SQLI_PATTERN" in sig_names
        assert "PLAINTEXT_CRED_LEAK" in sig_names
        # SQLI must appear before CRED
        assert sig_names.index("SQLI_PATTERN") < sig_names.index("PLAINTEXT_CRED_LEAK")

    def test_all_5_signatures_independent(self) -> None:
        """
        A flow can produce findings for multiple signatures independently.
        Each match emits its own separate DPI finding.

        Text-based signatures only run on printable payloads (ratio >= 0.9).
        Byte-level signatures (SHELLCODE_NOPSLED) run on any payload.
        This test uses two separate payloads to demonstrate independence.
        """
        # Test 1: printable payload matching SQLI + User-Agent + Cred on port 80
        text = (
            "GET /?id=1 UNION SELECT 1 HTTP/1.1\r\n"
            "User-Agent: sqlmap/1.7\r\n"
            "password=admin\r\n\r\n"
        )
        text_payload = _b64str(text)
        text_findings = evaluate_payload(text_payload, src_port=12345, dst_port=80)
        text_sigs = set(f.signature_name for f in text_findings if f.signature_name)
        assert "SQLI_PATTERN" in text_sigs
        assert "MALICIOUS_USER_AGENT" in text_sigs
        assert "PLAINTEXT_CRED_LEAK" in text_sigs

        # Test 2: payload with NOP sled (any port) — shellcode is independent
        shellcode_payload = _b64(b"A" * 50 + b"\x90" * 16 + b"B" * 50)
        sc_findings = evaluate_payload(shellcode_payload, src_port=12345, dst_port=9999)
        sc_sigs = set(f.signature_name for f in sc_findings if f.signature_name)
        assert "SHELLCODE_NOPSLED" in sc_sigs


# ---------------------------------------------------------------------------
# Binary payload — text-based checks skip (Section 10.2 step 3)
# ---------------------------------------------------------------------------

class TestBinaryPayloadSkipLogic:
    """Binary payloads skip text-based signatures but run byte-level ones."""

    def test_binary_payload_skips_sqli(self) -> None:
        """Binary payload (printable_ratio < 0.9) does not run SQLI check."""
        # Mix binary with SQLi text — but binary ratio dominates
        binary = bytes(range(0, 128))  # all bytes 0-127 including many non-printable
        payload = _b64(binary)
        findings = evaluate_payload(payload, src_port=12345, dst_port=80)
        sqli = [f for f in findings if f.signature_name == "SQLI_PATTERN"]
        assert not sqli

    def test_binary_payload_runs_shellcode_check(self) -> None:
        """Binary payload still runs SHELLCODE_NOPSLED (operates on raw bytes)."""
        binary = bytes(range(0, 128)) + b"\x90" * 16
        payload = _b64(binary)
        findings = evaluate_payload(payload, src_port=12345, dst_port=9000)
        shellcode = [f for f in findings if f.signature_name == "SHELLCODE_NOPSLED"]
        assert shellcode


# ---------------------------------------------------------------------------
# Port selection helper tests (Section 10.2 step 5)
# ---------------------------------------------------------------------------

class TestWellKnownPort:
    """well_known_port() helper tests."""

    def test_dst_is_well_known(self) -> None:
        """Destination port 80 is well-known; returns dst_port."""
        assert well_known_port(54321, 80) == 80

    def test_src_is_well_known(self) -> None:
        """Source port 21 is well-known (server-side response); returns src_port."""
        assert well_known_port(21, 54321) == 21

    def test_both_ephemeral_returns_dst(self) -> None:
        """Both ports above 1023 → returns dst_port (client initiates to service)."""
        assert well_known_port(54321, 8080) == 8080
