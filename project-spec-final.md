# SentinelMesh
## A Multi-Agent Collaborative Security System Using Deep Packet Inspection

### Final Project Specification & Build Guide (v2.0 — Final)

**Purpose of this document:** This is the authoritative reference for building this system. Every agent/module described below MUST conform to the shared data schemas and interfaces defined in Section 5 (Data Contracts) exactly — this is what allows independently-built components to integrate without rework. Treat Section 5 as non-negotiable; everything else can flex within the stated constraints.

**Build note:** This project is built by a two-person team (one human + AI coding agents), not a large team. The architecture is intentionally still service-oriented (not a monolith) because that separation is itself part of the engineering demonstration for evaluation — but the phased plan in Section 6 is scoped realistically for a small team, not four parallel contributors.

---

## 1. Project Overview

### 1.1 What we are building

**SentinelMesh** is a network security system composed of multiple independent, communicating software agents that collaboratively detect malicious network activity using Deep Packet Inspection (DPI) and flow-based behavioral analysis.

Instead of one monolithic detection engine, responsibilities are split across specialized agents that each do one job well and share findings with each other over a message bus, catching multi-stage threats that no single agent could detect alone — for example, a slow reconnaissance scan followed by a targeted exploit attempt against the specific service that scan revealed.

### 1.2 Core problem being solved

Traditional single-pass firewalls and intrusion detection systems evaluate traffic in isolation, packet-by-packet or connection-by-connection, with no memory of what happened five minutes ago from a different angle. This means they routinely miss **multi-stage attacks** — the kind that don't look dangerous at any single moment, only when you connect signals across time and across detection strategies.

SentinelMesh correlates signals across time and across multiple specialized detection agents to catch these compound attack patterns, while remaining modular enough that each agent can be built, tested, and reasoned about independently.

### 1.3 What makes this project non-trivial (evaluation talking points)

This is deliberately architected to demonstrate several distinct engineering competencies in one system, which is worth stating explicitly in your report and defense:

- **Distributed systems design** — independent services communicating asynchronously over a message bus, not a single script
- **Real-time stream processing** — flow assembly and sliding-window correlation under continuous data flow
- **Security domain knowledge** — actual DPI techniques (signature matching, entropy analysis, protocol validation), not just calling a library
- **Systems thinking under constraints** — explicit, documented trade-offs between what's built and what production would require (Section 8)
- **Full observability** — health checks, structured audit logging, live dashboarding — not just "it prints something to console"

### 1.4 Unit of analysis

**Flow-level is primary.** Packets are captured individually but immediately aggregated into flows (5-tuple: src IP, dst IP, src port, dst port, protocol). Detection and correlation operate on flows. DPI performs payload inspection *within* a flow for signature matching.

Do not build a purely packet-by-packet detection system. A single SYN packet is meaningless in isolation; a pattern of SYN packets across a flow, or across many flows from the same source, is a port scan. This distinction is core to the system's design and should be reflected in every agent's logic.

### 1.5 Input / Output contract (system-level)

**Input:**
- Live packets from a network interface (via Scapy/libpcap), OR
- Packets replayed from a stored `.pcap` file (via `tcpreplay` or direct file read)
- Both sources MUST normalize into the same internal packet event format (Section 5.1) before entering the pipeline — no downstream agent should know or care which source was used.

**Output:**
1. Real-time alerts: traffic classified as benign/suspicious/malicious, with confidence score and attack type where applicable
2. Structured audit log (JSON, timestamped) of every decision made, tagged with which agent made it and why — fully traceable from incident back to the exact DPI finding(s) and detection(s) that triggered it
3. Dashboard visualization (Grafana) showing live traffic classification, incident timeline, and per-agent health status
4. Recommended mitigation action, **log-only or alert — never auto-executed**. This is a deliberate safety and demo-reliability decision, stated explicitly in Section 8, not a limitation to apologize for.

---

## 2. System Architecture

```
                     ┌─────────────────────┐
        Live NIC ───▶│                     │
                     │   Sniffer Agent     │──▶ raw packet events
   PCAP file    ───▶ │  (capture layer)    │        │
                     └─────────────────────┘        ▼
                                              ┌──────────────┐
                                              │ Flow Assembler│  (part of Sniffer
                                              │  (5-tuple)    │   Agent)
                                              └──────┬───────┘
                                                     │
                                                     ▼
                                          message bus (Kafka topic: flow-events)
                                                     │
                       ┌─────────────────────────────┤
                       ▼                              │
              ┌────────────────┐                      │
              │   DPI Agent     │                      │
              │ (payload/sig    │                      │
              │  inspection)    │                      │
              └────────┬────────┘                      │
                       │                                │
                       ▼                                ▼
                 topic: dpi-findings ─────────▶ ┌──────────────────┐
                       │                        │ Detection Agent   │
                       │                        │ (classification:  │
                       │                        │  benign/suspect/  │
                       │                        │  malicious + conf)│
                       │                        └─────────┬──────────┘
                       │                                  ▼
                       │                            topic: detections
                       │                                  │
                       └──────────────┬───────────────────┘
                                      ▼
                          ┌─────────────────────┐
                          │  Correlation Agent   │  (time-windowed,
                          │                       │   cross-agent aggregation,
                          │                       │   Redis-backed sliding window)
                          └──────────┬───────────┘
                                     ▼
                              topic: incidents
                                     │
                       ┌─────────────┴─────────────┐
                       ▼                             ▼
             ┌──────────────────┐          ┌──────────────────┐
             │  Response Agent   │          │  Dashboard         │
             │ (log / alert)     │          │  (Grafana)         │
             └──────────────────┘          └──────────────────┘

              All agents register with and report health to:
                     ┌─────────────────────┐
                     │  Coordinator Agent    │
                     │ (orchestration,       │
                     │  health checks,       │
                     │  restart signals)     │
                     └─────────────────────┘
```

**Note on this revision:** The Detection Agent consumes **both** `flow-events` and `dpi-findings` (this diagram now matches the responsibility table in 2.1 exactly — a prior draft had these out of sync). This means a single high-confidence DPI signature match can immediately influence flow classification, rather than only being folded in later at the Correlation stage. This is a deliberate design choice: it makes Detection Agent's reasoning traceable and explainable ("classified malicious because DPI matched signature X"), which is good for both your audit log and your demo narrative.

### 2.1 Agent responsibilities (one owner per agent — human or AI build-agent)

| Agent | Owns | Consumes | Produces |
|---|---|---|---|
| **Sniffer Agent** | Packet capture (live/pcap), flow assembly | Raw NIC traffic or pcap file | `flow-events` topic |
| **DPI Agent** | Payload inspection, signature matching, entropy-based anomaly detection | `flow-events` | `dpi-findings` topic |
| **Detection Agent** | Flow classification (benign/suspicious/malicious) | `flow-events`, `dpi-findings` | `detections` topic |
| **Correlation Agent** | Time-windowed cross-signal aggregation into incidents | `detections`, `dpi-findings` | `incidents` topic |
| **Response Agent** | Decide/log/alert action per incident | `incidents` | `actions` topic, audit log |
| **Coordinator Agent** | Agent registration, health checks, config distribution, restart-on-failure | health pings from all agents | agent status, restart signals |
| **Dashboard (Grafana)** | Visualization | `detections`, `incidents`, `actions`, agent health (via Prometheus) | UI only |

---

## 3. Technology Stack

| Layer | Choice | Notes |
|---|---|---|
| Packet capture | Python + Scapy | BPF filters at capture time; `store=False` to avoid memory bloat |
| Message bus | Kafka (Docker, KRaft mode — no Zookeeper needed) | Chosen deliberately for replay-ability and resume value; topics enable independent agent testing |
| Serialization | JSON | Sufficient for this scale; Protobuf noted as a production upgrade, not implemented |
| Detection logic | Rule/signature-based only (Suricata-style rules for DPI, threshold rules for Detection Agent) | No ML — this is a deliberate scope decision, not a gap. A well-tuned rule-based system is a defensible, explainable MVP and is easier to validate against ground-truth datasets |
| Correlation | Custom time-windowed logic in Python, backed by Redis for sliding-window shared state | This is the most engineering-intensive component — budget the most time here |
| Dashboard | Grafana reading from Prometheus (agent health) + Elasticsearch or a simple queryable JSON log store (detections/incidents) | Chosen over custom Flask UI to maximize engineering time on the actual detection pipeline rather than frontend code |
| Containerization | Docker + Docker Compose, one container per agent | Kubernetes is explicitly out of scope (Section 8) |
| Testing data | CICIDS2017 (primary), self-generated pcaps via `hping3`/`nmap`/Scapy in an isolated lab VM network | Labeled dataset enables real precision/recall/F1 metrics, not just "it seems to work" |
| Live demo | `tcpreplay` to replay a curated pcap onto a live interface | Controlled, repeatable, looks live without depending on unpredictable real traffic |

---

## 4. Repository Structure

```
sentinelmesh/
├── docker-compose.yml              # Kafka, Redis, Prometheus, Grafana, all agent containers
├── docs/
│   ├── project-spec-final.md       # this file
│   ├── architecture.png
│   └── production-gap.md           # Section 8, expanded for the final report
├── agents/
│   ├── sniffer/
│   │   ├── Dockerfile
│   │   ├── main.py
│   │   └── flow_assembler.py
│   ├── dpi/
│   │   ├── Dockerfile
│   │   ├── main.py
│   │   └── signatures/             # signature rule definitions, one file per rule
│   ├── detection/
│   │   ├── Dockerfile
│   │   ├── main.py
│   │   └── rules.py
│   ├── correlation/
│   │   ├── Dockerfile
│   │   ├── main.py
│   │   └── window_manager.py       # Redis-backed sliding window logic
│   ├── response/
│   │   ├── Dockerfile
│   │   └── main.py
│   └── coordinator/
│       ├── Dockerfile
│       └── main.py
├── shared/
│   ├── schemas.py                  # single source of truth for all Section 5 schemas
│   └── kafka_client.py             # shared producer/consumer wrapper used by all agents
├── datasets/
│   └── README.md                   # instructions to download CICIDS2017
├── pcaps/
│   └── demo_scenario.pcap          # curated attack scenario for live demo
└── tests/
    ├── test_sniffer.py
    ├── test_dpi.py
    ├── test_detection.py
    ├── test_correlation.py
    └── test_end_to_end.py
```

**Why this matters for AI build agents:** `shared/schemas.py` should be built first and imported by every agent — never let an agent hand-roll its own copy of a schema. This single-source-of-truth approach prevents the exact kind of drift (diagram vs. table mismatch) that this spec itself went through in an earlier draft.

---

## 5. Data Contracts (MUST be implemented exactly as specified)

### 5.1 Flow Event (Sniffer Agent output → `flow-events` topic)

```json
{
  "flow_id": "uuid-string",
  "timestamp_start": "ISO8601",
  "timestamp_last": "ISO8601",
  "src_ip": "string",
  "dst_ip": "string",
  "src_port": "int",
  "dst_port": "int",
  "protocol": "TCP | UDP | ICMP | OTHER",
  "packet_count": "int",
  "byte_count": "int",
  "tcp_flags_seen": ["SYN", "ACK", "FIN", "RST", "..."],
  "payload_sample": "base64-encoded string, first N bytes of first payload-bearing packet, may be null",
  "duration_ms": "int"
}
```

### 5.2 DPI Finding (DPI Agent output → `dpi-findings` topic)

```json
{
  "finding_id": "uuid-string",
  "flow_id": "string, references 5.1",
  "timestamp": "ISO8601",
  "match_type": "signature | anomaly",
  "signature_name": "string, null if anomaly-based",
  "anomaly_reason": "string, null if signature-based (e.g. 'high payload entropy', 'protocol mismatch on declared port')",
  "severity": "low | medium | high",
  "raw_evidence": "string, short human-readable description, NOT full payload dump"
}
```

### 5.3 Detection Result (Detection Agent output → `detections` topic)

```json
{
  "detection_id": "uuid-string",
  "flow_id": "string, references 5.1",
  "timestamp": "ISO8601",
  "classification": "benign | suspicious | malicious",
  "confidence": "float 0.0-1.0",
  "attack_type": "string, e.g. 'port_scan', 'syn_flood', 'exfiltration', null if benign",
  "contributing_findings": ["finding_id, ... references 5.2, optional"]
}
```

### 5.4 Incident (Correlation Agent output → `incidents` topic)

```json
{
  "incident_id": "uuid-string",
  "timestamp_opened": "ISO8601",
  "timestamp_updated": "ISO8601",
  "related_flow_ids": ["array of flow_id"],
  "related_detection_ids": ["array of detection_id"],
  "src_ip": "string, primary suspected actor, may be null if not applicable",
  "incident_type": "string, e.g. 'coordinated_scan', 'multi_stage_attack'",
  "severity": "low | medium | high | critical",
  "status": "open | escalated | resolved | false_positive"
}
```

### 5.5 Action (Response Agent output → `actions` topic + audit log)

```json
{
  "action_id": "uuid-string",
  "incident_id": "string, references 5.4",
  "timestamp": "ISO8601",
  "action_type": "log_only | alert",
  "target": "string, e.g. IP under investigation, null if log_only",
  "executed": "boolean, always true for log_only/alert since neither requires external execution",
  "operator_note": "string, optional"
}
```

> **Scope note:** `recommend_block` and `block_executed` were considered but are intentionally **not implemented** in this version. Only `log_only` and `alert` are built. This keeps the Response Agent simple and avoids any risk of the system taking a real network action during a live demo. Document `recommend_block` as a "designed but not implemented, future work" item in your final report — this is itself a good example of scoped, deliberate engineering judgment for your evaluators.

### 5.6 Agent Health Ping (all agents → Coordinator)

```json
{
  "agent_name": "string",
  "timestamp": "ISO8601",
  "status": "healthy | degraded | down",
  "throughput_last_interval": "int, events processed in last reporting window",
  "queue_depth": "int, if applicable"
}
```

---

## 6. Phased Build Plan (10 weeks, small team + AI build agents)

### Phase 1 — Foundation (Weeks 1–2)
- [ ] Finalize this spec; confirm all 6 data contracts (Section 5) before any agent code is written
- [ ] Build `shared/schemas.py` and `shared/kafka_client.py` first — every agent imports these, never redefines them
- [ ] Set up Kafka (Docker Compose, KRaft mode), create all 5 topics (`flow-events`, `dpi-findings`, `detections`, `incidents`, `actions`)
- [ ] Set up isolated lab network (2-3 VMs: target, attacker, capture agent host)
- [ ] Download CICIDS2017, confirm it can be parsed into valid flow events matching Section 5.1

### Phase 2 — Sniffer + DPI Agents (Weeks 3–4)
- [ ] Sniffer Agent: support both live Scapy capture and reading from a pcap file, both producing identical `flow-events` output
- [ ] Sniffer Agent: flow assembly by 5-tuple, with a configurable flow-timeout for closing stale flows
- [ ] DPI Agent: implement exactly 5 signature rules (recommend: SQL injection pattern, known malicious User-Agent string, shellcode/NOP-sled pattern, DNS tunneling pattern, plaintext credential leak pattern)
- [ ] DPI Agent: implement one anomaly check — payload entropy (high entropy on a normally-plaintext port is suspicious)
- [ ] Independent test: feed each agent a hardcoded mock input matching its upstream schema, verify valid output

### Phase 3 — Detection, Response, Coordinator Agents (Weeks 5–6)
- [ ] Detection Agent: rule-based classification consuming both `flow-events` and `dpi-findings` (e.g., >X SYN packets to different ports in <Y seconds = port_scan; any DPI signature match with severity=high = immediate malicious classification)
- [ ] Response Agent: `log_only` and `alert` action types only, writes structured audit log entries
- [ ] Coordinator Agent: health check listener (Section 5.6), basic restart-on-failure via Docker Compose restart policies
- [ ] Independent test each agent against mocked upstream input

### Phase 4 — Correlation Agent + Integration (Weeks 7–8)
- [ ] Correlation Agent: sliding time window (60s default, configurable), Redis-backed shared state, groups detections by `src_ip`
- [ ] Correlation Agent: flags repeated/escalating suspicious activity from the same source as an incident (e.g., port scan detection followed by a malicious detection from the same `src_ip` within the window = `multi_stage_attack`)
- [ ] Wire all agents together through the real Kafka bus (not mocks)
- [ ] End-to-end smoke test: replay a known-benign pcap → confirm zero false incidents; replay a known-attack pcap → confirm a correct incident is raised

### Phase 5 — Testing, Dashboard, Metrics (Week 9)
- [ ] Run full CICIDS2017 dataset through the pipeline, compute precision/recall/F1 against ground-truth labels
- [ ] Tune detection thresholds to reduce false positives without missing known attacks — document before/after numbers
- [ ] Load test: measure sustained throughput (flows/sec) and end-to-end detection latency — document these numbers, they matter a lot for your evaluation
- [ ] Build Grafana dashboard: live flow classification, incident timeline, per-agent health (via Prometheus)

### Phase 6 — Demo Prep & Report (Week 10)
- [ ] Curate a `tcpreplay` scenario: a clean pcap showing port scan → targeted exploit attempt, chosen to visibly demonstrate cross-agent correlation
- [ ] Rehearse the full demo end-to-end at least twice
- [ ] Write the final report, including: architecture, measured metrics (precision/recall/F1, throughput, latency), and the Production Gap section (Section 8) as your "future work" discussion

---

## 7. Legal & Ethical Note (include in report)

Live packet capture must only be performed on networks you own or have explicit permission to monitor (your own isolated lab VM network). Do not capture traffic on shared, public, or institutional networks without authorization. All attack simulation (port scans, floods, exploit attempts, etc.) must be conducted only within the isolated lab environment against systems you control.

---

## 8. Explicit Non-Goals / Production Gap (state this clearly in the final report)

This implementation intentionally does **not** include the following, which would be required for real production deployment. Stating these explicitly demonstrates awareness of the production gap without needing to build it — this is expected, credible framing for a final year project and shows engineering maturity to evaluators:

- Line-rate packet capture at 1Gbps+ (would require DPDK or eBPF/XDP instead of Scapy)
- Kernel-bypass or hardware-accelerated inspection (SmartNICs)
- mTLS-encrypted, authenticated agent-to-agent communication
- Kubernetes-based autoscaling and self-healing
- GDPR/compliance-grade payload redaction and retention policy
- Auto-executed blocking or mitigation without human review (`recommend_block`/`block_executed` designed in the schema but deliberately unimplemented)
- ML-based classification (deliberately deferred — rule-based is more explainable and easier to validate for a project of this scope)
- Distributed correlation state across multiple physical sites

---

## 9. Acceptance Criteria (definition of "done" per agent)

An agent is considered complete when:
1. It consumes only from its specified input topic(s) and produces only to its specified output topic(s), matching the schemas in Section 5 exactly
2. It can run standalone against a mocked upstream input and produce valid output
3. It reports health pings to the Coordinator per Section 5.6
4. It has been tested against both benign and malicious traffic samples from CICIDS2017
5. It logs its decisions in a human-readable way for the audit trail

**System integration is considered complete when:** a replayed attack pcap produces a correct end-to-end incident, visible on the Grafana dashboard, traceable back through the audit log to the specific DPI finding(s) and detection(s) that triggered it — and a replayed benign pcap produces zero false incidents.

**Project is considered demo-ready when:** the measured precision/recall/F1 against CICIDS2017 ground truth, and the measured throughput/latency numbers from Phase 5, are both documented and can be spoken to confidently in the defense — numbers, not just "it works."

---

## 10. Detailed Implementation Blueprint

This section fills in the exact numbers, keys, and behaviors an AI build agent needs to write code without guessing. It does not change the architecture, scope, tech stack, or Section 5 data contracts — every field name below matches Section 5 exactly. Treat every threshold here as a `.env`-configurable default (Section 10.11), not a hardcoded magic number, so it can be tuned during Phase 5 without a code change.

### 10.1 Flow Lifecycle and Timeout Behavior

**Flow key:** the 5-tuple, normalized so that a flow is direction-independent — i.e. traffic from A→B and B→A on the same 4-tuple+protocol is one flow, not two. Normalize by always ordering the tuple with the numerically lower IP:port pair first internally; `src_ip`/`dst_ip` in the emitted event still reflect the flow's actual initiator (first packet seen).

**States:** `OPENING → ACTIVE → CLOSING → CLOSED` (natural close) or `OPENING → ACTIVE → EXPIRED` (timeout close). State is internal to the Sniffer Agent's flow table — it is not part of the emitted schema.

**Per-protocol timeout rules:**

| Protocol | Opens on | Closes naturally on | Idle timeout | Hard max duration |
|---|---|---|---|---|
| TCP | First SYN | FIN+ACK seen in both directions, or RST | 120s (`FLOW_TCP_IDLE_TIMEOUT_S`) | 300s (`FLOW_TCP_MAX_DURATION_S`) |
| UDP | First packet | Never closes naturally (no session concept) | 60s (`FLOW_UDP_IDLE_TIMEOUT_S`) | n/a |
| ICMP | First packet | n/a | 30s (`FLOW_ICMP_IDLE_TIMEOUT_S`) | n/a |

**Flow table implementation:** an in-memory dict inside the Sniffer Agent, keyed by normalized 5-tuple, holding running counters (`packet_count`, `byte_count`, `tcp_flags_seen`, first-payload sample). A background sweep thread runs every 10s, checking each flow's `timestamp_last` against its idle timeout; expired flows are emitted (state=EXPIRED) and removed from the table.

**Long-lived flow handling (important, since TCP max duration is 300s but a legitimate download could run longer):** if a flow is still `ACTIVE` after `FLOW_INTERIM_EMIT_INTERVAL_S` (default 30s) without closing, emit an interim `flow-event` with the **same `flow_id`**, current cumulative counters, and `timestamp_last` updated — then keep the flow open in the table and continue accumulating. This does not add any field to Section 5.1; downstream agents already treat `flow_id` as the correlation key, so repeated emissions under one `flow_id` are handled naturally (Detection Agent re-evaluates each event; Correlation Agent already groups by `flow_id`/`src_ip`). If the flow hits `FLOW_TCP_MAX_DURATION_S`, force-close it (final event) and start a fresh `flow_id` if the same 5-tuple sees more traffic afterward.

### 10.2 DPI Signatures and Entropy Thresholds

Exactly 5 signature rules, all string/regex-based, applied to `payload_sample` (Section 5.1) reconstructed by the Sniffer Agent (minimum first 256 bytes of the flow's first payload-bearing packet):

| Signature name | Match logic | Applicable ports | Severity |
|---|---|---|---|
| `SQLI_PATTERN` | Canonical regex, see below | 80, 8080, 8000 | high |
| `MALICIOUS_USER_AGENT` | Canonical list + extraction algorithm, see below | 80, 8080, 443 (header visible pre-TLS handshake only) | medium |
| `SHELLCODE_NOPSLED` | Canonical byte-level check, see below | any | high |
| `DNS_TUNNELING` | Canonical parse algorithm, see below | 53 | medium |
| `PLAINTEXT_CRED_LEAK` | Canonical regex, see below | 21, 23, 80, 110 (protocols that should not carry credentials in plaintext) | high |

**Shared preprocessing (applies to all 5 signatures, must be implemented identically by every agent/developer):**

1. Take `payload_sample` (Section 5.1), which is base64-encoded — decode to raw bytes first. Call this `raw_bytes`.
2. Compute `printable_ratio` = (count of bytes in `raw_bytes` that are `0x09`, `0x0A`, `0x0D`, or in range `0x20`–`0x7E`) ÷ `len(raw_bytes)`.
3. If `printable_ratio >= 0.9`, decode `raw_bytes` as UTF-8 with `errors="ignore"` to get `text`; this is the "printable" path used by the three text/regex-based signatures (`SQLI_PATTERN`, `MALICIOUS_USER_AGENT`, `PLAINTEXT_CRED_LEAK`). If `printable_ratio < 0.9`, skip those three signatures for this flow entirely (do not run regexes against binary noise) — but still run `SHELLCODE_NOPSLED` and `DNS_TUNNELING`, since those operate on `raw_bytes` directly and are meaningful on binary payloads.
4. Evaluation order (fixed, for reproducibility — order does not change which findings are emitted, since all 5 are independent and a flow can produce multiple findings, but a fixed order keeps `finding_id` generation and logs deterministic across implementations): `SQLI_PATTERN` → `MALICIOUS_USER_AGENT` → `PLAINTEXT_CRED_LEAK` → `SHELLCODE_NOPSLED` → `DNS_TUNNELING`.
5. Each signature is checked only if the flow's `dst_port` (or `src_port`, whichever is the well-known side) is in its applicable ports list above. A flow can trigger more than one signature; each match emits its own separate `dpi-findings` message with its own `finding_id`.

**1. `SQLI_PATTERN` — canonical regex, applied to `text` with `re.IGNORECASE`, using `re.search` (not `re.match`):**
```
r"(\bunion\s+select\b)|('\s*or\s*'1'\s*=\s*'1)|(\bor\s+1\s*=\s*1\s*--)"
```
A match on any of the three alternatives triggers the finding. `raw_evidence` = the matched substring only (never the full payload).

**2. `MALICIOUS_USER_AGENT` — deterministic extraction + substring match:**
1. Split `text` on `\r\n` (fallback to `\n` if no `\r\n` present) into lines.
2. Find the first line matching `^user-agent:\s*` case-insensitively; call the remainder of that line `ua_value`.
3. If no such line exists, no match — do not fall back to scanning the whole payload.
4. Lowercase `ua_value` and check for any of these fixed substrings, in this exact list and order (first hit wins, order does not affect the boolean outcome but is fixed for deterministic logging): `["sqlmap", "nikto", "nmap scripting engine", "masscan", "nessus"]`.

**3. `SHELLCODE_NOPSLED` — canonical byte-level check, operates on `raw_bytes` regardless of printable ratio:**
```python
NOP_RUN = b"\x90" * 16
is_match = NOP_RUN in raw_bytes
```
A single Python `in` substring check on the raw bytes (O(n), deterministic, no regex needed — this must not be reimplemented as a manual byte-counting loop, to avoid off-by-one divergence between developers).

**4. `DNS_TUNNELING` — canonical parse algorithm, must use the `dnspython` library (`dns.message.from_wire`) rather than hand-rolled byte parsing, so every implementation parses identically:**
```python
import dns.message
msg = dns.message.from_wire(raw_bytes)
qname = str(msg.question[0].name) if msg.question else ""
labels = qname.strip(".").split(".")
max_label_len = max((len(l) for l in labels), default=0)
is_match = max_label_len > 50 or len(qname) > 150
```
If `dns.message.from_wire` raises (malformed/truncated packet), treat as no match (log at DEBUG, do not crash the DPI Agent) rather than guessing at a partial parse.

**5. `PLAINTEXT_CRED_LEAK` — canonical regex, applied to `text` with `re.IGNORECASE`, using `re.search`:**
```
r"(\bpassword\s*=)|(\bpasswd\s*=)|(\bpwd\s*=)|(\bauthorization:\s*basic\b)"
```

**Entropy-based anomaly check (the one non-signature DPI check, per Section 3):**

- Compute Shannon entropy over the byte histogram of `payload_sample`: `H = -Σ p(x)·log2(p(x))` for each observed byte value `x`.
- Minimum sample size to compute: 64 bytes (`DPI_MIN_SAMPLE_BYTES`) — below this, skip the check rather than risk a noisy result on a tiny sample.
- Threshold: `H > 7.2` bits/byte (`DPI_ENTROPY_THRESHOLD`) on a port that is conventionally plaintext (80, 21, 23, 25, 110) → emit a DPI finding with `match_type: "anomaly"`, `anomaly_reason: "high payload entropy for plaintext port"`, severity `medium`.
- **Explicitly skip entropy checks on known-encrypted ports** (443, 22, 993, 995) — high entropy there is expected (TLS/SSH) and would otherwise generate constant false positives.
- Second anomaly type, same finding schema: `anomaly_reason: "protocol mismatch on declared port"` — e.g., payload on port 80 that doesn't parse as valid HTTP (no recognizable HTTP verb in the first line). This is a cheap heuristic check (regex for `GET |POST |PUT |HEAD `), not a full protocol parser.

### 10.3 Detection Rules, Thresholds, Confidence Scores, and Priority

Detection Agent evaluates all applicable rules per flow-event/dpi-finding pair and picks the **highest-priority match** (priority 1 = most important; ties broken by higher confidence). Every field below maps directly onto Section 5.3.

| Priority | Rule | Condition | Classification | Confidence | attack_type |
|---|---|---|---|---|---|
| 1 | DPI high-severity match | Any `dpi-findings` entry with `severity: "high"` for this `flow_id` | malicious | 0.90 | `exploit_attempt` |
| 1 | SYN flood | Same `dst_ip`+`dst_port` receives >100 flows with SYN-only flags (`det:synflood` counter, Section 10.5) within 5s (`DETECTION_SYNFLOOD_WINDOW_S`) | malicious | 0.85 | `syn_flood` |
| 2 | Port scan | Same `src_ip` touches ≥15 distinct `dst_port`s (`det:portscan` set, Section 10.5) within 10s (`DETECTION_PORTSCAN_WINDOW_S`) | suspicious | 0.70 | `port_scan` |
| 3 | DPI medium-severity match (alone) | Any `dpi-findings` entry with `severity: "medium"`, no higher-priority rule matched | suspicious | 0.60 | `suspicious_payload` |
| 4 | Possible exfiltration | Single flow `byte_count` > 50MB (`DETECTION_EXFIL_BYTES_THRESHOLD`) to an external IP on a non-standard port | suspicious | 0.50 | `possible_exfiltration` |
| 5 (default) | No rule matched | — | benign | 0.95 | `null` |

`contributing_findings` is populated with the `finding_id`(s) of any DPI matches that fed into the decision; empty array for purely flow-behavior-based rules (port scan, SYN flood, exfiltration).

### 10.4 Correlation Rules and Multi-Stage Attack Scenarios

Correlation Agent groups incoming `detections` and `dpi-findings` primarily by `src_ip` (resolved via flow context, Section 10.6) within a **sliding** 60s window (`CORRELATION_WINDOW_S`), backed by Redis (Section 10.5). Two of the five rules below (Rule 4 and Rule 5) group by `dst_ip` instead, since they capture a different collaborative signal — this is why Section 5.4's `src_ip` field is documented as nullable ("primary suspected actor, may be null if not applicable"): a `distributed_target_attack` incident has one target and multiple actors, so `src_ip` is genuinely not applicable there.

| # | Rule | Condition | incident_type | severity |
|---|---|---|---|---|
| 1 | Coordinated scan | `src_ip` has `port_scan`-classified detections whose underlying flows (resolved via flow context, Section 10.6) touch ≥5 distinct `dst_ip`s (`CORRELATION_COORD_SCAN_DISTINCT_DST`) within the window | `coordinated_scan` | medium |
| 2 | Multi-stage attack | `src_ip` has a `port_scan`/`suspicious` detection, **followed within the window** by a `malicious` detection against a `dst_ip` that was part of the earlier scan | `multi_stage_attack` | high (or **critical** if the triggering malicious detection's `confidence ≥ 0.85`) |
| 3 | Repeated malicious | `src_ip` produces ≥3 `malicious` detections (`CORRELATION_REPEATED_MALICIOUS_COUNT`) within the window, regardless of stage | `repeated_malicious` | high |
| 4 | DPI-confirmed scan | `src_ip` has a `port_scan` detection **and**, within the same window, at least one `dpi-findings` entry (any severity) whose flow resolves to one of the scanned `dst_ip`s — this is the cross-agent case where DPI Agent and Detection Agent evidence is combined by Correlation, not just Detection Agent evidence alone | `dpi_confirmed_scan` | medium (high if the contributing DPI finding's `severity` is `"high"`) |
| 5 | Distributed target attack | A single `dst_ip` (resolved via flow context) is the target of `malicious`- or `suspicious`-classified detections from ≥3 distinct `src_ip`s within the window | `distributed_target_attack` | high |

**Why Rules 4 and 5 matter for the "collaborative" part of the architecture:** Rules 1–3 can each be evaluated from Detection Agent output alone (Correlation is just counting/windowing what Detection already decided). Rules 4 and 5 genuinely require combining signals that no single upstream agent has on its own — Rule 4 fuses DPI Agent's payload-level evidence with Detection Agent's behavioral evidence for the same actor; Rule 5 flips the grouping axis entirely (by target instead of by source) to catch a pattern that's invisible if you only ever look at one `src_ip` at a time. This is worth highlighting explicitly in your report as the concrete demonstration of multi-agent collaboration, not just multi-agent existence.

**Incident lifecycle:** created on first rule match (`status: "open"`). Each subsequent matching event for the same grouping key (`src_ip` for Rules 1–4, `dst_ip` for Rule 5) appends to `related_flow_ids`/`related_detection_ids` and updates `timestamp_updated` (rather than opening a duplicate incident) — see `corr:active_incident:{src_ip}` and `corr:active_incident_dst:{dst_ip}` lookup keys, Section 10.5. Severity can escalate (e.g. `coordinated_scan` → `multi_stage_attack` as new evidence arrives), moving `status` to `"escalated"`. An incident with no new matching activity for `CORRELATION_MAX_INCIDENT_LIFETIME_S` (default 600s / 10 min) auto-closes with `status: "resolved"`. `status: "false_positive"` is reserved for manual/operator marking and is not set automatically by any agent — this is intentional (no agent should be self-grading its own false positives).

**This directly implements the "port scan → targeted exploit" demo scenario from Section 6, Phase 6:** a scan against a host trips the `port_scan` detection; a subsequent exploit attempt against one of the scanned ports from the same `src_ip` trips a `malicious` DPI-backed detection; the Correlation Agent ties them into one `multi_stage_attack` incident — this is the story your demo should visibly walk through end-to-end.

### 10.5 Redis Keys, Data Structures, and TTLs

| Key pattern | Type | Purpose | TTL |
|---|---|---|---|
| `det:portscan:{src_ip}` | Set (members = dst_ports) | Distinct-port tracking for the port scan rule | 10s, refreshed (EXPIRE reset) on each add |
| `det:synflood:{dst_ip}:{dst_port}` | Counter (INCR) | SYN-only flow count for the SYN flood rule | 5s, refreshed on each increment |
| `corr:src:{src_ip}:events` | Sorted Set (score = event epoch timestamp, member = detection_id/finding_id) | Sliding-window membership for correlation | 60s per member (via periodic ZREMRANGEBYSCORE sweep, not native Redis TTL since ZSET entries don't expire individually) |
| `corr:detection:{detection_id}` | Hash (full detection JSON) | Detail lookup for events referenced in the sorted set above | 120s (window length + buffer) |
| `corr:active_incident:{src_ip}` | String (value = incident_id) | Lookup to append to an existing open incident instead of creating a duplicate (Rules 1–4) | 600s, refreshed on every update (matches `CORRELATION_MAX_INCIDENT_LIFETIME_S`) |
| `corr:dst:{dst_ip}:sources` | Set (members = src_ip) | Distinct-source tracking for the distributed target attack rule (Rule 5) | 60s, refreshed (EXPIRE reset) on each add |
| `corr:active_incident_dst:{dst_ip}` | String (value = incident_id) | Same as `corr:active_incident:{src_ip}` but for the dst-grouped rule (Rule 5) | 600s, refreshed on every update |
| `corr:incident:{incident_id}` | Hash (full incident JSON) | Canonical incident record, source of truth before it's also persisted to Postgres (Section 10.9) | 600s, refreshed on every update |
| `flow:ctx:{flow_id}` | Hash (`src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`) | Flow context cache for correlation resolution (Section 10.6) | 300s — deliberately longer than the correlation window, so a late-arriving detection can still resolve context |
| `health:{agent_name}` | String (JSON health ping payload) | Liveness tracking; Coordinator treats key expiry as agent-down | 15s (3× the 5s heartbeat interval) |
| `dedupe:{topic}:{id}` | String (value = "1") | At-least-once delivery dedup guard (Section 10.7) | 60s |

### 10.6 Flow Context Resolution for the Correlation Agent

The Correlation Agent needs `src_ip`/`dst_ip` to group activity, but `detections` (5.3) and `dpi-findings` (5.2) only carry `flow_id` — they don't repeat the IP/port fields, by design (avoids duplicating Section 5.1 data in every downstream message). To resolve this without changing any schema, the Correlation Agent maintains a **read-only side cache**: it additionally consumes the `flow-events` topic (on its own consumer group, `correlation-flow-context-group`) purely to populate `flow:ctx:{flow_id}` in Redis (Section 10.5) — it does not act on flow-events for detection purposes, only for context lookup. When a `detection` or `dpi-finding` arrives, the Correlation Agent reads `flow:ctx:{flow_id}` to get `src_ip`/`dst_ip` before applying the rules in Section 10.4. If context isn't found (rare race condition where the detection arrives before the flow-event context is cached), the event is held in a short retry buffer (up to 2 seconds, 3 attempts) before being logged as unresolvable and skipped — this should be rare in practice since `flow-events` is upstream of both `dpi-findings` and `detections` in the pipeline.

### 10.7 Kafka Topics, Message Keys, Consumer Groups, Retries, Duplicate Handling

| Topic | Partitions | Message key | Retention | Consumer group(s) |
|---|---|---|---|---|
| `flow-events` | 1 | `src_ip` | 24h | `dpi-agent-group`, `detection-agent-group`, `correlation-flow-context-group` |
| `dpi-findings` | 1 | `flow_id` | 24h | `detection-agent-group`, `correlation-agent-group` |
| `detections` | 1 | `flow_id` | 24h | `correlation-agent-group`, `dashboard-writer-group` |
| `incidents` | 1 | `incident_id` | 7 days | `response-agent-group`, `dashboard-writer-group` |
| `actions` | 1 | `incident_id` | 7 days | `dashboard-writer-group` |
| `*-dlq` (one per topic above) | 1 | same as source topic | 7 days | manual inspection only, no consuming agent |

Single partition per topic is sufficient for this project's throughput and keeps ordering trivial — but keying by `src_ip`/`flow_id`/`incident_id` (rather than leaving keys null) documents the correct partitioning strategy for future horizontal scaling, and is worth stating explicitly in your report as a scaling consideration you accounted for even though you didn't need it yet.

**Producer config:** `enable.idempotence=true`, `retries=3`, exponential backoff starting at 100ms, `acks=all`.

**Consumer duplicate handling (at-least-once delivery):** manual offset commit, committed only *after* successful processing. Before processing a message, each agent checks `dedupe:{topic}:{id}` (Section 10.5, using the message's own `*_id` field) — if present, skip (already processed); if absent, set it and proceed. This makes reprocessing after a crash-and-restart safe.

**Dead-letter handling:** if a message fails processing 3 consecutive times (malformed schema, unhandled exception), publish it as-is to `{topic}-dlq` with an added error reason and timestamp, log at ERROR level, and move on — this prevents one bad message from blocking an entire partition indefinitely.

### 10.8 CICIDS2017 Evaluation Methodology

1. **Dataset subset used for headline metrics:** Friday (Working Hours — PortScan, Bot, Benign) and Thursday (Working Hours — Web Attacks: SQL Injection, Brute Force, XSS, Benign). Wednesday's DoS day (Hulk/GoldenEye/Slowloris/Slowhttptest) is intentionally **not** used for headline metrics — see point 3 below for why.
2. **Ground truth mapping — genuinely supported classes only:**
   - `BENIGN` (Friday and Thursday subsets) → `benign`
   - `PortScan` (Friday) → `suspicious` / `port_scan` — matches the Detection Agent's port-scan rule (Section 10.3) directly
   - `Web Attack – Sql Injection` (Thursday) → `malicious` / `exploit_attempt` — matches the `SQLI_PATTERN` DPI signature (Section 10.2) directly
   
   These are the only two attack classes SentinelMesh has a purpose-built rule or signature for, so they are the only two used to compute the headline precision/recall/F1 numbers.
3. **Explicitly excluded from headline metrics (and why — this must be stated in the report, not silently dropped):**
   - **`DoS Hulk` / `DoS GoldenEye` / `DoS slowloris` / `DoS Slowhttptest`** — these are application-layer HTTP flood attacks that complete full TCP handshakes; they are mechanically different from the SYN-only-flag counting the SYN flood rule (Section 10.3) targets. Scoring them against that rule would measure the system against an attack it was never designed to catch and unfairly deflate recall.
   - **`Bot`** (Friday) — SentinelMesh has no botnet C2 signature or behavioral rule. There is no rule this label could validate.
   - **`Web Attack – Brute Force` / `Web Attack – XSS`** (Thursday), and all labels from days not used here (Infiltration, Heartbleed) — no corresponding signature or rule exists for any of these.
   
   These excluded classes may still be reported in a **separate, clearly-labeled secondary table** ("classes out of detection scope") showing what SentinelMesh does with them (almost certainly classifies as `benign`, since no rule fires) — framed as documented limitation, not a failure of the evaluated system.
4. **SYN flood rule evaluation (separate from CICIDS2017, since the dataset has no matching label):** validated using self-generated synthetic traffic in the isolated lab network (`hping3 -S --flood` against a lab target), reported as a smaller, separate validation — e.g. "detected N/N synthetic SYN flood bursts within X seconds" — not folded into the CICIDS2017 confusion matrix.
5. **Replay procedure:** feed the corresponding raw `.pcap` for Thursday and Friday through the Sniffer Agent (pcap mode), run the full pipeline end-to-end, capture every `detections` message produced.
6. **Joining predicted vs. ground truth:** since generated `flow_id`s won't match CICIDS2017's own flow IDs, join on the natural key (`src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, timestamp within a 5-second tolerance window) between this system's output and the dataset's labeled CSV, restricted to rows labeled `BENIGN`, `PortScan`, or `Web Attack – Sql Injection`.
7. **Metrics:** compute precision, recall, and F1 for the three supported classes (`benign` / `port_scan` / `exploit_attempt`) plus a confusion matrix, using plain arithmetic over the joined, filtered dataset (this is evaluation math, not a trained model — no ML is introduced by computing these numbers).
8. **Sampling for time constraints:** rather than the full dataset, replay a stratified random sample of ~200,000 flows drawn only from the three supported-class rows (proportionally sampled) — document this as a deliberate methodology choice in the report, not a limitation you're hiding.
9. **Target numbers to aim for (state actual measured numbers in the final report, whatever they are):** ≥80% recall on the two supported attack classes, ≤10% false positive rate on benign traffic. These are goals to tune toward during Phase 5, not guaranteed outcomes — report what you actually measured.

### 10.9 Grafana Data Storage and Dashboard Design

**Storage choice:** PostgreSQL (simplest option consistent with Section 3's "simple queryable store" language — easier to stand up and query than Elasticsearch for a project this size, and Grafana has first-class Postgres support).

**Schema (3 tables, populated by a small dashboard-writer consumer script under `shared/`, not a new core agent — it just persists what's already flowing through `detections`/`incidents`/`actions`):**

```sql
CREATE TABLE detections (
  detection_id UUID PRIMARY KEY,
  flow_id UUID NOT NULL,
  ts TIMESTAMPTZ NOT NULL,
  classification TEXT NOT NULL,
  confidence REAL NOT NULL,
  attack_type TEXT
);

CREATE TABLE incidents (
  incident_id UUID PRIMARY KEY,
  ts_opened TIMESTAMPTZ NOT NULL,
  ts_updated TIMESTAMPTZ NOT NULL,
  src_ip TEXT,
  incident_type TEXT NOT NULL,
  severity TEXT NOT NULL,
  status TEXT NOT NULL
);

CREATE TABLE actions (
  action_id UUID PRIMARY KEY,
  incident_id UUID REFERENCES incidents(incident_id),
  ts TIMESTAMPTZ NOT NULL,
  action_type TEXT NOT NULL,
  target TEXT
);
```

The dashboard-writer consumer (`dashboard-writer-group`, Section 10.7) upserts on primary key so incident updates overwrite rather than duplicate rows.

**Dashboard panels:**
1. Live traffic classification — bar/pie chart, benign/suspicious/malicious counts over the last 5 minutes
2. Incident timeline — table of recent incidents, color-coded by severity
3. Per-agent health — up/down indicator per agent, sourced from Prometheus (`sentinelmesh_agent_up`)
4. Throughput graph — flows/sec and detections/sec over time, sourced from Prometheus counters
5. Top source IPs by detection count — table, last 15 minutes
6. DPI signature hit counts — bar chart, by `signature_name`

**Refresh interval:** 5s auto-refresh, chosen specifically so the dashboard visibly updates in real time during the live demo.

### 10.10 Prometheus Metrics

Every agent exposes a `/metrics` HTTP endpoint (via the `prometheus_client` Python library) on its own configured port (Section 10.11), scraped by Prometheus every 5s.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `sentinelmesh_events_consumed_total` | Counter | `agent`, `topic` | Messages successfully consumed |
| `sentinelmesh_events_produced_total` | Counter | `agent`, `topic` | Messages successfully produced |
| `sentinelmesh_processing_latency_seconds` | Histogram | `agent` | Time to process one message, consume-to-produce |
| `sentinelmesh_errors_total` | Counter | `agent`, `error_type` | Processing failures, by category |
| `sentinelmesh_queue_depth` | Gauge | `agent` | Consumer lag on the agent's input topic(s) |
| `sentinelmesh_agent_up` | Gauge | `agent` | 1/0, set by the Coordinator based on `health:{agent_name}` key freshness (Section 10.5) |

### 10.11 Environment Variables and Configuration

All agents load config from a shared `.env` file (via `python-dotenv`), with a committed `.env.example` at the repo root documenting every variable below and its default.

```
# Shared
KAFKA_BOOTSTRAP_SERVERS=kafka:9092
REDIS_HOST=redis
REDIS_PORT=6379
LOG_LEVEL=INFO

# Sniffer Agent
SNIFFER_INTERFACE=eth0
SNIFFER_MODE=live                    # live | pcap
SNIFFER_PCAP_PATH=/pcaps/demo_scenario.pcap
FLOW_TCP_IDLE_TIMEOUT_S=120
FLOW_TCP_MAX_DURATION_S=300
FLOW_UDP_IDLE_TIMEOUT_S=60
FLOW_ICMP_IDLE_TIMEOUT_S=30
FLOW_INTERIM_EMIT_INTERVAL_S=30

# DPI Agent
DPI_ENTROPY_THRESHOLD=7.2
DPI_MIN_SAMPLE_BYTES=64

# Detection Agent
DETECTION_PORTSCAN_DISTINCT_PORTS=15
DETECTION_PORTSCAN_WINDOW_S=10
DETECTION_SYNFLOOD_THRESHOLD=100
DETECTION_SYNFLOOD_WINDOW_S=5
DETECTION_EXFIL_BYTES_THRESHOLD=52428800

# Correlation Agent
CORRELATION_WINDOW_S=60
CORRELATION_MAX_INCIDENT_LIFETIME_S=600
CORRELATION_COORD_SCAN_DISTINCT_DST=5
CORRELATION_REPEATED_MALICIOUS_COUNT=3

# Coordinator / Health
HEALTH_PING_INTERVAL_S=5
HEALTH_KEY_TTL_S=15

# Prometheus ports (one per agent, avoid collisions)
PROMETHEUS_PORT_SNIFFER=9101
PROMETHEUS_PORT_DPI=9102
PROMETHEUS_PORT_DETECTION=9103
PROMETHEUS_PORT_CORRELATION=9104
PROMETHEUS_PORT_RESPONSE=9105
PROMETHEUS_PORT_COORDINATOR=9106

# Postgres (dashboard storage)
POSTGRES_HOST=postgres
POSTGRES_PORT=5432
POSTGRES_DB=sentinelmesh
POSTGRES_USER=sentinelmesh
POSTGRES_PASSWORD=changeme
```

### 10.12 Error Handling and Agent Failure Behavior

- **Kafka connection loss:** reconnect with exponential backoff (1s, 2s, 4s... capped at 30s), log every attempt, never crash the process over a transient connection issue.
- **Malformed message:** validate every consumed message against its Section 5 schema (via Pydantic models in `shared/schemas.py`) before processing. On validation failure: log the error with a hash of the offending message (not the full payload, to keep logs clean), route to the topic's DLQ (Section 10.7), increment `sentinelmesh_errors_total{error_type="schema_validation"}`, and continue the consume loop.
- **Redis unavailable:** Detection and Correlation Agents degrade gracefully rather than crash — they fall back to per-event classification without cross-flow/cross-source aggregation (port scan, SYN flood, and correlation rules are effectively disabled), log a clear warning, and report `status: "degraded"` in their health ping (Section 5.6) so this is visible on the dashboard rather than silently losing detection capability.
- **Agent crash:** Docker Compose `restart_policy: on-failure`, max 5 restart attempts with backoff. If an agent's `health:{agent_name}` key isn't refreshed within `HEALTH_KEY_TTL_S`, the Coordinator marks it down and this surfaces immediately on the Grafana health panel.
- **Poison message / crash-loop protection:** if the same message causes 3 consecutive processing failures, it's routed to the DLQ instead of being retried indefinitely — this is what actually prevents a single bad message from crash-looping an agent forever.
- **Sniffer Agent capture failure specifically:** if the configured interface is down or capture permission is denied, log a clear, actionable error and exit non-zero immediately (Docker restarts it) — never silently produce zero flows and appear "healthy" while capturing nothing.

### 10.13 Testing Plan

**Unit tests** (pytest, one file per agent under `tests/`):
- **Sniffer:** flow assembly correctness against synthetic packet sequences; correct bidirectional 5-tuple normalization; idle-timeout and max-duration expiry logic; interim-emit behavior for long-lived flows.
- **DPI:** each of the 5 signatures tested against both a known-positive and a known-negative payload sample; entropy calculation verified against payloads with known, hand-computed entropy values.
- **Detection:** each rule in Section 10.3 tested against constructed flow-event/dpi-finding fixtures; priority/conflict resolution verified with fixtures designed to match multiple rules at once.
- **Correlation:** sliding-window logic, incident creation vs. append-to-existing-incident logic, and incident expiry, all tested against a mocked/fake Redis (`fakeredis`); flow-context resolution cache tested including the late-arrival retry path.
- **Response:** correct `action_type` selection given incident severity.

**Integration tests:** using `testcontainers-python` to spin up a real local Kafka instance per test run, verify that each adjacent pair of agents in the pipeline produces output that validates against the next agent's expected input schema (contract testing) — e.g., confirm the Sniffer Agent's real output is accepted without modification by the DPI Agent's input parser.

**End-to-end tests:** four curated pcaps under `pcaps/`:
- `benign_sample.pcap` — ordinary traffic, no rule should fire. Assert **zero** incidents.
- `portscan_sample.pcap` — a single `src_ip` scanning across **≥5 distinct `dst_ip`s** (at least 3 distinct ports touched per target, ≥15 distinct ports total across all targets combined, all within `DETECTION_PORTSCAN_WINDOW_S`). This specific shape is required, not a generic "port scan" — a classic single-host, many-port scan (e.g. a plain Nmap sweep of one target) would satisfy the Detection Agent's `port_scan` rule (Section 10.3, which only counts distinct ports, not distinct hosts) but would **not** satisfy the Correlation Agent's `coordinated_scan` rule (Section 10.4, Rule 1), which specifically requires ≥5 distinct hosts. Assert exactly one `coordinated_scan` incident.
- `multistage_sample.pcap` — a scan (as above or single-host) followed by a malicious DPI-backed exploit attempt against one of the scanned hosts, from the same `src_ip`, within the correlation window. Assert exactly one `multi_stage_attack` incident.
- `distributed_target_sample.pcap` — malicious/suspicious traffic against one `dst_ip` originating from ≥3 distinct `src_ip`s within the window, to cover Rule 5 (`distributed_target_attack`) end-to-end, since it's the one rule that can't be validated by any single-source test scenario above.

All incident assertions run within a defined timeout (e.g. 30s after replay completes, to allow for window-based correlation delay). Rules 3 (`repeated_malicious`) and 4 (`dpi_confirmed_scan`) are covered at the unit/integration level (Section 10.13 unit tests for Correlation) rather than requiring their own dedicated pcap, since they're variations on signal combinations already exercised by the scenarios above.

**Performance tests:**
- **Throughput:** replay a CICIDS2017 subset at max speed (`tcpreplay --topspeed`), measure the sustained flows/sec each agent can process before `sentinelmesh_queue_depth` grows unbounded — this is your headline "how fast does it actually run" number for the report.
- **Latency:** measure elapsed time from a flow-event's production timestamp to its corresponding detection/incident/action, report p50/p95/p99.
- **Soak test:** run the full pipeline continuously for 2+ hours under steady light benign traffic, monitoring container memory (`docker stats`) for leaks and confirming Redis keys expire correctly (no unbounded key growth over the soak period) — this is what proves the system is stable enough to actually demo live rather than just working in a 30-second test run.
