# pcaps/

Curated PCAP files for testing and live demo.

## Files (to be created in later phases)

| File | Purpose | Phase |
|------|---------|-------|
| `demo_scenario.pcap` | Live demo: port scan → targeted exploit (Section 6, Phase 6) | Phase 6 |
| `benign_sample.pcap` | E2E test: ordinary traffic, expect zero incidents | Phase 4 |
| `portscan_sample.pcap` | E2E test: coordinated scan across ≥5 dst_ips | Phase 4 |
| `multistage_sample.pcap` | E2E test: scan → exploit from same src_ip | Phase 4 |
| `distributed_target_sample.pcap` | E2E test: ≥3 src_ips attacking one dst_ip | Phase 4 |

See Section 10.13 for exact test pcap specifications.
