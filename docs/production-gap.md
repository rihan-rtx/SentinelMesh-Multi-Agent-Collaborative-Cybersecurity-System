# SentinelMesh — Production Gap Analysis

See Section 8 of `project-spec-final.md` for the full list.

This document will be expanded during Phase 6 for the final report.

## Intentional Non-Goals

| Feature | Why Not Built | Production Alternative |
|---------|---------------|----------------------|
| Line-rate capture (1Gbps+) | Scapy is adequate for demo-scale traffic | DPDK or eBPF/XDP |
| Kernel-bypass / SmartNICs | Out of scope for a software project | Specialized hardware |
| mTLS agent-to-agent auth | Isolated lab network; no adversarial infra | mTLS certificates per service |
| Kubernetes autoscaling | Docker Compose sufficient for demo | K8s with HPA |
| GDPR-grade payload redaction | Controlled lab data only | Encryption at rest, retention policies |
| Auto-executed blocking | Safety: never auto-block during demo | `recommend_block` + operator approval |
| ML-based classification | Rule-based is more explainable, easier to validate | Ensemble ML models |
| Distributed correlation | Single-site deployment | Cross-site state replication |
