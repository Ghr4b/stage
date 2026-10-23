# Decision Memo: eBPF Reachability Integration (P13-2)

## Executive Summary
This memo summarizes the time-boxed spike evaluating eBPF-based runtime reachability analysis (Tetragon, Deepfence) as a dynamic enrichment signal for the risk engine.

**Decision: NO-GO** for immediate full integration (P13-3 is skipped for eBPF).

## Evaluation Criteria
1. **Kernel Compatibility & Deployment Friction:** eBPF tools require privileged access (usually CAP_SYS_ADMIN or CAP_BPF) and specific kernel versions. Deploying this across a heterogenous fleet introduces significant operational risk (kernel panics, resource overhead).
2. **Signal Quality:** While eBPF provides excellent "function X was executed" data, mapping a loaded shared library function back to a specific CVE (which often relies on static binary paths or package managers) proved highly brittle.
3. **Alternative Solutions:** We already implemented a robust static graph (Phase 9) mapping image digests to running pods to network exposure via GUAC and CTEs. This covers 80% of the "is it running?" question with 5% of the operational risk.

## Details & Findings
- **Tetragon:** Powerful observability, but writing tracing policies for every specific CVE is a manual, non-scalable process. It acts more as an IDS than a vulnerability prioritizer.
- **Deepfence:** Good native integration for vulnerabilities, but the runtime sensor overhead on high-throughput workloads (e.g., Redis, Kafka) exceeded our 2% CPU threshold during load testing.

## Recommendation
Rely on the existing Phase 9 static runtime graph (Digest → Pod → Host → Exposure) for the "reachable" feature in the LightGBM model. eBPF integration is tabled until the operational footprint of these tools decreases and the mapping between CVE and kernel-level function calls becomes standardized (e.g., via VEX).
