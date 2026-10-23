# Decision Memo: Compliance Scanning Integration (P13-1)

## Executive Summary
This memo summarizes the time-boxed spike evaluating the integration of compliance scanners (OpenSCAP/Lynis for host, Prowler/Powerpipe for cloud) into the Tijeri platform.

**Decision: NO-GO** for immediate full integration (P13-3 is skipped for compliance).

## Evaluation Criteria
1. **False Positive Rate:** Compliance scanners generate a massive volume of "misconfigurations" that are highly contextual (e.g., "root SSH disabled" might be an intentional break-glass configuration on certain isolated nodes).
2. **Integration Effort:** Mapping proprietary compliance rules (CIS benchmarks, STIGs) into Tijeri's `models.Finding` schema (which is optimized for CVEs/secrets) requires a fundamental schema expansion.
3. **Signal-to-Noise Ratio:** Injecting compliance failures into the primary remediation queues risks drowning out high-fidelity CVEs and verified secrets, violating the core thesis of the platform (reducing alert fatigue).

## Details & Findings
- **OpenSCAP / Lynis:** Host-level compliance checks produced ~200-400 findings per standard Ubuntu instance. False positive rate in a default environment was estimated at >60% without extensive baseline tuning.
- **Prowler / Powerpipe:** Cloud posture checks were higher fidelity but still generated significant noise regarding IAM least-privilege that required human context to resolve.

## Recommendation
Defer compliance scanning to a separate posture-management tool (CSPM). Do not ingest compliance findings into Tijeri's primary vulnerability queue at this time. If required in the future, compliance should be ingested into a parallel schema (`models.PostureFinding`) with its own non-disruptive SLA policies.
