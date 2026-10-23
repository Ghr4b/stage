# NATS Subject Registry

All NATS subjects used by the Tijeri platform. No phase may invent a new subject without updating this file.

Defined in Phase 0 per §B.5 of the architecture document.

---

## Signal Subjects

| Subject Pattern | Description | Producer(s) | Consumer(s) |
|---|---|---|---|
| `signals.repo` | Repository discovery signals (webhook-driven) | Repository discovery service (§5.1) | Identity Resolver (§6) |
| `signals.cloud` | Cloud resource discovery signals | CloudQuery sync / CloudTrail events (§5.2) | Identity Resolver (§6) |
| `signals.host.active` | Active host discovery signals (nmap/masscan) | Host discovery — active scanner (§5.3) | Identity Resolver (§6) |
| `signals.host.passive` | Passive host discovery signals (Zeek/NetFlow) | Host discovery — passive observer (§5.3) | Identity Resolver (§6) |
| `signals.host.agent` | Agent-based host discovery signals (Fleet/osquery) | Host discovery — agent heartbeat (§5.3) | Identity Resolver (§6) |
| `signals.container.registry` | Container image registry push signals | Registry webhook (§5.4) | Identity Resolver (§6) |
| `signals.container.runtime` | Container runtime discovery signals (K8s/Docker) | K8s/Docker runtime watcher (§5.4) | Identity Resolver (§6) |
| `signals.wazuh` | Wazuh syscollector endpoint signals | Wazuh custom integration (§5.5) | Identity Resolver (§6) |
| `signals.directory` | Directory/infra import signals (AD/SCCM/hypervisor) | Directory import connectors (§5.6) | Identity Resolver (§6) |

## Scan Subjects

| Subject Pattern | Description | Producer(s) | Consumer(s) |
|---|---|---|---|
| `scans.jobs.created` | New scan job dispatched | Orchestrator (§7) | Scan workers |
| `scans.jobs.started` | Scan job execution begun | Scan worker | Orchestrator, observability |
| `scans.jobs.completed` | Scan job completed successfully | Scan worker | Normalizer (§9), observability |
| `scans.jobs.failed` | Scan job failed or timed out | Scan worker | Orchestrator (retry logic), observability |

## Finding Subjects

| Subject Pattern | Description | Producer(s) | Consumer(s) |
|---|---|---|---|
| `findings.new` | New normalized finding created | Normalizer (§9) | Risk Engine (§10), DefectDojo sync |
| `findings.updated` | Existing finding updated (status change, re-score) | Risk Engine (§10), Verification (§13) | Remediation (§12), DefectDojo sync |
| `findings.resolved` | Finding marked resolved | Remediation (§12) | Verification layer (§13) — triggers rescan |
| `findings.reopened` | Finding reopened after failed verification | Verification (§13) | Remediation (§12) |

## SIEM Subjects

| Subject Pattern | Description | Producer(s) | Consumer(s) |
|---|---|---|---|
| `siem.fim.changed` | FIM file-integrity change event from Wazuh | Wazuh integrator (§11) | Orchestrator (§7) — triggers targeted rescan |
| `siem.fim.alert` | FIM alert requiring correlation | Wazuh integrator (§11) | SIEM correlation layer (§11) |

## KEV Subjects

| Subject Pattern | Description | Producer(s) | Consumer(s) |
|---|---|---|---|
| `kev.updates` | New entry added to CISA KEV catalog | KEV feed poller | Risk Engine (§10) — triggers re-evaluation |

## Asset Subjects

| Subject Pattern | Description | Producer(s) | Consumer(s) |
|---|---|---|---|
| `assets.new` | New canonical asset discovered (first-ever sighting) | Identity Resolver (§6) | Orchestrator (§7), dashboards |
| `assets.updated` | Asset metadata changed (exposure, criticality, software inventory) | Identity Resolver (§6) | Risk Engine (§10) — triggers re-evaluation |
| `assets.stale` | Asset transitioned to stale state | Identity Resolver (§6) | Dashboards, alerting |
| `assets.archived` | Asset transitioned to archived state | Identity Resolver (§6) | Dashboards |
