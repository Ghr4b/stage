# Tijeri: Advanced Vulnerability Management Platform

Tijeri is a next-generation, asset-centric vulnerability management and orchestration platform. It is designed to act as the "brain" of a security operations center, ingesting raw data from a massive fleet of scanners, normalizing it, and prioritizing it deterministically using threat intelligence and machine learning.

This repository is an active prototype; `ARCHITECTURE_FINAL.md` describes the target architecture, not a claim that every feature is implemented. It is not yet approved for production or company-network scanning. Track go-live work in `docs/production-readiness-plan.md`.

## 🏗️ Architecture & Core Principles

The target architecture emphasizes:
1. **Asset-Centric, Not Scan-Centric**: Vulnerabilities are attached to long-lived canonical assets, deduplicated via intelligent hashing.
2. **Async-Over-Sync**: NATS events are currently core subscriptions; scan job delivery is not yet durable.
3. **Immutable Artifacts**: The current artifact store is local filesystem storage, not an S3-compatible immutable store.
4. **Least-Privilege Workers**: Scanner execution is in-process/subprocess based and is not yet isolated in worker containers.

## 📁 Repository Structure

- `cmd/orchestrator/`: The main entrypoint. Handles the event loop, NATS subscriptions, CDB list syncing, and API server initialization.
- `deploy/`: Infrastructure configuration.
  - `compose/`: Development infrastructure plus the guarded full-stack Compose deployment and its environment template.
- `wazuh/`: Custom Wazuh manager image, authenticated webhook integration, and correlation rules.
- `internal/`: Core platform logic.
  - `adapters/`: Scanner adapters; the production image does not yet package or validate every adapter's executable.
  - `api/`: The REST API and Webhook handlers.
  - `assets/`: Asset discovery and identity resolution (`AssetIdentityResolver`).
  - `defectdojo/`: DefectDojo GUI client for vulnerability aggregation.
  - `dependencytrack/`: OWASP Dependency-Track client for continuous SBOM monitoring.
  - `graph/`: GUAC (Graph for Understanding Artifact Composition) integration.
  - `models/`: Unified domain models (`Finding`, `Asset`, `CVSS`, `EPSS`, `AnalystFeedback`).
  - `normalize/`: VEX generation, deduplication, and schema normalization.
  - `remediation/`: Ticketing adapters for Jira, ServiceNow, and Zammad.
  - `risk/`: The Multi-Layered Risk Engine.
  - `secrets/`: Gitleaks integration and active credential verification.
  - `siem/`: Wazuh CDB list generator.
  - `store/`: Postgres database and Object Storage implementations.
  - `vault/`: Vault-compatible client code; dynamic secret retrieval is not yet wired into scanner configuration.
  - `verification/`: Automated patch verification logic.
- `ml/lightgbm-ranker/`: Python-based Machine Learning model for false-positive reduction.
- `schemas/`: Database schemas, NATS subjects, and architectural diagrams.
- `tests/`: End-to-End, Unit, and Contract tests.

## 🛠️ The Adapter Army (Scanners)

Adapters exist for scanners across multiple domains, but presence of an adapter does not mean its binary is installed or production-supported:
- **Container / SBOM**: Trivy, Grype, Syft.
- **Network / Host**: Greenbone (OpenVAS), Nuclei, TLS-Scan.
- **Software Composition Analysis (SCA)**: govulncheck (Go), uv audit (Python), npm audit (Node.js), cargo audit (Rust), bundler-audit (Ruby), osv-scanner (Multi-language).
- **Cloud Security Posture Management (KSPM)**: Prowler (AWS/Azure/GCP misconfigurations).
- **Secrets**: Gitleaks (Pattern matching), backed by active API verification.

## 🧠 The Risk Engine

Findings are not just labeled "Critical" or "High". They are passed through a deterministic pipeline to calculate an exact **SLA Deadline** and a **Risk Score**:
1. **BOD 26-04 Triage**: If a CVE is on the CISA KEV (Known Exploited Vulnerabilities) list, it gets a strict 14-day SLA. Otherwise, it falls back to CVSS-based SLAs (e.g., 30 days for High).
2. **SSVC (Stakeholder-Specific Vulnerability Categorization)**: Correlates the vulnerability's exploitation status with the underlying asset's mission-criticality to yield a decision (`track`, `attend`, `act`).
3. **EPSS (Exploit Prediction Scoring System)**: Ingests exploit probability scores. High EPSS percentiles can override standard SLAs to prioritize likely future attacks.
4. **Machine Learning (LightGBM)**: Re-ranks findings within their SLA tiers based on historical analyst feedback, pushing likely false-positives to the bottom of the queue.

## 🔄 Real-Time Integrations

### Wazuh SIEM
- **Inbound**: Full-stack Compose builds a custom Wazuh manager, mounts Tijeri's local rules, and forwards matching sensitive-file `rescan_trigger` alerts to Tijeri over verified HTTPS. Configure `TIJERI_WAZUH_WEBHOOK_URL` with a hostname covered by the Tijeri TLS certificate and `TIJERI_CA_CERT_FILE` with its issuing CA bundle. The existing shared bearer token authenticates delivery; per-integration credentials, replay protection, and deduplication remain open.
- **Indexer credentials**: The custom indexer image reads `WAZUH_INDEXER_PASSWORD_FILE` as a Compose secret, initializes indexer security on first start, and applies password rotations on restart. The manager reads the same secret. Create a private secret file with `install -d -m 700 deploy/compose/secrets`, then `umask 077; openssl rand -hex 32 > deploy/compose/secrets/wazuh-indexer-password`; set `WAZUH_INDEXER_PASSWORD_FILE` in `deploy/compose/.env` to that file's absolute path. Do not commit the secret. The manager currently connects as `admin`; replace this with a dedicated least-privilege account before production.
- **Outbound**: CDB synchronization code exists; deployment and rule behavior still require end-to-end validation.

### DefectDojo
- Pushes normalized findings into DefectDojo for a unified graphical view.
- Webhook feedback handling exists. Full-stack Compose requires the shared Tijeri API bearer token; per-integration signatures and replay protection are still missing. Feedback is stored, while automatic ML retraining is deliberately disabled until safe label merging and evaluation exist.

### OWASP Dependency-Track
- Pushes CycloneDX SBOMs to Dependency-Track for continuous supply-chain monitoring, ensuring zero-day detection without re-scanning.

### Secrets service
- The Compose Vault development container is lab-only. Production-mode OpenBao/Vault deployment, policies, and application integration remain unfinished.

## 📜 VEX Generation

Tijeri leverages advanced compiler analysis (like `govulncheck`) to prove when a vulnerability is unreachable in the call graph.
- When proven unreachable, the platform automatically generates a strictly compliant OpenVEX `not_affected` JSON document.
- Documents use the local filesystem object store today. It is not yet an immutable, backed-up production artifact store.

## Development and Deployment

- Use `make infra-up` and `make infra-down` for the isolated local development dependencies. Do not point the lab topology or unrestricted discovery at company systems.
- Run unit tests with `go test ./...` and build with `go build ./...`; Python feature tests use `make test-ml` after installing the pinned project requirements. Wazuh delivery tests run with `make test-wazuh`.
- Scanner adapters now report missing executables at startup. Full Compose requires all enabled adapter binaries and exits early if any are absent; the current runtime image still lacks part of that scanner matrix, so full Compose remains intentionally blocked until packaging is completed.
- The guarded full-stack launcher requires Docker Compose v2, a private `deploy/compose/.env` copied from `.env.example`, strong generated credentials, a company-trusted certificate matching `TIJERI_SERVER_NAME`, explicitly approved CIDRs, a pinned DefectDojo tag, a least-privilege Dependency-Track API key, OIDC settings, and a Wazuh callback URL/CA bundle trusted by the manager. It can be started with `./run.sh`; management UIs bind to loopback.
- Current PostgreSQL role/database provisioning runs only when the named volume is initialized. Existing volumes have no supported upgrade/migration procedure yet; back them up and do not run this changed configuration against existing data until that procedure exists.
- The launcher is not a production-readiness certification. OIDC login and group-based roles are implemented but need testing against the organization's IdP; durable scan jobs, complete scanner packaging, production secrets management, backups/restore, and release gates remain open. Consult `docs/production-readiness-plan.md` before any company-network deployment.

### Company SSO

The production Compose deployment requires an HTTPS OIDC provider using discovery metadata (for example, a compatible Entra ID, Okta, or Keycloak tenant). Register the exact `OIDC_REDIRECT_URL` callback, `https://<Tijeri-host>:8080/auth/callback`, at the provider. Configure `OIDC_ISSUER_URL`, client ID/secret, and a random `OIDC_SESSION_SECRET` of at least 32 characters in `deploy/compose/.env`.

Configure the provider to include the selected `OIDC_GROUPS_CLAIM` in its ID token, then map group names or IDs with comma-separated `OIDC_ADMIN_GROUPS`, `OIDC_OPERATOR_GROUPS`, and `OIDC_VIEWER_GROUPS`. Admins may run network discovery and manage webhook subscriptions; operators may use mutating APIs; viewers have read access. Unmapped users are denied. In production, OIDC protects user-facing APIs; the shared `TIJERI_API_TOKEN` is limited to service-authenticated webhook routes. Provider-specific claim issuance and the callback must be tested with the actual company tenant before rollout.
