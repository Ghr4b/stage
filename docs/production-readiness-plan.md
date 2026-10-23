# Tijeri Production Readiness Plan

**Status:** In progress (foundational code and deployment hardening; not production approved)  
**Purpose:** Track the work required to turn the current prototype into a complete, supportable internal vulnerability-management platform. Update the checkboxes as work is completed; do not mark a phase complete until its acceptance criteria pass.

## Agreed Requirements

- Initial deployment uses Docker Compose on a dedicated company Linux server. Do not build a Kubernetes deployment now; keep containers and configuration portable so Kubernetes can be added later.
- Tijeri deploys and operates its own PostgreSQL, NATS, Wazuh, DefectDojo, Dependency-Track, and production-mode secrets service.
- Tijeri provides provider-neutral OIDC login, with issuer and group-to-role mapping configured for the company's SSO provider when identified. Do not require a vendor-specific implementation.
- Network discovery/scanning covers company CIDRs explicitly approved by the network/security owners, with exclusions and safety limits. “All company networks” must be represented as an approved CIDR inventory, not an unrestricted scanner target.
- Scan worker capacity adapts to the server's available CPU and memory but stays within configurable hard limits and leaves resources for the platform and host.
- Recovery objectives: RPO no greater than one hour; RTO no greater than four hours.

## Progress Overview

| Phase | Status | Exit condition |
| --- | --- | --- |
| 0. Inventory and acceptance | Not started | Every advertised capability is classified and has an owner and acceptance test. |
| 1. Reliable Compose deployment | In progress | A clean host install, restart, upgrade, and uninstall behave predictably. |
| 2. Security and identity | In progress | SSO, authorization, webhook trust, secrets, TLS, and scan scope are enforced. |
| 3. Durable runtime and data | In progress | Jobs, artifacts, migrations, and integrations survive service and host restarts. |
| 4. Complete product workflows | In progress | No advertised workflow depends on a stub or simulated behavior. |
| 5. Operations and recovery | In progress | Monitoring, backups, restore, capacity, and support procedures meet agreed objectives. |
| 6. Automated quality and release | In progress | CI gates every supported build and release artifact. |
| 7. Staging and company pilot | Not started | End-to-end and operational acceptance gates pass on the target network. |

## Phase 0: Inventory and Acceptance

- [ ] Build a feature matrix from `README.md`, `ARCHITECTURE_FINAL.md`, `IMPLEMENTATION_AND_TESTING_PLAN.md`, schemas, and API routes. For each promise, record implementation status, required services/tools, owner, and test evidence.
- [ ] Search production code for simulation comments, TODO/FIXME markers, no-op functions, in-memory-only state, ignored errors, and unimplemented interfaces. Classify each as implement, remove, or explicitly defer; do not leave advertised functionality silently stubbed.
- [ ] Define a supported scanner matrix: scanner name/version, asset types, required binary/runtime, credentials, expected output, timeout, resource profile, and failure behavior.
- [ ] Define an integration matrix for Wazuh, DefectDojo, Dependency-Track, NATS, PostgreSQL, and the selected secrets service, including authentication and supported versions.
- [ ] Define supported deployment host OS, CPU/RAM/disk baseline, expected asset volume, retention, network zones, approved scan CIDRs/exclusions, and installation prerequisites with the infrastructure/network owners.
- [ ] Convert the agreed RPO/RTO into backup frequency, retained recovery points, restore procedure, and a timed recovery exercise.

**Exit criteria:** Every feature in public documentation is classified; all go-live features have observable acceptance tests; approved network scope and target-host baseline are recorded.

## Phase 1: Reliable Compose Deployment

- [ ] Split development/lab configuration from production configuration. Keep weak credentials, vulnerable lab targets, and permissive networking confined to an explicitly named lab profile.
- [ ] Remove destructive `.env` rewriting from `run.sh`. Preserve user configuration and generated credentials safely; add a complete `.env.example`, protect real secret files from version control, and fail with clear errors when required values are missing or weak.
- [x] Make the startup script and Compose settings agree on HTTPS, public readiness, service names, exposed URLs, and the `orc` profile. Replace startup polling loops with bounded waits, diagnostics, and non-zero exit codes.
- [ ] Add a preflight command that checks Docker/Compose versions, required environment settings, TLS certificate/key validity and hostname, required external networks, disk space, and port conflicts before changing services.
- [ ] Use a company-trusted certificate or terminate TLS at a documented reverse proxy. Do not ship a self-signed localhost certificate as the production identity. Enforce HTTPS, secure cookies, and trusted-proxy handling.
- [ ] Publish only the user-facing HTTPS endpoint to company networks. Keep database, NATS monitoring, Redis, Vault, Wazuh indexer, and internal service ports on private Compose networks; document approved firewall flows.
- [ ] Pin all container images to supported versions (and immutable digests for releases), pin Python and scanner dependencies, and define an update cadence. Remove `latest` from production configuration.
- [ ] Run application containers as non-root with minimal capabilities, read-only filesystems where feasible, explicit writable data mounts, resource limits, and no Docker socket access. Grant scanner workers only the network access and privileges their scanner requires.
- [ ] Add separate Compose profiles for app, bundled integrations, and optional lab services while preserving a one-command supported production install.
- [ ] Document first install, configuration, startup, shutdown, upgrade, rollback, log access, and clean removal. Ensure the documented commands match the actual Compose paths and profiles.

**Exit criteria:** On a fresh supported Linux host, an operator can install from documented steps, receive a bounded and accurate readiness result, restart without losing configuration/data, and upgrade or roll back without manual file edits.

## Phase 2: Security, SSO, and Scan Authorization

### Identity and API authorization

- [ ] Implement the provider-neutral OIDC Authorization Code flow with PKCE for browser users. ID-token verification, issuer/audience/signature/expiry, state, nonce, secure HttpOnly cookies, CSRF checks, and in-process logout revocation are implemented; persistent revocation, live provider, key-rotation, and callback validation remain.
- [ ] Configure and validate OIDC against a standards-compliant test IdP and representative Entra ID, Okta, and Keycloak configurations. Issuer discovery, client credentials, callback, and configurable ID-token groups claim are implemented; provider claim shape and operational SSO setup remain unverified.
- [ ] Define and enforce server-side roles: administrator, scan manager/operator, analyst, and read-only/auditor. Deny by default. Enforce both action permissions and asset/network scope on every API route, not only in the UI.
- [ ] Provide short-lived, scoped, revocable API credentials for service integrations. Hash/store credentials safely, support rotation/revocation, audit their use, and never expose a shared server token to browser JavaScript.
- [ ] Add a documented, tightly restricted break-glass administrator process and audit all identity/role changes.
- [ ] Add authorization tests for every route and role, including object/asset scoping, expired/revoked credentials, missing claims, and default-deny behavior.

### Webhooks, secrets, and network controls

- [ ] Require authenticated webhooks. Use per-integration signing secrets or mutual TLS, timestamp/replay protection, constant-time signature validation, request-size limits, idempotency keys, and audit records.
- [ ] Validate all webhook payload fields, accepted state transitions, referenced asset/finding IDs, and content types. Reject malformed or oversized requests before database or queue work.
- [ ] Implement outbound webhook destination controls: HTTPS by default, host allowlist, DNS/IP checks that block loopback/link-local/metadata and unauthorized private ranges, redirect limits, secret redaction, signed payloads, bounded retries, and a dead-letter view. This prevents subscriptions from becoming an SSRF path.
- [ ] Replace Vault development mode/root token with a production-mode, persistent, TLS-protected secrets server (select and pin Vault or OpenBao). Add least-privilege policies, service identities, audit logging, secret rotation, and recovery/unseal procedure appropriate to the selected service.
- [ ] Use separate database users and databases for Tijeri, DefectDojo, and Dependency-Track. Require strong credentials and TLS where traffic leaves the host; restrict each account to its own database.
- [ ] Configure NATS authentication/TLS and subject-level permissions. Keep monitoring endpoints private and authenticated.
- [ ] Record approved CIDRs and exclusions in managed configuration. Validate CIDR containment, reject ambiguous hostnames for active scanning, prevent targets outside approved ranges, and ensure API users can scan only scopes granted to their role.
- [ ] Add per-target and per-subnet rate limits, maintenance windows, scan profiles, exclusions for sensitive systems, and an emergency stop for active scans. Audit who approved and launched each scan.
- [ ] Ensure errors and logs never contain API tokens, passwords, private keys, or scanner credentials.

**Exit criteria:** Unauthenticated or unauthorized callers cannot read sensitive data, trigger scans, submit feedback, or impersonate integrations. OIDC group membership maps to least-privilege roles; active scans are constrained to approved targets.

## Phase 3: Durable Runtime, Data, and Capacity

### Jobs and scanner workers

- [ ] Separate the API/control plane from scanner execution. The API validates and records a job; a scheduler places it on a durable queue; worker containers claim and execute it.
- [ ] Use NATS JetStream with persistent file-backed stream, durable consumers, synchronous acknowledgements after scan processing, bounded retries, and dead-letter publication. Live persistence/ack and retry-exhaustion/dead-letter tests pass; operator-visible dead-letter handling, queue metrics, restart/shutdown tests, and production sizing remain.
- [ ] Define durable job states and transitions: accepted, queued, running, succeeded, partial, failed, canceled, and timed out. Persist timestamps, retry count, scanner version, scope, owner, and bounded failure details.
- [ ] Make job submission and result ingestion idempotent. Deduplicate repeated events and avoid losing a completed result if a worker or API restarts.
- [x] Replace per-event unbounded scan execution with a bounded global worker pool and a bounded worker-shutdown wait. Add per-scanner, per-team, per-target limits, fairness, and tested drain/redelivery behavior before production.
- [ ] Build resource-aware capacity using container/cgroup CPU and memory limits, measured scanner resource profiles, a reserved host/platform budget, and configurable minimum/maximum workers. A conservative cgroup-memory/CPU-based baseline and operator cap now exist; expose queue depth, capacity, throttling, and worker health.
- [ ] Set scanner-specific execution timeouts, output limits, temporary-disk quotas, process cleanup, and resource limits. Capture stdout/stderr safely and distinguish scanner failure from a successful zero-finding scan.
- [ ] Package every enabled scanner and required runtime, or create versioned per-tool worker images. Startup now reports missing capabilities, and full Compose fails closed when an enabled scanner binary is absent; the runtime image still needs the complete matrix.
- [ ] Run untrusted scanner inputs in restricted worker containers with non-root users, read-only roots, isolated temporary directories, no host mounts/secrets by default, and narrowly scoped egress.

### Persistence and schema evolution

- [ ] Replace the default `/tmp` object store with durable S3-compatible storage (self-hosted MinIO or an agreed equivalent). Add encryption at rest, versioning/retention, checksums, atomic writes, access controls, backup coverage, and safe object-key validation.
- [ ] Put persistent PostgreSQL, NATS/JetStream, object storage, and required integration state on explicit named volumes or separately managed services. Postgres, NATS JetStream storage, Wazuh indexer, and Tijeri's local object directory now use named volumes; durable scan consumers, all service state, disk monitoring, and capacity alerts remain.
- [ ] Replace the custom rerun-every-file migration behavior with a versioned migration system and migration ledger. Use locking, explicit transaction strategy, checksums, useful failure reporting, and tested forward/rollback procedures; never silently ignore arbitrary SQL errors.
- [ ] Run migrations as an explicit one-off initializer before app readiness. Back up before schema upgrades and verify upgrade from the previous supported release on a copy of production-like data.
- [ ] Add database indexes/constraints based on measured access patterns, connection-pool budgets, query timeouts, retention/cleanup jobs, and database health checks.
- [ ] Make object-store and database operations honor request/job contexts. Do not continue a scan as successful after required asset/finding writes fail.

**Exit criteria:** Queue and result state survive process/container restarts; worker crashes lead to bounded retry or a visible terminal failure; storage and migrations preserve data through restart and supported upgrade tests.

## Phase 4: Complete Every Product Workflow

- [ ] **Wazuh ingestion:** A custom manager image mounts the local rules and wires JSON `rescan_trigger` alerts to the HTTPS Tijeri webhook using CA verification; the endpoint validates agent fields, persists an audit event, and publishes a targeted job. Indexer admin credentials now bootstrap and rotate through a file-backed Compose secret, verified in an isolated container. Still replace the manager's `admin` login with a least-privilege account, add integration-scoped webhook credentials and replay/idempotency protection, canonical agent mapping, and end-to-end manager/indexer/event delivery and retry verification.
- [ ] **DefectDojo feedback:** Verify webhook authenticity; validate finding identity and permitted status changes; persist actor, source, timestamp, and evidence; publish a durable feedback event; handle duplicate delivery safely. Do not let untrusted events trigger model training.
- [ ] **Webhook subscriptions:** Persist subscriptions in the database; validate event types and owners; encrypt per-destination secrets; implement delivery attempts, exponential backoff, signing, disable/delete, delivery history, and dead-letter/replay controls. Enforce destination restrictions on every DNS resolution and redirect.
- [x] **ML retraining:** Automatic retraining is disabled in the orchestrator until feedback-to-training-data merge, label provenance, holdout evaluation, model promotion, and rollback are implemented. Feedback storage remains active; the current retrainer stub is not presented as production behavior.
- [ ] **Scanner adapters:** For every supported adapter, test command construction, tool/version detection, timeouts, cancellation, exit-code semantics, malformed output, partial output, credential handling, and normalization. Ensure failures cannot appear as “no vulnerabilities.”
- [ ] **Asset and finding pipeline:** Verify asset persistence precedes dependent findings, stable identity and deduplication are correct, stale findings are handled, partial scanner failures remain visible, and results are safely retried into DefectDojo/Dependency-Track.
- [ ] **DefectDojo integration:** Add bounded HTTP timeouts, TLS verification, retry policy for transient failures, idempotent product/engagement/import behavior, response validation, rate limiting, and integration health status.
- [ ] **Dependency-Track integration:** Use separately configured frontend/API OIDC settings where enabled, separate production database credentials, upload retry/idempotency, health reporting, and tests against the supported version.
- [ ] **VEX and object APIs:** Validate VEX schema and provenance, prevent path traversal, enforce access policy, define immutable artifact semantics, and test generated documents with independent validators.
- [ ] Update README and API/OpenAPI documentation so each advertised feature accurately describes its prerequisites, limits, security model, and supported versions.

**Exit criteria:** Every advertised integration has a real end-to-end test; all simulated/no-op paths are implemented or removed from the supported feature set; failures are visible and recoverable.

## Phase 5: Operations, Observability, and Recovery

- [ ] Implement distinct liveness and readiness endpoints. `/health` and `/ready` now exist; readiness checks Postgres and NATS, but still needs object-storage and required-integration checks.
- [ ] Implement graceful shutdown: stop accepting new work, stop queue claims, cancel or drain running scans within a configurable deadline, flush NATS, close HTTP listeners, and close database connections. HTTP shutdown and worker cancellation are implemented; bounded drain/flush and SIGTERM evidence remain.
- [ ] Add consistent structured logs with request/job/asset correlation IDs, actor identity, integration name, and redaction. Use rotation/central log forwarding and documented retention.
- [ ] Export Prometheus-compatible technical and business metrics: API latency/errors, auth failures, scan queue depth/age, worker capacity/utilization, scanner success/failure/timeout rates, findings throughput, DB/NATS/object storage health, and webhook delivery failures. Protect metrics endpoints.
- [ ] Add dashboards and actionable alerts for failed scans, stuck/old queue jobs, missing scanners, low disk, database saturation, expired certificates, backup failures, repeated auth failures, and integration outages.
- [ ] Add an administrator status page/CLI that shows dependency health, enabled scanners, last successful feeds/backups, queue health, image versions, and configuration validation without exposing secrets.
- [ ] Define data retention and cleanup for findings, scan output, uploaded SBOMs, audit logs, webhook attempts, and ML datasets/models. Document legal/security review where sensitive evidence is stored.
- [ ] Automate encrypted PostgreSQL backups and WAL archiving at a cadence meeting RPO <= 1 hour; back up object data, NATS persistent state where required, secrets-service recovery material, and deployment configuration without plaintext secrets.
- [ ] Write and rehearse restore procedures to a clean host. Demonstrate maximum one-hour data loss and service restoration within four hours; record evidence and fix any missed objective.
- [ ] Document single-host Compose failure limitations, spare-host restore process, disk sizing, resource sizing, patch windows, certificate renewal, secret rotation, service upgrades, and escalation contacts.

**Exit criteria:** Monitoring detects dependency and scan failures; operators can diagnose health without shell access to application internals; a timed restore proves the agreed RPO/RTO.

## Phase 6: Automated Quality and Release

- [ ] Add CI for supported Go versions: formatting, `go vet`, unit/contract tests, race-sensitive packages, build, and coverage reporting. A starter Go/ML test-and-build workflow exists; Python lint/type checks, dependency locks, coverage, and race-sensitive CI remain.
- [ ] Add Compose configuration validation and clean-host smoke tests, including secret-missing/weak-secret rejection, HTTP-to-HTTPS behavior, readiness, migrations, OIDC callback, and shutdown.
- [ ] Add integration tests using isolated Postgres, NATS JetStream, object storage, and mock OIDC/webhook providers; add end-to-end tests for each supported external integration where feasible.
- [ ] Add authorization matrix tests for every endpoint and asset scope; webhook signature/replay/SSRF tests; scanner containment and rate-limit tests; migration upgrade tests; and backup-restore tests.
- [ ] Add performance/load tests for expected asset counts and scan mixes. Measure scanner CPU/memory/network impact, database growth, queue latency, and API response times on the target class of server. Define a supported capacity envelope from evidence.
- [ ] Add dependency, secret, static-analysis, container-image, license, and generated-SBOM checks. Pin and scan images; publish signed images and provenance for release artifacts.
- [ ] Produce versioned release artifacts and checksums. Maintain release notes, compatibility matrix, upgrade/rollback instructions, vulnerability response process, and dependency update policy.
- [ ] Remove generated binaries, scratch fix/test scripts, stale test output, and private/local test artifacts from release packaging. Verify repository ignores prevent accidental credential, certificate, and local-state commits.

**Exit criteria:** A change cannot be released unless required checks pass, artifacts are reproducible/traceable, and the release notes include compatibility and upgrade guidance.

## Phase 7: Staging and Company Pilot

- [ ] Deploy the release to a staging server matching the planned company host and network path. Configure OIDC with an authorized test tenant and map real group claims to the defined roles.
- [ ] Test all company-approved CIDRs in a staged or explicitly authorized window. Start with conservative scan profiles; coordinate with network/security owners and monitor target/network health.
- [ ] Verify every scanner/tool is present and versioned; run representative host, repository, container, cloud, and network scans as applicable. Confirm results and failures reach the UI and downstream integrations.
- [ ] Test service restarts, host reboot, database outage, NATS outage, object storage outage, webhook replay, certificate expiry/renewal, secret rotation, full disk, and worker exhaustion.
- [ ] Run a capacity test and tune adaptive concurrency using measured CPU/RAM and network impact. Configure hard limits, reserved resources, and a documented emergency stop before broad scanning.
- [ ] Run a security review of API authorization, OIDC, webhook trust, secret handling, network exposure, container privileges, data access, and audit trail. Remediate all critical/high findings before pilot.
- [ ] Complete a restore exercise and record measured RPO/RTO. Ensure the on-call/support owner can perform the procedure without relying on the original developer.
- [ ] Obtain operational acceptance from application owner, infrastructure, identity, database, and network/security owners. Expand the scan scope only after the initial pilot is stable.

**Final release gate:** All Phase 0–6 exit criteria pass; the pilot proves approved-scope scanning, access controls, integrations, recoverability, and resource safety; all known limitations are documented and accepted by the company service owner.

## Known Findings to Track

- [x] Fix `run.sh` protocol/readiness mismatch and stop it from overwriting `.env`; generated integration keys now live in a mode-0600 runtime file.
- [x] Render dashboard API values with safe DOM APIs, prevent the shared token from bypassing OIDC roles on user-facing APIs, and return discovery queue failures instead of false success.
- [x] Retry partial scanner results instead of acknowledging them as complete; count deadline failures toward the delivery cap and dead-letter after the configured attempt limit.
- [ ] Remove insecure production Compose defaults, broad host port publishing, Vault dev mode, and localhost self-signed API certificate.
- [ ] Complete OIDC/RBAC rollout: browser login, PKCE sessions, CSRF, role mapping, dashboard authentication, and rejection of the shared token on OIDC-protected APIs are implemented; test real providers and every route, add asset/network scope, persist session revocation, and replace shared machine-token authorization with scoped credentials.
- [ ] Add per-integration webhook credentials/signatures and replay protection. Wazuh `rescan_trigger` alerts now have a configured custom integration and verified HTTPS transport; shared-token scope, event deduplication, identity-to-asset mapping, delivery retry evidence, and full-stack tests remain.
- [ ] Persist webhook subscriptions and implement safe, retried outbound delivery.
- [ ] Replace temporary local object storage and finish queue operations. Scan requests now use JetStream file storage and durable consumers with bounded retry/dead-letter publication; object storage, dead-letter visibility/replay, metrics, and restart/failure tests remain.
- [ ] Install or package and validate all enabled scanner dependencies. Scan concurrency now has a bounded CPU/memory-aware worker pool and a configurable cap.
- [ ] Separate service databases/users; introduce versioned migrations and tested restore procedures. Fresh Postgres initialization now provisions separate app, DefectDojo, and Dependency-Track roles/databases; existing-volume migration and versioned ledger are not implemented.
- [ ] Implement the ML feedback data merge/evaluation/promotion path or disable automatic model retraining until it is trustworthy.
- [ ] Add readiness, exported metrics, CI/release controls, and production operating documentation.
