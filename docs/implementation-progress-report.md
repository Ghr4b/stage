# Implementation Progress Report

**Status:** OIDC and durable scan-queue foundations are implemented and tested; Tijeri is **not production-ready** and should not yet be deployed as a company service.  
**Review date:** 2026-10-22

## Progress Made

- Hardened the launcher and full Compose deployment: required secrets, TLS checks, authenticated NATS, private service bindings, bounded resource settings, readiness checks, and database initialization for fresh volumes. Existing PostgreSQL volumes still need a tested upgrade path.
- Improved service startup and shutdown, API readiness and webhook validation, scan worker limits based on available CPU/memory, CIDR target validation, and local object-store permissions. Automatic ML retraining remains disabled until safe evaluation and feedback controls exist.
- Added provider-neutral OIDC authorization-code login with PKCE, state/nonce checks, signed HttpOnly sessions, CSRF protection, group-to-role mapping, and dashboard API authentication. Real provider configuration, exhaustive route/asset scoping, and company-tenant acceptance remain unverified.
- Replaced ephemeral scan-event subscriptions with a file-backed JetStream stream, durable consumers, bounded worker dispatch, synchronous acknowledgements, retry/dead-letter handling, and periodic processing heartbeats. Added an opt-in live JetStream persistence/ack integration test.
- Wired Wazuh `rescan_trigger` JSON alerts to Tijeri using a custom manager image and mounted local rules, verified HTTPS, a required CA bundle, and bearer authentication. Added Python and Go tests for request formation and durable event acceptance; full Wazuh runtime delivery remains unverified.
- Added a custom Wazuh indexer image that securely initializes the admin credential from a Compose secret and updates it on restart without replacing existing roles/configuration. A disposable-container test verified first boot, rejection of the image default password, and password rotation; the manager still uses the admin account pending least-privilege setup.
- Added a scanner executable inventory and startup capability preflight. The full Compose deployment now fails closed if any enabled adapter binary is missing, instead of appearing healthy while scans fail later; the runtime image still lacks much of the registered scanner matrix, so this gate currently blocks full Compose startup.
- Fixed reviewed vulnerabilities and failure reporting: dashboard values now use safe DOM APIs; when OIDC is enabled, the shared token cannot bypass user-role authorization; discovery reports queue errors; partial scanner failures retry; deadline failures count toward DLQ; logout revokes sessions in-process; shutdown uses one bounded deadline.
- Updated deployment guidance, CI scaffolding, and the production-readiness tracker. Corrected three stale selectors in `make test-invariants` so it runs the intended tests.

## Validation

- Passed: `go test ./...`, `go vet ./...`, `go build ./...`, and `go test -race ./internal/api ./internal/msgbus ./cmd/orchestrator`.
- Passed: `make test-invariants`, all 8 ML feature tests in an isolated temporary Python environment, and `bash -n run.sh`.
- Passed: live JetStream integration tests against a temporary NATS 2.10 container; persisted delivery was synchronously acknowledged, and a deadline-failed job retried five times before dead-lettering.
- Passed: focused API regressions for dashboard safe rendering, OIDC logout revocation and role checks, admin-token restrictions, and discovery queue failure reporting.
- Passed: seven Wazuh sender unit tests, focused Go API test for authenticated audit-and-queue acceptance, Wazuh custom-image build, and an isolated image check for script permissions/Python availability.
- Passed: scanner capability/preflight tests, `go vet` for the changed Go packages, Go formatting check, and full Compose YAML parsing without interpolation.
- Passed: built the custom Wazuh indexer image from the locally available base image; an isolated disposable container bootstrapped the secret, rejected `admin:admin`, and accepted a rotated password after restart while rejecting the prior password.
- Passed: full Compose YAML parsing without interpolation; integration values and actual manager startup were not exercised.
- Passed: full Compose config parsing and launcher syntax using temporary dummy settings. No production secrets or company settings were used.
- Not validated: company OIDC provider, full-stack startup, Wazuh manager/indexer and webhook event flow, DefectDojo/Dependency-Track flows, scanner image completeness, load, backup/restore, or company-network behavior. No full project stack was started.
- Review limitation: this checkout has no `.git` directory, so a working-tree diff and `git diff --check` were unavailable. The independent review covered current files, not a baseline diff.

## Independent Code Review

Two read-only subagent reviews found issues; fixes were added for the critical paths and focused tests cover several regressions:

- **Fixed in this pass:** stored XSS in dashboard dynamic rendering; the global machine token's access to OIDC-protected APIs; discovery returning success after queue publication failure; and partial scanner failures being acknowledged as complete. Retries now count timeouts toward the delivery cap, worker shutdown has a total deadline, and logout revokes the session in-process until expiry.
- **P1 — Retry idempotency remains incomplete.** A scan retried after a downstream integration error can create duplicate DefectDojo engagements/tests; make downstream writes idempotent before production.
- **P1 — Runtime image omits registered scanners.** The image installs only a subset of the tools registered by the orchestrator. Startup now reports missing tools and full Compose fails closed, but the binaries still need packaging and end-to-end scan verification (`Dockerfile:19`, `internal/adapters/capabilities.go`).
- **Wazuh credential status:** The indexer admin password now comes from a required file-backed Compose secret; isolated first-start and rotation checks pass. The manager still authenticates as `admin`, and manager/indexer plus event-delivery integration remain unverified; create a dedicated least-privilege account before production.
- **P2 — Runtime container runs as root.** Add a dedicated unprivileged user and verify scanner permissions and TLS-key access (`Dockerfile:19`).
- **Remaining auth limitation:** session revocation is process-local and is lost on restart; real-provider callback tests, complete route/asset scoping, and scoped/revocable service credentials remain.
- **Test gap:** add local OIDC callback tests, JetStream restart/shutdown/redelivery tests, and full Wazuh/DefectDojo/Dependency-Track flows. Live JetStream tests are opt-in via `NATS_TEST_URL`.

The final re-review verified the XSS, discovery, partial-scan, retry-cap, and bounded-worker fixes. It flagged the shared token's broad reach; the latest change rejects that token on all OIDC-protected routes, and the focused role test passes.

## Next Work, In Order

1. **Validate security end to end:** test OIDC with a standards-compliant provider and company tenant; cover every endpoint and asset scope; add scoped/revocable integration credentials and webhook replay/idempotency protection.
2. **Finish queue operations:** exercise restart, retry exhaustion, dead-letter visibility/replay, queue-full behavior, and bounded shutdown; expose queue health and durable job state.
3. **Make integrations real:** pin and install every scanner the orchestrator can select, or mark unavailable scanners clearly. Replace Wazuh manager's `admin` login with a dedicated least-privilege account, add scoped webhook auth and replay protection, and test Wazuh event delivery end to end.
4. **Harden runtime and data upgrades:** run as non-root with least privilege; add safe migrations for existing database volumes rather than relying on first-start initialization. Test upgrades from a populated prior database and document backup/restore with a successful restore drill.
5. **Prove operational readiness:** add metrics, actionable logs and alerts, resource/load tests, network allowlist and proxy checks, and CI checks for Compose and launcher configuration. Run full Compose integration/E2E and security checks using actual deployment settings before any pilot.

**Immediate next milestone:** verify Wazuh manager/indexer connectivity and full event delivery, replace the manager's `admin` login with least privilege, and package the complete scanner matrix. Then harden migrations/runtime privileges and add operational monitoring/recovery evidence. Keep production deployment blocked until the company identity provider and network policies are confirmed and the full pilot gates pass.
