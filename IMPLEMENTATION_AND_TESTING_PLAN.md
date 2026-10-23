# Open-Source VM+SIEM Platform — Implementation & Testing Plan

**Source document:** `ARCHITECTURE_FINAL.md` (Status: Final v1.0)
**Plan status:** v1.0 — derived 1:1 from the architecture doc's 21 sections and §19 roadmap
**Audience:** an autonomous or semi-autonomous coding agent executing this build task-by-task
**Prime rule:** the architecture doc is the spec of record. Where this plan states a technical choice the architecture doc did not make (a library, a framework, a file layout), it is marked **[ASSUMPTION]** — the agent may substitute an equivalent only if it records the substitution in that task's Step Report (§A.3) with a reason. Every requirement, invariant, and named behavior in the architecture doc is binding and is **not** substitutable.

---

## Part A — Agent Operating Protocol

### A.1 Non-negotiables

1. **No task is DONE without an executed test run.** Code review, static reasoning, or "this should work" is never sufficient. Every task's Step Report must include actual command output (or a faithful transcript of it) — exit code, test counts, pass/fail breakdown.
2. **No silent scope reduction.** If a task's acceptance criteria can't be met, the task is `BLOCKED`, not quietly redefined to something easier. Report the blocker; do not mark DONE against a lowered bar.
3. **No merge-and-move-on.** A task is only closed once its own tests pass AND it does not regress any previously-passing test in the same phase's suite. Run the full phase suite, not just the new test file, before closing a task.
4. **No fabricated results.** If a tool, dependency, or environment isn't available to actually run a test, say so explicitly in the Step Report as `UNVERIFIED` — never report a pass that wasn't observed.
5. **Security- and correctness-critical invariants (listed in §A.8) are hard stops.** A task that would violate one is `BLOCKED` pending human review, not implemented "for now."
6. **One task, one branch, one commit series.** Do not batch unrelated tasks into a single commit. Traceability from commit → Task ID → architecture section is required.

### A.2 Definition of Done (applies to every task, every phase)

A task is DONE only when **all** of the following hold:

- [ ] Deliverable(s) listed for the task exist at the specified path(s) and are committed.
- [ ] Every test listed under "Required Tests" for the task exists, runs, and passes.
- [ ] The task's "Acceptance Criteria" are each individually verifiable from test output (not asserted from memory).
- [ ] Lint/type-check/static-analysis for the touched language is clean (no new warnings introduced).
- [ ] No `TODO`/`FIXME` left in the diff without a corresponding tracked follow-up task ID.
- [ ] The Step Report (§A.3) has been produced and includes real command output.
- [ ] No invariant in §A.8 is violated by the change (explicitly checked, not assumed).

If any box is unchecked, the task's status is `BLOCKED` or `PARTIAL` — never `DONE`.

### A.3 Step Report Template (mandatory, verbatim structure, one per task)

```
## Step Report — <Task ID>: <Task title>

**Phase:** <phase number/name>
**Architecture section(s) implemented:** <e.g. §6.3 Flow 1, Flow 3>
**Status:** DONE | PARTIAL | BLOCKED

### What was built
<1–5 sentences, concrete, no marketing language>

### Files changed/created
- path/to/file — <one-line purpose>
- ...

### Commands run
```
<exact commands, e.g. go test ./... -run TestIdentityResolver -v>
```

### Test results
<pasted/transcribed real output — test names, pass/fail, counts, duration>
Summary: <N passed> / <M total>, coverage: <X%> (if measured)

### Acceptance criteria check
- [x]/[ ] <criterion 1> — evidence: <which test/line proves it>
- [x]/[ ] <criterion 2> — evidence: ...

### Deviations from spec
<None, or: what was changed vs. this plan/the architecture doc, and why>

### Invariant check (§A.8)
<Which invariants apply to this task, and explicit confirmation each still holds>

### Open risks / follow-ups
<None, or: new Task IDs filed and why>

### Next task
<Task ID this unblocks or leads into>
```

No task's work is considered reportable in any other format. If the interface running the agent cannot show raw terminal output, the report must say so and mark results `UNVERIFIED` rather than omit the section.

### A.4 Escalation / stop conditions

Stop and request human input — do not guess — when:

- The architecture doc is ambiguous or silent on something a hard-stop invariant (§A.8) depends on.
- A task would require destructive action on shared state (dropping a production-shaped migration, rotating a real credential, deleting audit history) — even in a dev environment, pause and confirm scope.
- A required external service/feed (NVD API, CISA KEV, FIRST EPSS, a cloud provider) is unreachable and no fixture/mock exists yet — do not fabricate response data as if it were real; build the fixture explicitly and label it as such.
- Two architecture sections appear to conflict. Flag both section numbers and stop rather than picking one silently.
- A test can only be made to pass by weakening the assertion below what the architecture doc specifies (e.g., loosening the false-merge bias, allowing a criticality override to loosen a deadline). This is always a stop, never a judgment call.

### A.5 Version control & traceability

- Branch naming: `phase<N>/<task-id>-<short-slug>` (e.g. `phase5/p5-3-bod2604-baseline`).
- Commit message first line: `[<Task ID>] <summary>` — body references the architecture section(s) implemented.
- One task = one PR (or one atomic commit set if PRs aren't in use). No task's diff should span into another task's deliverables without a note in "Deviations from spec."

### A.6 Test pyramid & layout

```
/tests
  /unit/<service>/...         # pure logic, no network/db/container, run on every commit
  /integration/<service>/...  # real Postgres/NATS/etc. via docker-compose, run pre-merge
  /contract/...                # interface-conformance suites (ScannerAdapter, TicketingAdapter,
                                #   AssetIdentityResolver, IdentitySignal) run against every implementation
  /security/...                # isolation-escape, fail-open, credential-scope, digest-pinning checks
  /e2e/...                     # cross-service flows (Phase D matrix), run nightly + pre-release
```

Coverage gates **[ASSUMPTION — adjust only with justification in a Step Report]**:
- Risk Engine deterministic logic (§10 Step 1, Step 2): **100% branch coverage** — this is a lookup table; every branch must be exercised, no exceptions.
- Identity Resolver merge/split logic (§6): **≥95% branch coverage**, given false-merge cost is asymmetric and high.
- Everything else: **≥80% line coverage** for new code.

### A.7 Tooling baseline **[ASSUMPTION]**

| Concern | Choice | Notes |
|---|---|---|
| Core services language | Go (per architecture doc's own repeated "Build: Go" entries) | §4 build-vs-integrate table is authoritative on what's Go |
| ML component language | Python | LightGBM has no mature Go binding; §10 already implies Python |
| Go test stack | `go test`, `testify/assert`, `testify/require`, `gomock`/`uber-go/mock` | |
| Python test stack | `pytest`, `pytest-cov` | |
| API contracts | OpenAPI 3.1 (REST) for the public API layer (§16.1); internal service-to-service calls may use gRPC/protobuf if throughput requires it | doc does not mandate a protocol; REST+OpenAPI chosen for the widest external-integration compatibility given §16.1's webhook/API-first framing |
| DB migrations | `golang-migrate` or `atlas`, versioned SQL files, no ORM-generated schema drift | |
| Message bus | NATS JetStream (doc lists "NATS or Kafka" — NATS chosen as the lighter-weight default; keep the interface abstract per §17 extensibility principle so Kafka remains swappable) | |
| CI | GitHub Actions (matches `codeload.github.com`/`github.com` already in the network allowlist) | |
| Container runtime for adapter isolation (§7) | gVisor (`runsc`) or Firecracker-backed microVMs as the sandbox runtime; rootless Docker/Podman as the minimum-viable fallback if a stronger sandbox isn't available in the target environment | doc mandates isolation and least privilege, not a specific runtime — the security tests in §A.8/Phase 3 must pass regardless of which is chosen |

### A.8 Hard-stop invariants (checked in every relevant Step Report, never traded off)

| # | Invariant | Source |
|---|---|---|
| I1 | A merge above the deterministic tier never happens without a review-trail flag; only deterministic-tier matches auto-merge without review. | §6.3 Flow 1 |
| I2 | MAC and IP address are never used in the deterministic matching tier, only probabilistic, and an IP-based match's confidence must decay with age. | §6.3 Flow 3 |
| I3 | Every merge/split is reversible with full lineage preserved; nothing is hard-deleted for staleness, only archived. | §6.3 Flow 4, Flow 5 |
| I4 | Every integrated scanner engine runs in an isolated, least-privilege worker with only the credentials/egress that specific job needs — never in-process, never ambient. | §7, §17 |
| I5 | Every scanner container/binary is referenced by immutable digest, never a mutable tag. | §7 |
| I6 | CVSS v3.1 and v4.0 scores are never averaged or compared numerically; store full version + vector string. | §9 |
| I7 | The BOD 26-04 Step 1 baseline reproduces CISA's published 16-combination table exactly. | §10 Step 1 |
| I8 | The asset-criticality override (§10 Step 2) can only tighten a deadline, never loosen one, and every application is logged with tier + reason. | §10 Step 2 |
| I9 | EPSS and the LightGBM learned score only reorder findings *within* a BOD 26-04 tier; neither ever moves a finding across tier boundaries. | §10 |
| I10 | Wazuh alert suppression is never automatic on a timeout/error — fail-open (let the alert through) is the only allowed default on failure; suppression requires an explicit downstream decision with an audit trail. | §2, §11.2 |
| I11 | A raw secret-pattern match alone never triggers Critical-severity blast-radius escalation; only a verified-live credential does. | §14.1 |
| I12 | A scan job failure/timeout must be observably distinct from "zero findings" — never silently equivalent. | §17 |
| I13 | The image digest, not the pod/container instance, is the canonical software asset; scan history survives pod churn. | §14.2 |

---

## Part B — Global Conventions (build once in Phase 0, referenced by every later phase)

### B.1 Repository layout

```
/cmd/                       # main() entrypoints, one per deployable service
  /identity-resolver/
  /orchestrator/
  /risk-engine/
  /api-gateway/
  /wazuh-integrator/
/internal/
  /assets/                  # Asset, IdentitySignal, AssetIdentityResolver + impls
  /adapters/                # ScannerAdapter implementations, one package per tool
  /normalize/                # common finding schema + mappers per adapter
  /risk/                    # BOD 26-04 engine, criticality override, EPSS ranking
  /remediation/             # TicketingAdapter + implementations, SLA/elimination policies
  /verification/            # closed-loop rescan scheduler
  /secrets/                 # Gitleaks integration, live-credential verifier, blast-radius correlation
  /graph/                   # GUAC client, runtime CTE queries
  /siem/                    # Wazuh CDB-list generator, FIM event consumer
/ml/lightgbm-ranker/         # Python: feature pipeline, training, serving, retrain/rollback
/schemas/                   # JSON Schema (finding, asset, etc.), OpenAPI spec, protobufs if used
/migrations/                # versioned SQL
/deploy/
  /compose/                 # docker-compose.yml for local/eval
  /helm/                    # Helm chart for k8s
/tests/                     # per §A.6
```

### B.2 Interfaces to implement verbatim (copied from architecture doc; do not redesign)

```go
type IdentitySignal interface {
    SignalType() string          // "mac_address", "agent_uuid", "cloud_arn", "image_digest", "fqdn"
    Value() string
    Confidence() float64
}

type AssetIdentityResolver interface {
    Resolve(ctx context.Context, signal IdentitySignal) (assetID string, err error)
}

type ScannerAdapter interface {
    Supports(asset Asset) bool
    Scan(ctx context.Context, asset Asset) (FindingsBatch, error)
    Name() string
}
```

```go
// Not given verbatim in the architecture doc, but required by §12/§17 — define in Phase 0:
type TicketingAdapter interface {
    CreateTicket(ctx context.Context, f Finding) (ticketID string, err error)
    UpdateTicket(ctx context.Context, ticketID string, update TicketUpdate) error
    CloseTicket(ctx context.Context, ticketID string, reason string) error
    Name() string
}
```

**Contract test suite (Phase 0 deliverable, reused every phase after):** any concrete implementation of these four interfaces must pass a shared conformance test suite in `/tests/contract/`. A new adapter is not DONE until it passes the relevant conformance suite, not just its own bespoke tests.

### B.3 Common finding schema (formalize §9's JSON example as `/schemas/finding.schema.json`)

Required fields, enums, and nullability exactly as specified in §9:

- `cvss` is nullable at the object level (not just individual sub-fields) — a finding can have zero CVSS data.
- `cvss.source` enum: `NVD | CNA | ADP | null`.
- `nvd_enrichment_status` enum: `full | lowest_priority | not_scheduled` — no other values, no null (§9 schema design notes: this must always be set so "not yet scored" is distinguishable from "will not be scored").
- `ssvc` enum: `track | track_star | attend | act | null`.
- `vex_status` enum: `not_affected | affected | fixed | under_investigation | null`.
- `status` enum: `open | resolved | reopened | accepted_risk | suppressed_vex`.
- `dedup_hash` = `hash(asset_id + vulnerability_id + component)` — implement as a pure, deterministic function with its own unit tests (same inputs → same hash, across process restarts).

**Phase 0 test:** a JSON Schema validator round-trips the exact example object from §9 of the architecture doc without error, and rejects a mutated copy missing `nvd_enrichment_status` or using an out-of-enum `status`.

### B.4–B.7 (data store, messaging, security, observability conventions)

- **Postgres:** one schema per bounded context (`assets`, `findings`, `risk`, `remediation`); every migration is forward-only and reviewed for reversibility notes even if not auto-reversible.
- **NATS subjects:** `signals.<source_type>`, `scans.jobs.<status>`, `findings.<event>`, `siem.fim.<event>`, `kev.updates` — fixed at Phase 0, not invented ad hoc per phase.
- **Secrets:** every credential lives in OpenBao; adapter configs reference a secret path, never an inline value. CI includes a static check that fails the build if a config file contains what looks like an inline credential.
- **Observability:** every scan job emits structured logs (`job_id`, `asset_id`, `adapter`, `duration_ms`, `status`, `findings_count`) and Prometheus metrics `scan_job_duration_seconds{adapter=...}`, `scan_job_failures_total{adapter=...,reason=...}` — required specifically because §17 calls out timeout-vs-zero-findings as a silent-failure risk (ties to invariant I12).

---

## Part C — Phased Implementation Plan

Each phase lists: objective, preconditions, tasks (with deliverables/tests/acceptance criteria), and phase exit criteria. Phase numbering matches §19's roadmap table.

---

### Phase 0 — Foundations: scope, data model, API contracts

**Objective:** stand up everything Part B describes so every later phase has a fixed foundation to build against.
**Preconditions:** none.

| ID | Task | Deliverable(s) | Required tests | Acceptance criteria |
|---|---|---|---|---|
| P0-1 | Repo scaffold | Directory tree per §B.1, empty `go.mod`/module boilerplate, `Makefile` or task runner with `test`, `lint`, `build` targets | `make test` runs (zero tests, exit 0); `make lint` runs clean on scaffold | CI pipeline green on an empty scaffold commit |
| P0-2 | Core entity schemas | `/schemas/asset.schema.json`, `/schemas/finding.schema.json` (§B.3), `/schemas/vulnerability.schema.json`, `/schemas/secret_finding.schema.json`, `/schemas/image_digest.schema.json`, `/schemas/attestation.schema.json`, `/schemas/software_inventory_item.schema.json` (the 7 entities named in §19 Phase 0) | Schema-validator unit test per schema: valid fixture passes, one deliberately-broken fixture per required-field fails | All 7 schemas exist, validate their own worked example, reject a broken example |
| P0-3 | Interfaces + contract test harness | `IdentitySignal`, `AssetIdentityResolver`, `ScannerAdapter`, `TicketingAdapter` Go interfaces (§B.2) + `/tests/contract/` harness (currently zero implementations, harness runs against a trivial in-memory fake to prove the harness itself works) | Contract harness test passes against the in-memory fake for each interface | Harness fails clearly (not silently skips) when a required method is missing from a fake implementation |
| P0-4 | Local infra | `docker-compose.yml` with Postgres, NATS (JetStream enabled), object storage (e.g. MinIO for §15.3) | `docker compose up -d && docker compose ps` — all services healthy | All 3 services report healthy status; Postgres accepts a test connection; NATS accepts a test publish/subscribe round-trip |
| P0-5 | Migrations baseline | `/migrations/0001_init.sql` creating `assets`, `identity_signals`, `findings`, `scan_jobs`, `tickets`, `criticality_tags` tables per §15.1 | Migration applies cleanly to a fresh DB; a second `migrate up` is a no-op | `\dt` in psql shows all 6 tables after migration |
| P0-6 | OpenAPI skeleton | `/schemas/api/openapi.yaml` with the 7 entities as schemas, no endpoints implemented yet | OpenAPI lint (e.g. `spectral`) passes with zero errors | Lint clean; file parses as valid OpenAPI 3.1 |
| P0-7 | NATS subject registry | `/schemas/subjects.md` documenting the fixed subject list (§B.5) | N/A (documentation) | Every later phase's tasks reference a subject from this list; no phase invents a new subject without updating this file |

**Phase 0 exit criteria:**
- [ ] `make test lint build` all pass from a clean checkout.
- [ ] `docker compose up` brings up a fully healthy local environment in under 2 minutes.
- [ ] All 7 entity schemas validate their worked examples.
- [ ] Contract test harness exists and is proven against fakes.

---

### Phase 1 — Collection / Discovery Layer (§5)

**Objective:** get raw, source-tagged identity signals flowing onto `signals.*` NATS subjects from all channels in §5. This phase does **not** implement correlation (that's Phase 2) — every signal is allowed to create a naive duplicate asset for now if Phase 2 isn't ready; the point is signal production and shape correctness.
**Preconditions:** Phase 0 done.

| ID | Task | Deliverable(s) | Required tests | Acceptance criteria |
|---|---|---|---|---|
| P1-1 | Repository discovery (§5.1) | `internal/assets/discovery/repo/` — GitHub/GitLab/Bitbucket webhook receiver; manifest detector (`package.json`, `go.mod`, `pyproject.toml`, `Cargo.toml`, `Gemfile`) | Unit: table-driven test, one row per manifest type plus a multi-manifest repo, asserting correct ecosystem tag set; Integration: simulated webhook payload → `signals.repo` message published within 500ms | Every manifest type in §5.1 maps to the right ecosystem tag; webhook-driven (no polling loop present in the code) |
| P1-2 | Cloud & Kubernetes discovery (§5.2) | CloudQuery config + sync job; Steampipe ad-hoc query config; `CloudDiscoveryAdapter` interface wrapping both | Integration: CloudQuery sync against LocalStack (or provider sandbox) populates ≥1 expected table with >0 rows; unit: adapter interface swap test (mock plugin substituted without touching call sites) | Event-driven (CloudTrail/EventBridge) **and** periodic full reconciliation both present and independently testable (two separate test cases) |
| P1-3 | Host discovery (§5.3) | Active (nmap/masscan wrapper), passive (Zeek/NetFlow consumer), agent-based (Fleet/osquery heartbeat consumer, AD/LDAP bulk sync) — three separate signal producers | Unit: each producer emits a well-formed `IdentitySignal` fixture; Integration: a scan-averse simulated host (firewalled, active probe fails) is still discovered via the passive path | Passive path independently discovers a host that the active path fails to reach (this is the specific capability §5.3 calls out) |
| P1-4 | Container discovery (§5.4) | Registry webhook (push-triggered) + K8s/Docker runtime watcher; OCI label parser for `org.opencontainers.image.source` | Unit: digest extraction correctness on fixture image manifests; unit: OCI label parse correctly links image → source repo | A running pod's signal always resolves to an image-digest identity, never a pod-name identity (ties into I13, enforced fully in Phase 2/9) |
| P1-5 | Passive/endpoint discovery — Wazuh (§5.5) | Wazuh custom integration script + HTTP receiver endpoint on the platform side | Integration: simulated `syscollector` payload POSTed to the receiver → correctly-shaped `IdentitySignal` on `signals.wazuh` | 200 response; signal contains hostname/IP/MAC/OS/package fields from the fixture payload |
| P1-6 | Directory & infrastructure import (§5.6) | AD/SCCM/hypervisor import connector(s) | Unit: sample AD export (LDIF or mock API response) parses into correctly-typed signals (domain SID as identity key) | Domain SID, not hostname, is the primary key extracted for AD-sourced signals |
| P1-7 | Code & supply-chain collection plumbing (§5.7) | Routing stub that will hand off to Phase 3/8 adapters — this task only wires the plumbing, not the scanners themselves | Unit: a repo signal with a `Dockerfile` present is flagged for later container-scan routing; a `pyproject.toml` repo is flagged for SCA routing | Flags match the ecosystem-detection logic from P1-1 exactly (no divergent second implementation) |
| P1-8 | Cross-cutting: contract compliance | N/A (verification task) | Contract test suite from P0-3 run against every producer built in P1-1..P1-6 | Every producer's output passes the `IdentitySignal` contract suite — zero exceptions |

**Phase 1 exit criteria:**
- [ ] All six discovery channels (§5.1–§5.6) produce at least one real or fixture-driven signal that passes the `IdentitySignal` contract suite.
- [ ] Passive host discovery is proven to catch what active discovery misses (P1-3's specific test).
- [ ] No discovery channel makes an "is this a duplicate asset" decision — that judgment is confirmed absent from this phase's code (grep/code-review gate, since §5 explicitly reserves that decision for §6).

---

### Phase 2 — Identity Resolver (§6)

**Objective:** implement the 5-flow tiered correlation model. This is called out in the architecture doc as the single most architecturally important component — treat its test suite as the highest-scrutiny suite in the whole project (100%/95% coverage gate per §A.6).
**Preconditions:** Phase 1 done (need real signal shapes to correlate).

| ID | Task | Deliverable(s) | Required tests | Acceptance criteria |
|---|---|---|---|---|
| P2-1 | Resolver skeleton + blocking (Flow 2) | `internal/assets/resolver/` implementing `AssetIdentityResolver`; blocking logic (same subnet/cloud account/OS family) | Unit: two signals in different blocks are never compared (mock/spy on the comparison function asserts zero cross-block calls); benchmark: comparison count scales with block size, not total asset count | Comparison count for N assets across K equal blocks is O(N²/K), verified against a computed expectation in the benchmark, not just "fast enough" |
| P2-2 | Deterministic tier (Flow 1a) | Exact-match logic for cloud instance ID, hardware serial, TPM/hardware UUID | Unit: exact match on each identifier type auto-merges with **no** review flag set; near-miss (off-by-one-char) does **not** match | Auto-merge only fires on exact equality; a fuzzed/near-miss identifier never falls into this tier |
| P2-3 | Probabilistic tier (Flow 1b) | Weighted scoring across hostname similarity, subnet, OS fingerprint, first-seen proximity | Unit: score-threshold table test — above threshold → provisional merge **with** review flag set; below threshold → no merge | Every probabilistic-tier merge carries a review flag in its DB record — a merge without one from this tier is a test failure |
| P2-4 | Heuristic tier / manual review queue (Flow 1c) | Routing of below-threshold matches to a manual-review queue table/view | Unit: below-probabilistic-threshold case never appears as merged in the asset table, only as a queue entry | Zero auto-merges originate from this tier, ever (invariant I1) |
| P2-5 | MAC/IP handling (Flow 3) | Confidence weighting that excludes MAC/IP from the deterministic tier; time-decay function for IP-based match confidence | Unit: three signals bearing three different randomized MACs for what fixture metadata says is one physical device must **not** auto-merge on MAC alone; unit: an IP-based match's computed confidence at t+30 days is strictly lower than at t+0 for identical other inputs | MAC and IP appear **only** in probabilistic-tier code paths (static/code-review check + test); confidence-decay test passes with a monotonically decreasing curve |
| P2-6 | Reversible merge/split with lineage (Flow 4) | `Merge(ctx, a, b, tier, confidence) (mergeID, err)` and `Unmerge(ctx, mergeID) error`; lineage table recording source records, tier, confidence, timestamp | Integration: merge two fixture assets → unmerge → both original records restored with their pre-merge finding/scan history intact, and the lineage record itself is retained (not deleted) | Post-unmerge record equality check against pre-merge snapshot (byte-for-byte on the fields that matter: findings, scan history, criticality tier) |
| P2-7 | Staleness handling (Flow 5) | Per-asset-class configurable staleness window; `stale` and `archived` states (archived ≠ deleted) | Unit: asset with no signal for N+1 days (per its class's configured window) transitions to `stale`; further-aged asset transitions to `archived` but remains queryable via an explicit "include archived" flag | A hard-delete code path for staleness does not exist in the codebase (grep gate); archived record is returned by a direct-lookup query 6+ months of simulated time later |
| P2-8 | Per-asset software inventory | Inventory merge logic — latest-reporting-channel wins per package | Unit: two sources report different versions of the same package at different timestamps; the newer timestamp's version wins in the merged inventory | Inventory read-back matches the most-recently-timestamped source, per package, in a multi-source fixture |
| P2-9 | Asset criticality classification | Tagging logic from exposure/data-classification/role inputs → tier | Unit: table-driven test covering at least: public-facing + payment data → highest tier; internal dev sandbox → lowest tier; and two mid-tier combinations | Tier output matches expected tier for every row of the table |
| P2-10 | Change tracking / new-asset signal | Emits a distinct "new asset" event (not just a row insert) onto `findings`/`assets` subject on first-ever sighting | Integration: first signal for a never-seen identity produces a "new asset discovered" event on the bus; a subsequent signal for the same asset does not re-fire it | Event fires exactly once per genuinely new asset |
| P2-11 | False-merge bias regression suite | A dedicated, larger fixture set of ambiguous cases (shared subnet + similar hostname + no deterministic identifier, etc.) | Property/fuzz-style test: **every** ambiguous case in the fixture set resolves to either "no merge" or "provisional merge with review flag" — **never** an unflagged merge | 0 unflagged merges across the entire ambiguous fixture set (this is the single most important test in the project — treat a failure here as a release blocker, not a flaky test to retry) |

**Phase 2 exit criteria:**
- [ ] Branch coverage ≥95% on `internal/assets/resolver/`.
- [ ] P2-11's ambiguous-case suite passes with zero unflagged merges.
- [ ] Unmerge (P2-6) round-trips correctly on at least 3 distinct fixture scenarios (deterministic-tier merge, probabilistic-tier merge, and a merge with attached findings/scan history).
- [ ] Invariants I1, I2, I3 explicitly checked and confirmed in the phase's consolidated Step Report.

---

### Phase 3 — Scan Orchestration + Adapter Layer + Isolation (§7, §8)

**Objective:** turn a canonical asset into dispatched, isolated, least-privilege scan jobs, with every adapter behind the `ScannerAdapter` interface.
**Preconditions:** Phase 2 done (need canonical assets to schedule against).

| ID | Task | Deliverable(s) | Required tests | Acceptance criteria |
|---|---|---|---|---|
| P3-1 | Orchestrator core | `cmd/orchestrator/` — job queue consumer off NATS, routing logic | Unit: table-driven routing test covering every row of §8's routing table (host→network scanner; `pyproject.toml`/`uv.lock`→`uv audit`; `go.mod`→`govulncheck`; `package.json`→`npm audit`; `Cargo.toml`→`cargo audit`; `Gemfile`→`bundler-audit`; multi-language→OSV-Scanner V2; repo with both `package.json` and `Dockerfile`→SCA **and** container adapters) | Every row of the routing table produces the exact adapter set specified; the multi-adapter case produces ≥2 adapters, not a first-match-wins single pick |
| P3-2 | Isolated execution model (§7) | Per-job sandboxed worker launch (container/microVM per §A.7's runtime choice), scoped credential injection | Security: attempt disallowed egress from inside a running adapter sandbox → denied; security: two concurrent adapter jobs for different assets never share an injected credential (credential-scope test); unit: adapter never runs in-process or as an ambient host subprocess (code-path assertion) | Disallowed-egress attempt fails (non-zero exit / connection refused) in the security test; credential-scope test finds zero cross-job credential overlap |
| P3-3 | Digest pinning enforcement | CI static check scanning all adapter image references | Static check: any adapter config using a mutable tag (`:latest`, a branch name, etc.) instead of `sha256:<digest>` fails the build | CI fails on a deliberately-introduced mutable-tag fixture; passes on all real configs |
| P3-4 | Template/signature feed cadence | Config-driven pull schedule for Nuclei templates / OpenVAS community feed (not always-latest) | Unit: config validation rejects an "always pull HEAD" configuration; integration: feed puller respects the configured interval (simulated clock) | Feed pull only occurs on the configured cadence in the simulated-clock test, not on every job |
| P3-5 | Scheduling windows & concurrency | Maintenance-window enforcement for active/production scans; concurrency limiter; always-on path for passive/agent signals; push+nightly cadence for SCA | Unit: a production-tagged host scan requested outside its configured window is deferred, not run; unit: passive signal processing is never gated by the window check; integration: SCA job fires on push and again on the nightly sweep, verified as two distinct triggers | Out-of-window active scan is provably deferred (queued state, not executed state) in the test |
| P3-6 | Adapter: network & host (Greenbone/OpenVAS, Nuclei) | `internal/adapters/greenbone/`, `internal/adapters/nuclide/` implementing `ScannerAdapter` | Contract suite (P0-3) passes; fixture-based unit test parses a sample tool JSON output into the pre-normalization shape | Contract suite green; `Supports()` returns true only for host-type assets |
| P3-7 | Adapter: container/SBOM point-in-time (Trivy, Grype, Syft) | `internal/adapters/trivy/`, `grype/`, `syft/` | Contract suite passes; fixture output parses correctly; `--vex`/built-in VEX flag wired through (tested fully in Phase 4) | Contract suite green |
| P3-8 | Adapter: SCA per ecosystem | One adapter per row of §8's SCA routing table | Contract suite passes per adapter; each adapter's `Supports()` correctly gates on its manifest file | 6/6 SCA adapters (uv audit, govulncheck, npm audit, cargo audit, bundler-audit, OSV-Scanner V2) pass contract suite independently |
| P3-9 | Adapter: secret detection (Gitleaks, pattern stage only) | `internal/adapters/gitleaks/` — detection only, **no** escalation logic here (that's Phase 10) | Contract suite passes; unit test confirms this adapter's output alone never sets a Critical severity field | Explicit negative test: raw Gitleaks output never carries a Critical/escalated marker (ties to I11, fully enforced in Phase 10) |
| P3-10 | Silent-failure observability (I12) | Structured logging + Prometheus metrics per job (§B.7) | Integration: a deliberately-timed-out adapter run produces a `status=failed,reason=timeout` metric/log entry distinguishable from `status=success,findings_count=0` | The two states are asserted as distinct in a single test that triggers both and diffs the emitted telemetry |

**Phase 3 exit criteria:**
- [ ] All 8+ adapters (2 network/host, 3 container/SBOM, 6 SCA, 1 secrets) pass the shared contract suite.
- [ ] Digest-pinning CI check is active and demonstrated to fail on a bad fixture.
- [ ] Isolation security tests (P3-2) pass — no ambient credential sharing, no disallowed egress.
- [ ] Invariants I4, I5, I12 explicitly confirmed.

---

### Phase 4 — Normalization, OpenVEX, DefectDojo Aggregation (§9)

**Objective:** map every adapter's raw output to the common finding schema, apply OpenVEX suppression, dedup, and push into DefectDojo.
**Preconditions:** Phase 3 done.

| ID | Task | Deliverable(s) | Required tests | Acceptance criteria |
|---|---|---|---|---|
| P4-1 | Per-adapter normalizers | `internal/normalize/<tool>.go` mapping each Phase 3 adapter's output → `/schemas/finding.schema.json` | For every adapter: fixture-in → schema-valid finding out (schema validation test per adapter) | 100% of adapters from Phase 3 have a passing normalizer test |
| P4-2 | CVSS version handling (I6) | Storage of full vector + version string; explicit rejection of cross-version comparison | Unit: attempting to numerically compare a v3.1 score and a v4.0 score for the same CVE raises/returns an explicit error, never a silent number | Cross-version comparison test fails loudly if attempted; passes when versions match |
| P4-3 | `nvd_enrichment_status` tri-state logic | Mapping from feed metadata → `full \| lowest_priority \| not_scheduled` | Unit: fixture CVEs covering all three states map correctly; invariant test — a finding is never `cvss=null` **and** `nvd_enrichment_status=full` simultaneously (contradiction check) | Contradiction check fails the build if violated |
| P4-4 | OpenVEX suppression | Trivy `--vex` / Grype native VEX consumption wired through; custom `openvex/go-vex` generator for reachability-proven `not_affected` cases | Unit: a finding with an upstream `not_affected` VEX doc auto-transitions to `status=suppressed_vex` with zero manual step; unit: `govulncheck` reachability=false triggers programmatic VEX generation → same auto-suppression | Both the "consume" and "generate" paths independently produce `suppressed_vex` without manual intervention in their respective tests |
| P4-5 | Dedup | `dedup_hash` implementation + collapse-on-match logic preserving multiple `source_tool` entries | Unit (named exactly): `test_dedup_collapses_govulncheck_and_osv_scanner_same_finding` — two fixture findings, same asset+component+CVE, different tools → one record, both tools listed, neither overwritten | Post-dedup record's `source_tool` list contains both original tools |
| P4-6 | DefectDojo integration | API client pushing normalized findings; product-hierarchy mapping (team/app, not just hostname) | Integration (mocked or sandbox DefectDojo instance): push fixture finding → verify it's retrievable via DefectDojo's API under the correct product | Pushed finding is queryable back from DefectDojo with matching `dedup_hash`/external ID and correct product/team association |

**Phase 4 exit criteria:**
- [ ] Every Phase 3 adapter has a passing normalizer test.
- [ ] I6 cross-version comparison guard is in place and tested.
- [ ] Both OpenVEX paths (consume + generate) demonstrated.
- [ ] Named dedup test (P4-5) passes exactly as specified.

---

### Phase 5 — Risk Scoring Engine (§10, Steps 1–2 and EPSS ranking; LightGBM deferred to Phase 11 per §19)

**Objective:** implement the BOD 26-04 deterministic baseline, the criticality override, and EPSS-based intra-tier ranking, with full explainability output.
**Preconditions:** Phase 4 done (needs normalized findings with SSVC/exposure/KEV fields populated).

| ID | Task | Deliverable(s) | Required tests | Acceptance criteria |
|---|---|---|---|---|
| P5-1 | BOD 26-04 four-variable lookup table | `internal/risk/bod2604.go` — pure function `(exposure, kev, automatable, techImpact) → deadlineTier` | **Named test (I7):** `test_bod2604_matches_cisa_published_table` — all 16 combinations checked against CISA's published table values | 16/16 combinations match exactly; 100% branch coverage on this function per §A.6 |
| P5-2 | Fail-safe conservative defaults | Missing-input handling: unresolved exposure → treated as publicly exposed; unresolved automatability → treated as automatable | Unit: `test_missing_exposure_defaults_to_public`; `test_missing_automatability_defaults_to_automatable` | Both named tests pass; no other missing-input path defaults toward leniency |
| P5-3 | Criticality override (Step 2) | `internal/risk/criticality_override.go` — one-directional tightening only, logged with tier+reason | **Property test:** for randomized (base deadline, criticality tier) pairs, `output_deadline <= base_deadline` always holds, with equality when tier is not high-value/mission-critical; every non-equal application produces an audit record | Property test run across ≥1000 randomized cases with zero violations; audit record schema check passes |
| P5-4 | EPSS ingestion & intra-tier ranking | Daily bulk CSV pull job; ranking applied only within a tier | **Named test:** `test_epss_never_changes_bod_tier` — varying EPSS score for a fixed finding never changes its assigned BOD tier, only its rank position among same-tier findings | Test passes across a range of EPSS values from 0.0 to 1.0 |
| P5-5 | SSVC/Automatable/Technical-Impact ingestion | NVD API + CISA Vulnrichment ADP parser | Unit: fixture NVD/Vulnrichment payloads parse into correct `Automatable`/`TechnicalImpact` values | Parser output matches fixture-expected values for at least one payload per SSVC bucket |
| P5-6 | Continuous re-evaluation | Event-driven recompute on exposure change and on new KEV entries (via `kev.updates` subject) | Integration: simulated "asset exposure flips to private" event → deadline recomputed and lengthens without a new scan; simulated new-KEV event for an existing finding → deadline recomputed and shortens | Both directional tests pass with no scan job triggered as a precondition |
| P5-7 | Explainability output | Composite score payload with `bod_tier`, `criticality_override` (nullable, with reason if present), `epss_rank`, `ssvc_bucket` fields | Schema validation test on the output payload | All four fields present on every scored finding, `criticality_override` correctly null when not applied |

**Phase 5 exit criteria:**
- [ ] `test_bod2604_matches_cisa_published_table` passes — this single test is a phase release gate; do not proceed to Phase 6 without it green.
- [ ] Criticality-override property test passes at ≥1000 cases, zero violations.
- [ ] EPSS tier-boundary test (P5-4) passes.
- [ ] Invariants I7, I8, I9 (I9 partially — full check completes in Phase 11) explicitly confirmed.

---

### Phase 6 — Remediation Workflow & Elimination Policies (§12)

**Objective:** ticket creation, SLA computation sourced from the Risk Engine, elimination policies, KPIs.
**Preconditions:** Phase 5 done.

| ID | Task | Deliverable(s) | Required tests | Acceptance criteria |
|---|---|---|---|---|
| P6-1 | `TicketingAdapter` implementations | Jira, ServiceNow implementations; GLPI/Zammad lightweight option — all behind the interface from §B.2 | Contract suite (mocked APIs) passes for each implementation independently | 3+ implementations pass identical contract suite with zero implementation-specific test logic leaking into the suite itself |
| P6-2 | Ticket population | Ticket pre-filled with owner, KEV/EPSS/SSVC, BOD tier + deadline, component/version, suggested fix version | Unit: fixture finding → ticket payload contains all required fields, none blank when source data exists | Field-presence test passes for a fully-populated fixture |
| P6-3 | SLA computation from Risk Engine | SLA sourced from Phase 5 output, not a flat rule | **Regression test:** two findings with identical CVSS but different KEV/exposure/criticality produce different SLA deadlines | Test asserts the two computed SLAs differ and each matches its own Phase 5 output, not a shared constant |
| P6-4 | Elimination policies | Auto-close on confirmed patch (rescan or CDB flip); auto-assign by owner; auto-escalate on SLA breach | Unit (fake clock): auto-close fires only after confirmation signal; auto-assign fires on ticket creation; auto-escalate fires exactly at breach time, not early/late | Each of the 3 policies has an independent passing test |
| P6-5 | Escalation cadence | SLA-breach alert to owner + manager on configurable cadence | Integration (fake clock): repeated cadence firing verified over simulated multi-day window | Alert count matches expected count for the configured cadence over the simulated window |
| P6-6 | KPIs | MTTR by severity tier, count open-past-SLA, elimination-rate trend | Unit: fixture finding-history dataset with hand-computed expected KPI values | Computed KPIs match hand-computed values exactly on the fixture dataset |

**Phase 6 exit criteria:**
- [ ] SLA regression test (P6-3) passes, proving SLA is not a flat CVSS-only rule.
- [ ] All 3 elimination policies independently tested and passing.
- [ ] `TicketingAdapter` conformance proven across ≥2 real-shaped implementations plus the lightweight option.

---

### Phase 7 — Closed-Loop Verification (§13)

**Objective:** targeted re-scan on resolution, recurrence handling, drift metric, feedback signal to the learned tier.
**Preconditions:** Phase 6 done (needs ticket/finding resolution events).

| ID | Task | Deliverable(s) | Required tests | Acceptance criteria |
|---|---|---|---|---|
| P7-1 | Scheduled targeted rescan | Orchestrator hook: on `status=resolved`, schedule a rescan 24–48h later, scoped to asset+component only | Unit: scheduled job's scope excludes all other components/findings on the asset; scheduled delay falls within the configured 24–48h window | Job payload asserted to reference exactly one asset+component pair, not a full-asset rescan |
| P7-2 | Recurrence handling | On rescan finding the vulnerability still present → `status=reopened`, original ticket reopened | **Named test:** `test_recurrence_reopens_original_ticket_not_duplicate` | Ticket count before and after recurrence is identical (1), and it's the same ticket ID, with a note attached explaining automated-verification failure |
| P7-3 | Drift metric | Per-team "fixed actually means fixed" rate | Unit: fixture verification history with known recurrence rate → computed metric matches hand-calculated value | Metric matches to within floating-point tolerance |
| P7-4 | Feedback signal to learned tier | Recurrence events published in a schema consumable by Phase 11's training pipeline | Contract test: event schema validates against the schema Phase 11 will later consume (define this schema now, in `/schemas/`, so Phase 11 doesn't redefine it) | Schema file exists and both phases' code reference the same file |

**Phase 7 exit criteria:**
- [ ] P7-2's named test passes — no duplicate-ticket regression.
- [ ] Rescan scoping (P7-1) proven narrow, not a full-asset rescan.

---

### Phase 8 — SIEM Correlation Layer / Wazuh (§11)

**Objective:** CDB-list-driven escalation, fail-open guarantees, FIM-triggered rescans.
**Preconditions:** Phase 5 done (needs current vulnerable+reachable computation); Phase 3 done (rescans dispatch through the orchestrator).

| ID | Task | Deliverable(s) | Required tests | Acceptance criteria |
|---|---|---|---|---|
| P8-1 | CDB list generator | Job producing "vulnerable + reachable" host list (IP or IP+CVE keyed), refreshed on a short interval | Unit: list format matches Wazuh CDB syntax exactly; integration: refresh interval respected under simulated clock | Generated file parses successfully when loaded by a real or stubbed Wazuh CDB loader |
| P8-2 | Wazuh correlation rule | Rule checking incoming alert IP against the CDB list, escalating in-rule-engine | Integration (Wazuh test/simulation tooling, or local rule-logic harness): IP present → escalated severity; IP absent → unmodified severity | Both branches produce the expected severity in the test harness |
| P8-3 | No-synchronous-bottleneck verification | Code-path audit + load test | Load test: alert-processing latency under CDB-refresh load stays within baseline (define baseline in the test, e.g. p99 unaffected by refresh cycles) | No blocking network call exists in the per-alert evaluation path (grep/code-review gate) and load test confirms no latency regression during a refresh |
| P8-4 | Fail-open guarantee (I10) | On-demand lookup path (used only for the rare non-CDB case) with timeout + circuit breaker | **Named test:** `test_fail_open_never_suppresses_on_error` — simulated timeout/error on the on-demand path → alert passes through at original severity, unmodified | Test explicitly asserts the alert is **not** suppressed and **not** silently downgraded on any error path |
| P8-5 | FIM-triggered rescan | Wazuh FIM event (e.g. SUID bit set) → message bus → orchestrator queues targeted rescan | Integration: simulated FIM event → targeted rescan job appears in the orchestrator's queue within a low-second-count latency bound | Latency assertion passes; rescan is scoped to just that host/path, not a full sweep |

**Phase 8 exit criteria:**
- [ ] `test_fail_open_never_suppresses_on_error` passes — treat any failure here as a release blocker.
- [ ] No blocking call found in the per-alert path (P8-3 code audit documented in the Step Report, not just asserted).
- [ ] FIM→rescan latency bound met and documented.

---

### Phase 9 — Software-Composition & Runtime Relationship Graph (§15.4)

**Objective:** GUAC-backed source→artifact→vulnerability graph; hand-built runtime CTE graph for digest→pod→host→exposure.
**Preconditions:** Phase 3 (Syft SBOMs) and Phase 1 (§5.4 digest↔repo link) done.

| ID | Task | Deliverable(s) | Required tests | Acceptance criteria |
|---|---|---|---|---|
| P9-1 | GUAC ingestion | Syft SBOMs + attestations fed into GUAC | Integration: fixture SBOM ingested → GUAC query returns the expected source→artifact→vulnerability path | Query result matches expected path exactly for at least 2 fixture SBOMs of different ecosystems |
| P9-2 | Runtime relationship graph (Postgres CTEs) | Adjacency tables + recursive CTE query for digest→pod→host→exposure | Unit: recursive CTE against seeded fixture data returns the exact expected blast-radius set (both currently-running and historical) | Result set matches expected set exactly, including a case where the original pod no longer exists (I13) |
| P9-3 | Image digest as canonical asset (I13) | Enforcement that digest, not pod name/ID, is the join key everywhere in this graph | **Regression test:** pod terminated, new pod with identical digest created → vulnerability history for that digest is unbroken across the transition | Scan history query before and after pod churn returns identical vulnerability records for the digest |

**Phase 9 exit criteria:**
- [ ] Blast-radius query (P9-2) validated against a fixture with at least one terminated-pod case.
- [ ] I13 regression test passes.

---

### Phase 10 — Secrets Exposure & Supply-Chain Blast Radius (§14)

**Objective:** two-stage, verification-gated secret escalation; supply-chain provenance on the digest asset.
**Preconditions:** Phase 3 (Gitleaks adapter), Phase 9 (digest asset model) done.

| ID | Task | Deliverable(s) | Required tests | Acceptance criteria |
|---|---|---|---|---|
| P10-1 | Detection stage (no escalation) | Every Gitleaks hit logged; confirmed not to trigger blast-radius correlation alone | **Named negative test:** `test_unverified_secret_does_not_escalate` — raw pattern match alone → routes to human-review queue at Attend level, no Critical escalation | Test asserts both: (a) no Critical severity set, (b) no blast-radius query executed as a side effect |
| P10-2 | Verification stage | Live-credential check via safe, read-only provider API call | Unit (mocked provider): confirmed-live secret → proceeds to blast-radius correlation; confirmed-dead/rotated secret → does not | Both branches independently tested; dead-credential branch explicitly asserts no escalation (mirrors I11) |
| P10-3 | Blast-radius correlation on verified secrets | Cloud asset inventory (CloudQuery/NetBox) queried to find infra the credential unlocks; both repo and target infra escalated to Critical | Integration: verified-live fixture secret → both the repo asset and a fixture target infra asset show Critical severity after the pipeline runs | Both assets' severity fields confirmed Critical, sourced from the same verified event |
| P10-4 | Supply-chain provenance | Sigstore/cosign signature + SLSA attestation attached to the digest asset record | Unit: two fixture digests (one signed+attested, one unsigned) → blast-radius report differentiates them explicitly in its output | Report output for the two fixtures is provably different (not just internally, but in the user-facing/report-facing field) |

**Phase 10 exit criteria:**
- [ ] `test_unverified_secret_does_not_escalate` passes — release blocker if failing (this is I11 directly).
- [ ] Verified-secret escalation path (P10-3) demonstrated end-to-end on fixtures.

---

### Phase 11 — LightGBM Learned Tier (§10, learned-tier subsection)

**Objective:** train, validate, and safely deploy the intra-tier learned ranker, with rollback.
**Preconditions:** Phase 5 (baseline scoring) and Phase 7 (recurrence feedback schema) done; needs some accumulated labeled data (real or fixture) to train against.

| ID | Task | Deliverable(s) | Required tests | Acceptance criteria |
|---|---|---|---|---|
| P11-1 | Feature pipeline | `ml/lightgbm-ranker/features.py` — all BOD 26-04 variables, EPSS, CVSS (nullable), reachability, asset criticality, exposure, **plus** `nvd_enrichment_status` and CVSS-presence as explicit features | **Named test:** `test_model_does_not_conflate_unscored_with_low_score` — two fixture findings, one genuinely low-CVSS and one `not_scheduled`/null-CVSS, must produce distinguishable feature vectors, not the same encoded value | Feature vectors differ specifically on the enrichment-status/CVSS-presence dimensions between the two fixtures |
| P11-2 | Class imbalance handling | `scale_pos_weight` configured; conservative `num_leaves` | Config validation test asserting non-default imbalance handling is active, not left at library defaults | Test fails if `scale_pos_weight` is left at 1.0 (the imbalance-unaware default) on an imbalanced fixture dataset |
| P11-3 | Ranking scope (I9, full check) | Learned score applied only within a BOD tier | **Named test:** `test_lightgbm_never_crosses_bod_tier` — varying the learned score for a fixed finding across its full possible range never changes its BOD tier assignment | Test passes across the full score range on a fixed-tier fixture |
| P11-4 | Retraining + validation gate | Scheduled retrain triggered by accumulated feedback (Phase 7); held-out FPR/recall threshold check before promotion | Unit: retrain producing worse held-out FPR/recall than the current production model is **blocked** from deployment; a better retrain **is** promoted | Both branches tested with two fixture model artifacts (one deliberately worse, one better) |
| P11-5 | Rollback-capable deployment | Timestamped model versions; rollback command/endpoint | Integration: deploy model A → deploy model B → rollback → production serves model A's exact scores again on a fixed fixture input | Rollback test's post-rollback output matches model A's original output bit-for-bit on the fixture |
| P11-6 | Early-stage weighting | Composite score dominated by baseline tier when labeled-data volume is below a configured threshold | Unit: with a small fixture labeled-dataset, the learned-adjustment's contribution to the composite score is capped/small relative to baseline — measured directly, not asserted | Contribution ratio (learned : baseline) is below a documented cap in the low-data fixture, and rises in a separate high-data fixture |

**Phase 11 exit criteria:**
- [ ] `test_lightgbm_never_crosses_bod_tier` passes — this completes invariant I9 fully (Phase 5 covered the EPSS half).
- [ ] Retrain gate (P11-4) demonstrated to block a worse model.
- [ ] Rollback (P11-5) proven bit-exact.

---

### Phase 12 — API Layer & Presentation Layer (§16)

**Objective:** the platform's single integration point — API, webhooks, dashboards, RBAC, audit trail.
**Preconditions:** all preceding phases functionally done (this layer surfaces everything built so far).

| ID | Task | Deliverable(s) | Required tests | Acceptance criteria |
|---|---|---|---|---|
| P12-1 | API implementation against OpenAPI spec | Endpoints implementing `/schemas/api/openapi.yaml` from Phase 0, extended per-phase as entities were added | Contract test: every endpoint response validates against its OpenAPI schema | 100% of defined endpoints pass schema-conformance tests |
| P12-2 | "Is this CVE+host vulnerable and reachable" query | The specific query named in §16.1, same question the CDB refresh (Phase 8) answers on a schedule, exposed as an on-demand API call | Integration: query against a known fixture state returns the same answer the CDB-list generator (P8-1) would compute for that state | Both paths agree on the same fixture — a divergence here is a correctness bug, not a style issue |
| P12-3 | Webhook events | `finding created`, `SLA breached`, `verification failed`, `new asset discovered`, `KEV addition re-scored` | Unit: one test per event type — triggering condition fires the correct payload to a subscribed test endpoint | 5/5 event types independently tested and firing correctly |
| P12-4 | RBAC | Role/asset-group/severity-scoped access control | Authorization matrix test: role × resource → allow/deny, covering at least 4 roles × 4 resource-severity combinations | Every cell of the matrix matches expected allow/deny |
| P12-5 | Audit trail completeness | Immutable audit record on every escalation, suppression, elimination-policy action, criticality-override decision | Integration: scripted scenario performing one of each action type → audit table row count matches action count exactly | No action type is unaccounted for in the audit table after the scripted scenario |
| P12-6 | Dashboards/KPIs | Presentation layer surfacing §16.2's dashboard list | Reuses Phase 6 KPI unit tests as the data-correctness layer; UI/rendering tests are out of scope for this backend-focused plan unless a frontend framework is chosen — **[ASSUMPTION: flag as a separate frontend task stream if a UI framework decision hasn't been made; do not silently skip]** | Dashboard data endpoints return values matching Phase 6's independently-verified KPI computations |

**Phase 12 exit criteria:**
- [ ] P12-2's cross-check against Phase 8's CDB logic shows zero divergence.
- [ ] Audit-trail completeness test (P12-5) shows 1:1 action-to-audit-record mapping.
- [ ] RBAC matrix fully green.

---

### Phase 13 — Hardening, Compliance Scanning, eBPF Reachability (§17, evaluation phase per §19)

**Objective:** per the roadmap's own framing — "evaluate deliberately, don't default to building." This phase is a spike-and-decide phase, not an assumed full build.

| ID | Task | Deliverable(s) | Required tests | Acceptance criteria |
|---|---|---|---|---|
| P13-1 | Compliance scanning spike | Run OpenSCAP/Lynis **and** Prowler/Powerpipe against a test environment; comparison memo | Spike is time-boxed; deliverable is a decision memo with a recorded Go/No-Go, not necessarily shipped code | Memo exists, includes false-positive rate and integration-effort estimate for each candidate, and an explicit recommendation |
| P13-2 | eBPF reachability spike (Tetragon/Deepfence) | Same spike format as P13-1 | Same as above | Same as above |
| P13-3 | Conditional full integration | **Only if** P13-1/P13-2 produced a Go decision | If Go: implement as a new `ScannerAdapter` following the exact Phase 3 pattern (contract suite, digest pinning, isolation, scheduling windows) | New adapter passes the same contract/security suite as every Phase 3 adapter — no shortcut path for a "later phase" tool |

**Phase 13 exit criteria:**
- [ ] Decision memos exist for both spikes regardless of outcome.
- [ ] Any resulting adapter meets the identical bar Phase 3 set — this phase does not get a lighter test bar just because it's later in the roadmap.

---

## Part D — Cross-Phase Test Traceability Matrix

| Invariant | Primary phase | Named test | Also touches |
|---|---|---|---|
| I1 | Phase 2 | P2-11 ambiguous-case suite | — |
| I2 | Phase 2 | P2-5 MAC/IP tests | — |
| I3 | Phase 2 | P2-6 unmerge round-trip | — |
| I4 | Phase 3 | P3-2 isolation security tests | — |
| I5 | Phase 3 | P3-3 digest-pinning CI check | — |
| I6 | Phase 4 | P4-2 CVSS version guard | — |
| I7 | Phase 5 | `test_bod2604_matches_cisa_published_table` | — |
| I8 | Phase 5 | P5-3 property test | Phase 12 (P12-5 audit trail) |
| I9 | Phase 5 (EPSS half) + Phase 11 (LightGBM half) | `test_epss_never_changes_bod_tier`, `test_lightgbm_never_crosses_bod_tier` | — |
| I10 | Phase 8 | `test_fail_open_never_suppresses_on_error` | — |
| I11 | Phase 10 | `test_unverified_secret_does_not_escalate` | Phase 3 (P3-9) |
| I12 | Phase 3 | P3-10 | — |
| I13 | Phase 9 | P9-3 regression test | Phase 1 (P1-4) |

Before declaring the project release-ready, re-run every test in this table as one consolidated suite (`make test-invariants` **[ASSUMPTION: name this target explicitly in Phase 0's Makefile]**) — a green run of this specific subset is the final go/no-go gate, independent of the per-phase suites already having passed individually, since regressions can be introduced by later phases touching shared code.

---

## Part E — Non-Goals (do not build; flag and stop if a task starts drifting here)

Per §2 of the architecture doc, out of scope for v1 — if any phase's work starts requiring one of these, stop and escalate rather than quietly expanding scope:

- A proprietary SAST engine competing with Semgrep/CodeQL on analysis depth (ingest their output only).
- A proprietary scan engine or vulnerability signature database.
- Full EDR/XDR-style endpoint response.
- OT/ICS scanning.

---

## Part F — Glossary (acronyms used throughout this plan, for an agent without prior context)

| Term | Meaning |
|---|---|
| BOD 26-04 | CISA Binding Operational Directive 26-04 — four-variable vulnerability prioritization model |
| EPSS | Exploit Prediction Scoring System (FIRST.org) |
| KEV | CISA Known Exploited Vulnerabilities catalog |
| SSVC | Stakeholder-Specific Vulnerability Categorization |
| VEX | Vulnerability Exploitability eXchange |
| SBOM | Software Bill of Materials |
| SCA | Software Composition Analysis |
| CDB list | Constant database list (Wazuh's local lookup-list mechanism) |
| FIM | File Integrity Monitoring |
| SLSA | Supply-chain Levels for Software Artifacts |
| MTTR | Mean Time To Remediate |
| GUAC | Graph for Understanding Artifact Composition |
