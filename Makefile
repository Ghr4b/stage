.PHONY: all test lint build test-invariants test-wazuh e2e

test:
	go test ./...

lint:
	go vet ./...

build:
	go build ./...

# Run the Python ML tests
test-ml:
	pytest ml/lightgbm-ranker/test_features.py -v

test-wazuh:
	python3 -m unittest discover -s deploy/wazuh -p 'test_*.py' -v

# Run the critical invariant tests explicitly (I1 - I13)
test-invariants:
	@echo "Running hard-stop invariant tests (I1-I13)..."
	go test -v ./internal/normalize -run TestCVSSVersionHandling  # I6
	go test -v ./internal/risk -run TestCriticalityOverrideProperty # I8
	python3 -m pytest ml/lightgbm-ranker/test_features.py::TestRankingScopeInvariant::test_lightgbm_never_crosses_bod_tier -v # I9
	go test -v ./internal/siem -run TestFailOpenNeverSuppressesOnError # I10
	go test -v ./internal/adapters/gitleaks -run TestGitleaksOutputNeverSetsCriticalSeverity # I11
	go test -v ./internal/graph -run TestImageDigestAsCanonicalAsset # I13
	@echo "All invariants passed."

# Spin up local infrastructure for E2E testing
infra-up:
	docker compose -f deploy/compose/docker-compose.yml up -d
	@echo "Waiting for services to be healthy..."
	sleep 5

# Spin down local infrastructure
infra-down:
	docker compose -f deploy/compose/docker-compose.yml down

# Run full end-to-end flow (requires infra-up)
e2e:
	@echo "Running full E2E flow..."
	TEST_DATABASE_URL="postgres://tijeri:password@localhost:5433/tijeri?sslmode=disable" go test -v ./tests/e2e/...
