# Repository Guidelines

## Project Structure & Module Organization

Tijeri is a Go vulnerability-management service with a Python ranking component. The executable entry point is `cmd/orchestrator/`; core packages and scanner integrations live under `internal/`. Go tests sit beside their packages, with additional contract, E2E, and schema tests under `tests/`. Supporting material is grouped in `schemas/`, `migrations/`, `config/`, `deploy/`, `localtest/`, and `docs/`. The ML code, its tests, and data are in `ml/lightgbm-ranker/`.

## Build, Test, and Development Commands

- `go test ./...` runs the Go test suite; `make test` is the Makefile alias.
- `go build ./...` compiles all Go packages; `make build` is the alias.
- `make lint` runs `go vet ./...`.
- `make test-ml` runs the Python feature tests with pytest (install `ml/lightgbm-ranker/requirements.txt` first).
- `make test-invariants` runs selected critical Go and ML regression checks.
- `go run ./cmd/orchestrator` starts the service locally.
- `make infra-up` starts local Compose dependencies; `make e2e` runs E2E tests against them. Finish with `make infra-down`.

## Coding Style & Naming Conventions

Format Go changes with `gofmt`; use idiomatic Go package names and exported identifiers, and name Go tests `*_test.go` with `Test...` functions. Keep Python code consistent with the surrounding files (four-space indentation); there is no repository-wide Python formatter command. Keep changes focused in the owning package and update schemas or migrations when data contracts change.

## Testing Guidelines

Add or update tests alongside changed Go packages; use `tests/contract/` for cross-package contracts and `tests/e2e/` for infrastructure-dependent flows. Run the narrow affected package tests first, then `go test ./...`. E2E requires the Compose services and database URL configured by the Makefile. ML changes should include pytest coverage and run `make test-ml`.

## Commit & Pull Request Guidelines

Git history is unavailable in this checkout, so no established commit convention could be confirmed. Use a short imperative subject (optionally `area: change`, such as `risk: tighten deadline calculation`). Pull requests should explain the behavior change, list validation commands and results, link related issues when applicable, and include screenshots only for user-visible changes.

## Security & Configuration

Use `.env.example` as the configuration reference; do not commit `.env`, credentials, certificates, or generated secrets. Keep local test credentials and infrastructure isolated to `localtest/` and development Compose configurations.
