.PHONY: build build-all build-engine build-licenseserver test test-integration test-all test-integration-race test-system test-e2e test-e2e-license bench vet clean install run fmt lint deps db-up db-down db-reset container-build container-run container-stop container-build-licenseserver container-run-licenseserver container-stop-licenseserver container-build-engine container-run-engine container-stop-engine

# Variables (overridable)
POSTGRES_USER       ?= triton
POSTGRES_CONTAINER  ?= triton-db

# Build for current platform
build:
	@mkdir -p bin
	go build -o bin/triton main.go

# Build license server binary
build-licenseserver:
	@mkdir -p bin
	go build -o bin/triton-license-server cmd/licenseserver/main.go

# Build for all platforms
build-all:
	@mkdir -p bin
	GOOS=darwin GOARCH=amd64 go build -o bin/triton-darwin-amd64 main.go
	GOOS=darwin GOARCH=arm64 go build -o bin/triton-darwin-arm64 main.go
	GOOS=linux GOARCH=amd64 go build -o bin/triton-linux-amd64 main.go
	GOOS=linux GOARCH=arm64 go build -o bin/triton-linux-arm64 main.go
	GOOS=windows GOARCH=amd64 go build -o bin/triton-windows-amd64.exe main.go
	# License server (server-only platforms)
	GOOS=linux GOARCH=amd64 go build -o bin/triton-license-server-linux-amd64 cmd/licenseserver/main.go
	GOOS=linux GOARCH=arm64 go build -o bin/triton-license-server-linux-arm64 cmd/licenseserver/main.go

# Database lifecycle
db-up:
	podman compose up -d postgres
	@echo "Waiting for PostgreSQL..."
	@for i in $$(seq 1 30); do \
		podman exec $(POSTGRES_CONTAINER) pg_isready -U $(POSTGRES_USER) -q 2>/dev/null && break; \
		sleep 1; \
	done
	@podman exec $(POSTGRES_CONTAINER) psql -U $(POSTGRES_USER) -tc \
		"SELECT 1 FROM pg_database WHERE datname='triton_test'" \
		| grep -q 1 || podman exec $(POSTGRES_CONTAINER) psql -U $(POSTGRES_USER) -c "CREATE DATABASE triton_test"

db-down:
	podman compose down

db-reset:
	podman compose down -v
	podman compose up -d postgres
	@echo "Waiting for PostgreSQL..."
	@for i in $$(seq 1 30); do \
		podman exec $(POSTGRES_CONTAINER) pg_isready -U $(POSTGRES_USER) -q 2>/dev/null && break; \
		sleep 1; \
	done
	@podman exec $(POSTGRES_CONTAINER) psql -U $(POSTGRES_USER) -tc \
		"SELECT 1 FROM pg_database WHERE datname='triton_test'" \
		| grep -q 1 || podman exec $(POSTGRES_CONTAINER) psql -U $(POSTGRES_USER) -c "CREATE DATABASE triton_test"

# Container lifecycle
container-build:
	podman compose --profile server build

container-run: container-build
	podman compose --profile server up -d

container-stop:
	podman compose --profile server down

# Engine binary
build-engine:
	@mkdir -p bin
	go build -o bin/triton-engine ./cmd/triton-engine

# Engine container lifecycle
container-build-engine:
	podman build -t triton-engine:local -f Containerfile.engine \
	  --build-arg VERSION=$$(git describe --tags --always --dirty 2>/dev/null || echo dev) .

container-run-engine: container-build-engine
	podman run --rm --name triton-engine \
	  -v $$(pwd)/bundle.tar.gz:/etc/triton/bundle.tar.gz:ro \
	  triton-engine:local

container-stop-engine:
	podman stop triton-engine 2>/dev/null || true

# License server container lifecycle
container-build-licenseserver:
	podman compose --profile license-server build

container-run-licenseserver: container-build-licenseserver
	podman compose --profile license-server up -d

container-stop-licenseserver:
	podman compose --profile license-server down

# Unit tests only — no database required
test:
	go test -v ./...

# Integration tests (requires PostgreSQL; -p 1 serializes packages sharing DB)
test-integration: db-up
	go test -v -tags integration -count=1 -p 1 ./test/integration/...

# Full suite: unit + integration (-p 1 serializes packages sharing DB)
test-all: db-up
	go test -v -tags integration -count=1 -p 1 ./...

# Integration with race detector
test-integration-race: db-up
	go test -v -tags integration -race -count=1 -p 1 ./test/integration/...

# System tests (Phase 5 Sprint 3 C1) — spawns REAL triton + triton-license-server
# binaries as child processes and drives the full multi-tenant flow via HTTP.
# Requires PostgreSQL with CREATE DATABASE privilege (each run allocates its
# own two databases and drops them in cleanup). Rebuilds binaries on every run.
test-system: db-up
	TRITON_SYSTEM_TEST_DB_URL="postgres://triton:triton@localhost:5435/postgres?sslmode=disable" \
	  go test -v -tags system -timeout 300s ./test/system/...

# Playwright E2E browser tests (requires PostgreSQL + Chromium)
test-e2e: db-up build
	cd test/e2e && npm ci && npx playwright install chromium && npx playwright test

# Playwright E2E browser tests for license server admin UI
test-e2e-license: db-up build-licenseserver
	cd test/e2e && npm ci && npx playwright install chromium && npx playwright test --config=playwright.license.config.js

# Clean build artifacts
clean:
	rm -rf bin/
	rm -f coverage.out cover.out *.out
	rm -rf test/e2e/test-results/

# Install locally
install:
	go install .

# Run development version
run:
	go run main.go --profile quick

# Format code
fmt:
	go fmt ./...

# Run linter
lint:
	golangci-lint run

# Run benchmarks
bench:
	go test -bench=. -benchmem -run='^$$' ./...

# Run go vet
vet:
	go vet ./...

# Download dependencies
deps:
	go mod download
	go mod tidy
