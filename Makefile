.PHONY: build build-all test test-integration test-all test-integration-race test-e2e bench vet clean install run fmt lint deps db-up db-down db-reset container-build container-run container-stop

# Build for current platform
build:
	go build -o bin/triton main.go

# Build for all platforms
build-all:
	GOOS=darwin GOARCH=amd64 go build -o bin/triton-darwin-amd64 main.go
	GOOS=darwin GOARCH=arm64 go build -o bin/triton-darwin-arm64 main.go
	GOOS=linux GOARCH=amd64 go build -o bin/triton-linux-amd64 main.go
	GOOS=linux GOARCH=arm64 go build -o bin/triton-linux-arm64 main.go
	GOOS=windows GOARCH=amd64 go build -o bin/triton-windows-amd64.exe main.go

# Database lifecycle
db-up:
	podman compose up -d postgres
	@echo "Waiting for PostgreSQL..."
	@sleep 2
	@podman exec triton-db psql -U triton -tc "SELECT 1 FROM pg_database WHERE datname='triton_test'" | grep -q 1 || \
		podman exec triton-db psql -U triton -c "CREATE DATABASE triton_test"

db-down:
	podman compose down

db-reset:
	podman compose down -v
	podman compose up -d postgres
	@echo "Waiting for PostgreSQL..."
	@sleep 2
	@podman exec triton-db psql -U triton -c "CREATE DATABASE triton_test"

# Container lifecycle
container-build:
	podman build -t triton:local -f Containerfile .

container-run: container-build
	podman compose --profile server up -d

container-stop:
	podman compose --profile server down

# Run tests (requires PostgreSQL running; -p 1 serializes packages sharing DB)
test: db-up
	go test -v -p 1 ./...

# Integration tests (requires PostgreSQL)
test-integration: db-up
	go test -v -tags integration -count=1 ./test/integration/...

# Full suite: unit + integration (-p 1 serializes packages sharing DB)
test-all: db-up
	go test -v -tags integration -count=1 -p 1 ./...

# Integration with race detector
test-integration-race: db-up
	go test -v -tags integration -race -count=1 ./test/integration/...

# Playwright E2E browser tests (requires PostgreSQL + Chromium)
test-e2e: db-up
	cd test/e2e && npm ci && npx playwright install chromium && npx playwright test

# Clean build artifacts
clean:
	rm -rf bin/

# Install locally
install:
	go install

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
	go test -bench=. -benchmem ./...

# Run go vet
vet:
	go vet ./...

# Download dependencies
deps:
	go mod download
	go mod tidy
