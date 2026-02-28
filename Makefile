.PHONY: build build-all test bench vet clean install db-up db-down db-reset

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

# Run tests (requires PostgreSQL running)
test: db-up
	go test -v ./...

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
