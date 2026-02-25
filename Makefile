.PHONY: build build-all test clean install

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

# Run tests
test:
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

# Download dependencies
deps:
	go mod download
	go mod tidy
