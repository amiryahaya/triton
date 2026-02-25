# Go Quick Reference for Beginners

## Essential Commands

```bash
# Build
go build -o bin/triton main.go

# Run
go run main.go --profile quick

# Test
go test ./...
go test -v ./pkg/scanner          # Verbose
go test -run TestName ./pkg/scanner  # Run specific test
go test -cover ./...              # With coverage

# Format code (do this often!)
go fmt ./...

# Download dependencies
go mod tidy

# View documentation
go doc fmt.Printf
go doc github.com/amiryahaya/triton/pkg/scanner
```

## Common Go Patterns

### Error Handling
```go
// Always check errors!
result, err := someFunction()
if err != nil {
    return err  // or log and return
}
// Use result
```

### Structs and Methods
```go
type Scanner struct {
    Config *Config
}

// Method with value receiver (read-only)
func (s Scanner) Name() string {
    return s.Config.Name
}

// Method with pointer receiver (can modify)
func (s *Scanner) SetConfig(c *Config) {
    s.Config = c
}
```

### Interfaces
```go
// Define interface
type Module interface {
    Name() string
    Scan() error
}

// Implement implicitly
type CertificateModule struct{}

func (c CertificateModule) Name() string { return "cert" }
func (c CertificateModule) Scan() error  { return nil }
// Now CertificateModule implements Module
```

### Testing
```go
func TestMyFunction(t *testing.T) {
    // Arrange
    input := "test"
    expected := "TEST"
    
    // Act
    result := strings.ToUpper(input)
    
    // Assert
    if result != expected {
        t.Errorf("Expected %s, got %s", expected, result)
    }
    
    // Or use testify
    assert.Equal(t, expected, result)
}
```

## Common Errors and Fixes

| Error | Cause | Fix |
|-------|-------|-----|
| `undefined: X` | Missing import or typo | Check import path and spelling |
| `imported and not used` | Unused import | Remove import or use `_` prefix |
| `declared but not used` | Unused variable | Remove or use `_ = variable` |
| `cannot find package` | Missing dependency | Run `go mod tidy` |
| `no non-test Go files` | Wrong package name | Ensure package name matches folder |

## Project Structure

```
triton/
├── main.go              # Entry point
├── go.mod               # Module definition
├── go.sum               # Dependency checksums
├── cmd/                 # CLI commands
│   └── root.go
├── pkg/                 # Public packages
│   ├── scanner/         # Scanning logic
│   ├── crypto/          # Crypto utilities
│   ├── model/           # Data types
│   └── report/          # Report generation
├── internal/            # Private packages
│   └── config/
└── test/                # Test fixtures
    └── fixtures/
```

## Resources

- **Go Tour:** https://tour.golang.org
- **Go by Example:** https://gobyexample.com
- **Effective Go:** https://go.dev/doc/effective_go
- **Standard Library:** https://pkg.go.dev/std
