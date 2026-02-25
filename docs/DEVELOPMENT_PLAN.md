# Triton Development Plan
## SBOM/CBOM Scanner for PQC Compliance

**Version:** 1.1  
**Target:** MVP in 4 weeks for partner buy-in  
**Methodology:** Test-Driven Development (TDD) + Code Review + QA Gates  
**Language:** Go (beginner-friendly guide included)

---

## 0. Go for Beginners - Quick Reference

### 0.1 Essential Go Concepts

**Package Structure:**
```go
package main        // Entry point package
package scanner     // Library package

import (
    "fmt"           // Standard library
    "github.com/..." // External package
)
```

**Key Differences from Other Languages:**
| Concept | Go Way | Notes |
|---------|--------|-------|
| Visibility | Capitalized = public, lowercase = private | `Name` vs `name` |
| Error handling | Explicit `if err != nil` | No exceptions |
| Types | After variable name | `var count int` |
| Pointers | `*Type` for pointer, `&` for address | Safer than C |
| Structs | Like classes without inheritance | Use composition |

**Common Patterns:**
```go
// Error handling (this is idiomatic Go)
result, err := someFunction()
if err != nil {
    return err  // Always handle errors!
}

// Struct definition
type Person struct {
    Name string
    Age  int
}

// Method (receiver is like 'this')
func (p Person) Greet() string {
    return "Hello, " + p.Name
}

// Interface (implicit implementation)
type Greeter interface {
    Greet() string
}
```

### 0.2 Essential Commands
```bash
# Run tests
go test ./...

# Run specific test
go test -v -run TestName ./pkg/scanner

# Run with coverage
go test -cover ./...

# Format code (always do this!)
go fmt ./...

# Build
go build -o bin/triton main.go

# Run
go run main.go --profile quick

# Download dependencies
go mod tidy

# View documentation
go doc package.Function
```

### 0.3 Go Resources
- **Tour of Go:** https://tour.golang.org (interactive tutorial)
- **Go by Example:** https://gobyexample.com (cookbook style)
- **Effective Go:** https://go.dev/doc/effective_go (best practices)

---

## 1. Project Overview

### 1.1 Goals
- Build a lightweight, cross-platform SBOM/CBOM scanner
- Support Malaysian government PQC compliance (2030 deadline)
- Generate reports matching government format
- Outperform PCert (Java) in speed and memory efficiency

### 1.2 Success Criteria
| Metric | Target |
|--------|--------|
| Scan 1TB disk | < 2 hours |
| Memory usage | < 200MB |
| Binary size | < 50MB |
| False positive rate | < 5% |
| Test coverage | > 80% |
| Code review pass | 100% |
| QA gate pass | 100% |

---

## 2. Development Methodology: TDD + Code Review + QA

### 2.1 Development Cycle
```
┌─────────────────────────────────────────────────────────┐
│  WEEKLY CYCLE                                           │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐   │
│  │   TDD   │→│  Review │→│   QA    │→│  Merge  │   │
│  │ Red-Green│  │ Checklist│  │  Gate   │  │         │   │
│  │ Refactor│  │         │  │         │  │         │   │
│  └─────────┘  └─────────┘  └─────────┘  └─────────┘   │
└─────────────────────────────────────────────────────────┘
```

### 2.2 TDD Cycle (Daily)
```
Red  → Write failing test (think about what you want)
Green → Write minimal code to pass (make it work)
Refactor → Clean up, optimize (make it right)
```

### 2.3 Code Review Checklist (End of Each Phase)

**Before requesting review:**
- [ ] All tests pass (`go test ./...`)
- [ ] Coverage > 80% (`go test -cover`)
- [ ] No linting errors (`golangci-lint run`)
- [ ] Code formatted (`go fmt ./...`)
- [ ] Documentation updated
- [ ] Commit messages are clear

**Reviewer checks:**
- [ ] Code follows Go conventions
- [ ] Error handling is complete
- [ ] No obvious bugs or edge cases missed
- [ ] Performance is acceptable
- [ ] Security considerations addressed

### 2.4 QA Gate (End of Each Phase)

**Functional QA:**
- [ ] Feature works as specified
- [ ] Edge cases handled
- [ ] Error messages are helpful
- [ ] Documentation is accurate

**Performance QA:**
- [ ] Memory usage acceptable
- [ ] Speed acceptable
- [ ] No resource leaks

**Integration QA:**
- [ ] Works with other modules
- [ ] No regression in existing features

---

## 3. Phase Breakdown with Review & QA Gates

### Phase 1: Foundation (Week 1)
**Goal:** Core engine with certificate scanning

#### Week 1 Tasks

| Day | Task | Tests | Deliverable |
|-----|------|-------|-------------|
| 1 | Project setup, CI/CD | N/A | GitHub Actions workflow |
| 2 | Config system | Test config loading | Config package |
| 3 | Engine scaffold | Test engine lifecycle | Engine with mock modules |
| 4 | Certificate scanner | Test PEM/DER parsing | Certificate module |
| 5 | Report generator | Test JSON/CSV output | Report package |

#### Phase 1 Code Review (Day 5)
**Reviewer:** Self-review + document in README

**Checklist:**
- [ ] Project structure follows Go conventions
- [ ] All packages have proper documentation comments
- [ ] No `panic()` calls (use error returns)
- [ ] Configuration is validated
- [ ] Tests are meaningful (not just coverage padding)

#### Phase 1 QA Gate (Day 5)
**Test on your Mac:**
```bash
# Build and run
make build
./bin/triton --profile quick

# Check it doesn't crash
# Check output files are created
ls -la *.json *.csv *.html
```

**QA Checklist:**
- [ ] Binary runs without errors
- [ ] Help text is clear (`./bin/triton --help`)
- [ ] Progress bar displays correctly
- [ ] Output files are valid JSON/CSV/HTML

---

### Phase 2: Core Scanners (Week 2)
**Goal:** Key, package, and library scanning

#### Week 2 Tasks

| Day | Task | Tests | Deliverable |
|-----|------|-------|-------------|
| 6 | Key scanner | Test key type detection | Key module |
| 7 | Package scanner | Test brew/dpkg/rpm | Package module |
| 8 | Library scanner | Test shared lib detection | Library module |
| 9 | Process scanner | Test process enumeration | Process module |
| 10 | Integration | Test full scan flow | Integrated scanner |

#### Phase 2 Code Review (Day 10)
**Reviewer:** Peer review (if available) or detailed self-review

**Checklist:**
- [ ] Each scanner has comprehensive tests
- [ ] Error handling covers all error paths
- [ ] No hardcoded paths (use configuration)
- [ ] Resource cleanup (files closed, etc.)
- [ ] Concurrent code is safe (if any)

**Go-Specific Review:**
- [ ] Proper use of `defer` for cleanup
- [ ] Context cancellation handled
- [ ] No goroutine leaks
- [ ] Channel usage is correct

#### Phase 2 QA Gate (Day 10)
**Test on real data:**
```bash
# Run on your Mac's actual system
./bin/triton --profile standard -o week2-test.json

# Check results
head week2-test.json
cat week2-test.csv
```

**QA Checklist:**
- [ ] Finds certificates on your system
- [ ] Finds keys on your system
- [ ] Finds packages (brew list)
- [ ] No false positives (check a few findings)
- [ ] Performance acceptable (< 5 min for standard scan)

---

### Phase 3: Service & Config Scanning (Week 3)
**Goal:** TLS configs, service detection, PQC assessment

#### Week 3 Tasks

| Day | Task | Tests | Deliverable |
|-----|------|-------|-------------|
| 11 | Service discovery | Test port scanning | Service module |
| 12 | TLS config parser | Test Apache/Nginx parsing | Config scanner |
| 13 | Cipher detection | Test TLS handshake | Cipher module |
| 14 | PQC assessment | Test risk scoring | Assessment engine |
| 15 | Report polish | Test all output formats | Complete reports |

#### Phase 3 Code Review (Day 15)
**Reviewer:** Thorough review - this is critical functionality

**Checklist:**
- [ ] PQC classification matches NIST standards
- [ ] TLS parsing handles all common formats
- [ ] Service detection is safe (no exploits)
- [ ] Reports match government format exactly
- [ ] Edge cases handled (expired certs, etc.)

**Security Review:**
- [ ] No hardcoded credentials
- [ ] Input validation on all external data
- [ ] Safe file path handling
- [ ] No command injection vulnerabilities

#### Phase 3 QA Gate (Day 15)
**Test PQC classification:**
```bash
# Run comprehensive scan
./bin/triton --profile comprehensive -o week3-test.json

# Verify PQC classifications
grep -o '"pqcStatus": "[^"]*"' week3-test.json | sort | uniq -c
```

**QA Checklist:**
- [ ] PQC classifications look correct
- [ ] Report format matches sample CSVs
- [ ] HTML report is readable
- [ ] Risk scores make sense
- [ ] No crashes on edge cases

---

### Phase 4: Polish & Demo (Week 4)
**Goal:** Cross-platform builds, performance, demo

#### Week 4 Tasks

| Day | Task | Tests | Deliverable |
|-----|------|-------|-------------|
| 16 | Windows support | Test on Windows VM | Windows binary |
| 17 | Performance | Benchmark tests | Optimized scanner |
| 18 | Air-gapped mode | Test offline operation | Offline support |
| 19 | Demo data | Test with sample certs | Demo package |
| 20 | Documentation | Final review | Partner presentation |

#### Phase 4 Code Review (Day 20)
**Reviewer:** Final comprehensive review

**Checklist:**
- [ ] All previous review items addressed
- [ ] Performance benchmarks documented
- [ ] Cross-platform code is clean
- [ ] No TODO comments left in code
- [ ] README is complete and accurate

**Final QA Gate (Day 20)**
**Full system test:**
```bash
# Build all platforms
make build-all

# Test each binary
./bin/triton-darwin-arm64 --version
./bin/triton-darwin-arm64 --profile quick

# Verify outputs
ls -la *.json *.csv *.html
```

**Final QA Checklist:**
- [ ] All binaries run on target platforms
- [ ] Demo scenario works end-to-end
- [ ] Documentation is complete
- [ ] Partner presentation ready
- [ ] No known critical bugs

---

## 4. Testing Strategy

### 4.1 Test Fixtures
Create these test files in `test/fixtures/`:

```
test/
├── fixtures/
│   ├── certificates/
│   │   ├── rsa-2048.pem       # TRANSITIONAL
│   │   ├── rsa-4096.pem       # SAFE
│   │   ├── ecdsa-p256.pem     # TRANSITIONAL
│   │   ├── ed25519.pem        # TRANSITIONAL
│   │   └── expired.pem        # Edge case
│   ├── keys/
│   │   ├── rsa-private.pem
│   │   ├── ec-private.pem
│   │   └── openssh-ed25519
│   └── configs/
│       ├── apache-ssl.conf
│       └── nginx-ssl.conf
```

### 4.2 Writing Your First Test

**Step 1: Create test file** (name ends with `_test.go`):
```go
// pkg/scanner/certificate_test.go
package scanner

import (
    "testing"
    "github.com/stretchr/testify/assert"
)

// Test function must start with "Test"
func TestIsCertificateFile(t *testing.T) {
    // Arrange
    m := &CertificateModule{}
    
    // Act
    result := m.isCertificateFile("/etc/ssl/cert.pem")
    
    // Assert
    assert.True(t, result)
}
```

**Step 2: Run test**:
```bash
go test -v ./pkg/scanner -run TestIsCertificateFile
```

**Step 3: See it fail (Red)**, then write code to make it pass (Green)

### 4.3 Test Coverage

**Check coverage:**
```bash
go test -cover ./...
```

**Generate HTML report:**
```bash
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html
open coverage.html
```

---

## 5. Code Review Process

### 5.1 Self-Review Template

Before asking for review, answer these:

```markdown
## Self-Review Checklist

### Functionality
- [ ] Does it solve the problem?
- [ ] Are all requirements met?
- [ ] Are edge cases handled?

### Code Quality
- [ ] Is the code readable?
- [ ] Are variable names clear?
- [ ] Are functions small and focused?
- [ ] Is there duplicated code?

### Testing
- [ ] Are there tests for new code?
- [ ] Do all tests pass?
- [ ] Is coverage > 80%?

### Go Specific
- [ ] Is error handling complete?
- [ ] Are resources properly closed?
- [ ] Is the code formatted?
- [ ] Are there any linting errors?

### Documentation
- [ ] Are exported functions documented?
- [ ] Is the README updated?
- [ ] Are complex parts explained?
```

### 5.2 Review Request Template

When requesting review, provide:

```markdown
## Review Request: Phase X Complete

### What Changed
- Added certificate scanner
- Implemented PEM/DER parsing
- Added PQC classification

### Test Results
```
$ go test -cover ./...
ok      github.com/amiryahaya/triton/pkg/scanner    0.5s    coverage: 85.3%
```

### Known Issues
- None

### Questions for Reviewer
- Is the error handling pattern correct?
- Should I add more edge case tests?
```

---

## 6. CI/CD Pipeline

### 6.1 GitHub Actions Workflow
Already included in `.github/workflows/ci.yml`:

- Runs on every push and PR
- Tests on Ubuntu and macOS
- Checks code coverage
- Builds cross-platform binaries
- Runs linter

### 6.2 Interpreting CI Results

**Green checkmark:** All good, proceed

**Red X:** Check the logs
```
Click on the failed job → Read the error message → Fix locally → Push again
```

**Common CI failures:**
- Tests failing → Fix the test or the code
- Linting errors → Run `go fmt ./...` and `golangci-lint run`
- Coverage too low → Add more tests
- Build failure → Check imports and dependencies

---

## 7. Troubleshooting Guide

### 7.1 Common Go Errors

**"undefined: SomeFunction"**
```
→ Check import path
→ Check function name spelling
→ Check if package is in go.mod
```

**"cannot find package"**
```
→ Run `go mod tidy`
→ Check internet connection
→ Check import path is correct
```

**"imported and not used"**
```
→ Remove unused import
→ Or use `_` prefix: `import _ "package"` (for side effects)
```

**"declared but not used"**
```
→ Remove unused variable
→ Or use `_ = variableName` to silence
```

### 7.2 Common TDD Mistakes

**Testing implementation instead of behavior:**
```go
// BAD: Tests internal details
func TestInternalCounter(t *testing.T) {
    s := &Scanner{}
    s.internalCounter = 5  // Don't test internals!
}

// GOOD: Tests behavior
func TestScannerFindsCertificates(t *testing.T) {
    results := scanner.Scan("/path")
    assert.NotEmpty(t, results.Certificates)
}
```

**Not testing error cases:**
```go
// Always test what happens on errors
func TestScannerHandlesInvalidPath(t *testing.T) {
    _, err := scanner.Scan("/nonexistent")
    assert.Error(t, err)
}
```

---

## 8. Daily Standup Template

```
## Date: YYYY-MM-DD

### Yesterday
- Completed: [what tests/code]
- Blockers: [any issues]

### Today
- Goal: [what to write]
- Tests: [what tests to write first]

### Phase Progress
- Phase X: Y/5 days complete
- Next review: [date]

### Concerns
- [Any risks or blockers]
```

---

## 9. Definition of Done

### For Each Task:
- [ ] Tests written first (Red)
- [ ] Code implemented (Green)
- [ ] Refactored and clean
- [ ] All tests pass
- [ ] Coverage > 80%
- [ ] Linter passes
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Committed with clear message

### For Each Phase:
- [ ] All phase tasks complete
- [ ] Phase code review passed
- [ ] Phase QA gate passed
- [ ] Review checklist signed off
- [ ] Ready for next phase

---

## 10. Emergency Procedures

### If Falling Behind:
1. **Cut scope, not quality** — Remove features, keep tests
2. **Simplify** — Hardcode instead of configure, add config later
3. **Ask for help** — Don't struggle alone for > 2 hours

### If Tests Are Hard to Write:
1. **The code might be poorly designed** — Refactor first
2. **Start with a smaller test** — Test one function, not whole module
3. **Use mocks** — Isolate the code under test

### If Stuck on a Bug:
1. **Write a test that reproduces it**
2. **Add logging** — `fmt.Printf("DEBUG: value=%v\n", value)`
3. **Use debugger** — `delve` or VS Code debugger
4. **Take a break** — 15 minutes away from screen

---

## 11. Next Steps

### Right Now:
1. **Extract the tarball** on your Mac
2. **Run `go mod tidy`** to download dependencies
3. **Run `make build`** to verify it compiles
4. **Run `go test ./...`** to see current test status

### This Week:
1. **Day 1:** Set up CI/CD (push to GitHub, verify Actions run)
2. **Day 2:** Write first test for certificate parser
3. **Day 3:** Make test pass
4. **Day 4:** Write more tests, refactor
5. **Day 5:** Phase 1 code review + QA gate

### Questions?
- Go syntax: https://gobyexample.com
- Testing: https://pkg.go.dev/testing
- This plan: Check the appropriate section above

---

**Remember:** Red → Green → Refactor → Review → QA → Merge

**Quality over speed. Working code over perfect code. Tests over documentation.**
