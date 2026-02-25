# Code Review Checklist

Use this checklist for every code review.

## Pre-Review (Author)

- [ ] All tests pass (`go test ./...`)
- [ ] Coverage > 80% (`go test -cover`)
- [ ] No linting errors (`golangci-lint run`)
- [ ] Code formatted (`go fmt ./...`)
- [ ] Documentation updated
- [ ] Commit messages are clear and descriptive

## Code Review (Reviewer)

### Correctness
- [ ] Code solves the stated problem
- [ ] Edge cases are handled
- [ ] Error handling is complete
- [ ] No obvious bugs

### Go Conventions
- [ ] Follows Go formatting standards
- [ ] Proper use of error handling (no ignored errors)
- [ ] Exported functions have documentation comments
- [ ] Variable names are clear and idiomatic
- [ ] No unnecessary exported symbols

### Design
- [ ] Functions are small and focused
- [ ] No code duplication (DRY principle)
- [ ] Proper separation of concerns
- [ ] Interfaces are used appropriately

### Performance
- [ ] No obvious performance issues
- [ ] Resource cleanup (files closed, connections closed)
- [ ] No memory leaks
- [ ] Efficient algorithms used

### Security
- [ ] No hardcoded credentials
- [ ] Input validation present
- [ ] Safe file path handling
- [ ] No injection vulnerabilities

### Testing
- [ ] Tests are meaningful (not just coverage padding)
- [ ] Edge cases are tested
- [ ] Error cases are tested
- [ ] Test names describe behavior

## Post-Review (Author)

- [ ] All review comments addressed
- [ ] Re-reviewed if significant changes
- [ ] CI passes after changes
- [ ] Ready to merge

## Sign-Off

**Reviewer:** _______________  **Date:** _______________

**Approved / Changes Requested / Rejected**

**Comments:**
