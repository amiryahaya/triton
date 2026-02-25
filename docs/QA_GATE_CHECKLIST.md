# QA Gate Checklist

Use this at the end of each phase before proceeding.

## Phase: _______________  Date: _______________

## Functional QA

### Basic Functionality
- [ ] Feature works as specified in requirements
- [ ] Happy path (normal usage) works correctly
- [ ] All user-facing commands work
- [ ] Help text is accurate and helpful

### Edge Cases
- [ ] Empty inputs handled gracefully
- [ ] Large inputs handled without crash
- [ ] Invalid inputs produce clear error messages
- [ ] Boundary conditions tested

### Error Handling
- [ ] Errors are informative
- [ ] No panic crashes
- [ ] Resources cleaned up on errors
- [ ] Logs are useful for debugging

## Performance QA

### Speed
- [ ] Scan completes within acceptable time
- [ ] Progress indicator works
- [ ] No hanging or freezing

### Memory
- [ ] Memory usage stays within limits
- [ ] No memory leaks (check with long-running scan)
- [ ] Large files don't cause OOM

### Resource Usage
- [ ] CPU usage is reasonable
- [ ] Disk I/O is efficient
- [ ] Network usage (if any) is minimal

## Integration QA

### Module Integration
- [ ] New module works with existing modules
- [ ] No regression in other modules
- [ ] Shared resources handled correctly

### Platform Testing
- [ ] Works on macOS (your Mac)
- [ ] Cross-compilation succeeds
- [ ] No platform-specific issues

### Output Verification
- [ ] JSON output is valid
- [ ] CSV output matches expected format
- [ ] HTML output displays correctly
- [ ] Reports contain expected data

## Regression Testing

- [ ] Previous phases still work
- [ ] No broken existing functionality
- [ ] Performance hasn't degraded

## Documentation QA

- [ ] README is up to date
- [ ] Code comments are accurate
- [ ] User-facing documentation is clear
- [ ] Examples work as shown

## Sign-Off

**QA Performed By:** _______________

**Result:** ☐ PASS  ☐ PASS WITH NOTES  ☐ FAIL

**Notes/Issues:**

**Approved to proceed to next phase:** ☐ YES  ☐ NO

**Date:** _______________
