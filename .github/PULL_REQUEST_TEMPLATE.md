## Summary

<!-- A clear, concise description of what this PR does and why. -->

## Type of change

- [ ] Bug fix (non-breaking fix for a reported issue)
- [ ] New feature (defensive analysis capability)
- [ ] Documentation update
- [ ] Refactor / code quality improvement
- [ ] Dependency update
- [ ] CI / build change

## Related issue

<!-- Link the issue this PR addresses, e.g. "Closes #42" -->

## Testing

<!-- Describe how you tested your changes. -->

- [ ] Tested on Linux
- [ ] Tested on macOS
- [ ] `go test ./...` passes
- [ ] Manual end-to-end test performed

## Security checklist

These are **required** for all code changes:

- [ ] No shell string concatenation with user input (all external commands use structured `exec.Command` args)
- [ ] All new fields from external tools are sanitised before storage or display
- [ ] All new user inputs are validated with strict allow-lists
- [ ] No automatic privilege escalation introduced
- [ ] No offensive capability added
- [ ] No telemetry, phone-home, or data collection added
- [ ] No global mutable state introduced
- [ ] `go vet ./...` passes with no new warnings
- [ ] `golangci-lint run ./...` passes with no new issues

## Documentation

- [ ] Public API changes are documented with Go doc comments
- [ ] README updated if usage changed
- [ ] CHANGELOG updated (if this project maintains one)
