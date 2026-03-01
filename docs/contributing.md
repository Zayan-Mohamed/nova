# Contributing

Thank you for your interest in contributing to NOVA!

---

## Before you start

Read the [Copilot & Contributor Instructions](https://github.com/Zayan-Mohamed/nova/blob/main/.github/copilot-instructions.md) — they define the strict security, legal, and architectural rules all contributions must follow.

Key principles:

- NOVA is **defensive only** — no exploitation features will be accepted
- All user input must be validated and sanitised
- No shell string interpolation — always use structured `exec.Command` argument slices
- No global mutable state
- No circular imports

---

## Development setup

```bash
git clone https://github.com/Zayan-Mohamed/nova.git
cd nova

# Install dependencies
go mod download

# Build
go build -o nova .

# Run tests
go test ./...

# Run linter (requires golangci-lint v2+)
golangci-lint run --timeout=5m
```

### Install golangci-lint v2

```bash
# Homebrew (Linux/macOS)
brew install golangci-lint

# Manual install
curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh \
  | sh -s -- -b $(go env GOPATH)/bin v2.10.1
```

---

## Pull request checklist

- [ ] `go build ./...` passes
- [ ] `go vet ./...` passes
- [ ] `golangci-lint run --timeout=5m` passes with 0 issues
- [ ] No new shell string interpolation
- [ ] All external input sanitised before use or display
- [ ] New features do not add exploitation capabilities
- [ ] Tests added for any new logic in `internal/`

---

## What we accept

✅ Bug fixes  
✅ Performance improvements  
✅ New defensive analysis rules  
✅ macOS WiFi support (via `airport` command)  
✅ Documentation improvements  
✅ UI/UX enhancements  
✅ Additional output formats (JSON, CSV export)

## What we will not accept

❌ Password brute-forcing  
❌ Exploit modules  
❌ Packet injection / deauth attacks  
❌ Stealth scanning modes  
❌ Credential harvesting  
❌ Any feature designed to attack rather than assess

---

## Reporting bugs

Open an issue using the [Bug Report template](https://github.com/Zayan-Mohamed/nova/issues/new?template=bug_report.md).

## Suggesting features

Open an issue using the [Feature Request template](https://github.com/Zayan-Mohamed/nova/issues/new?template=feature_request.md).
