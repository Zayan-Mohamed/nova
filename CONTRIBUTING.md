# Contributing to NOVA

Thank you for your interest in contributing! NOVA is a **defensive** security tool and all
contributions must uphold that principle. Please read this document before opening a PR.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [What we accept](#what-we-accept)
- [What we do not accept](#what-we-do-not-accept)
- [Getting started](#getting-started)
- [Development workflow](#development-workflow)
- [Code standards](#code-standards)
- [Commit messages](#commit-messages)
- [Pull request checklist](#pull-request-checklist)
- [Reporting bugs](#reporting-bugs)
- [Security issues](#security-issues)

---

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).
By participating you agree to abide by its terms.

---

## What we accept

- Bug fixes with a clear description and reproduction steps
- Performance improvements that do not weaken security controls
- New **defensive** analysis features (e.g., new risk findings, better scoring)
- Documentation improvements
- Test coverage improvements
- Platform compatibility fixes (macOS, Linux)
- Dependency updates (with security rationale)

---

## What we do not accept

Any contribution that:

- Adds offensive capabilities (exploitation, brute-force, packet injection, deauth, MITM, etc.)
- Removes or weakens the legal consent screen
- Introduces shell string concatenation with user input
- Adds automatic privilege escalation
- Adds telemetry, phone-home, or data collection
- Introduces stealth or evasion techniques
- Adds global mutable state
- Breaks the `main → cmd → internal/*` dependency direction

---

## Getting started

### Prerequisites

- Go 1.21 or later — [go.dev/dl](https://go.dev/dl/)
- `nmap` and `nmcli` installed for manual testing
- `golangci-lint` for linting — [golangci-lint.run](https://golangci-lint.run/usage/install/)

```bash
# Clone the repository
git clone https://github.com/Zayan-Mohamed/nova.git
cd nova

# Download dependencies
go mod download

# Build
go build -o nova .

# Run tests
go test ./...

# Run linter
golangci-lint run ./...
```

---

## Development workflow

1. **Fork** the repository and clone your fork.
2. Create a **feature branch** from `main`:
   ```bash
   git checkout -b feat/my-feature
   ```
3. Make your changes following the [Code standards](#code-standards) below.
4. Run the full check suite before pushing:
   ```bash
   go build ./...
   go vet ./...
   go test ./...
   golangci-lint run ./...
   ```
5. Push your branch and open a **Pull Request** against `main`.

---

## Code standards

### Security requirements (non-negotiable)

- **Never** use `exec.Command("sh", "-c", ...)` or any form of shell string expansion with user input.
- **Always** use structured argument lists: `exec.Command("nmap", "-sn", cidr)`.
- **Sanitise** all output from external commands before storing or displaying it.
- **Validate** all inputs with strict allow-lists (regex or type assertions) before use.
- **Set timeouts** on all external calls using `context.WithTimeout`.
- **Never panic** on user input or malformed network data.

### Style

- Follow standard Go formatting: run `gofmt -w .` before committing.
- All exported types, functions, and constants must have doc comments.
- Prefer explicit error returns over panics.
- Keep functions focused — if a function is longer than ~60 lines, consider splitting it.
- No global mutable state. Use dependency injection.
- Keep third-party dependencies minimal. Justify any new dependency in the PR description.

---

## Commit messages

Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>(<scope>): <short description>

[optional body]

[optional footer]
```

**Types:** `feat`, `fix`, `docs`, `test`, `refactor`, `chore`, `perf`, `ci`

**Examples:**

```
feat(risk): add UPnP exposure finding for port 1900
fix(wifi): handle nmcli output with colons in SSID
docs: add usage examples to README
test(scanner): add CIDR validation edge cases
```

---

## Pull request checklist

Before submitting your PR, confirm all of the following:

- [ ] `go build ./...` passes with no errors
- [ ] `go vet ./...` passes with no warnings
- [ ] `go test ./...` passes (add tests for new behaviour)
- [ ] `golangci-lint run ./...` passes with no new issues
- [ ] No shell string concatenation with external input
- [ ] All new external command calls use structured argument lists
- [ ] All new fields from external tools are sanitised before use
- [ ] No new global mutable state introduced
- [ ] Documentation updated if public API changed
- [ ] PR description explains _what_ and _why_ (not just _how_)

---

## Reporting bugs

Open a [GitHub Issue](https://github.com/Zayan-Mohamed/nova/issues/new?template=bug_report.yml)
and fill in the template. Please include:

- NOVA version (`nova --version`)
- OS and version
- Steps to reproduce
- Expected vs. actual behaviour
- Any relevant logs or screenshots

---

## Security issues

**Do not open a public issue for security vulnerabilities.**  
Please read [SECURITY.md](SECURITY.md) for the responsible disclosure process.
