# NOVA – Copilot & Contributor Instructions

NOVA (Network Observation & Vulnerability Analyzer) is a terminal-based network intelligence and security assessment tool written in Go.

This document defines strict development, security, legal, and architectural guidelines.

NOVA is intended to be a responsible, defensive security tool. It must NEVER become an offensive exploitation framework.

All AI-generated or human-written contributions must follow this document.

---

# 1. Project Philosophy

NOVA is:

- Defensive, not offensive
- Transparent, not stealth malware-like
- User-consent driven
- Secure-by-design
- Minimal privilege wherever possible
- Auditable and predictable

NOVA must NOT:
- Automate exploitation
- Perform brute-force attacks
- Evade detection
- Provide stealth scanning modes
- Enable scanning without explicit user action

---

# 2. Legal & Ethical Requirements

## 2.1 Explicit Consent Requirement

NOVA must:

- Display a legal warning before scanning
- Require explicit user confirmation
- Default to safe scan modes
- Log user acknowledgment for audit trace

Users must be reminded:

"Only scan networks you own or have explicit permission to assess."

## 2.2 No Silent Scanning

NOVA must NEVER:
- Automatically scan networks at startup
- Continuously scan without user action
- Run background hidden scans

All scans must be user-triggered.

---

# 3. Security Threat Model

NOVA interacts with:

- System network interfaces
- OS-level commands (nmap, nmcli, iw, etc.)
- Potentially untrusted networks
- Untrusted devices
- External command outputs

Security risks include:

- Command injection
- Malicious output parsing
- Privilege escalation
- Shell injection
- Unsafe file writes
- Race conditions
- Malicious SSID names
- Terminal escape injection
- Memory exhaustion via large scan results
- Dependency vulnerabilities
- Path traversal
- Abuse for unauthorized reconnaissance

All code must mitigate these.

---

# 4. Secure Coding Requirements

## 4.1 Never Use Shell Execution

DO NOT use:

exec.Command("sh", "-c", userInput)

Always use structured arguments:

exec.Command("nmap", "-sn", targetSubnet)

Never concatenate user input into shell strings.

---

## 4.2 Input Validation

All user input must be:

- Validated
- Strictly typed
- Sanitized
- Length-limited

Validate:
- IP addresses
- CIDR ranges
- Port numbers
- File paths

Reject:
- Wildcards
- Command separators
- Control characters
- Unexpected whitespace

---

## 4.3 Safe Output Rendering

NOVA displays untrusted network data:

- SSID names
- Hostnames
- MAC vendors
- Service banners

All terminal output must:

- Strip ANSI escape sequences
- Remove control characters
- Truncate excessively long strings
- Prevent terminal injection attacks

Never directly print raw external command output.

---

## 4.4 Privilege Handling

Some operations may require root privileges.

NOVA must:

- Detect privilege level
- Inform the user clearly
- Avoid automatic privilege escalation
- Never attempt sudo internally

If root is required:
Display instruction and exit gracefully.

---

## 4.5 Resource Limiting

All scans must:

- Set timeouts
- Limit parallel threads
- Prevent infinite blocking
- Avoid uncontrolled goroutine spawning

Use context.WithTimeout for all scan operations.

---

## 4.6 Dependency Security

- Run `go mod tidy` regularly
- Avoid unnecessary dependencies
- Keep third-party libraries minimal
- Monitor for CVEs
- Avoid abandoned packages

No obscure GitHub dependencies.

---

# 5. Architecture Rules

Dependency direction:

main → cmd → internal/*

Never allow:
internal packages importing cmd
Circular imports
Global mutable state

Use dependency injection where appropriate.

---

# 6. Feature Scope (Allowed)

## 6.1 WiFi Analysis
- SSID listing
- Encryption type detection
- Channel detection
- Signal strength
- Basic congestion analysis

## 6.2 LAN Host Discovery
- Subnet scanning
- MAC address detection
- Vendor lookup
- Hostname resolution

## 6.3 Port & Service Scanning
- Open ports
- Service detection
- OS fingerprinting (read-only)
- Risk tagging

## 6.4 Security Insights
- Weak encryption detection
- Dangerous open ports
- Suspicious unknown devices
- Router exposure detection
- SMB/Telnet exposure detection
- UPnP exposure flagging

## 6.5 Security Scoring
Weighted scoring based on:
- Encryption
- Open services
- Exposure level
- Unknown devices
- Router exposure

No exploit modules.

---

# 7. Features Explicitly Forbidden

NOVA must never implement:

- Password brute-forcing
- Exploit execution
- Metasploit integration
- Credential spraying
- Packet injection attacks
- WiFi deauthentication attacks
- Rogue AP creation
- Traffic interception
- MITM automation
- ARP poisoning
- WPA cracking
- Hidden stealth scanning
- Evasion techniques

NOVA is analysis only.

---

# 8. Logging & Privacy

NOVA must:

- Not collect user data
- Not phone home
- Not auto-upload scan results
- Not embed telemetry

Logs must:

- Be local-only
- Optional
- Never contain sensitive credentials
- Never store raw service banners without sanitization

---

# 9. TUI Security Requirements

Since NOVA is keyboard-driven:

- All key bindings must be documented
- No hidden key combos
- No destructive actions without confirmation
- Clear state transitions
- Visible scan status indicators

Never freeze UI during long operations.

Use async updates safely.

---

# 10. Error Handling Standards

Never:

- Panic on user input
- Crash on malformed network data
- Expose stack traces by default

All errors must be:

- User-readable
- Non-verbose unless debug mode enabled
- Logged safely

---

# 11. Safe Defaults

Default behavior:

- Safe scan mode
- No aggressive scanning
- Local subnet only
- Limited port range unless user opts in

Aggressive scans must require explicit flag.

---

# 12. Secure File Export

If exporting reports:

- Use safe file creation
- Prevent path traversal
- Validate filename
- Use JSON or Markdown only
- Never auto-execute exported files

---

# 13. Documentation Requirements

Before public release:

- README.md
- SECURITY.md
- CONTRIBUTING.md
- LICENSE (MIT or Apache-2.0 recommended)
- Code of Conduct

---

# 14. AI Contribution Rules

AI-generated code must be:

- Reviewed manually
- Tested
- Validated against injection risks
- Checked for shell misuse
- Audited for unsafe concurrency

Never blindly accept AI output.

---

# 15. Release Requirements

Before v1.0:

- Run static analysis (golangci-lint)
- Run go vet
- Perform dependency audit
- Test on:
  - Linux
  - macOS
- Confirm no root-required operations run silently
- Confirm consent screen displays

---

# 16. Security Disclosure Policy

Add SECURITY.md with:

- Responsible disclosure instructions
- Email contact
- Expected response timeline

---

# 17. Code Quality Expectations

- No unused code
- No global state
- No giant god-functions
- Clear separation of modules
- Tests for core logic
- Deterministic behavior

---

# 18. Final Principle

If a feature could be abused offensively,
it must not be implemented.

NOVA is for visibility, not exploitation.

Security through responsibility.