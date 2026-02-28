# Security Policy

## Supported Versions

| Version        | Supported                    |
| -------------- | ---------------------------- |
| `main` branch  | ✅ Active development        |
| Latest release | ✅ Security fixes backported |
| Older releases | ❌ No longer maintained      |

---

## Reporting a Vulnerability

**Please do NOT open a public GitHub Issue for security vulnerabilities.**

If you discover a security issue in NOVA, please disclose it responsibly:

1. **Email:** Send a detailed report to `security@[your-domain].com`  
   _(replace with your actual contact address before publishing)_
2. **Subject line:** `[NOVA Security] <brief description>`
3. **Include:**
   - A description of the vulnerability and its impact
   - Steps to reproduce (proof-of-concept if applicable)
   - The version of NOVA affected
   - Your suggested fix, if any

### What to expect

| Timeline            | Action                                         |
| ------------------- | ---------------------------------------------- |
| **Within 48 hours** | Acknowledgement of your report                 |
| **Within 7 days**   | Initial triage and severity assessment         |
| **Within 30 days**  | Patch released (critical issues may be faster) |
| **After patch**     | Public disclosure coordinated with reporter    |

We follow [responsible disclosure](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html).
Reporters who follow this policy will be credited in the release notes unless they prefer anonymity.

---

## Scope

### In scope

- Command injection vulnerabilities in external tool invocations (`nmap`, `nmcli`)
- Terminal injection via unsanitised network data (SSID, hostname, service banners)
- Privilege escalation pathways
- Path traversal in report export
- Dependency vulnerabilities (please also report upstream)
- Logic errors that could cause NOVA to scan without user consent

### Out of scope

- Issues in the underlying OS or network stack
- Issues requiring physical access to the machine
- Social engineering attacks
- Theoretical vulnerabilities without a realistic attack path

---

## Security Design Principles

NOVA is built with the following guarantees:

- **No shell expansion** — all external commands use structured `exec.Command` argument lists. User-controlled input is never concatenated into shell strings.
- **All external output is sanitised** — ANSI escape sequences and control characters are stripped from every field before display or storage.
- **Hard timeouts** — every scan operation runs under a `context.WithTimeout` to prevent resource exhaustion.
- **Input validation** — all IP addresses, CIDRs, port ranges, and interface names are validated against strict allow-lists before use.
- **No automatic privilege escalation** — NOVA detects root and uses the appropriate scan mode, but never calls `sudo` internally.
- **User consent required** — a legal consent screen is displayed on every launch. No scan is possible without explicit acknowledgement.
- **No telemetry** — NOVA does not phone home, collect user data, or auto-upload results.
