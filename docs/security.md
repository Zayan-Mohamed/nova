# Security Policy

## Supported versions

| Version        | Supported |
| -------------- | --------- |
| `main` branch  | ✅        |
| Latest release | ✅        |
| Older releases | ❌        |

---

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report security issues via GitHub's [private security advisory](https://github.com/Zayan-Mohamed/nova/security/advisories/new) feature, or email the maintainer directly (see the GitHub profile).

Please include:

- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We aim to acknowledge reports within **48 hours** and provide a fix or mitigation within **7 days** for critical issues.

---

## Security design

NOVA is built with the following security properties:

| Property                | Implementation                                                                                            |
| ----------------------- | --------------------------------------------------------------------------------------------------------- |
| No shell injection      | All `exec.Command` calls use structured argument slices — never `sh -c` with user input                   |
| Input validation        | All IPs, CIDRs, port numbers, and file paths are validated and rejected if malformed                      |
| Output sanitisation     | All external data (SSID names, hostnames, service banners) has control characters stripped before display |
| No privilege escalation | NOVA never calls `sudo` internally; it informs the user and exits gracefully                              |
| No telemetry            | Zero data collection; no network calls except the scans the user explicitly triggers                      |
| No stealth mode         | All scans are user-initiated; no background or automatic scanning                                         |
| Resource limiting       | All scans use `context.WithTimeout`; goroutine counts are bounded                                         |

---

## Threat model

NOVA interacts with potentially hostile data from:

- Untrusted WiFi networks (malicious SSID names, rogue APs)
- Unknown LAN devices (crafted hostnames, unusual MAC addresses)
- nmap and nmcli output (treated as untrusted)

Mitigations in place:

- Terminal escape injection prevention (control character stripping)
- Length limits on all displayed strings
- No `eval` or dynamic code execution
- XML output parsed structurally, not with string matching
