# Changelog

All notable changes to NOVA are documented here.

---

## [v0.1.0] — 2026-03-01

### Initial release

#### Features

- **WiFi Analysis** — scan nearby access points via `nmcli`; displays SSID, BSSID, signal, band, encryption type, and security score
- **WiFi search** — live SSID/BSSID search with `/` key
- **WiFi filter** — cycle security type filter (Open / WPA2 / WPA3) with `f` key
- **LAN Host Discovery** — auto-detect subnet, enumerate hosts via nmap (root) or parallel ping sweep (non-root)
- **ARP cache enrichment** — MAC address and vendor lookup via `/proc/net/arp` (Linux) / `arp -an` (macOS)
- **Port & Service Scanning** — per-host nmap scan with service version detection
- **Risk Scoring** — weighted 0–100 score + colour-coded findings (Info → Critical)
- **Keyboard-driven TUI** — Bubble Tea with Dracula-inspired palette, ASCII NOVA logo, centred layout
- **Legal consent screen** — required acknowledgement before any scan
- **Subnet auto-detection** — skips virtual interfaces (Docker, VPN, bridges)
- **Root vs non-root awareness** — appropriate scan mode selected automatically

#### Infrastructure

- CI with GitHub Actions (build, lint, govulncheck)
- golangci-lint v2 with 14 enabled linters
- GoReleaser v2 for cross-platform binaries (Linux + macOS, amd64 + arm64)
- MkDocs Material documentation published to GitHub Pages
- SECURITY.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md, issue templates

---

## [Unreleased]

- macOS WiFi support via `airport` command
- JSON / CSV export of scan results
- Host list search and filter
- Sort WiFi results by signal or score
