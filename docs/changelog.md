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

## [v0.2.0] — 2026-03-03

### Deep Scan

- **Deep Scan** (`d` from Host Detail view) — full Fing-style host intelligence scan:
  - All 65 535 TCP ports (`-p 1-65535`) with service & version detection (`-sV --version-intensity 7`)
  - OS fingerprinting with confidence percentage (`-O --osscan-guess`)
  - NSE safe-script suite: `http-title`, `http-server-header`, `ssl-cert`, `ssh-hostkey`, `smb-os-discovery`, `dns-service-discovery`, `banner`, `snmp-info`, `upnp-info`, `nbstat`
  - UDP scan on high-value ports 67 (DHCP), 161 (SNMP), 1900 (UPnP), 5353 (mDNS) — root only
  - Extra targeted probe on common admin/IoT ports (7547, 8080, 8081, 8443, 8888, 9090, 49152…) to pierce Android hotspot iptables rules
  - Scrollable port table in TUI with inline NSE script output per port
  - Deep risk analysis: SSL cert warnings, SNMP/UPnP exposure, TR-069 (port 7547), Telnet/SSH version checks, router firmware identification

### Hotspot & Gateway Fixes

- **Default gateway detection** — `defaultCIDR()` now reads `/proc/net/route` (Linux) and `route get default` (macOS) instead of using interface index order; correctly selects the hotspot interface over Docker/VPN bridges
- **`-Pn` flag** added to all Deep Scan TCP arguments so Android hotspot targets are always scanned (Android iptables drops ICMP on the tethering interface by default)
- **Gateway badge `📡`** shown in the host list next to the detected default gateway / hotspot router
- **Hotspot heuristic** in `AnalyseHostDeep`: gateway + Linux OS + ≤ 4 open TCP ports → classified as `mobile hotspot / router`

### Code Quality

- Fixed 7 `staticcheck QF1012` warnings in `buildRawSummary` — replaced `sb.WriteString(fmt.Sprintf(…))` with `fmt.Fprintf(&sb, …)`
- Fixed `misspell` false-positive on `"routeros"` (MikroTik RouterOS product name) with `//nolint:misspell`

---

## [Unreleased]

- macOS WiFi support via `airport` command
- JSON / CSV export of scan results
- Host list search and filter
- Sort WiFi results by signal or score
