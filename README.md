# NOVA — Network Observation & Vulnerability Analyzer

> A terminal-based WiFi and LAN security assessment tool written in Go.

[![CI](https://github.com/Zayan-Mohamed/nova/actions/workflows/ci.yml/badge.svg)](https://github.com/Zayan-Mohamed/nova/actions/workflows/ci.yml)
[![Release](https://github.com/Zayan-Mohamed/nova/actions/workflows/release.yml/badge.svg)](https://github.com/Zayan-Mohamed/nova/actions/workflows/release.yml)
[![Docs](https://github.com/Zayan-Mohamed/nova/actions/workflows/docs.yml/badge.svg)](https://zayan-mohamed.github.io/nova/)
[![Go Report Card](https://goreportcard.com/badge/github.com/Zayan-Mohamed/nova)](https://goreportcard.com/report/github.com/Zayan-Mohamed/nova)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

📖 **[Full Documentation](https://zayan-mohamed.github.io/nova/)**

---

## ⚠ Legal Notice

**Only scan networks you own or have explicit written permission to assess.**

Scanning networks without authorisation is illegal in most jurisdictions and may result
in criminal or civil liability. NOVA displays a consent screen before every scan session
and requires explicit acknowledgement.

---

## What is NOVA?

NOVA is a **defensive** security assessment tool. It helps network owners and administrators
understand the security posture of their own WiFi and LAN environments. It does **not**
perform exploitation, brute-forcing, or any offensive action.

### Features

| Feature                     | Description                                                                                                                                     |
| --------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| **WiFi Analysis**           | Lists nearby access points with SSID, BSSID, encryption type, channel, frequency, and signal strength                                           |
| **WiFi Search & Filter**    | Live search by SSID/BSSID (`/`) and filter by security type — Open / WPA2 / WPA3 (`f`)                                                          |
| **Encryption Assessment**   | Detects Open / WEP / WPA / WPA2 / WPA3 and flags weak or broken configurations                                                                  |
| **LAN Host Discovery**      | Ping-sweep of your subnet to enumerate active hosts with MAC address and vendor lookup                                                          |
| **Port & Service Scanning** | Scans ports 1–1024 (or a custom range) and identifies running services                                                                          |
| **Risk Scoring**            | Weighted 0–100 security score per network and per host                                                                                          |
| **Risk Tagging**            | Color-coded findings (Info → Critical) for dangerous open ports (SMB, Telnet, RDP, Redis, MongoDB, etc.)                                        |
| **Keyboard-driven TUI**     | Full terminal UI built with [Bubble Tea](https://github.com/charmbracelet/bubbletea) and [Lip Gloss](https://github.com/charmbracelet/lipgloss) |

---

## Requirements

| Dependency | Purpose                                | Install                                       |
| ---------- | -------------------------------------- | --------------------------------------------- |
| `nmap`     | LAN host discovery and port scanning   | `sudo apt install nmap` / `brew install nmap` |
| `nmcli`    | WiFi network scanning (NetworkManager) | Pre-installed on most Linux distros           |
| Go 1.24+   | Build from source only                 | [go.dev/dl](https://go.dev/dl/)               |

> **macOS note:** `nmcli` is Linux-only. WiFi scanning on macOS is not yet supported.
> LAN host discovery and port scanning work on both platforms.

---

## Installation

### Option A — Download a pre-built binary (recommended)

Go to the [Releases page](https://github.com/Zayan-Mohamed/nova/releases) and download
the binary for your platform:

```
nova_linux_amd64.tar.gz    — Linux (64-bit)
nova_linux_arm64.tar.gz    — Linux (ARM64 / Raspberry Pi)
nova_darwin_amd64.tar.gz   — macOS (Intel)
nova_darwin_arm64.tar.gz   — macOS (Apple Silicon)
```

```bash
tar -xzf nova_linux_amd64.tar.gz
sudo mv nova /usr/local/bin/
nova --help
```

### Option B — Install with `go install`

```bash
go install github.com/Zayan-Mohamed/nova@latest
```

### Option C — Build from source

```bash
git clone https://github.com/Zayan-Mohamed/nova.git
cd nova
go build -o nova .
./nova --help
```

---

## Usage

```bash
nova                       # auto-detect subnet
nova --subnet 10.0.0.0/24  # override subnet
nova -s 192.168.1.0/24     # short form
```

### TUI Key Bindings

| Key               | Action                                                 |
| ----------------- | ------------------------------------------------------ |
| `↑` / `k`         | Move selection up                                      |
| `↓` / `j`         | Move selection down                                    |
| `Enter` / `Space` | Select / activate                                      |
| `r`               | Re-run the current scan                                |
| `/`               | Search (WiFi view)                                     |
| `f`               | Cycle security filter — Open → WPA2 → WPA3 (WiFi view) |
| `c`               | Clear all filters (WiFi view)                          |
| `Esc` / `q`       | Go back / exit current view                            |
| `Ctrl+C`          | Quit NOVA immediately                                  |

### Typical workflow

```
1. Launch nova
2. Accept the legal consent screen  →  press y
3. Main Menu:
   ├── WiFi Analysis       → lists nearby APs with security score
   │     ├── /             → live search by SSID or BSSID
   │     └── f             → filter by encryption type
   └── LAN Host Discovery  → lists active hosts on your subnet
                            └── Enter on a host → port scan + risk detail
```

---

## Architecture

```
main.go
  └── cmd/root.go          CLI entry-point (cobra)
        └── internal/
              ├── wifi/    WiFi scanning via nmcli
              ├── scanner/ LAN host discovery + port scanning via nmap/ping
              ├── risk/    Security scoring and risk tagging
              └── ui/      BubbleTea TUI
```

Dependency direction is strictly `main → cmd → internal/*`.
No global mutable state. No circular imports.

---

## Security

Please report vulnerabilities responsibly — see [SECURITY.md](SECURITY.md).

---

## Contributing

Pull requests are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

---

## License

[MIT](LICENSE) © Zayan Mohamed
