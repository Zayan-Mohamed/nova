# NOVA — Network Observation & Vulnerability Analyzer

> A terminal-based WiFi and LAN security assessment tool written in Go.

[![CI](https://github.com/Zayan-Mohamed/nova/actions/workflows/ci.yml/badge.svg)](https://github.com/Zayan-Mohamed/nova/actions/workflows/ci.yml)
[![Release](https://github.com/Zayan-Mohamed/nova/actions/workflows/release.yml/badge.svg)](https://github.com/Zayan-Mohamed/nova/actions/workflows/release.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/Zayan-Mohamed/nova)](https://goreportcard.com/report/github.com/Zayan-Mohamed/nova)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

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
| Go 1.21+   | Build from source only                 | [go.dev/dl](https://go.dev/dl/)               |

> **macOS note:** `nmcli` is Linux-only. WiFi scanning on macOS is not yet supported.
> The LAN host discovery and port scanning features work on both platforms.

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

Extract and place the binary on your `PATH`:

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

### Launch the interactive TUI

```bash
nova
```

NOVA will auto-detect your local `/24` subnet. You can override it:

```bash
nova --subnet 10.0.0.0/24
# or short form:
nova -s 10.0.0.0/24
```

### TUI Key Bindings

| Key               | Action                      |
| ----------------- | --------------------------- |
| `↑` / `k`         | Move selection up           |
| `↓` / `j`         | Move selection down         |
| `Enter` / `Space` | Select / activate           |
| `r`               | Re-run the current scan     |
| `Esc` / `q`       | Go back / exit current view |
| `Ctrl+C`          | Quit NOVA immediately       |

### Typical workflow

```
1. Launch nova
2. Read and accept the legal consent screen (press y)
3. Main Menu:
   ├── WiFi Analysis      → lists nearby APs with security score
   └── LAN Host Discovery → lists active hosts on your subnet
                           └── press Enter on a host → port scan + risk detail
```

### Root vs. non-root

| Mode                   | Behaviour                                                  |
| ---------------------- | ---------------------------------------------------------- |
| **Root** (`sudo nova`) | Uses nmap SYN scan (`-sS`) — faster, more accurate         |
| **Non-root**           | Uses nmap TCP connect scan (`-sT`) — slower but functional |

NOVA **never** attempts to escalate privileges automatically. If root is required it will
display a message and let you decide.

---

## Architecture

```
main.go
  └── cmd/root.go          CLI entry-point (cobra)
        └── internal/
              ├── wifi/    WiFi scanning via nmcli
              ├── scanner/ LAN host discovery + port scanning via nmap
              ├── risk/    Security scoring and risk tagging
              └── ui/      BubbleTea TUI
```

Dependency direction is strictly `main → cmd → internal/*`. Internal packages
never import `cmd`. There is no global mutable state.

---

## Security

Please report vulnerabilities responsibly. See [SECURITY.md](SECURITY.md).

---

## Contributing

Pull requests are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

---

## License

[MIT](LICENSE) © Zayan Mohamed
