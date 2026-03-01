# NOVA

**Network Observation & Vulnerability Analyzer**

> A terminal-based, keyboard-driven security assessment tool for WiFi and LAN environments — written in Go.

[![CI](https://github.com/Zayan-Mohamed/nova/actions/workflows/ci.yml/badge.svg)](https://github.com/Zayan-Mohamed/nova/actions/workflows/ci.yml)
[![Release](https://github.com/Zayan-Mohamed/nova/actions/workflows/release.yml/badge.svg)](https://github.com/Zayan-Mohamed/nova/actions/workflows/release.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/Zayan-Mohamed/nova)](https://goreportcard.com/report/github.com/Zayan-Mohamed/nova)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/Zayan-Mohamed/nova/blob/main/LICENSE)

---

!!! warning "Legal Notice"
**Only scan networks you own or have explicit written permission to assess.**

    Scanning networks without authorisation is illegal in most jurisdictions and may result in criminal or civil liability.
    NOVA displays a consent screen before every scan session and requires explicit acknowledgement.

---

## What is NOVA?

NOVA is a **defensive** network security assessment tool. It gives network administrators and security-conscious users a clear view of their WiFi and LAN security posture — without performing any exploitation, brute-forcing, or offensive action.

<div class="grid cards" markdown>

- :material-wifi:{ .lg .middle } **WiFi Analysis**

  ***

  Scan nearby access points, inspect encryption strength, detect open or WEP networks, and search/filter results live.

  [:octicons-arrow-right-24: WiFi Analysis](features/wifi-analysis.md)

- :material-lan:{ .lg .middle } **LAN Host Discovery**

  ***

  Auto-detect your subnet and enumerate all active hosts with MAC addresses, vendor lookup, and hostname resolution.

  [:octicons-arrow-right-24: LAN Discovery](features/lan-discovery.md)

- :material-magnify:{ .lg .middle } **Port & Service Scanning**

  ***

  Scan open ports on any discovered host and identify running services with risk assessments.

  [:octicons-arrow-right-24: Port Scanning](features/port-scanning.md)

- :material-shield-alert:{ .lg .middle } **Risk Scoring**

  ***

  Get a weighted 0–100 security score and colour-coded findings (Info → Critical) for every network and host.

  [:octicons-arrow-right-24: Risk Scoring](features/risk-scoring.md)

</div>

---

## Quick Start

```bash
# Install (Linux/macOS amd64)
tar -xzf nova_linux_amd64.tar.gz
sudo mv nova /usr/local/bin/

# Launch
nova
```

NOVA auto-detects your subnet. Override it with:

```bash
nova --subnet 192.168.1.0/24
```

See the [Installation guide](getting-started/installation.md) for all options.

---

## Design Principles

| Principle             | What it means                                                    |
| --------------------- | ---------------------------------------------------------------- |
| **Defensive only**    | No exploits, no brute-force, no packet injection                 |
| **Explicit consent**  | Consent screen before every scan — no silent background scanning |
| **Minimal privilege** | Root is optional; non-root mode uses `ping` + ARP cache          |
| **No telemetry**      | Zero data collection, no phone-home, local-only logs             |
| **Secure by design**  | All external input sanitised; no shell string interpolation      |
