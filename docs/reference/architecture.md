# Architecture

## Package structure

```
nova/
├── main.go               Entry point — wires version info, calls cmd.Execute()
├── go.mod                Module: github.com/Zayan-Mohamed/nova
├── cmd/
│   └── root.go           Cobra CLI — flags, subnet detection, launches ui.Run()
└── internal/
    ├── wifi/
    │   └── wifi.go       WiFi scanning via nmcli
    ├── scanner/
    │   └── scanner.go    LAN host discovery + port scanning via nmap/ping
    ├── risk/
    │   └── risk.go       Security scoring and risk tagging (pure functions)
    └── ui/
        └── ui.go         BubbleTea TUI — all views and keyboard handling
```

---

## Dependency direction

```
main.go
  └── cmd/root.go
        ├── internal/ui
        │     ├── internal/risk
        │     │     ├── internal/wifi
        │     │     └── internal/scanner
        │     ├── internal/wifi
        │     └── internal/scanner
        └── internal/scanner  (for ValidateCIDR)
```

**Rule:** `internal/*` packages never import `cmd/`. No circular imports. No global mutable state.

---

## Data flow

```
nmcli output
    │
    ▼
wifi.ScanNetworks()        returns []wifi.Network
    │
    ▼
risk.AnalyseNetwork()      returns []risk.NetworkReport
    │
    ▼
ui.viewWiFi()              renders TUI table

─────────────────────────────────────────────

ping sweep / nmap ICMP
    │
    ▼
scanner.DiscoverHosts()    returns []scanner.Host
    │
    ▼
risk.AnalyseHost()         returns []risk.HostReport
    │
    ▼
ui.viewHosts()             renders TUI table

─────────────────────────────────────────────

nmap TCP/SYN scan
    │
    ▼
scanner.PortScan()         returns []scanner.Port
    │
    ▼
risk.AnalyseHost()         enriched with port findings
    │
    ▼
ui.viewHostDetail()        renders port list + findings
```

---

## Key design decisions

### No shell interpolation

All external commands use structured argument slices:

```go
// ✅ correct
exec.Command("nmap", "-sn", "-oX", "-", cidr)

// ❌ never done
exec.Command("sh", "-c", "nmap -sn "+cidr)
```

This eliminates shell injection regardless of the CIDR value.

### XML output parsing

nmap results are consumed as XML via `-oX -` (stdout). The parser uses `bufio` line-by-line scanning rather than loading the entire output into memory, bounding memory use for large scans.

### Input sanitisation

All data from external sources (nmap, nmcli, ARP cache, rDNS) passes through sanitisation helpers before storage or display:

- `sanitizeField` — strips non-printable characters, limits length
- `sanitizeIP` — validates IPv4 format
- `sanitizeMAC` — validates MAC format
- `sanitizePort` — numeric range check
- `sanitizeProtocol` — allowlist: `tcp` / `udp`

### Privilege separation

`DiscoverHosts(ctx, cidr, isRoot bool)` dispatches to:

- `discoverWithNmap` — root path (raw ICMP via nmap)
- `discoverWithPing` — non-root path (setuid ping binary + `/proc/net/arp`)

No automatic privilege escalation is ever attempted.

### TUI async safety

All scans run as `tea.Cmd` goroutines that return result messages. The BubbleTea `Update` loop processes them on the main goroutine — no shared mutable state between scan goroutines and the UI.

---

## Technology choices

| Component      | Library                   | Reason                             |
| -------------- | ------------------------- | ---------------------------------- |
| CLI            | `spf13/cobra`             | Industry-standard Go CLI framework |
| TUI            | `charmbracelet/bubbletea` | Elm-architecture TUI; async-safe   |
| Styling        | `charmbracelet/lipgloss`  | Declarative terminal styling       |
| WiFi scan      | `nmcli` (system)          | Standard NetworkManager CLI        |
| Host discovery | `nmap` / `ping` (system)  | Proven, setuid-capable tools       |
| Port scan      | `nmap` (system)           | Best-in-class service detection    |
