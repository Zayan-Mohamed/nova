# LAN Host Discovery

NOVA enumerates all active hosts on your local subnet and enriches each result with hostname, MAC address, and vendor information.

---

## How it works

NOVA uses two discovery strategies depending on privilege level:

### Root mode (`sudo nova`)

Uses **nmap** with ICMP echo + timestamp probes for fast, reliable discovery:

```
nmap -sn -n -oX - -PE -PP <cidr>
```

### Non-root mode

Uses a **parallel `ping` sweep** combined with **ARP cache reading**:

1. All host IPs in the subnet are enumerated (up to 512 hosts)
2. 50 concurrent goroutines each run `ping -c 1 -W 2 <ip>`
3. The kernel ARP table (`/proc/net/arp` on Linux, `arp -an` on macOS) is read to retrieve MAC addresses for hosts that responded
4. Reverse DNS lookup enriches each host with a hostname

!!! info
The system `ping` binary is typically setuid-root, allowing it to send ICMP packets without your process being root. This is the standard behaviour on all major Linux distributions and macOS.

---

## Subnet auto-detection

NOVA automatically selects your active subnet by:

1. Reading the OS routing table to find the **default route** interface:
   - **Linux** — parses `/proc/net/route` and picks the row with destination `0.0.0.0`
   - **macOS** — runs `route get default` and extracts the interface name
2. Using the subnet mask of that interface (not a forced `/24`)
3. Falling back to iterating interfaces and skipping virtual/container prefixes (`docker`, `br-`, `virbr`, `veth`, `vmnet`, `vboxnet`, `tun`, `tap`, `wg`, `utun`, `vpn`, `dummy`, `bond`, `team`) if no default route is found

This ensures NOVA selects the **hotspot / WiFi tethering interface** rather than a Docker bridge or VPN tunnel that may appear earlier in the interface list.

Override with:

```bash
nova --subnet 10.10.0.0/16
```

---

## Displayed fields

| Column       | Description                                                           |
| ------------ | --------------------------------------------------------------------- |
| **IP**       | Host IPv4 address — `📡` badge shown on the default gateway / hotspot |
| **Hostname** | Reverse DNS name (or `—` if unresolvable)                             |
| **MAC**      | Hardware address from ARP cache (root: from nmap)                     |
| **Vendor**   | NIC manufacturer derived from MAC OUI prefix                          |
| **Score**    | Security score 0–100                                                  |

---

## Limits

| Limit                     | Value                 | Reason                                      |
| ------------------------- | --------------------- | ------------------------------------------- |
| Max hosts scanned         | 512                   | Prevents memory exhaustion on large subnets |
| Minimum prefix length     | /8                    | Rejects subnets too large to scan safely    |
| Maximum prefix length     | /30                   | Rejects point-to-point links                |
| Per-host ping timeout     | 2 seconds             | Prevents indefinite blocking                |
| Scan-wide context timeout | Inherited from caller | Respects global cancellation                |

---

## Security findings per host

After discovery, each host is passed to the [Risk Scoring](risk-scoring.md) engine which analyses:

- Unknown/unresolvable MAC vendor
- Presence of a router/gateway IP
- Open dangerous ports (once port scan is run)
