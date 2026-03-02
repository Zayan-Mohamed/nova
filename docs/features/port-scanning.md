# Port & Service Scanning

Once a host is selected in the LAN Discovery view, NOVA runs a targeted port scan to identify open services and assess their risk.

---

## How it works

NOVA delegates port scanning to **nmap** with structured arguments (no shell interpolation):

### Root mode

```
nmap -sS -sV --open -T3 -p <ports> -oX - <ip>
```

Uses SYN scan (`-sS`) — faster, more accurate, less noisy than TCP connect.

### Non-root mode

```
nmap -sT -sV --open -T3 -p <ports> -oX - <ip>
```

Uses TCP connect scan (`-sT`) — slightly slower but requires no raw socket privileges.

In both cases, output is XML (`-oX -`) parsed directly from stdout — no temporary files written.

---

## Default port range

The default scan covers **ports 1–1024** (well-known services range).

---

## Displayed fields

| Column      | Description                                              |
| ----------- | -------------------------------------------------------- |
| **Port**    | TCP port number                                          |
| **Service** | Service name identified by nmap                          |
| **Version** | Service version string (truncated and sanitised)         |
| **Risk**    | Risk level badge — Info / Low / Medium / High / Critical |

---

## Dangerous ports

NOVA maintains a curated list of high-risk ports with associated risk levels:

| Port    | Service          | Level    | Reason                                      |
| ------- | ---------------- | -------- | ------------------------------------------- |
| 21      | FTP              | High     | Plaintext credentials                       |
| 23      | Telnet           | Critical | Fully plaintext protocol                    |
| 25      | SMTP             | Medium   | Open relay risk                             |
| 80      | HTTP             | Low      | Unencrypted web interface                   |
| 111     | RPC              | High     | NFS exploitation vector                     |
| 135     | MS RPC           | High     | Windows attack surface                      |
| 139/445 | NetBIOS/SMB      | Critical | Ransomware / lateral movement (EternalBlue) |
| 512–514 | rexec/rlogin/rsh | Critical | Legacy trust-based auth                     |
| 1900    | UPnP             | High     | Unauthenticated port-forward requests       |
| 2049    | NFS              | High     | Unauthenticated filesystem access           |
| 3306    | MySQL            | Medium   | Database exposed to LAN                     |
| 3389    | RDP              | High     | Remote Desktop — brute-force target         |
| 5900    | VNC              | High     | Remote desktop — often poorly secured       |
| 6379    | Redis            | Critical | Default: no authentication                  |
| 27017   | MongoDB          | Critical | Default: no authentication                  |

---

## Security considerations

- All nmap arguments are passed as a structured slice — **no shell string interpolation**
- Service banner strings are **sanitised** before display (control chars stripped, length capped)
- nmap is required to be installed; NOVA does not bundle or download it
- NOVA never performs exploit probes — only service version detection (`-sV`)

---

## Deep Scan

Press `d` from the Host Detail view to run a **Deep Scan** — a comprehensive, Fing-style host intelligence pass that goes far beyond the default 1–1024 port range.

### What it runs

#### TCP full-port sweep

```
nmap {-sS|-sT} -Pn [-O] --osscan-guess \
  -sV --version-intensity 7 \
  --script http-title,http-server-header,ssl-cert,ssh-hostkey,\
           smb-os-discovery,dns-service-discovery,banner,\
           snmp-info,upnp-info,nbstat \
  --open -p 1-65535 -T4 --host-timeout 120s -oX - <ip>
```

- `-Pn` — skips host-discovery ICMP probes; essential for **mobile hotspots** where Android iptables drops ICMP on the tethering interface
- `-O` / `--osscan-guess` — OS fingerprinting with confidence percentage (root only)
- NSE scripts are limited to the **`safe`** and **`discovery`** categories — no `exploit`, `brute`, or `dos` scripts ever run

#### UDP high-value ports (root only)

```
nmap -sU -Pn -p 67,161,1900,5353 -T4 --host-timeout 30s -oX - <ip>
```

| Port | Service | Why it matters                          |
| ---- | ------- | --------------------------------------- |
| 67   | DHCP    | Confirms device is acting as a gateway  |
| 161  | SNMP    | Device description, firmware, uptime    |
| 1900 | UPnP    | Unauthenticated port-forward capability |
| 5353 | mDNS    | Bonjour/Avahi service advertisement     |

#### Admin/IoT port probe (hotspot bypass)

A targeted TCP connect scan is run against ports commonly used by router admin panels and IoT devices that would otherwise be blocked by Android hotspot iptables rules:

```
80, 443, 7547, 8080, 8081, 8443, 8888, 9090, 4040, 5985, 49152, 49153
```

### Deep Scan TUI view

- **Identity panel** — hostname, MAC + vendor, OS with confidence %, device type, risk score
- **Full port table** — all 65 535 ports, scrollable with `↑`/`↓`; dangerous ports highlighted in red `⚠`
- **Inline NSE output** — up to 2 script results shown per port (e.g. HTTP title, SSL CN, SSH key fingerprint)
- **Risk findings** — deep analysis findings listed with severity and description

### Deep scan timeout

The deep scan allows up to **3 minutes** total. A spinner and ETA message are shown during the scan. Root mode is faster (SYN scan); non-root uses TCP connect and skips UDP and raw OS detection.
