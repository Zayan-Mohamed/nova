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
