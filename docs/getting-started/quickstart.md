# Quickstart

## 1. Launch NOVA

```bash
nova
```

NOVA auto-detects your active subnet (skipping virtual interfaces like Docker, VPNs, bridges).

To override the subnet:

```bash
nova --subnet 192.168.0.0/24
# or
nova -s 10.0.0.0/24
```

---

## 2. Consent screen

```
 ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗
 ████╗  ██║██╔═══██╗██║   ██║██╔══██╗
 ...

⚠  LEGAL NOTICE

By continuing you confirm that:

  •  You OWN the network(s) you are about to scan, OR
  •  You have received EXPLICIT written permission from the owner.

Do you understand and accept these terms?
[y] Accept & continue    [n / q] Exit
```

Press **`y`** to continue. Any other key exits immediately.

---

## 3. Main menu

Navigate with `↑`/`↓` (or `k`/`j`), select with `Enter`:

```
╭──────────────────────────────╮
│  ▶   WiFi Analysis           │
╰──────────────────────────────╯
╭──────────────────────────────╮
│     LAN Host Discovery       │
╰──────────────────────────────╯
╭──────────────────────────────╮
│     Help                     │
╰──────────────────────────────╯
╭──────────────────────────────╮
│     Quit                     │
╰──────────────────────────────╯
```

---

## 4. WiFi Analysis

NOVA runs `nmcli` and displays all visible networks ranked by signal strength:

```
SSID              BSSID              Signal  Band  Security  Score
MyHomeRouter      AA:BB:CC:DD:EE:FF    82%   5GHz  WPA2       88
Neighbour_WiFi    11:22:33:44:55:66    61%   2.4GHz WPA2      76
OldRouter         FF:EE:DD:CC:BB:AA    34%   2.4GHz WEP        5
```

**Search:** press `/`, type SSID or BSSID, press `Enter`.  
**Filter by security:** press `f` to cycle through Open → WPA2 → WPA3.  
**Clear filters:** press `c`.

---

## 5. LAN Host Discovery

Enumerates all active hosts on your subnet:

```
IP               Hostname           MAC               Vendor         Score
192.168.1.1      router.local       AA:BB:CC:DD:EE:FF  TP-Link         62
192.168.1.42     desktop.local      11:22:33:44:55:66  Intel           91
192.168.1.105    —                  FF:EE:DD:CC:BB:AA  Unknown         45
```

Press **`Enter`** on any host to run a port scan and see detailed findings.

---

## 6. Host detail & port scan

```
Host: 192.168.1.1  (router.local)
MAC:  AA:BB:CC:DD:EE:FF — TP-Link Technologies
Score: 62 / 100  [Medium Risk]

Open Ports:
  80   HTTP     [LOW]     Unencrypted web interface detected.
  23   Telnet   [CRITICAL] Transmits all data in plaintext.
  1900 UPnP     [HIGH]    May allow unauthenticated port-forward requests.

Findings:
  ● [HIGH]     Router exposure — management port open to LAN
  ● [CRITICAL] Telnet service active
```

Press **`r`** to re-scan, **`Esc`** to go back.
