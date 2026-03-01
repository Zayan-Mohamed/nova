# Risk Scoring

NOVA computes a **0–100 security score** and a list of human-readable **findings** for every WiFi network and LAN host.

---

## Score interpretation

| Range  | Label    | Colour          |
| ------ | -------- | --------------- |
| 0–30   | Critical | 🔴 Red          |
| 31–55  | High     | 🟠 Orange       |
| 56–70  | Medium   | 🟡 Yellow       |
| 71–85  | Low      | 🟢 Green        |
| 86–100 | Secure   | 💚 Bright Green |

---

## Finding severity levels

Each finding has one of five levels:

| Level        | Meaning                                             |
| ------------ | --------------------------------------------------- |
| **Info**     | Purely informational — no immediate action required |
| **Low**      | Minor concern — worth noting                        |
| **Medium**   | Notable issue — should be reviewed                  |
| **High**     | Serious vulnerability — prioritise remediation      |
| **Critical** | Severe / immediate risk — act now                   |

---

## WiFi network scoring

Starts at **100**. Deductions applied per finding:

| Finding                      | Deduction | Level    |
| ---------------------------- | --------- | -------- |
| No encryption (open network) | −60       | Critical |
| WEP encryption               | −55       | Critical |
| WPA (TKIP) — deprecated      | −30       | High     |
| WPA2 with no WPA3            | −5        | Low      |
| WPA3 present                 | 0         | —        |

---

## LAN host scoring

Starts at **100**. Deductions depend on open ports and findings:

| Finding                                        | Deduction         | Level    |
| ---------------------------------------------- | ----------------- | -------- |
| Critical-level port open (Telnet, SMB, Redis…) | −25 each (capped) | Critical |
| High-level port open (RDP, UPnP, NFS…)         | −15 each (capped) | High     |
| Medium-level port open (MySQL, SMTP…)          | −8 each           | Medium   |
| Low-level port open (HTTP, DNS…)               | −3 each           | Low      |
| Unknown MAC vendor                             | −5                | Low      |
| Router/gateway detected with dangerous ports   | −10               | High     |

---

## Data flow

```
wifi.Network / scanner.Host
        │
        ▼
   risk.AnalyseNetwork()
   risk.AnalyseHost()
        │
        ▼
  []Finding  +  Score (0–100)
        │
        ▼
   ui.viewWiFi / ui.viewHostDetail
```

The risk package has **no side effects** — it is a pure function that takes scan data and returns findings. It never modifies the network, opens connections, or writes files.
