# WiFi Analysis

NOVA scans nearby wireless access points using `nmcli` and produces a security assessment for each network.

---

## How it works

NOVA invokes:

```
nmcli -t -f SSID,BSSID,SIGNAL,CHAN,FREQ,SECURITY,DEVICE dev wifi list --rescan yes
```

The output is parsed, sanitised (control characters stripped, SSID/BSSID length-limited), and enriched with:

- **Frequency band** derived from the frequency field (2.4 GHz vs 5 GHz)
- **Security risk analysis** based on the encryption type
- **Security score** (0–100)

!!! note "Linux only"
WiFi scanning requires `nmcli` (NetworkManager). macOS support is planned for a future release.

---

## Displayed fields

| Column       | Description                                                              |
| ------------ | ------------------------------------------------------------------------ |
| **SSID**     | Network name (truncated to 32 characters)                                |
| **BSSID**    | Access point MAC address                                                 |
| **Signal**   | Signal strength as percentage (derived from nmcli's 0–100 value)         |
| **Band**     | `2.4 GHz` or `5 GHz`                                                     |
| **Security** | Encryption type reported by nmcli (`WPA2`, `WPA3`, `WEP`, `--` for open) |
| **Score**    | Security score 0–100 (higher = more secure)                              |

---

## Search and filter

### Live search — `/`

Press `/` to enter search mode. Type any part of an SSID or BSSID.
Results filter in real time. Press `Enter` to lock in the filter or `Esc` to cancel.

```
Search: MyHome_
Showing 2 of 14 networks
```

### Security filter — `f`

Press `f` to cycle through security type filters:

| State    | Shows                       |
| -------- | --------------------------- |
| _(none)_ | All networks                |
| `open`   | Networks with no encryption |
| `wpa2`   | WPA2-secured networks       |
| `wpa3`   | WPA3-secured networks       |

### Clear filters — `c`

Press `c` to clear both the search query and the security filter.

---

## Security findings

| Condition                    | Level        | Description                                             |
| ---------------------------- | ------------ | ------------------------------------------------------- |
| Open network (no encryption) | **Critical** | All traffic is visible to anyone within range           |
| WEP encryption               | **Critical** | WEP is cryptographically broken and trivially crackable |
| WPA (TKIP)                   | **High**     | WPA-TKIP is deprecated; vulnerable to several attacks   |
| WPA2                         | Low / None   | Generally secure; score depends on other factors        |
| WPA3                         | None         | Current best-practice encryption                        |

---

## Scoring

The WiFi security score starts at **100** and deductions are applied based on findings:

| Finding              | Deduction |
| -------------------- | --------- |
| Open network         | −60       |
| WEP                  | −55       |
| WPA (TKIP)           | −30       |
| Hidden SSID concerns | −5        |

A score of **0–30** is Critical, **31–60** is High/Medium, **61–80** is Low, **81–100** is healthy.
