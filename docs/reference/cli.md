# CLI Reference

## Synopsis

```
nova [flags]
```

---

## Flags

| Flag        | Short | Default       | Description                                 |
| ----------- | ----- | ------------- | ------------------------------------------- |
| `--subnet`  | `-s`  | Auto-detected | CIDR subnet to scan (e.g. `192.168.1.0/24`) |
| `--version` |       |               | Print version, commit, and build date       |
| `--help`    | `-h`  |               | Show help                                   |

---

## Examples

```bash
# Launch with auto-detected subnet
nova

# Override subnet
nova --subnet 10.0.0.0/24
nova -s 172.16.0.0/16

# Print version
nova --version

# Run as root for full scan capabilities
sudo nova
sudo nova -s 192.168.0.0/24
```

---

## Subnet auto-detection

When no `--subnet` flag is provided, NOVA selects the first non-virtual network interface
with a non-loopback IPv4 address and uses its actual network address and mask.

Interfaces with the following prefixes are **skipped**:

```
docker  br-  virbr  veth  vmnet  vboxnet  tun  tap  wg  utun  vpn  dummy  bond  team
```

---

## Exit codes

| Code | Meaning                                              |
| ---- | ---------------------------------------------------- |
| `0`  | Clean exit (user quit normally)                      |
| `1`  | Fatal error (missing dependency, invalid flag, etc.) |

---

## Version string

The `--version` output is injected at build time via ldflags:

```
nova version v0.1.0 (commit abc1234, built 2026-03-01)
```

In development builds (no ldflags), defaults to:

```
nova version dev (commit none, built unknown)
```
