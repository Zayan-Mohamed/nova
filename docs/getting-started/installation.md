# Installation

## Requirements

| Dependency      | Purpose                                          | Required?          |
| --------------- | ------------------------------------------------ | ------------------ |
| `nmap`          | LAN host discovery (root mode) and port scanning | Yes                |
| `nmcli`         | WiFi scanning via NetworkManager (Linux)         | For WiFi only      |
| `ping` (setuid) | Non-root host discovery via ICMP sweep           | Yes (non-root)     |
| Go 1.24+        | Build from source only                           | Source builds only |

!!! note "macOS"
`nmcli` is a Linux-only tool (NetworkManager). WiFi scanning is **not yet supported on macOS**.
LAN host discovery and port scanning work normally on both Linux and macOS.

### Install nmap

=== "Debian / Ubuntu"
`bash
    sudo apt install nmap
    `

=== "Arch / Manjaro"
`bash
    sudo pacman -S nmap
    `

=== "Fedora / RHEL"
`bash
    sudo dnf install nmap
    `

=== "macOS (Homebrew)"
`bash
    brew install nmap
    `

---

## Option A — Pre-built binary (recommended)

Download the binary for your platform from the [Releases page](https://github.com/Zayan-Mohamed/nova/releases):

| File                       | Platform                         |
| -------------------------- | -------------------------------- |
| `nova_linux_amd64.tar.gz`  | Linux 64-bit (Intel/AMD)         |
| `nova_linux_arm64.tar.gz`  | Linux ARM64 (Raspberry Pi, etc.) |
| `nova_darwin_amd64.tar.gz` | macOS Intel                      |
| `nova_darwin_arm64.tar.gz` | macOS Apple Silicon              |

```bash
# Example: Linux amd64
tar -xzf nova_linux_amd64.tar.gz
chmod +x nova
sudo mv nova /usr/local/bin/

# Verify
nova --version
```

---

## Option B — `go install`

Requires Go 1.24+ on your `PATH`:

```bash
go install github.com/Zayan-Mohamed/nova@latest
```

The binary is placed in `$(go env GOPATH)/bin`. Make sure that directory is on your `PATH`:

```bash
export PATH="$PATH:$(go env GOPATH)/bin"
```

---

## Option C — Build from source

```bash
git clone https://github.com/Zayan-Mohamed/nova.git
cd nova
go build -o nova .
./nova --help
```

For a fully static binary matching the release builds:

```bash
CGO_ENABLED=0 go build -ldflags="-s -w" -o nova .
```

---

## Verify installation

```bash
nova --version
nova --help
```

---

## Running without root

NOVA works without root privileges. In non-root mode:

- **Host discovery** uses the system `ping` binary (which is setuid-root on most distros, so it can send ICMP without your process being root) combined with reading the kernel ARP cache at `/proc/net/arp`.
- **Port scanning** uses nmap TCP connect scan (`-sT`) instead of SYN scan.

To use the faster root mode:

```bash
sudo nova
```

!!! warning
NOVA will **never** attempt to escalate privileges automatically.
If a root-only operation is needed and you are not root, NOVA will display a message and let you decide.
