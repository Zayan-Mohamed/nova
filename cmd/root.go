// Package cmd is the entry-point for all NOVA CLI commands.
// It wires together the cobra command tree and delegates to the ui package
// for the interactive TUI. No business logic lives here.
package cmd

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Zayan-Mohamed/nova/internal/ui"
)

// version info — set by main via SetVersionInfo, populated at link time by GoReleaser.
var (
	appVersion = "dev"
	appCommit  = "none"
	appDate    = "unknown"
)

// SetVersionInfo is called by main to inject build-time version metadata.
// It must also update rootCmd.Version and the version template because rootCmd
// is initialised as a package-level variable (before main runs), so the
// Version field and SetVersionTemplate call in init() both see the default
// "dev" / "none" / "unknown" values — not the ldflags-injected ones.
func SetVersionInfo(version, commit, date string) {
	appVersion = version
	appCommit = commit
	appDate = date
	rootCmd.Version = version
	rootCmd.SetVersionTemplate(
		"NOVA {{.Version}} (commit: " + commit + ", built: " + date + ")\n",
	)
}

// flagCIDR holds the value of the --subnet flag.
var flagCIDR string

// virtualIfacePrefixes lists interface name prefixes that belong to virtual,
// container, or VPN adapters. These are skipped when auto-detecting the
// physical LAN subnet so we don't accidentally target a Docker bridge or VPN.
var virtualIfacePrefixes = []string{
	"docker", "br-", "virbr", "veth", "vmnet", "vboxnet",
	"tun", "tap", "wg", "utun", "vpn", "dummy", "bond", "team",
}

// defaultCIDR returns the subnet of the interface that carries the default
// route (i.e. the one actually routing traffic to the internet — the hotspot
// WiFi adapter, the tethering USB interface, etc.).
//
// Strategy:
//  1. Read the kernel routing table (/proc/net/route on Linux) to find which
//     interface has the 0.0.0.0/0 (default) route.  This is the definitive
//     answer and correctly handles the case where both Ethernet and WiFi are
//     up simultaneously but only the hotspot is the active internet path.
//  2. On macOS / BSD, fall back to running `route get default` and parsing
//     the "interface:" line.
//  3. If both fail, iterate interfaces by index (original behaviour).
func defaultCIDR() string {
	// ── Linux: read routing table ──────────────────────────────────────────
	if iface := defaultRouteIfaceLinux(); iface != "" {
		if cidr := subnetForIface(iface); cidr != "" {
			return cidr
		}
	}
	// ── macOS / BSD fallback ───────────────────────────────────────────────
	if iface := defaultRouteIfaceMacOS(); iface != "" {
		if cidr := subnetForIface(iface); cidr != "" {
			return cidr
		}
	}
	// ── Interface-iteration fallback (original behaviour) ─────────────────
	ifaces, err := net.Interfaces()
	if err != nil {
		return "192.168.1.0/24"
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		name := strings.ToLower(iface.Name)
		virtual := false
		for _, prefix := range virtualIfacePrefixes {
			if strings.HasPrefix(name, prefix) {
				virtual = true
				break
			}
		}
		if virtual {
			continue
		}
		if cidr := subnetForIface(iface.Name); cidr != "" {
			return cidr
		}
	}
	return "192.168.1.0/24"
}

// defaultRouteIfaceLinux reads /proc/net/route and returns the name of the
// interface that owns the 0.0.0.0/0 (default) route.
// The Destination column is a little-endian hex uint32; "00000000" = 0.0.0.0.
func defaultRouteIfaceLinux() string {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Scan() // discard header line
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		// Column 1 = Destination; "00000000" is the default route.
		if fields[1] == "00000000" {
			return fields[0] // column 0 = Iface
		}
	}
	return ""
}

// defaultRouteIfaceMacOS runs `route get default` and extracts the interface
// name from the "interface:" line. Returns empty string on failure.
func defaultRouteIfaceMacOS() string {
	out, err := exec.Command("route", "get", "default").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "interface:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "interface:"))
		}
	}
	return ""
}

// subnetForIface returns the IPv4 CIDR network string for the named interface
// (e.g. "10.204.230.0/24"). Returns empty string if not found / not IPv4.
func subnetForIface(name string) string {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return ""
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipNet.IP.To4()
		if ip == nil || ip.IsLoopback() {
			continue
		}
		network := ip.Mask(ipNet.Mask)
		ones, _ := ipNet.Mask.Size()
		return fmt.Sprintf("%s/%d", network.String(), ones)
	}
	return ""
}

var rootCmd = &cobra.Command{
	Use:     "nova",
	Short:   "NOVA - Network Observation & Vulnerability Analyzer",
	Version: appVersion,
	Long: `NOVA is a terminal-based WiFi and LAN security assessment tool.

It provides:
  - WiFi network analysis (SSID, encryption, signal, channel)
  - LAN host discovery (ping sweep via nmap)
  - Port and service scanning (TCP connect or SYN)
  - Security scoring and risk tagging

IMPORTANT: Only scan networks you own or have explicit permission to assess.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		isRoot := ui.CheckPrivilege()

		cidr := flagCIDR
		if cidr == "" {
			cidr = defaultCIDR()
		}

		// Validate the CIDR before launching the TUI so the user gets a
		// clear error message immediately rather than inside an async scan.
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("invalid --subnet value %q: %w", cidr, err)
		}

		if err := ui.Run(isRoot, cidr); err != nil {
			return fmt.Errorf("TUI error: %w", err)
		}
		return nil
	},
}

// Execute runs the root cobra command. Called from main.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().StringVarP(
		&flagCIDR,
		"subnet", "s",
		"",
		"Target subnet for LAN host discovery (CIDR, e.g. 192.168.1.0/24). "+
			"Defaults to the auto-detected local /24 subnet.",
	)

	// Override the default version template to include commit and date.
	rootCmd.SetVersionTemplate(
		"NOVA {{.Version}} (commit: " + appCommit + ", built: " + appDate + ")\n",
	)
}
