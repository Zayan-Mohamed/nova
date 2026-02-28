// Package cmd is the entry-point for all NOVA CLI commands.
// It wires together the cobra command tree and delegates to the ui package
// for the interactive TUI. No business logic lives here.
package cmd

import (
	"fmt"
	"net"
	"os"
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
func SetVersionInfo(version, commit, date string) {
	appVersion = version
	appCommit = commit
	appDate = date
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

// defaultCIDR detects the subnet of the active physical network interface
// (WiFi or Ethernet). It skips loopback and well-known virtual/container
// interfaces, then uses the interface's real network mask — not a forced /24.
// Falls back to 192.168.1.0/24 if nothing suitable is found.
func defaultCIDR() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "192.168.1.0/24"
	}
	for _, iface := range ifaces {
		// Must be up and not loopback.
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		// Skip virtual / container / VPN interfaces.
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
		addrs, err := iface.Addrs()
		if err != nil {
			continue
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
			// Use the actual subnet mask the interface was assigned,
			// not a forced /24 — a home router might give /24 but a
			// corporate network or VPN often uses /22, /23, etc.
			network := ip.Mask(ipNet.Mask)
			ones, _ := ipNet.Mask.Size()
			return fmt.Sprintf("%s/%d", network.String(), ones)
		}
	}
	return "192.168.1.0/24"
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
