// Package scanner provides LAN host discovery and port/service scanning for NOVA.
// It uses structured exec.Command calls (never shell expansion) and validates
// all inputs before passing them to external tools.
package scanner

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

// scanTimeout is the maximum time granted to a single nmap invocation.
const scanTimeout = 60 * time.Second

// deepScanTimeout allows more time for service probing, OS detection, and NSE
// scripts. Kept at 3 minutes — long enough for version probes against slow
// services, short enough to prevent indefinite blocking.
const deepScanTimeout = 3 * 60 * time.Second

// maxHosts is the maximum number of host results we will process to prevent
// memory exhaustion from maliciously crafted or unexpectedly large outputs.
const maxHosts = 512

// maxOpenPorts is the ceiling on ports per host.
const maxOpenPorts = 1024

// arpSettleDelay is how long we wait after sending ARP-warmup UDP packets for
// the kernel to receive and process ARP replies from live hosts on the LAN.
const arpSettleDelay = 1500 * time.Millisecond

// Host represents a single discovered LAN host.
type Host struct {
	IP        string
	Hostname  string
	MAC       string
	Vendor    string
	OpenPorts []Port
	OS        string // best-guess OS fingerprint (read-only, no exploitation)

	// Deep-scan enrichment fields.
	OSAccuracy  int    // 0–100 confidence from nmap OS detection
	DeviceType  string // e.g. "router", "phone", "general purpose"
	NetworkDist int    // network hop distance (TTL-derived)
}

// Port represents an open TCP/UDP port on a host.
type Port struct {
	Number   int
	Protocol string // "tcp" or "udp"
	Service  string
	State    string // "open", "filtered"

	// Deep-scan fields (populated by DeepScan only).
	Product string         // e.g. "OpenSSH", "Apache httpd"
	Version string         // e.g. "7.4", "2.4.41"
	Extra   string         // extra info from nmap -sV
	CPE     string         // Common Platform Enumeration string
	Scripts []ScriptResult // NSE script output
}

// ScriptResult holds the output of a single NSE script run against a port.
type ScriptResult struct {
	ID     string // e.g. "http-title", "ssl-cert"
	Output string // sanitised script output
}

// DeepScanResult holds the complete intelligence gathered by DeepScan.
type DeepScanResult struct {
	Host      Host
	RawOutput string // sanitised nmap output for advanced display
}

// ─── Input validation ─────────────────────────────────────────────────────────

// validIPv4 matches a bare IPv4 address.
var validIPv4 = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)

// ValidateCIDR validates a CIDR string; only IPv4 /8–/30 ranges are accepted.
func ValidateCIDR(cidr string) error {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}
	// Only IPv4.
	if ip.To4() == nil {
		return fmt.Errorf("only IPv4 CIDR ranges are supported")
	}
	ones, bits := network.Mask.Size()
	if bits != 32 {
		return fmt.Errorf("only IPv4 CIDR ranges are supported")
	}
	// Reject /0–/7 (too large — would scan millions of hosts).
	if ones < 8 {
		return fmt.Errorf("CIDR prefix /%d is too broad; minimum is /8", ones)
	}
	return nil
}

// ValidateIP returns an error if s is not a valid IPv4 address.
func ValidateIP(s string) error {
	s = strings.TrimSpace(s)
	if !validIPv4.MatchString(s) {
		return fmt.Errorf("invalid IPv4 address: %q", s)
	}
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() == nil {
		return fmt.Errorf("invalid IPv4 address: %q", s)
	}
	return nil
}

// ValidatePort returns an error if n is outside 1–65535.
func ValidatePort(n int) error {
	if n < 1 || n > 65535 {
		return fmt.Errorf("port %d out of range [1, 65535]", n)
	}
	return nil
}

// ─── Sanitisation helpers ─────────────────────────────────────────────────────

// sanitizeField strips ANSI escape sequences and control characters, then
// truncates the string to 256 runes.
func sanitizeField(s string) string {
	ansiEsc := regexp.MustCompile(`\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])`)
	s = ansiEsc.ReplaceAllString(s, "")

	var b strings.Builder
	for _, r := range s {
		if unicode.IsPrint(r) && r != '\x7f' {
			b.WriteRune(r)
		}
	}
	result := strings.TrimSpace(b.String())
	runes := []rune(result)
	if len(runes) > 256 {
		runes = runes[:256]
	}
	return string(runes)
}

// sanitizeIP validates and normalises an IP string parsed from tool output.
// Returns empty string if the value is not a valid IPv4 address.
func sanitizeIP(s string) string {
	s = strings.TrimSpace(s)
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() == nil {
		return ""
	}
	return ip.String()
}

// sanitizeMAC checks that a MAC address matches the standard hex colon format.
var validMAC = regexp.MustCompile(`^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$`)

func sanitizeMAC(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	if !validMAC.MatchString(s) {
		return ""
	}
	return s
}

// sanitizePort returns 0 if p is outside the valid port range.
func sanitizePort(p int) int {
	if p < 1 || p > 65535 {
		return 0
	}
	return p
}

// sanitizeProtocol returns "tcp" or "udp"; anything else becomes "tcp".
func sanitizeProtocol(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "udp":
		return "udp"
	default:
		return "tcp"
	}
}

// ─── Gateway detection ────────────────────────────────────────────────────────

// DetectDefaultGatewayIP returns the IPv4 address of the system's default
// gateway by reading /proc/net/route (Linux) or running `route get default`
// (macOS/BSD). Returns empty string if it cannot be determined.
//
// The value is sanitised through net.ParseIP so it is always a canonical
// dotted-decimal string and cannot contain shell-injection characters.
func DetectDefaultGatewayIP() string {
	// Linux: /proc/net/route
	// Columns: Iface Destination Gateway Flags RefCnt Use Metric Mask ...
	// All numeric fields are 8-char zero-padded little-endian hex uint32.
	if f, err := os.Open("/proc/net/route"); err == nil {
		defer func() { _ = f.Close() }()
		sc := bufio.NewScanner(f)
		sc.Scan() // skip header
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) < 3 {
				continue
			}
			// Default route: Destination == "00000000"
			if fields[1] != "00000000" {
				continue
			}
			gwHex := fields[2]
			if len(gwHex) != 8 {
				continue
			}
			// Parse 4 little-endian bytes.
			var b [4]byte
			for i := 0; i < 4; i++ {
				val, err := strconv.ParseUint(gwHex[i*2:i*2+2], 16, 8)
				if err != nil {
					b = [4]byte{}
					break
				}
				b[i] = byte(val)
			}
			// Kernel stores in little-endian order: b[0]=LSB → reverse for network order.
			ip := net.IPv4(b[3], b[2], b[1], b[0])
			if s := sanitizeIP(ip.String()); s != "" {
				return s
			}
		}
	}
	// macOS / BSD fallback: `route get default`
	out, err := exec.Command("route", "get", "default").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "gateway:") {
			s := sanitizeIP(strings.TrimSpace(strings.TrimPrefix(line, "gateway:")))
			if s != "" {
				return s
			}
		}
	}
	return ""
}

// ─── Host Discovery ───────────────────────────────────────────────────────────

// DiscoverHosts discovers live hosts on the given CIDR subnet.
//
//   - With root: nmap raw ICMP/ARP probes (-PE -PP) — fastest, most accurate.
//   - Without root: nmap TCP-connect ping (-PS) against common ports so hosts
//     are found even when ICMP is completely blocked by the network firewall.
//     Results are merged with the kernel ARP cache so hosts already known to
//     the OS (router, recent peers) always appear even if all probes fail.
func DiscoverHosts(ctx context.Context, cidr string, isRoot bool) ([]Host, error) {
	if err := ValidateCIDR(cidr); err != nil {
		return nil, err
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, scanTimeout)
		defer cancel()
	}
	if isRoot {
		return discoverWithNmap(ctx, cidr, true)
	}
	return discoverWithNmap(ctx, cidr, false)
}

// discoverWithNmap runs an nmap ping scan and merges the results with the
// kernel ARP cache.
//
//   - root=true:  -PE -PP (raw ICMP echo + timestamp probes; ARP automatic).
//   - root=false: -PS<ports> (TCP SYN/connect ping to common service ports).
//     nmap automatically falls back to TCP connect() when it cannot open raw
//     sockets, so this works without any special privilege.
//
// The ARP-cache merge ensures that hosts the kernel already knows about
// (router, DHCP server, recently-seen peers) are always included, even when
// every probe type is blocked by the network.
func discoverWithNmap(ctx context.Context, cidr string, isRoot bool) ([]Host, error) {
	var args []string
	if isRoot {
		// Raw ICMP probes — ARP is added automatically by nmap for LAN targets.
		args = []string{
			"-sn", "-n", "-oX", "-",
			"-PE", "-PP",
			"--host-timeout", "5s",
			"-T4",
			cidr,
		}
	} else {
		// Warm up the kernel ARP cache first. We send one UDP datagram to
		// every IP in the subnet; the kernel must ARP-resolve each address
		// before it can transmit, so every live host on the LAN will reply
		// and its entry will appear in /proc/net/arp — regardless of whether
		// it has any open TCP port or passes ICMP. No root privilege needed.
		arpWarmup(ctx, cidr)
		// TCP SYN/connect ping on a wide set of common service ports.
		// nmap uses TCP connect() when raw sockets are unavailable, so this
		// works fully without root.  -Pn is NOT set so nmap still skips hosts
		// that don't respond to any probe (keeps the scan fast).
		args = []string{
			"-sn", "-n", "-oX", "-",
			"-PS22,23,80,135,139,443,445,3389,8080,8443",
			"-PA80,443",
			"--host-timeout", "5s",
			"-T4",
			cidr,
		}
	}

	cmd := exec.CommandContext(ctx, "nmap", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("host discovery timed out")
		}
		// Partial output? Try to parse what nmap wrote before crashing.
		if stdout.Len() > 0 {
			if hosts := parseNmapXMLHosts(stdout.String()); len(hosts) > 0 {
				return mergeARPCache(hosts, cidr), nil
			}
		}
		// Nmap unavailable or hard error — fall back to ARP-only.
		return discoverFromARP(cidr), nil
	}

	nmapHosts := parseNmapXMLHosts(stdout.String())
	return mergeARPCache(nmapHosts, cidr), nil
}

// mergeARPCache enriches nmapHosts with MAC addresses from the ARP cache and
// adds any ARP-known hosts that nmap missed (e.g. host blocked all probes but
// the kernel still has a valid ARP entry from prior communication).
func mergeARPCache(nmapHosts []Host, cidr string) []Host {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nmapHosts
	}
	arpTable := readARPCache()

	// Index nmap results by IP for O(1) lookup.
	byIP := make(map[string]*Host, len(nmapHosts))
	result := make([]Host, len(nmapHosts))
	copy(result, nmapHosts)
	for i := range result {
		// Fill in missing MAC from ARP.
		if result[i].MAC == "" {
			if mac, ok := arpTable[result[i].IP]; ok {
				result[i].MAC = mac
			}
		}
		byIP[result[i].IP] = &result[i]
	}

	// Add ARP-known hosts nmap didn't find.
	for ip, mac := range arpTable {
		if byIP[ip] != nil {
			continue
		}
		parsed := net.ParseIP(ip)
		if parsed == nil || !network.Contains(parsed) {
			continue
		}
		if len(result) >= maxHosts {
			break
		}
		h := Host{IP: ip, MAC: mac}
		if names, rErr := net.LookupAddr(ip); rErr == nil && len(names) > 0 {
			h.Hostname = sanitizeField(strings.TrimSuffix(names[0], "."))
		}
		result = append(result, h)
	}
	return result
}

// discoverFromARP returns hosts visible in the kernel ARP cache for cidr.
// Used as a last-resort fallback when nmap is unavailable.
func discoverFromARP(cidr string) []Host {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil
	}
	arpTable := readARPCache()
	var hosts []Host
	for ip, mac := range arpTable {
		if len(hosts) >= maxHosts {
			break
		}
		parsed := net.ParseIP(ip)
		if parsed == nil || !network.Contains(parsed) {
			continue
		}
		h := Host{IP: ip, MAC: mac}
		if names, rErr := net.LookupAddr(ip); rErr == nil && len(names) > 0 {
			h.Hostname = sanitizeField(strings.TrimSuffix(names[0], "."))
		}
		hosts = append(hosts, h)
	}
	return hosts
}

// arpWarmup sends one UDP datagram to every host address in cidr, which
// causes the Linux kernel to issue an ARP broadcast for each destination.
// Every live device on the LAN must reply to ARP (it cannot be blocked by
// iptables/nftables, which operate above L2), so after waiting arpSettleDelay
// the kernel neighbour table will contain an entry for every reachable host.
// This needs no root privilege and is immune to ICMP/TCP firewalls.
func arpWarmup(ctx context.Context, cidr string) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return
	}

	// Enumerate all usable host addresses (skip network + broadcast), capped.
	cur := make(net.IP, len(network.IP))
	copy(cur, network.IP)
	var ips []string
	for network.Contains(cur) {
		if len(ips) >= maxHosts+2 {
			break
		}
		ips = append(ips, cur.String())
		for j := len(cur) - 1; j >= 0; j-- {
			cur[j]++
			if cur[j] != 0 {
				break
			}
		}
	}
	if len(ips) >= 2 {
		ips = ips[1 : len(ips)-1]
	}

	const fanout = 128
	sem := make(chan struct{}, fanout)
	var wg sync.WaitGroup
	for _, ip := range ips {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(ipStr string) {
			defer wg.Done()
			defer func() { <-sem }()
			addr := &net.UDPAddr{IP: net.ParseIP(ipStr), Port: 9}
			conn, dialErr := net.DialUDP("udp", nil, addr)
			if dialErr != nil {
				return
			}
			_ = conn.SetDeadline(time.Now().Add(100 * time.Millisecond))
			_, _ = conn.Write([]byte{0})
			_ = conn.Close()
		}(ip)
	}
	wg.Wait()

	// Give the kernel time to process ARP replies before we read the cache.
	select {
	case <-ctx.Done():
	case <-time.After(arpSettleDelay):
	}
}

// ─── ARP helpers ──────────────────────────────────────────────────────────────

// readARPCache returns a map of IPv4 address → sanitised MAC address for
// all complete ARP entries (i.e. confirmed hosts with a non-zero MAC).
// It reads /proc/net/arp directly on Linux (no subprocess, no privileges)
// and falls back to running `arp -an` on macOS / BSD.
func readARPCache() map[string]string {
	table := make(map[string]string)

	// Linux: /proc/net/arp columns: IP, HW type, Flags, HW address, Mask, Device
	if f, fErr := os.Open("/proc/net/arp"); fErr == nil {
		defer func() { _ = f.Close() }()
		sc := bufio.NewScanner(f)
		sc.Scan() // discard header line
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) < 4 {
				continue
			}
			ip := sanitizeIP(fields[0])
			mac := sanitizeMAC(strings.ToUpper(fields[3]))
			if ip != "" && mac != "" && mac != "00:00:00:00:00:00" {
				table[ip] = mac
			}
		}
		return table
	}

	// macOS / BSD fallback: arp -an
	// Example line: ? (10.0.0.1) at a4:b1:e9:xx:xx:xx on en0 ifscope ...
	out, aErr := exec.Command("arp", "-an").Output()
	if aErr != nil {
		return table
	}
	arpRe := regexp.MustCompile(`\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]{17})`)
	for _, line := range strings.Split(string(out), "\n") {
		m := arpRe.FindStringSubmatch(line)
		if len(m) == 3 {
			ip := sanitizeIP(m[1])
			mac := sanitizeMAC(strings.ToUpper(m[2]))
			if ip != "" && mac != "" {
				table[ip] = mac
			}
		}
	}
	return table
}

// ─── Port Scanning ───────────────────────────────────────────────────────────

// PortScan performs a fast TCP SYN scan (-sS requires root) or TCP connect
// scan (-sT, no root required) on the given host for the supplied port range.
// isRoot should be set by the caller after checking os.Getuid().
func PortScan(ctx context.Context, ip string, ports string, isRoot bool) ([]Port, error) {
	if err := ValidateIP(ip); err != nil {
		return nil, err
	}
	if err := validatePortRange(ports); err != nil {
		return nil, err
	}

	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, scanTimeout)
		defer cancel()
	}

	scanType := "-sT" // TCP connect (no root needed)
	if isRoot {
		scanType = "-sS" // SYN scan (faster, less noisy)
	}

	// -sV: service version detection (read-only).
	// --open: only show open ports.
	// -T3: normal timing template (not aggressive).
	// -oX -: machine-readable XML to stdout.
	args := []string{
		scanType, "-sV",
		"--open", "-T3",
		"-p", ports,
		"-oX", "-",
		ip,
	}

	cmd := exec.CommandContext(ctx, "nmap", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("port scan timed out")
		}
		if stderr.Len() == 0 {
			return nil, nil
		}
		return nil, fmt.Errorf("nmap port scan failed: %w", err)
	}

	return parseNmapXMLPorts(stdout.String()), nil
}

// DeepScan performs a thorough, Host intelligence scan.
//
// It combines:
//   - Full TCP port sweep (1–65535)
//   - Service & version detection (-sV --version-intensity 7)
//   - OS fingerprinting (-O --osscan-guess)
//   - Default NSE safe scripts (-sC) for service intelligence:
//     http-title, ssh-hostkey, ssl-cert, smb-os-discovery, dns-service-discovery
//     banner, http-server-header, snmp-info, upnp-info, and more.
//   - UDP scan on high-value ports (161/SNMP, 1900/UPnP, 5353/mDNS, 67/DHCP)
//     to detect router/mobile-hotspot services invisible to TCP.
//
// isRoot must be set when os.Getuid() == 0. Root enables SYN scanning (-sS)
// and raw-socket OS detection; without root, TCP connect (-sT) is used and OS
// detection is downgraded to TTL-based guessing only.
//
// Safe-by-design: no exploit scripts, no brute-force, --script-args is not
// exposed to user input, and all output is sanitised before returning.
func DeepScan(ctx context.Context, ip string, isRoot bool) (*DeepScanResult, error) {
	if err := ValidateIP(ip); err != nil {
		return nil, err
	}

	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, deepScanTimeout)
		defer cancel()
	}

	// ── TCP deep scan ──────────────────────────────────────────────────────
	// Scan all 65535 TCP ports so we catch non-standard service ports that
	// would be invisible in the default 1-1024 range (e.g. mobile-hotspot
	// admin panels on 7547, 8888; IoT devices on 9090, 49152+).
	scanType := "-sT" // TCP connect — no root required
	if isRoot {
		scanType = "-sS" // SYN scan — faster, stealthier
	}

	// NSE safe-scripts category only. Explicitly excluded categories:
	// exploit, brute, dos, intrusive, malware — in line with NOVA's
	// defensive philosophy. The "safe" and "discovery" categories are
	// read-only and produce no side-effects on the target.
	// Individual scripts augment the basic discovery with service-specific
	// intelligence useful for router/hotspot profiling:
	//   http-title        – web admin panel title
	//   http-server-header – software version in HTTP Server: header
	//   ssl-cert          – TLS certificate info (CN, expiry)
	//   ssh-hostkey       – SSH host key fingerprint
	//   smb-os-discovery  – Windows/Samba version via SMB
	//   dns-service-discovery – mDNS/DNS-SD service list (Apple Bonjour, etc.)
	//   banner            – raw TCP banner grab
	//   snmp-info         – SNMP sysDescr (read community string "public")
	//   upnp-info         – UPnP root device description
	//   nbstat            – NetBIOS name/workgroup
	scriptList := strings.Join([]string{
		"http-title",
		"http-server-header",
		"ssl-cert",
		"ssh-hostkey",
		"smb-os-discovery",
		"dns-service-discovery",
		"banner",
		"snmp-info",
		"upnp-info",
		"nbstat",
	}, ",")

	// -Pn: treat target as up even when ICMP probes are blocked.
	// This is ESSENTIAL for mobile hotspots: Android iptables drops ICMP
	// echo-request on the tethering interface by default, so without -Pn
	// nmap marks the host "down" and never scans its ports. We already know
	// the host is up (the user selected it from the discovery list), so
	// skipping host-discovery here is always correct.
	tcpArgs := []string{
		scanType,
		"-Pn",
		"-sV", "--version-intensity", "7",
		"--osscan-guess",
		"--script", scriptList,
		"--open",
		"-p", "1-65535",
		"-T4",
		"--host-timeout", "120s",
		"-oX", "-",
		ip,
	}
	// -O (raw OS detection) requires root and at least one open + one closed
	// port.  Add it only when we have the necessary privileges.
	if isRoot {
		// Insert -O right after the scan type flag.
		updated := make([]string, 0, len(tcpArgs)+1)
		updated = append(updated, tcpArgs[0]) // scanType
		updated = append(updated, "-O")
		updated = append(updated, tcpArgs[1:]...)
		tcpArgs = updated
	}

	cmd := exec.CommandContext(ctx, "nmap", tcpArgs...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if runErr := cmd.Run(); runErr != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("deep scan timed out after %v", deepScanTimeout)
		}
		if stdout.Len() == 0 {
			return nil, fmt.Errorf("nmap deep scan failed: %w", runErr)
		}
		// Partial output — parse what we have.
	}

	tcpXML := stdout.String()

	// ── UDP high-value port scan ───────────────────────────────────────────
	// UDP exposes services that are exclusively UDP-based and are critical
	// for router/hotspot intelligence:
	//   67  DHCP server  – confirms this is a gateway/hotspot
	//   161 SNMP         – device description, firmware, uptime
	//   1900 UPnP/SSDP  – device type, friendly name, model
	//   5353 mDNS        – hostname, service list via DNS-SD
	var udpXML string
	if isRoot {
		udpCtx, udpCancel := context.WithTimeout(ctx, 40*time.Second)
		defer udpCancel()
		udpArgs := []string{
			"-sU",
			"-sV", "--version-intensity", "5",
			"--script", "snmp-info,upnp-info,dns-service-discovery",
			"--open",
			"-p", "67,161,1900,5353",
			"-T4",
			"--host-timeout", "30s",
			"-oX", "-",
			ip,
		}
		udpCmd := exec.CommandContext(udpCtx, "nmap", udpArgs...)
		var udpOut bytes.Buffer
		udpCmd.Stdout = &udpOut
		_ = udpCmd.Run() // errors are non-fatal; UDP often returns partial data
		udpXML = udpOut.String()
	}

	// ── Parse and merge ────────────────────────────────────────────────────
	hosts := parseNmapXMLHostsDeep(tcpXML)
	if len(hosts) == 0 {
		// Host may be blocking all TCP; add a stub so UDP results attach.
		hosts = []Host{{IP: ip}}
	}
	h := hosts[0]

	if udpXML != "" {
		udpHosts := parseNmapXMLHostsDeep(udpXML)
		if len(udpHosts) > 0 {
			for _, p := range udpHosts[0].OpenPorts {
				if len(h.OpenPorts) < maxOpenPorts {
					h.OpenPorts = append(h.OpenPorts, p)
				}
			}
			// Prefer UDP-derived device type for routers/APs.
			if h.DeviceType == "" && udpHosts[0].DeviceType != "" {
				h.DeviceType = udpHosts[0].DeviceType
			}
		}
	}

	// ── Hotspot / gateway extra TCP probe ─────────────────────────────────
	// Mobile hotspots (Android, iPhone, MiFi) and routers often expose admin
	// panels on non-standard ports that are NOT in the 1-1024 standard range
	// AND are filtered from the main full scan by iptables rules that only
	// allow connections from the local subnet's admin interface.
	// We do a fast targeted connect-scan on the most common admin/management
	// ports.  -Pn is essential (ICMP still blocked here).  Timeout is short
	// (15 s) so this doesn't materially extend scan time.
	hotspotAdminPorts := "80,443,7547,8080,8081,8443,8888,9090,4040,5985,49152,49153"
	hotspotCtx, hotspotCancel := context.WithTimeout(ctx, 20*time.Second)
	defer hotspotCancel()
	hotspotArgs := []string{
		"-sT", // TCP connect — works without root
		"-Pn",
		"-sV", "--version-intensity", "3",
		"--script", "http-title,http-server-header,upnp-info,banner",
		"--open",
		"-p", hotspotAdminPorts,
		"-T4",
		"--host-timeout", "15s",
		"-oX", "-",
		ip,
	}
	hotspotCmd := exec.CommandContext(hotspotCtx, "nmap", hotspotArgs...)
	var hotspotOut bytes.Buffer
	hotspotCmd.Stdout = &hotspotOut
	_ = hotspotCmd.Run() // non-fatal; enriches existing results
	if hotspotOut.Len() > 0 {
		hotspotHosts := parseNmapXMLHostsDeep(hotspotOut.String())
		if len(hotspotHosts) > 0 {
			for _, p := range hotspotHosts[0].OpenPorts {
				// Only add ports not already found by the main scan.
				alreadyFound := false
				for _, existing := range h.OpenPorts {
					if existing.Number == p.Number && existing.Protocol == p.Protocol {
						alreadyFound = true
						break
					}
				}
				if !alreadyFound && len(h.OpenPorts) < maxOpenPorts {
					h.OpenPorts = append(h.OpenPorts, p)
				}
			}
		}
	}

	// ── Auto-detect if this is the default gateway ─────────────────────────
	if gwIP := DetectDefaultGatewayIP(); gwIP == h.IP && h.DeviceType == "" {
		// This host is the default gateway (router / hotspot).
		// We'll mark it so the risk analyser can apply gateway-specific rules.
		h.DeviceType = "gateway"
	}

	// Enrich from ARP cache for MAC/vendor if not already populated.
	arpTable := readARPCache()
	if h.MAC == "" {
		if mac, ok := arpTable[h.IP]; ok {
			h.MAC = mac
		}
	}

	// Build a compact human-readable summary for the raw output field.
	rawSummary := buildRawSummary(h)

	return &DeepScanResult{
		Host:      h,
		RawOutput: rawSummary,
	}, nil
}

// buildRawSummary creates a concise, sanitised plain-text overview of the
// deep scan result suitable for display in the TUI details pane.
func buildRawSummary(h Host) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Host: %s\n", h.IP)
	if h.Hostname != "" {
		fmt.Fprintf(&sb, "Hostname: %s\n", h.Hostname)
	}
	if h.MAC != "" {
		fmt.Fprintf(&sb, "MAC: %s", h.MAC)
		if h.Vendor != "" {
			sb.WriteString(" (" + h.Vendor + ")")
		}
		sb.WriteString("\n")
	}
	if h.OS != "" {
		acc := ""
		if h.OSAccuracy > 0 {
			acc = fmt.Sprintf(" [%d%%]", h.OSAccuracy)
		}
		fmt.Fprintf(&sb, "OS: %s%s\n", h.OS, acc)
	}
	if h.DeviceType != "" {
		fmt.Fprintf(&sb, "Device: %s\n", h.DeviceType)
	}
	fmt.Fprintf(&sb, "Open Ports: %d\n", len(h.OpenPorts))
	for _, p := range h.OpenPorts {
		line := fmt.Sprintf("  %d/%s\t%s", p.Number, p.Protocol, p.Service)
		if p.Product != "" {
			line += " " + p.Product
		}
		if p.Version != "" {
			line += " " + p.Version
		}
		if p.Extra != "" {
			line += " (" + p.Extra + ")"
		}
		sb.WriteString(line + "\n")
		for _, s := range p.Scripts {
			fmt.Fprintf(&sb, "    [%s]: %s\n", s.ID, s.Output)
		}
	}
	return sb.String()
}

// validatePortRange accepts expressions like "22,80,443" or "1-1024" or "22".
// It rejects anything that could be used for shell injection.
var validPortRange = regexp.MustCompile(`^[0-9,\-]+$`)

func validatePortRange(ports string) error {
	ports = strings.TrimSpace(ports)
	if ports == "" {
		return fmt.Errorf("port range must not be empty")
	}
	if !validPortRange.MatchString(ports) {
		return fmt.Errorf("invalid port range %q: only digits, commas, and hyphens are allowed", ports)
	}
	// Validate individual numbers.
	for _, part := range strings.Split(ports, ",") {
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			lo, err1 := strconv.Atoi(bounds[0])
			hi, err2 := strconv.Atoi(bounds[1])
			if err1 != nil || err2 != nil {
				return fmt.Errorf("invalid port range part: %q", part)
			}
			if err := ValidatePort(lo); err != nil {
				return err
			}
			if err := ValidatePort(hi); err != nil {
				return err
			}
			if lo > hi {
				return fmt.Errorf("port range %d-%d is inverted", lo, hi)
			}
		} else {
			n, err := strconv.Atoi(part)
			if err != nil {
				return fmt.Errorf("invalid port number: %q", part)
			}
			if err := ValidatePort(n); err != nil {
				return err
			}
		}
	}
	return nil
}

// ─── nmap XML parsing ─────────────────────────────────────────────────────────
// We parse nmap XML manually with bufio to avoid importing an XML library
// (keeping dependencies minimal as required) and to sanitize every field.

// parseNmapXMLHosts extracts host entries from nmap XML output.
func parseNmapXMLHosts(xmlData string) []Host {
	var hosts []Host
	scanner := bufio.NewScanner(strings.NewReader(xmlData))

	var current *Host
	count := 0

	for scanner.Scan() {
		if count >= maxHosts {
			break
		}
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "<host ") || line == "<host>" {
			current = &Host{}
			count++
		} else if line == "</host>" {
			if current != nil && current.IP != "" {
				hosts = append(hosts, *current)
			}
			current = nil
		} else if current == nil {
			continue
		} else if strings.Contains(line, `<address addr=`) {
			addr, addrType := extractAttr(line, "addr"), extractAttr(line, "addrtype")
			switch addrType {
			case "ipv4":
				if ip := sanitizeIP(addr); ip != "" {
					current.IP = ip
				}
			case "mac":
				if mac := sanitizeMAC(addr); mac != "" {
					current.MAC = mac
					current.Vendor = sanitizeField(extractAttr(line, "vendor"))
				}
			}
		} else if strings.Contains(line, `<hostname `) {
			name := sanitizeField(extractAttr(line, "name"))
			if name != "" && current.Hostname == "" {
				current.Hostname = name
			}
		} else if strings.Contains(line, `<osmatch `) {
			name := sanitizeField(extractAttr(line, "name"))
			if name != "" && current.OS == "" {
				current.OS = name
			}
		}
	}
	return hosts
}

// parseNmapXMLPorts extracts open port entries from nmap XML output.
func parseNmapXMLPorts(xmlData string) []Port {
	var ports []Port
	scanner := bufio.NewScanner(strings.NewReader(xmlData))

	portCount := 0
	for scanner.Scan() {
		if portCount >= maxOpenPorts {
			break
		}
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "<port ") {
			continue
		}
		portNum, err := strconv.Atoi(extractAttr(line, "portid"))
		if err != nil {
			continue
		}
		portNum = sanitizePort(portNum)
		if portNum == 0 {
			continue
		}
		proto := sanitizeProtocol(extractAttr(line, "protocol"))

		// State and service are on child lines; peek ahead by reading the
		// next scanner lines until </port>.
		state := ""
		service := ""
		for scanner.Scan() {
			inner := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(inner, "<state ") {
				s := extractAttr(inner, "state")
				if s == "open" || s == "filtered" {
					state = s
				}
			} else if strings.HasPrefix(inner, "<service ") {
				service = sanitizeField(extractAttr(inner, "name"))
			} else if inner == "</port>" {
				break
			}
		}

		if state == "" {
			state = "open"
		}
		ports = append(ports, Port{
			Number:   portNum,
			Protocol: proto,
			Service:  service,
			State:    state,
		})
		portCount++
	}
	return ports
}

// parseNmapXMLHostsDeep is like parseNmapXMLHosts but also captures
// service version, product, extra, CPE, NSE script output, OS accuracy,
// and device type — all fields written by -sV -O --script scans.
func parseNmapXMLHostsDeep(xmlData string) []Host {
	var hosts []Host
	sc := bufio.NewScanner(strings.NewReader(xmlData))
	// nmap XML can have very long <script output=...> lines; increase buffer.
	sc.Buffer(make([]byte, 1<<20), 1<<20)

	var current *Host
	var currentPort *Port
	count := 0

	for sc.Scan() {
		if count >= maxHosts {
			break
		}
		line := strings.TrimSpace(sc.Text())

		switch {
		case strings.HasPrefix(line, "<host ") || line == "<host>":
			current = &Host{}
			currentPort = nil
			count++

		case line == "</host>":
			if currentPort != nil && current != nil {
				if len(current.OpenPorts) < maxOpenPorts {
					current.OpenPorts = append(current.OpenPorts, *currentPort)
				}
				currentPort = nil
			}
			if current != nil && current.IP != "" {
				hosts = append(hosts, *current)
			}
			current = nil

		case current == nil:
			continue

		// ── address ──
		case strings.Contains(line, "<address addr="):
			addr, addrType := extractAttr(line, "addr"), extractAttr(line, "addrtype")
			switch addrType {
			case "ipv4":
				if ip := sanitizeIP(addr); ip != "" {
					current.IP = ip
				}
			case "mac":
				if mac := sanitizeMAC(addr); mac != "" {
					current.MAC = mac
					current.Vendor = sanitizeField(extractAttr(line, "vendor"))
				}
			}

		// ── hostname ──
		case strings.Contains(line, "<hostname "):
			name := sanitizeField(extractAttr(line, "name"))
			if name != "" && current.Hostname == "" {
				current.Hostname = name
			}

		// ── OS match ──
		case strings.Contains(line, "<osmatch "):
			name := sanitizeField(extractAttr(line, "name"))
			accStr := extractAttr(line, "accuracy")
			acc, _ := strconv.Atoi(accStr)
			if name != "" && current.OS == "" {
				current.OS = name
				current.OSAccuracy = acc
			}

		// ── OS class (device type) ──
		case strings.Contains(line, "<osclass "):
			dt := sanitizeField(extractAttr(line, "type"))
			if dt != "" && current.DeviceType == "" {
				current.DeviceType = strings.ToLower(dt)
			}

		// ── port open ──
		case strings.HasPrefix(line, "<port "):
			// Commit previous port if still pending.
			if currentPort != nil {
				if len(current.OpenPorts) < maxOpenPorts {
					current.OpenPorts = append(current.OpenPorts, *currentPort)
				}
			}
			portNum, err := strconv.Atoi(extractAttr(line, "portid"))
			if err != nil {
				currentPort = nil
				continue
			}
			portNum = sanitizePort(portNum)
			if portNum == 0 {
				currentPort = nil
				continue
			}
			currentPort = &Port{
				Number:   portNum,
				Protocol: sanitizeProtocol(extractAttr(line, "protocol")),
			}

		// ── port state ──
		case strings.HasPrefix(line, "<state ") && currentPort != nil:
			s := extractAttr(line, "state")
			if s == "open" || s == "filtered" {
				currentPort.State = s
			}

		// ── service version ──
		case strings.HasPrefix(line, "<service ") && currentPort != nil:
			currentPort.Service = sanitizeField(extractAttr(line, "name"))
			currentPort.Product = sanitizeField(extractAttr(line, "product"))
			currentPort.Version = sanitizeField(extractAttr(line, "version"))
			currentPort.Extra = sanitizeField(extractAttr(line, "extrainfo"))

		// ── CPE ──
		case strings.HasPrefix(line, "<cpe>") && currentPort != nil:
			// <cpe>cpe:/a:openbsd:openssh:7.4</cpe>
			start := strings.Index(line, "<cpe>")
			end := strings.Index(line, "</cpe>")
			if start >= 0 && end > start+5 {
				currentPort.CPE = sanitizeField(line[start+5 : end])
			}

		// ── NSE script output ──
		case strings.HasPrefix(line, "<script ") && currentPort != nil:
			scriptID := sanitizeField(extractAttr(line, "id"))
			scriptOut := sanitizeField(extractAttr(line, "output"))
			if scriptID != "" && len(currentPort.Scripts) < 16 {
				currentPort.Scripts = append(currentPort.Scripts, ScriptResult{
					ID:     scriptID,
					Output: scriptOut,
				})
			}

		// ── end port ──
		case line == "</port>" && currentPort != nil:
			if currentPort.State == "" {
				currentPort.State = "open"
			}
			if len(current.OpenPorts) < maxOpenPorts {
				current.OpenPorts = append(current.OpenPorts, *currentPort)
			}
			currentPort = nil
		}
	}
	return hosts
}

// extractAttr extracts the value of a named XML attribute from a line.
// It handles both single and double quoted values.
// Returns empty string if the attribute is not present.
func extractAttr(line, attr string) string {
	// Try double-quoted: attr="value"
	dq := attr + `="`
	if idx := strings.Index(line, dq); idx != -1 {
		rest := line[idx+len(dq):]
		if end := strings.Index(rest, `"`); end != -1 {
			return rest[:end]
		}
	}
	// Try single-quoted: attr='value'
	sq := attr + `='`
	if idx := strings.Index(line, sq); idx != -1 {
		rest := line[idx+len(sq):]
		if end := strings.Index(rest, `'`); end != -1 {
			return rest[:end]
		}
	}
	return ""
}
