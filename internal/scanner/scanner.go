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
	"sync"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// scanTimeout is the maximum time granted to a single nmap invocation.
const scanTimeout = 60 * time.Second

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
}

// Port represents an open TCP/UDP port on a host.
type Port struct {
	Number   int
	Protocol string // "tcp" or "udp"
	Service  string
	State    string // "open", "filtered"
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
