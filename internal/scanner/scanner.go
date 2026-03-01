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

// maxHosts is the maximum number of host results we will process to prevent
// memory exhaustion from maliciously crafted or unexpectedly large outputs.
const maxHosts = 512

// maxOpenPorts is the ceiling on ports per host.
const maxOpenPorts = 1024

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
//   - With root: delegates to nmap with raw ICMP/ARP probes — returns MAC,
//     vendor, OS fingerprint and is the most comprehensive method.
//   - Without root: uses a parallel ping sweep via the system ping binary
//     (which is setuid-root on Linux/macOS so it can send ICMP echo without
//     the calling process being privileged). Responding hosts are enriched
//     from the kernel ARP cache (MAC address) and reverse DNS (hostname).
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
		return discoverWithNmap(ctx, cidr)
	}
	return discoverWithPing(ctx, cidr)
}

// discoverWithNmap runs nmap -sn with raw ICMP probes. Requires root.
func discoverWithNmap(ctx context.Context, cidr string) ([]Host, error) {
	// -PE: ICMP echo  -PP: ICMP timestamp  (ARP is automatic for LAN targets)
	args := []string{"-sn", "-n", "-oX", "-", "-PE", "-PP", cidr}
	cmd := exec.CommandContext(ctx, "nmap", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("host discovery timed out")
		}
		// Partial XML? Try to parse whatever nmap wrote before failing.
		if stdout.Len() > 0 {
			if hosts := parseNmapXMLHosts(stdout.String()); len(hosts) > 0 {
				return hosts, nil
			}
		}
		if stderr.Len() == 0 {
			return nil, nil
		}
		return nil, fmt.Errorf("nmap host discovery failed: %w", err)
	}
	return parseNmapXMLHosts(stdout.String()), nil
}

// discoverWithPing discovers hosts using a three-layer strategy so it works
// even on networks where ICMP is blocked (corporate, university, etc.):
//
//  1. ARP cache — instant, requires no ICMP, works on any LAN segment.
//     Populated by the kernel whenever the machine communicates with a host.
//  2. ICMP ping — standard sweep for hosts not yet in ARP.
//     Requires the system ping binary to have setuid/CAP_NET_RAW.
//  3. TCP connect probe — for hosts that block ICMP but have open/closed TCP
//     ports on common services (80, 22, 443, 53). "Connection refused" means
//     the host is alive even if no port is open.
func discoverWithPing(ctx context.Context, cidr string) ([]Host, error) {
	ips, err := enumerateIPs(cidr)
	if err != nil {
		return nil, err
	}
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	// ── Layer 1: ARP cache (zero-latency, ICMP-independent) ──────────────────
	// arpTable: confirmed entries (non-zero MAC) → used for host identity + MAC.
	// arpKnown: all entries including incomplete ones → seed for TCP probe.
	arpTable := readARPCache()
	arpKnown := readARPCacheKnownIPs(network)
	upIPs := make(map[string]bool)
	for ip := range arpTable {
		if parsed := net.ParseIP(ip); parsed != nil && network.Contains(parsed) {
			upIPs[ip] = true
		}
	}

	// ── Layers 2 & 3: parallel ping + TCP probe for remaining IPs ────────────
	const concurrency = 50
	type pResult struct {
		ip string
		up bool
	}
	results := make(chan pResult, len(ips))
	sem := make(chan struct{}, concurrency)

	var wg sync.WaitGroup
outerLoop:
	for _, ip := range ips {
		if upIPs[ip] {
			continue // already confirmed via ARP
		}
		select {
		case <-ctx.Done():
			break outerLoop
		case sem <- struct{}{}: // acquire concurrency slot
		}
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			// Hosts in incomplete ARP entries are known to the network; skip the
			// slow ICMP sweep and go straight to the faster TCP probe.
			var up bool
			if arpKnown[ip] {
				up = tcpProbe(ctx, ip)
			} else {
				up = icmpProbe(ctx, ip) || tcpProbe(ctx, ip)
			}
			results <- pResult{ip: ip, up: up}
		}(ip)
	}
	go func() { wg.Wait(); close(results) }()

	for r := range results {
		if r.up {
			upIPs[r.ip] = true
		}
	}

	if len(upIPs) == 0 {
		return nil, nil
	}

	// Enrich with hostname (reverse DNS). MAC already in arpTable.
	hosts := make([]Host, 0, len(upIPs))
	for ip := range upIPs {
		h := Host{IP: ip}
		if mac, ok := arpTable[ip]; ok {
			h.MAC = mac
		}
		if names, rErr := net.LookupAddr(ip); rErr == nil && len(names) > 0 {
			h.Hostname = sanitizeField(strings.TrimSuffix(names[0], "."))
		}
		hosts = append(hosts, h)
	}
	return hosts, nil
}

// icmpProbe sends a single ICMP echo request and returns true if the host
// responds within 1 second. Requires setuid/CAP_NET_RAW on the ping binary.
func icmpProbe(ctx context.Context, ip string) bool {
	pCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	// -W 1: wait at most 1 s for a reply (avoids default 10-s wait on some distros).
	return exec.CommandContext(pCtx, "ping", "-c", "1", "-W", "1", ip).Run() == nil
}

// tcpProbe tries TCP connects on common ports. A refused connection proves
// the remote TCP stack is alive even when ICMP is blocked by a firewall.
func tcpProbe(ctx context.Context, ip string) bool {
	for _, port := range []int{80, 22, 443, 53} {
		addr := fmt.Sprintf("%s:%d", ip, port)
		pCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		conn, dialErr := (&net.Dialer{}).DialContext(pCtx, "tcp", addr)
		cancel()
		if conn != nil {
			_ = conn.Close()
			return true // port open = host alive
		}
		// "connection refused" = host alive, port merely closed.
		if dialErr != nil && strings.Contains(dialErr.Error(), "connection refused") {
			return true
		}
	}
	return false
}

// enumerateIPs returns all usable host IPs within cidr, excluding the network
// and broadcast addresses. The result is capped at maxHosts entries.
func enumerateIPs(cidr string) ([]string, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	// Clone so we can safely increment.
	cur := make(net.IP, len(network.IP))
	copy(cur, network.IP)

	var ips []string
	for network.Contains(cur) {
		if len(ips) >= maxHosts {
			break
		}
		ips = append(ips, cur.String())
		// Increment the IP by 1 (big-endian).
		for j := len(cur) - 1; j >= 0; j-- {
			cur[j]++
			if cur[j] != 0 {
				break
			}
		}
	}
	// Drop network address (first) and broadcast (last).
	if len(ips) >= 2 {
		ips = ips[1 : len(ips)-1]
	}
	return ips, nil
}

// ─── ARP helpers ──────────────────────────────────────────────────────────────

// readARPCache returns a map of IPv4 address → sanitised MAC address for
// all complete ARP entries (i.e. confirmed hosts with a non-zero MAC).
// It reads /proc/net/arp directly on Linux (no subprocess, no privileges)
// and falls back to running `arp -an` on macOS / BSD.
func readARPCache() map[string]string {
	table := make(map[string]string)
	readARPCacheInto(table, true)
	return table
}

// readARPCacheKnownIPs returns the set of all IP addresses that appear in the
// kernel ARP table — including incomplete entries (flags 0x0) that have no
// confirmed MAC yet. This lets us probe hosts the kernel knows about even when
// ICMP is blocked and the ARP handshake has not yet completed.
func readARPCacheKnownIPs(network *net.IPNet) map[string]bool {
	known := make(map[string]bool)
	raw := make(map[string]string) // ip → raw MAC (may be all-zero)
	readARPCacheInto(raw, false)
	for ip := range raw {
		if parsed := net.ParseIP(ip); parsed != nil && network.Contains(parsed) {
			known[ip] = true
		}
	}
	return known
}

// readARPCacheInto populates dst.  If onlyComplete is true only entries with a
// valid non-zero MAC are stored; otherwise all entries are stored (with the raw
// MAC value, which may be "00:00:00:00:00:00" for incomplete entries).
func readARPCacheInto(dst map[string]string, onlyComplete bool) {
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
			if ip == "" {
				continue
			}
			mac := strings.ToUpper(strings.TrimSpace(fields[3]))
			if onlyComplete {
				mac = sanitizeMAC(mac)
				if mac == "" || mac == "00:00:00:00:00:00" {
					continue
				}
				dst[ip] = mac
			} else {
				// Keep all entries so we know the host's IP exists in the ARP table.
				dst[ip] = mac
			}
		}
		return
	}

	// macOS / BSD fallback: arp -an
	// Example line: ? (10.0.0.1) at a4:b1:e9:xx:xx:xx on en0 ifscope ...
	out, aErr := exec.Command("arp", "-an").Output()
	if aErr != nil {
		return
	}
	arpRe := regexp.MustCompile(`\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]{17})`)
	for _, line := range strings.Split(string(out), "\n") {
		m := arpRe.FindStringSubmatch(line)
		if len(m) == 3 {
			ip := sanitizeIP(m[1])
			if ip == "" {
				continue
			}
			mac := strings.ToUpper(m[2])
			if onlyComplete {
				mac = sanitizeMAC(mac)
				if mac == "" || mac == "00:00:00:00:00:00" {
					continue
				}
				dst[ip] = mac
			} else {
				dst[ip] = mac
			}
		}
	}
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
