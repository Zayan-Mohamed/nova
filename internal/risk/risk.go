// Package risk provides security scoring and risk tagging for NOVA.
// It analyses WiFi networks and LAN hosts and produces human-readable
// risk assessments. No exploitation is performed — this is read-only analysis.
package risk

import (
	"fmt"
	"strings"

	"github.com/Zayan-Mohamed/nova/internal/scanner"
	"github.com/Zayan-Mohamed/nova/internal/wifi"
)

// Level represents a severity tier.
type Level int

// Level constants define severity tiers from informational to critical.
const (
	LevelInfo     Level = iota // purely informational
	LevelLow                   // minor concern
	LevelMedium                // notable security issue
	LevelHigh                  // serious vulnerability
	LevelCritical              // severe / immediate risk
)

// String returns the textual name of a Level.
func (l Level) String() string {
	switch l {
	case LevelInfo:
		return "Info"
	case LevelLow:
		return "Low"
	case LevelMedium:
		return "Medium"
	case LevelHigh:
		return "High"
	case LevelCritical:
		return "Critical"
	default:
		return "Unknown"
	}
}

// Finding is a single security observation attached to a network or host.
type Finding struct {
	Level       Level
	Title       string
	Description string
}

// NetworkReport holds the risk assessment for a WiFi network.
type NetworkReport struct {
	Network  wifi.Network
	Findings []Finding
	Score    int // 0 (insecure) – 100 (secure)
}

// HostReport holds the risk assessment for a LAN host.
type HostReport struct {
	Host     scanner.Host
	Findings []Finding
	Score    int // 0 (insecure) – 100 (secure)
}

// ─── Dangerous port definitions ───────────────────────────────────────────────

// dangerousPorts maps port numbers to a human-readable risk description.
// This is an allow-listed map; only well-known risky services are included.
var dangerousPorts = map[int]struct {
	name  string
	level Level
	desc  string
}{
	21:    {"FTP", LevelHigh, "FTP transmits credentials in plaintext."},
	23:    {"Telnet", LevelCritical, "Telnet transmits all data, including credentials, in plaintext."},
	25:    {"SMTP (open relay risk)", LevelMedium, "SMTP exposed to LAN; verify it is not an open relay."},
	53:    {"DNS", LevelLow, "DNS exposed; ensure it is not an open resolver."},
	80:    {"HTTP", LevelLow, "Unencrypted web interface detected."},
	110:   {"POP3", LevelMedium, "POP3 transmits credentials in plaintext."},
	111:   {"RPC", LevelHigh, "RPC portmapper exposure can lead to NFS exploitation."},
	135:   {"MS RPC", LevelHigh, "Microsoft RPC can expose attack surface on Windows hosts."},
	137:   {"NetBIOS-NS", LevelHigh, "NetBIOS Name Service exposed; information leakage risk."},
	139:   {"NetBIOS-SSN", LevelHigh, "NetBIOS Session Service exposed; SMB/CIFS attack surface."},
	143:   {"IMAP", LevelMedium, "IMAP may transmit credentials in plaintext."},
	445:   {"SMB", LevelCritical, "SMB exposed; high risk of ransomware and lateral movement (e.g. EternalBlue)."},
	512:   {"rexec", LevelCritical, "Legacy rexec service transmits credentials in plaintext."},
	513:   {"rlogin", LevelCritical, "Legacy rlogin service; no authentication by default."},
	514:   {"rsh/syslog", LevelCritical, "Legacy rsh service — trust-based auth; trivially bypassed."},
	1900:  {"UPnP", LevelHigh, "UPnP exposed; routers may allow unauthenticated port-forward requests."},
	2049:  {"NFS", LevelHigh, "NFS exposed; may allow unauthenticated filesystem access."},
	3306:  {"MySQL", LevelMedium, "Database port exposed to LAN; restrict to localhost where possible."},
	3389:  {"RDP", LevelHigh, "RDP exposed; brute-force and credential-stuffing target."},
	4444:  {"Possible backdoor", LevelCritical, "Port 4444 is commonly used by reverse shells and backdoors."},
	5432:  {"PostgreSQL", LevelMedium, "Database port exposed to LAN; restrict to localhost where possible."},
	5900:  {"VNC", LevelHigh, "VNC exposed; often misconfigured with weak or no authentication."},
	6379:  {"Redis", LevelCritical, "Redis often ships with no authentication; remote code execution risk."},
	8080:  {"HTTP-Alt", LevelLow, "Alternative HTTP port detected; verify it uses TLS."},
	27017: {"MongoDB", LevelCritical, "MongoDB exposed; often ships with no authentication."},
}

// ─── WiFi risk analysis ───────────────────────────────────────────────────────

// AnalyseNetwork evaluates a single WiFi network and returns a NetworkReport.
func AnalyseNetwork(n wifi.Network) NetworkReport {
	var findings []Finding

	// --- Encryption ---
	switch n.Security {
	case "Open":
		findings = append(findings, Finding{
			Level: LevelCritical,
			Title: "Open Network",
			Description: "No encryption is in use. All traffic is transmitted in plaintext " +
				"and can be read by any nearby observer.",
		})
	case "WEP":
		findings = append(findings, Finding{
			Level: LevelCritical,
			Title: "WEP Encryption",
			Description: "WEP is cryptographically broken and can be cracked within minutes. " +
				"Upgrade to WPA2 or WPA3 immediately.",
		})
	case "WPA":
		findings = append(findings, Finding{
			Level:       LevelHigh,
			Title:       "WPA (TKIP) Encryption",
			Description: "WPA-TKIP has known weaknesses. Upgrade to WPA2-AES or WPA3.",
		})
	case "WPA2":
		findings = append(findings, Finding{
			Level:       LevelInfo,
			Title:       "WPA2 Encryption",
			Description: "WPA2 is acceptable but WPA3 provides stronger protection.",
		})
	case "WPA3":
		findings = append(findings, Finding{
			Level:       LevelInfo,
			Title:       "WPA3 Encryption",
			Description: "WPA3 offers the strongest currently available WiFi encryption.",
		})
	default:
		findings = append(findings, Finding{
			Level:       LevelMedium,
			Title:       "Unknown Encryption",
			Description: "The encryption type could not be determined.",
		})
	}

	// --- Channel congestion ---
	if n.Channel >= 1 && n.Channel <= 14 && n.Signal >= -60 {
		findings = append(findings, Finding{
			Level:       LevelInfo,
			Title:       fmt.Sprintf("2.4 GHz Channel %d", n.Channel),
			Description: "2.4 GHz bands are more congested. Consider 5 GHz if interference is a concern.",
		})
	}

	// --- Signal quality ---
	if n.Signal < -80 {
		findings = append(findings, Finding{
			Level:       LevelLow,
			Title:       "Weak Signal",
			Description: fmt.Sprintf("Signal strength is %d dBm (%s). Weak signals may cause connectivity issues.", n.Signal, wifi.SignalLabel(n.Signal)),
		})
	}

	score := scoreNetwork(findings, n)
	return NetworkReport{
		Network:  n,
		Findings: findings,
		Score:    score,
	}
}

// scoreNetwork produces a 0–100 security score for a WiFi network.
// Deductions are applied per finding level.
func scoreNetwork(findings []Finding, n wifi.Network) int {
	score := 100

	// Encryption base deduction.
	switch n.Security {
	case "Open":
		score -= 60
	case "WEP":
		score -= 55
	case "WPA":
		score -= 30
	case "WPA2":
		// no deduction
	case "WPA3":
		score += 0 // already at baseline
	default:
		score -= 20
	}

	for _, f := range findings {
		switch f.Level {
		case LevelCritical:
			score -= 40
		case LevelHigh:
			score -= 20
		case LevelMedium:
			score -= 10
		case LevelLow:
			score -= 5
		}
	}

	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return score
}

// ─── Host risk analysis ───────────────────────────────────────────────────────

// AnalyseHost evaluates a single LAN host and returns a HostReport.
func AnalyseHost(h scanner.Host) HostReport {
	var findings []Finding

	// --- Dangerous open ports ---
	for _, p := range h.OpenPorts {
		if info, ok := dangerousPorts[p.Number]; ok {
			findings = append(findings, Finding{
				Level:       info.level,
				Title:       fmt.Sprintf("Port %d/%s open (%s)", p.Number, p.Protocol, info.name),
				Description: info.desc,
			})
		}
	}

	// --- Unknown device warning ---
	if h.MAC != "" && h.Vendor == "" {
		findings = append(findings, Finding{
			Level:       LevelLow,
			Title:       "Unknown MAC Vendor",
			Description: "The MAC address vendor could not be identified. This could indicate a spoofed MAC or an unfamiliar device.",
		})
	}

	// --- No hostname ---
	if h.Hostname == "" {
		findings = append(findings, Finding{
			Level:       LevelInfo,
			Title:       "No Hostname Resolved",
			Description: "The device did not respond to reverse DNS. This is normal for many IoT devices.",
		})
	}

	score := scoreHost(findings, h)
	return HostReport{
		Host:     h,
		Findings: findings,
		Score:    score,
	}
}

// AnalyseHostDeep extends AnalyseHost with richer findings from a deep scan:
// service version advisories, device type classification, UDP service risks,
// SSL certificate expiry hints, and NSE script intelligence.
func AnalyseHostDeep(h scanner.Host) HostReport {
	// Start with the standard analysis.
	report := AnalyseHost(h)

	// --- Device type classification + mobile-hotspot heuristic ---
	//
	// Mobile hotspots (Android / iPhone tethering, MiFi devices) show up as
	// the default gateway with very few open TCP ports because iptables only
	// lets DNS and DHCP through the tethering interface.  nmap therefore
	// reports OS as "Linux 2.6.x / 3.x / 4.x" (Android kernel) and device
	// type as "general purpose" — which is unhelpfully generic.
	//
	// We override the classification when the following are ALL true:
	//   1. The host is marked as the default gateway by DeepScan.
	//   2. Fewer than 4 TCP ports are open (hotspot firewall blocks the rest).
	//   3. OS contains a Linux kernel version string.
	// → Almost certainly a mobile hotspot, not a "general purpose" server.
	deviceType := strings.ToLower(h.DeviceType)
	openTCPCount := 0
	for _, p := range h.OpenPorts {
		if p.Protocol == "tcp" {
			openTCPCount++
		}
	}
	isLikelyHotspot := deviceType == "gateway" && openTCPCount <= 4 &&
		(strings.Contains(strings.ToLower(h.OS), "linux") ||
			strings.Contains(strings.ToLower(h.OS), "android"))

	if isLikelyHotspot {
		// Override so the device-type switch below and the UI both see this.
		h.DeviceType = "mobile hotspot / router"
		deviceType = "mobile hotspot / router"
		report.Host.DeviceType = h.DeviceType
	}

	switch {
	case deviceType == "mobile hotspot / router" || isLikelyHotspot:
		report.Findings = append(report.Findings, Finding{
			Level: LevelInfo,
			Title: "Mobile Hotspot / Tethering Gateway Detected",
			Description: fmt.Sprintf(
				"This device (%s) is the network default gateway and shows "+
					"characteristics of a mobile hotspot or Android/iOS tethering "+
					"device (Linux kernel OS, few exposed ports). Ensure no admin "+
					"interface is reachable from connected clients.", h.IP),
		})
	case strings.Contains(deviceType, "router") || strings.Contains(deviceType, "firewall") || strings.Contains(deviceType, "broadband"):
		report.Findings = append(report.Findings, Finding{
			Level:       LevelInfo,
			Title:       "Gateway / Router Detected",
			Description: fmt.Sprintf("Device type identified as %q. Verify admin interface is not accessible from untrusted networks.", h.DeviceType),
		})
	case strings.Contains(deviceType, "phone") || strings.Contains(deviceType, "smartphone"):
		report.Findings = append(report.Findings, Finding{
			Level:       LevelInfo,
			Title:       "Mobile Device / Hotspot Detected",
			Description: "A mobile device or mobile hotspot was identified. Ensure the tethering admin interface is not exposed.",
		})
	case strings.Contains(deviceType, "print") || deviceType == "printer":
		report.Findings = append(report.Findings, Finding{
			Level:       LevelMedium,
			Title:       "Network Printer Detected",
			Description: "Printers often have weak authentication and can be used as pivot points. Verify admin access is restricted.",
		})
	case strings.Contains(deviceType, "webcam") || strings.Contains(deviceType, "media") || strings.Contains(deviceType, "storage"):
		report.Findings = append(report.Findings, Finding{
			Level:       LevelMedium,
			Title:       fmt.Sprintf("IoT / Embedded Device (%s)", h.DeviceType),
			Description: "Embedded devices frequently run outdated firmware. Check for default credentials and available firmware updates.",
		})
	}

	// --- Service version advisories ---
	for _, p := range h.OpenPorts {
		// HTTP admin panels (common on routers and mobile hotspots).
		if (p.Number == 80 || p.Number == 8080 || p.Number == 8888 || p.Number == 7547) &&
			p.Protocol == "tcp" {
			for _, s := range p.Scripts {
				if s.ID == "http-title" && s.Output != "" {
					report.Findings = append(report.Findings, Finding{
						Level:       LevelInfo,
						Title:       fmt.Sprintf("Web Interface Detected (port %d)", p.Number),
						Description: fmt.Sprintf("Page title: %q. Verify this admin interface requires authentication.", s.Output),
					})
				}
			}
		}

		// SSL/TLS certificate info.
		for _, s := range p.Scripts {
			if s.ID == "ssl-cert" && s.Output != "" {
				out := s.Output
				if strings.Contains(strings.ToLower(out), "expired") ||
					strings.Contains(strings.ToLower(out), "not valid after") {
					report.Findings = append(report.Findings, Finding{
						Level:       LevelMedium,
						Title:       fmt.Sprintf("TLS Certificate Issue (port %d)", p.Number),
						Description: "The TLS certificate may be expired or self-signed. Details: " + truncate(out, 120),
					})
				}
			}

			// SMB OS discovery.
			if s.ID == "smb-os-discovery" && s.Output != "" {
				report.Findings = append(report.Findings, Finding{
					Level:       LevelInfo,
					Title:       "SMB OS Details",
					Description: truncate(s.Output, 160),
				})
			}

			// SNMP info — reveals device description.
			if s.ID == "snmp-info" && s.Output != "" {
				report.Findings = append(report.Findings, Finding{
					Level:       LevelMedium,
					Title:       "SNMP Public Community String Accessible",
					Description: "SNMP with community string 'public' is responding. Device info: " + truncate(s.Output, 160),
				})
			}

			// UPnP info — reveals device model/manufacturer.
			if s.ID == "upnp-info" && s.Output != "" {
				report.Findings = append(report.Findings, Finding{
					Level:       LevelHigh,
					Title:       "UPnP Service Exposed",
					Description: "UPnP can allow unauthenticated port-forwarding. Device info: " + truncate(s.Output, 160),
				})
			}
		}

		// Port 7547 (TR-069) — ISP remote management protocol, very dangerous if exposed.
		if p.Number == 7547 && p.Protocol == "tcp" {
			report.Findings = append(report.Findings, Finding{
				Level:       LevelCritical,
				Title:       "TR-069 (CWMP) Management Port Exposed",
				Description: "Port 7547 is used by ISPs for remote router management. If exposed to LAN, it may allow unauthorised configuration changes (e.g. Mirai botnet vector).",
			})
		}

		// Port 49152+ — common UPnP/SOAP control URLs on consumer routers.
		if p.Number >= 49152 && p.Number <= 49165 && p.Protocol == "tcp" {
			report.Findings = append(report.Findings, Finding{
				Level:       LevelHigh,
				Title:       fmt.Sprintf("High Dynamic Port %d Open (possible UPnP control)", p.Number),
				Description: "Dynamic ports in the 49152+ range are commonly used for UPnP SOAP control endpoints on routers and IoT devices.",
			})
		}

		// SSH with old version.
		if p.Service == "ssh" && p.Version != "" {
			if strings.HasPrefix(p.Version, "6.") || strings.HasPrefix(p.Version, "5.") || strings.HasPrefix(p.Version, "4.") {
				report.Findings = append(report.Findings, Finding{
					Level:       LevelHigh,
					Title:       fmt.Sprintf("Outdated SSH Version (port %d): %s %s", p.Number, p.Product, p.Version),
					Description: "This SSH version is likely end-of-life and may contain unpatched vulnerabilities. Upgrade the SSH server.",
				})
			}
		}

		// Telnet detected by service version (extra insurance beyond port 23).
		if strings.Contains(strings.ToLower(p.Service), "telnet") {
			report.Findings = append(report.Findings, Finding{
				Level:       LevelCritical,
				Title:       fmt.Sprintf("Telnet Service Confirmed (port %d)", p.Number),
				Description: "Telnet transmits all data in plaintext. Disable this service immediately.",
			})
		}

		// Default router credentials hint via HTTP server header.
		if p.Product != "" {
			pLow := strings.ToLower(p.Product)
			routerKeywords := []string{"miniupnp", "dnsmasq", "openwrt", "dd-wrt", "tomato", "routeros", "mikrotik", "zyxel", "netgear", "tplink", "tp-link", "asus", "linksys", "dlink", "d-link", "huawei", "zte", "tenda"} //nolint:misspell // routeros is MikroTik's RouterOS product, not a misspelling
			for _, kw := range routerKeywords {
				if strings.Contains(pLow, kw) {
					report.Findings = append(report.Findings, Finding{
						Level:       LevelMedium,
						Title:       fmt.Sprintf("Router/AP Software Identified: %s", p.Product),
						Description: "Check for default credentials and ensure firmware is up to date. Vendor: " + p.Product + " " + p.Version,
					})
					break
				}
			}
		}
	}

	// --- OS confidence advisory ---
	if h.OS != "" && h.OSAccuracy > 0 && h.OSAccuracy < 85 {
		report.Findings = append(report.Findings, Finding{
			Level:       LevelInfo,
			Title:       fmt.Sprintf("OS Detection Low Confidence (%d%%): %s", h.OSAccuracy, h.OS),
			Description: "OS fingerprinting confidence is below 85%. The OS guess may be inaccurate.",
		})
	}

	// Re-score with the enriched findings.
	report.Score = scoreHost(report.Findings, h)
	return report
}

// scoreHost produces a 0–100 security score for a LAN host.
func scoreHost(findings []Finding, _ scanner.Host) int {
	score := 100
	for _, f := range findings {
		switch f.Level {
		case LevelCritical:
			score -= 35
		case LevelHigh:
			score -= 20
		case LevelMedium:
			score -= 10
		case LevelLow:
			score -= 5
		}
	}
	if score < 0 {
		score = 0
	}
	return score
}

// ─── Score colouring helpers ──────────────────────────────────────────────────

// ScoreLabel returns a human label for a 0–100 score.
func ScoreLabel(score int) string {
	switch {
	case score >= 80:
		return "Secure"
	case score >= 60:
		return "Moderate"
	case score >= 40:
		return "At Risk"
	default:
		return "Critical"
	}
}

// ScoreColor returns a lipgloss-compatible hex color for a score.
func ScoreColor(score int) string {
	switch {
	case score >= 80:
		return "#2ECC71" // green
	case score >= 60:
		return "#F1C40F" // yellow
	case score >= 40:
		return "#E67E22" // orange
	default:
		return "#E74C3C" // red
	}
}

// LevelColor returns a lipgloss-compatible hex color for a Finding level.
func LevelColor(l Level) string {
	switch l {
	case LevelInfo:
		return "#3498DB"
	case LevelLow:
		return "#2ECC71"
	case LevelMedium:
		return "#F1C40F"
	case LevelHigh:
		return "#E67E22"
	case LevelCritical:
		return "#E74C3C"
	default:
		return "#AAAAAA"
	}
}

// SummaryLine returns a one-line textual summary of a NetworkReport.
func SummaryLine(r NetworkReport) string {
	return fmt.Sprintf("%-32s  %-8s  Score: %3d/100  (%s)",
		truncate(r.Network.SSID, 32),
		r.Network.Security,
		r.Score,
		ScoreLabel(r.Score),
	)
}

// HostSummaryLine returns a one-line textual summary of a HostReport.
func HostSummaryLine(r HostReport) string {
	portCount := len(r.Host.OpenPorts)
	vendor := r.Host.Vendor
	if vendor == "" {
		vendor = "Unknown"
	}
	return fmt.Sprintf("%-16s  %-20s  Ports: %3d  Score: %3d/100  (%s)",
		r.Host.IP,
		truncate(vendor, 20),
		portCount,
		r.Score,
		ScoreLabel(r.Score),
	)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func truncate(s string, max int) string {
	runes := []rune(s)
	if len(runes) <= max {
		return s + strings.Repeat(" ", max-len(runes))
	}
	return string(runes[:max-1]) + "…"
}
