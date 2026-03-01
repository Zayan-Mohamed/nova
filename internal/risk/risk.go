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
