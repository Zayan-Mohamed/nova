// Package wifi provides WiFi network analysis capabilities for NOVA.
// It lists nearby access points, reads signal strength, encryption type,
// channel, and BSSID. All output is sanitized before being returned to
// callers to prevent terminal injection attacks.
package wifi

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// maxFieldLen is the maximum number of runes allowed for any single field
// value (SSID, BSSID, vendor, etc.) to prevent memory exhaustion.
const maxFieldLen = 256

// scanTimeout is the maximum time allowed for the underlying scan command.
const scanTimeout = 20 * time.Second

// Network represents a single WiFi access point discovered during a scan.
type Network struct {
	SSID      string
	BSSID     string
	Signal    int // dBm, e.g. -65
	Channel   int
	Frequency string // e.g. "2.4 GHz" or "5 GHz"
	Security  string // e.g. "WPA2", "WEP", "Open"
	Interface string
}

// validBSSID is a strict pattern for a colon-delimited MAC address.
var validBSSID = regexp.MustCompile(`^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$`)

// sanitize removes control characters, ANSI escape sequences, and truncates
// the value to maxFieldLen runes to prevent terminal injection.
func sanitize(s string) string {
	// Strip ANSI/VT escape sequences (ESC [ ... m and similar).
	ansiEscape := regexp.MustCompile(`\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])`)
	s = ansiEscape.ReplaceAllString(s, "")

	// Remove non-printable / control characters.
	var b strings.Builder
	for _, r := range s {
		if unicode.IsPrint(r) && r != '\x7f' {
			b.WriteRune(r)
		}
	}
	result := strings.TrimSpace(b.String())

	// Truncate to maxFieldLen runes.
	runes := []rune(result)
	if len(runes) > maxFieldLen {
		runes = runes[:maxFieldLen]
	}
	return string(runes)
}

// validateChannel returns a channel number only if it is in a sane range
// (1–196). Returns 0 for anything outside that range.
func validateChannel(ch int) int {
	if ch >= 1 && ch <= 196 {
		return ch
	}
	return 0
}

// validateSignal accepts dBm values in the range -120..0.
// Values outside that range are clamped to 0.
func validateSignal(dbm int) int {
	if dbm >= -120 && dbm <= 0 {
		return dbm
	}
	return 0
}

// sanitizeSecurity maps raw security strings to a small allow-list so that
// arbitrary tool output cannot inject unexpected strings into the UI.
func sanitizeSecurity(raw string) string {
	upper := strings.ToUpper(strings.TrimSpace(raw))
	switch {
	case strings.Contains(upper, "WPA3"):
		return "WPA3"
	case strings.Contains(upper, "WPA2"):
		return "WPA2"
	case strings.Contains(upper, "WPA"):
		return "WPA"
	case strings.Contains(upper, "WEP"):
		return "WEP"
	case upper == "" || strings.Contains(upper, "OPEN") || strings.Contains(upper, "NONE"):
		return "Open"
	default:
		return "Unknown"
	}
}

// frequencyBand converts a raw frequency string to a human label.
// nmcli terse output may include a " MHz" suffix (e.g. "2457 MHz" or "5180 MHz").
// We extract the leading digit run before attempting integer conversion.
func frequencyBand(freqStr string) string {
	freqStr = strings.TrimSpace(freqStr)
	// Keep only the leading numeric characters (stop at first non-digit, e.g. space).
	numPart := strings.FieldsFunc(freqStr, func(r rune) bool {
		return r < '0' || r > '9'
	})
	if len(numPart) == 0 {
		return "Unknown"
	}
	mhz, err := strconv.Atoi(numPart[0])
	if err != nil {
		return "Unknown"
	}
	switch {
	case mhz >= 2400 && mhz < 2500:
		return "2.4 GHz"
	case mhz >= 5000 && mhz < 6000:
		return "5 GHz"
	case mhz >= 6000 && mhz < 7200:
		return "6 GHz"
	default:
		return fmt.Sprintf("%d MHz", mhz)
	}
}

// Scan discovers available WiFi networks using nmcli (NetworkManager CLI).
// It returns an error if nmcli is not available or the scan fails.
// ctx must carry a deadline; if not, a default timeout is applied internally.
func Scan(ctx context.Context, iface string) ([]Network, error) {
	// Apply a hard timeout if the caller did not set one.
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, scanTimeout)
		defer cancel()
	}

	// Validate the interface name: only allow alphanumeric chars, dash, underscore, dot.
	if iface != "" && !isValidInterfaceName(iface) {
		return nil, fmt.Errorf("invalid interface name: %q", iface)
	}

	// Build the argument list using structured arguments — NO shell expansion.
	// We ask nmcli to rescan and dump fields in a machine-readable form.
	args := []string{
		"-t", // terse (colon-separated)
		"-f", "SSID,BSSID,SIGNAL,CHAN,FREQ,SECURITY,DEVICE",
		"dev", "wifi", "list", "--rescan", "yes",
	}
	if iface != "" {
		args = append(args, "ifname", iface)
	}

	cmd := exec.CommandContext(ctx, "nmcli", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("wifi scan timed out")
		}
		return nil, fmt.Errorf("nmcli failed: %w", err)
	}

	return parseNmcliOutput(stdout.String()), nil
}

// isValidInterfaceName permits only characters that are legal in Linux
// network interface names (up to 15 chars, alphanumeric + -._ ).
func isValidInterfaceName(name string) bool {
	if len(name) == 0 || len(name) > 15 {
		return false
	}
	for _, r := range name {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' && r != '_' && r != '.' {
			return false
		}
	}
	return true
}

// parseNmcliOutput parses the terse output of `nmcli -t dev wifi list`.
// Fields are colon-separated; escaped colons appear as \: in nmcli output.
func parseNmcliOutput(raw string) []Network {
	var networks []Network
	seen := make(map[string]bool) // deduplicate by BSSID

	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := splitNmcliTerse(line)
		if len(parts) < 7 {
			continue
		}

		ssid := sanitize(parts[0])
		bssid := sanitize(parts[1])

		// Skip entries with invalid BSSIDs.
		if !validBSSID.MatchString(bssid) {
			continue
		}
		// Deduplicate.
		if seen[bssid] {
			continue
		}
		seen[bssid] = true

		signal, _ := strconv.Atoi(strings.TrimSpace(parts[2]))
		// nmcli reports signal as 0-100 percentage; convert to approximate dBm.
		dbm := percentToDBm(signal)

		channel, _ := strconv.Atoi(strings.TrimSpace(parts[3]))
		channel = validateChannel(channel)

		freq := frequencyBand(strings.TrimSpace(parts[4]))
		security := sanitizeSecurity(parts[5])
		device := sanitize(parts[6])
		if !isValidInterfaceName(device) {
			device = ""
		}

		networks = append(networks, Network{
			SSID:      ssid,
			BSSID:     bssid,
			Signal:    validateSignal(dbm),
			Channel:   channel,
			Frequency: freq,
			Security:  security,
			Interface: device,
		})
	}
	return networks
}

// splitNmcliTerse splits a colon-delimited nmcli terse line, respecting
// escaped colons (\:) that appear inside SSID values.
func splitNmcliTerse(line string) []string {
	var parts []string
	var current strings.Builder
	runes := []rune(line)
	for i := 0; i < len(runes); i++ {
		if runes[i] == '\\' && i+1 < len(runes) && runes[i+1] == ':' {
			current.WriteRune(':')
			i++ // skip the escaped colon
		} else if runes[i] == ':' {
			parts = append(parts, current.String())
			current.Reset()
		} else {
			current.WriteRune(runes[i])
		}
	}
	parts = append(parts, current.String())
	return parts
}

// percentToDBm converts nmcli's 0-100 signal percentage to approximate dBm.
// Formula: dBm = (percentage / 2) - 100.
func percentToDBm(pct int) int {
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	return (pct / 2) - 100
}

// SignalLabel returns a human-readable label for a dBm signal value.
func SignalLabel(dbm int) string {
	switch {
	case dbm >= -50:
		return "Excellent"
	case dbm >= -60:
		return "Good"
	case dbm >= -70:
		return "Fair"
	case dbm >= -80:
		return "Weak"
	default:
		return "Poor"
	}
}
