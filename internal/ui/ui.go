// Package ui implements the NOVA terminal user interface using BubbleTea
// and Lipgloss. The TUI is keyboard-driven with clearly documented bindings,
// no hidden actions, and no destructive operations without confirmation.
// All scan operations run asynchronously so the UI never freezes.
package ui

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/Zayan-Mohamed/nova/internal/risk"
	"github.com/Zayan-Mohamed/nova/internal/scanner"
	"github.com/Zayan-Mohamed/nova/internal/wifi"
)

// ─── View states ──────────────────────────────────────────────────────────────

type viewState int

const (
	viewConsent    viewState = iota // legal consent screen
	viewMainMenu                    // main navigation menu
	viewWiFi                        // WiFi scan results
	viewHosts                       // LAN host discovery results
	viewHostDetail                  // single-host port/risk detail
	viewDeepScan                    // full deep scan intelligence view
	viewHelp                        // key bindings
)

// ─── Async message types ─────────────────────────────────────────────────────

// wifiScanDoneMsg is sent when a WiFi scan completes.
type wifiScanDoneMsg struct {
	reports []risk.NetworkReport
	err     error
}

// hostScanDoneMsg is sent when a LAN host discovery completes.
type hostScanDoneMsg struct {
	reports []risk.HostReport
	err     error
}

// portScanDoneMsg is sent when a port scan of a single host completes.
type portScanDoneMsg struct {
	ip    string
	ports []scanner.Port
	err   error
}

// deepScanDoneMsg is sent when a deep scan of a single host completes.
type deepScanDoneMsg struct {
	result *scanner.DeepScanResult
	report risk.HostReport
	err    error
}

// tickMsg drives the loading animation.
type tickMsg time.Time

// ─── Model ────────────────────────────────────────────────────────────────────

// Model holds the complete TUI state.
type Model struct {
	// layout
	width  int
	height int

	// view state
	state viewState

	// consent
	consentAccepted bool

	// menus
	menuCursor int
	menuItems  []string

	// wifi
	wifiReports      []risk.NetworkReport
	wifiCursor       int
	wifiLoading      bool
	wifiError        string
	wifiSearchActive bool   // true when search input is focused
	wifiSearchQuery  string // current search text
	wifiFilterSec    string // "" = all, "open", "wpa2", "wpa3"

	// hosts
	hostReports []risk.HostReport
	hostCursor  int
	hostLoading bool
	hostError   string
	hostCIDR    string

	// host detail (port scan)
	selectedHost *risk.HostReport
	portLoading  bool
	portError    string

	// deep scan
	deepScanResult  *scanner.DeepScanResult
	deepScanReport  *risk.HostReport
	deepScanLoading bool
	deepScanError   string
	deepScanScrollY int // vertical scroll offset for the detail pane

	// general
	spinner int // 0-3 for spinner frames
	isRoot  bool
}

// menuItems list — index must stay stable; append-only.
var mainMenuItems = []string{
	"WiFi Analysis",
	"LAN Host Discovery",
	"Help",
	"Quit",
}

// ─── Styles ───────────────────────────────────────────────────────────────────

var (
	colorPrimary  = lipgloss.Color("#7B68EE") // medium slate blue
	colorAccent   = lipgloss.Color("#00D7FF") // cyan
	colorAccent2  = lipgloss.Color("#FF79C6") // pink
	colorTitle    = lipgloss.Color("#BD93F9") // lavender
	colorMuted    = lipgloss.Color("#6272A4") // muted blue-grey
	colorFaint    = lipgloss.Color("#44475A") // very muted
	colorSuccess  = lipgloss.Color("#50FA7B") // green
	colorWarn     = lipgloss.Color("#FFB86C") // orange
	colorDanger   = lipgloss.Color("#FF5555") // red
	colorSelected = lipgloss.Color("#00D7FF") // cyan (matches accent)

	styleTitle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorTitle).
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(colorPrimary).
			Padding(0, 3)

	styleSelected = lipgloss.NewStyle().
			Foreground(colorSelected).
			Bold(true)

	styleNormal = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F8F8F2"))

	styleMuted = lipgloss.NewStyle().
			Foreground(colorMuted)

	styleFaint = lipgloss.NewStyle().
			Foreground(colorFaint)

	styleSuccess = lipgloss.NewStyle().
			Foreground(colorSuccess).
			Bold(true)

	styleDanger = lipgloss.NewStyle().
			Foreground(colorDanger).
			Bold(true)

	styleWarn = lipgloss.NewStyle().
			Foreground(colorWarn).
			Bold(true)

	styleAccent = lipgloss.NewStyle().
			Foreground(colorAccent).
			Bold(true)

	styleAccent2 = lipgloss.NewStyle().
			Foreground(colorAccent2).
			Bold(true)

	styleBox = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(colorPrimary).
			Padding(1, 3)

	styleHelp = lipgloss.NewStyle().
			Foreground(colorMuted)

	// Menu item styles.
	styleMenuBox = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(colorFaint).
			Padding(0, 2)

	styleMenuBoxSelected = lipgloss.NewStyle().
				BorderStyle(lipgloss.RoundedBorder()).
				BorderForeground(colorAccent).
				Padding(0, 2)
)

// spinnerFrames are the frames for the loading animation.
var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// novaASCII is the NOVA ASCII art logo (7 lines × ~46 chars wide).
const novaASCII = `
 ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗ 
 ████╗  ██║██╔═══██╗██║   ██║██╔══██╗
 ██╔██╗ ██║██║   ██║██║   ██║███████║
 ██║╚██╗██║██║   ██║╚██╗ ██╔╝██╔══██║
 ██║ ╚████║╚██████╔╝ ╚████╔╝ ██║  ██║
 ╚═╝  ╚═══╝ ╚═════╝   ╚═══╝  ╚═╝  ╚═╝`

// center places s horizontally in a field of width w.
func center(s string, w int) string {
	return lipgloss.NewStyle().Width(w).Align(lipgloss.Center).Render(s)
}

// vcenter pads the top so that content appears vertically centred.
func vcenter(content string, totalHeight, contentHeight int) string {
	pad := (totalHeight - contentHeight) / 2
	if pad < 0 {
		pad = 0
	}
	var sb strings.Builder
	for i := 0; i < pad; i++ {
		sb.WriteString("\n")
	}
	sb.WriteString(content)
	return sb.String()
}

// ─── Constructor ─────────────────────────────────────────────────────────────

// NewModel creates a new TUI model. isRoot indicates whether the process has
// root privileges (affects scan type offered to the user).
func NewModel(isRoot bool, hostCIDR string) Model {
	return Model{
		state:     viewConsent,
		menuItems: mainMenuItems,
		isRoot:    isRoot,
		hostCIDR:  hostCIDR,
	}
}

// ─── BubbleTea interface ──────────────────────────────────────────────────────

// Init starts the loading spinner tick.
func (m Model) Init() tea.Cmd {
	return tickCmd()
}

// Update processes incoming messages and updates the model.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	// ── Window size ──
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	// ── Spinner tick ──
	case tickMsg:
		m.spinner = (m.spinner + 1) % len(spinnerFrames)
		return m, tickCmd()

	// ── WiFi scan result ──
	case wifiScanDoneMsg:
		m.wifiLoading = false
		if msg.err != nil {
			m.wifiError = msg.err.Error()
		} else {
			m.wifiReports = msg.reports
			m.wifiError = ""
			m.wifiCursor = 0
		}
		return m, nil

	// ── Host discovery result ──
	case hostScanDoneMsg:
		m.hostLoading = false
		if msg.err != nil {
			m.hostError = msg.err.Error()
		} else {
			m.hostReports = msg.reports
			m.hostError = ""
			m.hostCursor = 0
		}
		return m, nil

	// ── Port scan result ──
	case portScanDoneMsg:
		m.portLoading = false
		if msg.err != nil {
			m.portError = msg.err.Error()
		} else if m.selectedHost != nil {
			// Rebuild the host report with the freshly scanned ports.
			updated := m.selectedHost.Host
			updated.OpenPorts = msg.ports
			newReport := risk.AnalyseHost(updated)
			m.selectedHost = &newReport
			m.portError = ""
		}
		return m, nil

	// ── Deep scan result ──
	case deepScanDoneMsg:
		m.deepScanLoading = false
		if msg.err != nil {
			m.deepScanError = msg.err.Error()
		} else {
			m.deepScanResult = msg.result
			report := msg.report
			m.deepScanReport = &report
			m.deepScanError = ""
			m.deepScanScrollY = 0
		}
		return m, nil

	// ── Keyboard ──
	case tea.KeyMsg:
		return m.handleKey(msg)
	}

	return m, nil
}

// handleKey processes keyboard input for the current view state.
func (m Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	// Global quit bindings.
	if key == "ctrl+c" {
		return m, tea.Quit
	}

	switch m.state {
	// ── Consent screen ──
	case viewConsent:
		switch key {
		case "y", "Y":
			m.consentAccepted = true
			m.state = viewMainMenu
		case "n", "N", "q", "Q":
			return m, tea.Quit
		}

	// ── Main menu ──
	case viewMainMenu:
		switch key {
		case "up", "k":
			if m.menuCursor > 0 {
				m.menuCursor--
			}
		case "down", "j":
			if m.menuCursor < len(m.menuItems)-1 {
				m.menuCursor++
			}
		case "enter", " ":
			return m.activateMenuItem()
		case "q":
			return m, tea.Quit
		}

	// ── WiFi view ──
	case viewWiFi:
		if m.wifiSearchActive {
			// Search input mode.
			switch key {
			case "esc":
				m.wifiSearchActive = false
				m.wifiSearchQuery = ""
				m.wifiCursor = 0
			case "enter":
				m.wifiSearchActive = false
				m.wifiCursor = 0
			case "backspace", "delete":
				if len(m.wifiSearchQuery) > 0 {
					m.wifiSearchQuery = m.wifiSearchQuery[:len(m.wifiSearchQuery)-1]
					m.wifiCursor = 0
				}
			case "ctrl+u":
				// Clear entire search.
				m.wifiSearchQuery = ""
				m.wifiCursor = 0
			default:
				// Single printable character.
				if len(key) == 1 && key[0] >= 32 && key[0] <= 126 {
					m.wifiSearchQuery += key
					m.wifiCursor = 0
				}
			}
		} else {
			// Normal navigation mode.
			filtered := m.filterWiFiReports()
			switch key {
			case "up", "k":
				if m.wifiCursor > 0 {
					m.wifiCursor--
				}
			case "down", "j":
				if m.wifiCursor < len(filtered)-1 {
					m.wifiCursor++
				}
			case "/":
				// Enter search mode.
				m.wifiSearchActive = true
				m.wifiSearchQuery = ""
			case "f":
				// Cycle through security filters: "" → "open" → "wpa2" → "wpa3" → "".
				switch m.wifiFilterSec {
				case "":
					m.wifiFilterSec = "open"
				case "open":
					m.wifiFilterSec = "wpa2"
				case "wpa2":
					m.wifiFilterSec = "wpa3"
				case "wpa3":
					m.wifiFilterSec = ""
				}
				m.wifiCursor = 0
			case "c":
				// Clear all filters.
				m.wifiSearchQuery = ""
				m.wifiFilterSec = ""
				m.wifiCursor = 0
			case "r":
				// Re-scan.
				m.wifiLoading = true
				m.wifiError = ""
				return m, runWiFiScan()
			case "esc", "q":
				m.state = viewMainMenu
			}
		}

	// ── Host list view ──
	case viewHosts:
		switch key {
		case "up", "k":
			if m.hostCursor > 0 {
				m.hostCursor--
			}
		case "down", "j":
			if m.hostCursor < len(m.hostReports)-1 {
				m.hostCursor++
			}
		case "enter", " ":
			if len(m.hostReports) > 0 {
				report := m.hostReports[m.hostCursor]
				m.selectedHost = &report
				m.state = viewHostDetail
				m.portLoading = true
				m.portError = ""
				return m, runPortScan(report.Host.IP, m.isRoot)
			}
		case "r":
			// Re-scan.
			m.hostLoading = true
			m.hostError = ""
			return m, runHostScan(m.hostCIDR, m.isRoot)
		case "esc", "q":
			m.state = viewMainMenu
		}

	// ── Host detail view ──
	case viewHostDetail:
		switch key {
		case "d", "D":
			// Launch deep scan from the host detail view.
			if m.selectedHost != nil && !m.deepScanLoading {
				m.state = viewDeepScan
				m.deepScanLoading = true
				m.deepScanError = ""
				m.deepScanResult = nil
				m.deepScanReport = nil
				m.deepScanScrollY = 0
				return m, runDeepScan(m.selectedHost.Host.IP, m.isRoot)
			}
		case "esc", "q":
			m.state = viewHosts
			m.selectedHost = nil
			m.portError = ""
		}

	// ── Deep scan view ──
	case viewDeepScan:
		switch key {
		case "up", "k":
			if m.deepScanScrollY > 0 {
				m.deepScanScrollY--
			}
		case "down", "j":
			m.deepScanScrollY++
		case "r":
			if m.deepScanReport != nil && !m.deepScanLoading {
				ip := m.deepScanReport.Host.IP
				m.deepScanLoading = true
				m.deepScanError = ""
				m.deepScanResult = nil
				m.deepScanReport = nil
				m.deepScanScrollY = 0
				return m, runDeepScan(ip, m.isRoot)
			}
		case "esc", "q":
			m.state = viewHostDetail
			m.deepScanScrollY = 0
		}

	// ── Help view ──
	case viewHelp:
		switch key {
		case "esc", "q":
			m.state = viewMainMenu
		}
	}

	return m, nil
}

// activateMenuItem executes the selected main menu action.
func (m Model) activateMenuItem() (tea.Model, tea.Cmd) {
	switch m.menuCursor {
	case 0: // WiFi Analysis
		m.state = viewWiFi
		m.wifiLoading = true
		m.wifiError = ""
		return m, runWiFiScan()
	case 1: // LAN Host Discovery
		m.state = viewHosts
		m.hostLoading = true
		m.hostError = ""
		return m, runHostScan(m.hostCIDR, m.isRoot)
	case 2: // Help
		m.state = viewHelp
	case 3: // Quit
		return m, tea.Quit
	}
	return m, nil
}

// ─── Async commands ───────────────────────────────────────────────────────────

// tickCmd returns a command that fires after 100 ms to drive the spinner.
func tickCmd() tea.Cmd {
	return tea.Tick(100*time.Millisecond, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

// runWiFiScan returns a BubbleTea command that performs the WiFi scan
// in the background and sends the result as a wifiScanDoneMsg.
func runWiFiScan() tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()

		networks, err := wifi.Scan(ctx, "")
		if err != nil {
			return wifiScanDoneMsg{err: err}
		}

		var reports []risk.NetworkReport
		for _, n := range networks {
			reports = append(reports, risk.AnalyseNetwork(n))
		}
		return wifiScanDoneMsg{reports: reports}
	}
}

// runHostScan returns a BubbleTea command that performs LAN discovery
// in the background and sends the result as a hostScanDoneMsg.
func runHostScan(cidr string, isRoot bool) tea.Cmd {
	return func() tea.Msg {
		if err := scanner.ValidateCIDR(cidr); err != nil {
			return hostScanDoneMsg{err: err}
		}

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		hosts, err := scanner.DiscoverHosts(ctx, cidr, isRoot)
		if err != nil {
			return hostScanDoneMsg{err: err}
		}

		var reports []risk.HostReport
		for _, h := range hosts {
			reports = append(reports, risk.AnalyseHost(h))
		}
		return hostScanDoneMsg{reports: reports}
	}
}

// runPortScan returns a BubbleTea command that scans open ports on a host.
func runPortScan(ip string, isRoot bool) tea.Cmd {
	return func() tea.Msg {
		if err := scanner.ValidateIP(ip); err != nil {
			return portScanDoneMsg{ip: ip, err: err}
		}

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		ports, err := scanner.PortScan(ctx, ip, "1-1024", isRoot)
		if err != nil {
			return portScanDoneMsg{ip: ip, err: err}
		}
		return portScanDoneMsg{ip: ip, ports: ports}
	}
}

// runDeepScan returns a BubbleTea command that performs a full deep scan
// (all TCP ports + UDP high-value ports + -sV + -O + NSE safe scripts) on
// the target host and sends the result as a deepScanDoneMsg.
func runDeepScan(ip string, isRoot bool) tea.Cmd {
	return func() tea.Msg {
		if err := scanner.ValidateIP(ip); err != nil {
			return deepScanDoneMsg{err: err}
		}
		// 3-minute hard ceiling for the deep scan context.
		ctx, cancel := context.WithTimeout(context.Background(), 3*60*time.Second)
		defer cancel()

		result, err := scanner.DeepScan(ctx, ip, isRoot)
		if err != nil {
			return deepScanDoneMsg{err: err}
		}
		report := risk.AnalyseHostDeep(result.Host)
		return deepScanDoneMsg{result: result, report: report}
	}
}

// ─── View ─────────────────────────────────────────────────────────────────────

// View renders the current UI state as a string.
func (m Model) View() string {
	switch m.state {
	case viewConsent:
		return m.viewConsent()
	case viewMainMenu:
		return m.viewMainMenu()
	case viewWiFi:
		return m.viewWiFi()
	case viewHosts:
		return m.viewHosts()
	case viewHostDetail:
		return m.viewHostDetail()
	case viewDeepScan:
		return m.viewDeepScan()
	case viewHelp:
		return m.viewHelp()
	default:
		return "Unknown state"
	}
}

// ─── Consent screen ───────────────────────────────────────────────────────────

func (m Model) viewConsent() string {
	w := m.width
	if w <= 0 {
		w = 100
	}
	h := m.height
	if h <= 0 {
		h = 30
	}

	// ASCII logo with gradient-like colouring across lines.
	logoLines := strings.Split(strings.TrimPrefix(novaASCII, "\n"), "\n")
	logoColors := []lipgloss.Color{
		"#BD93F9", "#A97EF5", "#9569F1", "#7B68EE", "#6754EB", "#5340E7",
	}
	coloredLogo := make([]string, 0, len(logoLines))
	for i, l := range logoLines {
		cIdx := i
		if cIdx >= len(logoColors) {
			cIdx = len(logoColors) - 1
		}
		coloredLogo = append(coloredLogo,
			lipgloss.NewStyle().Foreground(logoColors[cIdx]).Bold(true).Render(l))
	}
	logo := strings.Join(coloredLogo, "\n")

	tagline := center(
		lipgloss.NewStyle().Foreground(colorAccent).Italic(true).
			Render("Network Observation & Vulnerability Analyzer"),
		w,
	)

	consentBody := strings.TrimSpace(`
⚠  LEGAL NOTICE

By continuing you confirm that:

  •  You OWN the network(s) you are about to scan, OR
  •  You have received EXPLICIT written permission from the owner.

Unauthorised scanning is ILLEGAL in most jurisdictions and may
result in criminal or civil liability.

This tool is for DEFENSIVE security assessment ONLY.
It must NEVER be used for exploitation or unauthorised reconnaissance.`)

	boxContent := styleBox.
		Width(min(w-8, 72)).
		BorderForeground(colorWarn).
		Render(consentBody)

	prompt := center(
		lipgloss.NewStyle().Foreground(colorAccent2).Bold(true).
			Render("Do you understand and accept these terms?"),
		w,
	)
	hint := center(
		styleHelp.Render("[y] Accept & continue    [n / q] Exit"),
		w,
	)

	body := lipgloss.JoinVertical(lipgloss.Center,
		center(logo, w),
		tagline,
		"",
		center(boxContent, w),
		"",
		prompt,
		hint,
	)

	// Vertically centre: count lines in body.
	bodyLines := strings.Count(body, "\n") + 1
	return vcenter(body, h, bodyLines)
}

// ─── Main menu ────────────────────────────────────────────────────────────────

// menuIcons maps each menu item index to a decorative icon.
var menuIcons = []string{"  ", "  ", "  ", "  "}

func (m Model) viewMainMenu() string {
	w := m.width
	if w <= 0 {
		w = 100
	}
	h := m.height
	if h <= 0 {
		h = 30
	}

	// Logo (compact single-line colour version for the menu header).
	logoLines := strings.Split(strings.TrimPrefix(novaASCII, "\n"), "\n")
	logoColors := []lipgloss.Color{
		"#BD93F9", "#A97EF5", "#9569F1", "#7B68EE", "#6754EB", "#5340E7",
	}
	coloredLogo := make([]string, 0, len(logoLines))
	for i, l := range logoLines {
		cIdx := i
		if cIdx >= len(logoColors) {
			cIdx = len(logoColors) - 1
		}
		coloredLogo = append(coloredLogo,
			lipgloss.NewStyle().Foreground(logoColors[cIdx]).Bold(true).Render(l))
	}
	logo := center(strings.Join(coloredLogo, "\n"), w)

	tagline := center(
		lipgloss.NewStyle().Foreground(colorAccent).Italic(true).
			Render("Network Observation & Vulnerability Analyzer"),
		w,
	)

	// Version badge.
	badge := center(
		lipgloss.NewStyle().
			Foreground(colorFaint).
			Render("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"),
		w,
	)

	// Menu items rendered as pill cards.
	menuWidth := 36
	var menuCards []string
	for i, item := range m.menuItems {
		icon := ""
		if i < len(menuIcons) {
			icon = menuIcons[i]
		}
		if i == m.menuCursor {
			inner := styleSelected.Render(" ▶ " + icon + item)
			card := styleMenuBoxSelected.
				Width(menuWidth).
				Render(inner)
			menuCards = append(menuCards, center(card, w))
		} else {
			inner := styleMuted.Render("   " + icon + item)
			card := styleMenuBox.
				Width(menuWidth).
				Render(inner)
			menuCards = append(menuCards, center(card, w))
		}
	}

	// Privilege notice.
	privNote := ""
	if m.isRoot {
		privNote = center(styleSuccess.Render("✔  Running as root — full scan capabilities enabled"), w)
	} else {
		privNote = center(styleWarn.Render("⚠  Running without root — some scan features limited"), w)
	}

	// Subnet info.
	subnetLine := center(
		styleMuted.Render("Subnet: ")+styleAccent.Render(m.hostCIDR),
		w,
	)

	hintLine := center(
		styleHelp.Render("↑ / k  ↓ / j   navigate    enter  select    q  quit"),
		w,
	)

	parts := make([]string, 0, 4+len(menuCards)+5)
	parts = append(parts, logo, tagline, badge, "")
	parts = append(parts, menuCards...)
	parts = append(parts, "", privNote, subnetLine, "", hintLine)

	body := strings.Join(parts, "\n")
	bodyLines := strings.Count(body, "\n") + 1
	return vcenter(body, h, bodyLines)
}

// ─── WiFi view ────────────────────────────────────────────────────────────────

// filterWiFiReports returns the WiFi reports that match current filters.
func (m Model) filterWiFiReports() []risk.NetworkReport {
	if m.wifiSearchQuery == "" && m.wifiFilterSec == "" {
		return m.wifiReports
	}

	var filtered []risk.NetworkReport
	query := strings.ToLower(m.wifiSearchQuery)

	for _, r := range m.wifiReports {
		// Security filter.
		if m.wifiFilterSec != "" {
			sec := strings.ToLower(r.Network.Security)
			switch m.wifiFilterSec {
			case "open":
				if !strings.Contains(sec, "open") && sec != "" && sec != "none" {
					continue
				}
			case "wpa2":
				if !strings.Contains(sec, "wpa2") {
					continue
				}
			case "wpa3":
				if !strings.Contains(sec, "wpa3") {
					continue
				}
			}
		}

		// Search query (matches SSID or BSSID).
		if query != "" {
			ssid := strings.ToLower(r.Network.SSID)
			bssid := strings.ToLower(r.Network.BSSID)
			if !strings.Contains(ssid, query) && !strings.Contains(bssid, query) {
				continue
			}
		}

		filtered = append(filtered, r)
	}

	return filtered
}

func (m Model) viewWiFi() string {
	w := m.width
	if w <= 0 {
		w = 100
	}

	headerTitle := styleTitle.Render("  WiFi Analysis ")
	header := center(headerTitle, w)

	var sb strings.Builder
	sb.WriteString(header + "\n")

	// Search/filter bar.
	if m.wifiSearchActive {
		// Search input mode.
		searchPrompt := styleAccent.Render("Search: ") + styleNormal.Render(m.wifiSearchQuery) + styleSelected.Render("█")
		sb.WriteString(center(searchPrompt, w) + "\n")
		sb.WriteString(center(styleFaint.Render("enter · apply    esc · cancel    ctrl+u · clear"), w) + "\n\n")
	} else {
		// Filter status line.
		var filterBadges []string
		if m.wifiSearchQuery != "" {
			filterBadges = append(filterBadges,
				styleAccent.Render("⌕")+styleMuted.Render(m.wifiSearchQuery))
		}
		if m.wifiFilterSec != "" {
			filterBadges = append(filterBadges,
				styleAccent2.Render("🛡 ")+styleMuted.Render(strings.ToUpper(m.wifiFilterSec)))
		}
		if len(filterBadges) > 0 {
			sb.WriteString(center(strings.Join(filterBadges, "  "), w) + "\n")
		}
		sb.WriteString("\n")
	}

	if m.wifiLoading {
		sb.WriteString(center(
			lipgloss.NewStyle().Foreground(colorAccent).Render(
				spinnerFrames[m.spinner]+"  Scanning for WiFi networks…",
			), w))
		sb.WriteString("\n\n" + center(styleHelp.Render("esc · back"), w))
		return sb.String()
	}

	if m.wifiError != "" {
		sb.WriteString(center(styleDanger.Render("✖  "+m.wifiError), w) + "\n")
		sb.WriteString("\n" + center(styleHelp.Render("r · retry    esc · back"), w))
		return sb.String()
	}

	filtered := m.filterWiFiReports()

	if len(m.wifiReports) == 0 {
		sb.WriteString(center(styleMuted.Render("No networks found — are you in range of a WiFi AP?"), w) + "\n")
		sb.WriteString("\n" + center(styleHelp.Render("r · rescan    esc · back"), w))
		return sb.String()
	}

	if len(filtered) == 0 {
		sb.WriteString(center(styleMuted.Render("No networks match current filters."), w) + "\n")
		sb.WriteString("\n" + center(styleHelp.Render("c · clear filters    r · rescan    esc · back"), w))
		return sb.String()
	}

	// Show count if filtered.
	if len(filtered) < len(m.wifiReports) {
		sb.WriteString(center(
			styleFaint.Render(fmt.Sprintf("Showing %d of %d networks", len(filtered), len(m.wifiReports))),
			w) + "\n")
	}

	// Column widths.
	const (
		wSSID  = 30
		wSec   = 10
		wSig   = 7
		wChan  = 6
		wFreq  = 10
		wScore = 9
	)

	headerRow := fmt.Sprintf("  %-*s  %-*s  %-*s  %-*s  %-*s  %s",
		wSSID, "SSID",
		wSec, "Security",
		wSig, "Signal",
		wChan, "Chan",
		wFreq, "Frequency",
		"Score",
	)
	divider := strings.Repeat("─", min(w-2, 92))
	sb.WriteString(styleMuted.Render(headerRow) + "\n")
	sb.WriteString(styleFaint.Render(divider) + "\n")

	maxVisible := m.height - 10
	if maxVisible < 1 {
		maxVisible = 10
	}
	start := 0
	if m.wifiCursor >= maxVisible {
		start = m.wifiCursor - maxVisible + 1
	}

	for i := start; i < len(filtered) && i < start+maxVisible; i++ {
		r := filtered[i]
		scoreColor := lipgloss.Color(risk.ScoreColor(r.Score))
		scoreStyle := lipgloss.NewStyle().Foreground(scoreColor).Bold(true)

		ssid := r.Network.SSID
		if ssid == "" {
			ssid = "‹hidden›"
		}

		rowText := fmt.Sprintf("%-*s  %-*s  %*d   %*d  %-*s  %s",
			wSSID, truncateRunes(ssid, wSSID),
			wSec, truncateRunes(r.Network.Security, wSec),
			wSig-1, r.Network.Signal,
			wChan-1, r.Network.Channel,
			wFreq, r.Network.Frequency,
			scoreStyle.Render(fmt.Sprintf("%3d/100", r.Score)),
		)

		if i == m.wifiCursor {
			sb.WriteString(styleSelected.Render("▶ "+rowText) + "\n")
			// Inline findings for selected row.
			for _, f := range r.Findings {
				fStyle := lipgloss.NewStyle().
					Foreground(lipgloss.Color(risk.LevelColor(f.Level)))
				sb.WriteString("   " + fStyle.Render("▸ "+f.Level.String()+": "+f.Title) + "\n")
				wrapped := wordWrap("     "+f.Description, min(w-6, 90))
				sb.WriteString(styleMuted.Render(wrapped) + "\n")
			}
		} else {
			sb.WriteString("  " + rowText + "\n")
		}
	}

	sb.WriteString("\n")
	if m.wifiSearchActive {
		sb.WriteString(center(
			styleHelp.Render("Type to search    enter · apply    esc · cancel"),
			w,
		))
	} else {
		sb.WriteString(center(
			styleHelp.Render("↑/k ↓/j  navigate    /  search    f  filter security    c  clear    r  rescan    esc · back"),
			w,
		))
	}
	return sb.String()
}

// ─── Host list view ───────────────────────────────────────────────────────────

func (m Model) viewHosts() string {
	w := m.width
	if w <= 0 {
		w = 100
	}

	// Detect the default gateway so we can badge it in the list.
	gatewayIP := scanner.DetectDefaultGatewayIP()

	header := center(styleTitle.Render("  LAN Host Discovery "), w)
	subLine := center(
		styleMuted.Render("Subnet  ")+styleAccent.Render(m.hostCIDR),
		w,
	)
	var gwLine string
	if gatewayIP != "" {
		gwLine = center(
			styleMuted.Render("Gateway ")+
				styleAccent2.Render("\U0001f4f6 "+gatewayIP+"  (your hotspot / router)"),
			w,
		)
	}

	var sb strings.Builder
	sb.WriteString(header + "\n")
	sb.WriteString(subLine + "\n")
	if gwLine != "" {
		sb.WriteString(gwLine + "\n")
	}
	sb.WriteString("\n")

	if m.hostLoading {
		sb.WriteString(center(
			lipgloss.NewStyle().Foreground(colorAccent).Render(
				spinnerFrames[m.spinner]+"  Discovering hosts on "+m.hostCIDR+"…",
			), w))
		sb.WriteString("\n\n" + center(styleHelp.Render("esc · back"), w))
		return sb.String()
	}

	if m.hostError != "" {
		sb.WriteString(center(styleDanger.Render("✖  "+m.hostError), w) + "\n")
		sb.WriteString("\n" + center(styleHelp.Render("r · retry    esc · back"), w))
		return sb.String()
	}

	if len(m.hostReports) == 0 {
		sb.WriteString(center(styleMuted.Render("No hosts found. Try a broader CIDR or check connectivity."), w) + "\n")
		sb.WriteString("\n" + center(styleHelp.Render("r · rescan    esc · back"), w))
		return sb.String()
	}

	// Table.
	const (
		wIP       = 16
		wVendor   = 22
		wHostname = 22
		wScore    = 9
	)
	headerRow := fmt.Sprintf("  %-*s  %-*s  %-*s  %s",
		wIP, "IP Address",
		wVendor, "Vendor",
		wHostname, "Hostname",
		"Score",
	)
	divider := strings.Repeat("─", min(w-2, 82))
	sb.WriteString(styleMuted.Render(headerRow) + "\n")
	sb.WriteString(styleFaint.Render(divider) + "\n")

	maxVisible := m.height - 10
	if maxVisible < 1 {
		maxVisible = 10
	}
	start := 0
	if m.hostCursor >= maxVisible {
		start = m.hostCursor - maxVisible + 1
	}

	for i := start; i < len(m.hostReports) && i < start+maxVisible; i++ {
		r := m.hostReports[i]
		scoreStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color(risk.ScoreColor(r.Score))).Bold(true)

		vendor := r.Host.Vendor
		if vendor == "" {
			vendor = "—"
		}
		hostname := r.Host.Hostname
		if hostname == "" {
			hostname = "—"
		}
		// Badge the gateway (hotspot / router) with a distinct icon.
		gatewayBadge := ""
		if r.Host.IP == gatewayIP {
			gatewayBadge = styleAccent2.Render(" 📡")
		}

		row := fmt.Sprintf("%-*s  %-*s  %-*s  %s",
			wIP, r.Host.IP,
			wVendor, truncateRunes(vendor, wVendor),
			wHostname, truncateRunes(hostname, wHostname),
			scoreStyle.Render(fmt.Sprintf("%3d/100", r.Score)),
		)

		if i == m.hostCursor {
			sb.WriteString(styleSelected.Render("▶ "+row) + gatewayBadge + "\n")
		} else {
			sb.WriteString("  " + row + gatewayBadge + "\n")
		}
	}

	// Scroll hint.
	if len(m.hostReports) > maxVisible {
		sb.WriteString(styleFaint.Render(
			fmt.Sprintf("  … %d more", len(m.hostReports)-maxVisible-start)) + "\n")
	}

	sb.WriteString("\n")
	sb.WriteString(center(
		styleHelp.Render("↑ / k  ↓ / j   navigate    enter  port scan    r  rescan    esc · back"),
		w,
	))
	return sb.String()
}

// ─── Host detail view ─────────────────────────────────────────────────────────

func (m Model) viewHostDetail() string {
	if m.selectedHost == nil {
		return "No host selected."
	}
	w := m.width
	if w <= 0 {
		w = 100
	}

	h := m.selectedHost
	var sb strings.Builder

	header := center(styleTitle.Render(fmt.Sprintf("  Host  %s ", h.Host.IP)), w)
	sb.WriteString(header + "\n\n")

	// Info panel.
	var infoLines []string
	if h.Host.Hostname != "" {
		infoLines = append(infoLines,
			styleMuted.Render("Hostname  ")+styleNormal.Render(h.Host.Hostname))
	}
	if h.Host.MAC != "" {
		vendor := h.Host.Vendor
		if vendor == "" {
			vendor = "Unknown vendor"
		}
		infoLines = append(infoLines,
			styleMuted.Render("MAC       ")+styleNormal.Render(h.Host.MAC+"  ("+vendor+")"))
	}
	if h.Host.OS != "" {
		infoLines = append(infoLines,
			styleMuted.Render("OS        ")+styleNormal.Render(h.Host.OS))
	}
	scoreColor := lipgloss.Color(risk.ScoreColor(h.Score))
	scoreStyle := lipgloss.NewStyle().Foreground(scoreColor).Bold(true)
	infoLines = append(infoLines,
		styleMuted.Render("Score     ")+
			scoreStyle.Render(fmt.Sprintf("%d/100  %s", h.Score, risk.ScoreLabel(h.Score))),
	)

	if len(infoLines) > 0 {
		infoBox := styleBox.
			BorderForeground(colorPrimary).
			Width(min(w-8, 66)).
			Render(strings.Join(infoLines, "\n"))
		sb.WriteString(center(infoBox, w) + "\n\n")
	}

	// Port scan section.
	sb.WriteString(center(styleAccent.Render("── Open Ports ──"), w) + "\n\n")

	if m.portLoading {
		sb.WriteString(center(
			lipgloss.NewStyle().Foreground(colorAccent).
				Render(spinnerFrames[m.spinner]+"  Scanning ports 1–1024…"),
			w) + "\n")
	} else if m.portError != "" {
		sb.WriteString(center(styleDanger.Render("✖  Port scan error: "+m.portError), w) + "\n")
	} else if len(h.Host.OpenPorts) == 0 {
		sb.WriteString(center(styleMuted.Render("No open ports found in range 1–1024"), w) + "\n")
	} else {
		headerRow := fmt.Sprintf("  %-8s  %-6s  %s", "Port", "Proto", "Service")
		divider := strings.Repeat("─", 40)
		sb.WriteString(center(styleMuted.Render(headerRow), w) + "\n")
		sb.WriteString(center(styleFaint.Render(divider), w) + "\n")
		for _, p := range h.Host.OpenPorts {
			label, danger := isDangerousPort(p.Number)
			svc := p.Service
			if svc == "" {
				svc = "—"
			}
			row := fmt.Sprintf("  %-8d  %-6s  %s", p.Number, p.Protocol, svc)
			if danger {
				row += "  " + styleDanger.Render("⚠ "+label)
				sb.WriteString(center(styleDanger.Render(row), w) + "\n")
			} else {
				sb.WriteString(center(styleNormal.Render(row), w) + "\n")
			}
		}
	}

	// Risk findings.
	if len(h.Findings) > 0 {
		sb.WriteString("\n")
		sb.WriteString(center(styleAccent2.Render("── Risk Findings ──"), w) + "\n\n")
		for _, f := range h.Findings {
			fColor := lipgloss.Color(risk.LevelColor(f.Level))
			fStyle := lipgloss.NewStyle().Foreground(fColor).Bold(true)
			titleLine := fStyle.Render("▸ [" + f.Level.String() + "] " + f.Title)
			descLine := styleMuted.Render("  " + f.Description)
			sb.WriteString(center(titleLine, w) + "\n")
			sb.WriteString(center(descLine, w) + "\n")
		}
	}

	sb.WriteString("\n")
	sb.WriteString(center(
		styleHelp.Render("d · deep scan (full ports + versions + scripts)    esc · back to host list"),
		w))
	return sb.String()
}

// ─── Deep scan view ───────────────────────────────────────────────────────────

func (m Model) viewDeepScan() string {
	w := m.width
	if w <= 0 {
		w = 100
	}

	// Determine the IP to show in the header.
	ip := ""
	if m.deepScanReport != nil {
		ip = m.deepScanReport.Host.IP
	} else if m.selectedHost != nil {
		ip = m.selectedHost.Host.IP
	}

	header := center(styleTitle.Render(fmt.Sprintf("  Deep Scan  %s ", ip)), w)

	var sb strings.Builder
	sb.WriteString(header + "\n\n")

	if m.deepScanLoading {
		eta := styleAccent.Render(spinnerFrames[m.spinner] + "  Deep scanning " + ip + " (all 65535 ports + NSE scripts)…")
		sb.WriteString(center(eta, w) + "\n")
		sb.WriteString(center(styleMuted.Render("This may take up to 3 minutes — scanning all ports, probing versions, running scripts…"), w) + "\n")
		if !m.isRoot {
			sb.WriteString(center(styleWarn.Render("⚠ Running without root: OS detection limited, UDP scan skipped"), w) + "\n")
		}
		sb.WriteString("\n" + center(styleHelp.Render("esc · cancel"), w))
		return sb.String()
	}

	if m.deepScanError != "" {
		sb.WriteString(center(styleDanger.Render("✖  Deep scan error: "+m.deepScanError), w) + "\n")
		sb.WriteString("\n" + center(styleHelp.Render("r · retry    esc · back"), w))
		return sb.String()
	}

	if m.deepScanReport == nil {
		sb.WriteString(center(styleMuted.Render("No results yet."), w) + "\n")
		return sb.String()
	}

	h := m.deepScanReport

	// ── Identity panel ──────────────────────────────────────────────────────
	var infoLines []string
	if h.Host.Hostname != "" {
		infoLines = append(infoLines, styleMuted.Render("Hostname   ")+styleNormal.Render(h.Host.Hostname))
	}
	if h.Host.MAC != "" {
		v := h.Host.Vendor
		if v == "" {
			v = "Unknown vendor"
		}
		infoLines = append(infoLines, styleMuted.Render("MAC        ")+styleNormal.Render(h.Host.MAC+"  ("+v+")"))
	}
	if h.Host.OS != "" {
		osTxt := h.Host.OS
		if h.Host.OSAccuracy > 0 {
			osTxt += fmt.Sprintf("  [%d%% confidence]", h.Host.OSAccuracy)
		}
		infoLines = append(infoLines, styleMuted.Render("OS         ")+styleNormal.Render(osTxt))
	}
	if h.Host.DeviceType != "" {
		infoLines = append(infoLines, styleMuted.Render("Device     ")+styleAccent.Render(h.Host.DeviceType))
	}
	scoreColor := lipgloss.Color(risk.ScoreColor(h.Score))
	scoreStyle := lipgloss.NewStyle().Foreground(scoreColor).Bold(true)
	infoLines = append(infoLines,
		styleMuted.Render("Risk Score ")+
			scoreStyle.Render(fmt.Sprintf("%d/100  %s", h.Score, risk.ScoreLabel(h.Score))),
	)

	if len(infoLines) > 0 {
		infoBox := styleBox.
			BorderForeground(colorPrimary).
			Width(min(w-8, 72)).
			Render(strings.Join(infoLines, "\n"))
		sb.WriteString(center(infoBox, w) + "\n\n")
	}

	// ── Port / Service table ─────────────────────────────────────────────────
	portCount := len(h.Host.OpenPorts)
	title := fmt.Sprintf("── %d Open Ports (full scan) ──", portCount)
	sb.WriteString(center(styleAccent.Render(title), w) + "\n\n")

	const (
		wPort  = 7
		wProto = 5
		wSvc   = 14
		wProd  = 22
		wVer   = 12
	)

	if portCount == 0 {
		sb.WriteString(center(styleMuted.Render("No open ports found in full scan (host may be firewalled)"), w) + "\n")
	} else {
		hRow := fmt.Sprintf("  %-*s  %-*s  %-*s  %-*s  %s",
			wPort, "Port",
			wProto, "Proto",
			wSvc, "Service",
			wProd, "Product",
			"Version",
		)
		div := strings.Repeat("─", min(w-4, 80))
		sb.WriteString(center(styleMuted.Render(hRow), w) + "\n")
		sb.WriteString(center(styleFaint.Render(div), w) + "\n")

		// Apply scroll.
		visible := m.height - 20
		if visible < 5 {
			visible = 5
		}
		start := m.deepScanScrollY
		if start >= portCount {
			start = portCount - 1
		}
		if start < 0 {
			start = 0
		}

		for i := start; i < portCount && i < start+visible; i++ {
			p := h.Host.OpenPorts[i]
			_, isDanger := isDangerousPort(p.Number)

			svc := p.Service
			if svc == "" {
				svc = "—"
			}
			prod := p.Product
			if prod == "" {
				prod = "—"
			}
			ver := p.Version
			if ver == "" {
				ver = "—"
			}

			row := fmt.Sprintf("  %-*d  %-*s  %-*s  %-*s  %s",
				wPort, p.Number,
				wProto, p.Protocol,
				wSvc, truncateRunes(svc, wSvc),
				wProd, truncateRunes(prod, wProd),
				ver,
			)
			if isDanger {
				sb.WriteString(center(styleDanger.Render(row+"  ⚠"), w) + "\n")
			} else {
				sb.WriteString(center(styleNormal.Render(row), w) + "\n")
			}

			// NSE script output — show first 2 scripts per port inline.
			for si, s := range p.Scripts {
				if si >= 2 {
					break
				}
				out := truncateRunes(s.Output, 80)
				sb.WriteString(center(
					styleFaint.Render(fmt.Sprintf("    [%s] %s", s.ID, out)),
					w) + "\n")
			}
		}

		if portCount > visible {
			sb.WriteString(center(
				styleFaint.Render(fmt.Sprintf("  … %d more  (↓/j to scroll)", portCount-start-visible)),
				w) + "\n")
		}
	}

	// ── Risk findings ────────────────────────────────────────────────────────
	if len(h.Findings) > 0 {
		sb.WriteString("\n")
		sb.WriteString(center(styleAccent2.Render("── Risk Findings ──"), w) + "\n\n")
		for _, f := range h.Findings {
			fColor := lipgloss.Color(risk.LevelColor(f.Level))
			fStyle := lipgloss.NewStyle().Foreground(fColor).Bold(true)
			titleLine := fStyle.Render("▸ [" + f.Level.String() + "] " + f.Title)
			descLine := styleMuted.Render("  " + f.Description)
			sb.WriteString(center(titleLine, w) + "\n")
			sb.WriteString(center(descLine, w) + "\n")
		}
	}

	sb.WriteString("\n")
	sb.WriteString(center(
		styleHelp.Render("↑/k ↓/j  scroll ports    r  re-scan    esc · back"),
		w,
	))
	return sb.String()
}

// ─── Help view ────────────────────────────────────────────────────────────────

func (m Model) viewHelp() string {
	w := m.width
	if w <= 0 {
		w = 100
	}
	h := m.height
	if h <= 0 {
		h = 30
	}

	header := center(styleTitle.Render("  Key Bindings "), w)

	bindings := [][2]string{
		{"↑  /  k", "Move selection up / scroll"},
		{"↓  /  j", "Move selection down / scroll"},
		{"enter  /  space", "Select / activate"},
		{"d", "Deep scan selected host (host detail view)"},
		{"r", "Re-run current scan"},
		{"esc  /  q", "Back / exit current view"},
		{"ctrl + c", "Quit NOVA immediately"},
	}

	rows := make([]string, 0, len(bindings))
	for _, b := range bindings {
		keyPart := lipgloss.NewStyle().Foreground(colorAccent).Bold(true).
			Render(fmt.Sprintf("  %-22s", b[0]))
		descPart := styleNormal.Render(b[1])
		rows = append(rows, keyPart+styleFaint.Render(" │  ")+descPart)
	}

	table := styleBox.
		BorderForeground(colorPrimary).
		Width(min(w-8, 60)).
		Render(strings.Join(rows, "\n"))

	body := lipgloss.JoinVertical(lipgloss.Center,
		header,
		"",
		center(table, w),
		"",
		center(styleHelp.Render("esc · back to main menu"), w),
	)

	bodyLines := strings.Count(body, "\n") + 1
	return vcenter(body, h, bodyLines)
}

// ─── Run ──────────────────────────────────────────────────────────────────────

// Run starts the BubbleTea program. It blocks until the user quits.
func Run(isRoot bool, hostCIDR string) error {
	m := NewModel(isRoot, hostCIDR)
	p := tea.NewProgram(m, tea.WithAltScreen(), tea.WithMouseCellMotion())
	_, err := p.Run()
	return err
}

// CheckPrivilege returns true if the process is running as root (UID 0).
func CheckPrivilege() bool {
	return os.Getuid() == 0
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func truncateRunes(s string, max int) string {
	runes := []rune(s)
	if len(runes) <= max {
		return s + strings.Repeat(" ", max-len(runes))
	}
	return string(runes[:max-1]) + "…"
}

// wordWrap wraps s at w characters per line while preserving leading indent.
func wordWrap(s string, w int) string {
	if w <= 0 {
		return s
	}
	words := strings.Fields(s)
	if len(words) == 0 {
		return s
	}
	// Extract leading whitespace from original string.
	indent := ""
	for _, r := range s {
		if r == ' ' || r == '\t' {
			indent += string(r)
		} else {
			break
		}
	}

	var lines []string
	current := indent
	for _, word := range words {
		if current == indent {
			current += word
		} else if len(current)+1+len(word) > w {
			lines = append(lines, current)
			current = indent + word
		} else {
			current += " " + word
		}
	}
	if current != indent {
		lines = append(lines, current)
	}
	return strings.Join(lines, "\n")
}

// isDangerousPort returns a label and true if the port is in the danger list.
func isDangerousPort(port int) (string, bool) {
	dangerPorts := map[int]string{
		21: "FTP", 23: "Telnet", 445: "SMB", 3389: "RDP",
		1900: "UPnP", 4444: "Backdoor?", 6379: "Redis", 27017: "MongoDB",
	}
	label, ok := dangerPorts[port]
	return label, ok
}
