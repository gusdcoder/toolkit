package scan

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"toolkit/internal/database"
	"toolkit/internal/integrations"
)

// UI States
type viewState int

const (
	targetSelectionView viewState = iota
	scanProgressView
	resultsView
)

// Styles inspired by Claude UI and Gemini CLI
var (
	// Colors
	primaryColor   = lipgloss.Color("#2563eb") // Blue
	secondaryColor = lipgloss.Color("#64748b") // Slate
	successColor   = lipgloss.Color("#10b981") // Green
	warningColor   = lipgloss.Color("#f59e0b") // Amber
	errorColor     = lipgloss.Color("#ef4444") // Red
	accentColor    = lipgloss.Color("#8b5cf6") // Purple

	// Base styles
	baseStyle = lipgloss.NewStyle().
			Padding(1, 2).
			Border(lipgloss.RoundedBorder()).
			BorderForeground(secondaryColor)

	// Header styles
	headerStyle = lipgloss.NewStyle().
			Foreground(primaryColor).
			Bold(true).
			MarginBottom(1)

	// Title style (Claude-inspired)
	titleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#ffffff")).
			Background(primaryColor).
			Padding(0, 2).
			Bold(true).
			MarginBottom(1)

	// Input styles
	focusedInputStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(primaryColor).
				Padding(0, 1)

	blurredInputStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(secondaryColor).
				Padding(0, 1)

	// Button styles (Gemini CLI inspired)
	activeButtonStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#ffffff")).
				Background(primaryColor).
				Padding(0, 2).
				Bold(true)

	inactiveButtonStyle = lipgloss.NewStyle().
				Foreground(secondaryColor).
				Border(lipgloss.RoundedBorder()).
				BorderForeground(secondaryColor).
				Padding(0, 2)

	// Status styles
	successStyle = lipgloss.NewStyle().Foreground(successColor).Bold(true)
	warningStyle = lipgloss.NewStyle().Foreground(warningColor).Bold(true)
	errorStyle   = lipgloss.NewStyle().Foreground(errorColor).Bold(true)

	// Progress bar style
	progressStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(primaryColor).
			Padding(0, 1)
)

// Scan results data structures
type ScanResult struct {
	Type      string
	Target    string
	Status    string
	Details   string
	Timestamp time.Time
	Severity  string
}

type ScanPhase struct {
	Name      string
	Status    string
	Progress  float64
	StartTime time.Time
	Duration  time.Duration
	Results   []ScanResult
}

type model struct {
	state  viewState
	width  int
	height int

	// Target selection
	targetInput   textinput.Model
	scanTypeIndex int
	scanTypes     []string

	// Scan progress
	spinner      spinner.Model
	progress     progress.Model
	currentPhase int
	phases       []ScanPhase

	// Results
	results        []ScanResult
	selectedResult int

	// Real scanning components
	database    *database.DatabaseWrapper
	toolManager *integrations.ToolManager
	scanCtx     context.Context
	scanCancel  context.CancelFunc

	// UI state
	focused  int
	showHelp bool
	scanning bool
}

// Messages
type tickMsg time.Time
type scanCompleteMsg struct{}
type phaseCompleteMsg int
type toolProgressMsg struct {
	phase   string
	tool    string
	status  string
	results int
}
type toolResultMsg struct {
	phase   string
	tool    string
	success bool
	results int
	error   error
}
type scanStartMsg struct {
	target string
}
type phaseStartMsg struct {
	phase string
	tool  string
}

func initialModel() model {
	return initialModelWithComponents(nil, nil)
}

func initialModelWithComponents(db *database.DatabaseWrapper, toolManager *integrations.ToolManager) model {
	// Initialize text input
	ti := textinput.New()
	ti.Placeholder = "Enter target domain or IP (e.g., example.com, 192.168.1.1/24)"
	ti.Focus()
	ti.CharLimit = 100
	ti.Width = 50

	// Initialize spinner
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(primaryColor)

	// Initialize progress bar
	p := progress.New(progress.WithDefaultGradient())
	p.Width = 50

	// Initialize scan phases - now mapped to real tools
	phases := []ScanPhase{
		{Name: "🔍 Host Discovery", Status: "pending", Progress: 0.0},
		{Name: "🌐 Subdomain Enumeration (Subfinder)", Status: "pending", Progress: 0.0},
		{Name: "🔓 Port Scanning (Naabu)", Status: "pending", Progress: 0.0},
		{Name: "🔎 Service Detection (HTTPX)", Status: "pending", Progress: 0.0},
		{Name: "🛡️ Vulnerability Assessment (Nuclei)", Status: "pending", Progress: 0.0},
		{Name: "📊 Results Analysis", Status: "pending", Progress: 0.0},
	}

	return model{
		state:         targetSelectionView,
		targetInput:   ti,
		scanTypeIndex: 0,
		scanTypes:     []string{"🎯 Basic Scan", "🔍 Comprehensive Scan", "⚡ Quick Scan", "🎭 Stealth Scan"},
		spinner:       s,
		progress:      p,
		phases:        phases,
		results:       []ScanResult{},
		database:      db,
		toolManager:   toolManager,
		focused:       0,
		showHelp:      false,
		scanning:      false,
	}
}

func (m model) Init() tea.Cmd {
	return tea.Batch(
		textinput.Blink,
		m.spinner.Tick,
		tickCmd(),
	)
}

func tickCmd() tea.Cmd {
	return tea.Tick(time.Millisecond*100, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tea.KeyMsg:
		switch m.state {
		case targetSelectionView:
			return m.updateTargetSelection(msg)
		case scanProgressView:
			return m.updateScanProgress(msg)
		case resultsView:
			return m.updateResults(msg)
		}

	case tickMsg:
		// Handle real scanning progress
		return m, tickCmd()

	case scanStartMsg:
		return m.startScanning(msg.target)

	case phaseStartMsg:
		m.phases[m.currentPhase].Status = "running"
		m.phases[m.currentPhase].StartTime = time.Now()
		return m, nil

	case toolProgressMsg:
		// Update current phase progress
		if m.currentPhase < len(m.phases) {
			m.phases[m.currentPhase].Progress = 0.5 // Intermediate progress
		}
		return m, nil

	case toolResultMsg:
		return m.handleToolResult(msg)

	case scanCompleteMsg:
		m.state = resultsView
		m.scanning = false
		return m, nil

	case spinner.TickMsg:
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}

	// Update input field
	if m.state == targetSelectionView {
		m.targetInput, cmd = m.targetInput.Update(msg)
		cmds = append(cmds, cmd)
	}

	return m, tea.Batch(cmds...)
}

func (m model) updateTargetSelection(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "tab":
		m.focused = (m.focused + 1) % 2
		if m.focused == 0 {
			m.targetInput.Focus()
		} else {
			m.targetInput.Blur()
		}
	case "up", "k":
		if m.focused == 1 {
			m.scanTypeIndex = (m.scanTypeIndex - 1 + len(m.scanTypes)) % len(m.scanTypes)
		}
	case "down", "j":
		if m.focused == 1 {
			m.scanTypeIndex = (m.scanTypeIndex + 1) % len(m.scanTypes)
		}
	case "enter":
		if m.targetInput.Value() != "" {
			m.state = scanProgressView
			target := m.targetInput.Value()
			return m, func() tea.Msg { return scanStartMsg{target: target} }
		}
	case "?":
		m.showHelp = !m.showHelp
	}

	var cmd tea.Cmd
	m.targetInput, cmd = m.targetInput.Update(msg)
	return m, cmd
}

func (m model) updateScanProgress(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "s":
		// Skip to results
		m.state = resultsView
		return m, nil
	}
	return m, nil
}

func (m model) updateResults(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "r":
		// Reset to target selection while preserving real components
		newModel := initialModelWithComponents(m.database, m.toolManager)
		newModel.width = m.width
		newModel.height = m.height
		return newModel, newModel.Init()
	case "up", "k":
		if m.selectedResult > 0 {
			m.selectedResult--
		}
	case "down", "j":
		if m.selectedResult < len(m.results)-1 {
			m.selectedResult++
		}
	}
	return m, nil
}

// startScanning initiates real scanning with proper tool integration
func (m model) startScanning(target string) (tea.Model, tea.Cmd) {
	if m.toolManager == nil {
		// Fallback: no real tools available
		m.addErrorResult("No tool manager available", "System error")
		m.state = resultsView
		return m, nil
	}

	// Initialize context for scanning
	m.scanCtx, m.scanCancel = context.WithCancel(context.Background())
	m.scanning = true
	m.currentPhase = 0
	m.phases[0].Status = "running"
	m.phases[0].StartTime = time.Now()

	// Start the scanning pipeline
	return m, tea.Batch(
		func() tea.Msg { return phaseStartMsg{phase: "discovery", tool: "ping"} },
		m.runDiscoveryPhase(target),
	)
}

// handleToolResult processes results from real tools
func (m model) handleToolResult(msg toolResultMsg) (tea.Model, tea.Cmd) {
	// Mark current phase as complete
	if m.currentPhase < len(m.phases) {
		m.phases[m.currentPhase].Progress = 1.0
		m.phases[m.currentPhase].Status = "complete"
		m.phases[m.currentPhase].Duration = time.Since(m.phases[m.currentPhase].StartTime)

		// Add results to display
		if msg.success {
			m.addToolResult(msg.tool, msg.results, "success")
		} else {
			m.addErrorResult(fmt.Sprintf("%s failed: %v", msg.tool, msg.error), "error")
		}

		// Move to next phase
		m.currentPhase++
		if m.currentPhase >= len(m.phases) {
			return m, func() tea.Msg { return scanCompleteMsg{} }
		}

		// Start next phase
		m.phases[m.currentPhase].Status = "running"
		m.phases[m.currentPhase].StartTime = time.Now()

		return m, m.runNextPhase()
	}

	return m, nil
}

// runDiscoveryPhase starts the discovery phase
func (m model) runDiscoveryPhase(target string) tea.Cmd {
	return func() tea.Msg {
		// Simple ping-like discovery
		time.Sleep(1 * time.Second) // Simulate discovery time
		return toolResultMsg{
			phase:   "discovery",
			tool:    "discovery",
			success: true,
			results: 1,
		}
	}
}

// runNextPhase determines and runs the next scanning phase
func (m model) runNextPhase() tea.Cmd {
	if m.currentPhase >= len(m.phases) {
		return func() tea.Msg { return scanCompleteMsg{} }
	}

	target := m.targetInput.Value()

	switch m.currentPhase {
	case 1: // Subdomain enumeration
		return m.runSubfinderPhase(target)
	case 2: // Port scanning
		return m.runNaabuPhase(target)
	case 3: // Service detection
		return m.runHTTPXPhase(target)
	case 4: // Vulnerability scanning
		return m.runNucleiPhase(target)
	case 5: // Analysis
		return m.runAnalysisPhase()
	default:
		return func() tea.Msg { return scanCompleteMsg{} }
	}
}

// Tool-specific phase functions
func (m model) runSubfinderPhase(target string) tea.Cmd {
	if m.toolManager == nil {
		return func() tea.Msg {
			return toolResultMsg{phase: "subfinder", tool: "subfinder", success: false, error: fmt.Errorf("tool manager not available")}
		}
	}

	return func() tea.Msg {
		result, err := m.toolManager.RunTool(m.scanCtx, "subfinder", map[string]interface{}{"target": target})
		resultCount := 0
		success := err == nil
		if result != nil {
			if subfinderResult, ok := result.(map[string]interface{}); ok {
				if domains, ok := subfinderResult["Domains"].([]string); ok {
					resultCount = len(domains)
				} else if domains, ok := subfinderResult["domains"].([]string); ok {
					resultCount = len(domains)
				}
			}
		}
		return toolResultMsg{
			phase:   "subfinder",
			tool:    "subfinder",
			success: success,
			results: resultCount,
			error:   err,
		}
	}
}

func (m model) runNaabuPhase(target string) tea.Cmd {
	if m.toolManager == nil {
		return func() tea.Msg {
			return toolResultMsg{phase: "naabu", tool: "naabu", success: false, error: fmt.Errorf("tool manager not available")}
		}
	}

	return func() tea.Msg {
		result, err := m.toolManager.RunTool(m.scanCtx, "naabu", map[string]interface{}{"target": target})
		resultCount := 0
		success := err == nil
		if result != nil {
			if naabuResult, ok := result.(map[string]interface{}); ok {
				if ports, ok := naabuResult["Ports"].([]int); ok {
					resultCount = len(ports)
				} else if ports, ok := naabuResult["ports"].([]int); ok {
					resultCount = len(ports)
				}
			}
		}
		return toolResultMsg{
			phase:   "naabu",
			tool:    "naabu",
			success: success,
			results: resultCount,
			error:   err,
		}
	}
}

func (m model) runHTTPXPhase(target string) tea.Cmd {
	if m.toolManager == nil {
		return func() tea.Msg {
			return toolResultMsg{phase: "httpx", tool: "httpx", success: false, error: fmt.Errorf("tool manager not available")}
		}
	}

	return func() tea.Msg {
		result, err := m.toolManager.RunTool(m.scanCtx, "httpx", map[string]interface{}{"target": target})
		resultCount := 0
		success := err == nil
		if result != nil {
			if httpxResult, ok := result.(map[string]interface{}); ok {
				if services, ok := httpxResult["Services"].([]string); ok {
					resultCount = len(services)
				} else if services, ok := httpxResult["services"].([]string); ok {
					resultCount = len(services)
				}
			}
		}
		return toolResultMsg{
			phase:   "httpx",
			tool:    "httpx",
			success: success,
			results: resultCount,
			error:   err,
		}
	}
}

func (m model) runNucleiPhase(target string) tea.Cmd {
	if m.toolManager == nil {
		return func() tea.Msg {
			return toolResultMsg{phase: "nuclei", tool: "nuclei", success: false, error: fmt.Errorf("tool manager not available")}
		}
	}

	return func() tea.Msg {
		result, err := m.toolManager.RunTool(m.scanCtx, "nuclei", map[string]interface{}{"target": target})
		resultCount := 0
		success := err == nil
		if result != nil {
			if nucleiResult, ok := result.(map[string]interface{}); ok {
				if vulns, ok := nucleiResult["Vulns"].([]string); ok {
					resultCount = len(vulns)
				} else if vulns, ok := nucleiResult["vulns"].([]string); ok {
					resultCount = len(vulns)
				}
			}
		}
		return toolResultMsg{
			phase:   "nuclei",
			tool:    "nuclei",
			success: success,
			results: resultCount,
			error:   err,
		}
	}
}

func (m model) runAnalysisPhase() tea.Cmd {
	return func() tea.Msg {
		time.Sleep(500 * time.Millisecond) // Simulate analysis time
		return toolResultMsg{
			phase:   "analysis",
			tool:    "analysis",
			success: true,
			results: len(m.results),
		}
	}
}

// Helper functions for adding results
func (m *model) addToolResult(tool string, count int, severity string) {
	result := ScanResult{
		Type:      "Tool Result",
		Target:    tool,
		Status:    "Complete",
		Details:   fmt.Sprintf("Found %d results", count),
		Timestamp: time.Now(),
		Severity:  severity,
	}
	m.results = append(m.results, result)
}

func (m *model) addErrorResult(message, severity string) {
	result := ScanResult{
		Type:      "Error",
		Target:    "System",
		Status:    "Failed",
		Details:   message,
		Timestamp: time.Now(),
		Severity:  severity,
	}
	m.results = append(m.results, result)
}

func (m model) View() string {
	switch m.state {
	case targetSelectionView:
		return m.renderTargetSelection()
	case scanProgressView:
		return m.renderScanProgress()
	case resultsView:
		return m.renderResults()
	default:
		return "Unknown state"
	}
}

func (m model) renderTargetSelection() string {
	var b strings.Builder

	// Title
	title := titleStyle.Render("🎯 Recon Platform - Interactive Scanner")
	b.WriteString(title + "\n\n")

	// Description with better formatting
	desc := lipgloss.NewStyle().
		Foreground(secondaryColor).
		Width(80).
		Align(lipgloss.Center).
		Render("Enterprise-grade reconnaissance platform with intelligent scanning capabilities")
	b.WriteString(desc + "\n\n")

	// Target input section
	inputLabel := headerStyle.Render("🎯 Target Selection")
	b.WriteString(inputLabel + "\n")

	var inputStyle lipgloss.Style
	if m.focused == 0 {
		inputStyle = focusedInputStyle.Copy().
			BorderForeground(primaryColor).
			Foreground(lipgloss.Color("#ffffff"))
	} else {
		inputStyle = blurredInputStyle
	}

	input := inputStyle.Width(60).Render(m.targetInput.View())
	b.WriteString(input + "\n\n")

	// Scan type selection with better visual hierarchy
	typeLabel := headerStyle.Render("⚙️ Scan Configuration")
	b.WriteString(typeLabel + "\n")

	for i, scanType := range m.scanTypes {
		var style lipgloss.Style
		var prefix string

		if i == m.scanTypeIndex && m.focused == 1 {
			style = activeButtonStyle.Copy().
				BorderForeground(primaryColor).
				BorderStyle(lipgloss.ThickBorder())
			prefix = "▶ "
		} else {
			style = inactiveButtonStyle
			prefix = "  "
		}

		button := style.Width(25).Render(scanType)
		b.WriteString(prefix + button + "\n")
	}

	b.WriteString("\n")

	// Status indicator
	if m.targetInput.Value() != "" {
		status := successStyle.Render("✓ Ready to scan: " + m.targetInput.Value())
		b.WriteString(status + "\n\n")
	} else {
		status := warningStyle.Render("⚠ Please enter a target to scan")
		b.WriteString(status + "\n\n")
	}

	// Controls with better formatting
	controls := lipgloss.NewStyle().
		Foreground(secondaryColor).
		Border(lipgloss.NormalBorder()).
		BorderForeground(secondaryColor).
		Padding(0, 1).
		Render("💡 Controls: [Tab] Switch focus • [↑↓] Navigate • [Enter] Start scan • [?] Help • [Q] Quit")
	b.WriteString(controls)

	if m.showHelp {
		b.WriteString("\n\n")
		help := baseStyle.Copy().
			BorderForeground(accentColor).
			BorderStyle(lipgloss.DoubleBorder()).
			Width(min(80, m.width-4)).
			Render(m.renderHelp())
		b.WriteString(help)
	}

	// Adjust width based on terminal size
	content := b.String()
	if m.width > 0 {
		return baseStyle.Copy().
			Width(min(90, m.width-2)).
			Align(lipgloss.Center).
			Render(content)
	}
	return baseStyle.Render(content)
}

// Helper function for min
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (m model) renderScanProgress() string {
	var b strings.Builder

	// Title with spinner
	title := titleStyle.Render("🔄 Scanning in Progress...")
	b.WriteString(title + "\n\n")

	// Target info
	targetInfo := fmt.Sprintf("Target: %s | Scan Type: %s",
		successStyle.Render(m.targetInput.Value()),
		successStyle.Render(m.scanTypes[m.scanTypeIndex]))
	b.WriteString(targetInfo + "\n\n")

	// Phase progress
	for i, phase := range m.phases {
		var status string
		var statusStyle lipgloss.Style

		switch phase.Status {
		case "complete":
			status = "✓"
			statusStyle = successStyle
		case "running":
			status = m.spinner.View()
			statusStyle = warningStyle
		default:
			status = "⏳"
			statusStyle = lipgloss.NewStyle().Foreground(secondaryColor)
		}

		phaseLine := fmt.Sprintf("%s %s", status, phase.Name)
		if phase.Status == "running" || phase.Status == "complete" {
			progressBar := progressStyle.Render(m.progress.ViewAs(phase.Progress))
			phaseLine += "\n  " + progressBar
		}

		b.WriteString(statusStyle.Render(phaseLine) + "\n")
		if i < len(m.phases)-1 {
			b.WriteString("\n")
		}
	}

	b.WriteString("\n\n")

	// Live results counter
	resultsCount := fmt.Sprintf("📊 Live Results: %d findings", len(m.results))
	b.WriteString(successStyle.Render(resultsCount) + "\n\n")

	// Controls
	controls := lipgloss.NewStyle().
		Foreground(secondaryColor).
		Render("Controls: [S] Skip to results • [Q] Quit")
	b.WriteString(controls)

	return baseStyle.Render(b.String())
}

func (m model) renderResults() string {
	var b strings.Builder

	// Title
	title := titleStyle.Render("📊 Scan Results")
	b.WriteString(title + "\n\n")

	// Summary
	summary := fmt.Sprintf("Target: %s | Total Findings: %d",
		successStyle.Render(m.targetInput.Value()),
		successStyle.Render(fmt.Sprintf("%d", len(m.results))))
	b.WriteString(summary + "\n\n")

	// Results list
	if len(m.results) == 0 {
		noResults := warningStyle.Render("No results found")
		b.WriteString(noResults + "\n")
	} else {
		for i, result := range m.results {
			var resultStyle lipgloss.Style
			var severityIcon string

			switch result.Severity {
			case "high":
				severityIcon = "🔴"
				resultStyle = errorStyle
			case "medium":
				severityIcon = "🟡"
				resultStyle = warningStyle
			default:
				severityIcon = "🔵"
				resultStyle = successStyle
			}

			prefix := "  "
			if i == m.selectedResult {
				prefix = "▶ "
				resultStyle = resultStyle.Underline(true)
			}

			resultLine := fmt.Sprintf("%s%s %s: %s - %s",
				prefix, severityIcon, result.Type, result.Target, result.Details)

			b.WriteString(resultStyle.Render(resultLine) + "\n")
		}
	}

	b.WriteString("\n")

	// Controls
	controls := lipgloss.NewStyle().
		Foreground(secondaryColor).
		Render("Controls: [↑↓] Navigate results • [R] New scan • [Q] Quit")
	b.WriteString(controls)

	return baseStyle.Render(b.String())
}

func (m model) renderHelp() string {
	help := `🎯 Recon Platform Help

SCAN TYPES:
• Basic Scan: Standard reconnaissance with common tools
• Comprehensive Scan: Full arsenal with all available tools  
• Quick Scan: Fast discovery for immediate results
• Stealth Scan: Low-profile scanning to avoid detection

FEATURES:
• Real-time progress tracking
• Intelligent tool selection
• Persistent results database
• Advanced correlation engine
• Multiple output formats

KEYBOARD SHORTCUTS:
• Tab: Switch between input fields
• ↑↓: Navigate options/results
• Enter: Confirm selection/start scan
• Q: Quit application
• ?: Toggle this help screen`

	return help
}

func Start() error {
	return StartWithComponents(nil, nil)
}

func StartWithComponents(db *database.DatabaseWrapper, toolManager *integrations.ToolManager) error {
	// Initialize database and tool manager if not provided
	if db == nil {
		config := &database.Config{
			Type:    "memory",
			DataDir: getDataDir(),
		}
		var err error
		db, err = database.NewDatabase(config)
		if err != nil {
			return fmt.Errorf("failed to initialize database: %w", err)
		}
	}

	if toolManager == nil {
		toolManager = integrations.NewToolManagerWithDB(db, false)
	}

	m := initialModelWithComponents(db, toolManager)
	p := tea.NewProgram(m, tea.WithAltScreen())

	if _, err := p.Run(); err != nil {
		return fmt.Errorf("could not start interactive scan UI: %w", err)
	}
	return nil
}

// getDataDir returns the default data directory path
func getDataDir() string {
	home, _ := os.UserHomeDir()
	return fmt.Sprintf("%s/.recon-platform", home)
}
