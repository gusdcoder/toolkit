package nuclei

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/recon-platform/core/internal/database"
	"github.com/recon-platform/core/pkg/models"
)

// NucleiIntegration provides interface to Nuclei vulnerability scanner
type NucleiIntegration struct {
	db      *database.DatabaseWrapper
	timeout time.Duration
	verbose bool
}

// NucleiResult represents a single vulnerability finding
type NucleiResult struct {
	TemplateID   string            `json:"template-id"`
	TemplatePath string            `json:"template-path"`
	Info         NucleiInfo        `json:"info"`
	Type         string            `json:"type"`
	Host         string            `json:"host"`
	Port         string            `json:"port"`
	Scheme       string            `json:"scheme"`
	URL          string            `json:"url"`
	MatchedAt    string            `json:"matched-at"`
	ExtractedResults []string      `json:"extracted-results,omitempty"`
	Request      string            `json:"request,omitempty"`
	Response     string            `json:"response,omitempty"`
	IP           string            `json:"ip,omitempty"`
	Timestamp    time.Time         `json:"timestamp"`
	CURLCommand  string            `json:"curl-command,omitempty"`
}

// NucleiInfo contains template metadata
type NucleiInfo struct {
	Name           string            `json:"name"`
	Author         []string          `json:"author"`
	Tags           []string          `json:"tags"`
	Description    string            `json:"description"`
	Reference      []string          `json:"reference,omitempty"`
	Severity       string            `json:"severity"`
	Classification NucleiClassification `json:"classification,omitempty"`
}

// NucleiClassification contains vulnerability classification info
type NucleiClassification struct {
	CVEID         []string `json:"cve-id,omitempty"`
	CWEID         []string `json:"cwe-id,omitempty"`
	CVSSMetrics   string   `json:"cvss-metrics,omitempty"`
	CVSSScore     float64  `json:"cvss-score,omitempty"`
	EPSSScore     float64  `json:"epss-score,omitempty"`
	EPSSPercentile float64 `json:"epss-percentile,omitempty"`
}

// NucleiConfig holds configuration for Nuclei scans
type NucleiConfig struct {
	Templates            []string
	Tags                 []string
	ExcludeTags          []string
	Severity             []string
	Threads              int
	RateLimit            int
	Timeout              int
	Retries              int
	BulkSize             int
	TemplateTimeout      int
	NoInteractsh         bool
	DisableUpdateCheck   bool
	FollowRedirects      bool
	MaxRedirects         int
	UserAgent            string
	CustomHeaders        map[string]string
	Proxy                string
	ResolversFile        string
	SkipHostErrorCheck   bool
	SystemResolvers      bool
	OfflineHTTP          bool
	EnableProgressBar    bool
	StatsJSON            bool
	Silent               bool
	Verbose              bool
	Debug                bool
}

// NewNucleiIntegration creates a new Nuclei integration instance
func NewNucleiIntegration(db *database.DatabaseWrapper, timeout time.Duration, verbose bool) *NucleiIntegration {
	return &NucleiIntegration{
		db:      db,
		timeout: timeout,
		verbose: verbose,
	}
}

// IsInstalled checks if Nuclei is installed and available
func (n *NucleiIntegration) IsInstalled() bool {
	_, err := exec.LookPath("nuclei")
	return err == nil
}

// InstallInstructions returns instructions for installing Nuclei
func (n *NucleiIntegration) InstallInstructions() string {
	return "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
}

// GetVersion returns the version of Nuclei
func (n *NucleiIntegration) GetVersion() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "nuclei", "-version")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get nuclei version: %w", err)
	}

	version := strings.TrimSpace(string(output))
	return version, nil
}

// ScanVulnerabilities performs vulnerability scanning using Nuclei
func (n *NucleiIntegration) ScanVulnerabilities(targets []string, config *NucleiConfig) ([]NucleiResult, error) {
	if config == nil {
		config = &NucleiConfig{
			Severity:             []string{"critical", "high", "medium"},
			Threads:              25,
			RateLimit:            150,
			Timeout:              5,
			Retries:              1,
			BulkSize:             25,
			TemplateTimeout:      30,
			NoInteractsh:         false,
			DisableUpdateCheck:   true,
			FollowRedirects:      true,
			MaxRedirects:         3,
			SkipHostErrorCheck:   true,
			SystemResolvers:      true,
			EnableProgressBar:    false,
			StatsJSON:            false,
			Silent:               true,
			Verbose:              n.verbose,
		}
	}

	// Build command arguments
	args := []string{
		"-json",
		"-silent",
		"-disable-update-check",
		"-no-color",
		"-stats",
	}

	// Template selection
	if len(config.Templates) > 0 {
		for _, template := range config.Templates {
			args = append(args, "-t", template)
		}
	}

	// Tag selection
	if len(config.Tags) > 0 {
		args = append(args, "-tags", strings.Join(config.Tags, ","))
	}

	// Exclude tags
	if len(config.ExcludeTags) > 0 {
		args = append(args, "-exclude-tags", strings.Join(config.ExcludeTags, ","))
	}

	// Severity filtering
	if len(config.Severity) > 0 {
		args = append(args, "-severity", strings.Join(config.Severity, ","))
	}

	// Performance settings
	if config.Threads > 0 {
		args = append(args, "-c", strconv.Itoa(config.Threads))
	}
	if config.RateLimit > 0 {
		args = append(args, "-rl", strconv.Itoa(config.RateLimit))
	}
	if config.Timeout > 0 {
		args = append(args, "-timeout", strconv.Itoa(config.Timeout))
	}
	if config.Retries > 0 {
		args = append(args, "-retries", strconv.Itoa(config.Retries))
	}
	if config.BulkSize > 0 {
		args = append(args, "-bs", strconv.Itoa(config.BulkSize))
	}

	// Behavior settings
	if config.NoInteractsh {
		args = append(args, "-ni")
	}
	if config.FollowRedirects {
		args = append(args, "-fr")
	}
	if config.MaxRedirects > 0 {
		args = append(args, "-mr", strconv.Itoa(config.MaxRedirects))
	}
	if config.SkipHostErrorCheck {
		args = append(args, "-fhr")
	}
	if config.SystemResolvers {
		args = append(args, "-sr")
	}

	// Custom user agent
	if config.UserAgent != "" {
		args = append(args, "-ua", config.UserAgent)
	}

	// Custom headers
	for header, value := range config.CustomHeaders {
		args = append(args, "-H", fmt.Sprintf("%s: %s", header, value))
	}

	// Proxy settings
	if config.Proxy != "" {
		args = append(args, "-proxy", config.Proxy)
	}

	// Resolvers file
	if config.ResolversFile != "" {
		args = append(args, "-r", config.ResolversFile)
	}

	// Verbose/Debug mode
	if config.Debug || (config.Verbose && n.verbose) {
		args = append(args, "-debug")
	} else if config.Verbose || n.verbose {
		args = append(args, "-v")
	}

	if n.verbose {
		fmt.Printf("[NUCLEI] Running: nuclei %s\n", strings.Join(args, " "))
		fmt.Printf("[NUCLEI] Targets: %s\n", strings.Join(targets, ", "))
	}

	// Execute command
	ctx, cancel := context.WithTimeout(context.Background(), n.timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "nuclei", args...)

	// Feed targets through stdin
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start nuclei: %w", err)
	}

	// Send targets to stdin
	go func() {
		defer stdin.Close()
		for _, target := range targets {
			fmt.Fprintln(stdin, target)
		}
	}()

	var results []NucleiResult
	scanner := bufio.NewScanner(stdout)

	// Parse JSON output line by line
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Skip stats and info lines
		if strings.Contains(line, "[INF]") || strings.Contains(line, "[WRN]") || 
		   strings.Contains(line, "[ERR]") || strings.Contains(line, "[DBG]") {
			continue
		}

		var result NucleiResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			if n.verbose {
				fmt.Printf("[NUCLEI] Failed to parse JSON: %s - Error: %v\n", line, err)
			}
			continue
		}

		result.Timestamp = time.Now()
		results = append(results, result)
	}

	if err := cmd.Wait(); err != nil {
		// Don't fail on exit code 1, which might just mean no vulnerabilities found
		if exitError, ok := err.(*exec.ExitError); ok && exitError.ExitCode() == 1 {
			if n.verbose {
				fmt.Printf("[NUCLEI] Command completed with exit code 1 (no vulnerabilities found)\n")
			}
		} else {
			return results, fmt.Errorf("nuclei command failed: %w", err)
		}
	}

	if err := scanner.Err(); err != nil {
		return results, fmt.Errorf("error reading nuclei output: %w", err)
	}

	return results, nil
}

// RunFullVulnerabilityScan performs comprehensive vulnerability scanning and stores results in database
func (n *NucleiIntegration) RunFullVulnerabilityScan(targets []string) (int, error) {
	if n.verbose {
		fmt.Printf("[NUCLEI] Starting vulnerability scan for %d targets\n", len(targets))
	}

	// Configure scan for comprehensive coverage
	config := &NucleiConfig{
		Severity:             []string{"critical", "high", "medium", "low"},
		Tags:                 []string{"cve", "oast", "default-logins", "misconfig", "exposed-panels"},
		Threads:              25,
		RateLimit:            150,
		Timeout:              10,
		Retries:              1,
		BulkSize:             25,
		TemplateTimeout:      30,
		NoInteractsh:         false,
		DisableUpdateCheck:   true,
		FollowRedirects:      true,
		MaxRedirects:         3,
		SkipHostErrorCheck:   true,
		SystemResolvers:      true,
		EnableProgressBar:    false,
		StatsJSON:            false,
		Silent:               true,
		Verbose:              n.verbose,
	}

	// Perform vulnerability scan
	results, err := n.ScanVulnerabilities(targets, config)
	if err != nil {
		return 0, fmt.Errorf("vulnerability scan failed: %w", err)
	}

	if n.verbose {
		fmt.Printf("[NUCLEI] Found %d vulnerabilities\n", len(results))
	}

	// Store results in database
	storedCount := 0
	for _, result := range results {
		// Extract host from URL or use IP
		host := result.Host
		if host == "" && result.IP != "" {
			host = result.IP
		}
		if host == "" && result.URL != "" {
			// Try to extract host from URL
			if strings.Contains(result.URL, "://") {
				parts := strings.Split(result.URL, "://")
				if len(parts) > 1 {
					hostPart := strings.Split(parts[1], "/")[0]
					hostPart = strings.Split(hostPart, ":")[0]
					host = hostPart
				}
			}
		}

		if host == "" {
			if n.verbose {
				fmt.Printf("[NUCLEI] Skipping result with no host information: %s\n", result.TemplateID)
			}
			continue
		}

		// First, ensure host exists
		hostModel := &models.Host{
			IP:        host,
			Hostname:  host,
			Status:    "active",
			OS:        "unknown",
			CreatedAt: result.Timestamp,
			UpdatedAt: result.Timestamp,
		}

		if err := n.db.CreateHost(hostModel); err != nil {
			if n.verbose {
				fmt.Printf("[NUCLEI] Host already exists or error creating: %v\n", err)
			}
		}

		// Get host from database
		hosts, err := n.db.GetHostsByIP(host)
		if err != nil || len(hosts) == 0 {
			if n.verbose {
				fmt.Printf("[NUCLEI] Failed to find host %s in database: %v\n", host, err)
			}
			continue
		}

		hostRecord := hosts[0]

		// Create vulnerability record
		vulnerability := &models.Vulnerability{
			HostID:      hostRecord.ID,
			Host:        hostRecord,
			Name:        result.Info.Name,
			Severity:    result.Info.Severity,
			Description: result.Info.Description,
			Solution:    "", // Nuclei doesn't provide solution
			References:  result.Info.Reference,
			CVSS:        result.Info.Classification.CVSSScore,
			Template:    result.TemplateID,
			POC:         fmt.Sprintf("URL: %s\nTemplate: %s\nMatched At: %s", result.URL, result.TemplatePath, result.MatchedAt),
			Exploitable: false, // Default to false, would need manual verification
			Verified:    true,  // Nuclei results are generally verified
			CreatedAt:   result.Timestamp,
			UpdatedAt:   result.Timestamp,
		}

		// Map severity to ensure consistency
		switch strings.ToLower(result.Info.Severity) {
		case "critical":
			vulnerability.Severity = "critical"
		case "high":
			vulnerability.Severity = "high"
		case "medium":
			vulnerability.Severity = "medium"
		case "low":
			vulnerability.Severity = "low"
		case "info", "information":
			vulnerability.Severity = "info"
		default:
			vulnerability.Severity = "unknown"
		}

		if err := n.db.CreateVulnerability(vulnerability); err != nil {
			if n.verbose {
				fmt.Printf("[NUCLEI] Failed to store vulnerability %s for %s: %v\n",
					result.TemplateID, host, err)
			}
			continue
		}

		storedCount++
	}

	if n.verbose {
		fmt.Printf("[NUCLEI] Stored %d vulnerabilities in database\n", storedCount)
	}

	return storedCount, nil
}

// ScanSpecificTemplates runs specific Nuclei templates
func (n *NucleiIntegration) ScanSpecificTemplates(targets []string, templates []string) ([]NucleiResult, error) {
	config := &NucleiConfig{
		Templates:            templates,
		Threads:              10,
		RateLimit:            50,
		Timeout:              10,
		Retries:              1,
		DisableUpdateCheck:   true,
		FollowRedirects:      true,
		SkipHostErrorCheck:   true,
		SystemResolvers:      true,
		Silent:               true,
		Verbose:              n.verbose,
	}

	return n.ScanVulnerabilities(targets, config)
}

// ScanBySeverity runs scans filtered by severity levels
func (n *NucleiIntegration) ScanBySeverity(targets []string, severities []string) ([]NucleiResult, error) {
	config := &NucleiConfig{
		Severity:             severities,
		Threads:              25,
		RateLimit:            100,
		Timeout:              10,
		Retries:              1,
		DisableUpdateCheck:   true,
		FollowRedirects:      true,
		SkipHostErrorCheck:   true,
		SystemResolvers:      true,
		Silent:               true,
		Verbose:              n.verbose,
	}

	return n.ScanVulnerabilities(targets, config)
}

// GetAvailableTemplates returns information about available templates (requires nuclei -tl)
func (n *NucleiIntegration) GetAvailableTemplates() ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "nuclei", "-tl")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get template list: %w", err)
	}

	var templates []string
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "[") {
			templates = append(templates, line)
		}
	}

	return templates, nil
}

// GenerateReport generates a summary report of vulnerability scan results
func (n *NucleiIntegration) GenerateReport(results []NucleiResult) string {
	if len(results) == 0 {
		return "No vulnerabilities found"
	}

	var report strings.Builder
	report.WriteString(fmt.Sprintf("Vulnerability Scan Results (%d findings):\n", len(results)))
	report.WriteString("=" + strings.Repeat("=", 60) + "\n\n")

	// Group by severity
	severityCounts := make(map[string]int)
	severityFindings := make(map[string][]NucleiResult)

	for _, result := range results {
		severity := strings.ToLower(result.Info.Severity)
		severityCounts[severity]++
		severityFindings[severity] = append(severityFindings[severity], result)
	}

	// Summary by severity
	report.WriteString("Summary by Severity:\n")
	for _, severity := range []string{"critical", "high", "medium", "low", "info"} {
		if count, exists := severityCounts[severity]; exists {
			report.WriteString(fmt.Sprintf("  %s: %d\n", strings.Title(severity), count))
		}
	}
	report.WriteString("\n")

	// Detailed findings by severity
	for _, severity := range []string{"critical", "high", "medium", "low", "info"} {
		if findings, exists := severityFindings[severity]; exists {
			report.WriteString(fmt.Sprintf("%s Severity Findings (%d):\n", strings.Title(severity), len(findings)))
			for _, finding := range findings {
				report.WriteString(fmt.Sprintf("  • %s (%s)\n", finding.Info.Name, finding.TemplateID))
				report.WriteString(fmt.Sprintf("    Target: %s\n", finding.URL))
				if finding.Info.Description != "" {
					report.WriteString(fmt.Sprintf("    Description: %s\n", finding.Info.Description))
				}
				report.WriteString("\n")
			}
		}
	}

	return report.String()
}