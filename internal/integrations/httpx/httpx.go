package httpx

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"toolkit/internal/database"
	"toolkit/pkg/models"
)

// HTTPXIntegration provides interface to HTTPX HTTP toolkit
type HTTPXIntegration struct {
	db      *database.DatabaseWrapper
	timeout time.Duration
	verbose bool
}

// HTTPXResult represents a single HTTP probe result
type HTTPXResult struct {
	URL               string            `json:"url"`
	Input             string            `json:"input"`
	Title             string            `json:"title"`
	StatusCode        int               `json:"status_code"`
	ContentLength     int               `json:"content_length"`
	ContentType       string            `json:"content_type"`
	Location          string            `json:"location"`
	Method            string            `json:"method"`
	Webserver         string            `json:"webserver"`
	TLS               bool              `json:"tls"`
	Host              string            `json:"host"`
	Port              int               `json:"port"`
	Scheme            string            `json:"scheme"`
	A                 []string          `json:"a"`
	CNAME             []string          `json:"cname"`
	TechnologiesSlice []string          `json:"tech"`
	Technologies      string            `json:"technologies"`
	Headers           map[string]string `json:"header"`
	ResponseTime      string            `json:"time"`
	Words             int               `json:"words"`
	Lines             int               `json:"lines"`
	Failed            bool              `json:"failed"`
	KnownService      string            `json:"knownservice,omitempty"`
	Pipeline          string            `json:"pipeline,omitempty"`
	Timestamp         time.Time         `json:"timestamp"`
}

// HTTPXConfig holds configuration for HTTPX probes
type HTTPXConfig struct {
	Ports             []int
	Threads           int
	Rate              int
	Timeout           int
	Retries           int
	FollowRedirects   bool
	RandomAgent       bool
	CustomHeaders     map[string]string
	StatusCodes       []int
	TechDetect        bool
	ScreenshotsPath   string
	OutputFormat      string
	FilterStatusCodes []int
	Silent            bool
	Verbose           bool
}

// NewHTTPXIntegration creates a new HTTPX integration instance
func NewHTTPXIntegration(db *database.DatabaseWrapper, timeout time.Duration, verbose bool) *HTTPXIntegration {
	return &HTTPXIntegration{
		db:      db,
		timeout: timeout,
		verbose: verbose,
	}
}

// IsInstalled checks if HTTPX is installed and available
func (h *HTTPXIntegration) IsInstalled() bool {
	_, err := exec.LookPath("httpx")
	return err == nil
}

// InstallInstructions returns instructions for installing HTTPX
func (h *HTTPXIntegration) InstallInstructions() string {
	return "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
}

// GetVersion returns the version of HTTPX
func (h *HTTPXIntegration) GetVersion() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "httpx", "-version")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get httpx version: %w", err)
	}

	version := strings.TrimSpace(string(output))
	return version, nil
}

// ProbeHTTP performs HTTP probing using HTTPX
func (h *HTTPXIntegration) ProbeHTTP(targets []string, config *HTTPXConfig) ([]HTTPXResult, error) {
	if config == nil {
		config = &HTTPXConfig{
			Threads:         50,
			Rate:            150,
			Timeout:         10,
			Retries:         2,
			FollowRedirects: true,
			RandomAgent:     true,
			TechDetect:      true,
			Silent:          true,
			Verbose:         h.verbose,
		}
	}

	// Build command arguments
	args := []string{
		"-json",
		"-tech-detect",
		"-title",
		"-status-code",
		"-content-length",
		"-content-type",
		"-location",
		"-web-server",
		"-response-time",
		"-line-count",
		"-word-count",
	}

	// Port specification
	if len(config.Ports) > 0 {
		ports := make([]string, len(config.Ports))
		for i, port := range config.Ports {
			ports[i] = strconv.Itoa(port)
		}
		args = append(args, "-ports", strings.Join(ports, ","))
	}

	// Performance settings
	if config.Threads > 0 {
		args = append(args, "-threads", strconv.Itoa(config.Threads))
	}
	if config.Rate > 0 {
		args = append(args, "-rate-limit", strconv.Itoa(config.Rate))
	}
	if config.Timeout > 0 {
		args = append(args, "-timeout", strconv.Itoa(config.Timeout))
	}
	if config.Retries > 0 {
		args = append(args, "-retries", strconv.Itoa(config.Retries))
	}

	// Behavior settings
	if config.FollowRedirects {
		args = append(args, "-follow-redirects")
	}
	if config.RandomAgent {
		args = append(args, "-random-agent")
	}

	// Custom headers
	for header, value := range config.CustomHeaders {
		args = append(args, "-H", fmt.Sprintf("%s: %s", header, value))
	}

	// Status code filtering
	if len(config.StatusCodes) > 0 {
		codes := make([]string, len(config.StatusCodes))
		for i, code := range config.StatusCodes {
			codes[i] = strconv.Itoa(code)
		}
		args = append(args, "-status-code", strings.Join(codes, ","))
	}

	// Filter status codes
	if len(config.FilterStatusCodes) > 0 {
		codes := make([]string, len(config.FilterStatusCodes))
		for i, code := range config.FilterStatusCodes {
			codes[i] = strconv.Itoa(code)
		}
		args = append(args, "-filter-code", strings.Join(codes, ","))
	}

	// Silent mode
	if config.Silent {
		args = append(args, "-silent")
	}

	// Verbose mode
	if config.Verbose || h.verbose {
		args = append(args, "-verbose")
	}

	if h.verbose {
		fmt.Printf("[HTTPX] Running: httpx %s\n", strings.Join(args, " "))
		fmt.Printf("[HTTPX] Targets: %s\n", strings.Join(targets, ", "))
	}

	// Execute command
	ctx, cancel := context.WithTimeout(context.Background(), h.timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "httpx", args...)

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
		return nil, fmt.Errorf("failed to start httpx: %w", err)
	}

	// Send targets to stdin
	go func() {
		defer stdin.Close()
		for _, target := range targets {
			fmt.Fprintln(stdin, target)
		}
	}()

	var results []HTTPXResult
	scanner := bufio.NewScanner(stdout)

	// Parse JSON output line by line
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var result HTTPXResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			if h.verbose {
				fmt.Printf("[HTTPX] Failed to parse JSON: %s - Error: %v\n", line, err)
			}
			continue
		}

		result.Timestamp = time.Now()
		if result.Technologies == "" && len(result.TechnologiesSlice) > 0 {
			result.Technologies = strings.Join(result.TechnologiesSlice, ",")
		}

		results = append(results, result)
	}

	if err := cmd.Wait(); err != nil {
		// Don't fail on exit code 1, which might just mean no services found
		if exitError, ok := err.(*exec.ExitError); ok && exitError.ExitCode() == 1 {
			if h.verbose {
				fmt.Printf("[HTTPX] Command completed with exit code 1 (no services found)\n")
			}
		} else {
			return results, fmt.Errorf("httpx command failed: %w", err)
		}
	}

	if err := scanner.Err(); err != nil {
		return results, fmt.Errorf("error reading httpx output: %w", err)
	}

	return results, nil
}

// RunFullHTTPProbe performs comprehensive HTTP probing and stores results in database
func (h *HTTPXIntegration) RunFullHTTPProbe(targets []string) (int, error) {
	if h.verbose {
		fmt.Printf("[HTTPX] Starting HTTP probe for %d targets\n", len(targets))
	}

	// Configure probe for comprehensive coverage
	config := &HTTPXConfig{
		Ports:           []int{80, 443, 8080, 8443, 8000, 8888, 9000, 9090},
		Threads:         50,
		Rate:            150,
		Timeout:         10,
		Retries:         2,
		FollowRedirects: true,
		RandomAgent:     true,
		TechDetect:      true,
		Silent:          true,
		Verbose:         h.verbose,
	}

	// Perform HTTP probing
	results, err := h.ProbeHTTP(targets, config)
	if err != nil {
		return 0, fmt.Errorf("HTTP probing failed: %w", err)
	}

	if h.verbose {
		fmt.Printf("[HTTPX] Found %d HTTP services\n", len(results))
	}

	// Store results in database
	storedCount := 0
	for _, result := range results {
		// First, ensure host exists
		hostModel := &models.Host{
			IP:        result.Host,
			Hostname:  result.Host,
			Status:    "active",
			OS:        "unknown",
			CreatedAt: result.Timestamp,
			UpdatedAt: result.Timestamp,
		}

		if err := h.db.CreateHost(hostModel); err != nil {
			if h.verbose {
				fmt.Printf("[HTTPX] Host already exists or error creating: %v\n", err)
			}
		}

		// Get host from database
		hosts, err := h.db.GetHostsByIP(result.Host)
		if err != nil || len(hosts) == 0 {
			if h.verbose {
				fmt.Printf("[HTTPX] Failed to find host %s in database: %v\n", result.Host, err)
			}
			continue
		}

		hostRecord := hosts[0]

		// Create service record
		serviceName := "http"
		if result.TLS {
			serviceName = "https"
		}

		service := &models.Service{
			HostID:       hostRecord.ID,
			Host:         hostRecord,
			Name:         serviceName,
			Version:      result.Webserver,
			Banner:       fmt.Sprintf("HTTP service - Status: %d, Title: %s, Tech: %s", result.StatusCode, result.Title, result.Technologies),
			Headers:      []string{}, // TODO: Parse headers from result
			Certificates: []string{}, // TODO: Extract cert info if HTTPS
			Fingerprint:  "",
			CreatedAt:    result.Timestamp,
			UpdatedAt:    result.Timestamp,
		}

		if err := h.db.CreateService(service); err != nil {
			if h.verbose {
				fmt.Printf("[HTTPX] Failed to store service %s:%d for %s: %v\n",
					result.Scheme, result.Port, result.Host, err)
			}
			continue
		}

		storedCount++
	}

	if h.verbose {
		fmt.Printf("[HTTPX] Stored %d HTTP services in database\n", storedCount)
	}

	return storedCount, nil
}

// ProbeSpecificServices probes specific hosts and ports
func (h *HTTPXIntegration) ProbeSpecificServices(hostPorts []string) ([]HTTPXResult, error) {
	config := &HTTPXConfig{
		Threads:         25,
		Rate:            100,
		Timeout:         10,
		Retries:         1,
		FollowRedirects: true,
		RandomAgent:     true,
		TechDetect:      true,
		Silent:          true,
		Verbose:         h.verbose,
	}

	return h.ProbeHTTP(hostPorts, config)
}

// ProbeCommonPorts probes common HTTP ports on given hosts
func (h *HTTPXIntegration) ProbeCommonPorts(hosts []string) ([]HTTPXResult, error) {
	commonPorts := []int{80, 443, 8080, 8443, 8000, 8888, 9000, 9090, 3000, 5000}

	config := &HTTPXConfig{
		Ports:           commonPorts,
		Threads:         25,
		Rate:            100,
		Timeout:         10,
		Retries:         1,
		FollowRedirects: true,
		RandomAgent:     true,
		TechDetect:      true,
		Silent:          true,
		Verbose:         h.verbose,
	}

	return h.ProbeHTTP(hosts, config)
}

// GetCommonPorts returns a list of commonly probed HTTP ports
func (h *HTTPXIntegration) GetCommonPorts() []int {
	return []int{
		80, 443, 8080, 8443, 8000, 8888, 9000, 9090,
		3000, 5000, 7001, 8001, 8008, 8888, 8983, 9443,
		// Add more common HTTP ports as needed
	}
}

// GenerateReport generates a summary report of HTTP probe results
func (h *HTTPXIntegration) GenerateReport(results []HTTPXResult) string {
	if len(results) == 0 {
		return "No HTTP services found"
	}

	var report strings.Builder
	report.WriteString(fmt.Sprintf("HTTP Probe Results (%d services):\n", len(results)))
	report.WriteString("=" + strings.Repeat("=", 50) + "\n\n")

	// Group by protocol
	httpServices := []HTTPXResult{}
	httpsServices := []HTTPXResult{}

	for _, result := range results {
		if result.TLS || result.Scheme == "https" {
			httpsServices = append(httpsServices, result)
		} else {
			httpServices = append(httpServices, result)
		}
	}

	// HTTP services
	if len(httpServices) > 0 {
		report.WriteString(fmt.Sprintf("HTTP Services (%d):\n", len(httpServices)))
		for _, result := range httpServices {
			server := result.Webserver
			if server == "" {
				server = "unknown"
			}
			report.WriteString(fmt.Sprintf("  %s [%d] - %s",
				result.URL, result.StatusCode, server))
			if result.Title != "" {
				report.WriteString(fmt.Sprintf(" - %s", result.Title))
			}
			if result.Technologies != "" {
				report.WriteString(fmt.Sprintf(" (%s)", result.Technologies))
			}
			report.WriteString("\n")
		}
		report.WriteString("\n")
	}

	// HTTPS services
	if len(httpsServices) > 0 {
		report.WriteString(fmt.Sprintf("HTTPS Services (%d):\n", len(httpsServices)))
		for _, result := range httpsServices {
			server := result.Webserver
			if server == "" {
				server = "unknown"
			}
			report.WriteString(fmt.Sprintf("  %s [%d] - %s",
				result.URL, result.StatusCode, server))
			if result.Title != "" {
				report.WriteString(fmt.Sprintf(" - %s", result.Title))
			}
			if result.Technologies != "" {
				report.WriteString(fmt.Sprintf(" (%s)", result.Technologies))
			}
			report.WriteString("\n")
		}
	}

	return report.String()
}
