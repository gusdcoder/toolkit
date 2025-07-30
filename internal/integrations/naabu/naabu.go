package naabu

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

// NaabuIntegration provides interface to Naabu port scanner
type NaabuIntegration struct {
	db      *database.DatabaseWrapper
	timeout time.Duration
	verbose bool
}

// NaabuResult represents a single port scan result
type NaabuResult struct {
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Protocol  string `json:"protocol"`
	Status    string `json:"status"`
	Service   string `json:"service,omitempty"`
	Banner    string `json:"banner,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// NaabuConfig holds configuration for Naabu scans
type NaabuConfig struct {
	Ports         []int
	PortRange     string
	TopPorts      int
	Threads       int
	Rate          int
	Timeout       int
	Retries       int
	ExcludePorts  []int
	ServiceDetection bool
	VerboseOutput    bool
}

// NewNaabuIntegration creates a new Naabu integration instance
func NewNaabuIntegration(db *database.DatabaseWrapper, timeout time.Duration, verbose bool) *NaabuIntegration {
	return &NaabuIntegration{
		db:      db,
		timeout: timeout,
		verbose: verbose,
	}
}

// IsInstalled checks if Naabu is installed and available
func (n *NaabuIntegration) IsInstalled() bool {
	_, err := exec.LookPath("naabu")
	return err == nil
}

// InstallInstructions returns instructions for installing Naabu
func (n *NaabuIntegration) InstallInstructions() string {
	return "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
}

// GetVersion returns the version of Naabu
func (n *NaabuIntegration) GetVersion() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "naabu", "-version")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get naabu version: %w", err)
	}

	version := strings.TrimSpace(string(output))
	return version, nil
}

// ScanPorts performs port scanning using Naabu
func (n *NaabuIntegration) ScanPorts(host string, config *NaabuConfig) ([]NaabuResult, error) {
	if config == nil {
		config = &NaabuConfig{
			TopPorts: 1000,
			Threads:  25,
			Rate:     1000,
			Timeout:  5,
			Retries:  1,
		}
	}

	// Build command arguments
	args := []string{
		"-host", host,
		"-json",
		"-silent",
	}

	// Port specification
	if len(config.Ports) > 0 {
		ports := make([]string, len(config.Ports))
		for i, port := range config.Ports {
			ports[i] = strconv.Itoa(port)
		}
		args = append(args, "-port", strings.Join(ports, ","))
	} else if config.PortRange != "" {
		args = append(args, "-port", config.PortRange)
	} else if config.TopPorts > 0 {
		args = append(args, "-top-ports", strconv.Itoa(config.TopPorts))
	}

	// Performance options
	if config.Threads > 0 {
		args = append(args, "-c", strconv.Itoa(config.Threads))
	}
	if config.Rate > 0 {
		args = append(args, "-rate", strconv.Itoa(config.Rate))
	}
	if config.Timeout > 0 {
		args = append(args, "-timeout", strconv.Itoa(config.Timeout*1000)) // Naabu expects milliseconds
	}
	if config.Retries > 0 {
		args = append(args, "-retries", strconv.Itoa(config.Retries))
	}

	// Exclude ports if specified
	if len(config.ExcludePorts) > 0 {
		excludePorts := make([]string, len(config.ExcludePorts))
		for i, port := range config.ExcludePorts {
			excludePorts[i] = strconv.Itoa(port)
		}
		args = append(args, "-exclude-ports", strings.Join(excludePorts, ","))
	}

	// Service detection
	if config.ServiceDetection {
		args = append(args, "-sV")
	}

	// Verbose output
	if config.VerboseOutput || n.verbose {
		args = append(args, "-v")
	}

	if n.verbose {
		fmt.Printf("[NAABU] Running: naabu %s\n", strings.Join(args, " "))
	}

	// Execute command
	ctx, cancel := context.WithTimeout(context.Background(), n.timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "naabu", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start naabu: %w", err)
	}

	var results []NaabuResult
	scanner := bufio.NewScanner(stdout)

	// Parse JSON output line by line
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var result NaabuResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			if n.verbose {
				fmt.Printf("[NAABU] Failed to parse JSON: %s - Error: %v\n", line, err)
			}
			continue
		}

		result.Timestamp = time.Now()
		if result.Status == "" {
			result.Status = "open"
		}
		if result.Protocol == "" {
			result.Protocol = "tcp"
		}

		results = append(results, result)
	}

	if err := cmd.Wait(); err != nil {
		// Don't fail on exit code 1, which might just mean no ports found
		if exitError, ok := err.(*exec.ExitError); ok && exitError.ExitCode() == 1 {
			if n.verbose {
				fmt.Printf("[NAABU] Command completed with exit code 1 (no ports found)\n")
			}
		} else {
			return results, fmt.Errorf("naabu command failed: %w", err)
		}
	}

	if err := scanner.Err(); err != nil {
		return results, fmt.Errorf("error reading naabu output: %w", err)
	}

	return results, nil
}

// RunFullPortScan performs comprehensive port scanning and stores results in database
func (n *NaabuIntegration) RunFullPortScan(host string) (int, error) {
	if n.verbose {
		fmt.Printf("[NAABU] Starting full port scan for %s\n", host)
	}

	// First, ensure host exists in database
	hostModel := &models.Host{
		IP:        host,
		Hostname:  host,
		Status:    "active",
		OS:        "unknown",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := n.db.CreateHost(hostModel); err != nil {
		if n.verbose {
			fmt.Printf("[NAABU] Host already exists or error creating: %v\n", err)
		}
		// Continue anyway, host might already exist
	}

	// Get host from database to get ID
	hosts, err := n.db.GetHostsByIP(host)
	if err != nil || len(hosts) == 0 {
		return 0, fmt.Errorf("failed to find host %s in database: %w", host, err)
	}

	hostRecord := hosts[0]

	// Configure scan for comprehensive coverage
	config := &NaabuConfig{
		TopPorts:         1000,
		Threads:          50,
		Rate:             1000,
		Timeout:          5,
		Retries:          2,
		ServiceDetection: true,
		VerboseOutput:    n.verbose,
	}

	// Perform port scan
	results, err := n.ScanPorts(host, config)
	if err != nil {
		return 0, fmt.Errorf("port scan failed: %w", err)
	}

	if n.verbose {
		fmt.Printf("[NAABU] Found %d open ports for %s\n", len(results), host)
	}

	// Store results in database
	storedCount := 0
	for _, result := range results {
		port := &models.Port{
			HostID:    hostRecord.ID,
			Host:      hostRecord,
			Port:      result.Port,
			Protocol:  result.Protocol,
			State:     result.Status,
			Service:   result.Service,
			Version:   "",
			Banner:    result.Banner,
			CreatedAt: result.Timestamp,
			UpdatedAt: result.Timestamp,
		}

		if err := n.db.CreatePort(port); err != nil {
			if n.verbose {
				fmt.Printf("[NAABU] Failed to store port %d/%s for %s: %v\n", 
					result.Port, result.Protocol, host, err)
			}
			continue
		}

		storedCount++
	}

	if n.verbose {
		fmt.Printf("[NAABU] Stored %d ports in database for %s\n", storedCount, host)
	}

	return storedCount, nil
}

// ScanSpecificPorts scans only specific ports
func (n *NaabuIntegration) ScanSpecificPorts(host string, ports []int) ([]NaabuResult, error) {
	config := &NaabuConfig{
		Ports:            ports,
		Threads:          25,
		Rate:             1000,
		Timeout:          5,
		Retries:          1,
		ServiceDetection: true,
		VerboseOutput:    n.verbose,
	}

	return n.ScanPorts(host, config)
}

// ScanPortRange scans a range of ports
func (n *NaabuIntegration) ScanPortRange(host string, portRange string) ([]NaabuResult, error) {
	config := &NaabuConfig{
		PortRange:        portRange,
		Threads:          25,
		Rate:             1000,
		Timeout:          5,
		Retries:          1,
		ServiceDetection: true,
		VerboseOutput:    n.verbose,
	}

	return n.ScanPorts(host, config)
}

// ScanTopPorts scans the most common ports
func (n *NaabuIntegration) ScanTopPorts(host string, topCount int) ([]NaabuResult, error) {
	config := &NaabuConfig{
		TopPorts:         topCount,
		Threads:          25,
		Rate:             1000,
		Timeout:          5,
		Retries:          1,
		ServiceDetection: true,
		VerboseOutput:    n.verbose,
	}

	return n.ScanPorts(host, config)
}

// GetCommonPorts returns a list of commonly scanned ports
func (n *NaabuIntegration) GetCommonPorts() []int {
	return []int{
		21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995,
		1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 9090,
		// Add more common ports as needed
	}
}

// GenerateReport generates a summary report of port scan results
func (n *NaabuIntegration) GenerateReport(results []NaabuResult) string {
	if len(results) == 0 {
		return "No open ports found"
	}

	var report strings.Builder
	report.WriteString(fmt.Sprintf("Port Scan Results (%d open ports):\n", len(results)))
	report.WriteString("=" + strings.Repeat("=", 40) + "\n\n")

	// Group by protocol
	tcpPorts := []NaabuResult{}
	udpPorts := []NaabuResult{}

	for _, result := range results {
		if result.Protocol == "udp" {
			udpPorts = append(udpPorts, result)
		} else {
			tcpPorts = append(tcpPorts, result)
		}
	}

	// TCP ports
	if len(tcpPorts) > 0 {
		report.WriteString(fmt.Sprintf("TCP Ports (%d):\n", len(tcpPorts)))
		for _, result := range tcpPorts {
			service := result.Service
			if service == "" {
				service = "unknown"
			}
			report.WriteString(fmt.Sprintf("  %d/tcp - %s", result.Port, service))
			if result.Banner != "" {
				report.WriteString(fmt.Sprintf(" (%s)", result.Banner))
			}
			report.WriteString("\n")
		}
		report.WriteString("\n")
	}

	// UDP ports
	if len(udpPorts) > 0 {
		report.WriteString(fmt.Sprintf("UDP Ports (%d):\n", len(udpPorts)))
		for _, result := range udpPorts {
			service := result.Service
			if service == "" {
				service = "unknown"
			}
			report.WriteString(fmt.Sprintf("  %d/udp - %s", result.Port, service))
			if result.Banner != "" {
				report.WriteString(fmt.Sprintf(" (%s)", result.Banner))
			}
			report.WriteString("\n")
		}
	}

	return report.String()
}