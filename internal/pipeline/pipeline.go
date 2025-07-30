package pipeline

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"toolkit/internal/database"
	"toolkit/internal/integrations"
	"toolkit/internal/integrations/httpx"
	"toolkit/internal/integrations/naabu"
	"toolkit/internal/integrations/nuclei"
	"toolkit/pkg/models"
)

// ScanConfig holds configuration for a scan session
type ScanConfig struct {
	Target     string
	Domains    []string
	Vertical   bool
	Horizontal bool
	AllTools   bool
	Tools      []string
	Threads    int
	Timeout    int
	OutputDir  string
	Verbose    bool
	Debug      bool
}

// ScanResults holds the results of a scan session
type ScanResults struct {
	SessionID            uint
	HostsFound           int
	OpenPorts            int
	DomainsFound         int
	VulnerabilitiesFound int
	ServicesFound        int
	FilesFound           int
	VulnerabilityStats   map[string]int64
	Duration             time.Duration
	OutputFile           string
	Errors               []string
}

// Pipeline represents the intelligent reconnaissance pipeline
type Pipeline struct {
	db          *database.DatabaseWrapper
	config      *ScanConfig
	toolManager *integrations.ToolManager

	// Session tracking
	session *models.ScanSession

	// Progress tracking
	progressChan chan PhaseProgress

	// Synchronization
	mutex sync.RWMutex
	wg    sync.WaitGroup
}

// PhaseProgress represents progress of a scanning phase
type PhaseProgress struct {
	Phase    string
	Progress float64
	Status   string
	Message  string
	Results  int
}

// NewPipeline creates a new reconnaissance pipeline
func NewPipeline(db *database.DatabaseWrapper, config *ScanConfig) *Pipeline {
	return &Pipeline{
		db:           db,
		config:       config,
		toolManager:  integrations.NewToolManager(),
		progressChan: make(chan PhaseProgress, 100),
	}
}

// NewPipelineWithProgress creates a new pipeline with progress channel
func NewPipelineWithProgress(db *database.DatabaseWrapper, config *ScanConfig, progressChan chan PhaseProgress) *Pipeline {
	return &Pipeline{
		db:           db,
		config:       config,
		toolManager:  integrations.NewToolManager(),
		progressChan: progressChan,
	}
}

// Execute runs the complete reconnaissance pipeline
func (p *Pipeline) Execute() (*ScanResults, error) {
	startTime := time.Now()

	// Create scan session
	if err := p.createSession(); err != nil {
		return nil, fmt.Errorf("failed to create scan session: %w", err)
	}

	// Initialize results
	results := &ScanResults{
		SessionID:          p.session.ID,
		VulnerabilityStats: make(map[string]int64),
		Errors:             []string{},
	}

	// Phase 1: Discovery Phase
	if err := p.discoveryPhase(); err != nil {
		p.logError(err, "Discovery phase failed")
		results.Errors = append(results.Errors, err.Error())
	}

	// Phase 2: Enumeration Phase
	if err := p.enumerationPhase(); err != nil {
		p.logError(err, "Enumeration phase failed")
		results.Errors = append(results.Errors, err.Error())
	}

	// Phase 3: Vulnerability Assessment Phase
	if err := p.vulnerabilityPhase(); err != nil {
		p.logError(err, "Vulnerability phase failed")
		results.Errors = append(results.Errors, err.Error())
	}

	// Phase 4: Vertical Analysis (if enabled)
	if p.config.Vertical {
		if err := p.verticalPhase(); err != nil {
			p.logError(err, "Vertical phase failed")
			results.Errors = append(results.Errors, err.Error())
		}
	}

	// Calculate results and duration
	results.Duration = time.Since(startTime)

	// Populate results
	if err := p.populateResults(results); err != nil {
		return nil, fmt.Errorf("failed to populate results: %w", err)
	}

	// Update session completion
	if err := p.completeSession(results); err != nil {
		p.logError(err, "Failed to update session completion")
	}

	return results, nil
}

// createSession creates a new scan session in the database
func (p *Pipeline) createSession() error {
	target := p.config.Target
	if target == "" && len(p.config.Domains) > 0 {
		target = fmt.Sprintf("%v", p.config.Domains)
	}

	tools := p.config.Tools
	if p.config.AllTools {
		tools = []string{"all"}
	}

	p.session = &models.ScanSession{
		Name:      fmt.Sprintf("Scan_%s", time.Now().Format("20060102_150405")),
		Target:    target,
		Status:    "running",
		StartedAt: time.Now(),
		Tools:     tools,
		Config: map[string]interface{}{
			"vertical":   p.config.Vertical,
			"horizontal": p.config.Horizontal,
			"threads":    p.config.Threads,
			"timeout":    p.config.Timeout,
		},
		Results: make(map[string]interface{}),
		Errors:  []string{},
	}

	return p.db.CreateSession(p.session)
}

// discoveryPhase performs initial target discovery
func (p *Pipeline) discoveryPhase() error {
	p.logInfo("🔍 Starting Discovery Phase...")

	// Subdomain enumeration for domains
	if len(p.config.Domains) > 0 {
		for _, domain := range p.config.Domains {
			if err := p.enumerateSubdomains(domain); err != nil {
				p.logError(err, fmt.Sprintf("Subdomain enumeration failed for %s", domain))
			}
		}
	}

	// Host discovery for IP targets
	if p.config.Target != "" {
		if err := p.discoverHosts(p.config.Target); err != nil {
			p.logError(err, fmt.Sprintf("Host discovery failed for %s", p.config.Target))
		}
	}

	p.logInfo("✅ Discovery Phase completed")
	return nil
}

// enumerationPhase performs detailed enumeration of discovered targets
func (p *Pipeline) enumerationPhase() error {
	p.logInfo("📊 Starting Enumeration Phase...")

	// Get discovered hosts for port scanning
	hosts, err := p.db.GetAllHosts()
	if err != nil {
		return fmt.Errorf("failed to get hosts for enumeration: %w", err)
	}

	// Port scanning
	for _, host := range hosts {
		if err := p.scanPorts(host.IP); err != nil {
			p.logError(err, fmt.Sprintf("Port scanning failed for %s", host.IP))
		}
	}

	// Service enumeration
	openPorts, err := p.db.GetOpenPorts()
	if err != nil {
		return fmt.Errorf("failed to get open ports: %w", err)
	}

	for _, port := range openPorts {
		if err := p.enumerateService(port.Host.IP, port.Port, port.Protocol); err != nil {
			p.logError(err, fmt.Sprintf("Service enumeration failed for %s:%d", port.Host.IP, port.Port))
		}
	}

	p.logInfo("✅ Enumeration Phase completed")
	return nil
}

// vulnerabilityPhase performs vulnerability assessment
func (p *Pipeline) vulnerabilityPhase() error {
	p.logInfo("🚨 Starting Vulnerability Assessment Phase...")

	// Get all discovered hosts and services for vulnerability scanning
	hosts, err := p.db.GetAllHosts()
	if err != nil {
		return fmt.Errorf("failed to get hosts for vulnerability assessment: %w", err)
	}

	// Run Nuclei templates against discovered targets
	for _, host := range hosts {
		if err := p.runVulnerabilityScans(host.IP); err != nil {
			p.logError(err, fmt.Sprintf("Vulnerability scanning failed for %s", host.IP))
		}
	}

	p.logInfo("✅ Vulnerability Assessment Phase completed")
	return nil
}

// verticalPhase performs deep analysis of interesting targets
func (p *Pipeline) verticalPhase() error {
	p.logInfo("🎯 Starting Vertical Analysis Phase...")

	// Identify high-value targets based on:
	// 1. Hosts with critical/high vulnerabilities
	// 2. Hosts with many open ports
	// 3. Hosts with interesting services

	targets, err := p.identifyHighValueTargets()
	if err != nil {
		return fmt.Errorf("failed to identify high-value targets: %w", err)
	}

	p.logInfo(fmt.Sprintf("🎯 Identified %d high-value targets for deep analysis", len(targets)))

	// Perform deep analysis on each target
	for _, target := range targets {
		if err := p.performDeepAnalysis(target); err != nil {
			p.logError(err, fmt.Sprintf("Deep analysis failed for %s", target))
		}
	}

	p.logInfo("✅ Vertical Analysis Phase completed")
	return nil
}

// populateResults calculates and populates scan results
func (p *Pipeline) populateResults(results *ScanResults) error {
	// Get counts from database
	counts, err := p.db.GetCounts()
	if err != nil {
		return fmt.Errorf("failed to get counts: %w", err)
	}

	results.HostsFound = int(counts["hosts"])
	results.OpenPorts = int(counts["open_ports"])
	results.DomainsFound = int(counts["domains"])
	results.ServicesFound = int(counts["services"])
	results.FilesFound = int(counts["files"])

	// Get vulnerability statistics
	vulnStats, err := p.db.GetVulnerabilityStats()
	if err != nil {
		return fmt.Errorf("failed to get vulnerability statistics: %w", err)
	}

	results.VulnerabilityStats = vulnStats
	totalVulns := int64(0)
	for _, count := range vulnStats {
		totalVulns += count
	}
	results.VulnerabilitiesFound = int(totalVulns)

	return nil
}

// completeSession updates the scan session with completion data
func (p *Pipeline) completeSession(results *ScanResults) error {
	now := time.Now()
	p.session.CompletedAt = &now
	p.session.Status = "completed"
	p.session.Results = map[string]interface{}{
		"hosts_found":           results.HostsFound,
		"open_ports":            results.OpenPorts,
		"domains_found":         results.DomainsFound,
		"vulnerabilities_found": results.VulnerabilitiesFound,
		"services_found":        results.ServicesFound,
		"files_found":           results.FilesFound,
		"vulnerability_stats":   results.VulnerabilityStats,
		"duration_seconds":      results.Duration.Seconds(),
	}

	return p.db.UpdateSession(p.session)
}

// Utility methods

func (p *Pipeline) logInfo(message string) {
	if p.config.Verbose {
		log.Printf("[INFO] %s", message)
	}
}

func (p *Pipeline) logError(err error, context string) {
	log.Printf("[ERROR] %s: %v", context, err)
}

// Tool integration methods

func (p *Pipeline) enumerateSubdomains(domain string) error {
	p.updateProgress("🌐 Subdomain Enumeration", 0.0, "running", fmt.Sprintf("Enumerating subdomains for %s", domain))

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(p.config.Timeout)*time.Second)
	defer cancel()

	// Use subfinder tool
	result, err := p.toolManager.RunTool(ctx, "subfinder", domain, map[string]interface{}{
		"silent": true,
	})

	if err != nil {
		p.logError(err, fmt.Sprintf("Subfinder enumeration failed for %s", domain))
		p.updateProgress("🌐 Subdomain Enumeration", 1.0, "error", fmt.Sprintf("Failed: %v", err))
		return nil // Don't fail the entire scan
	}

	// Store results in database
	for _, domainResult := range result.Domains {
		if err := p.db.CreateDomain(&domainResult); err != nil {
			p.logError(err, "Failed to store domain in database")
		}
	}

	p.logInfo(fmt.Sprintf("Found %d subdomains for %s", len(result.Domains), domain))
	p.updateProgress("🌐 Subdomain Enumeration", 1.0, "complete", fmt.Sprintf("Found %d subdomains", len(result.Domains)))
	return nil
}

// updateProgress sends progress updates if channel is available
func (p *Pipeline) updateProgress(phase string, progress float64, status string, message string) {
	if p.progressChan != nil {
		select {
		case p.progressChan <- PhaseProgress{
			Phase:    phase,
			Progress: progress,
			Status:   status,
			Message:  message,
		}:
		default:
			// Channel is full, skip this update
		}
	}
}

func (p *Pipeline) discoverHosts(target string) error {
	// TODO: Implement host discovery (ping sweep, etc.)
	p.logInfo(fmt.Sprintf("Discovering hosts in %s", target))
	return nil
}

func (p *Pipeline) scanPorts(host string) error {
	p.logInfo(fmt.Sprintf("Scanning ports for %s", host))

	// Create Naabu integration
	timeout := time.Duration(p.config.Timeout) * time.Second
	if timeout == 0 {
		timeout = 120 * time.Second // Default timeout for port scanning
	}

	naabuIntegration := naabu.NewNaabuIntegration(p.db, timeout, p.config.Verbose)

	// Check if Naabu is installed
	if !naabuIntegration.IsInstalled() {
		p.logInfo("Naabu not found, skipping port scanning")
		p.logInfo("Install instructions: " + naabuIntegration.InstallInstructions())
		return nil // Don't fail the entire scan
	}

	// Run port scan
	count, err := naabuIntegration.RunFullPortScan(host)
	if err != nil {
		p.logError(err, fmt.Sprintf("Naabu port scan failed for %s", host))
		return nil // Don't fail the entire scan
	}

	p.logInfo(fmt.Sprintf("Found %d open ports for %s", count, host))
	return nil
}

func (p *Pipeline) enumerateService(host string, port int, protocol string) error {
	p.logInfo(fmt.Sprintf("Enumerating service %s:%d/%s", host, port, protocol))

	// Only probe HTTP services (ports 80, 443, 8080, 8443, etc.)
	httpPorts := map[int]bool{
		80: true, 443: true, 8080: true, 8443: true,
		8000: true, 8888: true, 9000: true, 9090: true,
		3000: true, 5000: true, 7001: true, 8001: true,
	}

	if !httpPorts[port] {
		p.logInfo(fmt.Sprintf("Skipping non-HTTP service %s:%d", host, port))
		return nil
	}

	// Create HTTPX integration
	timeout := time.Duration(p.config.Timeout) * time.Second
	if timeout == 0 {
		timeout = 30 * time.Second // Default timeout for HTTP probing
	}

	httpxIntegration := httpx.NewHTTPXIntegration(p.db, timeout, p.config.Verbose)

	// Check if HTTPX is installed
	if !httpxIntegration.IsInstalled() {
		p.logInfo("HTTPX not found, skipping HTTP service enumeration")
		p.logInfo("Install instructions: " + httpxIntegration.InstallInstructions())
		return nil // Don't fail the entire scan
	}

	// Prepare target for HTTP probing
	target := fmt.Sprintf("%s:%d", host, port)
	targets := []string{target}

	// Run HTTP probe
	count, err := httpxIntegration.RunFullHTTPProbe(targets)
	if err != nil {
		p.logError(err, fmt.Sprintf("HTTPX service enumeration failed for %s:%d", host, port))
		return nil // Don't fail the entire scan
	}

	p.logInfo(fmt.Sprintf("Found %d HTTP services for %s:%d", count, host, port))
	return nil
}

func (p *Pipeline) runVulnerabilityScans(host string) error {
	p.logInfo(fmt.Sprintf("Running vulnerability scans for %s", host))

	// Create Nuclei integration
	timeout := time.Duration(p.config.Timeout) * time.Second
	if timeout == 0 {
		timeout = 300 * time.Second // Default timeout for vulnerability scanning (5 minutes)
	}

	nucleiIntegration := nuclei.NewNucleiIntegration(p.db, timeout, p.config.Verbose)

	// Check if Nuclei is installed
	if !nucleiIntegration.IsInstalled() {
		p.logInfo("Nuclei not found, skipping vulnerability scanning")
		p.logInfo("Install instructions: " + nucleiIntegration.InstallInstructions())
		return nil // Don't fail the entire scan
	}

	// Prepare target for vulnerability scanning
	targets := []string{host}

	// Run vulnerability scan
	count, err := nucleiIntegration.RunFullVulnerabilityScan(targets)
	if err != nil {
		p.logError(err, fmt.Sprintf("Nuclei vulnerability scan failed for %s", host))
		return nil // Don't fail the entire scan
	}

	p.logInfo(fmt.Sprintf("Found %d vulnerabilities for %s", count, host))
	return nil
}

func (p *Pipeline) identifyHighValueTargets() ([]string, error) {
	// TODO: Implement intelligent target identification
	return []string{}, nil
}

func (p *Pipeline) performDeepAnalysis(target string) error {
	// TODO: Implement deep analysis workflows
	p.logInfo(fmt.Sprintf("Performing deep analysis for %s", target))
	return nil
}
