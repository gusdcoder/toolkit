package subfinder

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"

	"github.com/recon-platform/core/internal/database"
	"github.com/recon-platform/core/pkg/models"
)

// SubfinderIntegration handles subfinder tool integration
type SubfinderIntegration struct {
	db      *database.DatabaseWrapper
	timeout time.Duration
	verbose bool
}

// SubfinderConfig holds configuration for subfinder
type SubfinderConfig struct {
	Sources    []string // Sources to use (all, passive, active)
	Threads    int      // Number of threads
	Timeout    int      // Timeout in seconds
	Silent     bool     // Silent mode
	Recursive  bool     // Recursive enumeration
	MaxDepth   int      // Maximum recursion depth
}

// SubfinderResult represents a single subdomain result
type SubfinderResult struct {
	Domain    string
	IP        string
	Source    string
	Timestamp time.Time
}

// NewSubfinderIntegration creates a new subfinder integration
func NewSubfinderIntegration(db *database.DatabaseWrapper, timeout time.Duration, verbose bool) *SubfinderIntegration {
	return &SubfinderIntegration{
		db:      db,
		timeout: timeout,
		verbose: verbose,
	}
}

// IsInstalled checks if subfinder is installed and accessible
func (s *SubfinderIntegration) IsInstalled() bool {
	cmd := exec.Command("subfinder", "-version")
	err := cmd.Run()
	return err == nil
}

// InstallInstructions returns instructions for installing subfinder
func (s *SubfinderIntegration) InstallInstructions() string {
	return `To install Subfinder:
	
Method 1 - Go Install:
  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

Method 2 - Download Binary:
  # Download from: https://github.com/projectdiscovery/subfinder/releases
  
Method 3 - Package Manager:
  # On Kali Linux: apt install subfinder
  # On macOS: brew install subfinder

After installation, ensure 'subfinder' is in your PATH.`
}

// EnumerateSubdomains performs subdomain enumeration for a given domain
func (s *SubfinderIntegration) EnumerateSubdomains(domain string, config *SubfinderConfig) ([]SubfinderResult, error) {
	if !s.IsInstalled() {
		return nil, fmt.Errorf("subfinder is not installed or not in PATH. %s", s.InstallInstructions())
	}

	// Build command arguments
	args := []string{
		"-d", domain,
		"-o", "-", // Output to stdout
		"-json",   // JSON output for parsing
	}

	// Add configuration options
	if config != nil {
		if config.Silent {
			args = append(args, "-silent")
		}
		if config.Threads > 0 {
			args = append(args, "-t", fmt.Sprintf("%d", config.Threads))
		}
		if config.Timeout > 0 {
			args = append(args, "-timeout", fmt.Sprintf("%d", config.Timeout))
		}
		if config.Recursive {
			args = append(args, "-recursive")
			if config.MaxDepth > 0 {
				args = append(args, "-max-depth", fmt.Sprintf("%d", config.MaxDepth))
			}
		}
		if len(config.Sources) > 0 {
			args = append(args, "-sources", strings.Join(config.Sources, ","))
		}
	}

	if s.verbose {
		log.Printf("Executing: subfinder %s", strings.Join(args, " "))
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	// Execute subfinder
	cmd := exec.CommandContext(ctx, "subfinder", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start subfinder: %w", err)
	}

	// Parse results
	var results []SubfinderResult
	scanner := bufio.NewScanner(stdout)
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// For JSON output, we'd parse the JSON here
		// For now, treating each line as a subdomain
		result := SubfinderResult{
			Domain:    line,
			Source:    "subfinder",
			Timestamp: time.Now(),
		}
		
		results = append(results, result)
		
		if s.verbose {
			log.Printf("Found subdomain: %s", line)
		}
	}

	// Wait for command to complete
	if err := cmd.Wait(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return results, fmt.Errorf("subfinder timed out after %v", s.timeout)
		}
		return results, fmt.Errorf("subfinder execution failed: %w", err)
	}

	if err := scanner.Err(); err != nil {
		return results, fmt.Errorf("error reading subfinder output: %w", err)
	}

	return results, nil
}

// SaveResults saves subfinder results to the database
func (s *SubfinderIntegration) SaveResults(results []SubfinderResult) error {
	for _, result := range results {
		domain := &models.Domain{
			Domain:    result.Domain,
			IP:        result.IP,
			FirstSeen: result.Timestamp,
			LastSeen:  result.Timestamp,
		}

		// For memory database, we need to implement CreateDomain
		// For now, we'll use the wrapper method when it's available
		if err := s.saveDomainToDatabase(domain); err != nil {
			log.Printf("Failed to save domain %s: %v", result.Domain, err)
			continue
		}

		if s.verbose {
			log.Printf("Saved domain to database: %s", result.Domain)
		}
	}

	return nil
}

// saveDomainToDatabase saves a domain to the database
func (s *SubfinderIntegration) saveDomainToDatabase(domain *models.Domain) error {
	return s.db.CreateDomain(domain)
}

// RunFullEnumeration performs complete subdomain enumeration with default settings
func (s *SubfinderIntegration) RunFullEnumeration(domain string) (int, error) {
	config := &SubfinderConfig{
		Sources:   []string{"all"},
		Threads:   50,
		Timeout:   30,
		Silent:    true,
		Recursive: false,
	}

	results, err := s.EnumerateSubdomains(domain, config)
	if err != nil {
		return 0, err
	}

	if err := s.SaveResults(results); err != nil {
		return len(results), fmt.Errorf("failed to save some results: %w", err)
	}

	if s.verbose {
		log.Printf("Subfinder enumeration completed: %d subdomains found for %s", len(results), domain)
	}

	return len(results), nil
}

// GetStats returns statistics about discovered subdomains
func (s *SubfinderIntegration) GetStats() (map[string]interface{}, error) {
	counts, err := s.db.GetCounts()
	if err != nil {
		return nil, err
	}

	stats := map[string]interface{}{
		"total_domains":     counts["domains"],
		"last_enumeration": time.Now(),
		"tool":             "subfinder",
	}

	return stats, nil
}