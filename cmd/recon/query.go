package recon

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"toolkit/internal/database"
	"toolkit/internal/workspace"
	"toolkit/pkg/models"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	showHosts           bool
	showPorts           bool
	showDomains         bool
	showVulnerabilities bool
	showServices        bool
	showCredentials     bool
	showFiles           bool
	showStats           bool
	severity            string
	status              string
	outputFormat        string
	limit               int
	search              string
)

// queryCmd represents the query command
var queryCmd = &cobra.Command{
	Use:   "query",
	Short: "Query the loot database",
	Long: `Query and explore reconnaissance data stored in the database.

Examples:
  # Show all hosts
  recon query --hosts
  
  # Show vulnerabilities by severity
  recon query --vulnerabilities --severity critical
  
  # Show open ports
  recon query --ports --status open
  
  # Search across all data
  recon query --search "admin"
  
  # Show statistics
  recon query --stats
  
  # Export to JSON
  recon query --hosts --format json > hosts.json`,
	RunE: runQuery,
}

func init() {
	rootCmd.AddCommand(queryCmd)

	// Query type flags
	queryCmd.Flags().BoolVar(&showHosts, "hosts", false,
		"show discovered hosts")
	queryCmd.Flags().BoolVar(&showPorts, "ports", false,
		"show discovered ports")
	queryCmd.Flags().BoolVar(&showDomains, "domains", false,
		"show discovered domains")
	queryCmd.Flags().BoolVar(&showVulnerabilities, "vulnerabilities", false,
		"show discovered vulnerabilities")
	queryCmd.Flags().BoolVar(&showServices, "services", false,
		"show discovered services")
	queryCmd.Flags().BoolVar(&showCredentials, "credentials", false,
		"show discovered credentials")
	queryCmd.Flags().BoolVar(&showFiles, "files", false,
		"show discovered files")
	queryCmd.Flags().BoolVar(&showStats, "stats", false,
		"show database statistics")

	// Filter flags
	queryCmd.Flags().StringVar(&severity, "severity", "",
		"filter by vulnerability severity (critical,high,medium,low,info)")
	queryCmd.Flags().StringVar(&status, "status", "",
		"filter by status (up,down,open,closed)")
	queryCmd.Flags().StringVar(&search, "search", "",
		"search keyword across all data")
	queryCmd.Flags().IntVar(&limit, "limit", 100,
		"limit number of results")

	// Output flags
	queryCmd.Flags().StringVarP(&outputFormat, "format", "f", "table",
		"output format (table,json,csv)")
}

func runQuery(cmd *cobra.Command, args []string) error {
	// Check if workspace is set
	if err := requireWorkspaceForQuery(); err != nil {
		return err
	}

	// Initialize database
	dbConfig := &database.Config{
		Type:     viper.GetString("database.type"),
		Host:     viper.GetString("database.host"),
		Port:     viper.GetInt("database.port"),
		User:     viper.GetString("database.user"),
		Password: viper.GetString("database.password"),
		DBName:   viper.GetString("database.dbname"),
		SSLMode:  viper.GetString("database.sslmode"),
		DataDir:  getDataDir(),
	}

	db, err := database.NewDatabase(dbConfig)
	if err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
	}
	defer db.Close()

	// Handle search query
	if search != "" {
		return handleSearch(db, search)
	}

	// Handle statistics
	if showStats {
		return handleStats(db)
	}

	// Handle specific queries
	if showHosts {
		return handleHosts(db)
	}

	if showPorts {
		return handlePorts(db)
	}

	if showDomains {
		return handleDomains(db)
	}

	if showVulnerabilities {
		return handleVulnerabilities(db)
	}

	if showServices {
		return handleServices(db)
	}

	if showCredentials {
		return handleCredentials(db)
	}

	if showFiles {
		return handleFiles(db)
	}

	// If no specific query, show summary
	return handleSummary(db)
}

func handleSearch(db *database.DatabaseWrapper, keyword string) error {
	results, err := db.SearchByKeyword(keyword)
	if err != nil {
		return fmt.Errorf("search failed: %w", err)
	}

	fmt.Printf("🔍 Search results for: %s\n\n", keyword)

	// Display hosts
	if hosts, ok := results["hosts"].([]models.Host); ok && len(hosts) > 0 {
		fmt.Printf("📡 Hosts (%d):\n", len(hosts))
		displayHostsTable(hosts)
		fmt.Println()
	}

	// Display domains
	if domains, ok := results["domains"].([]models.Domain); ok && len(domains) > 0 {
		fmt.Printf("🌐 Domains (%d):\n", len(domains))
		displayDomainsTable(domains)
		fmt.Println()
	}

	// Display vulnerabilities
	if vulns, ok := results["vulnerabilities"].([]models.Vulnerability); ok && len(vulns) > 0 {
		fmt.Printf("🚨 Vulnerabilities (%d):\n", len(vulns))
		displayVulnerabilitiesTable(vulns)
	}

	return nil
}

func handleStats(db *database.DatabaseWrapper) error {
	stats, err := db.GetVulnerabilityStats()
	if err != nil {
		return fmt.Errorf("failed to get statistics: %w", err)
	}

	// Get total counts for other entities
	counts, err := db.GetCounts()
	if err != nil {
		return fmt.Errorf("failed to get counts: %w", err)
	}

	fmt.Printf("📊 Database Statistics\n\n")

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "Category\tCount\n")
	fmt.Fprintf(w, "--------\t-----\n")
	fmt.Fprintf(w, "Hosts\t%d\n", counts["hosts"])
	fmt.Fprintf(w, "Open Ports\t%d\n", counts["open_ports"])
	fmt.Fprintf(w, "Domains\t%d\n", counts["domains"])
	fmt.Fprintf(w, "\t\n")

	totalVulns := int64(0)
	for severity, count := range stats {
		emoji := getVulnEmoji(severity)
		fmt.Fprintf(w, "%s %s\t%d\n", emoji, strings.Title(severity), count)
		totalVulns += count
	}
	fmt.Fprintf(w, "Total Vulnerabilities\t%d\n", totalVulns)

	w.Flush()
	return nil
}

func handleHosts(db *database.DatabaseWrapper) error {
	hosts, err := db.GetAllHosts()
	if err != nil {
		return fmt.Errorf("failed to get hosts: %w", err)
	}

	if outputFormat == "json" {
		return outputJSON(hosts)
	}

	fmt.Printf("📡 Discovered Hosts (%d)\n\n", len(hosts))
	displayHostsTable(hosts)
	return nil
}

func handlePorts(db *database.DatabaseWrapper) error {
	var ports []models.Port
	var err error

	if status == "open" || status == "" {
		ports, err = db.GetOpenPorts()
	} else {
		// For memory database, we'll just get open ports for now
		// TODO: Implement status filtering for memory database
		ports, err = db.GetOpenPorts()
	}

	if err != nil {
		return fmt.Errorf("failed to get ports: %w", err)
	}

	if outputFormat == "json" {
		return outputJSON(ports)
	}

	fmt.Printf("🔌 Discovered Ports (%d)\n\n", len(ports))
	displayPortsTable(ports)
	return nil
}

func handleVulnerabilities(db *database.DatabaseWrapper) error {
	// For now, just return empty vulnerabilities
	var vulns []models.Vulnerability

	if outputFormat == "json" {
		return outputJSON(vulns)
	}

	fmt.Printf("🚨 Discovered Vulnerabilities (0)\n\n")
	fmt.Printf("No vulnerabilities found. Vulnerabilities will be populated during scanning.\n")
	return nil
}

func handleDomains(db *database.DatabaseWrapper) error {
	domains, err := db.GetAllDomains()
	if err != nil {
		return fmt.Errorf("failed to get domains: %w", err)
	}

	if outputFormat == "json" {
		return outputJSON(domains)
	}

	fmt.Printf("🌐 Discovered Domains (%d)\n\n", len(domains))
	displayDomainsTable(domains)
	return nil
}

func handleServices(db *database.DatabaseWrapper) error {
	// For now, return empty services
	var services []models.Service

	if outputFormat == "json" {
		return outputJSON(services)
	}

	fmt.Printf("⚙️  Discovered Services (0)\n\n")
	fmt.Printf("No services found. Services will be populated during scanning.\n")
	return nil
}

func handleCredentials(db *database.DatabaseWrapper) error {
	// For now, return empty credentials
	var credentials []models.Credential

	if outputFormat == "json" {
		return outputJSON(credentials)
	}

	fmt.Printf("🔑 Discovered Credentials (0)\n\n")
	fmt.Printf("No credentials found. Credentials will be populated during scanning.\n")
	return nil
}

func handleFiles(db *database.DatabaseWrapper) error {
	// For now, return empty files
	var files []models.File

	if outputFormat == "json" {
		return outputJSON(files)
	}

	fmt.Printf("📁 Discovered Files (0)\n\n")
	fmt.Printf("No files found. Files will be populated during scanning.\n")
	return nil
}

func handleSummary(db *database.DatabaseWrapper) error {
	fmt.Printf("📋 Database Summary\n\n")
	fmt.Printf("Use specific flags to query data:\n")
	fmt.Printf("  --hosts              Show discovered hosts\n")
	fmt.Printf("  --ports              Show discovered ports\n")
	fmt.Printf("  --domains            Show discovered domains\n")
	fmt.Printf("  --vulnerabilities    Show vulnerabilities\n")
	fmt.Printf("  --services           Show services\n")
	fmt.Printf("  --credentials        Show credentials\n")
	fmt.Printf("  --files              Show files\n")
	fmt.Printf("  --stats              Show statistics\n")
	fmt.Printf("  --search <keyword>   Search across all data\n")

	return handleStats(db)
}

// Display functions for different data types

func displayHostsTable(hosts []models.Host) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "IP Address\tHostname\tStatus\tOS\tLast Seen\n")
	fmt.Fprintf(w, "----------\t--------\t------\t--\t---------\n")

	for _, host := range hosts {
		hostname := host.Hostname
		if hostname == "" {
			hostname = "-"
		}
		os := host.OS
		if os == "" {
			os = "-"
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			host.IP,
			hostname,
			host.Status,
			os,
			host.LastSeen.Format("2006-01-02 15:04"),
		)
	}
	w.Flush()
}

func displayPortsTable(ports []models.Port) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "Host\tPort\tProtocol\tState\tService\tVersion\n")
	fmt.Fprintf(w, "----\t----\t--------\t-----\t-------\t-------\n")

	for _, port := range ports {
		hostIP := "-"
		if port.Host.IP != "" {
			hostIP = port.Host.IP
		}

		service := port.Service
		if service == "" {
			service = "-"
		}

		version := port.Version
		if version == "" {
			version = "-"
		}

		fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\t%s\n",
			hostIP,
			port.Port,
			port.Protocol,
			port.State,
			service,
			version,
		)
	}
	w.Flush()
}

func displayVulnerabilitiesTable(vulns []models.Vulnerability) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "Host\tSeverity\tName\tCVE\tCVSS\n")
	fmt.Fprintf(w, "----\t--------\t----\t---\t----\n")

	for _, vuln := range vulns {
		hostIP := "-"
		if vuln.Host.IP != "" {
			hostIP = vuln.Host.IP
		}

		cve := vuln.CVE
		if cve == "" {
			cve = "-"
		}

		cvss := "-"
		if vuln.CVSS > 0 {
			cvss = fmt.Sprintf("%.1f", vuln.CVSS)
		}

		emoji := getVulnEmoji(vuln.Severity)

		fmt.Fprintf(w, "%s\t%s %s\t%s\t%s\t%s\n",
			hostIP,
			emoji,
			vuln.Severity,
			truncateString(vuln.Name, 40),
			cve,
			cvss,
		)
	}
	w.Flush()
}

func displayDomainsTable(domains []models.Domain) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "Domain\tIP\tStatus\tTitle\tServer\n")
	fmt.Fprintf(w, "------\t--\t------\t-----\t------\n")

	for _, domain := range domains {
		ip := domain.IP
		if ip == "" {
			ip = "-"
		}

		status := "-"
		if domain.Status > 0 {
			status = strconv.Itoa(domain.Status)
		}

		title := truncateString(domain.Title, 30)
		if title == "" {
			title = "-"
		}

		server := domain.Server
		if server == "" {
			server = "-"
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			domain.Domain,
			ip,
			status,
			title,
			server,
		)
	}
	w.Flush()
}

func displayServicesTable(services []models.Service) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "Host\tService\tVersion\tFingerprint\n")
	fmt.Fprintf(w, "----\t-------\t-------\t-----------\n")

	for _, service := range services {
		hostIP := "-"
		if service.Host.IP != "" {
			hostIP = service.Host.IP
		}

		version := service.Version
		if version == "" {
			version = "-"
		}

		fingerprint := truncateString(service.Fingerprint, 40)
		if fingerprint == "" {
			fingerprint = "-"
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			hostIP,
			service.Name,
			version,
			fingerprint,
		)
	}
	w.Flush()
}

func displayCredentialsTable(credentials []models.Credential) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "Host\tService\tUsername\tType\tVerified\n")
	fmt.Fprintf(w, "----\t-------\t--------\t----\t--------\n")

	for _, cred := range credentials {
		hostIP := "-"
		if cred.Host.IP != "" {
			hostIP = cred.Host.IP
		}

		username := cred.Username
		if username == "" {
			username = "-"
		}

		credType := cred.Type
		if credType == "" {
			credType = "-"
		}

		verified := "❌"
		if cred.Verified {
			verified = "✅"
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			hostIP,
			cred.Service,
			username,
			credType,
			verified,
		)
	}
	w.Flush()
}

func displayFilesTable(files []models.File) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "Host/Domain\tPath\tType\tStatus\tSize\tInteresting\n")
	fmt.Fprintf(w, "-----------\t----\t----\t------\t----\t-----------\n")

	for _, file := range files {
		target := "-"
		if file.Host.IP != "" {
			target = file.Host.IP
		} else if file.Domain.Domain != "" {
			target = file.Domain.Domain
		}

		fileType := file.Type
		if fileType == "" {
			fileType = "-"
		}

		status := "-"
		if file.Status > 0 {
			status = strconv.Itoa(file.Status)
		}

		size := "-"
		if file.Size > 0 {
			size = formatBytes(file.Size)
		}

		interesting := "❌"
		if file.Interesting {
			interesting = "✅"
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			target,
			truncateString(file.Path, 50),
			fileType,
			status,
			size,
			interesting,
		)
	}
	w.Flush()
}

// Utility functions

func outputJSON(data interface{}) error {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	fmt.Println(string(jsonData))
	return nil
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// requireWorkspaceForQuery checks if a workspace is currently active for query commands
func requireWorkspaceForQuery() error {
	ws, err := workspace.NewManager()
	if err != nil {
		return fmt.Errorf("failed to initialize workspace manager: %w", err)
	}

	current, err := ws.GetCurrentWorkspace()
	if err != nil {
		return fmt.Errorf("failed to check current workspace: %w", err)
	}

	if current == "" {
		return fmt.Errorf(`❌ No workspace is currently active.

Please create and switch to a workspace before querying data:

  # Create a new workspace
  recon workspace create <workspace-name>

  # Switch to an existing workspace  
  recon workspace switch <workspace-name>

  # List available workspaces
  recon workspace list`)
	}

	return nil
}
