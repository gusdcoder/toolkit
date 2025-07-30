package recon

import (
	"fmt"
	"os"
	"time"
	
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/recon-platform/core/internal/database"
	"github.com/recon-platform/core/internal/pipeline"
)

var (
	target      string
	domains     []string
	vertical    bool
	horizontal  bool
	allTools    bool
	outputDir   string
	outputFile  string
	tools       []string
	threads     int
	timeout     int
)

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Execute reconnaissance scan",
	Long: `Execute comprehensive reconnaissance scan using integrated tools.

Examples:
  # Basic domain scan
  recon scan -d example.com
  
  # Vertical scan (deep dive)
  recon scan -d example.com --vertical
  
  # Horizontal scan (broad discovery)
  recon scan -d example.com --horizontal
  
  # Use all available tools
  recon scan -d example.com --all-tools
  
  # Specify custom tools
  recon scan -d example.com --tools nmap,nuclei,subfinder
  
  # Network range scan
  recon scan -t 10.0.0.0/24 --vertical`,
	RunE: runScan,
}

func init() {
	rootCmd.AddCommand(scanCmd)
	
	// Scan flags
	scanCmd.Flags().StringVarP(&target, "target", "t", "", 
		"target IP, CIDR, or hostname")
	scanCmd.Flags().StringSliceVarP(&domains, "domain", "d", []string{}, 
		"domain(s) to scan (can be used multiple times)")
	scanCmd.Flags().BoolVar(&vertical, "vertical", false, 
		"enable vertical scanning (deep dive)")
	scanCmd.Flags().BoolVar(&horizontal, "horizontal", false, 
		"enable horizontal scanning (broad discovery)")
	scanCmd.Flags().BoolVar(&allTools, "all-tools", false, 
		"use all available tools")
	scanCmd.Flags().StringSliceVar(&tools, "tools", []string{}, 
		"specific tools to use (comma-separated)")
	scanCmd.Flags().StringVarP(&outputDir, "output", "o", "", 
		"output directory")
	scanCmd.Flags().StringVar(&outputFile, "output-file", "", 
		"output file path")
	scanCmd.Flags().IntVar(&threads, "threads", 0, 
		"number of threads (default: from config)")
	scanCmd.Flags().IntVar(&timeout, "timeout", 0, 
		"timeout in seconds (default: from config)")
	
	// Mark required flags
	scanCmd.MarkFlagsOneRequired("target", "domain")
}

func runScan(cmd *cobra.Command, args []string) error {
	// Validate input
	if target == "" && len(domains) == 0 {
		return fmt.Errorf("must specify either --target or --domain")
	}
	
	// Initialize database
	dbConfig := &database.Config{
		Type:    viper.GetString("database.type"),
		Host:    viper.GetString("database.host"),
		Port:    viper.GetInt("database.port"),
		User:    viper.GetString("database.user"),
		Password: viper.GetString("database.password"),
		DBName:  viper.GetString("database.dbname"),
		SSLMode: viper.GetString("database.sslmode"),
		DataDir: getDataDir(),
	}
	
	db, err := database.NewDatabase(dbConfig)
	if err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
	}
	defer db.Close()
	
	// Create scan configuration
	scanConfig := &pipeline.ScanConfig{
		Target:     target,
		Domains:    domains,
		Vertical:   vertical,
		Horizontal: horizontal,
		AllTools:   allTools,
		Tools:      tools,
		Threads:    getThreads(),
		Timeout:    getTimeout(),
		OutputDir:  getOutputDir(),
		Verbose:    viper.GetBool("verbose"),
		Debug:      viper.GetBool("debug"),
	}
	
	// Initialize pipeline
	reconPipeline := pipeline.NewPipeline(db, scanConfig)
	
	// Start scan
	fmt.Printf("🚀 Starting reconnaissance scan...\n")
	fmt.Printf("Target: %s\n", getTargetDisplay())
	fmt.Printf("Mode: %s\n", getScanMode())
	fmt.Printf("Tools: %s\n", getToolsDisplay())
	fmt.Printf("Started: %s\n\n", time.Now().Format("2006-01-02 15:04:05"))
	
	results, err := reconPipeline.Execute()
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}
	
	// Display results summary
	displayResults(results)
	
	return nil
}

func getDataDir() string {
	home, _ := os.UserHomeDir()
	return fmt.Sprintf("%s/.recon-platform", home)
}

func getThreads() int {
	if threads > 0 {
		return threads
	}
	return viper.GetInt("scan.threads")
}

func getTimeout() int {
	if timeout > 0 {
		return timeout
	}
	return viper.GetInt("scan.timeout")
}

func getOutputDir() string {
	if outputDir != "" {
		return outputDir
	}
	return viper.GetString("output.directory")
}

func getTargetDisplay() string {
	if target != "" {
		return target
	}
	if len(domains) == 1 {
		return domains[0]
	}
	return fmt.Sprintf("%d domains", len(domains))
}

func getScanMode() string {
	modes := []string{}
	if vertical {
		modes = append(modes, "Vertical")
	}
	if horizontal {
		modes = append(modes, "Horizontal")
	}
	if len(modes) == 0 {
		return "Standard"
	}
	return fmt.Sprintf("%v", modes)
}

func getToolsDisplay() string {
	if allTools {
		return "All available tools"
	}
	if len(tools) > 0 {
		return fmt.Sprintf("%v", tools)
	}
	return "Auto-selected tools"
}

func displayResults(results *pipeline.ScanResults) {
	if results == nil {
		fmt.Println("❌ No results to display")
		return
	}
	
	fmt.Printf("✅ Scan completed successfully!\n\n")
	fmt.Printf("📊 Results Summary:\n")
	fmt.Printf("  • Hosts discovered: %d\n", results.HostsFound)
	fmt.Printf("  • Open ports: %d\n", results.OpenPorts)
	fmt.Printf("  • Domains found: %d\n", results.DomainsFound)
	fmt.Printf("  • Vulnerabilities: %d\n", results.VulnerabilitiesFound)
	fmt.Printf("  • Services identified: %d\n", results.ServicesFound)
	fmt.Printf("  • Files discovered: %d\n", results.FilesFound)
	
	if results.VulnerabilitiesFound > 0 {
		fmt.Printf("\n🚨 Vulnerability Breakdown:\n")
		for severity, count := range results.VulnerabilityStats {
			if count > 0 {
				emoji := getVulnEmoji(severity)
				fmt.Printf("  %s %s: %d\n", emoji, severity, count)
			}
		}
	}
	
	fmt.Printf("\n⏱️  Scan Duration: %s\n", results.Duration)
	fmt.Printf("📁 Results saved to database\n")
	
	if results.OutputFile != "" {
		fmt.Printf("📄 Report saved: %s\n", results.OutputFile)
	}
	
	fmt.Printf("\n💡 Use 'recon query' to explore the results\n")
}

func getVulnEmoji(severity string) string {
	switch severity {
	case "critical":
		return "🔴"
	case "high":
		return "🟠"
	case "medium":
		return "🟡"
	case "low":
		return "🔵"
	case "info":
		return "ℹ️"
	default:
		return "❓"
	}
}