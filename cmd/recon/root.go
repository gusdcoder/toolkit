package recon

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile    string
	verbose    bool
	debug      bool
	dbType     string
	dbHost     string
	dbPort     int
	dbUser     string
	dbPassword string
	dbName     string
	dbSSLMode  string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "recon",
	Short: "Enterprise-grade reconnaissance platform",
	Long: `Recon Platform - A comprehensive reconnaissance tool that integrates 50+ Kali Linux tools
with ProjectDiscovery tools into a unified, intelligent framework with database persistence
and advanced correlation capabilities.

Features:
• 50+ integrated security tools (Nmap, Nuclei, Subfinder, etc.)
• Intelligent scanning pipeline with context-aware decisions
• Persistent loot database with advanced correlation
• Horizontal and vertical reconnaissance capabilities
• Real-time dashboards and comprehensive reporting

For detailed documentation, visit: https://toolkit/`,
	Version: "0.1.0",
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "",
		"config file (default is $HOME/.recon-platform/config.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false,
		"verbose output")
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false,
		"debug output")

	// Database flags
	rootCmd.PersistentFlags().StringVar(&dbType, "db-type", "postgres",
		"database type (postgres, memory)")
	rootCmd.PersistentFlags().StringVar(&dbHost, "db-host", "localhost",
		"database host")
	rootCmd.PersistentFlags().IntVar(&dbPort, "db-port", 5432,
		"database port")
	rootCmd.PersistentFlags().StringVar(&dbUser, "db-user", "postgres",
		"database user")
	rootCmd.PersistentFlags().StringVar(&dbPassword, "db-password", "postgres",
		"database password")
	rootCmd.PersistentFlags().StringVar(&dbName, "db-name", "recon_platform",
		"database name")
	rootCmd.PersistentFlags().StringVar(&dbSSLMode, "db-sslmode", "disable",
		"database SSL mode (disable, require, verify-ca, verify-full)")

	// Bind flags to viper
	viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))
	viper.BindPFlag("debug", rootCmd.PersistentFlags().Lookup("debug"))
	viper.BindPFlag("database.type", rootCmd.PersistentFlags().Lookup("db-type"))
	viper.BindPFlag("database.host", rootCmd.PersistentFlags().Lookup("db-host"))
	viper.BindPFlag("database.port", rootCmd.PersistentFlags().Lookup("db-port"))
	viper.BindPFlag("database.user", rootCmd.PersistentFlags().Lookup("db-user"))
	viper.BindPFlag("database.password", rootCmd.PersistentFlags().Lookup("db-password"))
	viper.BindPFlag("database.dbname", rootCmd.PersistentFlags().Lookup("db-name"))
	viper.BindPFlag("database.sslmode", rootCmd.PersistentFlags().Lookup("db-sslmode"))
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		configDir := filepath.Join(home, ".recon-platform")

		// Create config directory if it doesn't exist
		if err := os.MkdirAll(configDir, 0755); err != nil {
			fmt.Printf("Warning: Failed to create config directory: %v\n", err)
		}

		// Search config in home directory with name "config" (without extension).
		viper.AddConfigPath(configDir)
		viper.SetConfigType("yaml")
		viper.SetConfigName("config")
	}

	viper.SetEnvPrefix("RECON")
	viper.AutomaticEnv() // read in environment variables that match

	// Set default values
	setDefaults()

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil && viper.GetBool("verbose") {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}

func setDefaults() {
	// Database defaults
	viper.SetDefault("database.type", "postgres")
	viper.SetDefault("database.host", "localhost")
	viper.SetDefault("database.port", 5432)
	viper.SetDefault("database.user", "postgres")
	viper.SetDefault("database.password", "postgres")
	viper.SetDefault("database.dbname", "recon_platform")
	viper.SetDefault("database.sslmode", "disable")
	viper.SetDefault("database.sslmode", "disable")

	// Scanning defaults
	viper.SetDefault("scan.threads", 50)
	viper.SetDefault("scan.timeout", 30)
	viper.SetDefault("scan.rate_limit", 1000)
	viper.SetDefault("scan.retries", 3)

	// Tool defaults
	viper.SetDefault("tools.nmap.path", "nmap")
	viper.SetDefault("tools.nuclei.path", "nuclei")
	viper.SetDefault("tools.subfinder.path", "subfinder")
	viper.SetDefault("tools.naabu.path", "naabu")
	viper.SetDefault("tools.httpx.path", "httpx")
	viper.SetDefault("tools.katana.path", "katana")

	// Output defaults
	viper.SetDefault("output.format", "json")
	viper.SetDefault("output.directory", "./output")
	viper.SetDefault("output.timestamp", true)
}
