package recon

import (
	"fmt"
	"os"
	"strings"
	"syscall"

	"toolkit/internal/database"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/term"
)

// getConfigString returns a config string value or default if empty
func getConfigString(key, defaultValue string) string {
	value := viper.GetString(key)
	if value == "" {
		return defaultValue
	}
	return value
}

// getConfigInt returns a config int value or default if zero
func getConfigInt(key string, defaultValue int) int {
	value := viper.GetInt(key)
	if value == 0 {
		return defaultValue
	}
	return value
}

// configCmd represents the config command
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage configuration settings",
	Long: `Manage configuration settings for the recon platform.

This command allows you to configure database connections, tool paths,
and other settings for the reconnaissance platform.`,
}

// configDbCmd represents the config db command
var configDbCmd = &cobra.Command{
	Use:   "db",
	Short: "Configure database settings",
	Long: `Configure database connection settings.

Examples:
  # Test current database connection
  recon config db test

  # Setup PostgreSQL interactively
  recon config db setup

  # Reset to default settings
  recon config db reset`,
}

// configDbTestCmd tests the database connection
var configDbTestCmd = &cobra.Command{
	Use:   "test",
	Short: "Test database connection",
	Long:  `Test the current database connection settings.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return testDatabaseConnection()
	},
}

// configDbSetupCmd sets up database configuration
var configDbSetupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Setup database configuration interactively",
	Long:  `Setup database configuration through an interactive process.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return setupDatabaseConfiguration()
	},
}

// configDbResetCmd resets database configuration to defaults
var configDbResetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Reset database configuration to defaults",
	Long:  `Reset database configuration to default values.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return resetDatabaseConfiguration()
	},
}

func init() {
	rootCmd.AddCommand(configCmd)
	configCmd.AddCommand(configDbCmd)
	configDbCmd.AddCommand(configDbTestCmd)
	configDbCmd.AddCommand(configDbSetupCmd)
	configDbCmd.AddCommand(configDbResetCmd)
}

func testDatabaseConnection() error {
	fmt.Println("🔍 Testing database connection...")

	// Get current configuration
	dbConfig := &database.Config{
		Type:     getConfigString("database.type", "postgres"),
		Host:     getConfigString("database.host", "localhost"),
		Port:     getConfigInt("database.port", 5432),
		User:     getConfigString("database.user", "postgres"),
		Password: getConfigString("database.password", "postgres"),
		DBName:   getConfigString("database.dbname", "recon_platform"),
		SSLMode:  getConfigString("database.sslmode", "disable"),
		DataDir:  getDataDir(),
	}

	fmt.Printf("Configuration:\n")
	fmt.Printf("  Type: %s\n", dbConfig.Type)
	if dbConfig.Type == "postgres" {
		fmt.Printf("  Host: %s\n", dbConfig.Host)
		fmt.Printf("  Port: %d\n", dbConfig.Port)
		fmt.Printf("  User: %s\n", dbConfig.User)
		fmt.Printf("  Database: %s\n", dbConfig.DBName)
		fmt.Printf("  SSL Mode: %s\n", dbConfig.SSLMode)
	} else {
		fmt.Printf("  Data Directory: %s\n", dbConfig.DataDir)
	}

	// Test connection
	db, err := database.NewDatabase(dbConfig)
	if err != nil {
		fmt.Printf("❌ Connection failed: %v\n", err)
		return err
	}
	defer db.Close()

	// Test health
	if err := db.Health(); err != nil {
		fmt.Printf("❌ Health check failed: %v\n", err)
		return err
	}

	fmt.Printf("✅ Database connection successful!\n")
	return nil
}

func setupDatabaseConfiguration() error {
	fmt.Println("🔧 Setting up database configuration...")
	fmt.Println()

	// Ask for database type
	fmt.Print("Database type (postgres/memory) [postgres]: ")
	var dbType string
	fmt.Scanln(&dbType)
	if dbType == "" {
		dbType = "postgres"
	}

	if dbType == "memory" {
		viper.Set("database.type", "memory")
		fmt.Println("✅ Configured to use in-memory database")
		return saveConfiguration()
	}

	// PostgreSQL configuration
	fmt.Println("\n📊 PostgreSQL Configuration:")

	fmt.Print("Host [localhost]: ")
	var host string
	fmt.Scanln(&host)
	if host == "" {
		host = "localhost"
	}

	fmt.Print("Port [5432]: ")
	var port string
	fmt.Scanln(&port)
	if port == "" {
		port = "5432"
	}

	fmt.Print("Database name [recon_platform]: ")
	var dbname string
	fmt.Scanln(&dbname)
	if dbname == "" {
		dbname = "recon_platform"
	}

	fmt.Print("Username [postgres]: ")
	var username string
	fmt.Scanln(&username)
	if username == "" {
		username = "postgres"
	}

	fmt.Print("Password: ")
	passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}
	password := string(passwordBytes)
	fmt.Println() // New line after password input

	fmt.Print("SSL Mode (disable/require/verify-ca/verify-full) [disable]: ")
	var sslmode string
	fmt.Scanln(&sslmode)
	if sslmode == "" {
		sslmode = "disable"
	}

	// Set configuration
	viper.Set("database.type", "postgres")
	viper.Set("database.host", host)
	viper.Set("database.port", port)
	viper.Set("database.user", username)
	viper.Set("database.password", password)
	viper.Set("database.dbname", dbname)
	viper.Set("database.sslmode", sslmode)

	// Test the configuration
	fmt.Println("\n🔍 Testing connection...")
	if err := testDatabaseConnection(); err != nil {
		fmt.Printf("❌ Configuration test failed: %v\n", err)
		fmt.Println("Please check your settings and try again.")
		return err
	}

	// Save configuration
	if err := saveConfiguration(); err != nil {
		return err
	}

	fmt.Println("✅ Database configuration saved successfully!")
	return nil
}

func resetDatabaseConfiguration() error {
	fmt.Println("🔄 Resetting database configuration to defaults...")

	// Set default values
	viper.Set("database.type", "postgres")
	viper.Set("database.host", "localhost")
	viper.Set("database.port", 5432)
	viper.Set("database.user", "postgres")
	viper.Set("database.password", "postgres")
	viper.Set("database.dbname", "recon_platform")
	viper.Set("database.sslmode", "disable")

	if err := saveConfiguration(); err != nil {
		return err
	}

	fmt.Println("✅ Configuration reset to defaults!")
	return nil
}

func saveConfiguration() error {
	// Get config file path
	configFile := viper.ConfigFileUsed()
	if configFile == "" {
		// Create default config file
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}

		configDir := fmt.Sprintf("%s/.recon-platform", home)
		configFile = fmt.Sprintf("%s/config.yaml", configDir)

		// Create directory if it doesn't exist
		if err := os.MkdirAll(configDir, 0755); err != nil {
			return fmt.Errorf("failed to create config directory: %w", err)
		}

		viper.SetConfigFile(configFile)
	}

	// Write configuration
	if err := viper.WriteConfig(); err != nil {
		// If config file doesn't exist, create it
		if strings.Contains(err.Error(), "not found") {
			if err := viper.SafeWriteConfig(); err != nil {
				return fmt.Errorf("failed to create config file: %w", err)
			}
		} else {
			return fmt.Errorf("failed to save config: %w", err)
		}
	}

	fmt.Printf("Configuration saved to: %s\n", configFile)
	return nil
}
