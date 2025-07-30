package database

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	
	"github.com/recon-platform/core/pkg/models"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type Database struct {
	DB *gorm.DB
}

type Config struct {
	Type     string // sqlite, postgres
	Host     string
	Port     int
	User     string
	Password string
	DBName   string
	SSLMode  string
	DataDir  string
}

// NewDatabase creates a new database connection
func NewDatabase(config *Config) (*Database, error) {
	var db *gorm.DB
	var err error
	
	// Configure GORM logger
	gormConfig := &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	}
	
	switch config.Type {
	case "postgres", "postgresql":
		dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%d sslmode=%s",
			config.Host, config.User, config.Password, config.DBName, config.Port, config.SSLMode)
		db, err = gorm.Open(postgres.Open(dsn), gormConfig)
	case "sqlite", "":
		// Default to SQLite for development
		dbPath := filepath.Join(config.DataDir, "recon.db")
		
		// Create data directory if it doesn't exist
		if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
			return nil, fmt.Errorf("failed to create data directory: %w", err)
		}
		
		db, err = gorm.Open(sqlite.Open(dbPath), gormConfig)
	default:
		return nil, fmt.Errorf("unsupported database type: %s", config.Type)
	}
	
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}
	
	// Auto-migrate the schema
	if err := db.AutoMigrate(
		&models.Host{},
		&models.Port{},
		&models.Domain{},
		&models.Vulnerability{},
		&models.Network{},
		&models.Service{},
		&models.Credential{},
		&models.File{},
		&models.ScanSession{},
	); err != nil {
		return nil, fmt.Errorf("failed to migrate database schema: %w", err)
	}
	
	// Create indexes for better performance
	if err := createIndexes(db); err != nil {
		log.Printf("Warning: failed to create some indexes: %v", err)
	}
	
	return &Database{DB: db}, nil
}

// createIndexes creates additional database indexes for performance
func createIndexes(db *gorm.DB) error {
	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_hosts_ip_status ON hosts(ip, status)",
		"CREATE INDEX IF NOT EXISTS idx_ports_host_port ON ports(host_id, port)",
		"CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity)",
		"CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cve ON vulnerabilities(cve)",
		"CREATE INDEX IF NOT EXISTS idx_domains_ip ON domains(ip)",
		"CREATE INDEX IF NOT EXISTS idx_services_name ON services(name)",
		"CREATE INDEX IF NOT EXISTS idx_files_type ON files(type)",
	}
	
	for _, index := range indexes {
		if err := db.Exec(index).Error; err != nil {
			log.Printf("Failed to create index: %s - %v", index, err)
		}
	}
	
	return nil
}

// Close closes the database connection
func (d *Database) Close() error {
	sqlDB, err := d.DB.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// GetDefaultConfig returns default database configuration
func GetDefaultConfig() *Config {
	homeDir, _ := os.UserHomeDir()
	dataDir := filepath.Join(homeDir, ".recon-platform")
	
	return &Config{
		Type:    "sqlite",
		DataDir: dataDir,
	}
}

// Health checks database connection health
func (d *Database) Health() error {
	sqlDB, err := d.DB.DB()
	if err != nil {
		return err
	}
	return sqlDB.Ping()
}