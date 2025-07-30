package database

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"toolkit/pkg/models"

	"gorm.io/driver/postgres"
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

// Database interface for different implementations
type DatabaseInterface interface {
	CreateHost(host *models.Host) error
	GetHostByIP(ip string) (*models.Host, error)
	GetHostsByIP(ip string) ([]models.Host, error)
	GetAllHosts() ([]models.Host, error)
	UpdateHost(host *models.Host) error
	CreatePort(port *models.Port) error
	GetOpenPorts() ([]models.Port, error)
	CreateService(service *models.Service) error
	GetAllServices() ([]models.Service, error)
	CreateVulnerability(vuln *models.Vulnerability) error
	GetVulnerabilityStats() (map[string]int64, error)
	CreateDomain(domain *models.Domain) error
	GetAllDomains() ([]models.Domain, error)
	CreateSession(session *models.ScanSession) error
	UpdateSession(session *models.ScanSession) error
	SearchByKeyword(keyword string) (map[string]interface{}, error)
	GetCounts() (map[string]int64, error)
	Close() error
	Health() error
}

// DatabaseWrapper wraps either GORM or Memory database
type DatabaseWrapper struct {
	DB     *gorm.DB
	Memory *MemoryDatabase
	Type   string
}

// NewDatabase creates a new database connection with fallback to memory
func NewDatabase(config *Config) (*DatabaseWrapper, error) {
	// Try PostgreSQL first if specified or as default
	if config.Type == "postgres" || config.Type == "postgresql" {
		dbWrapper, err := newPostgresDatabase(config)
		if err != nil {
			log.Printf("⚠️  PostgreSQL connection failed: %v", err)
			log.Printf("📋 Falling back to in-memory database...")

			// Fallback to memory database
			memDB, memErr := NewMemoryDatabase(config.DataDir)
			if memErr != nil {
				return nil, fmt.Errorf("failed to create memory database: %w", memErr)
			}

			return &DatabaseWrapper{
				Memory: memDB,
				Type:   "memory",
			}, nil
		}

		log.Printf("🐘 Connected to PostgreSQL database successfully")
		return dbWrapper, nil
	}

	// For memory or other types, use memory database
	log.Printf("Using in-memory database (JSON persistence) for development")
	memDB, err := NewMemoryDatabase(config.DataDir)
	if err != nil {
		return nil, fmt.Errorf("failed to create memory database: %w", err)
	}

	return &DatabaseWrapper{
		Memory: memDB,
		Type:   "memory",
	}, nil
}

func newPostgresDatabase(config *Config) (*DatabaseWrapper, error) {
	// Configure GORM logger
	gormConfig := &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	}

	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%d sslmode=%s",
		config.Host, config.User, config.Password, config.DBName, config.Port, config.SSLMode)
	db, err := gorm.Open(postgres.Open(dsn), gormConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to PostgreSQL: %w", err)
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

	return &DatabaseWrapper{
		DB:   db,
		Type: "postgres",
	}, nil
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

// DatabaseWrapper methods - delegate to appropriate implementation

func (d *DatabaseWrapper) CreateHost(host *models.Host) error {
	if d.Type == "memory" {
		return d.Memory.CreateHost(host)
	}
	return d.DB.Create(host).Error
}

func (d *DatabaseWrapper) GetHostByIP(ip string) (*models.Host, error) {
	if d.Type == "memory" {
		return d.Memory.GetHostByIP(ip)
	}
	var host models.Host
	err := d.DB.Where("ip = ?", ip).First(&host).Error
	return &host, err
}

func (d *DatabaseWrapper) GetHostsByIP(ip string) ([]models.Host, error) {
	if d.Type == "memory" {
		return d.Memory.GetHostsByIP(ip)
	}
	var hosts []models.Host
	err := d.DB.Where("ip = ?", ip).Find(&hosts).Error
	return hosts, err
}

func (d *DatabaseWrapper) GetAllHosts() ([]models.Host, error) {
	if d.Type == "memory" {
		return d.Memory.GetAllHosts()
	}
	var hosts []models.Host
	err := d.DB.Find(&hosts).Error
	return hosts, err
}

func (d *DatabaseWrapper) CreatePort(port *models.Port) error {
	if d.Type == "memory" {
		return d.Memory.CreatePort(port)
	}
	return d.DB.Create(port).Error
}

func (d *DatabaseWrapper) CreateService(service *models.Service) error {
	if d.Type == "memory" {
		return d.Memory.CreateService(service)
	}
	return d.DB.Create(service).Error
}

func (d *DatabaseWrapper) GetAllServices() ([]models.Service, error) {
	if d.Type == "memory" {
		return d.Memory.GetAllServices()
	}
	var services []models.Service
	err := d.DB.Preload("Host").Find(&services).Error
	return services, err
}

func (d *DatabaseWrapper) GetOpenPorts() ([]models.Port, error) {
	if d.Type == "memory" {
		return d.Memory.GetOpenPorts()
	}
	var ports []models.Port
	err := d.DB.Where("state = ?", "open").Preload("Host").Find(&ports).Error
	return ports, err
}

func (d *DatabaseWrapper) CreateVulnerability(vuln *models.Vulnerability) error {
	if d.Type == "memory" {
		return d.Memory.CreateVulnerability(vuln)
	}
	return d.DB.Create(vuln).Error
}

func (d *DatabaseWrapper) GetVulnerabilityStats() (map[string]int64, error) {
	if d.Type == "memory" {
		return d.Memory.GetVulnerabilityStats()
	}

	stats := make(map[string]int64)
	severities := []string{"critical", "high", "medium", "low", "info"}

	for _, severity := range severities {
		var count int64
		err := d.DB.Model(&models.Vulnerability{}).
			Where("severity = ?", severity).
			Count(&count).Error
		if err != nil {
			return nil, err
		}
		stats[severity] = count
	}

	return stats, nil
}

func (d *DatabaseWrapper) SearchByKeyword(keyword string) (map[string]interface{}, error) {
	if d.Type == "memory" {
		return d.Memory.SearchByKeyword(keyword)
	}

	results := make(map[string]interface{})

	// Search hosts
	var hosts []models.Host
	d.DB.Where("ip LIKE ? OR hostname LIKE ?", "%"+keyword+"%", "%"+keyword+"%").Find(&hosts)
	results["hosts"] = hosts

	// Search domains
	var domains []models.Domain
	d.DB.Where("domain LIKE ? OR title LIKE ?", "%"+keyword+"%", "%"+keyword+"%").Find(&domains)
	results["domains"] = domains

	// Search vulnerabilities
	var vulns []models.Vulnerability
	d.DB.Where("name LIKE ? OR cve LIKE ?", "%"+keyword+"%", "%"+keyword+"%").
		Preload("Host").Find(&vulns)
	results["vulnerabilities"] = vulns

	return results, nil
}

func (d *DatabaseWrapper) GetCounts() (map[string]int64, error) {
	if d.Type == "memory" {
		return d.Memory.GetCounts()
	}

	counts := make(map[string]int64)

	// Count various entities
	var hostCount, portCount, domainCount, vulnCount, serviceCount, fileCount, openPortCount int64
	d.DB.Model(&models.Host{}).Count(&hostCount)
	d.DB.Model(&models.Port{}).Count(&portCount)
	d.DB.Model(&models.Domain{}).Count(&domainCount)
	d.DB.Model(&models.Vulnerability{}).Count(&vulnCount)
	d.DB.Model(&models.Service{}).Count(&serviceCount)
	d.DB.Model(&models.File{}).Count(&fileCount)
	d.DB.Model(&models.Port{}).Where("state = ?", "open").Count(&openPortCount)

	counts["hosts"] = hostCount
	counts["ports"] = portCount
	counts["domains"] = domainCount
	counts["vulnerabilities"] = vulnCount
	counts["services"] = serviceCount
	counts["files"] = fileCount
	counts["open_ports"] = openPortCount

	return counts, nil
}

func (d *DatabaseWrapper) CreateSession(session *models.ScanSession) error {
	if d.Type == "memory" {
		return d.Memory.CreateSession(session)
	}
	return d.DB.Create(session).Error
}

func (d *DatabaseWrapper) UpdateSession(session *models.ScanSession) error {
	if d.Type == "memory" {
		return d.Memory.UpdateSession(session)
	}
	return d.DB.Save(session).Error
}

func (d *DatabaseWrapper) GetAllDomains() ([]models.Domain, error) {
	if d.Type == "memory" {
		return d.Memory.GetAllDomains()
	}
	var domains []models.Domain
	err := d.DB.Find(&domains).Error
	return domains, err
}

func (d *DatabaseWrapper) CreateDomain(domain *models.Domain) error {
	if d.Type == "memory" {
		return d.Memory.CreateDomain(domain)
	}
	return d.DB.Create(domain).Error
}

// Close closes the database connection
func (d *DatabaseWrapper) Close() error {
	if d.Type == "memory" {
		return d.Memory.Close()
	}

	sqlDB, err := d.DB.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// Health checks database connection health
func (d *DatabaseWrapper) Health() error {
	if d.Type == "memory" {
		return d.Memory.Health()
	}

	sqlDB, err := d.DB.DB()
	if err != nil {
		return err
	}
	return sqlDB.Ping()
}

// GetDefaultConfig returns default database configuration
func GetDefaultConfig() *Config {
	homeDir, _ := os.UserHomeDir()
	dataDir := filepath.Join(homeDir, ".recon-platform")

	return &Config{
		Type:     "postgres", // Default to PostgreSQL
		Host:     "localhost",
		Port:     5432,
		User:     "postgres",
		Password: "postgres",
		DBName:   "recon_platform",
		SSLMode:  "disable",
		DataDir:  dataDir,
	}
}

// GetMemoryConfig returns memory database configuration as fallback
func GetMemoryConfig() *Config {
	homeDir, _ := os.UserHomeDir()
	dataDir := filepath.Join(homeDir, ".recon-platform")

	return &Config{
		Type:    "memory",
		DataDir: dataDir,
	}
}
