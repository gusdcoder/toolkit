package database

import (
	"time"

	"toolkit/pkg/models"

	"gorm.io/gorm"
)

// HostRepository provides database operations for hosts
type HostRepository struct {
	db *gorm.DB
}

// NewHostRepository creates a new host repository
func NewHostRepository(db *gorm.DB) *HostRepository {
	return &HostRepository{db: db}
}

// CreateOrUpdateHost creates a new host or updates existing one
func (r *HostRepository) CreateOrUpdateHost(host *models.Host) error {
	var existing models.Host
	result := r.db.Where("ip = ?", host.IP).First(&existing)

	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			// Create new host
			host.FirstSeen = time.Now()
			host.LastSeen = time.Now()
			return r.db.Create(host).Error
		}
		return result.Error
	}

	// Update existing host
	existing.Hostname = host.Hostname
	existing.Status = host.Status
	existing.OS = host.OS
	existing.OSVersion = host.OSVersion
	existing.MAC = host.MAC
	existing.TTL = host.TTL
	existing.LastSeen = time.Now()

	return r.db.Save(&existing).Error
}

// GetHostByIP retrieves a host by IP address
func (r *HostRepository) GetHostByIP(ip string) (*models.Host, error) {
	var host models.Host
	err := r.db.Where("ip = ?", ip).
		Preload("Ports").
		Preload("Services").
		Preload("Vulnerabilities").
		Preload("Credentials").
		Preload("Files").
		First(&host).Error

	if err != nil {
		return nil, err
	}
	return &host, nil
}

// GetAllHosts retrieves all hosts with optional filters
func (r *HostRepository) GetAllHosts(status string, limit, offset int) ([]models.Host, error) {
	var hosts []models.Host
	query := r.db.Model(&models.Host{})

	if status != "" {
		query = query.Where("status = ?", status)
	}

	if limit > 0 {
		query = query.Limit(limit)
	}

	if offset > 0 {
		query = query.Offset(offset)
	}

	err := query.Find(&hosts).Error
	return hosts, err
}

// VulnerabilityRepository provides database operations for vulnerabilities
type VulnerabilityRepository struct {
	db *gorm.DB
}

// NewVulnerabilityRepository creates a new vulnerability repository
func NewVulnerabilityRepository(db *gorm.DB) *VulnerabilityRepository {
	return &VulnerabilityRepository{db: db}
}

// CreateVulnerability creates a new vulnerability
func (r *VulnerabilityRepository) CreateVulnerability(vuln *models.Vulnerability) error {
	return r.db.Create(vuln).Error
}

// GetVulnerabilitiesBySeverity retrieves vulnerabilities by severity
func (r *VulnerabilityRepository) GetVulnerabilitiesBySeverity(severity string) ([]models.Vulnerability, error) {
	var vulns []models.Vulnerability
	err := r.db.Where("severity = ?", severity).
		Preload("Host").
		Find(&vulns).Error
	return vulns, err
}

// GetVulnerabilityStats returns vulnerability statistics
func (r *VulnerabilityRepository) GetVulnerabilityStats() (map[string]int64, error) {
	stats := make(map[string]int64)

	severities := []string{"critical", "high", "medium", "low", "info"}

	for _, severity := range severities {
		var count int64
		err := r.db.Model(&models.Vulnerability{}).
			Where("severity = ?", severity).
			Count(&count).Error
		if err != nil {
			return nil, err
		}
		stats[severity] = count
	}

	return stats, nil
}

// PortRepository provides database operations for ports
type PortRepository struct {
	db *gorm.DB
}

// NewPortRepository creates a new port repository
func NewPortRepository(db *gorm.DB) *PortRepository {
	return &PortRepository{db: db}
}

// CreateOrUpdatePort creates a new port or updates existing one
func (r *PortRepository) CreateOrUpdatePort(port *models.Port) error {
	var existing models.Port
	result := r.db.Where("host_id = ? AND port = ? AND protocol = ?",
		port.HostID, port.Port, port.Protocol).First(&existing)

	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return r.db.Create(port).Error
		}
		return result.Error
	}

	// Update existing port
	existing.State = port.State
	existing.Service = port.Service
	existing.Version = port.Version
	existing.Banner = port.Banner

	return r.db.Save(&existing).Error
}

// GetOpenPorts retrieves all open ports
func (r *PortRepository) GetOpenPorts() ([]models.Port, error) {
	var ports []models.Port
	err := r.db.Where("state = ?", "open").
		Preload("Host").
		Find(&ports).Error
	return ports, err
}

// DomainRepository provides database operations for domains
type DomainRepository struct {
	db *gorm.DB
}

// NewDomainRepository creates a new domain repository
func NewDomainRepository(db *gorm.DB) *DomainRepository {
	return &DomainRepository{db: db}
}

// CreateOrUpdateDomain creates a new domain or updates existing one
func (r *DomainRepository) CreateOrUpdateDomain(domain *models.Domain) error {
	var existing models.Domain
	result := r.db.Where("domain = ?", domain.Domain).First(&existing)

	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			domain.FirstSeen = time.Now()
			domain.LastSeen = time.Now()
			return r.db.Create(domain).Error
		}
		return result.Error
	}

	// Update existing domain
	existing.IP = domain.IP
	existing.Technologies = domain.Technologies
	existing.Status = domain.Status
	existing.Title = domain.Title
	existing.Server = domain.Server
	existing.ContentType = domain.ContentType
	existing.Certificates = domain.Certificates
	existing.LastSeen = time.Now()

	return r.db.Save(&existing).Error
}

// GetDomainsByIP retrieves domains by IP address
func (r *DomainRepository) GetDomainsByIP(ip string) ([]models.Domain, error) {
	var domains []models.Domain
	err := r.db.Where("ip = ?", ip).Find(&domains).Error
	return domains, err
}

// SearchRepository provides advanced search capabilities
type SearchRepository struct {
	db *gorm.DB
}

// NewSearchRepository creates a new search repository
func NewSearchRepository(db *gorm.DB) *SearchRepository {
	return &SearchRepository{db: db}
}

// SearchByKeyword performs keyword search across multiple tables
func (r *SearchRepository) SearchByKeyword(keyword string) (map[string]interface{}, error) {
	results := make(map[string]interface{})

	// Search hosts
	var hosts []models.Host
	r.db.Where("ip LIKE ? OR hostname LIKE ? OR os LIKE ?",
		"%"+keyword+"%", "%"+keyword+"%", "%"+keyword+"%").Find(&hosts)
	results["hosts"] = hosts

	// Search domains
	var domains []models.Domain
	r.db.Where("domain LIKE ? OR subdomain LIKE ? OR title LIKE ?",
		"%"+keyword+"%", "%"+keyword+"%", "%"+keyword+"%").Find(&domains)
	results["domains"] = domains

	// Search vulnerabilities
	var vulns []models.Vulnerability
	r.db.Where("name LIKE ? OR description LIKE ? OR cve LIKE ?",
		"%"+keyword+"%", "%"+keyword+"%", "%"+keyword+"%").
		Preload("Host").Find(&vulns)
	results["vulnerabilities"] = vulns

	return results, nil
}

// GetRecentActivity returns recent scanning activity
func (r *SearchRepository) GetRecentActivity(hours int) ([]models.ScanSession, error) {
	var sessions []models.ScanSession
	since := time.Now().Add(-time.Duration(hours) * time.Hour)

	err := r.db.Where("created_at > ?", since).
		Order("created_at DESC").
		Find(&sessions).Error

	return sessions, err
}

// GetDiscoveryTimeline returns discovery timeline for visualization
func (r *SearchRepository) GetDiscoveryTimeline(days int) (map[string]interface{}, error) {
	timeline := make(map[string]interface{})
	since := time.Now().Add(-time.Duration(days) * 24 * time.Hour)

	// Hosts discovered over time
	var hostStats []struct {
		Date  string `json:"date"`
		Count int64  `json:"count"`
	}

	r.db.Model(&models.Host{}).
		Select("DATE(first_seen) as date, COUNT(*) as count").
		Where("first_seen > ?", since).
		Group("DATE(first_seen)").
		Order("date").
		Find(&hostStats)

	timeline["hosts"] = hostStats

	// Vulnerabilities discovered over time
	var vulnStats []struct {
		Date     string `json:"date"`
		Severity string `json:"severity"`
		Count    int64  `json:"count"`
	}

	r.db.Model(&models.Vulnerability{}).
		Select("DATE(created_at) as date, severity, COUNT(*) as count").
		Where("created_at > ?", since).
		Group("DATE(created_at), severity").
		Order("date, severity").
		Find(&vulnStats)

	timeline["vulnerabilities"] = vulnStats

	return timeline, nil
}
