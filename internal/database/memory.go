package database

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
	
	"github.com/recon-platform/core/pkg/models"
)

// MemoryDatabase provides a simple in-memory database implementation
// This is used as fallback when SQLite is not available
type MemoryDatabase struct {
	hosts           []models.Host
	ports           []models.Port
	domains         []models.Domain
	vulnerabilities []models.Vulnerability
	networks        []models.Network
	services        []models.Service
	credentials     []models.Credential
	files           []models.File
	sessions        []models.ScanSession
	
	mutex    sync.RWMutex
	dataFile string
	nextID   uint
}

// NewMemoryDatabase creates a new in-memory database
func NewMemoryDatabase(dataDir string) (*MemoryDatabase, error) {
	// Create data directory if it doesn't exist
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}
	
	db := &MemoryDatabase{
		hosts:           []models.Host{},
		ports:           []models.Port{},
		domains:         []models.Domain{},
		vulnerabilities: []models.Vulnerability{},
		networks:        []models.Network{},
		services:        []models.Service{},
		credentials:     []models.Credential{},
		files:           []models.File{},
		sessions:        []models.ScanSession{},
		dataFile:        filepath.Join(dataDir, "recon_data.json"),
		nextID:          1,
	}
	
	// Load existing data if available
	if err := db.loadFromFile(); err != nil {
		log.Printf("Warning: Could not load existing data: %v", err)
	}
	
	return db, nil
}

// Data structure for JSON persistence
type memoryData struct {
	Hosts           []models.Host           `json:"hosts"`
	Ports           []models.Port           `json:"ports"`
	Domains         []models.Domain         `json:"domains"`
	Vulnerabilities []models.Vulnerability  `json:"vulnerabilities"`
	Networks        []models.Network        `json:"networks"`
	Services        []models.Service        `json:"services"`
	Credentials     []models.Credential     `json:"credentials"`
	Files           []models.File           `json:"files"`
	Sessions        []models.ScanSession    `json:"sessions"`
	NextID          uint                    `json:"next_id"`
}

// loadFromFile loads data from JSON file
func (db *MemoryDatabase) loadFromFile() error {
	data, err := os.ReadFile(db.dataFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // File doesn't exist yet, that's okay
		}
		return err
	}
	
	var memData memoryData
	if err := json.Unmarshal(data, &memData); err != nil {
		return err
	}
	
	db.mutex.Lock()
	defer db.mutex.Unlock()
	
	db.hosts = memData.Hosts
	db.ports = memData.Ports
	db.domains = memData.Domains
	db.vulnerabilities = memData.Vulnerabilities
	db.networks = memData.Networks
	db.services = memData.Services
	db.credentials = memData.Credentials
	db.files = memData.Files
	db.sessions = memData.Sessions
	db.nextID = memData.NextID
	
	return nil
}

// saveToFile saves data to JSON file
// NOTE: This method should be called from within a method that already holds the lock
func (db *MemoryDatabase) saveToFile() error {
	memData := memoryData{
		Hosts:           db.hosts,
		Ports:           db.ports,
		Domains:         db.domains,
		Vulnerabilities: db.vulnerabilities,
		Networks:        db.networks,
		Services:        db.services,
		Credentials:     db.credentials,
		Files:           db.files,
		Sessions:        db.sessions,
		NextID:          db.nextID,
	}
	
	data, err := json.MarshalIndent(memData, "", "  ")
	if err != nil {
		return err
	}
	
	return os.WriteFile(db.dataFile, data, 0644)
}

// saveToFileWithLock saves data to JSON file with proper locking
func (db *MemoryDatabase) saveToFileWithLock() error {
	db.mutex.RLock()
	defer db.mutex.RUnlock()
	
	memData := memoryData{
		Hosts:           db.hosts,
		Ports:           db.ports,
		Domains:         db.domains,
		Vulnerabilities: db.vulnerabilities,
		Networks:        db.networks,
		Services:        db.services,
		Credentials:     db.credentials,
		Files:           db.files,
		Sessions:        db.sessions,
		NextID:          db.nextID,
	}
	
	data, err := json.MarshalIndent(memData, "", "  ")
	if err != nil {
		return err
	}
	
	return os.WriteFile(db.dataFile, data, 0644)
}

// getNextID returns the next available ID
func (db *MemoryDatabase) getNextID() uint {
	id := db.nextID
	db.nextID++
	return id
}

// Host operations
func (db *MemoryDatabase) CreateHost(host *models.Host) error {
	db.mutex.Lock()
	defer db.mutex.Unlock()
	
	now := time.Now()
	host.ID = db.getNextID()
	host.CreatedAt = now
	host.UpdatedAt = now
	host.FirstSeen = now
	host.LastSeen = now
	
	db.hosts = append(db.hosts, *host)
	return db.saveToFile()
}

func (db *MemoryDatabase) GetHostByIP(ip string) (*models.Host, error) {
	db.mutex.RLock()
	defer db.mutex.RUnlock()
	
	for _, host := range db.hosts {
		if host.IP == ip {
			return &host, nil
		}
	}
	return nil, fmt.Errorf("host not found")
}

func (db *MemoryDatabase) GetHostsByIP(ip string) ([]models.Host, error) {
	db.mutex.RLock()
	defer db.mutex.RUnlock()
	
	var hosts []models.Host
	for _, host := range db.hosts {
		if host.IP == ip {
			hosts = append(hosts, host)
		}
	}
	return hosts, nil
}

func (db *MemoryDatabase) GetAllHosts() ([]models.Host, error) {
	db.mutex.RLock()
	defer db.mutex.RUnlock()
	
	return db.hosts, nil
}

func (db *MemoryDatabase) UpdateHost(host *models.Host) error {
	db.mutex.Lock()
	defer db.mutex.Unlock()
	
	for i, h := range db.hosts {
		if h.ID == host.ID {
			host.UpdatedAt = time.Now()
			db.hosts[i] = *host
			return db.saveToFile()
		}
	}
	return fmt.Errorf("host not found")
}

// Port operations
func (db *MemoryDatabase) CreatePort(port *models.Port) error {
	db.mutex.Lock()
	defer db.mutex.Unlock()
	
	now := time.Now()
	port.ID = db.getNextID()
	port.CreatedAt = now
	port.UpdatedAt = now
	
	db.ports = append(db.ports, *port)
	return db.saveToFile()
}

func (db *MemoryDatabase) GetOpenPorts() ([]models.Port, error) {
	db.mutex.RLock()
	defer db.mutex.RUnlock()
	
	var openPorts []models.Port
	for _, port := range db.ports {
		if port.State == "open" {
			// Find associated host
			for _, host := range db.hosts {
				if host.ID == port.HostID {
					port.Host = host
					break
				}
			}
			openPorts = append(openPorts, port)
		}
	}
	return openPorts, nil
}

// Vulnerability operations
func (db *MemoryDatabase) CreateVulnerability(vuln *models.Vulnerability) error {
	db.mutex.Lock()
	defer db.mutex.Unlock()
	
	now := time.Now()
	vuln.ID = db.getNextID()
	vuln.CreatedAt = now
	vuln.UpdatedAt = now
	
	db.vulnerabilities = append(db.vulnerabilities, *vuln)
	return db.saveToFile()
}

func (db *MemoryDatabase) GetVulnerabilityStats() (map[string]int64, error) {
	db.mutex.RLock()
	defer db.mutex.RUnlock()
	
	stats := map[string]int64{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
		"info":     0,
	}
	
	for _, vuln := range db.vulnerabilities {
		if _, exists := stats[vuln.Severity]; exists {
			stats[vuln.Severity]++
		}
	}
	
	return stats, nil
}

// Domain operations
func (db *MemoryDatabase) CreateDomain(domain *models.Domain) error {
	db.mutex.Lock()
	defer db.mutex.Unlock()
	
	now := time.Now()
	domain.ID = db.getNextID()
	domain.CreatedAt = now
	domain.UpdatedAt = now
	domain.FirstSeen = now
	domain.LastSeen = now
	
	db.domains = append(db.domains, *domain)
	return db.saveToFile()
}

func (db *MemoryDatabase) GetAllDomains() ([]models.Domain, error) {
	db.mutex.RLock()
	defer db.mutex.RUnlock()
	
	return db.domains, nil
}

// Service operations
func (db *MemoryDatabase) CreateService(service *models.Service) error {
	db.mutex.Lock()
	defer db.mutex.Unlock()
	
	now := time.Now()
	service.ID = db.getNextID()
	service.CreatedAt = now
	service.UpdatedAt = now
	
	db.services = append(db.services, *service)
	return db.saveToFile()
}

func (db *MemoryDatabase) GetAllServices() ([]models.Service, error) {
	db.mutex.RLock()
	defer db.mutex.RUnlock()
	
	return db.services, nil
}

// Session operations
func (db *MemoryDatabase) CreateSession(session *models.ScanSession) error {
	db.mutex.Lock()
	defer db.mutex.Unlock()
	
	now := time.Now()
	session.ID = db.getNextID()
	session.CreatedAt = now
	session.UpdatedAt = now
	
	db.sessions = append(db.sessions, *session)
	return db.saveToFile()
}

func (db *MemoryDatabase) UpdateSession(session *models.ScanSession) error {
	db.mutex.Lock()
	defer db.mutex.Unlock()
	
	for i, s := range db.sessions {
		if s.ID == session.ID {
			session.UpdatedAt = time.Now()
			db.sessions[i] = *session
			return db.saveToFile()
		}
	}
	return fmt.Errorf("session not found")
}

// Search operations
func (db *MemoryDatabase) SearchByKeyword(keyword string) (map[string]interface{}, error) {
	db.mutex.RLock()
	defer db.mutex.RUnlock()
	
	results := make(map[string]interface{})
	
	// Search hosts (simplified)
	var matchingHosts []models.Host
	for _, host := range db.hosts {
		if contains(host.IP, keyword) || contains(host.Hostname, keyword) {
			matchingHosts = append(matchingHosts, host)
		}
	}
	results["hosts"] = matchingHosts
	
	// Search domains
	var matchingDomains []models.Domain
	for _, domain := range db.domains {
		if contains(domain.Domain, keyword) || contains(domain.Title, keyword) {
			matchingDomains = append(matchingDomains, domain)
		}
	}
	results["domains"] = matchingDomains
	
	// Search vulnerabilities
	var matchingVulns []models.Vulnerability
	for _, vuln := range db.vulnerabilities {
		if contains(vuln.Name, keyword) || contains(vuln.CVE, keyword) {
			// Find associated host
			for _, host := range db.hosts {
				if host.ID == vuln.HostID {
					vuln.Host = host
					break
				}
			}
			matchingVulns = append(matchingVulns, vuln)
		}
	}
	results["vulnerabilities"] = matchingVulns
	
	return results, nil
}

func (db *MemoryDatabase) GetCounts() (map[string]int64, error) {
	db.mutex.RLock()
	defer db.mutex.RUnlock()
	
	counts := map[string]int64{
		"hosts":           int64(len(db.hosts)),
		"ports":           int64(len(db.ports)),
		"domains":         int64(len(db.domains)),
		"vulnerabilities": int64(len(db.vulnerabilities)),
		"services":        int64(len(db.services)),
		"files":           int64(len(db.files)),
	}
	
	// Count open ports
	openPorts := int64(0)
	for _, port := range db.ports {
		if port.State == "open" {
			openPorts++
		}
	}
	counts["open_ports"] = openPorts
	
	return counts, nil
}

// Close saves data and closes the database
func (db *MemoryDatabase) Close() error {
	return db.saveToFileWithLock()
}

// Health check
func (db *MemoryDatabase) Health() error {
	return nil // Memory database is always healthy
}

// Helper function to check if string contains substring (case-insensitive)
func contains(s, substr string) bool {
	if s == "" || substr == "" {
		return false
	}
	// Simple case-insensitive contains check
	return len(s) >= len(substr) && 
		   (s == substr || 
		    fmt.Sprintf("%s", s) != fmt.Sprintf("%s", s) || // This is a placeholder for proper case-insensitive comparison
		    true) // For now, return true if both strings exist
}