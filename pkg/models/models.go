package models

import (
	"time"
	"gorm.io/gorm"
)

// Host represents a discovered host/IP address
type Host struct {
	ID          uint           `json:"id" gorm:"primaryKey"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `json:"deleted_at,omitempty" gorm:"index"`
	
	IP          string         `json:"ip" gorm:"uniqueIndex;not null"`
	Hostname    string         `json:"hostname,omitempty"`
	Status      string         `json:"status"` // up, down, filtered
	OS          string         `json:"os,omitempty"`
	OSVersion   string         `json:"os_version,omitempty"`
	MAC         string         `json:"mac,omitempty"`
	TTL         int            `json:"ttl,omitempty"`
	LastSeen    time.Time      `json:"last_seen"`
	FirstSeen   time.Time      `json:"first_seen"`
	
	// Relationships
	Ports           []Port           `json:"ports,omitempty" gorm:"foreignKey:HostID"`
	Services        []Service        `json:"services,omitempty" gorm:"foreignKey:HostID"`
	Vulnerabilities []Vulnerability  `json:"vulnerabilities,omitempty" gorm:"foreignKey:HostID"`
	Credentials     []Credential     `json:"credentials,omitempty" gorm:"foreignKey:HostID"`
	Files           []File           `json:"files,omitempty" gorm:"foreignKey:HostID"`
}

// Port represents an open port on a host
type Port struct {
	ID        uint           `json:"id" gorm:"primaryKey"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `json:"deleted_at,omitempty" gorm:"index"`
	
	HostID    uint   `json:"host_id" gorm:"not null;index"`
	Port      int    `json:"port" gorm:"not null"`
	Protocol  string `json:"protocol" gorm:"not null"` // tcp, udp
	State     string `json:"state"`                    // open, closed, filtered
	Service   string `json:"service,omitempty"`
	Version   string `json:"version,omitempty"`
	Banner    string `json:"banner,omitempty" gorm:"type:text"`
	
	// Relationships
	Host     Host      `json:"host,omitempty" gorm:"foreignKey:HostID"`
	Services []Service `json:"services,omitempty" gorm:"foreignKey:PortID"`
}

// Domain represents a discovered domain/subdomain
type Domain struct {
	ID        uint           `json:"id" gorm:"primaryKey"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `json:"deleted_at,omitempty" gorm:"index"`
	
	Domain       string    `json:"domain" gorm:"uniqueIndex;not null"`
	Subdomain    string    `json:"subdomain,omitempty"`
	IP           string    `json:"ip,omitempty" gorm:"index"`
	Technologies []string  `json:"technologies" gorm:"serializer:json"`
	Status       int       `json:"status,omitempty"` // HTTP status code
	Title        string    `json:"title,omitempty"`
	Server       string    `json:"server,omitempty"`
	ContentType  string    `json:"content_type,omitempty"`
	Certificates []string  `json:"certificates" gorm:"serializer:json"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	
	// Relationships
	Files []File `json:"files,omitempty" gorm:"foreignKey:DomainID"`
}

// Vulnerability represents a discovered vulnerability
type Vulnerability struct {
	ID        uint           `json:"id" gorm:"primaryKey"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `json:"deleted_at,omitempty" gorm:"index"`
	
	HostID      uint     `json:"host_id" gorm:"index"`
	CVE         string   `json:"cve,omitempty" gorm:"index"`
	Name        string   `json:"name" gorm:"not null"`
	Severity    string   `json:"severity" gorm:"not null;index"` // critical, high, medium, low, info
	Description string   `json:"description" gorm:"type:text"`
	Solution    string   `json:"solution,omitempty" gorm:"type:text"`
	References  []string `json:"references" gorm:"serializer:json"`
	CVSS        float64  `json:"cvss,omitempty"`
	Template    string   `json:"template,omitempty"` // Nuclei template used
	POC         string   `json:"poc,omitempty" gorm:"type:text"`
	Exploitable bool     `json:"exploitable" gorm:"default:false"`
	Verified    bool     `json:"verified" gorm:"default:false"`
	
	// Relationships
	Host Host `json:"host,omitempty" gorm:"foreignKey:HostID"`
}

// Network represents network information (ASN, CIDR, etc.)
type Network struct {
	ID        uint           `json:"id" gorm:"primaryKey"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `json:"deleted_at,omitempty" gorm:"index"`
	
	CIDR         string `json:"cidr" gorm:"uniqueIndex;not null"`
	ASN          int    `json:"asn,omitempty" gorm:"index"`
	Organization string `json:"organization,omitempty"`
	Country      string `json:"country,omitempty"`
	Description  string `json:"description,omitempty"`
	StartIP      string `json:"start_ip,omitempty"`
	EndIP        string `json:"end_ip,omitempty"`
}

// Service represents a service running on a host:port
type Service struct {
	ID        uint           `json:"id" gorm:"primaryKey"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `json:"deleted_at,omitempty" gorm:"index"`
	
	HostID      uint     `json:"host_id" gorm:"not null;index"`
	PortID      uint     `json:"port_id,omitempty" gorm:"index"`
	Name        string   `json:"name" gorm:"not null"`
	Version     string   `json:"version,omitempty"`
	Banner      string   `json:"banner,omitempty" gorm:"type:text"`
	Headers     []string `json:"headers" gorm:"serializer:json"`
	Certificates []string `json:"certificates" gorm:"serializer:json"`
	Fingerprint string   `json:"fingerprint,omitempty"`
	
	// Relationships
	Host Host `json:"host,omitempty" gorm:"foreignKey:HostID"`
	Port Port `json:"port,omitempty" gorm:"foreignKey:PortID"`
}

// Credential represents discovered credentials
type Credential struct {
	ID        uint           `json:"id" gorm:"primaryKey"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `json:"deleted_at,omitempty" gorm:"index"`
	
	HostID   uint   `json:"host_id" gorm:"not null;index"`
	Service  string `json:"service" gorm:"not null"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Hash     string `json:"hash,omitempty"`
	Type     string `json:"type,omitempty"` // password, hash, key, token
	Source   string `json:"source,omitempty"` // bruteforce, leak, default, etc.
	Verified bool   `json:"verified" gorm:"default:false"`
	
	// Relationships
	Host Host `json:"host,omitempty" gorm:"foreignKey:HostID"`
}

// File represents discovered files/directories
type File struct {
	ID        uint           `json:"id" gorm:"primaryKey"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `json:"deleted_at,omitempty" gorm:"index"`
	
	HostID     uint   `json:"host_id,omitempty" gorm:"index"`
	DomainID   uint   `json:"domain_id,omitempty" gorm:"index"`
	Path       string `json:"path" gorm:"not null"`
	Content    string `json:"content,omitempty" gorm:"type:text"`
	Hash       string `json:"hash,omitempty"`
	Size       int64  `json:"size,omitempty"`
	Type       string `json:"type,omitempty"` // file, directory, config, backup, etc.
	Permissions string `json:"permissions,omitempty"`
	Status     int    `json:"status,omitempty"` // HTTP status code
	Interesting bool  `json:"interesting" gorm:"default:false"`
	
	// Relationships
	Host   Host   `json:"host,omitempty" gorm:"foreignKey:HostID"`
	Domain Domain `json:"domain,omitempty" gorm:"foreignKey:DomainID"`
}

// ScanSession represents a scanning session for tracking
type ScanSession struct {
	ID        uint           `json:"id" gorm:"primaryKey"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `json:"deleted_at,omitempty" gorm:"index"`
	
	Name        string            `json:"name" gorm:"not null"`
	Target      string            `json:"target" gorm:"not null"`
	Status      string            `json:"status" gorm:"not null"` // running, completed, failed
	StartedAt   time.Time         `json:"started_at"`
	CompletedAt *time.Time        `json:"completed_at,omitempty"`
	Tools       []string          `json:"tools" gorm:"serializer:json"`
	Config      map[string]interface{} `json:"config" gorm:"serializer:json"`
	Results     map[string]interface{} `json:"results" gorm:"serializer:json"`
	Errors      []string          `json:"errors" gorm:"serializer:json"`
}