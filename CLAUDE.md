# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an **enterprise-grade reconnaissance platform** project focused on building comprehensive security tools for defensive purposes. The project plans to integrate the complete arsenal of Kali Linux tools (50+) with ProjectDiscovery tools into a unified, intelligent reconnaissance framework with database persistence and advanced correlation capabilities.

## Planned Architecture

The project documentation in `plans.md` and `goals.md` outlines an intelligent, scalable architecture using:

### Core Technologies
- **Go**: Primary language for the reconnaissance framework
- **Database**: SQLite (dev) / PostgreSQL (prod) for loot persistence
- **ProjectDiscovery Libraries**: Core security scanning capabilities
  - `nuclei/v3/lib` - Vulnerability scanning
  - `subfinder/v2` - Subdomain enumeration  
  - `naabu/v2` - Port scanning
  - `httpx` - HTTP toolkit
  - `katana` - Web crawling
  - `dnsx` - DNS toolkit

### Kali Linux Arsenal Integration (50+ Tools)
- **Network Discovery**: Nmap, Masscan, ZMap, ARP-scan, NBTscan
- **Web Application**: Gobuster, Nikto, SQLmap, Wfuzz, Whatweb
- **DNS & OSINT**: DNSrecon, TheHarvester, Recon-ng, Maltego
- **Service-Specific**: SSLyze, TestSSL, SSH-audit, SNMP tools

### Database Schema (Loot Database)
```sql
-- Core tables for structured data persistence
Hosts (IP, hostname, status, OS, etc.)
Ports (host_id, port, protocol, service, version, state)  
Domains (domain, subdomain, IP, technologies, status)
Vulnerabilities (host_id, CVE, severity, description, POC)
Networks (CIDR, ASN, organization, country)
Services (host_id, port_id, banner, headers, certificates)
Credentials (host_id, service, username, password, hash)
Files (host_id, path, content, hash, permissions)
```

### Framework Components
- **Cobra**: CLI framework with intelligent commands
- **Bubble Tea + Lip Gloss**: Advanced terminal UI
- **Gin**: Web framework for dashboard/API
- **GORM**: Database ORM for loot persistence
- **Viper**: Configuration management

## Development Guidelines

### Security Focus
- This project is intended for **defensive security purposes only**
- Tools should be designed for legitimate security testing and reconnaissance
- Follow security best practices in all implementations
- Implement proper RBAC and audit logging

### Intelligent Pipeline Design
The system implements context-aware scanning:
1. **Horizontal Discovery**: Broad enumeration across attack surface
2. **Vertical Analysis**: Deep dive into interesting targets
3. **Correlation Engine**: Cross-reference discoveries for insights
4. **Risk Scoring**: Automatic prioritization of findings

### Code Organization
```
recon-platform/
├── cmd/                    # CLI commands
├── internal/
│   ├── database/          # Loot database models and queries
│   ├── pipeline/          # Intelligent scanning pipeline
│   ├── integrations/      # Tool integrations (50+ tools)
│   ├── correlation/       # Data correlation engine
│   ├── reporting/         # Report generation
│   └── ui/                # Terminal and web UI
├── pkg/
│   ├── models/            # Data models
│   ├── utils/             # Utility functions
│   └── api/               # REST API
├── templates/             # Nuclei templates and configs
├── workflows/             # Scanning workflows
└── docs/                  # Documentation
```

### Integration Tiers
- **Tier 1**: Native Go library integrations (ProjectDiscovery)
- **Tier 2**: Kali Linux tool integrations via subprocess
- **Tier 3**: Advanced correlation and intelligence features
- **Tier 4**: Enterprise features (distributed scanning, APIs)

## Development Phases

### Phase 1 (Weeks 1-6): Foundation & Database
- Core database schema implementation
- ProjectDiscovery tool integrations
- Basic pipeline architecture

### Phase 2 (Weeks 7-14): Kali Arsenal Integration  
- 30+ Kali Linux tools integration
- Service-specific scanning workflows
- Intelligent decision engine

### Phase 3 (Weeks 15-20): Advanced Intelligence
- Vertical scanning capabilities
- Advanced correlation and risk scoring
- Attack path mapping

### Phase 4 (Weeks 21-26): Enterprise Features
- Distributed scanning architecture
- Advanced dashboards and reporting
- API endpoints and integrations

## Current Status

This is an expanded planning-stage project with comprehensive architecture documentation. The `goals.md` file contains detailed technical specifications for building an enterprise-grade reconnaissance platform that will become the industry standard for automated security reconnaissance.