# Recon Platform

🚀 **Enterprise-grade reconnaissance platform** that integrates 50+ Kali Linux tools with ProjectDiscovery tools into a unified, intelligent framework with database persistence and advanced correlation capabilities.

## ⚡ Quick Start

```bash
# Install (coming soon)
go install toolkit/cmd/recon@latest

# Basic scan
recon scan -d example.com

# Advanced scan with vertical analysis
recon scan -d example.com --vertical --all-tools

# Query loot database
recon query --hosts --vulnerabilities --severity high
```

## 🎯 Features

### 🔍 Comprehensive Tool Integration
- **50+ Kali Linux Tools**: Nmap, Masscan, Gobuster, Nikto, SQLmap, and more
- **ProjectDiscovery Suite**: Nuclei, Subfinder, Naabu, HTTPX, Katana, DNSX
- **Intelligent Pipeline**: Context-aware scanning that adapts based on discoveries

### 🗄️ Persistent Loot Database
- **Structured Storage**: Hosts, Ports, Domains, Vulnerabilities, Networks, Services
- **Historical Tracking**: Timeline analysis and change detection
- **Advanced Correlation**: Cross-reference discoveries for deeper insights

### 🧠 Smart Reconnaissance
- **Horizontal Discovery**: Broad attack surface enumeration
- **Vertical Analysis**: Deep dive into interesting targets
- **Risk Scoring**: Automatic prioritization of findings
- **Attack Path Mapping**: Identify potential exploitation paths

## 🏗️ Architecture

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
└── templates/             # Nuclei templates and configs
```

## 🛠️ Development Status

**Current Phase**: Foundation & Database Implementation (Phase 1)

- [x] Project structure and Go module setup
- [x] Database schema design
- [ ] Core ProjectDiscovery integrations
- [ ] Basic CLI framework
- [ ] Loot database implementation

See [goals.md](goals.md) for detailed roadmap and milestones.

## 🤝 Contributing

This is an open-source project under Apache 2.0 license. Contributions welcome!

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📜 License

Apache License 2.0 - see [LICENSE](LICENSE) file for details.

## 🚨 Security Notice

This tool is designed for **defensive security purposes only**. Users are responsible for complying with applicable laws and regulations. Only use on systems you own or have explicit permission to test.

---

**Built for the infosec community** 🔒