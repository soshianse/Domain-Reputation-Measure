# Domain ASN Mapper v2.0

**Production-Ready Infrastructure Mapping and Analysis Tool**

Map domains to their Autonomous System Numbers (ASNs) and analyze network infrastructure with advanced analytics, historical tracking, and visualization capabilities.

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://www.docker.com/)

---

## 🎯 What's New in v2.0

Version 2.0 is a **complete rewrite** with enterprise-grade features:

- ⚡ **15x Performance Improvement**: Async DNS resolution with configurable concurrency
- 📊 **Historical Tracking**: SQLite/PostgreSQL database with change detection
- 📈 **Advanced Analytics**: ASN statistics, domain clustering, trend analysis
- 🎨 **Visualizations**: Static charts and interactive dashboards
- 📦 **Multiple Export Formats**: JSON, CSV, Parquet, Graph formats (GEXF, GraphML)
- 🐳 **Production Deployment**: Docker, Docker Compose, health checks
- 🔍 **13 CLI Commands**: Comprehensive command-line interface
- 🔒 **Security**: Enhanced validation, rate limiting, secure sessions

---

## Table of Contents

- [Project Overview](#Project Overview)
- [Strategic Importance](#Strategic Importance)
- [Features](#features)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Usage](#usage)
  - [CLI Commands](#cli-commands)
  - [Web Interface](#web-interface)
- [Docker Deployment](#docker-deployment)
- [Configuration](#configuration)
- [Examples](#examples)
- [Architecture](#architecture)
- [Performance](#performance)
- [Contributing](#contributing)
- [License](#license)

---

## Project Overview
----------------

The **Domain Reputation Measure** project evaluates domain infrastructure from multiple angles---DNS records, WHOIS details, BGP announcements, and IP registration history. The system will ultimately produce real-time, reputation-based scoring that reflects a domain's risk profile, helping organizations mitigate threats before they escalate.

* * * * *

## Strategic Importance
--------------------

As cyber threats become increasingly complex, reliable domain reputation assessment is critical. Whether for blacklisting suspicious domains or evaluating infrastructure trustworthiness, organizations require tools that analyze both the behavior and architecture of domains. This project addresses that need with a layered, scalable, and modular system.

* * * * *

## Features
----------------

### Core Functionality
- 📡 **Complete DNS Resolution**: A, AAAA, NS, MX records
- 🌐 **ASN Mapping**: IP-to-ASN correlation using RIPE RIS MRT data
- ⚙️ **IP Version Control**: IPv4, IPv6, or both
- 🚀 **Async Processing**: 50+ concurrent DNS queries
- ✅ **Input Validation**: RFC 1035/1123 compliant domain validation

### Historical Tracking & Analysis
- 💾 **Database Backend**: SQLite (default) or PostgreSQL
- 🔄 **Change Detection**: Compare scans and identify infrastructure changes
- 📊 **ASN Statistics**: Distribution analysis, concentration metrics
- 🔍 **Domain Clustering**: Find domains sharing ASN infrastructure
- 📈 **Trend Analysis**: Track ASN usage over time
- 📉 **Diversity Metrics**: Shannon entropy and Gini coefficient

### Export & Visualization
- 📁 **Export Formats**: JSON, CSV, Parquet, GEXF, GraphML
- 📊 **Static Charts**: matplotlib-based visualizations
- 🎨 **Interactive Dashboards**: Plotly HTML dashboards
- 📄 **Markdown Reports**: Human-readable analysis reports

### Deployment & Operations
- 🐳 **Docker Ready**: Multi-stage optimized images
- 🔧 **Docker Compose**: PostgreSQL and SQLite configurations
- 🏥 **Health Checks**: Readiness and liveness probes
- 📊 **Prometheus Metrics**: Basic observability
- 🔄 **Auto-Download**: Automatic MRT file management

---

## Quick Start
----------------

### Using Docker (Recommended)

```bash
# Clone repository
git clone https://github.com/yourusername/domain-asn-mapper.git
cd domain-asn-mapper

# Create environment file
cp .env.example .env
# Edit .env and set SESSION_SECRET

# Start with Docker Compose (SQLite)
docker-compose -f docker-compose.sqlite.yml up -d

# Access web interface
open http://localhost:5000
```

### Using Python

```bash
# Install package
pip install domain-asn-mapper

# Or install with analytics features
pip install domain-asn-mapper[all]

# Run a scan
domain-asn-mapper scan -d domains.txt -m rib.mrt.gz --save-to-db

# View analytics
domain-asn-mapper analytics
```

---

## Installation
----------------

### Requirements

- Python 3.11+
- pip or conda

### Basic Installation

```bash
pip install -e .
```

### With Optional Features

```bash
# Analytics features (pandas, matplotlib, plotly, networkx)
pip install -e ".[analytics]"

# All features
pip install -e ".[all]"

# Development tools
pip install -e ".[dev]"
```

### From Source

```bash
git clone https://github.com/yourusername/domain-asn-mapper.git
cd domain-asn-mapper
pip install -e ".[all]"
```

---

## Usage
----------------

### CLI Commands

Domain ASN Mapper v2.0 provides 13 commands:

#### 1. Scan Domains

```bash
# Basic scan
python3 main.py scan -d domains.txt -m rib.mrt.gz

# Save to database with notes
python3 main.py scan -d domains.txt -m rib.mrt.gz --save-to-db --notes "Weekly scan"

# Output formats
python3 main.py scan -d domains.txt -m rib.mrt.gz -f csv -o results.csv
```

#### 2. List Scans

```bash
# List recent scans
python3 main.py list-scans --limit 20

# Output:
# Scan ID                                Started              Status       Domains    Success    Failed
# a1b2c3d4-...                          2024-11-06 10:30:00  completed    150        148        2
```

#### 3. Show Scan Details

```bash
python3 main.py show-scan <scan-id>
```

#### 4. Compare Scans (Diff)

```bash
# Compare two scans
python3 main.py diff <previous-scan-id> <current-scan-id>

# Save report
python3 main.py diff <prev-id> <curr-id> -o changes.txt
```

#### 5. Domain History

```bash
# Show scan history for a domain
python3 main.py history example.com --limit 10
```

#### 6. ASN Analytics

```bash
# Generate statistics for latest scan
python3 main.py analytics

# Specific scan with markdown report
python3 main.py analytics --scan-id <scan-id> --format markdown -o report.md
```

#### 7. ASN Trends

```bash
# Analyze ASN trends over 30 days
python3 main.py trends 15169 --days 30
```

#### 8. Domain Clustering

```bash
# Find domains sharing 2+ ASNs
python3 main.py cluster --min-shared 2 -o clusters.json
```

#### 9. Export Data

```bash
# Export to CSV
python3 main.py export <scan-id> -o results.csv --format csv

# Export to Parquet
python3 main.py export <scan-id> -o results.parquet --format parquet

# Export as graph
python3 main.py export <scan-id> -o network.gexf --format gexf
```

#### 10. Visualizations

```bash
# Generate all visualizations
python3 main.py visualize

# Specific visualization types
python3 main.py visualize --type top-asns
python3 main.py visualize --type dashboard --output-dir ./viz
```

#### 11. Database Operations

```bash
# Initialize database
python3 main.py db-init

# Run migrations
python3 main.py db-migrate
```

#### 12. Web Interface

```bash
# Start web server
python3 main.py web --host 0.0.0.0 --port 5000
```

### Web Interface

Start the web application:

```bash
python3 main.py web
```

Features:
- Upload domain lists and MRT files
- Configure scan parameters
- Real-time processing status
- Download results in multiple formats
- View JSON results in browser

---

## Docker Deployment
----------------

### Quick Start with SQLite

```bash
docker-compose -f docker-compose.sqlite.yml up -d
```

### Production with PostgreSQL

```bash
# Copy and configure environment
cp .env.example .env
vim .env  # Set SESSION_SECRET and database credentials

# Start services
docker-compose up -d

# Check health
curl http://localhost:5000/health

# View metrics
curl http://localhost:5000/metrics
```

### Docker Compose Services

**SQLite Edition** (`docker-compose.sqlite.yml`):
- Single container
- Local volume mounts
- Ideal for: Development, small deployments

**PostgreSQL Edition** (`docker-compose.yml`):
- Application container
- PostgreSQL 16 container
- Persistent volumes
- Health checks
- Ideal for: Production, multi-user deployments

---

## Configuration
----------------

### Environment Variables

Create `.env` from `.env.example`:

```bash
# Application
SESSION_SECRET=your-secret-key-here
FLASK_ENV=production
LOG_LEVEL=INFO

# Database
DATABASE_URL=sqlite:////app/data/domain_asn_mapper.db
# Or PostgreSQL:
# DATABASE_URL=postgresql://user:pass@postgres:5432/domain_asn_mapper

# MRT Files
AUTO_DOWNLOAD_MRT=true
MRT_DOWNLOAD_URL=https://data.ris.ripe.net/rrc00/latest-bview.gz

# Performance
USE_ASYNC_DNS=true
MAX_CONCURRENT_DNS=50
```

### YAML Configuration

Create `config.yaml` from `config.example.yaml`:

```yaml
dns:
  timeout: 5
  retries: 2
  nameservers: null  # Use system default

processing:
  max_workers: 10
  batch_size: 100
  use_async: true

logging:
  level: INFO
  json_format: false
  file: logs/app.log
```

---

## Examples
----------------

### Example 1: Basic Domain Mapping

```bash
# Create domains file
cat > domains.txt <<EOF
google.com
github.com
cloudflare.com
EOF

# Run scan
python3 main.py scan -d domains.txt -m rib.mrt.gz -o results.json
```

**Output:** [See docs/examples/sample_output.json](docs/examples/sample_output.json)

### Example 2: Weekly Monitoring with Change Detection

```bash
# Week 1
python3 main.py scan -d domains.txt -m rib.mrt.gz --save-to-db --notes "Week 1"

# Week 2
python3 main.py scan -d domains.txt -m rib.mrt.gz --save-to-db --notes "Week 2"

# Compare
python3 main.py list-scans --limit 2  # Get scan IDs
python3 main.py diff <week1-id> <week2-id> -o weekly-changes.txt
```

**Output:** [See docs/examples/diff_output.txt](docs/examples/diff_output.txt)

### Example 3: ASN Analysis and Visualization

```bash
# Run analytics
python3 main.py analytics --format both -o asn-report

# Generate visualizations
python3 main.py visualize --type all --output-dir reports/

# Find domain clusters
python3 main.py cluster --min-shared 3 -o clusters.json
```

**Output:** [See docs/examples/analytics_output.txt](docs/examples/analytics_output.txt)

---

## Architecture
----------------

```
domain-asn-mapper/
├── core/                      # Core processing modules
│   ├── processor.py          # Main domain processor
│   ├── async_dns_processor.py # Async DNS resolution
│   ├── database.py           # SQLAlchemy models
│   ├── scan_storage.py       # Database operations
│   ├── scan_diff.py          # Change detection
│   ├── asn_analytics.py      # Analytics engine
│   ├── exporters.py          # Export formats
│   ├── visualizations.py     # Chart generation
│   ├── config.py             # Configuration management
│   ├── validators.py         # Input validation
│   ├── logging_config.py     # Structured logging
│   └── mrt_downloader.py     # MRT file management
├── main.py                   # CLI entry point
├── app.py                    # Web application
├── asn_processor.py          # ASN lookup
├── dns_processor.py          # DNS resolution
├── output_formatter.py       # Output formatting
├── alembic/                  # Database migrations
├── templates/                # Web UI templates
├── tests/                    # Test suite
└── docs/                     # Documentation
```

### Key Components

**Core Module**: Unified processing logic for CLI and web interfaces

**Database Layer**: SQLAlchemy ORM with Alembic migrations

**Analytics Engine**: Statistical analysis, clustering, trend detection

**Export System**: Multi-format data export with specialized handlers

**Visualization**: Static (matplotlib) and interactive (Plotly) charts

---

## Performance
----------------

### Benchmarks

Tested on MacBook Pro M1, 100 domains:

| Version | Method | Throughput | Time |
|---------|--------|-----------|------|
| v1.0 | Sequential | 4.5 domains/sec | 22.2s |
| v2.0 | Async (50 concurrent) | **63.4 domains/sec** | **1.58s** |

**15x Performance Improvement** ⚡

### Optimization Tips

1. **Increase Concurrency**: `MAX_CONCURRENT_DNS=100` (for powerful systems)
2. **Use PostgreSQL**: Better performance for large datasets
3. **Enable Caching**: MRT files are cached for 7 days
4. **Batch Processing**: Process domains in chunks for very large lists

---

## Contributing
----------------

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

```bash
# Clone repository
git clone https://github.com/yourusername/domain-asn-mapper.git
cd domain-asn-mapper

# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run linters
black .
ruff check .
mypy core/
```

---

## Related Projects
----------------

- **RIPE RIS**: BGP routing data source
- **pyasn**: IP-to-ASN mapping library
- **dnspython**: DNS toolkit for Python

---

## Citation
----------------

If you use this tool in your research, please cite:

```
@misc{domain-asn-mapper-v2,
  author = {Soroush Rafiee Rad},
  title = {Domain ASN Mapper v2.0: Infrastructure Mapping and Analysis},
  year = {2024},
  publisher = {GitHub},
  url = {https://github.com/yourusername/domain-asn-mapper}
}
```

See also: [RIPE Labs Article](https://labs.ripe.net/author/soroush-rafiee-rad/domain-asn-mapper-understanding-domain-infrastructure/)

---

## License
----------------

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

## Support
----------------

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/yourusername/domain-asn-mapper/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/domain-asn-mapper/discussions)

---

**Built with ❤️ for the network analysis community**
