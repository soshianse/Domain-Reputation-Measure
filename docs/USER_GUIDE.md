# Domain ASN Mapper v2.0 - User Guide

## Table of Contents

1. [Introduction](#introduction)
2. [Getting Started](#getting-started)
3. [Installation Methods](#installation-methods)
4. [Basic Usage](#basic-usage)
5. [Command Reference](#command-reference)
6. [Web Interface](#web-interface)
7. [Configuration](#configuration)
8. [Common Workflows](#common-workflows)
9. [Troubleshooting](#troubleshooting)
10. [FAQ](#faq)

---

## Introduction

Domain ASN Mapper v2.0 is a production-ready tool for mapping domains to their Autonomous System Numbers (ASNs) and analyzing network infrastructure. This guide will help you get up and running quickly.

### What Does It Do?

- Maps domain names to IP addresses (DNS resolution)
- Identifies which ASNs (network providers) host those IPs
- Tracks infrastructure changes over time
- Provides analytics on ASN distribution and trends
- Exports data in multiple formats for further analysis

### Who Is It For?

- Network security researchers
- Infrastructure monitoring teams
- Digital forensics investigators
- Academic researchers studying Internet topology
- Anyone curious about domain hosting infrastructure

---

## Getting Started

### Prerequisites

- **For Docker users**: Docker and Docker Compose installed
- **For Python users**: Python 3.11 or higher

### Quick Start (Docker)

The fastest way to get started is with Docker:

```bash
# Clone the repository
git clone https://github.com/yourusername/domain-asn-mapper.git
cd domain-asn-mapper

# Create environment configuration
cp .env.example .env

# Edit .env and set a secure SESSION_SECRET
nano .env  # or use your preferred editor

# Start with Docker Compose (SQLite)
docker-compose -f docker-compose.sqlite.yml up -d

# Access the web interface
open http://localhost:5000
```

That's it! The application will automatically download the required MRT file on first run.

### Quick Start (Python)

If you prefer a local Python installation:

```bash
# Install the package
pip install domain-asn-mapper

# Or install with all features
pip install domain-asn-mapper[all]

# Create a sample domains file
cat > domains.txt <<EOF
google.com
github.com
cloudflare.com
EOF

# Run your first scan
domain-asn-mapper scan -d domains.txt --save-to-db
```

---

## Installation Methods

### Method 1: Docker (Recommended for Production)

**Advantages**: Isolated environment, easy deployment, includes PostgreSQL option

#### SQLite Edition (Single Container)

```bash
docker-compose -f docker-compose.sqlite.yml up -d
```

Ideal for: Development, testing, small deployments (< 10,000 domains)

#### PostgreSQL Edition (Production)

```bash
# Configure environment
cp .env.example .env
vim .env  # Set DATABASE_URL, SESSION_SECRET, etc.

# Start services
docker-compose up -d

# Check health
curl http://localhost:5000/health
```

Ideal for: Production, multi-user environments, large-scale scanning

### Method 2: PyPI Package

**Advantages**: Quick installation, integrates with existing Python projects

```bash
# Basic installation (CLI only)
pip install domain-asn-mapper

# With analytics features
pip install domain-asn-mapper[analytics]

# All features
pip install domain-asn-mapper[all]

# Development installation
pip install domain-asn-mapper[dev]
```

### Method 3: From Source

**Advantages**: Latest features, ability to modify code

```bash
git clone https://github.com/yourusername/domain-asn-mapper.git
cd domain-asn-mapper

# Install in development mode
pip install -e ".[all]"

# Run tests to verify installation
pytest
```

### Verifying Installation

```bash
# Check CLI access
domain-asn-mapper --help

# Or if installed from source
python3 main.py --help

# Run database initialization
domain-asn-mapper db-init
```

---

## Basic Usage

### Your First Scan

1. **Create a domains file** (`domains.txt`):
```
google.com
github.com
cloudflare.com
amazon.com
microsoft.com
```

2. **Run the scan**:
```bash
python3 main.py scan -d domains.txt --save-to-db
```

3. **View results**:
```bash
# List all scans
python3 main.py list-scans

# Show detailed results
python3 main.py show-scan <scan-id>
```

### Understanding the Output

A typical scan result includes:

```json
{
  "domain": "google.com",
  "status": "success",
  "dns_records": {
    "A": ["142.250.185.46"],
    "AAAA": ["2607:f8b0:4004:c07::64"],
    "NS": ["ns1.google.com", "ns2.google.com"]
  },
  "asn_mappings": {
    "142.250.185.46": {
      "asn": 15169,
      "holder": "Google LLC",
      "prefix": "142.250.0.0/15"
    }
  }
}
```

**Key fields**:
- `status`: Whether DNS resolution succeeded
- `dns_records`: All resolved DNS records (A, AAAA, NS, MX)
- `asn_mappings`: IP-to-ASN mappings with network information

---

## Command Reference

### 1. scan - Run Domain Scan

Perform DNS resolution and ASN mapping for a list of domains.

```bash
python3 main.py scan -d <domains-file> [options]
```

**Options**:
- `-d, --domains`: Path to domains file (one domain per line)
- `-m, --mrt-file`: Path to MRT file (auto-downloads if not specified)
- `-f, --format`: Output format (json, csv, text)
- `-o, --output`: Output file path
- `--save-to-db`: Save results to database
- `--notes`: Add notes to the scan record
- `--ip-version`: IP version to use (4, 6, or both)

**Examples**:

```bash
# Basic scan with database storage
python3 main.py scan -d domains.txt --save-to-db

# Scan with notes for tracking
python3 main.py scan -d domains.txt --save-to-db --notes "Weekly scan - 2024-11-06"

# Export to CSV
python3 main.py scan -d domains.txt -f csv -o results.csv

# IPv4 only
python3 main.py scan -d domains.txt --ip-version 4
```

### 2. list-scans - View Scan History

List all scans stored in the database.

```bash
python3 main.py list-scans [--limit N]
```

**Output**:
```
Scan ID                                Started              Status       Domains    Success    Failed
a1b2c3d4-e5f6-7890-abcd-ef1234567890  2024-11-06 10:30:00  completed    150        148        2
```

### 3. show-scan - View Scan Details

Display detailed information for a specific scan.

```bash
python3 main.py show-scan <scan-id>
```

### 4. diff - Compare Scans

Compare two scans to identify infrastructure changes.

```bash
python3 main.py diff <previous-scan-id> <current-scan-id> [-o output.txt]
```

**Output includes**:
- Added domains
- Removed domains
- IP address changes
- ASN changes
- DNS record changes

**Example**:
```bash
# Get scan IDs
python3 main.py list-scans --limit 2

# Compare the two most recent scans
python3 main.py diff abc123... def456... -o changes.txt
```

### 5. history - Domain History

View historical scan data for a specific domain.

```bash
python3 main.py history <domain> [--limit N]
```

**Example**:
```bash
python3 main.py history google.com --limit 10
```

### 6. analytics - ASN Statistics

Generate comprehensive ASN statistics and distribution analysis.

```bash
python3 main.py analytics [--scan-id <id>] [--format json|markdown|both] [-o output]
```

**Example**:
```bash
# Analytics for latest scan
python3 main.py analytics

# Generate markdown report
python3 main.py analytics --format markdown -o report.md
```

### 7. trends - ASN Trends

Analyze usage trends for a specific ASN over time.

```bash
python3 main.py trends <asn> [--days N]
```

**Example**:
```bash
# Track Google's ASN (15169) over 30 days
python3 main.py trends 15169 --days 30
```

### 8. cluster - Domain Clustering

Find domains that share ASN infrastructure.

```bash
python3 main.py cluster [--min-shared N] [-o output.json]
```

**Example**:
```bash
# Find domains sharing 2+ ASNs
python3 main.py cluster --min-shared 2 -o clusters.json
```

### 9. export - Export Data

Export scan data in various formats.

```bash
python3 main.py export <scan-id> -o <output> --format <format>
```

**Supported formats**:
- `json`: Structured JSON
- `csv`: Flattened CSV (one row per IP mapping)
- `parquet`: Apache Parquet for big data tools
- `gexf`: GEXF graph format (for Gephi)
- `graphml`: GraphML format
- `edgelist`: Simple edge list format
- `markdown`: Human-readable report

**Examples**:
```bash
# Export to CSV
python3 main.py export abc123... -o results.csv --format csv

# Export as network graph
python3 main.py export abc123... -o network.gexf --format gexf
```

### 10. visualize - Generate Visualizations

Create charts and interactive dashboards.

```bash
python3 main.py visualize [--scan-id <id>] [--type <type>] [--output-dir <dir>]
```

**Visualization types**:
- `top-asns`: Bar chart of top ASNs
- `distribution`: Pie chart of ASN distribution
- `trends`: Line charts for ASN trends
- `dashboard`: Interactive HTML dashboard
- `all`: Generate all visualizations

**Examples**:
```bash
# Generate all visualizations
python3 main.py visualize

# Create interactive dashboard
python3 main.py visualize --type dashboard --output-dir ./reports
```

### 11. db-init - Initialize Database

Create database tables and schema.

```bash
python3 main.py db-init
```

### 12. db-migrate - Run Migrations

Apply database migrations to upgrade schema.

```bash
python3 main.py db-migrate
```

### 13. web - Start Web Interface

Launch the Flask web application.

```bash
python3 main.py web [--host HOST] [--port PORT]
```

**Example**:
```bash
# Start on all interfaces
python3 main.py web --host 0.0.0.0 --port 5000
```

---

## Web Interface

### Accessing the Interface

After starting the web server:

```bash
python3 main.py web
```

Open your browser to `http://localhost:5000`

### Features

1. **Upload Domain List**: Upload a text file with domains (one per line)
2. **Configure Scan**: Set IP version, DNS timeout, and other options
3. **Real-time Progress**: Watch scan progress with live updates
4. **Download Results**: Export in JSON, CSV, or other formats
5. **View Results**: Browse JSON results in the browser

### Web Interface Workflow

1. Navigate to the home page
2. Click "Upload Domain List" and select your file
3. (Optional) Upload a custom MRT file or use auto-download
4. Configure scan parameters
5. Click "Start Scan"
6. Monitor progress on the status page
7. Download results when complete

---

## Configuration

### Environment Variables

Create a `.env` file in the project root:

```bash
# Application
SESSION_SECRET=your-random-secret-key-here
FLASK_ENV=production
LOG_LEVEL=INFO

# Database
DATABASE_URL=sqlite:///domain_asn_mapper.db
# Or PostgreSQL:
# DATABASE_URL=postgresql://user:pass@localhost:5432/domain_asn_mapper

# MRT Files
AUTO_DOWNLOAD_MRT=true
MRT_DOWNLOAD_URL=https://data.ris.ripe.net/rrc00/latest-bview.gz

# Performance
USE_ASYNC_DNS=true
MAX_CONCURRENT_DNS=50
```

### YAML Configuration

Create `config.yaml` for advanced settings:

```yaml
dns:
  timeout: 5
  retries: 2
  nameservers: null  # Use system default

processing:
  max_workers: 10
  batch_size: 100
  use_async: true

database:
  url: "sqlite:///domain_asn_mapper.db"
  echo: false

logging:
  level: INFO
  json_format: false
  file: logs/app.log
```

### Configuration Priority

Settings are applied in this order (highest to lowest):

1. Environment variables
2. YAML configuration file
3. Default values

---

## Common Workflows

### Workflow 1: Weekly Infrastructure Monitoring

Track domain infrastructure changes over time.

```bash
# Week 1: Initial scan
python3 main.py scan -d domains.txt --save-to-db --notes "Week 1 - Baseline"

# Week 2: Follow-up scan
python3 main.py scan -d domains.txt --save-to-db --notes "Week 2"

# Compare scans
python3 main.py list-scans --limit 2
python3 main.py diff <week1-id> <week2-id> -o weekly-changes.txt

# Review changes
cat weekly-changes.txt
```

### Workflow 2: ASN Analysis

Analyze ASN distribution and identify hosting patterns.

```bash
# Run scan
python3 main.py scan -d domains.txt --save-to-db

# Generate analytics
python3 main.py analytics --format markdown -o asn-report.md

# Find domain clusters
python3 main.py cluster --min-shared 3 -o clusters.json

# Create visualizations
python3 main.py visualize --type all --output-dir ./reports

# Review reports
cat asn-report.md
```

### Workflow 3: Large-Scale Scanning

Process thousands of domains efficiently.

```bash
# Split domains into batches (optional)
split -l 1000 large-domains.txt batch-

# Scan with high concurrency
export MAX_CONCURRENT_DNS=100
python3 main.py scan -d large-domains.txt --save-to-db --notes "Large scan"

# Export to Parquet for analysis
python3 main.py export <scan-id> -o results.parquet --format parquet
```

### Workflow 4: Security Monitoring

Monitor for suspicious infrastructure changes.

```bash
# Daily scan (cron job)
0 0 * * * cd /path/to/domain-asn-mapper && python3 main.py scan -d critical-domains.txt --save-to-db --notes "Daily scan"

# Alert on changes
python3 main.py diff <yesterday-id> <today-id> -o changes.txt
if [ -s changes.txt ]; then
    # Send alert (email, Slack, etc.)
    mail -s "Domain Changes Detected" admin@example.com < changes.txt
fi
```

---

## Troubleshooting

### Issue: MRT File Download Fails

**Symptoms**: Error downloading MRT file, timeout, or connection issues

**Solutions**:
```bash
# Manual download
wget https://data.ris.ripe.net/rrc00/latest-bview.gz -O rib.mrt.gz

# Use manual file
python3 main.py scan -d domains.txt -m rib.mrt.gz

# Disable auto-download
export AUTO_DOWNLOAD_MRT=false
```

### Issue: DNS Resolution Timeouts

**Symptoms**: Slow scans, many failed domains

**Solutions**:
```bash
# Increase timeout in config.yaml
dns:
  timeout: 10
  retries: 3

# Reduce concurrency
export MAX_CONCURRENT_DNS=25

# Use custom DNS servers
dns:
  nameservers:
    - 8.8.8.8
    - 1.1.1.1
```

### Issue: Database Locked (SQLite)

**Symptoms**: "database is locked" errors

**Solutions**:
```bash
# Switch to PostgreSQL for concurrent access
export DATABASE_URL=postgresql://user:pass@localhost:5432/domain_asn_mapper

# Or increase SQLite timeout
database:
  timeout: 30
```

### Issue: Out of Memory

**Symptoms**: Process killed during large scans

**Solutions**:
```bash
# Process in smaller batches
split -l 500 domains.txt batch-
for file in batch-*; do
    python3 main.py scan -d $file --save-to-db
done

# Reduce concurrent operations
export MAX_CONCURRENT_DNS=25

# Disable progress bars
USE_PROGRESS_BAR=false python3 main.py scan -d domains.txt
```

### Issue: Invalid Domain Format

**Symptoms**: "Invalid domain" errors

**Solutions**:
- Ensure domains are one per line
- Remove protocols (`http://`, `https://`)
- Remove paths and query strings
- Use lowercase domain names
- Check for hidden characters or BOM

```bash
# Clean domains file
cat domains.txt | \
  tr '[:upper:]' '[:lower:]' | \
  sed 's/https\?:\/\///' | \
  sed 's/\/.*//' | \
  sort -u > domains-clean.txt
```

---

## FAQ

### General Questions

**Q: What is an ASN?**

A: An Autonomous System Number (ASN) uniquely identifies a network on the Internet. Each ASN represents a collection of IP prefixes managed by a single organization (ISP, cloud provider, enterprise, etc.).

**Q: Why do domains have multiple ASNs?**

A: Domains often use multiple hosting providers, CDNs, or geographically distributed infrastructure, resulting in multiple ASNs.

**Q: How accurate is the ASN data?**

A: ASN data is based on RIPE RIS BGP routing tables, which reflect actual Internet routing. Accuracy depends on the freshness of the MRT file (updated daily).

### Technical Questions

**Q: Can I use custom DNS servers?**

A: Yes, configure them in `config.yaml`:
```yaml
dns:
  nameservers:
    - 8.8.8.8
    - 1.1.1.1
```

**Q: How do I scan only IPv4 or IPv6?**

A: Use the `--ip-version` flag:
```bash
python3 main.py scan -d domains.txt --ip-version 4  # IPv4 only
python3 main.py scan -d domains.txt --ip-version 6  # IPv6 only
```

**Q: Can I export data to Excel?**

A: Export to CSV and open in Excel:
```bash
python3 main.py export <scan-id> -o results.csv --format csv
```

**Q: How do I visualize the network graph?**

A: Export to GEXF and open in Gephi:
```bash
python3 main.py export <scan-id> -o network.gexf --format gexf
```

### Performance Questions

**Q: How fast is v2.0 compared to v1.0?**

A: Approximately 15x faster (4.5 → 63.4 domains/sec on M1 MacBook Pro).

**Q: Can I make it even faster?**

A: Yes, increase concurrency:
```bash
export MAX_CONCURRENT_DNS=100
```

**Q: What's the recommended batch size for large scans?**

A: Process in batches of 1,000-5,000 domains for optimal memory usage.

### Database Questions

**Q: Should I use SQLite or PostgreSQL?**

A:
- **SQLite**: Development, single-user, < 10,000 domains
- **PostgreSQL**: Production, multi-user, > 10,000 domains

**Q: How do I backup the database?**

A:
```bash
# SQLite
cp domain_asn_mapper.db domain_asn_mapper.db.backup

# PostgreSQL
pg_dump domain_asn_mapper > backup.sql
```

**Q: Can I delete old scans?**

A: Not yet implemented in v2.0, but you can use SQL:
```sql
DELETE FROM scans WHERE started_at < '2024-01-01';
```

### Deployment Questions

**Q: Can I deploy this in production?**

A: Yes! Use Docker Compose with PostgreSQL:
```bash
docker-compose up -d
```

**Q: Is it secure?**

A: Yes, v2.0 includes:
- Session secret enforcement
- Security headers (CSP, X-Frame-Options, HSTS)
- Input validation
- Rate limiting

**Q: How do I monitor the application?**

A: Use the health and metrics endpoints:
```bash
curl http://localhost:5000/health
curl http://localhost:5000/metrics
```

---

## Next Steps

- Explore the [Developer Guide](DEVELOPER_GUIDE.md) for architecture details
- Read the [RIPE Labs article](RIPE_LABS_ARTICLE.md) for the full development story
- Check out [example outputs](examples/) for inspiration
- Join the [GitHub Discussions](https://github.com/yourusername/domain-asn-mapper/discussions)

---

**Need help?** Open an issue on [GitHub](https://github.com/yourusername/domain-asn-mapper/issues) or check the documentation at [docs/]().
