# Domain ASN Mapper v2.0: Production-Ready Infrastructure Analysis

## From MVP to Enterprise: Building a Scalable Network Intelligence Tool

*By Soroush Rafiee Rad*

---

## Introduction

Last year, I introduced the Domain ASN Mapper on RIPE Labs – a tool that maps domain names to their underlying Autonomous System Numbers (ASNs) by correlating DNS records with BGP routing data. The response from the community was encouraging, with researchers, network operators, and security professionals finding value in understanding domain infrastructure relationships.

Today, I'm excited to share **version 2.0**: a complete architectural overhaul that transforms the original proof-of-concept into a production-ready system with enterprise-grade features. This article details the journey from v1.0 to v2.0, the technical challenges overcome, and the new capabilities that enable deeper network intelligence analysis.

## Community Impact

Since v1.0's release, network operators across the RIPE community have deployed the tool for infrastructure monitoring, security research, and operational analysis. The feedback revealed a clear need: production-scale performance, historical tracking for change detection, and integration with existing monitoring workflows.

Version 2.0 directly addresses these operational requirements while maintaining the tool's reliance on RIPE RIS data as its foundation. By providing both lightweight (SQLite) and enterprise (PostgreSQL) deployment options, the tool scales from individual research to NOC operations, making infrastructure intelligence accessible to organizations of all sizes.

---

## The Challenge: Scaling from Prototype to Production

The original Domain ASN Mapper (v1.0) proved the concept effectively:
- Map domains to ASNs using DNS resolution and MRT files
- Simple CLI and web interface
- JSON/CSV/text output formats

However, real-world usage revealed several limitations:

1. **Performance Bottleneck**: Sequential DNS resolution meant processing 100 domains took over 20 seconds
2. **No Historical Context**: Each scan was standalone – no way to track infrastructure changes over time
3. **Limited Analysis**: Basic mapping without statistical analysis or trend detection
4. **Deployment Complexity**: Manual setup, no containerization, difficult to maintain
5. **Scalability Issues**: No database backend, results only in flat files

Version 2.0 addresses these challenges systematically through a **seven-phase development approach**.

---

## Phase 1: Foundation - Building for Scale

The first step was establishing a solid foundation with modern Python best practices.

### Unified Core Module

Instead of duplicate code between CLI and web interfaces, v2.0 introduces a unified `core/` module:

```python
from core import DomainProcessor

processor = DomainProcessor(
    mrt_file='rib.mrt.gz',
    use_async=True,
    max_concurrent=50
)

results = processor.process_domains(
    domains_file='domains.txt',
    output_file='results.json'
)
```

This architecture enables:
- Code reuse across interfaces
- Easier testing and maintenance
- Plugin architecture for future extensions

### YAML Configuration Management

Environment-specific settings move from hardcoded values to flexible YAML configuration with priority: `Environment Variables > Config File > Defaults`. This allows operators to customize DNS timeouts, concurrency limits, and database connections without code changes.

### Domain Validation

RFC 1035/1123 compliant validation prevents invalid inputs from reaching DNS resolvers, catching malformed domains before they consume network resources.

### Comprehensive Testing

Version 2.0 includes 68+ tests covering:
- DNS resolution (24 tests)
- ASN lookup (13 tests)
- Core processing (20+ tests)
- Output formatting
- Error handling

**Test Coverage**: ~75%

---

## Phase 2: Performance - From 4.5 to 63.4 Domains/Second

The performance bottleneck was clear: sequential DNS resolution. The solution: **asynchronous DNS resolution with controlled concurrency**.

### Async DNS Resolution with aiodns

```python
class AsyncDNSProcessor:
    async def resolve_domains_batch(
        self,
        domains: List[str],
        max_concurrent: int = 50
    ):
        semaphore = asyncio.Semaphore(max_concurrent)

        async def resolve_with_limit(domain):
            async with semaphore:
                return await self.resolve_domain(domain)

        tasks = [resolve_with_limit(d) for d in domains]
        return await asyncio.gather(*tasks)
```

### Performance Benchmarks

Tested on MacBook Pro M1, 100 domains:

| Version | Method | Throughput | Time | Improvement |
|---------|--------|-----------|------|-------------|
| v1.0 | Sequential | 4.5/sec | 22.2s | Baseline |
| v2.0 | Async (50 concurrent) | 63.4/sec | 1.58s | **15x faster** |

### Rich Progress Bars

Real-time feedback during scans:

```
Processing Domains ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100%
  ⏱ Elapsed: 1.58s
  📊 Rate: 63.4 domains/sec
  ✅ Success: 98/100
  ❌ Failed: 2/100
```

---

## Phase 3: Historical Tracking - Database Backend

Understanding infrastructure changes requires historical data. Phase 3 introduces a complete database layer.

### SQLAlchemy Schema

Five core tables track scans and changes:

```
scans                    - Scan metadata (ID, timestamp, status)
  ├── domain_scans       - Per-domain results for each scan
  │   ├── ip_asn_mappings  - Individual IP-ASN pairs
  │   └── infrastructure_changes  - Detected changes
  └── domains           - Unique domain metadata
```

**Key Features**:
- SQLite for development/small deployments
- PostgreSQL for production/scale
- Comprehensive indexing for performance
- Alembic migrations for schema evolution

### Change Detection

The `ScanDiff` class compares scans and identifies infrastructure changes including IP additions/removals, ASN migrations, nameserver changes, mail server modifications, and MX preference updates.

### Example: Weekly Monitoring

```bash
# Week 1
python3 main.py scan -d domains.txt -m rib.mrt.gz \
    --save-to-db --notes "Week 1 baseline"

# Week 2
python3 main.py scan -d domains.txt -m rib.mrt.gz \
    --save-to-db --notes "Week 2 check"

# Compare
python3 main.py diff <week1-id> <week2-id> -o weekly-changes.txt
```

**Output**:
```
======================================================================
SCAN COMPARISON REPORT
======================================================================

🔄 Domains with infrastructure changes: 8
   Total changes detected: 12

   example.com:
      ℹ️ 1 A record(s) added
      ⚠️ ASN changed for A record 203.0.113.5 (AS15169 → AS16509)

   test-domain.org:
      ⚠️ 1 nameserver(s) removed
      ℹ️ 2 A record(s) added
```

---

## Phase 4: Analytics & Intelligence

Raw mapping data becomes actionable intelligence through statistical analysis.

### ASN Statistics

Comprehensive distribution analysis provides metrics including total unique ASNs, IP mappings per ASN, concentration ratios, and distribution patterns.

**Example Output**:
```
======================================================================
ASN STATISTICS
======================================================================
Total Unique ASNs:    12
Total IP Mappings:    45
Avg IPs per ASN:      3.75
Concentration Ratio:  67.85%  # Top 10% ASNs serve 67.85% of IPs

Top ASNs:
  1. AS15169 (Google LLC): 18 IPs, 8 domains (40.0%)
  2. AS13335 (Cloudflare): 12 IPs, 5 domains (26.7%)
  3. AS16509 (Amazon AWS): 7 IPs, 4 domains (15.6%)
```

### Domain Clustering

Identify domains sharing infrastructure to detect related properties, infrastructure consolidation, and organizational boundaries.

**Example**:
```
Cluster 1: 12 domains sharing AS15169, AS16509
  google.com, youtube.com, gmail.com, drive.google.com...

Cluster 2: 8 domains on Cloudflare (AS13335)
  cloudflare.com, workers.dev, pages.dev...
```

### Diversity Metrics

Shannon entropy and Gini coefficient measure ASN diversity across three levels: High (>70, well-distributed), Medium (40-70, moderate concentration), and Low (<40, heavy concentration).

**Applications**:
- Risk assessment (single points of failure)
- Infrastructure resilience evaluation
- Dependency analysis

### Export Formats

Data export in multiple formats for analysis tools:

```bash
# CSV for spreadsheets
python3 main.py export <scan-id> -o results.csv --format csv

# Parquet for big data tools (Spark, Pandas)
python3 main.py export <scan-id> -o results.parquet --format parquet

# GEXF/GraphML for network visualization (Gephi, Cytoscape)
python3 main.py export <scan-id> -o network.gexf --format gexf
```

### Visualizations

The tool generates static (Matplotlib) and interactive (Plotly) visualizations including ASN distribution charts, trend graphs, diversity gauges, and interactive HTML dashboards for presentations and reports.

---

## Phase 5: Deployment & Packaging

Production readiness requires streamlined deployment and distribution.

### Docker Containerization

Multi-stage Docker builds reduce image size by ~200MB, with separate configurations for development (SQLite) and production (PostgreSQL). Container orchestration is supported through health check endpoints and Prometheus metrics integration.

### MRT Auto-Download

Automatic MRT file management downloads and caches RIPE RIS data for 7 days, with progress tracking and automatic updates, eliminating manual file management.

### PyPI Distribution

The package will be published to PyPI for simple installation: `pip install domain-asn-mapper[all]`

---

## Architecture Overview

Version 2.0 follows a clean, modular architecture:

```
┌─────────────────────────────────────────────────┐
│                 User Interface                   │
│  ┌──────────────────┐  ┌────────────────────┐  │
│  │  CLI (main.py)   │  │  Web (app.py)      │  │
│  │  13 commands     │  │  Flask UI          │  │
│  └──────────────────┘  └────────────────────┘  │
└──────────────────┬──────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────┐
│              Core Processing Layer               │
│  ┌──────────────────────────────────────────┐  │
│  │  DomainProcessor (unified logic)         │  │
│  │  ├─ AsyncDNSProcessor                    │  │
│  │  ├─ ASNProcessor                         │  │
│  │  └─ OutputFormatter                      │  │
│  └──────────────────────────────────────────┘  │
└──────────────────┬──────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────┐
│         Analytics & Intelligence Layer           │
│  ┌──────────────┐  ┌──────────────────────┐    │
│  │ ASNAnalytics │  │  ScanDiff            │    │
│  │ - Statistics │  │  - Change detection  │    │
│  │ - Clustering │  │  - Comparison        │    │
│  │ - Trends     │  │  - Reports           │    │
│  └──────────────┘  └──────────────────────┘    │
└──────────────────┬──────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────┐
│              Storage & Export Layer              │
│  ┌────────────────┐  ┌──────────────────────┐  │
│  │  SQLAlchemy DB │  │  Export Handlers     │  │
│  │  - SQLite      │  │  - JSON, CSV         │  │
│  │  - PostgreSQL  │  │  - Parquet           │  │
│  │  - Migrations  │  │  - Graph formats     │  │
│  └────────────────┘  └──────────────────────┘  │
└──────────────────────────────────────────────────┘
```

---

## Real-World Applications

Version 2.0 enables several practical use cases:

### 1. Infrastructure Monitoring

Track domain infrastructure changes for security and operations:

```bash
# Daily monitoring
0 2 * * * /app/scan_and_diff.sh
```

**Alerts on**:
- Unexpected ASN changes (potential DNS hijacking)
- Nameserver modifications
- Infrastructure consolidation
- Geographic shifts

### 2. Dependency Mapping

Understand organizational infrastructure boundaries:

```bash
# Find related domains
python3 main.py cluster --min-shared 3 -o clusters.json

# Analyze results
jq '.[] | select(.domain_count > 5)' clusters.json
```

### 3. Risk Assessment

Evaluate infrastructure resilience:

```python
# Calculate diversity score
diversity = analytics.get_asn_diversity_score()

if diversity['diversity_score'] < 40:
    print("⚠️  High concentration - single point of failure risk")
```

### 4. Competitive Intelligence

Analyze competitor infrastructure:

```bash
# Track competitor ASN usage trends
python3 main.py trends 15169 --days 90 -o google_trends.json
```

### 5. Research & Analysis

Export data for academic research:

```bash
# Export to Parquet for Spark/Pandas analysis
python3 main.py export <scan-id> -o dataset.parquet --format parquet

# Generate network graph for Gephi
python3 main.py export <scan-id> -o network.gexf --format gexf
```

---

## Performance Considerations

Key optimization strategies include concurrency tuning (adjustable via `MAX_CONCURRENT_DNS`), appropriate database selection (SQLite for <10K domains, PostgreSQL for production), MRT file caching (7-day validity), and batch processing for large domain lists.

**Scaling Guidelines**: Small deployments (<1K domains) run on SQLite in under a minute, medium deployments (1K-10K) take 1-5 minutes, while large-scale operations (>100K domains) require PostgreSQL with optimized concurrency settings and may benefit from sharding strategies.

---

## Lessons Learned

Building v2.0 taught four valuable lessons:

1. **Async Performance Justifies Complexity**: The 15x speedup from async DNS resolution validated the architectural investment, though maintaining fallback paths proved essential for edge cases.

2. **Configuration Flexibility Enables Adoption**: Supporting YAML config, environment variables, and sensible defaults allows operators to deploy without forking code.

3. **Observability Must Be Core**: Health checks and metrics endpoints should be designed in from the start, not retrofitted – they're essential for production deployment.

4. **Docker Democratizes Deployment**: Multi-stage builds with proper optimization significantly reduce deployment friction, making the tool accessible to operators without deep Python expertise.

---

## Future Roadmap

Version 2.0 establishes a solid foundation for future enhancements:

### Planned Features (v2.1-v2.5)

**v2.1: Enhanced Analytics**
- Machine learning for anomaly detection
- Predictive modeling for infrastructure changes
- Risk scoring algorithms

**v2.2: Real-time Monitoring**
- WebSocket-based live updates
- Alert system with webhooks
- Integration with monitoring platforms

**v2.3: Multi-Source Data**
- WHOIS integration
- Certificate Transparency logs
- Passive DNS databases

**v2.4: API & Integrations**
- RESTful API
- GraphQL endpoint
- SIEM integrations
- CI/CD plugins

**v2.5: Advanced Visualization**
- Geographic mapping
- Time-series animation
- 3D network graphs

---

## Getting Started

### Quick Start with Docker

```bash
git clone https://github.com/soshianse/Domain-Reputation-Measure.git
cd Domain-Reputation-Measure
cp .env.example .env
# Edit .env: Set SESSION_SECRET
docker-compose -f docker-compose.sqlite.yml up -d
open http://localhost:5000
```

### Using Python

```bash
pip install domain-asn-mapper[all]
echo "google.com\ngithub.com" > domains.txt
domain-asn-mapper scan -d domains.txt -m rib.mrt.gz --save-to-db
domain-asn-mapper analytics
```

---

## Conclusion

Domain ASN Mapper v2.0 transforms a simple mapping tool into a comprehensive network intelligence platform tailored for operational deployment. The systematic development approach resulted in 15x performance improvement, historical tracking capabilities, advanced analytics, production-ready containerization, and flexible export options.

**For the RIPE Community**: This tool exemplifies how community-provided data (RIS/MRT files) can power practical operational tools. Network operators gain visibility into domain infrastructure changes, security teams detect anomalies, and researchers analyze Internet topology patterns – all built on RIPE's open data infrastructure.

Version 2.0 makes these capabilities accessible to organizations of all sizes, from individual researchers to enterprise NOCs. The tool is open-source (MIT license), and community contributions are welcome as we continue evolving it based on operational feedback.

---

## Resources

- **GitHub Repository**: https://github.com/soshianse/Domain-Reputation-Measure
- **Original v1.0 Article**: https://labs.ripe.net/author/soroush-rafiee-rad/domain-asn-mapper-understanding-domain-infrastructure/
- **Documentation**: See repository README and user guides

---

## About the Author

Soroush Rafiee Rad is a network security researcher focusing on infrastructure analysis and threat intelligence. He contributes to open-source network analysis tools and publishes research on domain infrastructure patterns.

---

**Acknowledgments**

Thanks to the RIPE NCC for providing access to RIS data, the open-source community for the excellent Python libraries (dnspython, pyasn, Flask, SQLAlchemy), and all the users who provided feedback on v1.0 that shaped v2.0's development.
