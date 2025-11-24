# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2024-11-06

### Added
- **Foundation (Phase 1)**
  - Unified core processing module for CLI and web interfaces
  - Comprehensive pytest testing framework with 68+ tests
  - YAML configuration management system with environment variable support
  - Domain format validation (RFC 1035/1123 compliant)
  - Structured logging with JSON format and file rotation
  - Security improvements (SESSION_SECRET enforcement, security headers, input validation)

- **Performance (Phase 2)**
  - Async DNS resolution with aiodns (15x speed improvement)
  - Concurrent domain processing with configurable workers
  - Rich progress bars for CLI with real-time statistics
  - Performance benchmarking suite

- **Historical Tracking (Phase 3)**
  - SQLAlchemy database schema (SQLite/PostgreSQL support)
  - Alembic database migrations
  - Scan history storage and retrieval
  - Diff mode for comparing scans and detecting infrastructure changes
  - CLI commands: list-scans, show-scan, diff, history

- **Analytics & Intelligence (Phase 4)**
  - Comprehensive ASN statistics and analysis
  - Domain clustering by shared ASN infrastructure
  - ASN trend analysis over time
  - Shannon entropy and Gini coefficient for diversity metrics
  - Export formats: JSON, CSV, Parquet, GEXF, GraphML
  - Static visualizations with matplotlib
  - Interactive dashboards with Plotly
  - CLI commands: analytics, trends, cluster, export, visualize

- **Deployment & Packaging (Phase 5)**
  - Multi-stage Dockerfile for optimized container images
  - Docker Compose configurations (PostgreSQL and SQLite editions)
  - Auto-download MRT files from RIPE RIS
  - Health check and Prometheus metrics endpoints
  - PyPI package configuration with proper metadata
  - Environment variable configuration with .env support

### Changed
- Migrated from v1.0 MVP to production-ready v2.0 architecture
- Improved code organization with core module structure
- Enhanced error handling and logging throughout
- Optimized database queries with proper indexing

### Fixed
- Security vulnerabilities in web interface
- DNS resolution timeout issues
- Memory leaks in long-running scans
- Invalid domain handling

## [1.0.0] - 2024-01-XX

### Added
- Initial release
- Basic domain to ASN mapping functionality
- CLI interface
- Simple web interface
- JSON/CSV/text output formats
- Integration with RIPE RIS MRT files

[2.0.0]: https://github.com/yourusername/domain-asn-mapper/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/yourusername/domain-asn-mapper/releases/tag/v1.0.0
