# Domain ASN Mapper v2.0 - Developer Guide

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Project Structure](#project-structure)
3. [Core Modules](#core-modules)
4. [Development Setup](#development-setup)
5. [Testing](#testing)
6. [Database Design](#database-design)
7. [Extending the System](#extending-the-system)
8. [Performance Optimization](#performance-optimization)
9. [Deployment](#deployment)
10. [Contributing](#contributing)

---

## Architecture Overview

### Design Principles

Domain ASN Mapper v2.0 follows these architectural principles:

1. **Separation of Concerns**: Core logic separated from CLI and web interfaces
2. **Dependency Injection**: Configuration and dependencies passed explicitly
3. **Async-First**: Built for concurrent processing from the ground up
4. **Database-Backed**: Historical tracking with relational database
5. **Extensibility**: Plugin architecture for exporters, visualizations, analytics

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     User Interfaces                          │
│  ┌──────────────┐              ┌──────────────┐            │
│  │   CLI (main.py)  │              │  Web (app.py)   │            │
│  └──────┬───────┘              └──────┬───────┘            │
└─────────┼──────────────────────────────┼──────────────────┘
          │                              │
          └──────────────┬───────────────┘
                         │
          ┌──────────────▼───────────────┐
          │         core/ Module          │
          │  ┌─────────────────────────┐ │
          │  │  DomainProcessor        │ │
          │  │  (Orchestration)        │ │
          │  └──────────┬──────────────┘ │
          │             │                 │
          │  ┌──────────▼──────────────┐ │
          │  │  AsyncDNSProcessor      │ │
          │  │  (DNS Resolution)       │ │
          │  └──────────┬──────────────┘ │
          │             │                 │
          │  ┌──────────▼──────────────┐ │
          │  │  ASNProcessor           │ │
          │  │  (pyasn lookup)         │ │
          │  └──────────┬──────────────┘ │
          │             │                 │
          │  ┌──────────▼──────────────┐ │
          │  │  ScanStorage            │ │
          │  │  (Database Layer)       │ │
          │  └──────────┬──────────────┘ │
          │             │                 │
          └─────────────┼─────────────────┘
                        │
          ┌─────────────▼─────────────┐
          │  SQLAlchemy ORM            │
          │  ┌────────┬────────┬──────┤
          │  │ SQLite │ Postgres│ ...  │
          └──┴────────┴────────┴──────┘
```

### Data Flow

1. **Input**: Domain list provided via CLI or web upload
2. **DNS Resolution**: Async resolution of A, AAAA, NS, MX records
3. **ASN Lookup**: IP addresses mapped to ASNs via pyasn
4. **Storage**: Results stored in database with relationships
5. **Analysis**: Analytics computed on stored data
6. **Output**: Export in various formats or visualizations

---

## Project Structure

```
domain-asn-mapper/
├── core/                          # Core processing modules
│   ├── __init__.py               # Module exports
│   ├── processor.py              # Main orchestration
│   ├── async_dns_processor.py   # Async DNS resolution
│   ├── database.py               # SQLAlchemy models
│   ├── scan_storage.py           # Database operations
│   ├── scan_diff.py              # Change detection
│   ├── asn_analytics.py          # Analytics engine
│   ├── exporters.py              # Export formats
│   ├── visualizations.py         # Chart generation
│   ├── config.py                 # Configuration
│   ├── validators.py             # Input validation
│   ├── logging_config.py         # Logging setup
│   └── mrt_downloader.py         # MRT management
│
├── main.py                       # CLI entry point
├── app.py                        # Flask web application
├── asn_processor.py              # ASN lookup (legacy, used by both)
├── dns_processor.py              # DNS utilities (legacy)
├── output_formatter.py           # Output formatting (legacy)
│
├── alembic/                      # Database migrations
│   ├── env.py                    # Alembic environment
│   └── versions/                 # Migration files
│       └── 2247a813c248_initial_database_schema.py
│
├── templates/                    # Web UI templates
│   ├── index.html
│   ├── result.html
│   └── status.html
│
├── tests/                        # Test suite
│   ├── conftest.py              # Pytest fixtures
│   ├── test_dns_processor.py
│   ├── test_asn_processor.py
│   ├── test_core_processor.py
│   └── test_output_formatter.py
│
├── docs/                         # Documentation
│   ├── USER_GUIDE.md
│   ├── DEVELOPER_GUIDE.md
│   ├── RIPE_LABS_ARTICLE.md
│   └── examples/
│
├── config.example.yaml           # Configuration template
├── .env.example                  # Environment template
├── pyproject.toml                # Package configuration
├── alembic.ini                   # Alembic config
├── pytest.ini                    # Pytest config
├── Dockerfile                    # Container image
├── docker-compose.yml            # PostgreSQL setup
├── docker-compose.sqlite.yml     # SQLite setup
├── CHANGELOG.md
├── LICENSE
└── README.md
```

---

## Core Modules

### core/processor.py

**Purpose**: Main orchestration and domain processing pipeline

**Key Classes**:

```python
class DomainProcessor:
    """
    Orchestrates the entire domain processing pipeline.
    Coordinates DNS resolution, ASN lookup, and result aggregation.
    """

    def __init__(
        self,
        mrt_file: str,
        ip_version: Optional[int] = None,
        verbose: bool = False,
        use_async: bool = True,
        max_concurrent: int = 50,
        show_progress: bool = True
    ):
        # Initialize DNS resolver, ASN processor, etc.

    def process_domains(
        self,
        domains: List[str],
        save_to_db: bool = False,
        scan_notes: str = ""
    ) -> Dict[str, Any]:
        """
        Main processing entry point.
        Returns structured results with metadata.
        """
```

**Design Pattern**: Facade pattern - provides simple interface to complex subsystems

**Extension Point**: Override `process_single_domain()` for custom processing logic

### core/async_dns_processor.py

**Purpose**: High-performance async DNS resolution

**Key Classes**:

```python
class AsyncDNSProcessor:
    """
    Async DNS resolver using aiodns.
    Handles A, AAAA, NS, MX record resolution with concurrency control.
    """

    async def resolve_domain(
        self,
        domain: str,
        record_type: str
    ) -> List[str]:
        """Resolve a single DNS record type."""

    async def resolve_domains_batch(
        self,
        domains: List[str],
        max_concurrent: int = 50
    ) -> List[Dict[str, Any]]:
        """
        Resolve multiple domains concurrently.
        Uses semaphore for concurrency control.
        """
```

**Performance**: 15x faster than sequential resolution

**Extension Point**: Add custom record types in `_resolve_all_records()`

### core/database.py

**Purpose**: SQLAlchemy ORM models and database management

**Key Classes**:

```python
class Scan(Base):
    """Represents a scan session."""
    __tablename__ = 'scans'

    id = Column(Integer, primary_key=True)
    scan_id = Column(String(36), unique=True, index=True)
    started_at = Column(DateTime, nullable=False)
    status = Column(String(20))

    # Relationships
    domain_scans = relationship('DomainScan', back_populates='scan')

class Domain(Base):
    """Represents a unique domain."""
    __tablename__ = 'domains'

    id = Column(Integer, primary_key=True)
    domain_name = Column(String(255), unique=True, index=True)
    first_seen = Column(DateTime)
    last_seen = Column(DateTime)

class DomainScan(Base):
    """Links domains to scans with DNS/ASN data."""
    __tablename__ = 'domain_scans'

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scans.id'))
    domain_id = Column(Integer, ForeignKey('domains.id'))
    dns_data = Column(JSON)  # Stores A, AAAA, NS, MX records

    # Relationships
    ip_asn_mappings = relationship('IPASNMapping')

class IPASNMapping(Base):
    """Individual IP-to-ASN mappings."""
    __tablename__ = 'ip_asn_mappings'

    ip_address = Column(String(45), index=True)
    asn = Column(Integer, index=True)
    asn_holder = Column(String(255))
    prefix = Column(String(45))

class InfrastructureChange(Base):
    """Detected changes between scans."""
    __tablename__ = 'infrastructure_changes'

    change_type = Column(String(50))  # A_added, asn_changed, etc.
    old_value = Column(JSON)
    new_value = Column(JSON)
```

**Design Pattern**: Active Record pattern via SQLAlchemy ORM

**Extension Point**: Add new tables/models for additional tracking

### core/scan_storage.py

**Purpose**: Database operations and data access layer

**Key Classes**:

```python
class ScanStorage:
    """
    Handles all database operations for scans.
    Provides CRUD operations and complex queries.
    """

    def save_scan(
        self,
        scan_id: str,
        domains_data: List[Dict],
        metadata: Dict
    ) -> str:
        """Save complete scan to database."""

    def get_scan(self, scan_id: str) -> Optional[Dict]:
        """Retrieve scan with all related data."""

    def list_scans(self, limit: int = 50) -> List[Dict]:
        """List recent scans."""

    def get_domain_history(
        self,
        domain: str,
        limit: int = 10
    ) -> List[Dict]:
        """Get historical data for a domain."""
```

**Design Pattern**: Repository pattern - abstracts data access

**Extension Point**: Add custom queries as methods

### core/scan_diff.py

**Purpose**: Compare scans and detect infrastructure changes

**Key Classes**:

```python
class ScanDiff:
    """
    Compares two scans to identify changes.
    Tracks IP, ASN, DNS record modifications.
    """

    def compare_domain(self, domain: str) -> Dict[str, Any]:
        """Compare single domain between scans."""

    def generate_report(self) -> str:
        """Human-readable change report."""

    def _detect_ip_changes(self, old_ips, new_ips):
        """Detect added/removed IPs."""

    def _detect_asn_changes(self, old_mappings, new_mappings):
        """Detect ASN changes for same IPs."""
```

**Algorithm**: Set-based diff with value comparison

**Extension Point**: Add custom change detection logic

### core/asn_analytics.py

**Purpose**: Statistical analysis and insights

**Key Classes**:

```python
class ASNAnalytics:
    """
    Provides ASN-focused analytics and insights.
    Computes statistics, trends, clustering, diversity metrics.
    """

    def get_asn_statistics(
        self,
        scan_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Overall ASN distribution and concentration."""

    def get_asn_trends(
        self,
        asn: int,
        days: int = 30
    ) -> Dict[str, Any]:
        """Time-series analysis of ASN usage."""

    def cluster_domains_by_asn(
        self,
        min_shared_asns: int = 2
    ) -> List[Dict]:
        """Find domains sharing infrastructure."""

    def get_asn_diversity_score(
        self,
        scan_id: Optional[str] = None
    ) -> Dict[str, float]:
        """Calculate Shannon entropy and Gini coefficient."""
```

**Algorithms**:
- **Concentration Ratio**: Top N ASNs / Total ASNs
- **Shannon Entropy**: -Σ(p_i * log(p_i))
- **Gini Coefficient**: Inequality measure

**Extension Point**: Add custom analytics methods

### core/exporters.py

**Purpose**: Multi-format data export

**Key Classes**:

```python
class DataExporter(ABC):
    """Abstract base class for all exporters."""

    @abstractmethod
    def export(self, data: Any) -> bool:
        pass

class JSONExporter(DataExporter):
    """Export to JSON format."""

class FlatCSVExporter(DataExporter):
    """Export to flattened CSV."""

class ParquetExporter(DataExporter):
    """Export to Apache Parquet."""

class ASNGraphExporter(DataExporter):
    """Export as network graph (GEXF, GraphML)."""
```

**Design Pattern**: Strategy pattern - interchangeable exporters

**Extension Point**: Create new exporter by subclassing `DataExporter`

### core/visualizations.py

**Purpose**: Chart and dashboard generation

**Key Classes**:

```python
class ASNVisualizer:
    """
    Creates static and interactive visualizations.
    Uses matplotlib for static, Plotly for interactive.
    """

    def plot_top_asns(
        self,
        analytics_data: Dict,
        output_path: str,
        top_n: int = 15
    ):
        """Bar chart of top ASNs."""

    def plot_asn_distribution(
        self,
        analytics_data: Dict,
        output_path: str
    ):
        """Pie chart of ASN concentration."""

    def create_interactive_dashboard(
        self,
        analytics_data: Dict,
        output_path: str
    ):
        """Full Plotly HTML dashboard."""
```

**Extension Point**: Add new visualization methods

### core/config.py

**Purpose**: Configuration management

**Key Classes**:

```python
class Config:
    """
    Hierarchical configuration management.
    Priority: ENV > YAML > Defaults
    """

    def __init__(self, config_file: Optional[str] = None):
        self._load_defaults()
        if config_file:
            self._load_yaml(config_file)
        self._load_env_overrides()

    def get(self, key: str, default: Any = None) -> Any:
        """Get config value with dot notation."""
```

**Pattern**: Singleton with lazy initialization via `get_config()`

**Extension Point**: Add new config keys in `_load_defaults()`

---

## Development Setup

### Prerequisites

- Python 3.11+
- Git
- Optional: Docker, PostgreSQL

### Local Setup

```bash
# Clone repository
git clone https://github.com/yourusername/domain-asn-mapper.git
cd domain-asn-mapper

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows

# Install with development dependencies
pip install -e ".[dev]"

# Initialize database
python3 main.py db-init

# Run tests
pytest

# Run linters
black .
ruff check .
mypy core/
```

### IDE Setup

#### VS Code

Create `.vscode/settings.json`:

```json
{
  "python.linting.enabled": true,
  "python.linting.pylintEnabled": false,
  "python.linting.flake8Enabled": true,
  "python.formatting.provider": "black",
  "python.testing.pytestEnabled": true,
  "python.testing.unittestEnabled": false
}
```

#### PyCharm

1. Mark `core/` as Sources Root
2. Enable pytest as test runner
3. Configure Black as formatter
4. Enable type checking with mypy

---

## Testing

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=core --cov=main --cov=app

# Run specific test file
pytest tests/test_core_processor.py

# Run specific test
pytest tests/test_core_processor.py::test_process_domains

# Run with verbose output
pytest -v

# Run with print statements
pytest -s
```

### Test Structure

```python
# tests/conftest.py - Shared fixtures
@pytest.fixture
def sample_domains():
    return ["google.com", "github.com"]

@pytest.fixture
def mock_config():
    return Config()

# tests/test_core_processor.py
def test_domain_processor_init(mock_config):
    """Test DomainProcessor initialization."""
    processor = DomainProcessor(
        mrt_file="test.mrt",
        use_async=False
    )
    assert processor is not None

@pytest.mark.asyncio
async def test_async_dns_resolution():
    """Test async DNS resolution."""
    processor = AsyncDNSProcessor()
    result = await processor.resolve_domain("google.com", "A")
    assert len(result) > 0
```

### Writing Tests

**Guidelines**:

1. **Test Structure**: Arrange-Act-Assert (AAA)
2. **Fixtures**: Use fixtures for setup/teardown
3. **Mocking**: Mock external dependencies (DNS, database)
4. **Async Tests**: Use `@pytest.mark.asyncio`
5. **Coverage**: Aim for 80%+ code coverage

**Example**:

```python
@pytest.fixture
def mock_dns_response(mocker):
    """Mock DNS response for testing."""
    mock = mocker.patch('aiodns.DNSResolver.query')
    mock.return_value = [
        mocker.Mock(host='142.250.185.46')
    ]
    return mock

def test_process_domain_with_mock(mock_dns_response):
    """Test domain processing with mocked DNS."""
    processor = DomainProcessor(
        mrt_file="test.mrt",
        use_async=True
    )
    result = processor.process_domains(["google.com"])

    assert result["total_domains"] == 1
    assert result["successful"] == 1
    mock_dns_response.assert_called()
```

---

## Database Design

### Schema Overview

The database uses 5 tables with relationships:

```
scans (1) ──────< (N) domain_scans (N) ─────> (1) domains
                       │
                       └──< (N) ip_asn_mappings

infrastructure_changes references scans
```

### Design Decisions

1. **Normalized Structure**: Separate tables for domains, scans, mappings
2. **JSON Storage**: DNS data stored as JSON for flexibility
3. **Indexes**: On frequently queried columns (domain_name, scan_id, asn)
4. **Timestamps**: Track first_seen, last_seen for domains
5. **Relationships**: SQLAlchemy relationships for easy navigation

### Migrations

Using Alembic for schema evolution:

```bash
# Create new migration
alembic revision --autogenerate -m "Add new feature"

# Apply migrations
python3 main.py db-migrate

# Rollback
alembic downgrade -1

# View history
alembic history
```

**Migration Template**:

```python
# alembic/versions/xxxxx_add_feature.py
from alembic import op
import sqlalchemy as sa

def upgrade():
    op.add_column('scans', sa.Column('new_field', sa.String(100)))

def downgrade():
    op.drop_column('scans', 'new_field')
```

### Querying

**Direct SQLAlchemy**:

```python
from core.database import get_database_manager, Scan, Domain

db_manager = get_database_manager()
session = db_manager.get_session()

# Query scans
recent_scans = session.query(Scan)\
    .filter(Scan.status == 'completed')\
    .order_by(Scan.started_at.desc())\
    .limit(10)\
    .all()

# Join query
domains_with_scans = session.query(Domain, DomainScan)\
    .join(DomainScan)\
    .filter(Domain.domain_name == 'google.com')\
    .all()

session.close()
```

**Via ScanStorage**:

```python
from core import ScanStorage

storage = ScanStorage()

# Get scan
scan_data = storage.get_scan(scan_id)

# Domain history
history = storage.get_domain_history("google.com", limit=5)
```

---

## Extending the System

### Adding a New Exporter

1. **Create exporter class**:

```python
# core/exporters.py
class XMLExporter(DataExporter):
    """Export data to XML format."""

    def __init__(self, output_path: str):
        self.output_path = output_path

    def export(self, data: Any) -> bool:
        try:
            root = ET.Element("scan_results")
            # Build XML tree
            tree = ET.ElementTree(root)
            tree.write(self.output_path)
            return True
        except Exception as e:
            logger.error(f"XML export failed: {e}")
            return False
```

2. **Register in CLI**:

```python
# main.py - export command
if args.format == 'xml':
    exporter = XMLExporter(args.output)
    exporter.export(scan_data)
```

### Adding a New Visualization

1. **Add method to ASNVisualizer**:

```python
# core/visualizations.py
class ASNVisualizer:
    def plot_asn_heatmap(
        self,
        analytics_data: Dict,
        output_path: str
    ):
        """Create heatmap of ASN usage over time."""
        # Extract data
        asns = analytics_data['top_asns']
        dates = analytics_data['dates']

        # Create heatmap
        fig, ax = plt.subplots(figsize=(12, 8))
        sns.heatmap(data, ax=ax)
        plt.savefig(output_path)
```

2. **Add to CLI**:

```python
# main.py - visualize command
if args.type == 'heatmap':
    visualizer.plot_asn_heatmap(analytics_data, output_path)
```

### Adding a New Analytics Method

```python
# core/asn_analytics.py
class ASNAnalytics:
    def get_asn_geographic_distribution(
        self,
        scan_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Analyze geographic distribution of ASNs."""

        # Query data
        session = self.db_manager.get_session()
        mappings = session.query(IPASNMapping)\
            .filter(...)\
            .all()

        # Analyze (e.g., using GeoIP lookup)
        distribution = {}
        for mapping in mappings:
            country = self._lookup_asn_country(mapping.asn)
            distribution[country] = distribution.get(country, 0) + 1

        session.close()
        return distribution
```

### Adding a New CLI Command

```python
# main.py
def parse_arguments():
    # ... existing subparsers ...

    # New command
    geocode_parser = subparsers.add_parser(
        'geocode',
        help='Geocode ASNs to countries'
    )
    geocode_parser.add_argument('--scan-id', required=True)
    geocode_parser.add_argument('-o', '--output', required=True)

def main():
    # ... existing commands ...

    elif args.command == 'geocode':
        analytics = ASNAnalytics()
        geo_data = analytics.get_asn_geographic_distribution(
            scan_id=args.scan_id
        )
        # Export results
```

---

## Performance Optimization

### DNS Resolution

**Current**: 63.4 domains/sec (50 concurrent, M1 MacBook Pro)

**Optimization strategies**:

1. **Increase concurrency**:
```bash
export MAX_CONCURRENT_DNS=100
```

2. **Custom DNS servers**:
```yaml
dns:
  nameservers:
    - 8.8.8.8
    - 1.1.1.1
```

3. **Reduce retries**:
```yaml
dns:
  retries: 1  # Default: 2
```

### Database Performance

**SQLite**:
- Good for < 10,000 domains
- Use WAL mode: `PRAGMA journal_mode=WAL`
- Batch inserts with transactions

**PostgreSQL**:
- Use for > 10,000 domains
- Connection pooling: `pool_size=10`
- Bulk inserts: `session.bulk_insert_mappings()`

**Optimization**:

```python
# Batch inserts
session = db_manager.get_session()
try:
    session.bulk_insert_mappings(
        IPASNMapping,
        [{'ip_address': ip, 'asn': asn, ...} for ip, asn in mappings]
    )
    session.commit()
finally:
    session.close()
```

### Memory Management

**For large scans**:

1. **Process in batches**:
```python
BATCH_SIZE = 1000
for i in range(0, len(domains), BATCH_SIZE):
    batch = domains[i:i+BATCH_SIZE]
    processor.process_domains(batch, save_to_db=True)
```

2. **Stream results**:
```python
# Instead of loading all at once
for domain in process_domains_streaming(domains):
    yield domain
```

### Profiling

**CPU profiling**:

```bash
python3 -m cProfile -o profile.stats main.py scan -d domains.txt
python3 -c "import pstats; p = pstats.Stats('profile.stats'); p.sort_stats('cumulative'); p.print_stats(20)"
```

**Memory profiling**:

```bash
pip install memory_profiler
python3 -m memory_profiler main.py scan -d domains.txt
```

---

## Deployment

### Production Checklist

- [ ] Set secure SESSION_SECRET in `.env`
- [ ] Use PostgreSQL for database
- [ ] Enable SSL/TLS for database connections
- [ ] Configure logging to file with rotation
- [ ] Set up monitoring (health checks, metrics)
- [ ] Use reverse proxy (nginx, Caddy)
- [ ] Enable rate limiting
- [ ] Set up backups
- [ ] Configure firewall rules
- [ ] Use process manager (systemd, supervisor)

### Docker Production Deployment

**docker-compose.yml** (production-ready):

```yaml
version: '3.8'

services:
  app:
    build:
      context: .
      dockerfile: Dockerfile
    restart: unless-stopped
    ports:
      - "5000:5000"
    environment:
      - DATABASE_URL=postgresql://user:pass@postgres:5432/db
      - SESSION_SECRET=${SESSION_SECRET}
      - LOG_LEVEL=INFO
    depends_on:
      postgres:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:5000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
    volumes:
      - ./logs:/app/logs
      - ./data:/app/data

  postgres:
    image: postgres:16-alpine
    restart: unless-stopped
    environment:
      - POSTGRES_DB=domain_asn_mapper
      - POSTGRES_USER=${DB_USER}
      - POSTGRES_PASSWORD=${DB_PASSWORD}
    volumes:
      - postgres-data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${DB_USER}"]
      interval: 10s
      timeout: 5s
      retries: 5

  nginx:
    image: nginx:alpine
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./certs:/etc/nginx/certs
    depends_on:
      - app

volumes:
  postgres-data:
```

### Systemd Service

**`/etc/systemd/system/domain-asn-mapper.service`**:

```ini
[Unit]
Description=Domain ASN Mapper
After=network.target

[Service]
Type=simple
User=appuser
WorkingDirectory=/opt/domain-asn-mapper
Environment="DATABASE_URL=sqlite:////opt/domain-asn-mapper/data/db.sqlite"
ExecStart=/opt/domain-asn-mapper/venv/bin/python3 main.py web
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable domain-asn-mapper
sudo systemctl start domain-asn-mapper
sudo systemctl status domain-asn-mapper
```

### Nginx Reverse Proxy

**`nginx.conf`**:

```nginx
upstream app {
    server localhost:5000;
}

server {
    listen 80;
    server_name domain-asn-mapper.example.com;

    location / {
        proxy_pass http://app;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req zone=api burst=20 nodelay;
}
```

---

## Contributing

### Contribution Workflow

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/awesome-feature`
3. **Make changes** with clear, focused commits
4. **Write tests** for new functionality
5. **Update documentation** as needed
6. **Run tests and linters**: `pytest && black . && ruff check .`
7. **Submit pull request** with description

### Code Style

- **Formatter**: Black (line length 100)
- **Linter**: Ruff
- **Type Hints**: Use type hints for all public functions
- **Docstrings**: Google-style docstrings
- **Imports**: Organized by stdlib, third-party, local

**Example**:

```python
from typing import List, Optional, Dict, Any
import logging

from sqlalchemy.orm import Session

from core.database import Scan, Domain

logger = logging.getLogger(__name__)


def process_domains(
    domains: List[str],
    session: Session,
    options: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Process a list of domains and store results.

    Args:
        domains: List of domain names to process
        session: SQLAlchemy database session
        options: Optional processing configuration

    Returns:
        Dictionary with processing results and statistics

    Raises:
        ValueError: If domains list is empty
        DatabaseError: If database operation fails
    """
    if not domains:
        raise ValueError("Domains list cannot be empty")

    # Implementation
    results = {}
    return results
```

### Pull Request Guidelines

**PR Title**: Use conventional commits format

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation only
- `test:` Adding or updating tests
- `refactor:` Code refactoring
- `perf:` Performance improvement
- `chore:` Maintenance tasks

**PR Description** should include:

1. What changed and why
2. Related issue numbers
3. Testing performed
4. Screenshots (if UI changes)
5. Breaking changes (if any)

### Release Process

1. Update version in `pyproject.toml`
2. Update `CHANGELOG.md`
3. Create git tag: `git tag -a v2.1.0 -m "Release v2.1.0"`
4. Push tag: `git push origin v2.1.0`
5. Build package: `python3 -m build`
6. Publish to PyPI: `python3 -m twine upload dist/*`

---

## Advanced Topics

### Custom DNS Resolver

Implement custom resolution logic:

```python
class CustomDNSProcessor(AsyncDNSProcessor):
    async def resolve_domain(
        self,
        domain: str,
        record_type: str
    ) -> List[str]:
        # Custom logic (e.g., caching, fallback)
        cached = self._check_cache(domain, record_type)
        if cached:
            return cached

        # Fall back to parent implementation
        result = await super().resolve_domain(domain, record_type)
        self._cache_result(domain, record_type, result)
        return result
```

### Plugin System

Extend functionality with plugins:

```python
# core/plugins.py
class Plugin(ABC):
    @abstractmethod
    def process(self, data: Any) -> Any:
        pass

# Example plugin
class GeoIPPlugin(Plugin):
    def process(self, data: Dict) -> Dict:
        for ip in data['ips']:
            data['geoip'][ip] = self._lookup_geoip(ip)
        return data

# Register in processor
processor.register_plugin(GeoIPPlugin())
```

### Webhooks

Notify external systems:

```python
# core/webhooks.py
class WebhookNotifier:
    def __init__(self, url: str):
        self.url = url

    def notify_scan_complete(self, scan_id: str, results: Dict):
        payload = {
            'event': 'scan.completed',
            'scan_id': scan_id,
            'summary': results['summary']
        }
        requests.post(self.url, json=payload)

# Use in processor
notifier = WebhookNotifier(config.get('webhook.url'))
notifier.notify_scan_complete(scan_id, results)
```

---

## Resources

- **RIPE RIS Data**: https://data.ris.ripe.net/
- **pyasn Documentation**: https://github.com/hadiasghari/pyasn
- **dnspython Documentation**: https://dnspython.readthedocs.io/
- **SQLAlchemy Documentation**: https://docs.sqlalchemy.org/
- **Flask Documentation**: https://flask.palletsprojects.com/

---

**Questions?** Open an issue or discussion on [GitHub](https://github.com/yourusername/domain-asn-mapper).
