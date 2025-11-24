"""
Database models and session management for Domain ASN Mapper.

This module provides SQLAlchemy models for storing scan history,
DNS records, ASN mappings, and tracking infrastructure changes over time.
"""

import logging
from datetime import datetime
from typing import Optional, List
from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey, Text, Boolean, JSON, Index
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session
from sqlalchemy.pool import StaticPool

logger = logging.getLogger(__name__)

Base = declarative_base()


class Scan(Base):
    """
    Represents a complete scan run.

    A scan is a single execution of the domain mapper,
    processing a set of domains at a specific point in time.
    """
    __tablename__ = 'scans'

    id = Column(Integer, primary_key=True)
    scan_id = Column(String(36), unique=True, nullable=False, index=True)  # UUID
    started_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    completed_at = Column(DateTime)
    status = Column(String(20), nullable=False, default='running')  # running, completed, failed
    total_domains = Column(Integer, default=0)
    successful_domains = Column(Integer, default=0)
    failed_domains = Column(Integer, default=0)
    mrt_file = Column(String(500))
    config = Column(JSON)  # Store configuration used for this scan
    notes = Column(Text)

    # Relationships
    domain_scans = relationship('DomainScan', back_populates='scan', cascade='all, delete-orphan')

    def __repr__(self):
        return f"<Scan(id={self.scan_id}, started={self.started_at}, domains={self.total_domains})>"


class Domain(Base):
    """
    Represents a unique domain name.

    This table stores domain metadata and is referenced by
    multiple scans to track the same domain over time.
    """
    __tablename__ = 'domains'

    id = Column(Integer, primary_key=True)
    domain_name = Column(String(253), unique=True, nullable=False, index=True)
    first_seen = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_seen = Column(DateTime, nullable=False, default=datetime.utcnow)
    times_scanned = Column(Integer, default=0)

    # Relationships
    domain_scans = relationship('DomainScan', back_populates='domain')

    __table_args__ = (
        Index('idx_domain_name', 'domain_name'),
    )

    def __repr__(self):
        return f"<Domain(name={self.domain_name}, scanned={self.times_scanned}x)>"


class DomainScan(Base):
    """
    Represents a domain's data from a specific scan.

    Links a domain to a scan and stores all DNS/ASN data
    collected during that scan.
    """
    __tablename__ = 'domain_scans'

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scans.id'), nullable=False)
    domain_id = Column(Integer, ForeignKey('domains.id'), nullable=False)
    scanned_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    success = Column(Boolean, default=True)
    error_message = Column(Text)

    # DNS Records (stored as JSON for flexibility)
    a_records = Column(JSON)  # List of IPv4 addresses
    aaaa_records = Column(JSON)  # List of IPv6 addresses
    ns_records = Column(JSON)  # Dict: {nameserver: [ips]}
    mx_records = Column(JSON)  # Dict: {mailserver: {preference, ips}}

    # ASN data
    unique_asns = Column(JSON)  # List of {asn, sources}

    # Full result (for reference)
    full_result = Column(JSON)

    # Relationships
    scan = relationship('Scan', back_populates='domain_scans')
    domain = relationship('Domain', back_populates='domain_scans')
    ip_asn_mappings = relationship('IPASNMapping', back_populates='domain_scan', cascade='all, delete-orphan')

    __table_args__ = (
        Index('idx_domain_scan', 'domain_id', 'scan_id'),
        Index('idx_scan_time', 'scanned_at'),
    )

    def __repr__(self):
        return f"<DomainScan(domain_id={self.domain_id}, scan_id={self.scan_id}, at={self.scanned_at})>"


class IPASNMapping(Base):
    """
    Represents an IP-to-ASN mapping from a specific domain scan.

    This table stores individual IP address to ASN associations,
    allowing for detailed change tracking at the IP level.
    """
    __tablename__ = 'ip_asn_mappings'

    id = Column(Integer, primary_key=True)
    domain_scan_id = Column(Integer, ForeignKey('domain_scans.id'), nullable=False)
    ip_address = Column(String(45), nullable=False)  # Max length for IPv6
    ip_version = Column(Integer, nullable=False)  # 4 or 6
    asn = Column(Integer)
    prefix = Column(String(50))
    record_type = Column(String(10), nullable=False)  # a, aaaa, ns, mx
    hostname = Column(String(253))  # For NS/MX records
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow)

    # Relationships
    domain_scan = relationship('DomainScan', back_populates='ip_asn_mappings')

    __table_args__ = (
        Index('idx_ip_address', 'ip_address'),
        Index('idx_asn', 'asn'),
        Index('idx_timestamp', 'timestamp'),
    )

    def __repr__(self):
        return f"<IPASNMapping(ip={self.ip_address}, asn={self.asn}, type={self.record_type})>"


class InfrastructureChange(Base):
    """
    Represents a detected change in domain infrastructure.

    This table tracks when domains change their ASNs, IPs, or
    other infrastructure components between scans.
    """
    __tablename__ = 'infrastructure_changes'

    id = Column(Integer, primary_key=True)
    domain_id = Column(Integer, ForeignKey('domains.id'), nullable=False)
    previous_scan_id = Column(Integer, ForeignKey('domain_scans.id'))
    current_scan_id = Column(Integer, ForeignKey('domain_scans.id'), nullable=False)
    detected_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    change_type = Column(String(50), nullable=False)  # ip_added, ip_removed, asn_changed, ns_changed, mx_changed
    severity = Column(String(20), default='info')  # info, warning, critical
    details = Column(JSON)  # Change-specific details

    __table_args__ = (
        Index('idx_domain_changes', 'domain_id', 'detected_at'),
        Index('idx_change_type', 'change_type'),
    )

    def __repr__(self):
        return f"<InfrastructureChange(domain_id={self.domain_id}, type={self.change_type}, at={self.detected_at})>"


class DatabaseManager:
    """
    Manages database connections and sessions.

    Provides a centralized interface for database operations
    with support for both SQLite and PostgreSQL.
    """

    def __init__(self, database_url: str = 'sqlite:///domain_asn_mapper.db', echo: bool = False):
        """
        Initialize database manager.

        Args:
            database_url: SQLAlchemy database URL
            echo: Enable SQL query logging
        """
        self.database_url = database_url
        self.echo = echo

        # Create engine
        if database_url.startswith('sqlite'):
            # SQLite-specific settings
            self.engine = create_engine(
                database_url,
                echo=echo,
                connect_args={'check_same_thread': False},
                poolclass=StaticPool
            )
        else:
            # PostgreSQL or other databases
            self.engine = create_engine(database_url, echo=echo)

        # Create session factory
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)

        logger.info(f"Database manager initialized: {database_url}")

    def create_tables(self):
        """Create all database tables."""
        Base.metadata.create_all(bind=self.engine)
        logger.info("Database tables created")

    def drop_tables(self):
        """Drop all database tables (use with caution!)."""
        Base.metadata.drop_all(bind=self.engine)
        logger.warning("Database tables dropped")

    def get_session(self) -> Session:
        """
        Get a new database session.

        Returns:
            SQLAlchemy session
        """
        return self.SessionLocal()

    def init_database(self):
        """
        Initialize database (create tables if they don't exist).

        This is safe to call multiple times.
        """
        try:
            self.create_tables()
            logger.info("Database initialized successfully")
        except Exception as e:
            logger.error(f"Error initializing database: {e}")
            raise


# Global database manager instance
_db_manager: Optional[DatabaseManager] = None


def get_database_manager(database_url: Optional[str] = None, echo: bool = False) -> DatabaseManager:
    """
    Get or create the global database manager instance.

    Args:
        database_url: Database URL (only used on first call)
        echo: Enable SQL logging (only used on first call)

    Returns:
        DatabaseManager instance
    """
    global _db_manager

    if _db_manager is None:
        if database_url is None:
            database_url = 'sqlite:///domain_asn_mapper.db'
        _db_manager = DatabaseManager(database_url, echo)
        _db_manager.init_database()

    return _db_manager


def reset_database_manager():
    """Reset the global database manager (mainly for testing)."""
    global _db_manager
    _db_manager = None
