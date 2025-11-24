"""
Scan storage functionality for Domain ASN Mapper.

This module handles storing scan results in the database
and retrieving historical data.
"""

import logging
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from sqlalchemy import desc

from .database import (
    Scan, Domain, DomainScan, IPASNMapping, InfrastructureChange,
    get_database_manager
)

logger = logging.getLogger(__name__)


class ScanStorage:
    """
    Manages storage and retrieval of scan data.

    Provides high-level interface for saving scan results
    and querying historical data.
    """

    def __init__(self, database_url: Optional[str] = None):
        """
        Initialize scan storage.

        Args:
            database_url: Database URL (defaults to SQLite)
        """
        self.db_manager = get_database_manager(database_url)

    def create_scan(
        self,
        mrt_file: str,
        total_domains: int = 0,
        config: Optional[Dict] = None,
        notes: Optional[str] = None
    ) -> str:
        """
        Create a new scan record.

        Args:
            mrt_file: Path to MRT file used
            total_domains: Total number of domains in scan
            config: Configuration dict
            notes: Optional notes about the scan

        Returns:
            Scan ID (UUID string)
        """
        session = self.db_manager.get_session()
        try:
            scan_id = str(uuid.uuid4())
            scan = Scan(
                scan_id=scan_id,
                started_at=datetime.utcnow(),
                status='running',
                total_domains=total_domains,
                mrt_file=mrt_file,
                config=config,
                notes=notes
            )
            session.add(scan)
            session.commit()

            logger.info(f"Created scan: {scan_id}")
            return scan_id

        except Exception as e:
            session.rollback()
            logger.error(f"Error creating scan: {e}")
            raise
        finally:
            session.close()

    def complete_scan(
        self,
        scan_id: str,
        successful_domains: int,
        failed_domains: int,
        status: str = 'completed'
    ):
        """
        Mark a scan as completed.

        Args:
            scan_id: Scan ID
            successful_domains: Number of successful domains
            failed_domains: Number of failed domains
            status: Final status ('completed' or 'failed')
        """
        session = self.db_manager.get_session()
        try:
            scan = session.query(Scan).filter_by(scan_id=scan_id).first()
            if scan:
                scan.completed_at = datetime.utcnow()
                scan.status = status
                scan.successful_domains = successful_domains
                scan.failed_domains = failed_domains
                session.commit()
                logger.info(f"Completed scan: {scan_id}")
            else:
                logger.warning(f"Scan not found: {scan_id}")

        except Exception as e:
            session.rollback()
            logger.error(f"Error completing scan: {e}")
            raise
        finally:
            session.close()

    def save_domain_results(
        self,
        scan_id: str,
        results: List[Dict[str, Any]]
    ):
        """
        Save domain scan results to database.

        Args:
            scan_id: Scan ID
            results: List of domain results from processing
        """
        session = self.db_manager.get_session()
        try:
            # Get scan
            scan = session.query(Scan).filter_by(scan_id=scan_id).first()
            if not scan:
                raise ValueError(f"Scan not found: {scan_id}")

            for result in results:
                domain_name = result.get('domain')
                if not domain_name:
                    continue

                # Get or create domain
                domain = session.query(Domain).filter_by(domain_name=domain_name).first()
                if not domain:
                    domain = Domain(
                        domain_name=domain_name,
                        first_seen=datetime.utcnow(),
                        times_scanned=0
                    )
                    session.add(domain)
                    session.flush()  # Get domain.id

                # Update domain stats
                domain.last_seen = datetime.utcnow()
                domain.times_scanned += 1

                # Create domain scan record
                domain_scan = DomainScan(
                    scan_id=scan.id,
                    domain_id=domain.id,
                    scanned_at=datetime.utcnow(),
                    success='error' not in result,
                    error_message=result.get('error'),
                    a_records=result.get('a_records', []),
                    aaaa_records=result.get('aaaa_records', []),
                    ns_records=result.get('ns_records', {}),
                    mx_records=result.get('mx_records', {}),
                    unique_asns=result.get('unique_asns', []),
                    full_result=result
                )
                session.add(domain_scan)
                session.flush()  # Get domain_scan.id

                # Store IP-ASN mappings
                self._store_ip_asn_mappings(session, domain_scan, result)

            session.commit()
            logger.info(f"Saved {len(results)} domain results for scan {scan_id}")

        except Exception as e:
            session.rollback()
            logger.error(f"Error saving domain results: {e}")
            raise
        finally:
            session.close()

    def _store_ip_asn_mappings(
        self,
        session: Session,
        domain_scan: DomainScan,
        result: Dict[str, Any]
    ):
        """
        Store individual IP-ASN mappings.

        Args:
            session: Database session
            domain_scan: DomainScan instance
            result: Domain result dict
        """
        # A records
        for a_record in result.get('a_records', []):
            if isinstance(a_record, dict):
                mapping = IPASNMapping(
                    domain_scan_id=domain_scan.id,
                    ip_address=a_record.get('ip'),
                    ip_version=4,
                    asn=a_record.get('asn'),
                    prefix=a_record.get('prefix'),
                    record_type='a'
                )
                session.add(mapping)

        # AAAA records
        for aaaa_record in result.get('aaaa_records', []):
            if isinstance(aaaa_record, dict):
                mapping = IPASNMapping(
                    domain_scan_id=domain_scan.id,
                    ip_address=aaaa_record.get('ip'),
                    ip_version=6,
                    asn=aaaa_record.get('asn'),
                    prefix=aaaa_record.get('prefix'),
                    record_type='aaaa'
                )
                session.add(mapping)

        # NS records
        for ns_host, ns_ips in result.get('ns_records', {}).items():
            for ns_ip in ns_ips:
                if isinstance(ns_ip, dict):
                    mapping = IPASNMapping(
                        domain_scan_id=domain_scan.id,
                        ip_address=ns_ip.get('ip'),
                        ip_version=4 if ':' not in ns_ip.get('ip', '') else 6,
                        asn=ns_ip.get('asn'),
                        prefix=ns_ip.get('prefix'),
                        record_type='ns',
                        hostname=ns_host
                    )
                    session.add(mapping)

        # MX records
        for mx_host, mx_data in result.get('mx_records', {}).items():
            for mx_ip in mx_data.get('ips', []):
                if isinstance(mx_ip, dict):
                    mapping = IPASNMapping(
                        domain_scan_id=domain_scan.id,
                        ip_address=mx_ip.get('ip'),
                        ip_version=4 if ':' not in mx_ip.get('ip', '') else 6,
                        asn=mx_ip.get('asn'),
                        prefix=mx_ip.get('prefix'),
                        record_type='mx',
                        hostname=mx_host
                    )
                    session.add(mapping)

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """
        Get scan details by ID.

        Args:
            scan_id: Scan ID

        Returns:
            Scan details dict or None
        """
        session = self.db_manager.get_session()
        try:
            scan = session.query(Scan).filter_by(scan_id=scan_id).first()
            if not scan:
                return None

            return {
                'scan_id': scan.scan_id,
                'started_at': scan.started_at.isoformat() if scan.started_at else None,
                'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
                'status': scan.status,
                'total_domains': scan.total_domains,
                'successful_domains': scan.successful_domains,
                'failed_domains': scan.failed_domains,
                'mrt_file': scan.mrt_file,
                'config': scan.config,
                'notes': scan.notes
            }

        finally:
            session.close()

    def list_scans(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        List recent scans.

        Args:
            limit: Maximum number of scans to return

        Returns:
            List of scan dicts
        """
        session = self.db_manager.get_session()
        try:
            scans = session.query(Scan).order_by(desc(Scan.started_at)).limit(limit).all()

            return [
                {
                    'scan_id': scan.scan_id,
                    'started_at': scan.started_at.isoformat() if scan.started_at else None,
                    'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
                    'status': scan.status,
                    'total_domains': scan.total_domains,
                    'successful_domains': scan.successful_domains,
                    'failed_domains': scan.failed_domains
                }
                for scan in scans
            ]

        finally:
            session.close()

    def get_domain_history(
        self,
        domain_name: str,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Get scan history for a specific domain.

        Args:
            domain_name: Domain name
            limit: Maximum number of scans to return

        Returns:
            List of domain scan results
        """
        session = self.db_manager.get_session()
        try:
            domain = session.query(Domain).filter_by(domain_name=domain_name).first()
            if not domain:
                return []

            domain_scans = (
                session.query(DomainScan)
                .filter_by(domain_id=domain.id)
                .order_by(desc(DomainScan.scanned_at))
                .limit(limit)
                .all()
            )

            return [
                {
                    'scanned_at': ds.scanned_at.isoformat() if ds.scanned_at else None,
                    'success': ds.success,
                    'error_message': ds.error_message,
                    'a_records': ds.a_records,
                    'aaaa_records': ds.aaaa_records,
                    'ns_records': ds.ns_records,
                    'mx_records': ds.mx_records,
                    'unique_asns': ds.unique_asns
                }
                for ds in domain_scans
            ]

        finally:
            session.close()

    def get_scan_results(self, scan_id: str) -> List[Dict[str, Any]]:
        """
        Get all domain results from a specific scan.

        Args:
            scan_id: Scan ID

        Returns:
            List of domain results
        """
        session = self.db_manager.get_session()
        try:
            scan = session.query(Scan).filter_by(scan_id=scan_id).first()
            if not scan:
                return []

            domain_scans = (
                session.query(DomainScan)
                .filter_by(scan_id=scan.id)
                .all()
            )

            return [ds.full_result for ds in domain_scans if ds.full_result]

        finally:
            session.close()
