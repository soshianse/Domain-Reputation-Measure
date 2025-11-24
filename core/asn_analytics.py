"""
ASN Analytics and Statistics Module.

This module provides statistical analysis and insights about ASN data,
including distribution analysis, clustering, and trend detection.
"""

import logging
from typing import Dict, Any, List, Set, Tuple, Optional
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import func, distinct

from .database import (
    Scan, Domain, DomainScan, IPASNMapping,
    get_database_manager
)

logger = logging.getLogger(__name__)


class ASNAnalytics:
    """
    Provides statistical analysis and insights about ASN data.

    Analyzes ASN distribution, identifies trends, and provides
    clustering and relationship analysis.
    """

    def __init__(self, database_url: Optional[str] = None):
        """
        Initialize ASN analytics.

        Args:
            database_url: Database URL (defaults to SQLite)
        """
        self.db_manager = get_database_manager(database_url)

    def get_asn_statistics(self, scan_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Get comprehensive ASN statistics.

        Args:
            scan_id: Optional scan ID to analyze (uses latest if not provided)

        Returns:
            Dict with ASN statistics
        """
        session = self.db_manager.get_session()
        try:
            # Get scan
            if scan_id:
                scan = session.query(Scan).filter_by(scan_id=scan_id).first()
            else:
                scan = session.query(Scan).filter_by(status='completed').order_by(Scan.started_at.desc()).first()

            if not scan:
                return {'error': 'No scan found'}

            # Get all IP-ASN mappings for this scan
            mappings = (
                session.query(IPASNMapping)
                .join(DomainScan, IPASNMapping.domain_scan_id == DomainScan.id)
                .filter(DomainScan.scan_id == scan.id)
                .all()
            )

            # Count ASNs
            asn_counts = Counter()
            asn_by_type = defaultdict(lambda: defaultdict(int))
            asn_domains = defaultdict(set)
            total_ips = 0

            for mapping in mappings:
                if mapping.asn:
                    asn_counts[mapping.asn] += 1
                    asn_by_type[mapping.asn][mapping.record_type] += 1

                    # Get domain for this mapping
                    domain_scan = session.query(DomainScan).filter_by(id=mapping.domain_scan_id).first()
                    if domain_scan:
                        domain = session.query(Domain).filter_by(id=domain_scan.domain_id).first()
                        if domain:
                            asn_domains[mapping.asn].add(domain.domain_name)

                    total_ips += 1

            # Calculate statistics
            unique_asns = len(asn_counts)
            top_asns = asn_counts.most_common(20)

            # Concentration metrics
            if unique_asns > 0:
                top_10_percent = sum(count for _, count in top_asns[:max(1, unique_asns // 10)])
                concentration_ratio = (top_10_percent / total_ips * 100) if total_ips > 0 else 0
            else:
                concentration_ratio = 0

            # Distribution statistics
            ip_counts = list(asn_counts.values())
            avg_ips_per_asn = sum(ip_counts) / len(ip_counts) if ip_counts else 0
            max_ips_per_asn = max(ip_counts) if ip_counts else 0
            min_ips_per_asn = min(ip_counts) if ip_counts else 0

            return {
                'scan_id': scan.scan_id,
                'scan_date': scan.started_at.isoformat() if scan.started_at else None,
                'total_unique_asns': unique_asns,
                'total_ip_mappings': total_ips,
                'avg_ips_per_asn': round(avg_ips_per_asn, 2),
                'max_ips_per_asn': max_ips_per_asn,
                'min_ips_per_asn': min_ips_per_asn,
                'concentration_ratio': round(concentration_ratio, 2),
                'top_asns': [
                    {
                        'asn': asn,
                        'ip_count': count,
                        'domain_count': len(asn_domains[asn]),
                        'percentage': round(count / total_ips * 100, 2) if total_ips > 0 else 0,
                        'record_types': dict(asn_by_type[asn])
                    }
                    for asn, count in top_asns
                ]
            }

        finally:
            session.close()

    def get_asn_trends(self, asn: int, days: int = 30) -> Dict[str, Any]:
        """
        Get trends for a specific ASN over time.

        Args:
            asn: ASN number to analyze
            days: Number of days to look back

        Returns:
            Dict with trend data
        """
        session = self.db_manager.get_session()
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days)

            # Get scans in time range
            scans = (
                session.query(Scan)
                .filter(Scan.started_at >= cutoff_date)
                .filter(Scan.status == 'completed')
                .order_by(Scan.started_at)
                .all()
            )

            trend_data = []
            for scan in scans:
                # Count IPs for this ASN in this scan
                ip_count = (
                    session.query(func.count(IPASNMapping.id))
                    .join(DomainScan, IPASNMapping.domain_scan_id == DomainScan.id)
                    .filter(DomainScan.scan_id == scan.id)
                    .filter(IPASNMapping.asn == asn)
                    .scalar()
                )

                # Count unique domains
                domain_count = (
                    session.query(func.count(distinct(DomainScan.domain_id)))
                    .join(IPASNMapping, IPASNMapping.domain_scan_id == DomainScan.id)
                    .filter(DomainScan.scan_id == scan.id)
                    .filter(IPASNMapping.asn == asn)
                    .scalar()
                )

                trend_data.append({
                    'scan_id': scan.scan_id,
                    'date': scan.started_at.isoformat() if scan.started_at else None,
                    'ip_count': ip_count,
                    'domain_count': domain_count
                })

            # Calculate change over time
            if len(trend_data) >= 2:
                first = trend_data[0]
                last = trend_data[-1]
                ip_change = last['ip_count'] - first['ip_count']
                domain_change = last['domain_count'] - first['domain_count']
                ip_change_pct = (ip_change / first['ip_count'] * 100) if first['ip_count'] > 0 else 0
                domain_change_pct = (domain_change / first['domain_count'] * 100) if first['domain_count'] > 0 else 0
            else:
                ip_change = domain_change = 0
                ip_change_pct = domain_change_pct = 0

            return {
                'asn': asn,
                'period_days': days,
                'scan_count': len(trend_data),
                'trend_data': trend_data,
                'changes': {
                    'ip_count_change': ip_change,
                    'ip_count_change_pct': round(ip_change_pct, 2),
                    'domain_count_change': domain_change,
                    'domain_count_change_pct': round(domain_change_pct, 2)
                }
            }

        finally:
            session.close()

    def cluster_domains_by_asn(
        self,
        scan_id: Optional[str] = None,
        min_shared_asns: int = 2
    ) -> List[Dict[str, Any]]:
        """
        Cluster domains that share ASNs.

        Args:
            scan_id: Optional scan ID (uses latest if not provided)
            min_shared_asns: Minimum shared ASNs to form a cluster

        Returns:
            List of domain clusters
        """
        session = self.db_manager.get_session()
        try:
            # Get scan
            if scan_id:
                scan = session.query(Scan).filter_by(scan_id=scan_id).first()
            else:
                scan = session.query(Scan).filter_by(status='completed').order_by(Scan.started_at.desc()).first()

            if not scan:
                return []

            # Build domain -> ASN mapping
            domain_asns = defaultdict(set)

            domain_scans = (
                session.query(DomainScan)
                .filter_by(scan_id=scan.id)
                .all()
            )

            for ds in domain_scans:
                domain = session.query(Domain).filter_by(id=ds.domain_id).first()
                if not domain:
                    continue

                mappings = (
                    session.query(IPASNMapping)
                    .filter_by(domain_scan_id=ds.id)
                    .all()
                )

                for mapping in mappings:
                    if mapping.asn:
                        domain_asns[domain.domain_name].add(mapping.asn)

            # Find clusters (domains sharing ASNs)
            clusters = []
            processed_domains = set()

            for domain1, asns1 in domain_asns.items():
                if domain1 in processed_domains:
                    continue

                cluster_domains = {domain1}
                cluster_asns = asns1.copy()

                for domain2, asns2 in domain_asns.items():
                    if domain2 == domain1 or domain2 in processed_domains:
                        continue

                    shared_asns = asns1 & asns2
                    if len(shared_asns) >= min_shared_asns:
                        cluster_domains.add(domain2)
                        cluster_asns.update(asns2)

                if len(cluster_domains) > 1:
                    clusters.append({
                        'domain_count': len(cluster_domains),
                        'domains': sorted(list(cluster_domains)),
                        'shared_asns': sorted(list(cluster_asns)),
                        'asn_count': len(cluster_asns)
                    })
                    processed_domains.update(cluster_domains)

            # Sort clusters by size
            clusters.sort(key=lambda x: x['domain_count'], reverse=True)

            return clusters

        finally:
            session.close()

    def get_asn_domain_list(self, asn: int, scan_id: Optional[str] = None) -> List[str]:
        """
        Get list of domains using a specific ASN.

        Args:
            asn: ASN number
            scan_id: Optional scan ID (uses latest if not provided)

        Returns:
            List of domain names
        """
        session = self.db_manager.get_session()
        try:
            # Get scan
            if scan_id:
                scan = session.query(Scan).filter_by(scan_id=scan_id).first()
            else:
                scan = session.query(Scan).filter_by(status='completed').order_by(Scan.started_at.desc()).first()

            if not scan:
                return []

            # Get domains using this ASN
            domain_ids = (
                session.query(distinct(DomainScan.domain_id))
                .join(IPASNMapping, IPASNMapping.domain_scan_id == DomainScan.id)
                .filter(DomainScan.scan_id == scan.id)
                .filter(IPASNMapping.asn == asn)
                .all()
            )

            domains = []
            for (domain_id,) in domain_ids:
                domain = session.query(Domain).filter_by(id=domain_id).first()
                if domain:
                    domains.append(domain.domain_name)

            return sorted(domains)

        finally:
            session.close()

    def compare_asn_distributions(
        self,
        scan_id1: str,
        scan_id2: str
    ) -> Dict[str, Any]:
        """
        Compare ASN distributions between two scans.

        Args:
            scan_id1: First scan ID
            scan_id2: Second scan ID

        Returns:
            Comparison data
        """
        session = self.db_manager.get_session()
        try:
            # Get ASN counts for both scans
            def get_asn_counts(scan_id):
                scan = session.query(Scan).filter_by(scan_id=scan_id).first()
                if not scan:
                    return {}

                mappings = (
                    session.query(IPASNMapping.asn, func.count(IPASNMapping.id))
                    .join(DomainScan, IPASNMapping.domain_scan_id == DomainScan.id)
                    .filter(DomainScan.scan_id == scan.id)
                    .filter(IPASNMapping.asn.isnot(None))
                    .group_by(IPASNMapping.asn)
                    .all()
                )

                return {asn: count for asn, count in mappings}

            asns1 = get_asn_counts(scan_id1)
            asns2 = get_asn_counts(scan_id2)

            if not asns1 or not asns2:
                return {'error': 'One or both scans not found'}

            # Calculate changes
            all_asns = set(asns1.keys()) | set(asns2.keys())
            new_asns = set(asns2.keys()) - set(asns1.keys())
            removed_asns = set(asns1.keys()) - set(asns2.keys())
            common_asns = set(asns1.keys()) & set(asns2.keys())

            # ASNs with significant changes
            significant_changes = []
            for asn in common_asns:
                count1 = asns1[asn]
                count2 = asns2[asn]
                change = count2 - count1
                change_pct = (change / count1 * 100) if count1 > 0 else 0

                if abs(change_pct) >= 20:  # 20% threshold
                    significant_changes.append({
                        'asn': asn,
                        'previous_count': count1,
                        'current_count': count2,
                        'change': change,
                        'change_pct': round(change_pct, 2)
                    })

            significant_changes.sort(key=lambda x: abs(x['change_pct']), reverse=True)

            return {
                'scan_id1': scan_id1,
                'scan_id2': scan_id2,
                'total_asns_scan1': len(asns1),
                'total_asns_scan2': len(asns2),
                'new_asns': sorted(list(new_asns)),
                'new_asns_count': len(new_asns),
                'removed_asns': sorted(list(removed_asns)),
                'removed_asns_count': len(removed_asns),
                'common_asns_count': len(common_asns),
                'significant_changes': significant_changes[:20]  # Top 20
            }

        finally:
            session.close()

    def get_asn_diversity_score(self, scan_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Calculate ASN diversity score (Shannon entropy).

        Higher scores indicate more diverse ASN distribution.

        Args:
            scan_id: Optional scan ID (uses latest if not provided)

        Returns:
            Diversity metrics
        """
        import math

        session = self.db_manager.get_session()
        try:
            # Get scan
            if scan_id:
                scan = session.query(Scan).filter_by(scan_id=scan_id).first()
            else:
                scan = session.query(Scan).filter_by(status='completed').order_by(Scan.started_at.desc()).first()

            if not scan:
                return {'error': 'No scan found'}

            # Get ASN distribution
            mappings = (
                session.query(IPASNMapping.asn, func.count(IPASNMapping.id))
                .join(DomainScan, IPASNMapping.domain_scan_id == DomainScan.id)
                .filter(DomainScan.scan_id == scan.id)
                .filter(IPASNMapping.asn.isnot(None))
                .group_by(IPASNMapping.asn)
                .all()
            )

            if not mappings:
                return {'error': 'No ASN data found'}

            total_count = sum(count for _, count in mappings)

            # Calculate Shannon entropy
            entropy = 0
            for asn, count in mappings:
                proportion = count / total_count
                entropy -= proportion * math.log2(proportion)

            # Normalize to 0-100 scale (max entropy would be log2(num_asns))
            max_entropy = math.log2(len(mappings)) if len(mappings) > 1 else 1
            normalized_score = (entropy / max_entropy * 100) if max_entropy > 0 else 0

            # Calculate Gini coefficient for concentration
            sorted_counts = sorted([count for _, count in mappings])
            n = len(sorted_counts)
            cumsum = sum((i + 1) * count for i, count in enumerate(sorted_counts))
            gini = (2 * cumsum) / (n * sum(sorted_counts)) - (n + 1) / n

            return {
                'scan_id': scan.scan_id if scan_id else scan.scan_id,
                'unique_asns': len(mappings),
                'total_mappings': total_count,
                'shannon_entropy': round(entropy, 3),
                'diversity_score': round(normalized_score, 2),
                'gini_coefficient': round(gini, 3),
                'interpretation': {
                    'diversity': 'high' if normalized_score > 70 else 'medium' if normalized_score > 40 else 'low',
                    'concentration': 'high' if gini > 0.6 else 'medium' if gini > 0.3 else 'low'
                }
            }

        finally:
            session.close()
