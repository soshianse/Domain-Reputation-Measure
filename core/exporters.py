"""
Data Export Module.

Provides exporters for various output formats including CSV, Parquet,
JSON, and specialized formats for analysis tools.
"""

import json
import csv
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


class DataExporter:
    """
    Base class for data exporters.
    """

    def __init__(self, output_path: str):
        """
        Initialize exporter.

        Args:
            output_path: Path to output file
        """
        self.output_path = output_path

    def export(self, data: Any) -> bool:
        """
        Export data to file.

        Args:
            data: Data to export

        Returns:
            True if successful
        """
        raise NotImplementedError


class JSONExporter(DataExporter):
    """Export data to JSON format."""

    def export(self, data: Any, indent: int = 2) -> bool:
        """
        Export data to JSON file.

        Args:
            data: Data to export
            indent: JSON indentation level

        Returns:
            True if successful
        """
        try:
            with open(self.output_path, 'w') as f:
                json.dump(data, f, indent=indent, default=str)
            logger.info(f"Exported JSON to: {self.output_path}")
            return True
        except Exception as e:
            logger.error(f"Error exporting JSON: {e}")
            return False


class CSVExporter(DataExporter):
    """Export data to CSV format."""

    def export(self, data: List[Dict[str, Any]], fieldnames: Optional[List[str]] = None) -> bool:
        """
        Export data to CSV file.

        Args:
            data: List of dictionaries to export
            fieldnames: Optional list of field names (auto-detected if not provided)

        Returns:
            True if successful
        """
        try:
            if not data:
                logger.warning("No data to export")
                return False

            # Auto-detect fieldnames from first row
            if fieldnames is None:
                fieldnames = list(data[0].keys())

            with open(self.output_path, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(data)

            logger.info(f"Exported CSV to: {self.output_path}")
            return True
        except Exception as e:
            logger.error(f"Error exporting CSV: {e}")
            return False


class FlatCSVExporter(DataExporter):
    """Export nested scan results to flat CSV format."""

    def export(self, scan_results: List[Dict[str, Any]]) -> bool:
        """
        Export scan results to flattened CSV.

        Each IP/ASN mapping becomes a separate row.

        Args:
            scan_results: Scan results from database

        Returns:
            True if successful
        """
        try:
            rows = []

            for result in scan_results:
                domain = result.get('domain', '')

                # Process A records
                for a_record in result.get('a_records', []):
                    if isinstance(a_record, dict):
                        rows.append({
                            'domain': domain,
                            'record_type': 'A',
                            'ip': a_record.get('ip'),
                            'asn': a_record.get('asn'),
                            'prefix': a_record.get('prefix')
                        })

                # Process AAAA records
                for aaaa_record in result.get('aaaa_records', []):
                    if isinstance(aaaa_record, dict):
                        rows.append({
                            'domain': domain,
                            'record_type': 'AAAA',
                            'ip': aaaa_record.get('ip'),
                            'asn': aaaa_record.get('asn'),
                            'prefix': aaaa_record.get('prefix')
                        })

                # Process NS records
                for ns_host, ns_ips in result.get('ns_records', {}).items():
                    for ns_ip in ns_ips:
                        if isinstance(ns_ip, dict):
                            rows.append({
                                'domain': domain,
                                'record_type': 'NS',
                                'hostname': ns_host,
                                'ip': ns_ip.get('ip'),
                                'asn': ns_ip.get('asn'),
                                'prefix': ns_ip.get('prefix')
                            })

                # Process MX records
                for mx_host, mx_data in result.get('mx_records', {}).items():
                    for mx_ip in mx_data.get('ips', []):
                        if isinstance(mx_ip, dict):
                            rows.append({
                                'domain': domain,
                                'record_type': 'MX',
                                'hostname': mx_host,
                                'preference': mx_data.get('preference'),
                                'ip': mx_ip.get('ip'),
                                'asn': mx_ip.get('asn'),
                                'prefix': mx_ip.get('prefix')
                            })

            if not rows:
                logger.warning("No data to export")
                return False

            # Write CSV
            fieldnames = ['domain', 'record_type', 'hostname', 'preference', 'ip', 'asn', 'prefix']
            with open(self.output_path, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                writer.writerows(rows)

            logger.info(f"Exported flat CSV to: {self.output_path} ({len(rows)} rows)")
            return True

        except Exception as e:
            logger.error(f"Error exporting flat CSV: {e}")
            return False


class ParquetExporter(DataExporter):
    """Export data to Apache Parquet format."""

    def export(self, scan_results: List[Dict[str, Any]]) -> bool:
        """
        Export scan results to Parquet file.

        Args:
            scan_results: Scan results from database

        Returns:
            True if successful
        """
        try:
            import pandas as pd
            import pyarrow as pa
            import pyarrow.parquet as pq
        except ImportError:
            logger.error("Parquet export requires pandas and pyarrow: pip install pandas pyarrow")
            return False

        try:
            # Flatten data like FlatCSVExporter
            rows = []

            for result in scan_results:
                domain = result.get('domain', '')

                # Process A records
                for a_record in result.get('a_records', []):
                    if isinstance(a_record, dict):
                        rows.append({
                            'domain': domain,
                            'record_type': 'A',
                            'ip': a_record.get('ip'),
                            'asn': a_record.get('asn'),
                            'prefix': a_record.get('prefix')
                        })

                # Process AAAA records
                for aaaa_record in result.get('aaaa_records', []):
                    if isinstance(aaaa_record, dict):
                        rows.append({
                            'domain': domain,
                            'record_type': 'AAAA',
                            'ip': aaaa_record.get('ip'),
                            'asn': aaaa_record.get('asn'),
                            'prefix': aaaa_record.get('prefix')
                        })

                # Process NS records
                for ns_host, ns_ips in result.get('ns_records', {}).items():
                    for ns_ip in ns_ips:
                        if isinstance(ns_ip, dict):
                            rows.append({
                                'domain': domain,
                                'record_type': 'NS',
                                'hostname': ns_host,
                                'ip': ns_ip.get('ip'),
                                'asn': ns_ip.get('asn'),
                                'prefix': ns_ip.get('prefix')
                            })

                # Process MX records
                for mx_host, mx_data in result.get('mx_records', {}).items():
                    for mx_ip in mx_data.get('ips', []):
                        if isinstance(mx_ip, dict):
                            rows.append({
                                'domain': domain,
                                'record_type': 'MX',
                                'hostname': mx_host,
                                'preference': mx_data.get('preference'),
                                'ip': mx_ip.get('ip'),
                                'asn': mx_ip.get('asn'),
                                'prefix': mx_ip.get('prefix')
                            })

            if not rows:
                logger.warning("No data to export")
                return False

            # Create DataFrame and write Parquet
            df = pd.DataFrame(rows)
            df.to_parquet(self.output_path, compression='snappy', index=False)

            logger.info(f"Exported Parquet to: {self.output_path} ({len(rows)} rows)")
            return True

        except Exception as e:
            logger.error(f"Error exporting Parquet: {e}")
            return False


class ASNGraphExporter(DataExporter):
    """Export ASN relationships as graph data."""

    def export(self, scan_results: List[Dict[str, Any]], format: str = 'gexf') -> bool:
        """
        Export ASN relationships as graph.

        Args:
            scan_results: Scan results from database
            format: Graph format ('gexf', 'graphml', 'edgelist')

        Returns:
            True if successful
        """
        try:
            import networkx as nx
        except ImportError:
            logger.error("Graph export requires networkx: pip install networkx")
            return False

        try:
            # Build graph
            G = nx.Graph()

            # Add nodes (domains) and edges (shared ASNs)
            domain_asns = {}

            for result in scan_results:
                domain = result.get('domain', '')
                asns = set()

                # Collect all ASNs for this domain
                for a_record in result.get('a_records', []):
                    if isinstance(a_record, dict) and a_record.get('asn'):
                        asns.add(a_record.get('asn'))

                for aaaa_record in result.get('aaaa_records', []):
                    if isinstance(aaaa_record, dict) and aaaa_record.get('asn'):
                        asns.add(aaaa_record.get('asn'))

                if asns:
                    domain_asns[domain] = asns
                    G.add_node(domain, node_type='domain', asn_count=len(asns))

            # Add edges between domains sharing ASNs
            domains = list(domain_asns.keys())
            for i, domain1 in enumerate(domains):
                for domain2 in domains[i+1:]:
                    shared_asns = domain_asns[domain1] & domain_asns[domain2]
                    if shared_asns:
                        G.add_edge(
                            domain1,
                            domain2,
                            weight=len(shared_asns),
                            shared_asns=list(shared_asns)
                        )

            # Export graph
            if format == 'gexf':
                nx.write_gexf(G, self.output_path)
            elif format == 'graphml':
                nx.write_graphml(G, self.output_path)
            elif format == 'edgelist':
                nx.write_edgelist(G, self.output_path, data=True)
            else:
                logger.error(f"Unsupported graph format: {format}")
                return False

            logger.info(f"Exported {format.upper()} graph to: {self.output_path} ({G.number_of_nodes()} nodes, {G.number_of_edges()} edges)")
            return True

        except Exception as e:
            logger.error(f"Error exporting graph: {e}")
            return False


class MarkdownReportExporter(DataExporter):
    """Export data as a formatted Markdown report."""

    def export(self, analytics_data: Dict[str, Any]) -> bool:
        """
        Export analytics data as Markdown report.

        Args:
            analytics_data: Analytics data from ASNAnalytics

        Returns:
            True if successful
        """
        try:
            lines = []

            # Header
            lines.append("# ASN Analysis Report")
            lines.append("")
            lines.append(f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
            lines.append("")

            # Overview
            if 'scan_id' in analytics_data:
                lines.append("## Overview")
                lines.append("")
                lines.append(f"- **Scan ID:** {analytics_data['scan_id']}")
                lines.append(f"- **Scan Date:** {analytics_data.get('scan_date', 'N/A')}")
                lines.append(f"- **Total Unique ASNs:** {analytics_data.get('total_unique_asns', 0):,}")
                lines.append(f"- **Total IP Mappings:** {analytics_data.get('total_ip_mappings', 0):,}")
                lines.append(f"- **Avg IPs per ASN:** {analytics_data.get('avg_ips_per_asn', 0):.2f}")
                lines.append(f"- **Concentration Ratio:** {analytics_data.get('concentration_ratio', 0):.2f}%")
                lines.append("")

            # Top ASNs
            if 'top_asns' in analytics_data:
                lines.append("## Top ASNs")
                lines.append("")
                lines.append("| Rank | ASN | IP Count | Domain Count | Percentage | Record Types |")
                lines.append("|------|-----|----------|--------------|------------|--------------|")

                for i, asn_data in enumerate(analytics_data['top_asns'][:15], 1):
                    asn = asn_data['asn']
                    ip_count = asn_data['ip_count']
                    domain_count = asn_data['domain_count']
                    percentage = asn_data['percentage']
                    record_types = ', '.join(f"{k}:{v}" for k, v in asn_data.get('record_types', {}).items())

                    lines.append(f"| {i} | AS{asn} | {ip_count:,} | {domain_count:,} | {percentage:.2f}% | {record_types} |")

                lines.append("")

            # Diversity metrics
            if 'shannon_entropy' in analytics_data:
                lines.append("## Diversity Metrics")
                lines.append("")
                lines.append(f"- **Shannon Entropy:** {analytics_data['shannon_entropy']}")
                lines.append(f"- **Diversity Score:** {analytics_data['diversity_score']}/100")
                lines.append(f"- **Gini Coefficient:** {analytics_data['gini_coefficient']}")
                lines.append("")
                interp = analytics_data.get('interpretation', {})
                lines.append(f"**Interpretation:**")
                lines.append(f"- Diversity: {interp.get('diversity', 'N/A')}")
                lines.append(f"- Concentration: {interp.get('concentration', 'N/A')}")
                lines.append("")

            # Write report
            with open(self.output_path, 'w') as f:
                f.write('\n'.join(lines))

            logger.info(f"Exported Markdown report to: {self.output_path}")
            return True

        except Exception as e:
            logger.error(f"Error exporting Markdown report: {e}")
            return False


def export_scan_data(
    scan_results: List[Dict[str, Any]],
    output_path: str,
    format: str = 'json'
) -> bool:
    """
    Convenience function to export scan data in various formats.

    Args:
        scan_results: Scan results from database
        output_path: Output file path
        format: Export format ('json', 'csv', 'parquet', 'graph')

    Returns:
        True if successful
    """
    if format == 'json':
        exporter = JSONExporter(output_path)
        return exporter.export(scan_results)
    elif format == 'csv':
        exporter = FlatCSVExporter(output_path)
        return exporter.export(scan_results)
    elif format == 'parquet':
        exporter = ParquetExporter(output_path)
        return exporter.export(scan_results)
    elif format in ['gexf', 'graphml', 'edgelist']:
        exporter = ASNGraphExporter(output_path)
        return exporter.export(scan_results, format=format)
    else:
        logger.error(f"Unsupported export format: {format}")
        return False
