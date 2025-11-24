"""
Scan comparison and diff functionality.

This module provides tools to compare scans and detect
infrastructure changes over time.
"""

import logging
from typing import Dict, Any, List, Set, Optional, Tuple
from datetime import datetime

logger = logging.getLogger(__name__)


class ScanDiff:
    """
    Compares two scans and detects infrastructure changes.

    Identifies changes in IP addresses, ASNs, nameservers,
    and mail servers between two scan runs.
    """

    def __init__(self, previous_scan: List[Dict[str, Any]], current_scan: List[Dict[str, Any]]):
        """
        Initialize scan diff.

        Args:
            previous_scan: Previous scan results (list of domain results)
            current_scan: Current scan results (list of domain results)
        """
        self.previous_scan = {r['domain']: r for r in previous_scan if 'domain' in r}
        self.current_scan = {r['domain']: r for r in current_scan if 'domain' in r}

        self.previous_domains = set(self.previous_scan.keys())
        self.current_domains = set(self.current_scan.keys())

    def get_added_domains(self) -> List[str]:
        """Get domains present in current scan but not in previous."""
        return sorted(self.current_domains - self.previous_domains)

    def get_removed_domains(self) -> List[str]:
        """Get domains present in previous scan but not in current."""
        return sorted(self.previous_domains - self.current_domains)

    def get_common_domains(self) -> List[str]:
        """Get domains present in both scans."""
        return sorted(self.previous_domains & self.current_domains)

    def compare_domain(self, domain: str) -> Dict[str, Any]:
        """
        Compare a single domain between scans.

        Args:
            domain: Domain name to compare

        Returns:
            Dict containing detected changes
        """
        if domain not in self.previous_scan or domain not in self.current_scan:
            return {'error': 'Domain not found in both scans'}

        prev = self.previous_scan[domain]
        curr = self.current_scan[domain]

        changes = {
            'domain': domain,
            'has_changes': False,
            'changes': []
        }

        # Compare A records
        a_changes = self._compare_ip_records(
            prev.get('a_records', []),
            curr.get('a_records', []),
            'A'
        )
        if a_changes:
            changes['changes'].extend(a_changes)
            changes['has_changes'] = True

        # Compare AAAA records
        aaaa_changes = self._compare_ip_records(
            prev.get('aaaa_records', []),
            curr.get('aaaa_records', []),
            'AAAA'
        )
        if aaaa_changes:
            changes['changes'].extend(aaaa_changes)
            changes['has_changes'] = True

        # Compare NS records
        ns_changes = self._compare_ns_records(
            prev.get('ns_records', {}),
            curr.get('ns_records', {})
        )
        if ns_changes:
            changes['changes'].extend(ns_changes)
            changes['has_changes'] = True

        # Compare MX records
        mx_changes = self._compare_mx_records(
            prev.get('mx_records', {}),
            curr.get('mx_records', {})
        )
        if mx_changes:
            changes['changes'].extend(mx_changes)
            changes['has_changes'] = True

        # Compare ASNs
        asn_changes = self._compare_asns(
            prev.get('unique_asns', []),
            curr.get('unique_asns', [])
        )
        if asn_changes:
            changes['changes'].extend(asn_changes)
            changes['has_changes'] = True

        return changes

    def _compare_ip_records(
        self,
        prev_records: List,
        curr_records: List,
        record_type: str
    ) -> List[Dict[str, Any]]:
        """Compare IP records (A or AAAA)."""
        changes = []

        # Extract IPs
        prev_ips = set()
        prev_ip_to_asn = {}

        for record in prev_records:
            if isinstance(record, dict):
                ip = record.get('ip')
                if ip:
                    prev_ips.add(ip)
                    prev_ip_to_asn[ip] = record.get('asn')
            elif isinstance(record, str):
                prev_ips.add(record)

        curr_ips = set()
        curr_ip_to_asn = {}

        for record in curr_records:
            if isinstance(record, dict):
                ip = record.get('ip')
                if ip:
                    curr_ips.add(ip)
                    curr_ip_to_asn[ip] = record.get('asn')
            elif isinstance(record, str):
                curr_ips.add(record)

        # Detect changes
        added_ips = curr_ips - prev_ips
        removed_ips = prev_ips - curr_ips

        if added_ips:
            changes.append({
                'type': f'{record_type}_added',
                'severity': 'info',
                'description': f'{len(added_ips)} {record_type} record(s) added',
                'details': {
                    'added_ips': sorted(list(added_ips)),
                    'asns': {ip: curr_ip_to_asn.get(ip) for ip in added_ips if ip in curr_ip_to_asn}
                }
            })

        if removed_ips:
            changes.append({
                'type': f'{record_type}_removed',
                'severity': 'warning',
                'description': f'{len(removed_ips)} {record_type} record(s) removed',
                'details': {
                    'removed_ips': sorted(list(removed_ips)),
                    'asns': {ip: prev_ip_to_asn.get(ip) for ip in removed_ips if ip in prev_ip_to_asn}
                }
            })

        # Check for ASN changes on common IPs
        common_ips = prev_ips & curr_ips
        for ip in common_ips:
            prev_asn = prev_ip_to_asn.get(ip)
            curr_asn = curr_ip_to_asn.get(ip)

            if prev_asn and curr_asn and prev_asn != curr_asn:
                changes.append({
                    'type': f'{record_type}_asn_changed',
                    'severity': 'warning',
                    'description': f'ASN changed for {record_type} record {ip}',
                    'details': {
                        'ip': ip,
                        'previous_asn': prev_asn,
                        'current_asn': curr_asn
                    }
                })

        return changes

    def _compare_ns_records(
        self,
        prev_ns: Dict[str, Any],
        curr_ns: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Compare NS records."""
        changes = []

        prev_nameservers = set(prev_ns.keys())
        curr_nameservers = set(curr_ns.keys())

        added_ns = curr_nameservers - prev_nameservers
        removed_ns = prev_nameservers - curr_nameservers

        if added_ns:
            changes.append({
                'type': 'ns_added',
                'severity': 'info',
                'description': f'{len(added_ns)} nameserver(s) added',
                'details': {'added_nameservers': sorted(list(added_ns))}
            })

        if removed_ns:
            changes.append({
                'type': 'ns_removed',
                'severity': 'warning',
                'description': f'{len(removed_ns)} nameserver(s) removed',
                'details': {'removed_nameservers': sorted(list(removed_ns))}
            })

        return changes

    def _compare_mx_records(
        self,
        prev_mx: Dict[str, Any],
        curr_mx: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Compare MX records."""
        changes = []

        prev_mailservers = set(prev_mx.keys())
        curr_mailservers = set(curr_mx.keys())

        added_mx = curr_mailservers - prev_mailservers
        removed_mx = prev_mailservers - curr_mailservers

        if added_mx:
            changes.append({
                'type': 'mx_added',
                'severity': 'info',
                'description': f'{len(added_mx)} mail server(s) added',
                'details': {'added_mailservers': sorted(list(added_mx))}
            })

        if removed_mx:
            changes.append({
                'type': 'mx_removed',
                'severity': 'warning',
                'description': f'{len(removed_mx)} mail server(s) removed',
                'details': {'removed_mailservers': sorted(list(removed_mx))}
            })

        # Check for preference changes
        for mx_host in prev_mailservers & curr_mailservers:
            prev_pref = prev_mx.get(mx_host, {}).get('preference')
            curr_pref = curr_mx.get(mx_host, {}).get('preference')

            if prev_pref and curr_pref and prev_pref != curr_pref:
                changes.append({
                    'type': 'mx_preference_changed',
                    'severity': 'info',
                    'description': f'MX preference changed for {mx_host}',
                    'details': {
                        'mailserver': mx_host,
                        'previous_preference': prev_pref,
                        'current_preference': curr_pref
                    }
                })

        return changes

    def _compare_asns(
        self,
        prev_asns: List[Dict[str, Any]],
        curr_asns: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Compare unique ASNs."""
        changes = []

        prev_asn_numbers = {asn.get('asn') for asn in prev_asns if asn.get('asn')}
        curr_asn_numbers = {asn.get('asn') for asn in curr_asns if asn.get('asn')}

        added_asns = curr_asn_numbers - prev_asn_numbers
        removed_asns = prev_asn_numbers - curr_asn_numbers

        if added_asns:
            changes.append({
                'type': 'asn_added',
                'severity': 'info',
                'description': f'{len(added_asns)} ASN(s) added',
                'details': {'added_asns': sorted(list(added_asns))}
            })

        if removed_asns:
            changes.append({
                'type': 'asn_removed',
                'severity': 'warning',
                'description': f'{len(removed_asns)} ASN(s) removed',
                'details': {'removed_asns': sorted(list(removed_asns))}
            })

        return changes

    def generate_summary(self) -> Dict[str, Any]:
        """
        Generate a summary of all changes between scans.

        Returns:
            Summary dict with statistics and highlights
        """
        common_domains = self.get_common_domains()

        # Analyze all common domains
        domains_with_changes = []
        total_changes = 0
        change_types = {}

        for domain in common_domains:
            comparison = self.compare_domain(domain)
            if comparison.get('has_changes'):
                domains_with_changes.append(domain)
                total_changes += len(comparison.get('changes', []))

                for change in comparison.get('changes', []):
                    change_type = change.get('type')
                    change_types[change_type] = change_types.get(change_type, 0) + 1

        return {
            'total_previous_domains': len(self.previous_domains),
            'total_current_domains': len(self.current_domains),
            'added_domains': len(self.get_added_domains()),
            'removed_domains': len(self.get_removed_domains()),
            'common_domains': len(common_domains),
            'domains_with_changes': len(domains_with_changes),
            'total_changes_detected': total_changes,
            'change_types': change_types,
            'domains_list': {
                'added': self.get_added_domains(),
                'removed': self.get_removed_domains(),
                'changed': domains_with_changes
            }
        }

    def generate_report(self) -> str:
        """
        Generate a human-readable text report of changes.

        Returns:
            Formatted text report
        """
        lines = []
        lines.append("=" * 70)
        lines.append("SCAN COMPARISON REPORT")
        lines.append("=" * 70)
        lines.append("")

        summary = self.generate_summary()

        lines.append(f"Previous scan: {summary['total_previous_domains']} domains")
        lines.append(f"Current scan:  {summary['total_current_domains']} domains")
        lines.append("")

        if summary['added_domains'] > 0:
            lines.append(f"✅ Added domains: {summary['added_domains']}")
            for domain in summary['domains_list']['added'][:10]:
                lines.append(f"   + {domain}")
            if summary['added_domains'] > 10:
                lines.append(f"   ... and {summary['added_domains'] - 10} more")
            lines.append("")

        if summary['removed_domains'] > 0:
            lines.append(f"❌ Removed domains: {summary['removed_domains']}")
            for domain in summary['domains_list']['removed'][:10]:
                lines.append(f"   - {domain}")
            if summary['removed_domains'] > 10:
                lines.append(f"   ... and {summary['removed_domains'] - 10} more")
            lines.append("")

        if summary['domains_with_changes'] > 0:
            lines.append(f"🔄 Domains with infrastructure changes: {summary['domains_with_changes']}")
            lines.append(f"   Total changes detected: {summary['total_changes_detected']}")
            lines.append("")

            lines.append("Change types:")
            for change_type, count in sorted(summary['change_types'].items(), key=lambda x: -x[1]):
                lines.append(f"   - {change_type}: {count}")
            lines.append("")

            lines.append("Detailed changes:")
            for domain in summary['domains_list']['changed'][:20]:
                comparison = self.compare_domain(domain)
                lines.append(f"\n   {domain}:")
                for change in comparison.get('changes', []):
                    severity_icon = {
                        'info': 'ℹ️',
                        'warning': '⚠️',
                        'critical': '🔴'
                    }.get(change.get('severity', 'info'), 'ℹ️')
                    lines.append(f"      {severity_icon} {change['description']}")

            if summary['domains_with_changes'] > 20:
                lines.append(f"\n   ... and {summary['domains_with_changes'] - 20} more domains with changes")

        else:
            lines.append("✓ No infrastructure changes detected")

        lines.append("")
        lines.append("=" * 70)

        return "\n".join(lines)
