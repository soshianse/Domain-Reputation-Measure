"""
Output Formatter Module

This module handles formatting and writing domain ASN mapping results
to different output formats (JSON, CSV, Text).
"""

import logging
import json
import csv
import os

logger = logging.getLogger('domain_asn_mapper.output')


class OutputFormatter:
    """Class for formatting and writing domain ASN mapping results."""
    
    def __init__(self, format_type='json'):
        """
        Initialize the output formatter.
        
        Args:
            format_type (str): Output format type ('json', 'csv', or 'text').
        """
        self.format_type = format_type.lower()
        logger.debug(f"Output formatter initialized with format: {self.format_type}")
        
        if self.format_type not in ['json', 'csv', 'text']:
            logger.warning(f"Unsupported format type: {self.format_type}. Defaulting to JSON.")
            self.format_type = 'json'
    
    def write_output(self, results, output_file):
        """
        Format results and write to the output file.
        
        Args:
            results (list): List of domain ASN mapping results.
            output_file (str): Path to write the output file.
        """
        # Create parent directories if they don't exist
        os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
        
        if self.format_type == 'json':
            self._write_json(results, output_file)
        elif self.format_type == 'csv':
            self._write_csv(results, output_file)
        elif self.format_type == 'text':
            self._write_text(results, output_file)
    
    def _write_json(self, results, output_file):
        """Write results to a JSON file."""
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            logger.info(f"Results written to JSON file: {output_file}")
        except Exception as e:
            logger.error(f"Error writing JSON output: {e}")
            raise
    
    def _write_csv(self, results, output_file):
        """Write results to a CSV file."""
        try:
            # Flatten the nested structure for CSV format
            flattened_results = []
            
            for domain_result in results:
                domain = domain_result.get('domain', 'unknown')
                
                # Handle error case
                if 'error' in domain_result:
                    flattened_results.append({
                        'domain': domain,
                        'record_type': 'ERROR',
                        'hostname': '',
                        'ip': '',
                        'asn': '',
                        'prefix': '',
                        'error': domain_result['error']
                    })
                    continue
                
                # Process A records
                for ip_info in domain_result.get('asn_info', {}).get('a_records', []):
                    flattened_results.append({
                        'domain': domain,
                        'record_type': 'A',
                        'hostname': domain,
                        'ip': ip_info.get('ip', ''),
                        'asn': ip_info.get('asn', ''),
                        'prefix': ip_info.get('prefix', ''),
                        'error': ip_info.get('error', '')
                    })
                
                # Process AAAA records
                for ip_info in domain_result.get('asn_info', {}).get('aaaa_records', []):
                    flattened_results.append({
                        'domain': domain,
                        'record_type': 'AAAA',
                        'hostname': domain,
                        'ip': ip_info.get('ip', ''),
                        'asn': ip_info.get('asn', ''),
                        'prefix': ip_info.get('prefix', ''),
                        'error': ip_info.get('error', '')
                    })
                
                # Process NS records
                for ns in domain_result.get('asn_info', {}).get('ns_records', []):
                    hostname = ns.get('hostname', '')
                    for ip_info in ns.get('ip_asn_info', []):
                        flattened_results.append({
                            'domain': domain,
                            'record_type': 'NS',
                            'hostname': hostname,
                            'ip': ip_info.get('ip', ''),
                            'asn': ip_info.get('asn', ''),
                            'prefix': ip_info.get('prefix', ''),
                            'error': ip_info.get('error', '')
                        })
                
                # Process MX records
                for mx in domain_result.get('asn_info', {}).get('mx_records', []):
                    hostname = mx.get('hostname', '')
                    preference = mx.get('preference', '')
                    for ip_info in mx.get('ip_asn_info', []):
                        flattened_results.append({
                            'domain': domain,
                            'record_type': 'MX',
                            'hostname': f"{hostname} (pref: {preference})",
                            'ip': ip_info.get('ip', ''),
                            'asn': ip_info.get('asn', ''),
                            'prefix': ip_info.get('prefix', ''),
                            'error': ip_info.get('error', '')
                        })
            
            # Write CSV file
            if flattened_results:
                with open(output_file, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=flattened_results[0].keys())
                    writer.writeheader()
                    writer.writerows(flattened_results)
                logger.info(f"Results written to CSV file: {output_file}")
            else:
                logger.warning("No results to write to CSV")
                with open(output_file, 'w', newline='', encoding='utf-8') as f:
                    f.write("No results")
        except Exception as e:
            logger.error(f"Error writing CSV output: {e}")
            raise
    
    def _write_text(self, results, output_file):
        """Write results to a human-readable text file."""
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("Domain ASN Mapping Results\n")
                f.write("=========================\n\n")
                
                for domain_result in results:
                    domain = domain_result.get('domain', 'unknown')
                    f.write(f"Domain: {domain}\n")
                    f.write("-" * (len(domain) + 8) + "\n")
                    
                    # Handle error case
                    if 'error' in domain_result:
                        f.write(f"ERROR: {domain_result['error']}\n\n")
                        continue
                    
                    # Write unique ASNs summary
                    f.write("Unique ASNs:\n")
                    unique_asns = domain_result.get('unique_asns', {})
                    if unique_asns:
                        for asn, info in unique_asns.items():
                            sources = ", ".join(info['sources'])
                            hostnames = ", ".join(info['hostnames']) if info['hostnames'] else "None"
                            f.write(f"  ASN {asn}: Sources: {sources}, Hostnames: {hostnames}\n")
                    else:
                        f.write("  None found\n")
                    f.write("\n")
                    
                    # Write A records
                    a_records = domain_result.get('a_records', [])
                    if a_records:
                        f.write("A Records:\n")
                        for ip in a_records:
                            asn_info = next((item for item in domain_result.get('asn_info', {}).get('a_records', []) 
                                           if item.get('ip') == ip), {})
                            asn = asn_info.get('asn', 'Unknown')
                            prefix = asn_info.get('prefix', 'Unknown')
                            f.write(f"  {ip} (ASN: {asn}, Prefix: {prefix})\n")
                        f.write("\n")
                    
                    # Write AAAA records
                    aaaa_records = domain_result.get('aaaa_records', [])
                    if aaaa_records:
                        f.write("AAAA Records:\n")
                        for ip in aaaa_records:
                            asn_info = next((item for item in domain_result.get('asn_info', {}).get('aaaa_records', []) 
                                           if item.get('ip') == ip), {})
                            asn = asn_info.get('asn', 'Unknown')
                            prefix = asn_info.get('prefix', 'Unknown')
                            f.write(f"  {ip} (ASN: {asn}, Prefix: {prefix})\n")
                        f.write("\n")
                    
                    # Write NS records
                    ns_records = domain_result.get('ns_records', [])
                    if ns_records:
                        f.write("NS Records:\n")
                        for ns in ns_records:
                            hostname = ns.get('hostname', '')
                            f.write(f"  {hostname}\n")
                            
                            # Find corresponding ASN info
                            ns_asn_info = next((item for item in domain_result.get('asn_info', {}).get('ns_records', []) 
                                             if item.get('hostname') == hostname), {})
                            
                            # Write IP addresses with ASN info
                            for ip_info in ns_asn_info.get('ip_asn_info', []):
                                ip = ip_info.get('ip', '')
                                asn = ip_info.get('asn', 'Unknown')
                                prefix = ip_info.get('prefix', 'Unknown')
                                f.write(f"    {ip} (ASN: {asn}, Prefix: {prefix})\n")
                        f.write("\n")
                    
                    # Write MX records
                    mx_records = domain_result.get('mx_records', [])
                    if mx_records:
                        f.write("MX Records:\n")
                        for mx in mx_records:
                            hostname = mx.get('hostname', '')
                            preference = mx.get('preference', '')
                            f.write(f"  {hostname} (Preference: {preference})\n")
                            
                            # Find corresponding ASN info
                            mx_asn_info = next((item for item in domain_result.get('asn_info', {}).get('mx_records', []) 
                                             if item.get('hostname') == hostname), {})
                            
                            # Write IP addresses with ASN info
                            for ip_info in mx_asn_info.get('ip_asn_info', []):
                                ip = ip_info.get('ip', '')
                                asn = ip_info.get('asn', 'Unknown')
                                prefix = ip_info.get('prefix', 'Unknown')
                                f.write(f"    {ip} (ASN: {asn}, Prefix: {prefix})\n")
                        f.write("\n")
                    
                    f.write("\n")
            
            logger.info(f"Results written to text file: {output_file}")
        except Exception as e:
            logger.error(f"Error writing text output: {e}")
            raise
