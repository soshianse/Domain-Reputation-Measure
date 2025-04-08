"""
ASN Processor Module

This module handles the processing of MRT files and matching IP addresses to ASN information.
"""

import logging
import pyasn
import ipaddress
import os

logger = logging.getLogger('domain_asn_mapper.asn')


class ASNProcessor:
    """Class for processing ASN information and matching IPs to ASNs."""
    
    def __init__(self, mrt_file):
        """
        Initialize the ASN processor with an MRT file.
        
        Args:
            mrt_file (str): Path to the MRT file for ASN lookups.
        """
        self.mrt_file = mrt_file
        
        logger.info(f"Loading ASN database from MRT file: {mrt_file}")
        try:
            # Check if the compiled IPASN database exists
            ipasn_db = f"{mrt_file}.dat"
            if not os.path.exists(ipasn_db):
                logger.info("Compiled IPASN database not found. Converting MRT file...")
                pyasn.mrtx.dump_prefixes_to_file(self.mrt_file, ipasn_db)
                logger.info("MRT file conversion complete.")
            
            # Load the IPASN database
            self.asndb = pyasn.pyasn(ipasn_db)
            logger.info("ASN database loaded successfully.")
        except Exception as e:
            logger.error(f"Error loading ASN database: {e}")
            raise RuntimeError(f"Failed to initialize ASN database: {e}")
    
    def lookup_ip_asn(self, ip_address):
        """
        Look up ASN information for an IP address.
        
        Args:
            ip_address (str): IP address to look up.
            
        Returns:
            dict: ASN information including ASN number and prefix.
        """
        try:
            # Validate IP address
            ipaddress.ip_address(ip_address)
            
            # Look up ASN
            asn, prefix = self.asndb.lookup(ip_address)
            
            result = {
                'ip': ip_address,
                'asn': asn if asn else None,
                'prefix': prefix if prefix else None
            }
            
            return result
        except ValueError:
            logger.warning(f"Invalid IP address: {ip_address}")
            return {'ip': ip_address, 'asn': None, 'prefix': None, 'error': 'Invalid IP address'}
        except Exception as e:
            logger.error(f"Error looking up ASN for IP {ip_address}: {e}")
            return {'ip': ip_address, 'asn': None, 'prefix': None, 'error': str(e)}
    
    def lookup_domain_asn(self, dns_result):
        """
        Enrich DNS result with ASN information.
        
        Args:
            dns_result (dict): DNS resolution result for a domain.
            
        Returns:
            dict: Enriched result with ASN information.
        """
        domain = dns_result['domain']
        logger.debug(f"Looking up ASN information for domain: {domain}")
        
        # Create a copy of the DNS result to add ASN information
        result = dns_result.copy()
        
        # Add ASN info field
        result['asn_info'] = {
            'a_records': [],
            'aaaa_records': [],
            'ns_records': [],
            'mx_records': []
        }
        
        # Process A records
        for ip in dns_result['a_records']:
            asn_info = self.lookup_ip_asn(ip)
            result['asn_info']['a_records'].append(asn_info)
        
        # Process AAAA records
        for ip in dns_result['aaaa_records']:
            asn_info = self.lookup_ip_asn(ip)
            result['asn_info']['aaaa_records'].append(asn_info)
        
        # Process NS records
        for ns in dns_result['ns_records']:
            ns_asn_info = {
                'hostname': ns['hostname'],
                'ip_asn_info': []
            }
            
            for ip in ns['ip_addresses']:
                asn_info = self.lookup_ip_asn(ip)
                ns_asn_info['ip_asn_info'].append(asn_info)
            
            result['asn_info']['ns_records'].append(ns_asn_info)
        
        # Process MX records
        for mx in dns_result['mx_records']:
            mx_asn_info = {
                'hostname': mx['hostname'],
                'preference': mx['preference'],
                'ip_asn_info': []
            }
            
            for ip in mx['ip_addresses']:
                asn_info = self.lookup_ip_asn(ip)
                mx_asn_info['ip_asn_info'].append(asn_info)
            
            result['asn_info']['mx_records'].append(mx_asn_info)
        
        # Add a summary of unique ASNs for this domain
        result['unique_asns'] = self._extract_unique_asns(result['asn_info'])
        
        logger.debug(f"ASN lookup complete for {domain}")
        return result
    
    def _extract_unique_asns(self, asn_info):
        """
        Extract unique ASNs from the ASN information.
        
        Args:
            asn_info (dict): ASN information for a domain.
            
        Returns:
            dict: Dictionary of unique ASNs and their sources.
        """
        unique_asns = {}
        
        # Function to add an ASN to the unique set with its source
        def add_asn(asn, source, hostname=None):
            if asn is None:
                return
            
            asn_str = str(asn)
            if asn_str not in unique_asns:
                unique_asns[asn_str] = {
                    'sources': [],
                    'hostnames': set()
                }
            
            if source not in unique_asns[asn_str]['sources']:
                unique_asns[asn_str]['sources'].append(source)
            
            if hostname and hostname not in unique_asns[asn_str]['hostnames']:
                unique_asns[asn_str]['hostnames'].add(hostname)
        
        # Process A records
        for item in asn_info['a_records']:
            add_asn(item['asn'], 'A')
        
        # Process AAAA records
        for item in asn_info['aaaa_records']:
            add_asn(item['asn'], 'AAAA')
        
        # Process NS records
        for ns in asn_info['ns_records']:
            for item in ns['ip_asn_info']:
                add_asn(item['asn'], 'NS', ns['hostname'])
        
        # Process MX records
        for mx in asn_info['mx_records']:
            for item in mx['ip_asn_info']:
                add_asn(item['asn'], 'MX', mx['hostname'])
        
        # Convert sets to lists for JSON serialization
        for asn in unique_asns:
            unique_asns[asn]['hostnames'] = list(unique_asns[asn]['hostnames'])
        
        return unique_asns
