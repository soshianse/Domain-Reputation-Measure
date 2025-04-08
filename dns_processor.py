"""
DNS Processor Module

This module handles DNS resolution for domains, including A, NS, and MX records.
It supports both IPv4 and IPv6 resolution.
"""

import logging
import dns.resolver
import dns.exception
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger('domain_asn_mapper.dns')


class DNSProcessor:
    """Class for resolving DNS records for domains."""
    
    def __init__(self, ip_version=None, timeout=5, retries=2):
        """
        Initialize DNS processor.
        
        Args:
            ip_version (int, optional): IP version to resolve (4 or 6). None for both.
            timeout (int, optional): DNS query timeout in seconds.
            retries (int, optional): Number of retries for failed DNS queries.
        """
        self.ip_version = ip_version
        self.timeout = timeout
        self.retries = retries
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = self.timeout
        self.resolver.lifetime = self.timeout * 2
        
        logger.debug(f"DNS Processor initialized with IP version: {ip_version if ip_version else 'Both'}")
    
    def resolve_domain(self, domain):
        """
        Resolve A, NS, and MX records for a domain.
        
        Args:
            domain (str): Domain name to resolve.
            
        Returns:
            dict: Dictionary containing DNS resolution results.
        """
        logger.debug(f"Resolving DNS records for domain: {domain}")
        
        result = {
            'domain': domain,
            'a_records': [],
            'aaaa_records': [],
            'ns_records': [],
            'mx_records': []
        }
        
        # Resolve A records (IPv4)
        if self.ip_version is None or self.ip_version == 4:
            result['a_records'] = self._resolve_records(domain, 'A')
        
        # Resolve AAAA records (IPv6)
        if self.ip_version is None or self.ip_version == 6:
            result['aaaa_records'] = self._resolve_records(domain, 'AAAA')
        
        # Resolve NS records
        ns_records = self._resolve_records(domain, 'NS')
        result['ns_records'] = []
        
        # For each NS record, resolve its IP address
        for ns in ns_records:
            ns_info = {
                'hostname': ns,
                'ip_addresses': []
            }
            
            # Resolve A records for the nameserver
            if self.ip_version is None or self.ip_version == 4:
                ns_info['ip_addresses'].extend(self._resolve_records(ns, 'A'))
            
            # Resolve AAAA records for the nameserver
            if self.ip_version is None or self.ip_version == 6:
                ns_info['ip_addresses'].extend(self._resolve_records(ns, 'AAAA'))
            
            result['ns_records'].append(ns_info)
        
        # Resolve MX records
        mx_records = self._resolve_mx_records(domain)
        result['mx_records'] = []
        
        # For each MX record, resolve its IP address
        for mx in mx_records:
            mx_info = {
                'hostname': mx['hostname'],
                'preference': mx['preference'],
                'ip_addresses': []
            }
            
            # Resolve A records for the mail server
            if self.ip_version is None or self.ip_version == 4:
                mx_info['ip_addresses'].extend(self._resolve_records(mx['hostname'], 'A'))
            
            # Resolve AAAA records for the mail server
            if self.ip_version is None or self.ip_version == 6:
                mx_info['ip_addresses'].extend(self._resolve_records(mx['hostname'], 'AAAA'))
            
            result['mx_records'].append(mx_info)
        
        logger.debug(f"DNS resolution complete for {domain}")
        return result
    
    def _resolve_records(self, domain, record_type):
        """
        Resolve specific DNS record type for a domain.
        
        Args:
            domain (str): Domain to resolve.
            record_type (str): DNS record type (A, AAAA, NS, etc.).
            
        Returns:
            list: List of resolved records.
        """
        records = []
        try:
            for attempt in range(self.retries + 1):
                try:
                    answers = self.resolver.resolve(domain, record_type)
                    
                    if record_type in ('A', 'AAAA'):
                        # For IP addresses, return as strings
                        records = [str(answer) for answer in answers]
                    else:
                        # For other records, return target as string
                        records = [str(answer.target).rstrip('.') for answer in answers]
                    
                    break  # Success, exit retry loop
                except dns.exception.Timeout:
                    if attempt == self.retries:
                        logger.warning(f"DNS {record_type} resolution timeout for {domain} after {self.retries} retries")
                    continue
        except dns.resolver.NoAnswer:
            logger.debug(f"No {record_type} records found for {domain}")
        except dns.resolver.NXDOMAIN:
            logger.warning(f"Domain {domain} does not exist")
        except dns.exception.DNSException as e:
            logger.warning(f"DNS error resolving {record_type} for {domain}: {e}")
        
        return records
    
    def _resolve_mx_records(self, domain):
        """
        Resolve MX records for a domain, including preference values.
        
        Args:
            domain (str): Domain to resolve MX records for.
            
        Returns:
            list: List of dicts with hostname and preference.
        """
        records = []
        try:
            for attempt in range(self.retries + 1):
                try:
                    answers = self.resolver.resolve(domain, 'MX')
                    
                    # Sort by preference (lower values first)
                    answers = sorted(answers, key=lambda x: x.preference)
                    
                    for answer in answers:
                        records.append({
                            'hostname': str(answer.exchange).rstrip('.'),
                            'preference': answer.preference
                        })
                    
                    break  # Success, exit retry loop
                except dns.exception.Timeout:
                    if attempt == self.retries:
                        logger.warning(f"DNS MX resolution timeout for {domain} after {self.retries} retries")
                    continue
        except dns.resolver.NoAnswer:
            logger.debug(f"No MX records found for {domain}")
        except dns.resolver.NXDOMAIN:
            logger.warning(f"Domain {domain} does not exist")
        except dns.exception.DNSException as e:
            logger.warning(f"DNS error resolving MX for {domain}: {e}")
        
        return records
