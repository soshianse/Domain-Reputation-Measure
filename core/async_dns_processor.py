"""
Async DNS processor for high-performance domain resolution.

This module provides asynchronous DNS resolution using aiodns,
enabling concurrent processing of multiple domains for 10-20x
speed improvement over sequential resolution.
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any
import aiodns
import socket

logger = logging.getLogger(__name__)


class AsyncDNSProcessor:
    """
    Asynchronous DNS processor using aiodns.

    Provides concurrent DNS resolution with configurable timeout
    and retry logic for high-performance domain processing.
    """

    def __init__(
        self,
        ip_version: Optional[int] = None,
        timeout: float = 5.0,
        retries: int = 2,
        nameservers: Optional[List[str]] = None
    ):
        """
        Initialize async DNS processor.

        Args:
            ip_version: IP version to use (4 or 6, None for both)
            timeout: DNS query timeout in seconds
            retries: Number of retry attempts
            nameservers: Custom nameservers (None for system default)
        """
        self.ip_version = ip_version
        self.timeout = timeout
        self.retries = retries
        self.nameservers = nameservers

        # Create aiodns resolver
        self.resolver = aiodns.DNSResolver(
            timeout=timeout,
            tries=retries + 1,
            nameservers=nameservers
        )

        logger.debug(
            f"AsyncDNSProcessor initialized: "
            f"timeout={timeout}s, retries={retries}, "
            f"ip_version={ip_version or 'both'}"
        )

    async def resolve_a_records(self, domain: str) -> List[str]:
        """
        Resolve A records (IPv4) for a domain.

        Args:
            domain: Domain name to resolve

        Returns:
            List of IPv4 addresses
        """
        if self.ip_version == 6:
            return []

        try:
            result = await self.resolver.query(domain, 'A')
            addresses = [r.host for r in result]
            logger.debug(f"Resolved A records for {domain}: {addresses}")
            return addresses
        except aiodns.error.DNSError as e:
            logger.debug(f"No A records for {domain}: {e}")
            return []
        except Exception as e:
            logger.warning(f"Error resolving A records for {domain}: {e}")
            return []

    async def resolve_aaaa_records(self, domain: str) -> List[str]:
        """
        Resolve AAAA records (IPv6) for a domain.

        Args:
            domain: Domain name to resolve

        Returns:
            List of IPv6 addresses
        """
        if self.ip_version == 4:
            return []

        try:
            result = await self.resolver.query(domain, 'AAAA')
            addresses = [r.host for r in result]
            logger.debug(f"Resolved AAAA records for {domain}: {addresses}")
            return addresses
        except aiodns.error.DNSError as e:
            logger.debug(f"No AAAA records for {domain}: {e}")
            return []
        except Exception as e:
            logger.warning(f"Error resolving AAAA records for {domain}: {e}")
            return []

    async def resolve_ns_records(self, domain: str) -> Dict[str, List[str]]:
        """
        Resolve NS records (nameservers) for a domain.

        Args:
            domain: Domain name to resolve

        Returns:
            Dictionary mapping nameserver hostnames to their IP addresses
        """
        try:
            result = await self.resolver.query(domain, 'NS')
            nameservers = [r.host.rstrip('.') for r in result]
            logger.debug(f"Resolved NS records for {domain}: {nameservers}")

            # Resolve IPs for each nameserver concurrently
            ns_records = {}
            tasks = []
            for ns in nameservers:
                tasks.append(self._resolve_nameserver_ips(ns))

            results = await asyncio.gather(*tasks, return_exceptions=True)

            for ns, ips in zip(nameservers, results):
                if isinstance(ips, Exception):
                    logger.debug(f"Could not resolve IPs for nameserver {ns}: {ips}")
                    ns_records[ns] = []
                else:
                    ns_records[ns] = ips

            return ns_records

        except aiodns.error.DNSError as e:
            logger.debug(f"No NS records for {domain}: {e}")
            return {}
        except Exception as e:
            logger.warning(f"Error resolving NS records for {domain}: {e}")
            return {}

    async def _resolve_nameserver_ips(self, nameserver: str) -> List[str]:
        """
        Resolve IP addresses for a nameserver.

        Args:
            nameserver: Nameserver hostname

        Returns:
            List of IP addresses
        """
        ips = []

        # Try A records
        if self.ip_version != 6:
            try:
                result = await self.resolver.query(nameserver, 'A')
                ips.extend([r.host for r in result])
            except:
                pass

        # Try AAAA records
        if self.ip_version != 4:
            try:
                result = await self.resolver.query(nameserver, 'AAAA')
                ips.extend([r.host for r in result])
            except:
                pass

        return ips

    async def resolve_mx_records(self, domain: str) -> Dict[str, Dict[str, Any]]:
        """
        Resolve MX records (mail servers) for a domain.

        Args:
            domain: Domain name to resolve

        Returns:
            Dictionary mapping mail server hostnames to their details:
            {'mail.example.com': {'preference': 10, 'ips': ['1.2.3.4']}}
        """
        try:
            result = await self.resolver.query(domain, 'MX')
            mx_records = {}

            # Resolve IPs for each mail server concurrently
            tasks = []
            mx_hosts = []
            for mx in result:
                mx_host = mx.host.rstrip('.')
                mx_hosts.append((mx_host, mx.priority))
                tasks.append(self._resolve_nameserver_ips(mx_host))

            results = await asyncio.gather(*tasks, return_exceptions=True)

            for (mx_host, preference), ips in zip(mx_hosts, results):
                if isinstance(ips, Exception):
                    logger.debug(f"Could not resolve IPs for mail server {mx_host}: {ips}")
                    mx_records[mx_host] = {'preference': preference, 'ips': []}
                else:
                    mx_records[mx_host] = {'preference': preference, 'ips': ips}

            logger.debug(f"Resolved MX records for {domain}: {list(mx_records.keys())}")
            return mx_records

        except aiodns.error.DNSError as e:
            logger.debug(f"No MX records for {domain}: {e}")
            return {}
        except Exception as e:
            logger.warning(f"Error resolving MX records for {domain}: {e}")
            return {}

    async def resolve_domain(self, domain: str) -> Dict[str, Any]:
        """
        Resolve all DNS records for a domain concurrently.

        Args:
            domain: Domain name to resolve

        Returns:
            Dictionary containing all DNS record types:
            {
                'domain': 'example.com',
                'a_records': ['1.2.3.4'],
                'aaaa_records': ['2001:db8::1'],
                'ns_records': {'ns1.example.com': ['1.2.3.5']},
                'mx_records': {'mail.example.com': {'preference': 10, 'ips': ['1.2.3.6']}}
            }
        """
        # Resolve all record types concurrently
        a_task = asyncio.create_task(self.resolve_a_records(domain))
        aaaa_task = asyncio.create_task(self.resolve_aaaa_records(domain))
        ns_task = asyncio.create_task(self.resolve_ns_records(domain))
        mx_task = asyncio.create_task(self.resolve_mx_records(domain))

        # Wait for all tasks to complete
        a_records, aaaa_records, ns_records, mx_records = await asyncio.gather(
            a_task, aaaa_task, ns_task, mx_task,
            return_exceptions=False
        )

        return {
            'domain': domain,
            'a_records': a_records,
            'aaaa_records': aaaa_records,
            'ns_records': ns_records,
            'mx_records': mx_records
        }

    async def resolve_domains_batch(
        self,
        domains: List[str],
        max_concurrent: int = 50
    ) -> List[Dict[str, Any]]:
        """
        Resolve multiple domains concurrently with concurrency limit.

        Args:
            domains: List of domain names to resolve
            max_concurrent: Maximum concurrent DNS queries

        Returns:
            List of DNS resolution results
        """
        semaphore = asyncio.Semaphore(max_concurrent)

        async def resolve_with_semaphore(domain: str) -> Dict[str, Any]:
            async with semaphore:
                return await self.resolve_domain(domain)

        tasks = [resolve_with_semaphore(domain) for domain in domains]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Handle exceptions
        processed_results = []
        for domain, result in zip(domains, results):
            if isinstance(result, Exception):
                logger.error(f"Error resolving {domain}: {result}")
                processed_results.append({
                    'domain': domain,
                    'error': str(result),
                    'a_records': [],
                    'aaaa_records': [],
                    'ns_records': {},
                    'mx_records': {}
                })
            else:
                processed_results.append(result)

        return processed_results


def resolve_domains_sync(
    domains: List[str],
    ip_version: Optional[int] = None,
    timeout: float = 5.0,
    retries: int = 2,
    max_concurrent: int = 50,
    nameservers: Optional[List[str]] = None
) -> List[Dict[str, Any]]:
    """
    Synchronous wrapper for async DNS resolution.

    This function can be called from synchronous code and will
    handle the async event loop internally.

    Args:
        domains: List of domain names to resolve
        ip_version: IP version (4, 6, or None for both)
        timeout: DNS query timeout in seconds
        retries: Number of retry attempts
        max_concurrent: Maximum concurrent queries
        nameservers: Custom nameservers

    Returns:
        List of DNS resolution results

    Example:
        >>> results = resolve_domains_sync(['google.com', 'github.com'])
        >>> print(results[0]['a_records'])
    """
    async def _resolve():
        processor = AsyncDNSProcessor(
            ip_version=ip_version,
            timeout=timeout,
            retries=retries,
            nameservers=nameservers
        )
        return await processor.resolve_domains_batch(domains, max_concurrent)

    # Create and run event loop
    return asyncio.run(_resolve())
