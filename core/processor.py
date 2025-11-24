"""
Unified domain processing logic for Domain ASN Mapper.

This module provides the core processing functionality used by both
the command-line interface and the web application.
"""

import logging
import os
import asyncio
from typing import Dict, List, Optional, Any, Tuple

from dns_processor import DNSProcessor
from asn_processor import ASNProcessor
from output_formatter import OutputFormatter
from .validators import validate_domains, sanitize_domain, is_ip_address
from .async_dns_processor import AsyncDNSProcessor, resolve_domains_sync

# Try to import rich for progress bars
try:
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeRemainingColumn
    from rich.console import Console
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

logger = logging.getLogger(__name__)


class DomainProcessor:
    """
    Unified processor for domain-to-ASN mapping.

    This class encapsulates all the logic needed to process domains,
    resolve DNS records, map to ASNs, and format output.
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
        """
        Initialize the domain processor.

        Args:
            mrt_file: Path to the MRT file containing ASN information
            ip_version: IP version to use (4 or 6, None for both)
            verbose: Enable verbose logging
            use_async: Use async DNS resolution for better performance (default: True)
            max_concurrent: Maximum concurrent DNS queries when using async (default: 50)
            show_progress: Show progress bar during processing (default: True)
        """
        self.mrt_file = mrt_file
        self.ip_version = ip_version
        self.verbose = verbose
        self.use_async = use_async
        self.max_concurrent = max_concurrent
        self.show_progress = show_progress and RICH_AVAILABLE

        # Set logging level
        if verbose:
            logger.setLevel(logging.DEBUG)

        # Initialize processors
        try:
            logger.info("Initializing ASN processor...")
            self.asn_processor = ASNProcessor(mrt_file)

            if use_async:
                logger.info("Initializing Async DNS processor (performance mode)...")
                self.async_dns_processor = AsyncDNSProcessor(ip_version=ip_version)
                self.dns_processor = None  # Won't use sync processor
            else:
                logger.info("Initializing DNS processor (compatibility mode)...")
                self.dns_processor = DNSProcessor(ip_version=ip_version)
                self.async_dns_processor = None
        except Exception as e:
            logger.error(f"Error initializing processors: {e}")
            raise

    def validate_files(self, domains_file: str) -> bool:
        """
        Validate that required input files exist.

        Args:
            domains_file: Path to the domains file

        Returns:
            bool: True if files are valid, False otherwise
        """
        if not os.path.isfile(domains_file):
            logger.error(f"Domains file not found: {domains_file}")
            return False

        if not os.path.isfile(self.mrt_file):
            logger.error(f"MRT file not found: {self.mrt_file}")
            return False

        return True

    def read_domains(self, file_path: str, validate: bool = True, sanitize: bool = True) -> Tuple[List[str], List[Tuple[str, str]]]:
        """
        Read domains from a file with optional validation and sanitization.

        Args:
            file_path: Path to the domains file
            validate: If True, validate domain names and filter invalid ones
            sanitize: If True, sanitize domain names (lowercase, remove protocols, etc.)

        Returns:
            Tuple of (valid_domains, invalid_domains_with_errors)

        Raises:
            Exception: If file cannot be read
        """
        try:
            with open(file_path, 'r') as file:
                # Strip whitespace and skip empty lines and comments
                raw_domains = [
                    line.strip() for line in file
                    if line.strip() and not line.strip().startswith('#')
                ]

            logger.info(f"Read {len(raw_domains)} lines from {file_path}")

            # Sanitize domains if requested
            if sanitize:
                domains = [sanitize_domain(d) for d in raw_domains]
                domains = [d for d in domains if d]  # Remove empty strings
                logger.info(f"Sanitized to {len(domains)} domains")
            else:
                domains = raw_domains

            # Filter out IP addresses (we only process domains)
            non_ip_domains = []
            ip_addresses = []
            for d in domains:
                if is_ip_address(d):
                    ip_addresses.append(d)
                else:
                    non_ip_domains.append(d)

            if ip_addresses:
                logger.warning(f"Filtered out {len(ip_addresses)} IP addresses (use domain names instead)")

            domains = non_ip_domains

            # Validate domains if requested
            invalid_domains = []
            if validate:
                valid_domains, invalid_domains = validate_domains(
                    domains,
                    lenient=False,
                    skip_invalid=True
                )
                logger.info(f"Validated: {len(valid_domains)} valid, {len(invalid_domains)} invalid")
            else:
                valid_domains = domains

            return valid_domains, invalid_domains

        except Exception as e:
            logger.error(f"Error reading domains file: {e}")
            raise

    def process_single_domain(self, domain: str) -> Dict[str, Any]:
        """
        Process a single domain and return ASN mapping results.

        Args:
            domain: Domain name to process

        Returns:
            Dictionary containing the domain's ASN mapping or error information
        """
        try:
            # Resolve DNS records
            dns_result = self.dns_processor.resolve_domain(domain)

            # Match with ASN data
            asn_result = self.asn_processor.lookup_domain_asn(dns_result)

            return asn_result
        except Exception as e:
            logger.error(f"Error processing domain {domain}: {e}")
            return {
                'domain': domain,
                'error': str(e)
            }

    def process_domains(
        self,
        domains_file: str,
        output_file: str,
        format_type: str = 'json'
    ) -> Dict[str, Any]:
        """
        Process domains from a file and generate ASN mapping results.

        This is the main processing function that handles the entire pipeline:
        1. Validate input files
        2. Read domains from file
        3. Process each domain (DNS + ASN lookup)
        4. Format and write output

        Args:
            domains_file: Path to the domains file
            output_file: Path to write the output file
            format_type: Output format ('json', 'csv', or 'text')

        Returns:
            Dictionary containing processing results summary or error information
        """
        # Validate input files
        if not self.validate_files(domains_file):
            return {"error": "Invalid input files"}

        # Read domains from file
        try:
            domains, invalid_domains = self.read_domains(domains_file)
        except Exception as e:
            return {"error": f"Failed to read domains: {str(e)}"}

        if not domains:
            error_msg = "No valid domains found in the input file"
            if invalid_domains:
                error_msg += f" ({len(invalid_domains)} invalid domains filtered out)"
            return {"error": error_msg}

        # Process domains (async or sync)
        logger.info(f"Starting domain processing ({'async' if self.use_async else 'sync'} mode)...")

        if self.use_async:
            # Use async processing for better performance
            results = self._process_domains_async_wrapper(domains)
        else:
            # Use sync processing (legacy mode)
            results = self._process_domains_sync(domains)

        # Format and write output
        try:
            logger.info(f"Processing complete. Formatting output as {format_type}...")
            formatter = OutputFormatter(format_type)
            formatter.write_output(results, output_file)

            logger.info(f"Results written to {output_file}")
            return {
                "success": True,
                "domains_processed": len(domains),
                "output_file": output_file,
                "output_format": format_type
            }
        except Exception as e:
            logger.error(f"Error writing output: {e}")
            return {"error": f"Failed to write output: {str(e)}"}

    def _process_domains_sync(self, domains: List[str]) -> List[Dict[str, Any]]:
        """
        Process domains using synchronous DNS resolution (legacy mode).

        Args:
            domains: List of domains to process

        Returns:
            List of processing results
        """
        results = []

        if self.show_progress and RICH_AVAILABLE:
            # Use rich progress bar
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                TimeRemainingColumn(),
            ) as progress:
                task = progress.add_task("[cyan]Processing domains...", total=len(domains))

                for i, domain in enumerate(domains):
                    result = self.process_single_domain(domain)
                    results.append(result)
                    progress.update(task, advance=1)
        else:
            # No progress bar
            for i, domain in enumerate(domains):
                if (i + 1) % 100 == 0 or (i + 1) == len(domains):
                    logger.info(f"Processing domain {i + 1}/{len(domains)}: {domain}")
                else:
                    logger.debug(f"Processing domain {i + 1}/{len(domains)}: {domain}")

                result = self.process_single_domain(domain)
                results.append(result)

        return results

    def _process_domains_async_wrapper(self, domains: List[str]) -> List[Dict[str, Any]]:
        """
        Wrapper to run async processing from sync context.

        Args:
            domains: List of domains to process

        Returns:
            List of processing results
        """
        return asyncio.run(self._process_domains_async(domains))

    async def _process_domains_async(self, domains: List[str]) -> List[Dict[str, Any]]:
        """
        Process domains using asynchronous DNS resolution for high performance.

        Args:
            domains: List of domains to process

        Returns:
            List of processing results
        """
        # Step 1: Resolve DNS records concurrently
        logger.info(f"Resolving DNS for {len(domains)} domains (max {self.max_concurrent} concurrent)...")

        if self.show_progress and RICH_AVAILABLE:
            console = Console()
            with console.status("[cyan]Resolving DNS records...") as status:
                dns_results = await self.async_dns_processor.resolve_domains_batch(
                    domains,
                    max_concurrent=self.max_concurrent
                )
        else:
            dns_results = await self.async_dns_processor.resolve_domains_batch(
                domains,
                max_concurrent=self.max_concurrent
            )

        # Step 2: Map to ASNs (this is CPU-bound, so we do it synchronously)
        logger.info("Mapping IPs to ASNs...")
        results = []

        if self.show_progress and RICH_AVAILABLE:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                TimeRemainingColumn(),
            ) as progress:
                task = progress.add_task("[green]Mapping to ASNs...", total=len(dns_results))

                for dns_result in dns_results:
                    try:
                        asn_result = self.asn_processor.lookup_domain_asn(dns_result)
                        results.append(asn_result)
                    except Exception as e:
                        logger.error(f"Error mapping ASN for {dns_result.get('domain', 'unknown')}: {e}")
                        results.append({
                            'domain': dns_result.get('domain', 'unknown'),
                            'error': str(e)
                        })
                    progress.update(task, advance=1)
        else:
            for i, dns_result in enumerate(dns_results):
                if (i + 1) % 100 == 0 or (i + 1) == len(dns_results):
                    logger.info(f"Mapping ASN {i + 1}/{len(dns_results)}")

                try:
                    asn_result = self.asn_processor.lookup_domain_asn(dns_result)
                    results.append(asn_result)
                except Exception as e:
                    logger.error(f"Error mapping ASN for {dns_result.get('domain', 'unknown')}: {e}")
                    results.append({
                        'domain': dns_result.get('domain', 'unknown'),
                        'error': str(e)
                    })

        return results

    def process_domain_list(
        self,
        domains: List[str],
        output_file: str,
        format_type: str = 'json'
    ) -> Dict[str, Any]:
        """
        Process a list of domains directly (without reading from file).

        This method is useful for the web interface where domains might
        already be in memory.

        Args:
            domains: List of domain names to process
            output_file: Path to write the output file
            format_type: Output format ('json', 'csv', or 'text')

        Returns:
            Dictionary containing processing results summary or error information
        """
        if not domains:
            return {"error": "No domains provided"}

        # Validate MRT file
        if not os.path.isfile(self.mrt_file):
            logger.error(f"MRT file not found: {self.mrt_file}")
            return {"error": "Invalid MRT file"}

        # Process domains
        logger.info(f"Starting processing of {len(domains)} domains...")
        results = []

        for i, domain in enumerate(domains):
            if (i + 1) % 100 == 0 or (i + 1) == len(domains):
                logger.info(f"Processing domain {i + 1}/{len(domains)}: {domain}")
            else:
                logger.debug(f"Processing domain {i + 1}/{len(domains)}: {domain}")

            result = self.process_single_domain(domain)
            results.append(result)

        # Format and write output
        try:
            logger.info(f"Processing complete. Formatting output as {format_type}...")
            formatter = OutputFormatter(format_type)
            formatter.write_output(results, output_file)

            logger.info(f"Results written to {output_file}")
            return {
                "success": True,
                "domains_processed": len(domains),
                "output_file": output_file,
                "output_format": format_type
            }
        except Exception as e:
            logger.error(f"Error writing output: {e}")
            return {"error": f"Failed to write output: {str(e)}"}
