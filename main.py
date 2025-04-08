#!/usr/bin/env python3
"""
Domain ASN Mapper - Main Application

This application reads a list of domains from a file, resolves DNS records (A, NS, MX),
matches them to ASN data in MRT files, and outputs the mapping information.

It can be used as:
1. A command-line tool (via main() function)
2. A web application (via app instance from app.py)
"""

import argparse
import logging
import os
import sys
import tempfile
from dns_processor import DNSProcessor
from asn_processor import ASNProcessor
from output_formatter import OutputFormatter
from app import app

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('domain_asn_mapper')


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Map domains to ASN information by resolving DNS records and using MRT data.',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument(
        '-d', '--domains',
        type=str,
        required=True,
        help='Path to the file containing the list of domains (one per line)'
    )
    
    parser.add_argument(
        '-m', '--mrt-file',
        type=str,
        required=True,
        help='Path to the MRT file containing ASN information'
    )
    
    parser.add_argument(
        '-o', '--output',
        type=str,
        default='results.json',
        help='Path to output file (default: results.json)'
    )
    
    parser.add_argument(
        '-f', '--format',
        choices=['json', 'csv', 'text'],
        default='json',
        help='Output format (default: json)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    parser.add_argument(
        '--ipv4-only',
        action='store_true',
        help='Only resolve IPv4 addresses'
    )
    
    parser.add_argument(
        '--ipv6-only',
        action='store_true',
        help='Only resolve IPv6 addresses'
    )
    
    parser.add_argument(
        '--web',
        action='store_true',
        help='Start the web application server'
    )

    return parser.parse_args()


def validate_files(domains_file, mrt_file):
    """Validate input files existence."""
    if not os.path.isfile(domains_file):
        logger.error(f"Domains file not found: {domains_file}")
        return False
    
    if not os.path.isfile(mrt_file):
        logger.error(f"MRT file not found: {mrt_file}")
        return False
        
    return True


def read_domains(file_path):
    """Read domains from a file and return as a list."""
    try:
        with open(file_path, 'r') as file:
            # Strip whitespace and skip empty lines
            domains = [line.strip() for line in file if line.strip()]
        logger.info(f"Successfully read {len(domains)} domains from {file_path}")
        return domains
    except Exception as e:
        logger.error(f"Error reading domains file: {e}")
        return []


def process_domains(domains_file, mrt_file, output_file, format_type='json', ip_version=None, verbose=False):
    """
    Process domains from a file and generate ASN mapping results.
    
    This is the core processing function that can be used by both the CLI and web application.
    
    Args:
        domains_file (str): Path to the domains file
        mrt_file (str): Path to the MRT file
        output_file (str): Path to write the output file
        format_type (str): Output format ('json', 'csv', or 'text')
        ip_version (int, optional): IP version to use (4 or 6, None for both)
        verbose (bool, optional): Enable verbose logging
    
    Returns:
        dict: Processing results summary
    """
    # Set logging level based on verbose flag
    if verbose:
        logger.setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled")
    
    # Validate input files
    if not validate_files(domains_file, mrt_file):
        return {"error": "Invalid input files"}
    
    # Read domains from file
    domains = read_domains(domains_file)
    if not domains:
        return {"error": "No domains found in the input file"}
    
    # Initialize processors
    try:
        logger.info("Initializing ASN processor...")
        asn_processor = ASNProcessor(mrt_file)
        
        logger.info("Initializing DNS processor...")
        dns_processor = DNSProcessor(ip_version=ip_version)
    except Exception as e:
        logger.error(f"Error initializing processors: {e}")
        return {"error": f"Failed to initialize processors: {str(e)}"}
    
    # Process domains
    logger.info("Starting domain processing...")
    results = []
    
    for i, domain in enumerate(domains):
        if (i + 1) % 100 == 0 or (i + 1) == len(domains):
            logger.info(f"Processing domain {i + 1}/{len(domains)}: {domain}")
        else:
            logger.debug(f"Processing domain {i + 1}/{len(domains)}: {domain}")
        
        try:
            # Resolve DNS records
            dns_result = dns_processor.resolve_domain(domain)
            
            # Match with ASN data
            asn_result = asn_processor.lookup_domain_asn(dns_result)
            
            # Add to results
            results.append(asn_result)
        except Exception as e:
            logger.error(f"Error processing domain {domain}: {e}")
            # Add error entry
            results.append({
                'domain': domain,
                'error': str(e)
            })
    
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


def main():
    """Main execution function for command line use."""
    args = parse_arguments()
    
    # Check if web server should be started
    if args.web:
        # Start the web application server
        logger.info("Starting web application server...")
        app.run(host='0.0.0.0', port=5000, debug=True)
        return
    
    # Determine IP version to use
    ip_version = None
    if args.ipv4_only:
        ip_version = 4
    elif args.ipv6_only:
        ip_version = 6
    
    # Process domains
    result = process_domains(
        args.domains,
        args.mrt_file,
        args.output,
        format_type=args.format,
        ip_version=ip_version,
        verbose=args.verbose
    )
    
    if "error" in result:
        logger.error(result["error"])
        sys.exit(1)


if __name__ == "__main__":
    main()
