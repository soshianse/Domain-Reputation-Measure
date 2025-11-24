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
import sys
import json
from core import (
    DomainProcessor, ScanStorage, ScanDiff, get_database_manager,
    ASNAnalytics, export_scan_data, MarkdownReportExporter, ASNVisualizer
)

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

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Scan command (main processing)
    scan_parser = subparsers.add_parser('scan', help='Scan domains and map to ASNs')
    scan_parser.add_argument(
        '-d', '--domains',
        type=str,
        required=True,
        help='Path to the file containing the list of domains (one per line)'
    )
    scan_parser.add_argument(
        '-m', '--mrt-file',
        type=str,
        required=True,
        help='Path to the MRT file containing ASN information'
    )
    scan_parser.add_argument(
        '-o', '--output',
        type=str,
        default='results.json',
        help='Path to output file (default: results.json)'
    )
    scan_parser.add_argument(
        '-f', '--format',
        choices=['json', 'csv', 'text'],
        default='json',
        help='Output format (default: json)'
    )
    scan_parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    scan_parser.add_argument(
        '--ipv4-only',
        action='store_true',
        help='Only resolve IPv4 addresses'
    )
    scan_parser.add_argument(
        '--ipv6-only',
        action='store_true',
        help='Only resolve IPv6 addresses'
    )
    scan_parser.add_argument(
        '--save-to-db',
        action='store_true',
        help='Save scan results to database for historical tracking'
    )
    scan_parser.add_argument(
        '--notes',
        type=str,
        help='Optional notes about this scan (saved to database)'
    )

    # Web server command
    web_parser = subparsers.add_parser('web', help='Start the web application server')
    web_parser.add_argument(
        '--host',
        type=str,
        default='0.0.0.0',
        help='Host to bind to (default: 0.0.0.0)'
    )
    web_parser.add_argument(
        '--port',
        type=int,
        default=5000,
        help='Port to bind to (default: 5000)'
    )

    # Database initialization
    db_init_parser = subparsers.add_parser('db-init', help='Initialize database schema')
    db_init_parser.add_argument(
        '--force',
        action='store_true',
        help='Force re-initialization (drops existing tables)'
    )

    # Database migrations
    db_migrate_parser = subparsers.add_parser('db-migrate', help='Run database migrations')
    db_migrate_parser.add_argument(
        '--revision',
        type=str,
        default='head',
        help='Target revision (default: head)'
    )

    # List scans
    list_scans_parser = subparsers.add_parser('list-scans', help='List recent scans')
    list_scans_parser.add_argument(
        '--limit',
        type=int,
        default=10,
        help='Number of scans to show (default: 10)'
    )

    # Show scan details
    show_scan_parser = subparsers.add_parser('show-scan', help='Show details of a specific scan')
    show_scan_parser.add_argument(
        'scan_id',
        type=str,
        help='Scan ID to show'
    )

    # Diff scans
    diff_parser = subparsers.add_parser('diff', help='Compare two scans and detect changes')
    diff_parser.add_argument(
        'previous_scan_id',
        type=str,
        help='Previous scan ID'
    )
    diff_parser.add_argument(
        'current_scan_id',
        type=str,
        help='Current scan ID'
    )
    diff_parser.add_argument(
        '-o', '--output',
        type=str,
        help='Save diff report to file (optional)'
    )

    # Domain history
    history_parser = subparsers.add_parser('history', help='Show scan history for a domain')
    history_parser.add_argument(
        'domain',
        type=str,
        help='Domain name to show history for'
    )
    history_parser.add_argument(
        '--limit',
        type=int,
        default=10,
        help='Number of scans to show (default: 10)'
    )

    # ASN analytics
    analytics_parser = subparsers.add_parser('analytics', help='Generate ASN statistics and analysis')
    analytics_parser.add_argument(
        '--scan-id',
        type=str,
        help='Scan ID to analyze (uses latest if not provided)'
    )
    analytics_parser.add_argument(
        '-o', '--output',
        type=str,
        help='Save report to file (JSON or Markdown)'
    )
    analytics_parser.add_argument(
        '--format',
        choices=['json', 'markdown', 'both'],
        default='json',
        help='Output format (default: json)'
    )

    # ASN trends
    trends_parser = subparsers.add_parser('trends', help='Show trends for a specific ASN')
    trends_parser.add_argument(
        'asn',
        type=int,
        help='ASN number to analyze'
    )
    trends_parser.add_argument(
        '--days',
        type=int,
        default=30,
        help='Number of days to analyze (default: 30)'
    )
    trends_parser.add_argument(
        '-o', '--output',
        type=str,
        help='Save report to file'
    )

    # Domain clustering
    cluster_parser = subparsers.add_parser('cluster', help='Find domains sharing ASN infrastructure')
    cluster_parser.add_argument(
        '--scan-id',
        type=str,
        help='Scan ID to analyze (uses latest if not provided)'
    )
    cluster_parser.add_argument(
        '--min-shared',
        type=int,
        default=2,
        help='Minimum shared ASNs to form a cluster (default: 2)'
    )
    cluster_parser.add_argument(
        '-o', '--output',
        type=str,
        help='Save clusters to file (JSON)'
    )

    # Export scan data
    export_parser = subparsers.add_parser('export', help='Export scan data to various formats')
    export_parser.add_argument(
        'scan_id',
        type=str,
        help='Scan ID to export'
    )
    export_parser.add_argument(
        '-o', '--output',
        type=str,
        required=True,
        help='Output file path'
    )
    export_parser.add_argument(
        '--format',
        choices=['json', 'csv', 'parquet', 'gexf', 'graphml'],
        default='json',
        help='Export format (default: json)'
    )

    # Visualize scan data
    visualize_parser = subparsers.add_parser('visualize', help='Generate visualizations')
    visualize_parser.add_argument(
        '--scan-id',
        type=str,
        help='Scan ID to visualize (uses latest if not provided)'
    )
    visualize_parser.add_argument(
        '--type',
        choices=['top-asns', 'distribution', 'diversity', 'dashboard', 'all'],
        default='all',
        help='Visualization type (default: all)'
    )
    visualize_parser.add_argument(
        '--output-dir',
        type=str,
        default='visualizations',
        help='Output directory for visualizations (default: visualizations)'
    )

    return parser.parse_args()


def process_domains(domains_file, mrt_file, output_file, format_type='json', ip_version=None, verbose=False, save_to_db=False, notes=None):
    """
    Process domains from a file and generate ASN mapping results.

    This function wraps the DomainProcessor class for backward compatibility
    and provides a simple interface for both CLI and web usage.

    Args:
        domains_file (str): Path to the domains file
        mrt_file (str): Path to the MRT file
        output_file (str): Path to write the output file
        format_type (str): Output format ('json', 'csv', or 'text')
        ip_version (int, optional): IP version to use (4 or 6, None for both)
        verbose (bool, optional): Enable verbose logging
        save_to_db (bool, optional): Save results to database
        notes (str, optional): Notes about this scan (for database)

    Returns:
        dict: Processing results summary
    """
    try:
        # Create processor instance
        processor = DomainProcessor(
            mrt_file=mrt_file,
            ip_version=ip_version,
            verbose=verbose
        )

        # Count domains
        with open(domains_file, 'r') as f:
            total_domains = sum(1 for _ in f)

        scan_id = None
        storage = None

        # Initialize database storage if requested
        if save_to_db:
            storage = ScanStorage()
            scan_id = storage.create_scan(
                mrt_file=mrt_file,
                total_domains=total_domains,
                notes=notes
            )
            logger.info(f"Created scan record: {scan_id}")

        # Process domains
        result = processor.process_domains(
            domains_file=domains_file,
            output_file=output_file,
            format_type=format_type
        )

        # Save to database if enabled
        if save_to_db and storage and scan_id:
            # Read results to save to database
            with open(output_file, 'r') as f:
                results = json.load(f)

            storage.save_domain_results(scan_id, results)
            storage.complete_scan(
                scan_id,
                successful_domains=result.get('successful', 0),
                failed_domains=result.get('failed', 0),
                status='completed'
            )
            logger.info(f"Scan results saved to database: {scan_id}")
            result['scan_id'] = scan_id

        return result
    except Exception as e:
        logger.error(f"Error during processing: {e}")
        if save_to_db and storage and scan_id:
            storage.complete_scan(scan_id, 0, 0, status='failed')
        return {"error": f"Failed to process domains: {str(e)}"}


def main():
    """Main execution function for command line use."""
    args = parse_arguments()

    if args.command is None:
        logger.error("No command specified. Use --help to see available commands.")
        sys.exit(1)

    # Handle scan command
    if args.command == 'scan':
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
            verbose=args.verbose,
            save_to_db=args.save_to_db,
            notes=args.notes
        )

        if "error" in result:
            logger.error(result["error"])
            sys.exit(1)

        logger.info(f"Scan completed successfully: {result.get('successful', 0)} successful, {result.get('failed', 0)} failed")
        if 'scan_id' in result:
            logger.info(f"Scan ID: {result['scan_id']}")

    # Handle web command
    elif args.command == 'web':
        from app import app
        logger.info(f"Starting web application server on {args.host}:{args.port}...")
        app.run(host=args.host, port=args.port, debug=True)

    # Handle db-init command
    elif args.command == 'db-init':
        try:
            db_manager = get_database_manager()
            if args.force:
                logger.warning("Dropping all existing tables...")
                db_manager.drop_tables()
            logger.info("Initializing database schema...")
            db_manager.create_tables()
            logger.info("Database initialized successfully!")
        except Exception as e:
            logger.error(f"Error initializing database: {e}")
            sys.exit(1)

    # Handle db-migrate command
    elif args.command == 'db-migrate':
        import subprocess
        try:
            logger.info(f"Running migrations to {args.revision}...")
            subprocess.run(
                ['python3', '-m', 'alembic', 'upgrade', args.revision],
                check=True
            )
            logger.info("Migrations completed successfully!")
        except subprocess.CalledProcessError as e:
            logger.error(f"Error running migrations: {e}")
            sys.exit(1)

    # Handle list-scans command
    elif args.command == 'list-scans':
        try:
            storage = ScanStorage()
            scans = storage.list_scans(limit=args.limit)

            if not scans:
                print("No scans found in database.")
                return

            print(f"\nRecent scans (showing {len(scans)}):")
            print("-" * 120)
            print(f"{'Scan ID':<38} {'Started':<20} {'Status':<12} {'Domains':<10} {'Success':<10} {'Failed':<10}")
            print("-" * 120)

            for scan in scans:
                scan_id = scan['scan_id'][:36]
                started = scan['started_at'][:19] if scan['started_at'] else 'N/A'
                status = scan['status']
                total = scan['total_domains'] or 0
                success = scan['successful_domains'] or 0
                failed = scan['failed_domains'] or 0
                print(f"{scan_id:<38} {started:<20} {status:<12} {total:<10} {success:<10} {failed:<10}")

            print("-" * 120)
        except Exception as e:
            logger.error(f"Error listing scans: {e}")
            sys.exit(1)

    # Handle show-scan command
    elif args.command == 'show-scan':
        try:
            storage = ScanStorage()
            scan = storage.get_scan(args.scan_id)

            if not scan:
                logger.error(f"Scan not found: {args.scan_id}")
                sys.exit(1)

            print("\nScan Details:")
            print("=" * 70)
            print(f"Scan ID:           {scan['scan_id']}")
            print(f"Started:           {scan['started_at']}")
            print(f"Completed:         {scan['completed_at'] or 'N/A'}")
            print(f"Status:            {scan['status']}")
            print(f"Total domains:     {scan['total_domains']}")
            print(f"Successful:        {scan['successful_domains']}")
            print(f"Failed:            {scan['failed_domains']}")
            print(f"MRT file:          {scan['mrt_file']}")
            if scan['notes']:
                print(f"Notes:             {scan['notes']}")
            print("=" * 70)
        except Exception as e:
            logger.error(f"Error showing scan: {e}")
            sys.exit(1)

    # Handle diff command
    elif args.command == 'diff':
        try:
            storage = ScanStorage()

            # Get scan results
            prev_results = storage.get_scan_results(args.previous_scan_id)
            curr_results = storage.get_scan_results(args.current_scan_id)

            if not prev_results:
                logger.error(f"Previous scan not found: {args.previous_scan_id}")
                sys.exit(1)
            if not curr_results:
                logger.error(f"Current scan not found: {args.current_scan_id}")
                sys.exit(1)

            # Create diff
            diff = ScanDiff(prev_results, curr_results)
            report = diff.generate_report()

            # Print report
            print(report)

            # Save to file if requested
            if args.output:
                with open(args.output, 'w') as f:
                    f.write(report)
                logger.info(f"Diff report saved to: {args.output}")
        except Exception as e:
            logger.error(f"Error comparing scans: {e}")
            sys.exit(1)

    # Handle history command
    elif args.command == 'history':
        try:
            storage = ScanStorage()
            history = storage.get_domain_history(args.domain, limit=args.limit)

            if not history:
                print(f"No history found for domain: {args.domain}")
                return

            print(f"\nScan history for {args.domain}:")
            print("=" * 100)

            for i, scan in enumerate(history, 1):
                print(f"\nScan #{i} - {scan['scanned_at'][:19]}")
                print("-" * 100)
                if scan['success']:
                    print(f"  A records:    {len(scan.get('a_records', []))} found")
                    print(f"  AAAA records: {len(scan.get('aaaa_records', []))} found")
                    print(f"  NS records:   {len(scan.get('ns_records', {}))} found")
                    print(f"  MX records:   {len(scan.get('mx_records', {}))} found")
                    print(f"  Unique ASNs:  {len(scan.get('unique_asns', []))} found")
                else:
                    print(f"  Status:       Failed")
                    print(f"  Error:        {scan.get('error_message', 'Unknown error')}")

            print("=" * 100)
        except Exception as e:
            logger.error(f"Error showing domain history: {e}")
            sys.exit(1)

    # Handle analytics command
    elif args.command == 'analytics':
        try:
            analytics = ASNAnalytics()
            data = analytics.get_asn_statistics(scan_id=args.scan_id)

            if 'error' in data:
                logger.error(data['error'])
                sys.exit(1)

            # Print summary
            print("\n" + "=" * 70)
            print("ASN STATISTICS")
            print("=" * 70)
            print(f"Scan ID:              {data['scan_id']}")
            print(f"Total Unique ASNs:    {data['total_unique_asns']:,}")
            print(f"Total IP Mappings:    {data['total_ip_mappings']:,}")
            print(f"Avg IPs per ASN:      {data['avg_ips_per_asn']:.2f}")
            print(f"Concentration Ratio:  {data['concentration_ratio']:.2f}%")
            print("=" * 70)

            # Save if requested
            if args.output:
                if args.format in ['json', 'both']:
                    json_path = args.output if args.output.endswith('.json') else f"{args.output}.json"
                    with open(json_path, 'w') as f:
                        json.dump(data, f, indent=2)
                    logger.info(f"Saved JSON report to: {json_path}")

                if args.format in ['markdown', 'both']:
                    md_path = args.output if args.output.endswith('.md') else f"{args.output}.md"
                    exporter = MarkdownReportExporter(md_path)
                    exporter.export(data)

        except Exception as e:
            logger.error(f"Error generating analytics: {e}")
            sys.exit(1)

    # Handle trends command
    elif args.command == 'trends':
        try:
            analytics = ASNAnalytics()
            data = analytics.get_asn_trends(args.asn, days=args.days)

            if 'error' in data:
                logger.error(data['error'])
                sys.exit(1)

            print(f"\nASN {args.asn} Trends ({args.days} days)")
            print("=" * 70)
            print(f"Scans analyzed: {data['scan_count']}")
            print(f"IP count change: {data['changes']['ip_count_change']:+d} ({data['changes']['ip_count_change_pct']:+.2f}%)")
            print(f"Domain count change: {data['changes']['domain_count_change']:+d} ({data['changes']['domain_count_change_pct']:+.2f}%)")
            print("=" * 70)

            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(data, f, indent=2)
                logger.info(f"Saved trends to: {args.output}")

        except Exception as e:
            logger.error(f"Error generating trends: {e}")
            sys.exit(1)

    # Handle cluster command
    elif args.command == 'cluster':
        try:
            analytics = ASNAnalytics()
            clusters = analytics.cluster_domains_by_asn(
                scan_id=args.scan_id,
                min_shared_asns=args.min_shared
            )

            if not clusters:
                print("No clusters found.")
                return

            print(f"\nFound {len(clusters)} clusters:")
            print("=" * 70)

            for i, cluster in enumerate(clusters[:10], 1):
                print(f"\nCluster {i}:")
                print(f"  Domains: {cluster['domain_count']}")
                print(f"  Shared ASNs: {cluster['asn_count']}")
                print(f"  ASNs: {', '.join(f'AS{asn}' for asn in cluster['shared_asns'][:10])}")
                if len(cluster['domains']) <= 5:
                    print(f"  Domains: {', '.join(cluster['domains'])}")
                else:
                    print(f"  Domains: {', '.join(cluster['domains'][:5])} ... and {len(cluster['domains'])-5} more")

            if len(clusters) > 10:
                print(f"\n... and {len(clusters)-10} more clusters")

            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(clusters, f, indent=2)
                logger.info(f"Saved clusters to: {args.output}")

        except Exception as e:
            logger.error(f"Error clustering domains: {e}")
            sys.exit(1)

    # Handle export command
    elif args.command == 'export':
        try:
            storage = ScanStorage()
            results = storage.get_scan_results(args.scan_id)

            if not results:
                logger.error(f"Scan not found: {args.scan_id}")
                sys.exit(1)

            success = export_scan_data(results, args.output, format=args.format)

            if success:
                logger.info(f"Exported scan data to: {args.output}")
            else:
                logger.error("Export failed")
                sys.exit(1)

        except Exception as e:
            logger.error(f"Error exporting data: {e}")
            sys.exit(1)

    # Handle visualize command
    elif args.command == 'visualize':
        try:
            analytics = ASNAnalytics()
            visualizer = ASNVisualizer(output_dir=args.output_dir)

            # Get analytics data
            data = analytics.get_asn_statistics(scan_id=args.scan_id)

            if 'error' in data:
                logger.error(data['error'])
                sys.exit(1)

            # Generate visualizations based on type
            if args.type in ['top-asns', 'all']:
                path = visualizer.plot_top_asns(data)
                if path:
                    print(f"Created top ASNs visualization: {path}")

            if args.type in ['distribution', 'all']:
                path = visualizer.plot_asn_distribution(data)
                if path:
                    print(f"Created ASN distribution visualization: {path}")

            if args.type in ['diversity', 'all']:
                diversity_data = analytics.get_asn_diversity_score(scan_id=args.scan_id)
                path = visualizer.plot_diversity_metrics(diversity_data)
                if path:
                    print(f"Created diversity metrics visualization: {path}")

            if args.type in ['dashboard', 'all']:
                path = visualizer.create_interactive_dashboard(data)
                if path:
                    print(f"Created interactive dashboard: {path}")

            logger.info(f"All visualizations saved to: {args.output_dir}/")

        except Exception as e:
            logger.error(f"Error creating visualizations: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)


if __name__ == "__main__":
    main()
