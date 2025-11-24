#!/usr/bin/env python3
"""
Performance benchmark for Domain ASN Mapper.

Compares sync vs async DNS resolution performance.
"""

import time
import argparse
from typing import List
from core.async_dns_processor import resolve_domains_sync as async_resolve
from dns_processor import DNSProcessor


def benchmark_sync(domains: List[str]) -> float:
    """
    Benchmark synchronous DNS resolution.

    Args:
        domains: List of domains to resolve

    Returns:
        Time taken in seconds
    """
    print(f"\n{'='*60}")
    print("SYNC MODE (dnspython)")
    print(f"{'='*60}")

    dns_processor = DNSProcessor()

    start_time = time.time()

    results = []
    for i, domain in enumerate(domains, 1):
        result = dns_processor.resolve_domain(domain)
        results.append(result)
        if i % 10 == 0 or i == len(domains):
            elapsed = time.time() - start_time
            rate = i / elapsed if elapsed > 0 else 0
            print(f"Progress: {i}/{len(domains)} ({rate:.2f} domains/sec)")

    elapsed = time.time() - start_time
    print(f"\nTotal time: {elapsed:.2f} seconds")
    print(f"Average: {elapsed/len(domains):.3f} seconds/domain")
    print(f"Throughput: {len(domains)/elapsed:.2f} domains/second")

    return elapsed


def benchmark_async(domains: List[str], max_concurrent: int = 50) -> float:
    """
    Benchmark asynchronous DNS resolution.

    Args:
        domains: List of domains to resolve
        max_concurrent: Maximum concurrent queries

    Returns:
        Time taken in seconds
    """
    print(f"\n{'='*60}")
    print(f"ASYNC MODE (aiodns, max_concurrent={max_concurrent})")
    print(f"{'='*60}")

    start_time = time.time()

    results = async_resolve(domains, max_concurrent=max_concurrent)

    elapsed = time.time() - start_time
    print(f"\nTotal time: {elapsed:.2f} seconds")
    print(f"Average: {elapsed/len(domains):.3f} seconds/domain")
    print(f"Throughput: {len(domains)/elapsed:.2f} domains/second")

    return elapsed


def main():
    parser = argparse.ArgumentParser(description='Benchmark DNS resolution performance')
    parser.add_argument(
        '-d', '--domains',
        type=str,
        default='sample_domains.txt',
        help='Path to domains file'
    )
    parser.add_argument(
        '-n', '--count',
        type=int,
        default=None,
        help='Number of domains to test (default: all)'
    )
    parser.add_argument(
        '--skip-sync',
        action='store_true',
        help='Skip sync benchmark (only run async)'
    )
    parser.add_argument(
        '--max-concurrent',
        type=int,
        default=50,
        help='Max concurrent connections for async (default: 50)'
    )

    args = parser.parse_args()

    # Read domains
    with open(args.domains, 'r') as f:
        domains = [line.strip() for line in f if line.strip() and not line.startswith('#')]

    if args.count:
        domains = domains[:args.count]

    print(f"\n{'='*60}")
    print(f"DOMAIN ASN MAPPER - PERFORMANCE BENCHMARK")
    print(f"{'='*60}")
    print(f"Domains: {len(domains)}")
    print(f"Source: {args.domains}")

    # Run benchmarks
    sync_time = None
    if not args.skip_sync:
        sync_time = benchmark_sync(domains)

    async_time = benchmark_async(domains, max_concurrent=args.max_concurrent)

    # Summary
    print(f"\n{'='*60}")
    print("SUMMARY")
    print(f"{'='*60}")

    if sync_time:
        print(f"Sync time:  {sync_time:.2f}s")
        print(f"Async time: {async_time:.2f}s")
        speedup = sync_time / async_time
        print(f"\n🚀 SPEEDUP: {speedup:.1f}x faster!")
        percent_improvement = ((sync_time - async_time) / sync_time) * 100
        print(f"   ({percent_improvement:.1f}% improvement)")
    else:
        print(f"Async time: {async_time:.2f}s")
        print(f"Throughput: {len(domains)/async_time:.2f} domains/second")

    print(f"\n{'='*60}\n")


if __name__ == '__main__':
    main()
