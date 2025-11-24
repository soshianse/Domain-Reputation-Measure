"""
Validation utilities for Domain ASN Mapper.

This module provides validation functions for domain names and other inputs.
"""

import re
import logging
from typing import Tuple, List

logger = logging.getLogger(__name__)


# Domain name validation regex
# Matches valid domain names according to RFC 1035 and RFC 1123
DOMAIN_PATTERN = re.compile(
    r'^(?:[a-zA-Z0-9]'  # First character of the domain
    r'(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'  # Sub domain + hostname
    r'+[a-zA-Z]{2,63}$'  # First level TLD
)

# Alternative pattern that also accepts internationalized domain names (IDN)
# and punycode
DOMAIN_PATTERN_LENIENT = re.compile(
    r'^(?:[a-zA-Z0-9_]'
    r'(?:[a-zA-Z0-9\-_]{0,61}[a-zA-Z0-9_])?\.)*'
    r'[a-zA-Z0-9]'
    r'(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
)


def is_valid_domain(domain: str, lenient: bool = False) -> bool:
    """
    Validate a domain name.

    Args:
        domain: Domain name to validate
        lenient: If True, use more lenient validation that accepts underscores
                 and other less common but technically valid characters

    Returns:
        True if domain is valid, False otherwise
    """
    if not domain or not isinstance(domain, str):
        return False

    # Remove trailing dot if present (valid in DNS)
    domain = domain.rstrip('.')

    # Check length (RFC 1035: max 253 characters)
    if len(domain) > 253:
        return False

    # Check for empty domain
    if not domain:
        return False

    # Check for invalid characters
    if '..' in domain:
        return False

    # Cannot start or end with hyphen or dot
    if domain.startswith(('-', '.')) or domain.endswith(('-', '.')):
        return False

    # Use appropriate pattern
    pattern = DOMAIN_PATTERN_LENIENT if lenient else DOMAIN_PATTERN

    return bool(pattern.match(domain))


def validate_domain(domain: str, lenient: bool = False) -> Tuple[bool, str]:
    """
    Validate a domain name and return detailed result.

    Args:
        domain: Domain name to validate
        lenient: If True, use more lenient validation

    Returns:
        Tuple of (is_valid, error_message)
        If valid, error_message is empty string
    """
    if not domain:
        return False, "Domain name is empty"

    if not isinstance(domain, str):
        return False, f"Domain name must be a string, got {type(domain).__name__}"

    # Remove trailing dot
    domain_clean = domain.rstrip('.')

    # Length check
    if len(domain_clean) > 253:
        return False, f"Domain name too long: {len(domain_clean)} characters (max 253)"

    if len(domain_clean) == 0:
        return False, "Domain name is empty after removing trailing dot"

    # Check for double dots
    if '..' in domain_clean:
        return False, "Domain name contains consecutive dots"

    # Check for invalid start/end characters
    if domain_clean.startswith(('-', '.')):
        return False, f"Domain name cannot start with '{domain_clean[0]}'"

    if domain_clean.endswith(('-', '.')):
        return False, f"Domain name cannot end with '{domain_clean[-1]}'"

    # Check individual labels
    labels = domain_clean.split('.')

    if len(labels) < 2:
        return False, "Domain name must have at least two labels (e.g., example.com)"

    for i, label in enumerate(labels):
        if not label:
            return False, f"Label {i+1} is empty"

        if len(label) > 63:
            return False, f"Label '{label}' is too long: {len(label)} characters (max 63)"

        # Check label characters
        if not lenient:
            if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?$', label):
                return False, f"Label '{label}' contains invalid characters"
        else:
            if not re.match(r'^[a-zA-Z0-9_]([a-zA-Z0-9\-_]*[a-zA-Z0-9_])?$', label):
                return False, f"Label '{label}' contains invalid characters"

    # Check TLD (last label)
    tld = labels[-1]
    if not re.match(r'^[a-zA-Z]{2,}$', tld):
        # Allow numeric TLDs for lenient mode
        if not lenient or not re.match(r'^[a-zA-Z0-9]+$', tld):
            return False, f"Invalid TLD: '{tld}'"

    return True, ""


def validate_domains(domains: List[str], lenient: bool = False, skip_invalid: bool = False) -> Tuple[List[str], List[Tuple[str, str]]]:
    """
    Validate a list of domain names.

    Args:
        domains: List of domain names to validate
        lenient: If True, use more lenient validation
        skip_invalid: If True, skip invalid domains instead of raising error

    Returns:
        Tuple of (valid_domains, invalid_domains_with_errors)
        invalid_domains_with_errors is a list of (domain, error_message) tuples
    """
    valid_domains = []
    invalid_domains = []

    for domain in domains:
        is_valid, error_msg = validate_domain(domain, lenient=lenient)

        if is_valid:
            valid_domains.append(domain.rstrip('.'))
        else:
            invalid_domains.append((domain, error_msg))
            if not skip_invalid:
                logger.warning(f"Invalid domain '{domain}': {error_msg}")

    return valid_domains, invalid_domains


def sanitize_domain(domain: str) -> str:
    """
    Sanitize a domain name by removing common issues.

    Args:
        domain: Domain name to sanitize

    Returns:
        Sanitized domain name
    """
    if not domain:
        return ""

    # Convert to lowercase
    domain = domain.lower()

    # Strip whitespace
    domain = domain.strip()

    # Remove trailing dot
    domain = domain.rstrip('.')

    # Remove protocol if present
    domain = re.sub(r'^https?://', '', domain)
    domain = re.sub(r'^ftp://', '', domain)

    # Remove path if present
    domain = domain.split('/')[0]

    # Remove port if present
    domain = domain.split(':')[0]

    # Remove www. prefix (optional, can be commented out if not desired)
    # domain = re.sub(r'^www\.', '', domain)

    return domain


def is_likely_wildcard(domain: str) -> bool:
    """
    Check if a domain name looks like a wildcard pattern.

    Args:
        domain: Domain name to check

    Returns:
        True if domain appears to be a wildcard pattern
    """
    return '*' in domain or domain.startswith('.')


def is_ip_address(value: str) -> bool:
    """
    Check if a string is an IP address (IPv4 or IPv6).

    Args:
        value: String to check

    Returns:
        True if value looks like an IP address
    """
    # IPv4 pattern
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ipv4_pattern, value):
        return True

    # IPv6 pattern (simplified)
    if ':' in value and not '/' in value:
        return True

    return False
