"""
Pytest configuration and fixtures for Domain ASN Mapper tests.
"""

import os
import tempfile
import pytest
from unittest.mock import Mock, MagicMock


@pytest.fixture
def sample_domains():
    """Sample list of domains for testing."""
    return [
        'google.com',
        'cloudflare.com',
        'github.com',
        'amazon.com',
        'ripe.net'
    ]


@pytest.fixture
def sample_domains_file(tmp_path, sample_domains):
    """Create a temporary file with sample domains."""
    domains_file = tmp_path / "test_domains.txt"
    domains_file.write_text('\n'.join(sample_domains))
    return str(domains_file)


@pytest.fixture
def invalid_domains_file(tmp_path):
    """Create a temporary file with invalid domains."""
    domains_file = tmp_path / "invalid_domains.txt"
    domains_file.write_text('\n'.join([
        'invalid domain with spaces',
        '..invalid..',
        '-invalid-.com',
        ''
    ]))
    return str(domains_file)


@pytest.fixture
def empty_domains_file(tmp_path):
    """Create an empty domains file."""
    domains_file = tmp_path / "empty_domains.txt"
    domains_file.write_text('')
    return str(domains_file)


@pytest.fixture
def mock_mrt_file(tmp_path):
    """Create a mock MRT file for testing."""
    mrt_file = tmp_path / "test.mrt"
    # Create an empty file - actual MRT parsing will be mocked
    mrt_file.write_bytes(b'')
    return str(mrt_file)


@pytest.fixture
def sample_dns_result():
    """Sample DNS resolution result."""
    return {
        'domain': 'google.com',
        'a_records': ['142.250.185.46', '142.250.185.14'],
        'aaaa_records': ['2607:f8b0:4004:c07::64', '2607:f8b0:4004:c07::71'],
        'ns_records': {
            'ns1.google.com': ['216.239.32.10'],
            'ns2.google.com': ['216.239.34.10']
        },
        'mx_records': {
            'smtp.google.com': {
                'ips': ['142.250.153.27'],
                'preference': 10
            }
        }
    }


@pytest.fixture
def sample_asn_result():
    """Sample ASN lookup result."""
    return {
        'domain': 'google.com',
        'a_records': [
            {'ip': '142.250.185.46', 'asn': 15169, 'prefix': '142.250.0.0/15'},
            {'ip': '142.250.185.14', 'asn': 15169, 'prefix': '142.250.0.0/15'}
        ],
        'aaaa_records': [
            {'ip': '2607:f8b0:4004:c07::64', 'asn': 15169, 'prefix': '2607:f8b0::/32'},
            {'ip': '2607:f8b0:4004:c07::71', 'asn': 15169, 'prefix': '2607:f8b0::/32'}
        ],
        'ns_records': {
            'ns1.google.com': [
                {'ip': '216.239.32.10', 'asn': 15169, 'prefix': '216.239.32.0/24'}
            ],
            'ns2.google.com': [
                {'ip': '216.239.34.10', 'asn': 15169, 'prefix': '216.239.34.0/24'}
            ]
        },
        'mx_records': {
            'smtp.google.com': {
                'ips': [
                    {'ip': '142.250.153.27', 'asn': 15169, 'prefix': '142.250.0.0/15'}
                ],
                'preference': 10
            }
        },
        'unique_asns': [
            {'asn': 15169, 'sources': ['a', 'aaaa', 'ns', 'mx']}
        ]
    }


@pytest.fixture
def output_file(tmp_path):
    """Create a temporary output file path."""
    return str(tmp_path / "test_output.json")


@pytest.fixture
def mock_dns_processor():
    """Mock DNSProcessor for testing."""
    mock = Mock()
    mock.resolve_domain = Mock(return_value={
        'domain': 'test.com',
        'a_records': ['1.2.3.4'],
        'aaaa_records': [],
        'ns_records': {},
        'mx_records': {}
    })
    return mock


@pytest.fixture
def mock_asn_processor():
    """Mock ASNProcessor for testing."""
    mock = Mock()
    mock.lookup_domain_asn = Mock(return_value={
        'domain': 'test.com',
        'a_records': [{'ip': '1.2.3.4', 'asn': 12345, 'prefix': '1.2.0.0/16'}],
        'aaaa_records': [],
        'ns_records': {},
        'mx_records': {},
        'unique_asns': [{'asn': 12345, 'sources': ['a']}]
    })
    return mock


@pytest.fixture
def flask_app():
    """Create Flask app instance for testing."""
    from app import app
    app.config['TESTING'] = True
    app.config['SECRET_KEY'] = 'test_secret_key'
    return app


@pytest.fixture
def flask_client(flask_app):
    """Create Flask test client."""
    return flask_app.test_client()


@pytest.fixture
def temp_upload_folder(tmp_path):
    """Create temporary upload folder."""
    upload_folder = tmp_path / "uploads"
    upload_folder.mkdir()
    return str(upload_folder)
