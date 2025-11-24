"""
Unit tests for core DomainProcessor class.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import os
import json

from core import DomainProcessor


@pytest.mark.unit
class TestDomainProcessor:
    """Tests for unified DomainProcessor class."""

    @patch('core.processor.ASNProcessor')
    @patch('core.processor.DNSProcessor')
    def test_init_success(self, mock_dns_cls, mock_asn_cls):
        """Test successful initialization."""
        mock_asn = Mock()
        mock_dns = Mock()
        mock_asn_cls.return_value = mock_asn
        mock_dns_cls.return_value = mock_dns

        processor = DomainProcessor('test.mrt', ip_version=None, verbose=False)

        assert processor.mrt_file == 'test.mrt'
        assert processor.ip_version is None
        assert processor.verbose is False
        mock_asn_cls.assert_called_once_with('test.mrt')
        mock_dns_cls.assert_called_once_with(ip_version=None)

    @patch('core.processor.ASNProcessor')
    @patch('core.processor.DNSProcessor')
    def test_init_with_ipv4(self, mock_dns_cls, mock_asn_cls):
        """Test initialization with IPv4 only."""
        mock_asn_cls.return_value = Mock()
        mock_dns_cls.return_value = Mock()

        processor = DomainProcessor('test.mrt', ip_version=4)

        mock_dns_cls.assert_called_once_with(ip_version=4)

    @patch('core.processor.ASNProcessor')
    @patch('core.processor.DNSProcessor')
    def test_init_failure(self, mock_dns_cls, mock_asn_cls):
        """Test initialization failure."""
        mock_asn_cls.side_effect = Exception("MRT file error")

        with pytest.raises(Exception, match="MRT file error"):
            DomainProcessor('invalid.mrt')

    def test_validate_files_success(self, mock_mrt_file, sample_domains_file):
        """Test file validation with valid files."""
        with patch('core.processor.ASNProcessor'), patch('core.processor.DNSProcessor'):
            processor = DomainProcessor(mock_mrt_file)
            result = processor.validate_files(sample_domains_file)

        assert result is True

    def test_validate_files_missing_domains(self, mock_mrt_file):
        """Test file validation with missing domains file."""
        with patch('core.processor.ASNProcessor'), patch('core.processor.DNSProcessor'):
            processor = DomainProcessor(mock_mrt_file)
            result = processor.validate_files('/nonexistent/domains.txt')

        assert result is False

    def test_validate_files_missing_mrt(self, sample_domains_file):
        """Test file validation with missing MRT file."""
        with patch('core.processor.ASNProcessor'), patch('core.processor.DNSProcessor'):
            processor = DomainProcessor('/nonexistent/test.mrt')
            result = processor.validate_files(sample_domains_file)

        assert result is False

    def test_read_domains_success(self, mock_mrt_file, sample_domains_file, sample_domains):
        """Test successful domain reading."""
        with patch('core.processor.ASNProcessor'), patch('core.processor.DNSProcessor'):
            processor = DomainProcessor(mock_mrt_file)
            result = processor.read_domains(sample_domains_file)

        assert len(result) == len(sample_domains)
        assert all(d in result for d in sample_domains)

    def test_read_domains_empty_file(self, mock_mrt_file, empty_domains_file):
        """Test reading empty domains file."""
        with patch('core.processor.ASNProcessor'), patch('core.processor.DNSProcessor'):
            processor = DomainProcessor(mock_mrt_file)
            result = processor.read_domains(empty_domains_file)

        assert result == []

    def test_read_domains_file_not_found(self, mock_mrt_file):
        """Test reading nonexistent file."""
        with patch('core.processor.ASNProcessor'), patch('core.processor.DNSProcessor'):
            processor = DomainProcessor(mock_mrt_file)

            with pytest.raises(Exception):
                processor.read_domains('/nonexistent/file.txt')

    def test_process_single_domain_success(self, mock_mrt_file):
        """Test successful single domain processing."""
        mock_dns = Mock()
        mock_asn = Mock()

        dns_result = {'domain': 'test.com', 'a_records': ['1.2.3.4']}
        asn_result = {
            'domain': 'test.com',
            'a_records': [{'ip': '1.2.3.4', 'asn': 12345}]
        }

        mock_dns.resolve_domain.return_value = dns_result
        mock_asn.lookup_domain_asn.return_value = asn_result

        with patch('core.processor.ASNProcessor', return_value=mock_asn):
            with patch('core.processor.DNSProcessor', return_value=mock_dns):
                processor = DomainProcessor(mock_mrt_file)
                result = processor.process_single_domain('test.com')

        assert result['domain'] == 'test.com'
        assert 'a_records' in result
        mock_dns.resolve_domain.assert_called_once_with('test.com')
        mock_asn.lookup_domain_asn.assert_called_once_with(dns_result)

    def test_process_single_domain_error(self, mock_mrt_file):
        """Test single domain processing with error."""
        mock_dns = Mock()
        mock_dns.resolve_domain.side_effect = Exception("DNS resolution failed")

        mock_asn = Mock()

        with patch('core.processor.ASNProcessor', return_value=mock_asn):
            with patch('core.processor.DNSProcessor', return_value=mock_dns):
                processor = DomainProcessor(mock_mrt_file)
                result = processor.process_single_domain('invalid.com')

        assert result['domain'] == 'invalid.com'
        assert 'error' in result
        assert 'DNS resolution failed' in result['error']

    def test_process_domains_success(self, mock_mrt_file, sample_domains_file, output_file):
        """Test successful full pipeline processing."""
        mock_dns = Mock()
        mock_asn = Mock()

        mock_dns.resolve_domain.return_value = {
            'domain': 'test.com',
            'a_records': ['1.2.3.4']
        }
        mock_asn.lookup_domain_asn.return_value = {
            'domain': 'test.com',
            'a_records': [{'ip': '1.2.3.4', 'asn': 12345}]
        }

        with patch('core.processor.ASNProcessor', return_value=mock_asn):
            with patch('core.processor.DNSProcessor', return_value=mock_dns):
                processor = DomainProcessor(mock_mrt_file)
                result = processor.process_domains(
                    sample_domains_file,
                    output_file,
                    format_type='json'
                )

        assert result['success'] is True
        assert result['domains_processed'] == 5  # sample_domains has 5 domains
        assert result['output_file'] == output_file
        assert result['output_format'] == 'json'
        assert os.path.exists(output_file)

    def test_process_domains_invalid_files(self, mock_mrt_file):
        """Test processing with invalid input files."""
        with patch('core.processor.ASNProcessor'), patch('core.processor.DNSProcessor'):
            processor = DomainProcessor(mock_mrt_file)
            result = processor.process_domains(
                '/nonexistent/domains.txt',
                '/tmp/output.json'
            )

        assert 'error' in result
        assert 'Invalid input files' in result['error']

    def test_process_domains_empty_file(self, mock_mrt_file, empty_domains_file, output_file):
        """Test processing with empty domains file."""
        with patch('core.processor.ASNProcessor'), patch('core.processor.DNSProcessor'):
            processor = DomainProcessor(mock_mrt_file)
            result = processor.process_domains(
                empty_domains_file,
                output_file
            )

        assert 'error' in result
        assert 'No domains found' in result['error']

    def test_process_domain_list_success(self, mock_mrt_file, output_file):
        """Test processing a list of domains directly."""
        mock_dns = Mock()
        mock_asn = Mock()

        mock_dns.resolve_domain.return_value = {
            'domain': 'test.com',
            'a_records': ['1.2.3.4']
        }
        mock_asn.lookup_domain_asn.return_value = {
            'domain': 'test.com',
            'a_records': [{'ip': '1.2.3.4', 'asn': 12345}]
        }

        with patch('core.processor.ASNProcessor', return_value=mock_asn):
            with patch('core.processor.DNSProcessor', return_value=mock_dns):
                processor = DomainProcessor(mock_mrt_file)
                result = processor.process_domain_list(
                    ['test.com', 'example.com'],
                    output_file,
                    format_type='json'
                )

        assert result['success'] is True
        assert result['domains_processed'] == 2
        assert os.path.exists(output_file)

    def test_process_domain_list_empty(self, mock_mrt_file, output_file):
        """Test processing empty domain list."""
        with patch('core.processor.ASNProcessor'), patch('core.processor.DNSProcessor'):
            processor = DomainProcessor(mock_mrt_file)
            result = processor.process_domain_list([], output_file)

        assert 'error' in result
        assert 'No domains provided' in result['error']

    def test_process_domains_csv_format(self, mock_mrt_file, sample_domains_file, tmp_path):
        """Test processing with CSV output format."""
        output_file = str(tmp_path / "output.csv")

        mock_dns = Mock()
        mock_asn = Mock()

        mock_dns.resolve_domain.return_value = {
            'domain': 'test.com',
            'a_records': ['1.2.3.4']
        }
        mock_asn.lookup_domain_asn.return_value = {
            'domain': 'test.com',
            'a_records': [{'ip': '1.2.3.4', 'asn': 12345}],
            'aaaa_records': [],
            'ns_records': {},
            'mx_records': {},
            'unique_asns': []
        }

        with patch('core.processor.ASNProcessor', return_value=mock_asn):
            with patch('core.processor.DNSProcessor', return_value=mock_dns):
                processor = DomainProcessor(mock_mrt_file)
                result = processor.process_domains(
                    sample_domains_file,
                    output_file,
                    format_type='csv'
                )

        assert result['success'] is True
        assert result['output_format'] == 'csv'
        assert os.path.exists(output_file)

    def test_process_domains_text_format(self, mock_mrt_file, sample_domains_file, tmp_path):
        """Test processing with text output format."""
        output_file = str(tmp_path / "output.txt")

        mock_dns = Mock()
        mock_asn = Mock()

        mock_dns.resolve_domain.return_value = {
            'domain': 'test.com',
            'a_records': ['1.2.3.4']
        }
        mock_asn.lookup_domain_asn.return_value = {
            'domain': 'test.com',
            'a_records': [{'ip': '1.2.3.4', 'asn': 12345, 'prefix': '1.2.0.0/16'}],
            'aaaa_records': [],
            'ns_records': {},
            'mx_records': {},
            'unique_asns': [{'asn': 12345, 'sources': ['a']}]
        }

        with patch('core.processor.ASNProcessor', return_value=mock_asn):
            with patch('core.processor.DNSProcessor', return_value=mock_dns):
                processor = DomainProcessor(mock_mrt_file)
                result = processor.process_domains(
                    sample_domains_file,
                    output_file,
                    format_type='text'
                )

        assert result['success'] is True
        assert result['output_format'] == 'text'
        assert os.path.exists(output_file)

    def test_verbose_logging(self, mock_mrt_file):
        """Test that verbose mode enables debug logging."""
        with patch('core.processor.ASNProcessor'), patch('core.processor.DNSProcessor'):
            with patch('core.processor.logger') as mock_logger:
                processor = DomainProcessor(mock_mrt_file, verbose=True)
                mock_logger.setLevel.assert_called()


@pytest.mark.integration
class TestDomainProcessorIntegration:
    """Integration tests for DomainProcessor."""

    @pytest.mark.requires_mrt
    def test_full_pipeline_with_real_data(self, tmp_path):
        """Integration test with real MRT file if available."""
        mrt_file = 'sample.mrt.gz'

        if not os.path.exists(mrt_file):
            pytest.skip("Real MRT file not available for integration test")

        # Create test domains file
        domains_file = tmp_path / "domains.txt"
        domains_file.write_text("google.com\ncloudflare.com\n")

        output_file = tmp_path / "results.json"

        # Run full pipeline
        processor = DomainProcessor(mrt_file)
        result = processor.process_domains(
            str(domains_file),
            str(output_file),
            format_type='json'
        )

        assert result['success'] is True
        assert result['domains_processed'] == 2

        # Verify output
        with open(output_file) as f:
            results = json.load(f)

        assert len(results) == 2
        assert any(r['domain'] == 'google.com' for r in results)
        assert any(r['domain'] == 'cloudflare.com' for r in results)

        # Verify ASN data is present
        google_result = next(r for r in results if r['domain'] == 'google.com')
        assert len(google_result['unique_asns']) > 0
