"""
Unit tests for DNSProcessor class.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import dns.resolver
import dns.exception

from dns_processor import DNSProcessor


@pytest.mark.unit
class TestDNSProcessor:
    """Tests for DNSProcessor class."""

    def test_init_default(self):
        """Test DNSProcessor initialization with defaults."""
        processor = DNSProcessor()
        assert processor.ip_version is None
        assert processor.timeout == 5
        assert processor.retries == 2

    def test_init_ipv4_only(self):
        """Test DNSProcessor initialization with IPv4 only."""
        processor = DNSProcessor(ip_version=4)
        assert processor.ip_version == 4

    def test_init_ipv6_only(self):
        """Test DNSProcessor initialization with IPv6 only."""
        processor = DNSProcessor(ip_version=6)
        assert processor.ip_version == 6

    def test_init_custom_params(self):
        """Test DNSProcessor with custom parameters."""
        processor = DNSProcessor(timeout=10, retries=5)
        assert processor.timeout == 10
        assert processor.retries == 5

    @patch('dns.resolver.resolve')
    def test_resolve_a_records_success(self, mock_resolve):
        """Test successful A record resolution."""
        # Mock DNS response
        mock_answer = Mock()
        mock_answer.rrset = [Mock(address='1.2.3.4'), Mock(address='5.6.7.8')]
        mock_resolve.return_value = mock_answer

        processor = DNSProcessor()
        result = processor.resolve_a_records('test.com')

        assert result == ['1.2.3.4', '5.6.7.8']
        mock_resolve.assert_called_once()

    @patch('dns.resolver.resolve')
    def test_resolve_a_records_nxdomain(self, mock_resolve):
        """Test A record resolution with NXDOMAIN."""
        mock_resolve.side_effect = dns.resolver.NXDOMAIN()

        processor = DNSProcessor()
        result = processor.resolve_a_records('nonexistent.invalid')

        assert result == []

    @patch('dns.resolver.resolve')
    def test_resolve_a_records_timeout(self, mock_resolve):
        """Test A record resolution with timeout."""
        mock_resolve.side_effect = dns.exception.Timeout()

        processor = DNSProcessor()
        result = processor.resolve_a_records('timeout.com')

        assert result == []

    @patch('dns.resolver.resolve')
    def test_resolve_aaaa_records_success(self, mock_resolve):
        """Test successful AAAA record resolution."""
        mock_answer = Mock()
        mock_answer.rrset = [
            Mock(address='2001:db8::1'),
            Mock(address='2001:db8::2')
        ]
        mock_resolve.return_value = mock_answer

        processor = DNSProcessor()
        result = processor.resolve_aaaa_records('test.com')

        assert result == ['2001:db8::1', '2001:db8::2']

    @patch('dns.resolver.resolve')
    def test_resolve_ns_records_success(self, mock_resolve):
        """Test successful NS record resolution."""
        # Mock NS records
        mock_ns_answer = Mock()
        mock_ns_answer.rrset = [
            Mock(target=Mock(to_text=Mock(return_value='ns1.test.com.'))),
            Mock(target=Mock(to_text=Mock(return_value='ns2.test.com.')))
        ]

        # Mock A records for nameservers
        mock_a_answer = Mock()
        mock_a_answer.rrset = [Mock(address='1.1.1.1')]

        def resolve_side_effect(domain, rdtype, *args, **kwargs):
            if rdtype == 'NS':
                return mock_ns_answer
            elif rdtype == 'A':
                return mock_a_answer
            raise dns.resolver.NoAnswer()

        mock_resolve.side_effect = resolve_side_effect

        processor = DNSProcessor()
        result = processor.resolve_ns_records('test.com')

        assert 'ns1.test.com' in result
        assert 'ns2.test.com' in result
        assert result['ns1.test.com'] == ['1.1.1.1']

    @patch('dns.resolver.resolve')
    def test_resolve_mx_records_success(self, mock_resolve):
        """Test successful MX record resolution."""
        # Mock MX records
        mock_mx_answer = Mock()
        mock_mx = Mock()
        mock_mx.preference = 10
        mock_mx.exchange = Mock(to_text=Mock(return_value='mail.test.com.'))
        mock_mx_answer.rrset = [mock_mx]

        # Mock A records for mail servers
        mock_a_answer = Mock()
        mock_a_answer.rrset = [Mock(address='2.2.2.2')]

        def resolve_side_effect(domain, rdtype, *args, **kwargs):
            if rdtype == 'MX':
                return mock_mx_answer
            elif rdtype == 'A':
                return mock_a_answer
            raise dns.resolver.NoAnswer()

        mock_resolve.side_effect = resolve_side_effect

        processor = DNSProcessor()
        result = processor.resolve_mx_records('test.com')

        assert 'mail.test.com' in result
        assert result['mail.test.com']['preference'] == 10
        assert result['mail.test.com']['ips'] == ['2.2.2.2']

    @patch('dns.resolver.resolve')
    def test_resolve_domain_complete(self, mock_resolve):
        """Test complete domain resolution."""
        # Mock all record types
        mock_a = Mock()
        mock_a.rrset = [Mock(address='1.2.3.4')]

        mock_aaaa = Mock()
        mock_aaaa.rrset = [Mock(address='2001:db8::1')]

        mock_ns = Mock()
        mock_ns.rrset = [Mock(target=Mock(to_text=Mock(return_value='ns.test.com.')))]

        mock_mx = Mock()
        mx_record = Mock()
        mx_record.preference = 10
        mx_record.exchange = Mock(to_text=Mock(return_value='mail.test.com.'))
        mock_mx.rrset = [mx_record]

        def resolve_side_effect(domain, rdtype, *args, **kwargs):
            if rdtype == 'A':
                return mock_a
            elif rdtype == 'AAAA':
                return mock_aaaa
            elif rdtype == 'NS':
                return mock_ns
            elif rdtype == 'MX':
                return mock_mx
            raise dns.resolver.NoAnswer()

        mock_resolve.side_effect = resolve_side_effect

        processor = DNSProcessor()
        result = processor.resolve_domain('test.com')

        assert result['domain'] == 'test.com'
        assert '1.2.3.4' in result['a_records']
        assert '2001:db8::1' in result['aaaa_records']
        assert 'ns.test.com' in result['ns_records']
        assert 'mail.test.com' in result['mx_records']

    def test_resolve_domain_ipv4_only(self):
        """Test domain resolution with IPv4 only."""
        with patch('dns.resolver.resolve') as mock_resolve:
            mock_a = Mock()
            mock_a.rrset = [Mock(address='1.2.3.4')]
            mock_resolve.return_value = mock_a

            processor = DNSProcessor(ip_version=4)
            result = processor.resolve_domain('test.com')

            assert '1.2.3.4' in result['a_records']
            assert result['aaaa_records'] == []

    def test_resolve_domain_ipv6_only(self):
        """Test domain resolution with IPv6 only."""
        with patch('dns.resolver.resolve') as mock_resolve:
            mock_aaaa = Mock()
            mock_aaaa.rrset = [Mock(address='2001:db8::1')]
            mock_resolve.return_value = mock_aaaa

            processor = DNSProcessor(ip_version=6)
            result = processor.resolve_domain('test.com')

            assert result['a_records'] == []
            assert '2001:db8::1' in result['aaaa_records']

    @patch('dns.resolver.resolve')
    def test_resolve_domain_with_errors(self, mock_resolve):
        """Test domain resolution with mixed successes and errors."""
        call_count = [0]

        def resolve_side_effect(domain, rdtype, *args, **kwargs):
            call_count[0] += 1
            if rdtype == 'A':
                mock_a = Mock()
                mock_a.rrset = [Mock(address='1.2.3.4')]
                return mock_a
            # All other record types fail
            raise dns.resolver.NoAnswer()

        mock_resolve.side_effect = resolve_side_effect

        processor = DNSProcessor()
        result = processor.resolve_domain('test.com')

        assert result['domain'] == 'test.com'
        assert '1.2.3.4' in result['a_records']
        assert result['aaaa_records'] == []
        assert result['ns_records'] == {}
        assert result['mx_records'] == {}

    def test_resolve_domain_empty_domain(self):
        """Test resolution with empty domain."""
        processor = DNSProcessor()
        result = processor.resolve_domain('')

        assert result['domain'] == ''
        assert result['a_records'] == []
