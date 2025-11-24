"""
Unit tests for ASNProcessor class.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import os

from asn_processor import ASNProcessor


@pytest.mark.unit
class TestASNProcessor:
    """Tests for ASNProcessor class."""

    @patch('pyasn.pyasn')
    @patch('os.path.isfile')
    def test_init_with_existing_dat_file(self, mock_isfile, mock_pyasn):
        """Test initialization when .dat file already exists."""
        mock_isfile.return_value = True
        mock_asndb = Mock()
        mock_pyasn.return_value = mock_asndb

        processor = ASNProcessor('test.mrt')

        assert processor.mrt_file == 'test.mrt'
        assert processor.asndb == mock_asndb
        mock_pyasn.assert_called_once()

    @patch('pyasn.pyasn')
    @patch('pyasn.mrtx')
    @patch('os.path.isfile')
    def test_init_converts_mrt_to_dat(self, mock_isfile, mock_mrtx, mock_pyasn):
        """Test MRT conversion when .dat file doesn't exist."""
        # First call (check for .dat) returns False, second call (check for .mrt) returns True
        mock_isfile.side_effect = [False, True]
        mock_asndb = Mock()
        mock_pyasn.return_value = mock_asndb

        processor = ASNProcessor('test.mrt')

        mock_mrtx.assert_called_once()
        mock_pyasn.assert_called_once()

    def test_lookup_ip_success(self):
        """Test successful IP to ASN lookup."""
        mock_asndb = Mock()
        mock_asndb.lookup.return_value = (15169, '142.250.0.0/15')

        with patch('pyasn.pyasn', return_value=mock_asndb):
            with patch('os.path.isfile', return_value=True):
                processor = ASNProcessor('test.mrt')
                result = processor.lookup_ip('142.250.185.46')

        assert result['asn'] == 15169
        assert result['prefix'] == '142.250.0.0/15'

    def test_lookup_ip_not_found(self):
        """Test IP lookup when ASN not found."""
        mock_asndb = Mock()
        mock_asndb.lookup.return_value = (None, None)

        with patch('pyasn.pyasn', return_value=mock_asndb):
            with patch('os.path.isfile', return_value=True):
                processor = ASNProcessor('test.mrt')
                result = processor.lookup_ip('192.0.2.1')

        assert result['asn'] is None
        assert result['prefix'] is None

    def test_lookup_ip_invalid(self):
        """Test lookup with invalid IP."""
        mock_asndb = Mock()
        mock_asndb.lookup.side_effect = ValueError("Invalid IP")

        with patch('pyasn.pyasn', return_value=mock_asndb):
            with patch('os.path.isfile', return_value=True):
                processor = ASNProcessor('test.mrt')
                result = processor.lookup_ip('invalid-ip')

        assert result['asn'] is None
        assert result['prefix'] is None

    def test_enrich_a_records(self):
        """Test enriching A records with ASN data."""
        mock_asndb = Mock()
        mock_asndb.lookup.return_value = (15169, '142.250.0.0/15')

        with patch('pyasn.pyasn', return_value=mock_asndb):
            with patch('os.path.isfile', return_value=True):
                processor = ASNProcessor('test.mrt')

                a_records = ['142.250.185.46', '142.250.185.14']
                result = processor.enrich_a_records(a_records)

        assert len(result) == 2
        assert result[0]['ip'] == '142.250.185.46'
        assert result[0]['asn'] == 15169
        assert result[0]['prefix'] == '142.250.0.0/15'

    def test_enrich_aaaa_records(self):
        """Test enriching AAAA records with ASN data."""
        mock_asndb = Mock()
        mock_asndb.lookup.return_value = (15169, '2607:f8b0::/32')

        with patch('pyasn.pyasn', return_value=mock_asndb):
            with patch('os.path.isfile', return_value=True):
                processor = ASNProcessor('test.mrt')

                aaaa_records = ['2607:f8b0:4004:c07::64']
                result = processor.enrich_aaaa_records(aaaa_records)

        assert len(result) == 1
        assert result[0]['ip'] == '2607:f8b0:4004:c07::64'
        assert result[0]['asn'] == 15169

    def test_enrich_ns_records(self):
        """Test enriching NS records with ASN data."""
        mock_asndb = Mock()
        mock_asndb.lookup.return_value = (15169, '216.239.32.0/24')

        with patch('pyasn.pyasn', return_value=mock_asndb):
            with patch('os.path.isfile', return_value=True):
                processor = ASNProcessor('test.mrt')

                ns_records = {
                    'ns1.google.com': ['216.239.32.10'],
                    'ns2.google.com': ['216.239.34.10']
                }
                result = processor.enrich_ns_records(ns_records)

        assert 'ns1.google.com' in result
        assert 'ns2.google.com' in result
        assert result['ns1.google.com'][0]['asn'] == 15169

    def test_enrich_mx_records(self):
        """Test enriching MX records with ASN data."""
        mock_asndb = Mock()
        mock_asndb.lookup.return_value = (15169, '142.250.0.0/15')

        with patch('pyasn.pyasn', return_value=mock_asndb):
            with patch('os.path.isfile', return_value=True):
                processor = ASNProcessor('test.mrt')

                mx_records = {
                    'smtp.google.com': {
                        'ips': ['142.250.153.27'],
                        'preference': 10
                    }
                }
                result = processor.enrich_mx_records(mx_records)

        assert 'smtp.google.com' in result
        assert result['smtp.google.com']['preference'] == 10
        assert result['smtp.google.com']['ips'][0]['asn'] == 15169

    def test_extract_unique_asns(self):
        """Test extracting unique ASNs from enriched data."""
        enriched_data = {
            'a_records': [
                {'ip': '1.1.1.1', 'asn': 13335, 'prefix': '1.1.1.0/24'},
                {'ip': '1.1.1.2', 'asn': 13335, 'prefix': '1.1.1.0/24'}
            ],
            'aaaa_records': [
                {'ip': '2606:4700::', 'asn': 13335, 'prefix': '2606:4700::/32'}
            ],
            'ns_records': {
                'ns1.cloudflare.com': [
                    {'ip': '173.245.58.1', 'asn': 13335, 'prefix': '173.245.58.0/24'}
                ]
            },
            'mx_records': {
                'mail.example.com': {
                    'ips': [
                        {'ip': '1.2.3.4', 'asn': 12345, 'prefix': '1.2.0.0/16'}
                    ],
                    'preference': 10
                }
            }
        }

        mock_asndb = Mock()
        with patch('pyasn.pyasn', return_value=mock_asndb):
            with patch('os.path.isfile', return_value=True):
                processor = ASNProcessor('test.mrt')
                result = processor.extract_unique_asns(enriched_data)

        # Should find ASN 13335 (from a, aaaa, ns) and 12345 (from mx)
        assert len(result) == 2

        # Find the ASN 13335 entry
        asn_13335 = next(a for a in result if a['asn'] == 13335)
        assert set(asn_13335['sources']) == {'a', 'aaaa', 'ns'}

        # Find the ASN 12345 entry
        asn_12345 = next(a for a in result if a['asn'] == 12345)
        assert set(asn_12345['sources']) == {'mx'}

    def test_lookup_domain_asn_complete(self):
        """Test complete domain ASN lookup."""
        dns_result = {
            'domain': 'test.com',
            'a_records': ['1.2.3.4'],
            'aaaa_records': [],
            'ns_records': {},
            'mx_records': {}
        }

        mock_asndb = Mock()
        mock_asndb.lookup.return_value = (12345, '1.2.0.0/16')

        with patch('pyasn.pyasn', return_value=mock_asndb):
            with patch('os.path.isfile', return_value=True):
                processor = ASNProcessor('test.mrt')
                result = processor.lookup_domain_asn(dns_result)

        assert result['domain'] == 'test.com'
        assert len(result['a_records']) == 1
        assert result['a_records'][0]['asn'] == 12345
        assert len(result['unique_asns']) == 1
        assert result['unique_asns'][0]['asn'] == 12345

    def test_lookup_domain_asn_handles_none_values(self):
        """Test domain lookup handles None ASN values gracefully."""
        dns_result = {
            'domain': 'test.com',
            'a_records': ['192.0.2.1'],  # Reserved IP, likely no ASN
            'aaaa_records': [],
            'ns_records': {},
            'mx_records': {}
        }

        mock_asndb = Mock()
        mock_asndb.lookup.return_value = (None, None)

        with patch('pyasn.pyasn', return_value=mock_asndb):
            with patch('os.path.isfile', return_value=True):
                processor = ASNProcessor('test.mrt')
                result = processor.lookup_domain_asn(dns_result)

        assert result['domain'] == 'test.com'
        assert len(result['a_records']) == 1
        assert result['a_records'][0]['asn'] is None
        assert len(result['unique_asns']) == 0  # No valid ASNs

    @pytest.mark.requires_mrt
    def test_init_with_real_mrt_file(self):
        """Integration test with real MRT file if available."""
        mrt_file = 'sample.mrt.gz'

        if not os.path.exists(mrt_file):
            pytest.skip("Real MRT file not available for integration test")

        # This should work with the real file
        processor = ASNProcessor(mrt_file)

        # Test a known Google IP
        result = processor.lookup_ip('8.8.8.8')

        # Google's ASN is 15169
        assert result['asn'] is not None
        assert result['prefix'] is not None
