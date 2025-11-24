"""
Unit tests for main.py wrapper functions.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import sys

from main import process_domains


@pytest.mark.unit
class TestMainProcessDomains:
    """Tests for the main.py process_domains wrapper function."""

    @patch('main.DomainProcessor')
    def test_process_domains_success(self, mock_processor_cls, sample_domains_file, mock_mrt_file, output_file):
        """Test successful domain processing through main wrapper."""
        mock_processor = Mock()
        mock_processor.process_domains.return_value = {
            'success': True,
            'domains_processed': 5,
            'output_file': output_file,
            'output_format': 'json'
        }
        mock_processor_cls.return_value = mock_processor

        result = process_domains(
            sample_domains_file,
            mock_mrt_file,
            output_file,
            format_type='json',
            ip_version=None,
            verbose=False
        )

        assert result['success'] is True
        assert result['domains_processed'] == 5
        mock_processor_cls.assert_called_once_with(
            mrt_file=mock_mrt_file,
            ip_version=None,
            verbose=False
        )

    @patch('main.DomainProcessor')
    def test_process_domains_with_ipv4(self, mock_processor_cls, sample_domains_file, mock_mrt_file, output_file):
        """Test processing with IPv4 only."""
        mock_processor = Mock()
        mock_processor.process_domains.return_value = {'success': True}
        mock_processor_cls.return_value = mock_processor

        process_domains(
            sample_domains_file,
            mock_mrt_file,
            output_file,
            ip_version=4
        )

        mock_processor_cls.assert_called_once_with(
            mrt_file=mock_mrt_file,
            ip_version=4,
            verbose=False
        )

    @patch('main.DomainProcessor')
    def test_process_domains_with_ipv6(self, mock_processor_cls, sample_domains_file, mock_mrt_file, output_file):
        """Test processing with IPv6 only."""
        mock_processor = Mock()
        mock_processor.process_domains.return_value = {'success': True}
        mock_processor_cls.return_value = mock_processor

        process_domains(
            sample_domains_file,
            mock_mrt_file,
            output_file,
            ip_version=6
        )

        mock_processor_cls.assert_called_once_with(
            mrt_file=mock_mrt_file,
            ip_version=6,
            verbose=False
        )

    @patch('main.DomainProcessor')
    def test_process_domains_verbose(self, mock_processor_cls, sample_domains_file, mock_mrt_file, output_file):
        """Test processing with verbose logging."""
        mock_processor = Mock()
        mock_processor.process_domains.return_value = {'success': True}
        mock_processor_cls.return_value = mock_processor

        process_domains(
            sample_domains_file,
            mock_mrt_file,
            output_file,
            verbose=True
        )

        mock_processor_cls.assert_called_once_with(
            mrt_file=mock_mrt_file,
            ip_version=None,
            verbose=True
        )

    @patch('main.DomainProcessor')
    def test_process_domains_csv_format(self, mock_processor_cls, sample_domains_file, mock_mrt_file, tmp_path):
        """Test processing with CSV output."""
        output_file = str(tmp_path / "output.csv")
        mock_processor = Mock()
        mock_processor.process_domains.return_value = {
            'success': True,
            'output_format': 'csv'
        }
        mock_processor_cls.return_value = mock_processor

        result = process_domains(
            sample_domains_file,
            mock_mrt_file,
            output_file,
            format_type='csv'
        )

        mock_processor.process_domains.assert_called_once_with(
            domains_file=sample_domains_file,
            output_file=output_file,
            format_type='csv'
        )

    @patch('main.DomainProcessor')
    def test_process_domains_initialization_error(self, mock_processor_cls, sample_domains_file, mock_mrt_file, output_file):
        """Test error during processor initialization."""
        mock_processor_cls.side_effect = Exception("Initialization failed")

        result = process_domains(
            sample_domains_file,
            mock_mrt_file,
            output_file
        )

        assert 'error' in result
        assert 'Initialization failed' in result['error']

    @patch('main.DomainProcessor')
    def test_process_domains_processing_error(self, mock_processor_cls, sample_domains_file, mock_mrt_file, output_file):
        """Test error during domain processing."""
        mock_processor = Mock()
        mock_processor.process_domains.side_effect = Exception("Processing failed")
        mock_processor_cls.return_value = mock_processor

        result = process_domains(
            sample_domains_file,
            mock_mrt_file,
            output_file
        )

        assert 'error' in result
        assert 'Processing failed' in result['error']
