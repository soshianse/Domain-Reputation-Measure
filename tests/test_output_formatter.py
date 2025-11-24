"""
Unit tests for OutputFormatter class.
"""

import pytest
import json
import csv
import os

from output_formatter import OutputFormatter


@pytest.mark.unit
class TestOutputFormatter:
    """Tests for OutputFormatter class."""

    def test_init_json_format(self):
        """Test initialization with JSON format."""
        formatter = OutputFormatter('json')
        assert formatter.format_type == 'json'

    def test_init_csv_format(self):
        """Test initialization with CSV format."""
        formatter = OutputFormatter('csv')
        assert formatter.format_type == 'csv'

    def test_init_text_format(self):
        """Test initialization with text format."""
        formatter = OutputFormatter('text')
        assert formatter.format_type == 'text'

    def test_format_json(self, sample_asn_result):
        """Test JSON formatting."""
        formatter = OutputFormatter('json')
        result = formatter.format_json([sample_asn_result])

        # Should be valid JSON
        parsed = json.loads(result)
        assert len(parsed) == 1
        assert parsed[0]['domain'] == 'google.com'

    def test_format_json_multiple_domains(self):
        """Test JSON formatting with multiple domains."""
        data = [
            {'domain': 'test1.com', 'a_records': []},
            {'domain': 'test2.com', 'a_records': []}
        ]

        formatter = OutputFormatter('json')
        result = formatter.format_json(data)

        parsed = json.loads(result)
        assert len(parsed) == 2

    def test_format_json_with_error(self):
        """Test JSON formatting with error entries."""
        data = [
            {'domain': 'test.com', 'error': 'DNS resolution failed'}
        ]

        formatter = OutputFormatter('json')
        result = formatter.format_json(data)

        parsed = json.loads(result)
        assert parsed[0]['domain'] == 'test.com'
        assert 'error' in parsed[0]

    def test_format_csv(self, sample_asn_result):
        """Test CSV formatting."""
        formatter = OutputFormatter('csv')
        result = formatter.format_csv([sample_asn_result])

        # Check for CSV header
        assert 'domain' in result
        assert 'google.com' in result

    def test_format_text(self, sample_asn_result):
        """Test text formatting."""
        formatter = OutputFormatter('text')
        result = formatter.format_text([sample_asn_result])

        assert 'google.com' in result
        assert 'A Records' in result or 'IPv4' in result
        assert 'ASN' in result

    def test_write_output_json(self, sample_asn_result, tmp_path):
        """Test writing JSON output to file."""
        output_file = tmp_path / "test.json"
        formatter = OutputFormatter('json')
        formatter.write_output([sample_asn_result], str(output_file))

        assert output_file.exists()

        with open(output_file) as f:
            data = json.load(f)

        assert len(data) == 1
        assert data[0]['domain'] == 'google.com'

    def test_write_output_csv(self, sample_asn_result, tmp_path):
        """Test writing CSV output to file."""
        output_file = tmp_path / "test.csv"
        formatter = OutputFormatter('csv')

        # Simplify the sample result for CSV
        simple_result = {
            'domain': 'google.com',
            'a_records': [{'ip': '1.2.3.4', 'asn': 15169, 'prefix': '1.2.0.0/16'}],
            'aaaa_records': [],
            'ns_records': {},
            'mx_records': {},
            'unique_asns': [{'asn': 15169, 'sources': ['a']}]
        }

        formatter.write_output([simple_result], str(output_file))

        assert output_file.exists()

        # Verify CSV can be read
        with open(output_file) as f:
            reader = csv.reader(f)
            rows = list(reader)

        assert len(rows) >= 2  # Header + at least one data row
        assert 'domain' in rows[0]

    def test_write_output_text(self, sample_asn_result, tmp_path):
        """Test writing text output to file."""
        output_file = tmp_path / "test.txt"
        formatter = OutputFormatter('text')
        formatter.write_output([sample_asn_result], str(output_file))

        assert output_file.exists()

        with open(output_file) as f:
            content = f.read()

        assert 'google.com' in content

    def test_write_output_creates_directories(self, sample_asn_result, tmp_path):
        """Test that write_output creates parent directories if needed."""
        output_file = tmp_path / "subdir" / "nested" / "test.json"
        formatter = OutputFormatter('json')
        formatter.write_output([sample_asn_result], str(output_file))

        assert output_file.exists()
        assert output_file.parent.exists()

    def test_format_empty_results(self):
        """Test formatting with empty results list."""
        formatter = OutputFormatter('json')
        result = formatter.format_json([])

        parsed = json.loads(result)
        assert parsed == []

    def test_write_output_invalid_format(self, tmp_path):
        """Test with invalid format type."""
        output_file = tmp_path / "test.invalid"

        # OutputFormatter should handle this gracefully or raise appropriate error
        with pytest.raises(Exception):
            formatter = OutputFormatter('invalid_format')
            formatter.write_output([], str(output_file))


@pytest.mark.integration
class TestOutputFormatterIntegration:
    """Integration tests for OutputFormatter."""

    def test_full_workflow_all_formats(self, sample_asn_result, tmp_path):
        """Test complete workflow with all formats."""
        data = [sample_asn_result]

        for format_type in ['json', 'csv', 'text']:
            output_file = tmp_path / f"output.{format_type}"
            formatter = OutputFormatter(format_type)
            formatter.write_output(data, str(output_file))

            assert output_file.exists()
            assert output_file.stat().st_size > 0

    def test_large_dataset(self, tmp_path):
        """Test with large dataset."""
        # Create 1000 domains
        data = [
            {
                'domain': f'test{i}.com',
                'a_records': [{'ip': f'1.2.{i % 256}.{i % 256}', 'asn': 12345, 'prefix': '1.2.0.0/16'}],
                'aaaa_records': [],
                'ns_records': {},
                'mx_records': {},
                'unique_asns': [{'asn': 12345, 'sources': ['a']}]
            }
            for i in range(1000)
        ]

        output_file = tmp_path / "large.json"
        formatter = OutputFormatter('json')
        formatter.write_output(data, str(output_file))

        assert output_file.exists()

        with open(output_file) as f:
            loaded = json.load(f)

        assert len(loaded) == 1000
