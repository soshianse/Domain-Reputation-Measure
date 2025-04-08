# Domain ASN Mapper

A tool for mapping domains to Autonomous System Numbers (ASNs) by resolving DNS records and matching them to MRT data.

## Features

- Resolves A records (IPv4) and AAAA records (IPv6) for domains
- Resolves NS (nameserver) records and their IP addresses
- Resolves MX (mail server) records and their IP addresses
- Maps each IP address to corresponding ASN information from MRT files
- Supports multiple output formats (JSON, CSV, text)
- Available as both a command-line tool and a web application

## Usage

### Web Interface

The easiest way to use Domain ASN Mapper is through its web interface:

1. Start the web server:
   ```
   python main.py --web
   ```

2. Open your browser and navigate to `http://localhost:5000`

3. Upload a domains list file (one domain per line) and an MRT file

4. Select your preferred output format and IP version options

5. Click "Process Files" to start the mapping process

6. View and download the results

### Command Line

You can also use Domain ASN Mapper directly from the command line:

```
python main.py -d domains.txt -m mrt_file.mrt -o results.json -f json
```

#### Command Line Options

- `-d, --domains`: Path to the file containing domains (one per line)
- `-m, --mrt-file`: Path to the MRT file containing ASN information
- `-o, --output`: Path to the output file (default: results.json)
- `-f, --format`: Output format (json, csv, or text, default: json)
- `-v, --verbose`: Enable verbose output
- `--ipv4-only`: Only resolve IPv4 addresses
- `--ipv6-only`: Only resolve IPv6 addresses
- `--web`: Start the web application server

## Input File Format

The domains file should be a plain text file with one domain per line:

```
example.com
google.com
github.com
replit.com
```

## Output Formats

The tool supports three output formats:

- **JSON**: Detailed structured output with all resolved information
- **CSV**: Tabular format suitable for spreadsheet applications
- **Text**: Human-readable text format

## Requirements

- Python 3.6+
- dnspython
- pyasn
- flask (for web interface)

## Installation

1. Clone this repository
2. Install the required dependencies:
   ```
   pip install dnspython pyasn flask
   ```

## License

MIT License