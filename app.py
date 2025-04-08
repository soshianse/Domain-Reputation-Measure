#!/usr/bin/env python3
"""
Domain ASN Mapper - Web Application

This application provides a web interface for the Domain ASN Mapper,
allowing users to upload domain lists and MRT files, run the processing,
and view the results.
"""

import os
import uuid
import json
import tempfile
from flask import (
    Flask, render_template, request, redirect, url_for, 
    flash, session, send_file, jsonify
)
from werkzeug.utils import secure_filename
from dns_processor import DNSProcessor
from asn_processor import ASNProcessor
from output_formatter import OutputFormatter

# Create Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "default_secret_key")

# Configuration
UPLOAD_FOLDER = os.path.join(tempfile.gettempdir(), 'domain_asn_mapper')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS_DOMAINS = {'txt'}
ALLOWED_EXTENSIONS_MRT = {'mrt', 'gz', 'bz2'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max upload

# Helper functions
def allowed_file(filename, allowed_extensions):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

def get_results_path(job_id, format_type):
    """Get the path to the results file."""
    extension = format_type
    return os.path.join(app.config['UPLOAD_FOLDER'], f"{job_id}_results.{extension}")

def process_domains(domains_file, mrt_file, output_file, format_type='json', ip_version=None):
    """
    Process domains and MRT files to generate ASN mapping results.
    This function encapsulates the core logic from main.py's main function.
    """
    # Initialize processors
    asn_processor = ASNProcessor(mrt_file)
    dns_processor = DNSProcessor(ip_version=ip_version)
    
    # Read domains from file
    with open(domains_file, 'r') as file:
        # Strip whitespace and skip empty lines
        domains = [line.strip() for line in file if line.strip()]
    
    if not domains:
        return {"error": "No domains found in the input file."}
    
    # Process domains
    results = []
    total_domains = len(domains)
    
    for i, domain in enumerate(domains):
        try:
            # Resolve DNS records
            dns_result = dns_processor.resolve_domain(domain)
            
            # Match with ASN data
            asn_result = asn_processor.lookup_domain_asn(dns_result)
            
            # Add to results
            results.append(asn_result)
        except Exception as e:
            # Add error entry
            results.append({
                'domain': domain,
                'error': str(e)
            })
    
    # Format and write output
    formatter = OutputFormatter(format_type)
    formatter.write_output(results, output_file)
    
    return {"success": True, "total_processed": total_domains}

# Routes
@app.route('/')
def index():
    """Render the home page."""
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_files():
    """Handle file uploads and start processing."""
    # Check if files are in request
    if 'domains_file' not in request.files or 'mrt_file' not in request.files:
        flash('Both domains file and MRT file are required', 'error')
        return redirect(request.url)
    
    domains_file = request.files['domains_file']
    mrt_file = request.files['mrt_file']
    
    # If user does not select files
    if domains_file.filename == '' or mrt_file.filename == '':
        flash('Both domains file and MRT file are required', 'error')
        return redirect(request.url)
    
    # Check file extensions
    if not allowed_file(domains_file.filename, ALLOWED_EXTENSIONS_DOMAINS):
        flash('Domains file must be a .txt file', 'error')
        return redirect(request.url)
    
    if not allowed_file(mrt_file.filename, ALLOWED_EXTENSIONS_MRT):
        flash('MRT file must be a .mrt, .gz, or .bz2 file', 'error')
        return redirect(request.url)
    
    # Generate a job ID
    job_id = str(uuid.uuid4())
    
    # Get format and IP version options
    format_type = request.form.get('format_type', 'json')
    ip_version = None
    if request.form.get('ipv4_only'):
        ip_version = 4
    elif request.form.get('ipv6_only'):
        ip_version = 6
    
    # Save uploaded files
    domains_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{job_id}_domains.txt")
    mrt_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{job_id}_mrt_file.{mrt_file.filename.split('.')[-1]}")
    
    domains_file.save(domains_path)
    mrt_file.save(mrt_path)
    
    # Set output path
    output_path = get_results_path(job_id, format_type)
    
    # Store job info in session
    session['job_id'] = job_id
    session['format_type'] = format_type
    
    try:
        # Process the files
        result = process_domains(
            domains_path, 
            mrt_path, 
            output_path, 
            format_type=format_type,
            ip_version=ip_version
        )
        
        if 'error' in result:
            flash(f"Error: {result['error']}", 'error')
            return redirect(url_for('index'))
        
        # Redirect to results page
        return redirect(url_for('show_results', job_id=job_id))
    
    except Exception as e:
        flash(f"Error processing files: {str(e)}", 'error')
        return redirect(url_for('index'))

@app.route('/results/<job_id>')
def show_results(job_id):
    """Show processing results."""
    format_type = session.get('format_type', 'json')
    results_path = get_results_path(job_id, format_type)
    
    if not os.path.exists(results_path):
        flash('Results not found. Please try again.', 'error')
        return redirect(url_for('index'))
    
    # For JSON results, load and display them nicely in the template
    if format_type == 'json':
        try:
            with open(results_path, 'r') as f:
                results = json.load(f)
                return render_template('results.html', results=results, job_id=job_id, format_type=format_type)
        except Exception as e:
            flash(f"Error loading results: {str(e)}", 'error')
            return redirect(url_for('index'))
    
    # For other formats, provide a download link
    return render_template('results.html', job_id=job_id, format_type=format_type)

@app.route('/download/<job_id>')
def download_results(job_id):
    """Download the results file."""
    format_type = request.args.get('format', session.get('format_type', 'json'))
    results_path = get_results_path(job_id, format_type)
    
    if not os.path.exists(results_path):
        flash('Results file not found', 'error')
        return redirect(url_for('index'))
    
    return send_file(
        results_path,
        as_attachment=True,
        download_name=f"domain_asn_mapping_results.{format_type}"
    )

@app.route('/api/results/<job_id>')
def api_results(job_id):
    """API endpoint to get results in JSON format."""
    results_path = get_results_path(job_id, 'json')
    
    if not os.path.exists(results_path):
        return jsonify({"error": "Results not found"}), 404
    
    try:
        with open(results_path, 'r') as f:
            results = json.load(f)
            return jsonify(results)
    except Exception as e:
        return jsonify({"error": f"Error loading results: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)