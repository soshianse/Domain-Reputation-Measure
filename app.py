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
import logging
import sys
from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, send_file, jsonify
)
from werkzeug.utils import secure_filename
from core import DomainProcessor, get_config

logger = logging.getLogger(__name__)

# Create Flask app
app = Flask(__name__)

# SECURITY: Enforce SESSION_SECRET environment variable
if not os.environ.get("SESSION_SECRET"):
    logger.critical(
        "SESSION_SECRET environment variable is not set! "
        "This is required for secure session management. "
        "Set it with: export SESSION_SECRET='your-secret-key-here'"
    )
    if not app.config.get('TESTING'):
        # Don't exit in testing mode
        sys.exit(1)
    else:
        # Use test key in testing mode only
        app.secret_key = "test_secret_key_do_not_use_in_production"
else:
    app.secret_key = os.environ.get("SESSION_SECRET")

# Configuration
UPLOAD_FOLDER = os.path.join(tempfile.gettempdir(), 'domain_asn_mapper')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS_DOMAINS = {'txt'}
ALLOWED_EXTENSIONS_MRT = {'mrt', 'gz', 'bz2'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max upload

# Security: Add security headers to all responses
@app.after_request
def add_security_headers(response):
    """Add security headers to all HTTP responses."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "img-src 'self' data:;"
    )
    return response

# Helper functions
def allowed_file(filename, allowed_extensions):
    """
    Check if uploaded file has allowed extension.

    Args:
        filename: Name of the uploaded file
        allowed_extensions: Set of allowed extensions

    Returns:
        True if file extension is allowed
    """
    if not filename or '.' not in filename:
        return False

    ext = filename.rsplit('.', 1)[1].lower()
    return ext in allowed_extensions

def sanitize_job_id(job_id):
    """
    Sanitize job ID to prevent path traversal attacks.

    Args:
        job_id: Job ID to sanitize

    Returns:
        Sanitized job ID or None if invalid
    """
    if not job_id:
        return None

    # Job IDs should be UUIDs - validate format
    try:
        uuid.UUID(job_id)
        return job_id
    except ValueError:
        logger.warning(f"Invalid job ID format: {job_id}")
        return None

def get_results_path(job_id, format_type):
    """
    Get the path to the results file.

    Args:
        job_id: Job ID (must be valid UUID)
        format_type: Output format type

    Returns:
        Path to results file
    """
    # Sanitize job_id to prevent path traversal
    safe_job_id = sanitize_job_id(job_id)
    if not safe_job_id:
        raise ValueError("Invalid job ID")

    # Whitelist allowed format types
    allowed_formats = {'json', 'csv', 'text', 'txt'}
    if format_type not in allowed_formats:
        raise ValueError(f"Invalid format type: {format_type}")

    extension = format_type
    return os.path.join(app.config['UPLOAD_FOLDER'], f"{safe_job_id}_results.{extension}")

def process_domains(domains_file, mrt_file, output_file, format_type='json', ip_version=None):
    """
    Process domains and MRT files to generate ASN mapping results.

    This function uses the unified DomainProcessor class from the core module.

    Args:
        domains_file: Path to the domains file
        mrt_file: Path to the MRT file
        output_file: Path to write output
        format_type: Output format ('json', 'csv', or 'text')
        ip_version: IP version to use (4 or 6, None for both)

    Returns:
        dict: Processing results summary
    """
    try:
        # Create processor instance
        processor = DomainProcessor(
            mrt_file=mrt_file,
            ip_version=ip_version,
            verbose=False  # Web interface doesn't need verbose logging
        )

        # Process domains using unified processor
        return processor.process_domains(
            domains_file=domains_file,
            output_file=output_file,
            format_type=format_type
        )
    except Exception as e:
        logger.error(f"Error during processing: {e}")
        return {"error": f"Failed to process domains: {str(e)}"}

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
        return redirect(url_for('index'))

    domains_file = request.files['domains_file']
    mrt_file = request.files['mrt_file']

    # If user does not select files
    if not domains_file or domains_file.filename == '':
        flash('Domains file is required', 'error')
        return redirect(url_for('index'))

    if not mrt_file or mrt_file.filename == '':
        flash('MRT file is required', 'error')
        return redirect(url_for('index'))

    # Secure the filenames
    domains_filename = secure_filename(domains_file.filename)
    mrt_filename = secure_filename(mrt_file.filename)

    # Check file extensions
    if not allowed_file(domains_filename, ALLOWED_EXTENSIONS_DOMAINS):
        flash('Domains file must be a .txt file', 'error')
        return redirect(url_for('index'))

    if not allowed_file(mrt_filename, ALLOWED_EXTENSIONS_MRT):
        flash('MRT file must be a .mrt, .gz, or .bz2 file', 'error')
        return redirect(url_for('index'))

    # Validate content length (additional check beyond Flask's MAX_CONTENT_LENGTH)
    # This helps provide better error messages
    try:
        domains_file.seek(0, 2)  # Seek to end
        domains_size = domains_file.tell()
        domains_file.seek(0)  # Seek back to start

        if domains_size == 0:
            flash('Domains file is empty', 'error')
            return redirect(url_for('index'))

        if domains_size > 10 * 1024 * 1024:  # 10MB limit for domains file
            flash('Domains file is too large (max 10MB)', 'error')
            return redirect(url_for('index'))
    except Exception as e:
        logger.error(f"Error checking domains file size: {e}")
        flash('Error processing domains file', 'error')
        return redirect(url_for('index'))
    
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

@app.route('/health')
def health_check():
    """Health check endpoint for container orchestration."""
    try:
        # Check database connectivity
        from core import get_database_manager
        db_manager = get_database_manager()
        session = db_manager.get_session()

        # Try a simple query
        from core.database import Scan
        scan_count = session.query(Scan).count()
        session.close()

        db_status = "healthy"
    except Exception as e:
        logger.warning(f"Database health check failed: {e}")
        db_status = f"unhealthy: {str(e)}"

    health = {
        "status": "healthy" if db_status == "healthy" else "degraded",
        "version": "2.0.0",
        "database": db_status,
        "upload_folder": os.path.exists(UPLOAD_FOLDER)
    }

    status_code = 200 if health["status"] == "healthy" else 503
    return jsonify(health), status_code

@app.route('/metrics')
def metrics():
    """Prometheus metrics endpoint (basic)."""
    try:
        from core import get_database_manager
        from core.database import Scan, Domain

        db_manager = get_database_manager()
        session = db_manager.get_session()

        total_scans = session.query(Scan).count()
        completed_scans = session.query(Scan).filter_by(status='completed').count()
        total_domains = session.query(Domain).count()

        session.close()

        metrics_text = f"""# HELP domain_asn_mapper_scans_total Total number of scans
# TYPE domain_asn_mapper_scans_total counter
domain_asn_mapper_scans_total {total_scans}

# HELP domain_asn_mapper_scans_completed Completed scans
# TYPE domain_asn_mapper_scans_completed counter
domain_asn_mapper_scans_completed {completed_scans}

# HELP domain_asn_mapper_domains_total Total unique domains
# TYPE domain_asn_mapper_domains_total gauge
domain_asn_mapper_domains_total {total_domains}
"""
        return metrics_text, 200, {'Content-Type': 'text/plain; charset=utf-8'}
    except Exception as e:
        logger.error(f"Error generating metrics: {e}")
        return "# Error generating metrics\n", 500, {'Content-Type': 'text/plain; charset=utf-8'}

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)