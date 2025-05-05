import os
import json
import logging
import csv
import io
import socket
import time
import sqlalchemy
from datetime import datetime, timedelta
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Configure logging to show more detailed information
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, Response, make_response
from werkzeug.utils import secure_filename
from sqlalchemy import desc, or_

from models import db, Domain, ScanResult, ScheduledScan
from utils.subdomain_scanner import get_subdomains
from utils.security_checker import perform_security_checks

# Check if Redis is available
# No longer checking Redis as we're using synchronous processing only
def is_redis_available(host='0.0.0.0', port=6379, timeout=1):
    """Always returns False as we're now using synchronous processing only"""
    return False

# Path to the domains text file
DOMAINS_FILE = 'domains.txt'

# Set this to False to disable automatic scanning on startup
AUTO_SCAN_ON_STARTUP = False

def create_app():
    """Create and configure the Flask application using factory pattern"""
    app = Flask(__name__)
    app.secret_key = os.environ.get("SESSION_SECRET", "default_secret_key")
    
    # Configure the database with SQLAlchemy
    # Use PostgreSQL if DATABASE_URL is provided, otherwise fall back to SQLite
    database_url = os.environ.get("DATABASE_URL")
    
    if database_url:
        # Using PostgreSQL
        app.config["SQLALCHEMY_DATABASE_URI"] = database_url
        logging.info("Using PostgreSQL database")
    else:
        # Fall back to SQLite
        sqlite_db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'domain_scanner.db')
        app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{sqlite_db_path}"
        logging.info("Using SQLite database")
    
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    
    # Initialize the database within the app context
    db.init_app(app)
    
    with app.app_context():
        db.create_all()
        
        # Initialize schedule if it doesn't exist
        if not ScheduledScan.query.first():
            next_scan = calculate_next_scan_time()
            initial_schedule = ScheduledScan(
                last_full_scan=None,
                next_scheduled_scan=next_scan
            )
            db.session.add(initial_schedule)
            db.session.commit()
    
    # Define utility functions used by routes
    def load_domains():
        """Load domains from the domains.txt file."""
        try:
            if not os.path.exists(DOMAINS_FILE):
                logging.debug(f"Domains file not found at {DOMAINS_FILE}")
                return []
            
            with open(DOMAINS_FILE, 'r') as f:
                domains = [line.strip() for line in f.readlines() if line.strip()]
            
            logging.debug(f"Loaded {len(domains)} domains from {DOMAINS_FILE}")
            return domains
        except Exception as e:
            logging.error(f"Error loading domains from file: {str(e)}")
            return []

    def save_domain(domain):
        """Add a domain to the domains.txt file if it doesn't exist."""
        try:
            # Make sure the domain is valid
            if not domain or '.' not in domain:
                return False
            
            # Load existing domains
            existing_domains = load_domains()
            
            # Check if domain already exists
            if domain in existing_domains:
                return False  # Already exists
            
            # Append domain to file
            with open(DOMAINS_FILE, 'a+') as f:
                f.write(f"{domain}\n")
                
            logging.debug(f"Added domain {domain} to {DOMAINS_FILE}")
            return True
        except Exception as e:
            logging.error(f"Error saving domain to file: {str(e)}")
            return False

    def check_scheduled_scan():
        """Check if it's time to run a scheduled scan"""
        try:
            schedule = ScheduledScan.query.first()
            if not schedule:
                return False
            
            if not schedule.next_scheduled_scan:
                return False
            
            now = datetime.now()
            if now >= schedule.next_scheduled_scan:
                # Update next scan time
                next_scan = calculate_next_scan_time()
                schedule.next_scheduled_scan = next_scan
                schedule.last_full_scan = now
                db.session.commit()
                
                # Get all domains and scan them directly
                try:
                    logging.info("Starting scheduled full scan")
                    domains_to_scan = [domain.name for domain in Domain.query.all()]
                    
                    # Process domains synchronously with a small delay between each
                    for domain_name in domains_to_scan:
                        try:
                            perform_scan(domain_name)
                            logging.info(f"Scheduled scan completed for {domain_name}")
                            # Add a small delay between scans to prevent overwhelming the server
                            time.sleep(0.5)
                        except Exception as scan_err:
                            logging.error(f"Error in scheduled scan for {domain_name}: {str(scan_err)}")
                            
                    return True
                except Exception as e:
                    logging.error(f"Error during scheduled scan: {str(e)}")
                    return True
                
            return False
        except Exception as e:
            logging.error(f"Error checking scheduled scan: {str(e)}")
            return False

    def perform_scan(domain_name):
        """Perform a scan and store the results in the database"""
        try:
            # Get or create domain record
            domain = Domain.query.filter_by(name=domain_name).first()
            
            if not domain:
                domain = Domain(name=domain_name)
                db.session.add(domain)
                db.session.commit()
            
            # Perform security check
            security_data = perform_security_checks(domain_name)
            
            # Extract SSL expiry info
            ssl_expiry = security_data.get('ssl_expiry', 'N/A')
            ssl_days_remaining = security_data.get('checks', {}).get('https', {}).get('details', {}).get('ssl_days_remaining', 999)
            
            # Create new scan result
            scan_result = ScanResult(
                domain_id=domain.id,
                security_score=security_data['security_score'],
                security_rank=security_data['security_rank'],
                ssl_expiry=ssl_expiry,
                ssl_days_remaining=ssl_days_remaining,
                scan_time=datetime.now()
            )
            
            # Store the full report as JSON
            scan_result.set_full_report(security_data)
            
            # Save to database
            db.session.add(scan_result)
            db.session.commit()
            
            return scan_result
        except Exception as e:
            logging.error(f"Error performing scan on {domain_name}: {str(e)}")
            return None

    # Register routes
    @app.route('/')
    def index():
        """Render the main page with the domain scan results from the database"""
        try:
            # Check if it's time for a scheduled scan
            # The check_scheduled_scan function now runs the scan synchronously
            if check_scheduled_scan():
                logging.info("Scheduled scan has been completed")
            
            # Load all domains with their latest scan results
            domains_with_results = {}
            
            # Query all domains from the database
            all_domains = Domain.query.all()
            
            # If no domains in database, import from file
            if not all_domains:
                domain_names = load_domains()
                
                # If still no domains, use fallbacks
                if not domain_names or len(domain_names) < 10:
                    # Ensure we have at least 10 domains by adding common subdomains
                    default_domains = [
                        'www.experience.com', 
                        'app.experience.com', 
                        'experience.com',
                        'api.experience.com',
                        'blog.experience.com',
                        'docs.experience.com',
                        'help.experience.com',
                        'mail.experience.com',
                        'secure.experience.com',
                        'support.experience.com',
                        'dashboard.experience.com'
                    ]
                    
                    # Add only the domains that aren't already in the list
                    for domain in default_domains:
                        if domain not in domain_names:
                            domain_names.append(domain)
                            
                    # Ensure we have at least 10 domains
                    domain_names = domain_names[:max(10, len(domain_names))]
                
                # Add domains to database
                for domain_name in domain_names:
                    try:
                        # Check if domain exists
                        domain = Domain.query.filter_by(name=domain_name).first()
                        if not domain:
                            domain = Domain(name=domain_name)
                            db.session.add(domain)
                    except Exception as e:
                        logging.error(f"Error adding domain {domain_name}: {str(e)}")
                        db.session.rollback()
                
                try:
                    db.session.commit()
                except Exception as e:
                    logging.error(f"Error committing session: {str(e)}")
                    db.session.rollback()
                
                # Re-query all domains
                all_domains = Domain.query.all()
            
            # Get the latest scan result for each domain
            for domain in all_domains:
                try:
                    latest_scan = ScanResult.query.filter_by(domain_id=domain.id).order_by(desc(ScanResult.scan_time)).first()
                    
                    if latest_scan:
                        # If we have scan results, add them
                        domains_with_results[domain.name] = {
                            'domain': domain.name,
                            'security_rank': latest_scan.security_rank,
                            'security_score': latest_scan.security_score,
                            'ssl_expiry': latest_scan.ssl_expiry,
                            'ssl_days_remaining': latest_scan.ssl_days_remaining or 999,
                            'scan_time': latest_scan.scan_time.strftime('%Y-%m-%d %H:%M:%S'),
                            'full_report': latest_scan.get_full_report()
                        }
                    elif AUTO_SCAN_ON_STARTUP:
                        # Scan new domains if auto-scan is enabled
                        try:
                            # Perform synchronous scan
                            perform_scan(domain.name)
                            logging.info(f"Auto-scan completed for {domain.name}")
                        except Exception as e:
                            logging.error(f"Error scanning domain {domain.name}: {str(e)}")
                            # No need to handle since we'll refresh the page again
                except Exception as e:
                    logging.error(f"Error processing domain {domain.name}: {str(e)}")
            
            # Get the next scheduled scan time
            try:
                schedule = ScheduledScan.query.first()
                next_scan_time = schedule.next_scheduled_scan.strftime('%Y-%m-%d %H:%M:%S') if schedule and schedule.next_scheduled_scan else "Not scheduled"
            except Exception as e:
                logging.error(f"Error getting scheduled scan: {str(e)}")
                next_scan_time = "Not available"
            
            # Get the total number of domains in domains.txt file
            total_domains_count = 0
            try:
                domains_from_file = load_domains()
                total_domains_count = len(domains_from_file)
            except Exception as e:
                logging.error(f"Error counting domains in file: {str(e)}")
            
            return render_template('index.html', 
                                domains=domains_with_results, 
                                now=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                next_scan=next_scan_time,
                                total_domains_count=total_domains_count)
        except sqlalchemy.exc.PendingRollbackError:
            # Handle transaction rollback error
            db.session.rollback()
            logging.warning("Rolling back transaction due to PendingRollbackError")
            # Return a basic template without database access
            # Try to get the total domains count even if DB connection failed
            total_domains_count = 0
            try:
                domains_from_file = load_domains()
                total_domains_count = len(domains_from_file)
            except Exception as e:
                logging.error(f"Error counting domains in file: {str(e)}")
                
            return render_template('index.html', 
                                domains={}, 
                                now=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                next_scan="Not available",
                                total_domains_count=total_domains_count,
                                error_message="Database connection error. Please try again later.")
        except Exception as e:
            # Log other exceptions and show a friendly error message
            logging.error(f"Error in index route: {str(e)}")
            db.session.rollback()
            # Try to get the total domains count even when an error occurs
            total_domains_count = 0
            try:
                domains_from_file = load_domains()
                total_domains_count = len(domains_from_file)
            except Exception as e:
                logging.error(f"Error counting domains in file: {str(e)}")
                
            return render_template('index.html', 
                                domains={}, 
                                now=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                next_scan="Not available",
                                total_domains_count=total_domains_count,
                                error_message="An error occurred. Please try again later.")
    
    @app.route('/scan', methods=['POST'])
    def scan():
        """Scan the domain and its subdomains for security issues."""
        domain = 'experience.com'  # Fixed to experience.com as per requirements
        
        try:
            logging.debug(f"Starting subdomain scan for {domain}")
            
            # Get subdomains with reduced timeout to prevent hanging
            try:
                subdomains = get_subdomains(domain)
                logging.debug(f"Found {len(subdomains)} subdomains for {domain}")
            except Exception as e:
                logging.error(f"Error finding subdomains: {str(e)}")
                # Fallback to basic subdomains if scan fails
                subdomains = ['www', 'app', domain]
                logging.debug(f"Using fallback subdomains: {subdomains}")
            
            # Limit to 5 subdomains to prevent timeouts
            domains_to_scan = []
            for subdomain in subdomains[:5]:
                full_domain = subdomain if subdomain == domain else f"{subdomain}.{domain}"
                # Save the domain to file
                save_domain(full_domain)
                domains_to_scan.append(full_domain)
            
            # Process all domains synchronously with a small delay between each
            successful_scans = 0
            for domain_name in domains_to_scan:
                try:
                    perform_scan(domain_name)
                    successful_scans += 1
                    logging.info(f"Scan completed for {domain_name} ({successful_scans}/{len(domains_to_scan)})")
                    # Add a small delay between scans to prevent overwhelming the server
                    time.sleep(0.5)
                except Exception as scan_err:
                    logging.error(f"Error scanning {domain_name}: {str(scan_err)}")
            
            flash(f"Completed scanning {successful_scans} out of {len(domains_to_scan)} domains.", "success")
            logging.info(f"Completed scanning {successful_scans} domains")
        
            return redirect(url_for('index'))
        
        except Exception as e:
            logging.error(f"Error during scan: {str(e)}")
            flash(f"Error during scan: {str(e)}", "danger")
            return redirect(url_for('index'))
    
    @app.route('/detail/<path:domain>')
    def detail(domain):
        """Show detailed security information for a specific domain."""
        try:
            # Look up the domain in the database
            domain_obj = Domain.query.filter_by(name=domain).first()
            
            if domain_obj:
                # Get the latest scan result
                latest_scan = ScanResult.query.filter_by(domain_id=domain_obj.id).order_by(desc(ScanResult.scan_time)).first()
                
                if latest_scan:
                    # Prepare data in the same format as before
                    try:
                        full_report = latest_scan.get_full_report()
                        data = {
                            'domain': domain,
                            'security_rank': latest_scan.security_rank,
                            'security_score': latest_scan.security_score,
                            'ssl_expiry': latest_scan.ssl_expiry,
                            'ssl_days_remaining': latest_scan.ssl_days_remaining or 999,
                            'scan_time': latest_scan.scan_time.strftime('%Y-%m-%d %H:%M:%S'),
                            'full_report': full_report,
                            'is_error': False
                        }
                        return render_template('detail.html', domain=domain, data=data)
                    except Exception as report_error:
                        logging.error(f"Error parsing report data for {domain}: {str(report_error)}")
                        # If there's an error parsing the report, show the error page
                        raise
            
            # If we reach here, either domain not found or no scan results
            # Create an empty data placeholder with helpful information
            data = {
                'domain': domain,
                'security_rank': 'N/A',
                'security_score': 0,
                'ssl_expiry': 'Unknown',
                'ssl_days_remaining': 0,
                'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'full_report': {
                    'error': 'Scan could not be performed',
                    'message': f'The domain {domain} could not be scanned or may not be active.',
                    'recommendations': ['Verify that the domain is active and accessible',
                                        'Try rescanning the domain manually',
                                        'Check your network connection']
                },
                'is_error': True
            }
            
            # Return the detail page with the error information instead of redirecting
            return render_template('detail.html', domain=domain, data=data)
            
        except Exception as e:
            # Log the error
            logging.error(f"Error accessing details for domain {domain}: {str(e)}")
            flash(f"Error accessing domain details: The domain '{domain}' appears to be inactive or cannot be scanned.", "warning")
            return redirect(url_for('index'))
    
    @app.route('/api/domains')
    def api_domains():
        """API endpoint to get all domain scan results."""
        domains_data = {}
        
        # Query all domains
        domains = Domain.query.all()
        
        for domain in domains:
            # Get the latest scan for each domain
            latest_scan = ScanResult.query.filter_by(domain_id=domain.id).order_by(desc(ScanResult.scan_time)).first()
            
            if latest_scan:
                domains_data[domain.name] = {
                    'domain': domain.name,
                    'security_rank': latest_scan.security_rank,
                    'security_score': latest_scan.security_score,
                    'ssl_expiry': latest_scan.ssl_expiry,
                    'ssl_days_remaining': latest_scan.ssl_days_remaining or 999,
                    'scan_time': latest_scan.scan_time.strftime('%Y-%m-%d %H:%M:%S')
                }
        
        return jsonify(domains_data)
    
    @app.route('/api/domain/<path:domain>')
    def api_domain_detail(domain):
        """API endpoint to get detailed information for a specific domain."""
        try:
            # Look up the domain in the database
            domain_obj = Domain.query.filter_by(name=domain).first()
            
            if domain_obj:
                # Get the latest scan result
                latest_scan = ScanResult.query.filter_by(domain_id=domain_obj.id).order_by(desc(ScanResult.scan_time)).first()
                
                if latest_scan:
                    try:
                        # Prepare data
                        full_report = latest_scan.get_full_report()
                        data = {
                            'domain': domain,
                            'security_rank': latest_scan.security_rank,
                            'security_score': latest_scan.security_score,
                            'ssl_expiry': latest_scan.ssl_expiry,
                            'ssl_days_remaining': latest_scan.ssl_days_remaining or 999,
                            'scan_time': latest_scan.scan_time.strftime('%Y-%m-%d %H:%M:%S'),
                            'full_report': full_report,
                            'is_error': False
                        }
                        return jsonify(data)
                    except Exception as e:
                        logging.error(f"Error parsing report data for API detail {domain}: {str(e)}")
                        return jsonify({
                            'domain': domain,
                            'error': 'Error parsing scan data',
                            'message': 'Please try rescanning the domain',
                            'is_error': True
                        }), 500
            
            return jsonify({'error': 'Domain not found', 'is_error': True}), 404
        except Exception as e:
            logging.error(f"API error getting domain details for {domain}: {str(e)}")
            return jsonify({'error': str(e), 'is_error': True}), 500
    
    @app.route('/export/csv')
    def export_csv():
        """Export all scan results as CSV."""
        # Create a StringIO object to hold the CSV data
        csv_data = io.StringIO()
        csv_writer = csv.writer(csv_data)
        
        # Write the header row
        csv_writer.writerow([
            'Domain', 
            'Security Rank', 
            'Security Score', 
            'SSL Expiry', 
            'SSL Days Remaining',
            'Scan Time'
        ])
        
        # Query all domains and their latest scan results
        domains = Domain.query.all()
        
        for domain in domains:
            # Get the latest scan for each domain
            latest_scan = ScanResult.query.filter_by(domain_id=domain.id).order_by(desc(ScanResult.scan_time)).first()
            
            if latest_scan:
                # If SSL expiry is N/A or None, make sure SSL Days Remaining is also N/A
                ssl_days = 'N/A'
                if latest_scan.ssl_expiry and latest_scan.ssl_expiry != 'N/A':
                    ssl_days = latest_scan.ssl_days_remaining or 'N/A'
                
                csv_writer.writerow([
                    domain.name,
                    latest_scan.security_rank,
                    latest_scan.security_score,
                    latest_scan.ssl_expiry or 'N/A',
                    ssl_days,
                    latest_scan.scan_time.strftime('%Y-%m-%d %H:%M:%S')
                ])
        
        # Prepare the response
        output = csv_data.getvalue()
        csv_data.close()
        
        response = Response(
            output,
            mimetype='text/csv',
            headers={"Content-Disposition": "attachment;filename=domain_security_scan.csv"}
        )
        
        return response
    
    @app.route('/export/report/<domain>')
    def export_full_report(domain):
        """Export the full security report for a specific domain as JSON."""
        try:
            # Get the domain from the database
            domain_obj = Domain.query.filter_by(name=domain).first_or_404()
            
            # Get the latest scan result for this domain
            result = ScanResult.query.filter_by(domain_id=domain_obj.id).order_by(ScanResult.scan_time.desc()).first_or_404()
            
            try:
                # Get the full report data
                full_report = result.get_full_report()
                
                # Check if we got error in report
                if 'error' in full_report and not full_report.get('checks'):
                    # There was an error in the report, show a user-friendly message
                    flash(f"Error exporting report: {full_report.get('message', 'Invalid report data')}", "warning")
                    return redirect(url_for('detail', domain=domain))
                
                # Create a response with the JSON data
                response = make_response(json.dumps(full_report, indent=4))
                response.headers['Content-Type'] = 'application/json'
                response.headers['Content-Disposition'] = f'attachment; filename={domain}_security_report.json'
                
                return response
            except json.JSONDecodeError as json_err:
                app.logger.error(f"JSON decode error exporting report for {domain}: {str(json_err)}")
                flash(f"Error exporting report: The report contains invalid data. Try rescanning the domain.", "danger")
                return redirect(url_for('detail', domain=domain))
                
        except Exception as e:
            app.logger.error(f"Error exporting report for {domain}: {str(e)}")
            flash(f"Error exporting report: {str(e)}", "danger")
            return redirect(url_for('detail', domain=domain))
    
    @app.route('/scan_custom', methods=['POST'])
    def scan_custom():
        """Scan a custom subdomain using synchronous processing."""
        subdomain = request.form.get('subdomain', '').strip()
        domain = 'experience.com'
        
        if not subdomain:
            return redirect(url_for('index'))
        
        try:
            # Format the full domain
            full_domain = f"{subdomain}.{domain}"
            logging.debug(f"Scanning custom subdomain: {full_domain}")
            
            # Save to domains file
            save_domain(full_domain)
            
            # Scan the domain directly
            try:
                perform_scan(full_domain)
                flash(f"Scan for {full_domain} has been completed successfully.", "success")
                logging.info(f"Scanned domain {full_domain}")
            except Exception as e:
                logging.error(f"Error scanning {full_domain}: {str(e)}")
                flash(f"Error scanning domain: {str(e)}", "danger")
            
        except Exception as e:
            logging.error(f"Error scanning custom subdomain {subdomain}: {str(e)}")
            flash(f"Error scanning {subdomain}: {str(e)}", "danger")
        
        return redirect(url_for('index'))
    
    @app.route('/upload_subdomains', methods=['POST'])
    def upload_subdomains():
        """Process an uploaded file of subdomains using synchronous processing."""
        if 'subdomainFile' not in request.files:
            return redirect(url_for('index'))
        
        file = request.files['subdomainFile']
        
        if file.filename == '':
            return redirect(url_for('index'))
        
        if file:
            try:
                # Read file contents
                content = file.read().decode('utf-8')
                
                # Split by newline and filter empty lines
                subdomains = [line.strip() for line in content.split('\n') if line.strip()]
                
                domain = 'experience.com'
                logging.debug(f"Processing {len(subdomains)} custom subdomains from file")
                
                # Create full domain names
                domains_to_scan = []
                for subdomain in subdomains:
                    if subdomain:
                        full_domain = f"{subdomain}.{domain}"
                        # Save to domains file
                        save_domain(full_domain)
                        domains_to_scan.append(full_domain)
                
                # Process all domains synchronously
                if domains_to_scan:
                    flash(f"Processing {len(domains_to_scan)} domains from file. This may take some time.", "info")
                    
                    # Counter for successful scans
                    successful_scans = 0
                    
                    # Process all domains with a small delay between each
                    for domain_name in domains_to_scan:
                        try:
                            perform_scan(domain_name)
                            successful_scans += 1
                            logging.info(f"Scan completed for {domain_name} ({successful_scans}/{len(domains_to_scan)})")
                            
                            # Add a small delay between scans to prevent overwhelming the server
                            time.sleep(0.5)
                        except Exception as scan_err:
                            logging.error(f"Error scanning {domain_name}: {str(scan_err)}")
                    
                    # Show results
                    flash(f"Completed scanning {successful_scans} out of {len(domains_to_scan)} domains from file.", "success")
                
            except Exception as e:
                logging.error(f"Error processing file: {str(e)}")
                flash(f"Error processing file: {str(e)}", "danger")
        
        return redirect(url_for('index'))
    
    @app.route('/rescan_domain', methods=['POST'])
    def rescan_domain():
        """Rescan a specific domain using synchronous processing."""
        domain_to_rescan = request.form.get('domain', '').strip()
        
        if not domain_to_rescan:
            return redirect(url_for('index'))
        
        try:
            # Scan the domain directly
            logging.debug(f"Rescanning domain: {domain_to_rescan}")
            
            try:
                perform_scan(domain_to_rescan)
                flash(f"Rescan for {domain_to_rescan} has been completed successfully.", "success")
                logging.info(f"Rescanned domain {domain_to_rescan}")
            except Exception as e:
                logging.error(f"Error rescanning {domain_to_rescan}: {str(e)}")
                flash(f"Error scanning domain: {str(e)}", "danger")
        except Exception as e:
            logging.error(f"Error rescanning domain {domain_to_rescan}: {str(e)}")
            flash(f"Error rescanning domain: {str(e)}", "danger")
        
        return redirect(url_for('index'))
    
    @app.route('/documentation')
    def documentation():
        """Display the documentation page with information about the application."""
        return render_template('documentation.html')
        
    @app.route('/macos_setup')
    def macos_setup():
        """Display the macOS setup guide."""
        return render_template('macos_setup.html')
        
    @app.route('/linux_setup')
    def linux_setup():
        """Display the Linux setup guide."""
        return render_template('linux_setup.html')
        
    @app.route('/remove_domain', methods=['POST'])
    def remove_domain():
        """Remove a domain and its scan results."""
        domain_to_remove = request.form.get('domain', '').strip()
        
        if not domain_to_remove:
            flash("No domain specified for removal", "warning")
            return redirect(url_for('index'))
        
        try:
            # Find the domain in the database
            domain_obj = Domain.query.filter_by(name=domain_to_remove).first()
            
            if domain_obj:
                # Delete all scan results associated with this domain
                ScanResult.query.filter_by(domain_id=domain_obj.id).delete()
                
                # Delete the domain from the database
                db.session.delete(domain_obj)
                db.session.commit()
                
                # Also remove from domains.txt file
                try:
                    # Read current domains
                    with open(DOMAINS_FILE, 'r') as f:
                        domains = [line.strip() for line in f.readlines()]
                    
                    # Filter out the domain to remove
                    domains = [d for d in domains if d != domain_to_remove]
                    
                    # Write back to file
                    with open(DOMAINS_FILE, 'w') as f:
                        f.write('\n'.join(domains) + '\n' if domains else '')
                    
                    flash(f"Domain '{domain_to_remove}' and all its scan results have been removed successfully.", "success")
                except Exception as file_err:
                    logging.error(f"Error removing domain from file: {str(file_err)}")
                    flash(f"Domain removed from database but could not be removed from domains.txt file: {str(file_err)}", "warning")
            else:
                flash(f"Domain '{domain_to_remove}' not found in database.", "warning")
                
                # Still try to remove from domains.txt
                try:
                    # Read current domains
                    with open(DOMAINS_FILE, 'r') as f:
                        domains = [line.strip() for line in f.readlines()]
                    
                    if domain_to_remove in domains:
                        # Filter out the domain to remove
                        domains = [d for d in domains if d != domain_to_remove]
                        
                        # Write back to file
                        with open(DOMAINS_FILE, 'w') as f:
                            f.write('\n'.join(domains) + '\n' if domains else '')
                        
                        flash(f"Domain '{domain_to_remove}' removed from domains.txt file.", "success")
                    else:
                        flash(f"Domain '{domain_to_remove}' not found in domains.txt file.", "warning")
                except Exception as file_err:
                    logging.error(f"Error removing domain from file: {str(file_err)}")
                    flash(f"Error removing domain from domains.txt file: {str(file_err)}", "warning")
            
        except Exception as e:
            logging.error(f"Error removing domain {domain_to_remove}: {str(e)}")
            flash(f"Error removing domain: {str(e)}", "danger")
            db.session.rollback()
        
        return redirect(url_for('index'))
        
    @app.route('/edit_domains')
    def edit_domains():
        """Show a form to edit the domains.txt file."""
        try:
            # Read the current content of the domains.txt file
            with open(DOMAINS_FILE, 'r') as f:
                domains_content = f.read()
            
            return render_template('edit_domains.html', domains_content=domains_content)
        except Exception as e:
            logging.error(f"Error reading domains file: {str(e)}")
            flash(f"Error reading domains file: {str(e)}", "danger")
            return redirect(url_for('index'))
    
    @app.route('/save_domains_file', methods=['POST'])
    def save_domains_file():
        """Save the edited content of the domains.txt file."""
        try:
            # Get the content from the form
            domains_content = request.form.get('domains_content', '')
            
            # Write the content to the domains.txt file
            with open(DOMAINS_FILE, 'w') as f:
                f.write(domains_content)
            
            flash("Domains file has been updated successfully. Click 'Sync Domains' to scan new domains.", "success")
            return redirect(url_for('index'))
        except Exception as e:
            logging.error(f"Error saving domains file: {str(e)}")
            flash(f"Error saving domains file: {str(e)}", "danger")
            return redirect(url_for('edit_domains'))
    
    @app.route('/sync_domains', methods=['POST'])
    def sync_domains():
        """Sync domains from the domains.txt file and scan them using synchronous processing."""
        try:
            # Load domains from file
            domains_from_file = load_domains()
            
            if not domains_from_file:
                flash("No domains found in domains.txt file.", "warning")
                return redirect(url_for('index'))
                
            # Get all domains currently in the database
            domains_in_db = Domain.query.all()
            current_domains = [domain.name for domain in domains_in_db]
            
            # Find domains that are in the file but not in the database (domains to add)
            new_domains = list(set(domains_from_file) - set(current_domains))
            
            # Find domains that are in the database but not in the file (domains to remove)
            domains_to_remove = list(set(current_domains) - set(domains_from_file))
            
            changes_made = False
            
            # Add new domains to the database (without scanning immediately)
            for domain_name in new_domains:
                try:
                    # Add domain to database
                    domain = Domain(name=domain_name)
                    db.session.add(domain)
                    changes_made = True
                except Exception as e:
                    logging.error(f"Error adding domain {domain_name}: {str(e)}")
            
            # Remove domains that are no longer in the file
            for domain_name in domains_to_remove:
                try:
                    # Find domain in database
                    domain = Domain.query.filter_by(name=domain_name).first()
                    if domain:
                        logging.debug(f"Removing domain {domain_name} from database")
                        db.session.delete(domain)
                        changes_made = True
                except Exception as e:
                    logging.error(f"Error removing domain {domain_name}: {str(e)}")
            
            # Commit all database changes at once
            db.session.commit()
            
            # Process new domains synchronously
            if new_domains:
                total_domains = len(new_domains)
                if total_domains:
                    flash(f"Processing all {total_domains} new domains. This may take some time.", "info")
                    
                    # Counter for successful scans
                    successful_scans = 0
                    
                    # Process all domains with a small delay between each
                    for domain_name in new_domains:
                        try:
                            perform_scan(domain_name)
                            successful_scans += 1
                            logging.info(f"Scan completed for {domain_name} ({successful_scans}/{total_domains})")
                            
                            # Add a small delay between scans to prevent overwhelming the server
                            time.sleep(0.5)
                        except Exception as scan_err:
                            logging.error(f"Error scanning {domain_name}: {str(scan_err)}")
                    
                    # Show results
                    flash(f"Completed scanning {successful_scans} out of {total_domains} domains.", "success")
            
            if changes_made:
                if new_domains and domains_to_remove:
                    flash(f"Successfully synced domains.txt: Added {len(new_domains)} new domains and removed {len(domains_to_remove)} domains.", "success")
                elif new_domains:
                    flash(f"Successfully added {len(new_domains)} new domains from domains.txt file.", "success")
                elif domains_to_remove:
                    flash(f"Successfully removed {len(domains_to_remove)} domains that were no longer in domains.txt file.", "success")
            else:
                flash("No changes needed. Database already in sync with domains.txt file.", "info")
                
        except Exception as e:
            logging.error(f"Error in sync_domains: {str(e)}")
            flash(f"Error syncing domains: {str(e)}", "danger")
        
        return redirect(url_for('index'))
    
    @app.route('/scan_all', methods=['POST'])
    def scan_all():
        """Rescan all domains in the database using synchronous processing."""
        # Get all domains from the database
        domains_to_scan = [domain.name for domain in Domain.query.all()]
        
        # If no domains found in database, load from file
        if not domains_to_scan:
            domains_to_scan = load_domains()
            
            # If still no domains, redirect to standard scan
            if not domains_to_scan:
                flash("No domains found to scan. Please add some domains first.", "warning")
                return redirect(url_for('scan'))
        
        try:
            # Update the last full scan time
            schedule = ScheduledScan.query.first()
            if schedule:
                schedule.last_full_scan = datetime.now()
                schedule.next_scheduled_scan = calculate_next_scan_time()
                db.session.commit()
            
            # Process domains synchronously
            total_domains = len(domains_to_scan)
            flash(f"Processing all {total_domains} domains. This may take some time.", "info")
            
            # Counter for successful scans
            successful_scans = 0
            
            # Process all domains with a small delay between each
            for domain_name in domains_to_scan:
                try:
                    perform_scan(domain_name)
                    successful_scans += 1
                    logging.info(f"Scan completed for {domain_name} ({successful_scans}/{total_domains})")
                    
                    # Add a small delay between scans to prevent overwhelming the server
                    time.sleep(0.5)
                except Exception as scan_err:
                    logging.error(f"Error in scan for {domain_name}: {str(scan_err)}")
            
            # Show results
            flash(f"Completed scanning {successful_scans} out of {total_domains} domains.", "success")
        
        except Exception as e:
            logging.error(f"Error in scan_all: {str(e)}")
            flash(f"Error during scan operation: {str(e)}", "danger")
        
        return redirect(url_for('index'))
    
    return app

def calculate_next_scan_time():
    """Calculate the next scan time (6am, 12pm, 6pm, or 12am)"""
    now = datetime.now()
    hour = now.hour
    
    if hour < 6:
        next_hour = 6
    elif hour < 12:
        next_hour = 12
    elif hour < 18:
        next_hour = 18
    else:
        # Set for 6am tomorrow
        next_hour = 6
        now += timedelta(days=1)
    
    next_scan_time = now.replace(hour=next_hour, minute=0, second=0, microsecond=0)
    return next_scan_time

def update_scheduled_scan_time():
    """Update the scheduled scan time in the database"""
    from models import ScheduledScan, db
    
    schedule = ScheduledScan.query.first()
    if not schedule:
        schedule = ScheduledScan()
        db.session.add(schedule)
    
    schedule.last_full_scan = datetime.now()
    schedule.next_scheduled_scan = calculate_next_scan_time()
    db.session.commit()
    
    return schedule.next_scheduled_scan

if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=5000, debug=True)