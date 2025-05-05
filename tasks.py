import logging
import os
import time
import datetime
from celery_config import celery_app
from models import Domain, ScanResult, db
from utils.security_checker import perform_security_checks

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@celery_app.task(bind=True, name='tasks.scan_domain')
def scan_domain(self, domain_name):
    """Scan a single domain and update the database with results."""
    from app import create_app
    app = create_app()
    
    logger.info(f"Starting background scan for {domain_name}")
    
    with app.app_context():
        # Check if domain exists in database
        domain = Domain.query.filter_by(name=domain_name).first()
        if not domain:
            logger.info(f"Creating new domain record for {domain_name}")
            domain = Domain(name=domain_name)
            db.session.add(domain)
            db.session.commit()
        
        # Perform security scan
        try:
            scan_start = time.time()
            scan_results = perform_security_checks(domain_name)
            scan_duration = time.time() - scan_start
            
            # Get security score and rank
            security_score = scan_results.get('security_score', 0)
            security_rank = scan_results.get('security_rank', 'E')
            
            # Get SSL expiry info if available
            ssl_expiry = None
            ssl_days_remaining = None
            if 'checks' in scan_results and 'https' in scan_results['checks']:
                https_results = scan_results['checks']['https']
                if 'details' in https_results and 'expiry_date' in https_results['details']:
                    ssl_expiry = https_results['details']['expiry_date']
                if 'details' in https_results and 'days_remaining' in https_results['details']:
                    ssl_days_remaining = https_results['details']['days_remaining']
            
            # Create or update scan result
            result = ScanResult(
                domain_id=domain.id,
                security_score=security_score,
                security_rank=security_rank,
                ssl_expiry=ssl_expiry,
                ssl_days_remaining=ssl_days_remaining,
                scan_time=datetime.datetime.utcnow()
            )
            
            # Store full JSON report
            result.set_full_report(scan_results)
            
            db.session.add(result)
            db.session.commit()
            
            logger.info(f"Completed scan for {domain_name} with score {security_score} ({security_rank}) in {scan_duration:.2f} seconds")
            return {
                'domain': domain_name,
                'status': 'success',
                'score': security_score,
                'rank': security_rank,
                'duration': f"{scan_duration:.2f} seconds"
            }
            
        except Exception as e:
            logger.error(f"Error scanning {domain_name}: {str(e)}")
            # Store error result
            error_result = ScanResult(
                domain_id=domain.id,
                security_score=0,
                security_rank='E',
                scan_time=datetime.datetime.utcnow()
            )
            
            # Create error report
            error_report = {
                'error': 'Scan Error',
                'message': str(e),
                'recommendations': ['Try scanning again later', 'Check domain name is valid'],
                'checks': {}
            }
            
            error_result.set_full_report(error_report)
            db.session.add(error_result)
            db.session.commit()
            
            return {
                'domain': domain_name,
                'status': 'error',
                'error': str(e)
            }

@celery_app.task(name='tasks.batch_scan')
def batch_scan(domain_list):
    """Queue multiple domain scans as separate tasks."""
    results = []
    # Process domains in batches to avoid overwhelming the queue
    batch_size = 10
    total_domains = len(domain_list)
    
    logger.info(f"Queuing batch scan for {total_domains} domains")
    
    for i in range(0, total_domains, batch_size):
        batch = domain_list[i:i + batch_size]
        for domain in batch:
            scan_domain.delay(domain)
            # Small delay to avoid flooding the queue
            time.sleep(0.1)
        
        logger.info(f"Queued batch {i//batch_size + 1}/{(total_domains + batch_size - 1)//batch_size} ({len(batch)} domains)")
        # Add a brief pause between batches
        time.sleep(1)
    
    return {
        'status': 'queued',
        'total_domains': total_domains,
        'message': f"All {total_domains} domains have been queued for scanning"
    }

@celery_app.task(name='tasks.scheduled_full_scan')
def scheduled_full_scan():
    """Run a scheduled full scan of all domains in the database."""
    from app import create_app
    app = create_app()
    
    with app.app_context():
        # Get all domains to scan
        all_domains = Domain.query.all()
        domain_names = [domain.name for domain in all_domains]
        
        # Update scheduled scan time in the database
        from app import update_scheduled_scan_time
        update_scheduled_scan_time()
        
        # Queue scans as a batch
        return batch_scan(domain_names)

@celery_app.task(name='tasks.sync_domains_from_file')
def sync_domains_from_file(file_path='domains.txt'):
    """Sync domains from a file and queue scans for new domains."""
    from app import create_app
    app = create_app()
    
    with app.app_context():
        try:
            # Read domains from file
            if not os.path.exists(file_path):
                return {'status': 'error', 'message': f"File not found: {file_path}"}
            
            with open(file_path, 'r') as f:
                file_domains = [line.strip() for line in f if line.strip()]
            
            # Get existing domains
            existing_domains = Domain.query.all()
            existing_names = {domain.name for domain in existing_domains}
            
            # Find new domains
            new_domains = [domain for domain in file_domains if domain not in existing_names]
            
            # Add new domains to database
            for domain_name in new_domains:
                domain = Domain(name=domain_name)
                db.session.add(domain)
            
            db.session.commit()
            
            # Queue scans for new domains
            if new_domains:
                batch_scan.delay(new_domains)
            
            return {
                'status': 'success',
                'total_domains': len(file_domains),
                'new_domains': len(new_domains),
                'message': f"Synced {len(file_domains)} domains, {len(new_domains)} new domains queued for scanning"
            }
            
        except Exception as e:
            logger.error(f"Error syncing domains from file: {str(e)}")
            return {
                'status': 'error',
                'message': f"Error syncing domains: {str(e)}"
            }