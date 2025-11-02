"""
API routes for scanner web application
"""

from flask import Blueprint, request, jsonify
from scanner.database.models import db, Scan, Vulnerability, Request, Response, Endpoint, ScanHistory
from scanner.scanner.engine import ScanEngine
from scanner.crawler.spider import WebSpider
from scanner.core.config import Config
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

api_bp = Blueprint('api', __name__)


# Scan endpoints
@api_bp.route('/scans', methods=['GET'])
def get_scans():
    """Get all scans"""
    scans = Scan.query.order_by(Scan.started_at.desc()).all()
    return jsonify([scan.to_dict() for scan in scans])


@api_bp.route('/scans', methods=['POST'])
def create_scan():
    """Create a new scan"""
    data = request.json
    target_url = data.get('target_url')
    scan_type = data.get('scan_type', 'full')
    
    if not target_url:
        return jsonify({'error': 'target_url is required'}), 400
    
    scan = Scan(
        target_url=target_url,
        scan_type=scan_type,
        status='pending',
        created_by=data.get('created_by')
    )
    db.session.add(scan)
    db.session.commit()
    
    # Start scan asynchronously (in production, use celery/background tasks)
    try:
        scan.status = 'running'
        db.session.commit()
        
        # Run scan
        config = Config()
        engine = ScanEngine(config.scanner)
        
        # For now, this is simplified - in production, use background tasks
        vulnerabilities_list = engine.scan(target_url)
        
        # Save vulnerabilities
        for vuln in vulnerabilities_list:
            db_vuln = Vulnerability(
                scan_id=scan.id,
                title=vuln.title,
                description=vuln.description,
                severity=vuln.severity.value,
                confidence=vuln.confidence,
                cwe_id=vuln.cwe_id,
                cvss_score=vuln.cvss_score,
                evidence=vuln.evidence,
                remediation=vuln.remediation,
            )
            db.session.add(db_vuln)
        
        scan.status = 'completed'
        scan.completed_at = datetime.utcnow()
        db.session.commit()
        
    except Exception as e:
        logger.error(f"Scan error: {e}")
        scan.status = 'failed'
        db.session.commit()
    
    return jsonify(scan.to_dict()), 201


@api_bp.route('/scans/<int:scan_id>', methods=['GET'])
def get_scan(scan_id):
    """Get scan details"""
    scan = Scan.query.get_or_404(scan_id)
    return jsonify(scan.to_dict())


@api_bp.route('/scans/<int:scan_id>', methods=['DELETE'])
def delete_scan(scan_id):
    """Delete a scan"""
    scan = Scan.query.get_or_404(scan_id)
    db.session.delete(scan)
    db.session.commit()
    return jsonify({'message': 'Scan deleted'}), 200


# Vulnerability endpoints
@api_bp.route('/vulnerabilities', methods=['GET'])
def get_vulnerabilities():
    """Get all vulnerabilities"""
    scan_id = request.args.get('scan_id', type=int)
    severity = request.args.get('severity')
    
    query = Vulnerability.query
    if scan_id:
        query = query.filter(Vulnerability.scan_id == scan_id)
    if severity:
        query = query.filter(Vulnerability.severity == severity)
    
    vulnerabilities = query.order_by(Vulnerability.created_at.desc()).all()
    return jsonify([v.to_dict() for v in vulnerabilities])


@api_bp.route('/vulnerabilities/<int:vuln_id>', methods=['GET'])
def get_vulnerability(vuln_id):
    """Get vulnerability details"""
    vuln = Vulnerability.query.get_or_404(vuln_id)
    return jsonify(vuln.to_dict())


@api_bp.route('/vulnerabilities/<int:vuln_id>', methods=['PATCH'])
def update_vulnerability(vuln_id):
    """Update vulnerability (mark as verified, false positive, etc.)"""
    vuln = Vulnerability.query.get_or_404(vuln_id)
    data = request.json
    
    if 'verified' in data:
        vuln.verified = data['verified']
    if 'false_positive' in data:
        vuln.false_positive = data['false_positive']
    
    db.session.commit()
    return jsonify(vuln.to_dict())


# Statistics endpoints
@api_bp.route('/stats', methods=['GET'])
def get_stats():
    """Get statistics"""
    total_scans = Scan.query.count()
    total_vulns = Vulnerability.query.count()
    critical_vulns = Vulnerability.query.filter(Vulnerability.severity == 'critical').count()
    high_vulns = Vulnerability.query.filter(Vulnerability.severity == 'high').count()
    medium_vulns = Vulnerability.query.filter(Vulnerability.severity == 'medium').count()
    low_vulns = Vulnerability.query.filter(Vulnerability.severity == 'low').count()
    
    return jsonify({
        'total_scans': total_scans,
        'total_vulnerabilities': total_vulns,
        'by_severity': {
            'critical': critical_vulns,
            'high': high_vulns,
            'medium': medium_vulns,
            'low': low_vulns,
        }
    })


# Crawler endpoints
@api_bp.route('/crawl', methods=['POST'])
def start_crawl():
    """Start crawling a target"""
    data = request.json
    target_url = data.get('target_url')
    max_depth = data.get('max_depth', 10)
    
    if not target_url:
        return jsonify({'error': 'target_url is required'}), 400
    
    try:
        spider = WebSpider()
        results = spider.crawl(target_url, max_depth)
        return jsonify(results), 200
    except Exception as e:
        logger.error(f"Crawl error: {e}")
        return jsonify({'error': str(e)}), 500


# Health check
@api_bp.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({'status': 'ok'}), 200

