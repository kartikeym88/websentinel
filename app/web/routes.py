from flask import Blueprint, render_template, request, redirect, url_for, jsonify, send_file, Response
import threading
from app.core.scan_manager import ScanManager
from app.database.session import get_session_factory, get_engine
from app.database.repository import Repository
from app.reporting.html_reporter import HTMLReporter
from app.reporting.json_reporter import JSONReporter
import os

bp = Blueprint('web', __name__)
engine = get_engine()
session_factory = get_session_factory(engine)

@bp.route('/')
def index():
    with session_factory() as session:
        repo = Repository(session)
        repo.init_db(engine)
        scans = repo.list_scans(limit=10)
    return render_template('index.html', scans=scans)

@bp.route('/scan', methods=['POST'])
def start_scan():
    target = request.form.get('target')
    zap_enabled = request.form.get('zap_enabled') == 'on'
    
    # Simple validation
    if not target or not target.startswith('http'):
        return "Invalid target URL", 400
        
    def run_scan_background(t):
        from app.core.config import get_settings
        # A hack to temporarily enable/disable zap via env could be risky for concurrency.
        # But we'll just run it.
        manager = ScanManager()
        manager.run_scan(t)
        
    # Start scan in a background thread
    thread = threading.Thread(target=run_scan_background, args=(target,))
    thread.daemon = True
    thread.start()
    
    return redirect(url_for('web.index'))

@bp.route('/scan/<scan_id>')
def scan_results(scan_id):
    with session_factory() as session:
        repo = Repository(session)
        scan = repo.get_scan(scan_id)
        if not scan:
            return "Scan not found", 404
        stats = repo.get_scan_statistics(scan_id)
        findings = repo.get_scan_findings(scan_id)
    return render_template('results.html', scan=scan, stats=stats, findings=findings)

@bp.route('/report/<scan_id>/<format>')
def download_report(scan_id, format):
    with session_factory() as session:
        repo = Repository(session)
        scan = repo.get_scan(scan_id)
        if not scan:
            return "Scan not found", 404
        stats = repo.get_scan_statistics(scan_id)
        findings = repo.get_scan_findings(scan_id)
        
    if format == 'html':
        reporter = HTMLReporter()
        path = reporter.generate(stats, findings)
    elif format == 'json':
        reporter = JSONReporter()
        path = reporter.generate(stats, findings)
    else:
        return "Invalid format", 400
    return send_file(os.path.abspath(path), as_attachment=True)
    
@bp.route('/robots.txt')
def robots():
    content = "User-agent: *\nDisallow: /scan/\nDisallow: /report/\n"
    return Response(content, mimetype="text/plain")
