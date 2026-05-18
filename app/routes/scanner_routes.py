"""Scanner routes module."""

import csv
import json
from datetime import datetime
from io import StringIO

from flask import Blueprint, Response, make_response, render_template, request, abort
from flask_login import current_user, login_required

from app.models import ScanSession, ScanAudit, db
from app.rbac import permission_required, role_required
from scanner.credential_checker import check_default_credentials
from scanner.port_scanner import scan_ports
from scanner.service_detector import identify_services
from scanner.tls_checker import check_tls

scanner_bp = Blueprint('scanner', __name__, template_folder='../templates')


@scanner_bp.route('/new')
@login_required
@permission_required('scan')
def new_scan():
    """Render the new scan page."""
    return render_template('scan.html')


@scanner_bp.route('/dashboard')
@login_required
@permission_required('read')
def dashboard():
    """Render the dashboard with recent scans."""
    scans = ScanSession.query.order_by(ScanSession.created_at.desc()).limit(10).all()
    critical_count = sum(1 for s in scans if s.severity == 'critical')
    high_count = sum(1 for s in scans if s.severity == 'high')
    audit_count = ScanAudit.query.count() if current_user.has_role('admin') else None
    return render_template(
        'dashboard.html',
        scans=scans,
        critical_count=critical_count,
        high_count=high_count,
        audit_count=audit_count,
    )


@scanner_bp.route('/history')
@login_required
@permission_required('read')
def history():
    """Render the scan history page."""
    scans = ScanSession.query.order_by(ScanSession.created_at.desc()).all()
    return render_template('scan_history.html', scans=scans)


def calculate_severity(results):
    """Calculate severity based on findings."""
    score = 0

    if results['open_ports']:
        score += len(results['open_ports']) * 2

    tls_results = results.get('tls')
    if tls_results:
        if isinstance(tls_results, dict):
            if any(not port_data.get('valid', True) for port_data in tls_results.values()):
                score += 10
        elif not tls_results.get('valid', True):
            score += 10

    if results['creds'] and results['creds'].get('vulnerable', False):
        score += 15

    if score >= 20:
        return 'critical'
    if score >= 10:
        return 'high'
    if score >= 5:
        return 'medium'
    return 'low'


def is_tls_candidate(port, service_info=None):
    """Return True if the port/service is likely TLS-capable."""
    tls_ports = {443, 8443, 993, 995, 465, 636, 990, 992, 587}
    if port in tls_ports:
        return True

    if not service_info:
        return False

    service_name = str(service_info.get('service', '')).lower()
    product = str(service_info.get('product', '')).lower()
    tls_indicators = ('https', 'ssl', 'tls', 'ldaps', 'ftps', 'smtps', 'imaps', 'pop3s', 'secure')
    return any(keyword in service_name for keyword in tls_indicators) or any(keyword in product for keyword in tls_indicators)


@scanner_bp.route('/run', methods=['POST'])
@login_required
@permission_required('scan')
def run_scan():
    """Run a new scan on the target."""
    target = request.form.get('target')
    scan_types = request.form.getlist('scan_type')
    consent = request.form.get('scan_consent')

    if not consent:
        abort(400, description='Authorization confirmation is required before running a scan.')

    audit = ScanAudit(
        user_id=current_user.id,
        target=target,
        scan_type=','.join(scan_types),
        scan_consent=True,
        status='requested',
        request_ip=request.remote_addr,
        user_agent=request.headers.get('User-Agent'),
        requested_at=datetime.utcnow(),
    )
    db.session.add(audit)
    db.session.commit()

    audit.started_at = datetime.utcnow()
    audit.status = 'running'
    db.session.commit()

    print(f"\n{'=' * 50}")
    print(f"🔍 SCANNING: {target}")
    print(f"📊 Scan types: {scan_types}")
    print(f"{'=' * 50}\n")

    results = {'target': target, 'open_ports': [], 'services': [], 'tls': None, 'creds': None}

    try:
        if 'port' in scan_types:
            print("🔓 Running port scan...")
            ports = scan_ports(target)
            print(f"✅ Ports found: {ports}")
            results['open_ports'] = ports

        if 'service' in scan_types and results['open_ports']:
            print("🔧 Running service detection...")
            services = identify_services(target, results['open_ports'])
            print(f"✅ Services: {services}")
            results['services'] = services

        if 'tls' in scan_types:
            print("🔐 Evaluating TLS candidate ports...")
            tls_ports = []
            services = results.get('services')

            if isinstance(services, dict):
                for port_key, svc in services.items():
                    try:
                        port = int(port_key)
                    except (TypeError, ValueError):
                        continue
                    if is_tls_candidate(port, svc):
                        tls_ports.append(port)

            if not tls_ports:
                tls_ports = [port for port in results['open_ports'] if is_tls_candidate(port)]

            if tls_ports:
                print(f"🔐 Running TLS checks on candidate ports: {tls_ports}")
                tls_results = check_tls(target, tls_ports)
                results['tls'] = tls_results if tls_results else None
            else:
                print("⚠️ No TLS candidate ports detected; skipping TLS checks.")
                results['tls'] = None

        if 'creds' in scan_types and 80 in results['open_ports']:
            print("⚠️ Running credential check...")
            creds = check_default_credentials(target)
            print(f"✅ Creds: {creds}")
            results['creds'] = creds

        results['severity'] = calculate_severity(results)

        scan_session = ScanSession(
            user_id=current_user.id,
            target=target,
            scan_type=','.join(scan_types),
            results=json.dumps(results),
            severity=results['severity'],
        )
        db.session.add(scan_session)
        db.session.commit()

        audit.scan_session_id = scan_session.id
        audit.status = 'completed'
        audit.completed_at = datetime.utcnow()
        audit.notes = 'Scan completed successfully.'
        db.session.commit()

        print(f"💾 Scan saved with ID: {scan_session.id}")
        print(f"📊 Final results: {results}")
        print(f"{'=' * 50}\n")

        return render_template('scan_results.html', results=results, scan=scan_session, scan_id=scan_session.id)

    except Exception as e:
        audit.status = 'failed'
        audit.completed_at = datetime.utcnow()
        audit.notes = f'Scan failed: {e}'
        db.session.commit()
        raise


@scanner_bp.route('/audit')
@login_required
@role_required('admin')
def audit_log():
    """Render the audit log page for admin users."""
    audits = ScanAudit.query.order_by(ScanAudit.requested_at.desc()).all()
    return render_template('audit_log.html', audits=audits)


@scanner_bp.route('/detail/<int:scan_id>')
@login_required
@permission_required('read')
def scan_detail(scan_id):
    """Show detailed results for a scan."""
    scan = ScanSession.query.get_or_404(scan_id)
    if not (current_user.has_role('admin') or current_user.has_role('viewer') or current_user.has_role('analyst')) and scan.user_id != current_user.id:
        abort(404)
    results = json.loads(scan.results) if scan.results else {}
    return render_template('scan_results.html', results=results, scan=scan, scan_id=scan.id)


@scanner_bp.route('/export/csv/<int:scan_id>')
@login_required
@permission_required('export')
def export_csv(scan_id):
    """Export scan results as CSV."""
    scan = ScanSession.query.get_or_404(scan_id)
    if not (current_user.has_role('admin') or current_user.has_role('viewer') or current_user.has_role('analyst')) and scan.user_id != current_user.id:
        abort(404)
    results = json.loads(scan.results) if scan.results else {}

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['Target', 'Type', 'Severity', 'Open Ports', 'Services', 'TLS Valid', 'Creds Found'])
    tls_info = results.get('tls', {}) or {}
    tls_valid = False
    if isinstance(tls_info, dict) and tls_info:
        tls_valid = all(port_data.get('valid', False) for port_data in tls_info.values())
    writer.writerow([
        results.get('target', ''),
        scan.scan_type,
        results.get('severity', 'low'),
        ','.join(map(str, results.get('open_ports', []))),
        str(results.get('services', [])),
        str(tls_valid),
        str(len(results.get('creds', {}).get('findings', [])) > 0),
    ])

    response = make_response(output.getvalue())
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = f'attachment; filename=scan_{scan_id}.csv'
    return response


@scanner_bp.route('/export/json/<int:scan_id>')
@login_required
@permission_required('export')
def export_json(scan_id):
    """Export scan results as JSON."""
    scan = ScanSession.query.get_or_404(scan_id)
    if not (current_user.has_role('admin') or current_user.has_role('viewer') or current_user.has_role('analyst')) and scan.user_id != current_user.id:
        abort(404)
    return Response(
        scan.results,
        mimetype='application/json',
        headers={'Content-Disposition': f'attachment; filename=scan_{scan_id}.json'},
    )


@scanner_bp.route('/filter')
@login_required
@permission_required('read')
def filter_scans():
    """Filter scans by search query."""
    search = request.args.get('q', '')
    base_query = ScanSession.query.filter(ScanSession.target.contains(search))
    if not (current_user.has_role('admin') or current_user.has_role('viewer')):
        base_query = base_query.filter(ScanSession.user_id == current_user.id)
    scans = base_query.order_by(ScanSession.created_at.desc()).all()
    return render_template('scan_history.html', scans=scans)
