import json

from flask import Blueprint, render_template, request, jsonify, Response, redirect, url_for
from flask_login import login_required, current_user
from app.rbac import permission_required, role_required
from app.models import ScanSession, db
from scanner.port_scanner import scan_ports
from scanner.service_detector import identify_services
from scanner.tls_checker import check_tls
from scanner.credential_checker import check_default_credentials

scanner_bp = Blueprint('scanner', __name__, template_folder='../templates')

@scanner_bp.route('/new')
@login_required
@permission_required('scan')
def new_scan():
    return render_template('scan.html')

@scanner_bp.route('/dashboard')
@login_required
def dashboard():
    scans = ScanSession.query.order_by(ScanSession.created_at.desc()).limit(10).all()
    critical_count = sum(1 for s in scans if s.severity == 'critical')
    high_count = sum(1 for s in scans if s.severity == 'high')
    return render_template('dashboard.html', scans=scans, critical_count=critical_count, high_count=high_count)

@scanner_bp.route('/history')
@login_required
def history():
    scans = ScanSession.query.order_by(ScanSession.created_at.desc()).all()
    return render_template('scan_history.html', scans=scans)

def calculate_severity(results):
    """Calculate severity based on findings."""
    score = 0
    
    if results['open_ports']:
        score += len(results['open_ports']) * 2
    
    if results['tls'] and not results['tls'].get('valid', True):
        score += 10
    
    if results['creds'] and results['creds'].get('vulnerable', False):
        score += 15
    
    if score >= 20:
        return 'critical'
    elif score >= 10:
        return 'high'
    elif score >= 5:
        return 'medium'
    else:
        return 'low'


@scanner_bp.route('/run', methods=['POST'])
@login_required
def run_scan():
    target = request.form.get('target')
    scan_types = request.form.getlist('scan_type')  # ✅ NEW - gets ALL checked values
    
    print(f"\n{'='*50}")
    print(f"🔍 SCANNING: {target}")
    print(f"📊 Scan types: {scan_types}")  # ✅ Now shows ['port', 'tls', 'service']
    print(f"{'='*50}\n")
    
    results = {'target': target, 'open_ports': [], 'services': [], 'tls': None, 'creds': None}
    
    if 'port' in scan_types:  # ✅ Changed from: scan_type in ['all', 'port']
        print("🔓 Running port scan...")
        ports = scan_ports(target)
        print(f"✅ Ports found: {ports}")
        results['open_ports'] = ports
    
    if 'service' in scan_types and results['open_ports']:  # ✅ Changed
        print("🔧 Running service detection...")
        services = identify_services(target, results['open_ports'])
        print(f"✅ Services: {services}")
        results['services'] = services
    
    # if 'tls' in scan_types and 443 in results['open_ports']:  # ✅ Changed
    #     print("🔐 Running TLS check...")
    #     tls = check_tls(target)
    #     print(f"✅ TLS: {tls}")
    #     results['tls'] = tls

    if 'tls' in scan_types:
        print("🔐 Running TLS checks...")
        tls_results = check_tls(target, results['open_ports'])
        # Merge into final results
        if tls_results:
            results['tls'] = tls_results
        else:
            results['tls'] = None
    
    if 'creds' in scan_types and 80 in results['open_ports']:  # ✅ Changed
        print("⚠️ Running credential check...")
        creds = check_default_credentials(target)
        print(f"✅ Creds: {creds}")
        results['creds'] = creds
    
    results['severity'] = calculate_severity(results)
    
    scan_session = ScanSession(
        user_id=current_user.id,
        target=target,
        scan_type=','.join(scan_types),  # ✅ Save as comma-separated string
        results=json.dumps(results),
        severity=results['severity']
    )
    db.session.add(scan_session)
    db.session.commit()
    
    print(f"💾 Scan saved with ID: {scan_session.id}")
    print(f"📊 Final results: {results}")
    print(f"{'='*50}\n")
    
    return render_template('scan_results.html', results=results, scan_id=scan_session.id)

    target = request.form.get('target')
    scan_type = request.form.get('scan_type', 'all')
    
    print(f"\n{'='*50}")
    print(f"🔍 SCANNING: {target}")
    print(f"📊 Scan type: {scan_type}")
    print(f"{'='*50}\n")
    
    results = {'target': target, 'open_ports': [], 'services': [], 'tls': None, 'creds': None}
    
    if scan_type in ['all', 'port']:
        print("🔓 Running port scan...")
        ports = scan_ports(target)
        print(f"✅ Ports found: {ports}")
        results['open_ports'] = ports
    
    if scan_type in ['all', 'service'] and results['open_ports']:
        print("🔧 Running service detection...")
        services = identify_services(target, results['open_ports'])
        print(f"✅ Services: {services}")
        results['services'] = services
    
    if scan_type in ['all', 'tls'] and 443 in results['open_ports']:
        print("🔐 Running TLS check...")
        tls = check_tls(target)
        print(f"✅ TLS: {tls}")
        results['tls'] = tls
    
    if scan_type in ['all', 'creds'] and 80 in results['open_ports']:
        print("⚠️ Running credential check...")
        creds = check_default_credentials(target)
        print(f"✅ Creds: {creds}")
        results['creds'] = creds
    
    results['severity'] = calculate_severity(results)
    
    # ✅ FIX: Removed status='completed'
    scan_session = ScanSession(
        user_id=current_user.id,
        target=target,
        scan_type=scan_type,
        results=results
    )
    db.session.add(scan_session)
    db.session.commit()
    
    print(f"💾 Scan saved with ID: {scan_session.id}")
    print(f"📊 Final results: {results}")
    print(f"{'='*50}\n")
    
    return render_template('scan_results.html', results=results, scan_id=scan_session.id)
    target = request.form.get('target')
    scan_types = request.form.getlist('scan_type')
    ports_str = request.form.get('ports', '22,80,443,4443,8000,8081')
    ports = [int(p.strip()) for p in ports_str.split(',') if p.strip().isdigit()]

    results = {
        'target': target,
        'open_ports': [],
        'services': [],
        'tls': None,
        'creds': None,
        'severity': 'low'
    }

    # Port Scan
    if 'port' in scan_types:
        open_ports = scan_ports(target, ports)
        results['open_ports'] = open_ports

        # Service Detection
        if 'service' in scan_types:
            for port in open_ports:
                svc = identify_service(target, port)
                results['services'].append({
                    'port': port,
                    'service': svc['service'],
                    'banner': svc['banner'][:200] if svc['banner'] else ''
                })

        # TLS Check
        if 'tls' in scan_types:
            tls_ports = [p for p in open_ports if p in [443, 4443]]
            if tls_ports:
                results['tls'] = check_tls(target, tls_ports[0])

        # Credential Check
        if 'creds' in scan_types:
            http_ports = [p for p in open_ports if p in [80, 8080, 8081, 443, 4443]]
            if http_ports:
                results['creds'] = check_default_credentials(target, http_ports[0])

    # Determine severity
    if results['creds'] and results['creds'].get('findings'):
        results['severity'] = 'critical'
    elif results['tls'] and results['tls'].get('valid') == False:
        results['severity'] = 'high'
    elif len(results['open_ports']) > 10:
        results['severity'] = 'medium'

    # Save to DB
    scan_session = ScanSession(
        target=target,
        scan_type=','.join(scan_types),
        results=json.dumps(results),
        severity=results['severity'],
        user_id=current_user.id
    )
    db.session.add(scan_session)
    db.session.commit()

    return render_template('scan_results.html', results=results, scan_id=scan_session.id)

@scanner_bp.route('/detail/<int:scan_id>')
@login_required
def scan_detail(scan_id):
    scan = ScanSession.query.get_or_404(scan_id)
    results = json.loads(scan.results) if scan.results else {}
    return render_template('scan_results.html', results=results, scan_id=scan.id)

@scanner_bp.route('/export/csv/<int:scan_id>')
@login_required
@permission_required('export')
def export_csv(scan_id):
    scan = ScanSession.query.get_or_404(scan_id)
    results = json.loads(scan.results) if scan.results else {}

    import csv
    from io import StringIO
    from flask import make_response

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['Target', 'Type', 'Severity', 'Open Ports', 'Services', 'TLS Valid', 'Creds Found'])
    writer.writerow([
        results.get('target', ''),
        scan.scan_type,
        results.get('severity', 'low'),
        ','.join(map(str, results.get('open_ports', []))),
        str(results.get('services', [])),
        str(results.get('tls', {}).get('valid', False)),
        str(len(results.get('creds', {}).get('findings', [])) > 0)
    ])

    response = make_response(output.getvalue())
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = f'attachment; filename=scan_{scan_id}.csv'
    return response

@scanner_bp.route('/export/json/<int:scan_id>')
@login_required
@permission_required('export')
def export_json(scan_id):
    scan = ScanSession.query.get_or_404(scan_id)
    return Response(
        scan.results,
        mimetype='application/json',
        headers={'Content-Disposition': f'attachment; filename=scan_{scan_id}.json'}
    )


@scanner_bp.route('/filter')
@login_required
def filter_scans():
    search = request.args.get('q', '')
    scans = ScanSession.query.filter(
        ScanSession.target.contains(search)
    ).order_by(ScanSession.created_at.desc()).all()
    return render_template('scan_history.html', scans=scans)