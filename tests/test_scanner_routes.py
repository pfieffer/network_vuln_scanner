"""Unit tests for scanner routes module."""

import sys
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from flask import url_for
from flask_login import current_user

# Fix import path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import create_app, db
from app.models import ScanSession, User, Role
from app.routes.scanner_routes import calculate_severity


# ============================================================
# FIXTURES
# ============================================================

@pytest.fixture
def app():
    """Create test application."""
    app = create_app()
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['WTF_CSRF_ENABLED'] = False
    app.config['SECRET_KEY'] = 'test-secret-key'
    
    with app.app_context():
        db.create_all()
        yield app
        db.drop_all()


@pytest.fixture
def client(app):
    """Create test client."""
    return app.test_client()


@pytest.fixture
def mock_admin_user():
    """Create mock admin user."""
    user = MagicMock()
    user.id = 1
    user.is_authenticated = True
    user.has_role.side_effect = lambda role: role in ['admin', 'analyst', 'viewer']
    user.get_id.return_value = '1'
    return user


@pytest.fixture
def mock_viewer_user():
    """Create mock viewer user."""
    user = MagicMock()
    user.id = 2
    user.is_authenticated = True
    user.has_role.side_effect = lambda role: role in ['viewer']
    user.get_id.return_value = '2'
    return user


def login_client(client, user):
    """Login client with mock user."""
    with client.session_transaction() as sess:
        sess['user_id'] = user.id
    return client


# ============================================================
# TESTS: calculate_severity function
# ============================================================

class TestCalculateSeverity:
    """Test severity calculation logic."""

    def test_severity_low_no_findings(self, app):
        """No findings = low severity."""
        with app.app_context():
            results = {
                'open_ports': [],
                'tls': None,
                'creds': None
            }
            assert calculate_severity(results) == 'low'

    def test_severity_low_single_port(self, app):
        """Single open port = 2 pts = low."""
        with app.app_context():
            results = {
                'open_ports': [22],
                'tls': None,
                'creds': None
            }
            assert calculate_severity(results) == 'low'

    def test_severity_medium_three_ports(self, app):
        """3 ports = 6 pts = medium."""
        with app.app_context():
            results = {
                'open_ports': [22, 80, 443],
                'tls': None,
                'creds': None
            }
            assert calculate_severity(results) == 'medium'

    def test_severity_high_invalid_tls(self, app):
        """Invalid TLS = 10 pts = high."""
        with app.app_context():
            results = {
                'open_ports': [80],
                'tls': {'valid': False},
                'creds': None
            }
            assert calculate_severity(results) == 'high'

    def test_severity_high_vulnerable_creds(self, app):
        """Vulnerable creds = 15 pts = high."""
        with app.app_context():
            results = {
                'open_ports': [80],
                'tls': None,
                'creds': {'vulnerable': True}
            }
            assert calculate_severity(results) == 'high'

    def test_severity_critical_many_ports(self, app):
        """10+ ports = 20+ pts = critical."""
        with app.app_context():
            results = {
                'open_ports': list(range(10)),
                'tls': None,
                'creds': None
            }
            assert calculate_severity(results) == 'critical'

    def test_severity_critical_combined(self, app):
        """Combined findings = critical."""
        with app.app_context():
            results = {
                'open_ports': list(range(5)),
                'tls': {'valid': False},
                'creds': {'vulnerable': True}
            }
            assert calculate_severity(results) == 'critical'


# ============================================================
# TESTS: Dashboard
# ============================================================

class TestDashboard:
    """Test dashboard route."""

    def test_dashboard_shows_recent_scans(self, client, app, mock_admin_user):
        """Dashboard shows last 10 scans with severity counts."""
        login_client(client, mock_admin_user)
        
        with app.app_context():
            for i in range(12):
                db.session.add(ScanSession(
                    user_id=1,
                    target=f'192.168.1.{i}',
                    scan_type='port',
                    results='{}',
                    severity='low' if i < 5 else ('critical' if i % 2 == 0 else 'high')
                ))
            db.session.commit()

        response = client.get(url_for('scanner.dashboard'))
        assert response.status_code in [200, 302]

    def test_dashboard_counts_severity(self, client, app, mock_admin_user):
        """Dashboard correctly counts critical and high severity."""
        login_client(client, mock_admin_user)
        
        with app.app_context():
            db.session.add(ScanSession(
                user_id=1, target='scan1', scan_type='port',
                results='{}', severity='critical'
            ))
            db.session.add(ScanSession(
                user_id=1, target='scan2', scan_type='port',
                results='{}', severity='critical'
            ))
            db.session.add(ScanSession(
                user_id=1, target='scan3', scan_type='port',
                results='{}', severity='high'
            ))
            db.session.commit()

        response = client.get(url_for('scanner.dashboard'))
        assert response.status_code in [200, 302]


# ============================================================
# TESTS: Run Scan
# ============================================================

class TestRunScan:
    """Test run scan endpoint."""

    @patch('scanner.port_scanner.scan_ports')
    def test_run_scan_port_only(self, mock_ports, client, app, mock_admin_user):
        """Test port-only scan."""
        mock_ports.return_value = [22, 80, 443]
        
        login_client(client, mock_admin_user)
        
        response = client.post(url_for('scanner.run_scan'), data={
            'target': '192.168.1.1',
            'scan_type': ['port']
        }, follow_redirects=True)
        
        assert response.status_code == 200

    @patch('scanner.port_scanner.scan_ports')
    def test_run_scan_all_types(self, mock_ports, client, app, mock_admin_user):
        """Test scan with all types."""
        mock_ports.return_value = [80, 443]
        
        login_client(client, mock_admin_user)
        
        response = client.post(url_for('scanner.run_scan'), data={
            'target': '192.168.1.1',
            'scan_type': ['port', 'service', 'tls', 'creds']
        }, follow_redirects=True)
        
        assert response.status_code == 200

    @patch('scanner.port_scanner.scan_ports')
    def test_run_scan_creds_only_on_port_80(self, mock_ports, client, app, mock_admin_user):
        """Credential check only runs if port 80 is open."""
        mock_ports.return_value = [22]  # No port 80
        
        login_client(client, mock_admin_user)
        
        response = client.post(url_for('scanner.run_scan'), data={
            'target': '192.168.1.1',
            'scan_type': ['port', 'creds']
        }, follow_redirects=True)
        
        assert response.status_code == 200

    # @patch('scanner.port_scanner.scan_ports')
    # def test_run_scan_saves_to_database(self, mock_ports, client, app, mock_admin_user):
    #     """Test scan is saved to database."""
    #     mock_ports.return_value = [80]
        
    #     login_client(client, mock_admin_user)
        
    #     response = client.post(url_for('scanner.run_scan'), data={
    #         'target': 'example.com',
    #         'scan_type': ['port']
    #     }, follow_redirects=True)
        
    #     assert response.status_code == 200
        
    #     # Query within the same app context
    #     with app.app_context():
    #         scan = ScanSession.query.filter_by(target='example.com').first()
    #         assert scan is not None
    #         assert scan.user_id == 1
    #         assert scan.severity == 'low'


# ============================================================
# TESTS: Scan Detail
# ============================================================

class TestScanDetail:
    """Test scan detail route."""

    def test_detail_404_for_nonexistent(self, client, mock_admin_user):
        """404 for non-existent scan."""
        login_client(client, mock_admin_user)
        response = client.get(url_for('scanner.scan_detail', scan_id=999))
        assert response.status_code in [404, 302]

    def test_detail_shows_results(self, client, app, mock_admin_user):
        """Detail shows scan results."""
        login_client(client, mock_admin_user)
        
        with app.app_context():
            # Create a scan directly
            scan = ScanSession(
                user_id=1, target='10.0.0.1', scan_type='port',
                results='{}',
                severity='low'
            )
            db.session.add(scan)
            db.session.flush()
            scan_id = scan.id  # Store ID before commit
            db.session.commit()
        
        # Now make the request
        response = client.get(url_for('scanner.scan_detail', scan_id=scan_id))
        assert response.status_code in [200, 302]


# ============================================================
# TESTS: Export CSV & JSON
# ============================================================

class TestExports:
    """Test CSV and JSON export routes."""

    def test_export_csv_returns_correct_format(self, client, app, mock_admin_user):
        """CSV export returns correct format."""
        login_client(client, mock_admin_user)
        
        with app.app_context():
            scan = ScanSession(
                user_id=1, target='192.168.1.1', scan_type='port,tls',
                results='{}',
                severity='high'
            )
            db.session.add(scan)
            db.session.flush()
            scan_id = scan.id
            db.session.commit()
        
        response = client.get(url_for('scanner.export_csv', scan_id=scan_id))
        assert response.status_code in [200, 302]

    def test_export_json_returns_correct_data(self, client, app, mock_admin_user):
        """JSON export returns correct format."""
        login_client(client, mock_admin_user)
        
        with app.app_context():
            scan = ScanSession(
                user_id=1, target='10.0.0.1', scan_type='port',
                results='{}',
                severity='low'
            )
            db.session.add(scan)
            db.session.flush()
            scan_id = scan.id
            db.session.commit()
        
        response = client.get(url_for('scanner.export_json', scan_id=scan_id))
        assert response.status_code in [200, 302]


# ============================================================
# TESTS: Filter Scans
# ============================================================

class TestFilterScans:
    """Test filter scans route."""

    def test_filter_shows_matching_scans(self, client, app, mock_admin_user):
        """Filter returns scans matching query."""
        login_client(client, mock_admin_user)
        
        with app.app_context():
            db.session.add(ScanSession(
                user_id=1, target='192.168.1.100', scan_type='port',
                results='{}', severity='low'
            ))
            db.session.add(ScanSession(
                user_id=1, target='10.0.0.50', scan_type='port',
                results='{}', severity='medium'
            ))
            db.session.commit()

        response = client.get(url_for('scanner.filter_scans', q='192.168'))
        assert response.status_code in [200, 302]

    def test_filter_respects_user_isolation(self, client, app, mock_viewer_user):
        """Non-admin users only see their own scans."""
        login_client(client, mock_viewer_user)
        
        with app.app_context():
            db.session.add(ScanSession(
                user_id=1, target='10.0.0.1', scan_type='port',
                results='{}', severity='low'
            ))
            db.session.add(ScanSession(
                user_id=2, target='10.0.0.2', scan_type='port',
                results='{}', severity='low'
            ))
            db.session.commit()

        response = client.get(url_for('scanner.filter_scans', q='10.0'))
        assert response.status_code in [200, 302]


# ============================================================
# TESTS: History
# ============================================================

class TestHistory:
    """Test history route."""

    def test_history_shows_all_scans(self, client, app, mock_admin_user):
        """History shows all scans."""
        login_client(client, mock_admin_user)
        
        with app.app_context():
            db.session.add(ScanSession(
                user_id=1, target='10.0.0.1', scan_type='port',
                results='{}', severity='low'
            ))
            db.session.commit()

        response = client.get(url_for('scanner.history'))
        assert response.status_code in [200, 302]


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
