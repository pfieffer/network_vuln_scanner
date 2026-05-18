"""Pure unit tests for scanner utilities — no Flask, no DB, no mocks."""

import pytest

from app.utils.scanner_utils import calculate_severity, is_tls_candidate


# ============================================================
# TESTS: calculate_severity
# ============================================================

class TestCalculateSeverity:
    """Test severity calculation — pure math, zero dependencies."""

    def test_severity_low_no_findings(self):
        """No findings = low severity."""
        results = {
            'open_ports': [],
            'tls': None,
            'creds': None
        }
        assert calculate_severity(results) == 'low'

    def test_severity_low_single_port(self):
        """1 port = 2 pts = low."""
        results = {
            'open_ports': [22],
            'tls': None,
            'creds': None
        }
        assert calculate_severity(results) == 'low'

    def test_severity_low_two_ports(self):
        """2 ports = 4 pts = low."""
        results = {
            'open_ports': [22, 80],
            'tls': None,
            'creds': None
        }
        assert calculate_severity(results) == 'low'

    def test_severity_medium_three_ports(self):
        """3 ports = 6 pts = medium."""
        results = {
            'open_ports': [22, 80, 443],
            'tls': None,
            'creds': None
        }
        assert calculate_severity(results) == 'medium'

    def test_severity_medium_four_ports(self):
        """4 ports = 8 pts = medium."""
        results = {
            'open_ports': [22, 80, 443, 3306],
            'tls': None,
            'creds': None
        }
        assert calculate_severity(results) == 'medium'

    def test_severity_high_five_ports(self):
        """5 ports = 10 pts = high."""
        results = {
            'open_ports': [22, 80, 443, 3306, 8080],
            'tls': None,
            'creds': None
        }
        assert calculate_severity(results) == 'high'

    def test_severity_high_invalid_tls_dict(self):
        """Invalid TLS (dict) = +10 pts = high."""
        results = {
            'open_ports': [80],
            'tls': {
                80: {'valid': False},
                443: {'valid': True}
            },
            'creds': None
        }
        assert calculate_severity(results) == 'high'

    def test_severity_high_invalid_tls_simple(self):
        """Invalid TLS (simple) = +10 pts = high."""
        results = {
            'open_ports': [22],
            'tls': {'valid': False},
            'creds': None
        }
        assert calculate_severity(results) == 'high'

    def test_severity_high_vulnerable_creds(self):
        """Vulnerable creds = +15 pts = high."""
        results = {
            'open_ports': [80],
            'tls': None,
            'creds': {'vulnerable': True}
        }
        assert calculate_severity(results) == 'high'

    def test_severity_critical_many_ports(self):
        """10+ ports = 20+ pts = critical."""
        results = {
            'open_ports': list(range(10)),
            'tls': None,
            'creds': None
        }
        assert calculate_severity(results) == 'critical'

    def test_severity_critical_combined(self):
        """5 ports + invalid TLS + vulnerable creds = critical."""
        results = {
            'open_ports': [22, 80, 443, 3306, 8080],  # 10 pts
            'tls': {'valid': False},                  # 10 pts
            'creds': {'vulnerable': True}             # 15 pts
        }
        assert calculate_severity(results) == 'critical'

    def test_severity_empty_dict(self):
        """Empty results dict = low."""
        results = {}
        assert calculate_severity(results) == 'low'

    def test_severity_missing_keys(self):
        """Missing keys treated as None/empty = low."""
        results = {'open_ports': None, 'tls': None, 'creds': None}
        assert calculate_severity(results) == 'low'


# ============================================================
# TESTS: is_tls_candidate
# ============================================================

class TestIsTlsCandidate:
    """Test TLS candidate detection — pure logic, zero dependencies."""

    # ── Known TLS ports ──
    def test_tls_port_443(self):
        assert is_tls_candidate(443) is True

    def test_tls_port_8443(self):
        assert is_tls_candidate(8443) is True

    def test_tls_port_993(self):
        assert is_tls_candidate(993) is True

    def test_tls_port_995(self):
        assert is_tls_candidate(995) is True

    def test_tls_port_465(self):
        assert is_tls_candidate(465) is True

    def test_tls_port_636(self):
        assert is_tls_candidate(636) is True

    def test_tls_port_587(self):
        assert is_tls_candidate(587) is True

    # ── Non-TLS ports ──
    def test_not_tls_port_22(self):
        assert is_tls_candidate(22) is False

    def test_not_tls_port_80(self):
        assert is_tls_candidate(80) is False

    def test_not_tls_port_3306(self):
        assert is_tls_candidate(3306) is False

    def test_not_tls_port_8080(self):
        assert is_tls_candidate(8080) is False

    # ── Service info with TLS indicators ──
    def test_tls_service_https(self):
        service_info = {'service': 'https'}
        assert is_tls_candidate(80, service_info) is True

    def test_tls_service_ssl(self):
        service_info = {'service': 'ssl-wrap'}
        assert is_tls_candidate(110, service_info) is True

    def test_tls_product_tls(self):
        service_info = {'product': 'nginx/1.18 TLS'}
        assert is_tls_candidate(443, service_info) is True

    def test_tls_product_stunnel(self):
        service_info = {'product': 'stunnel'}
        assert is_tls_candidate(443, service_info) is True

    def test_tls_service_smtps(self):
        service_info = {'service': 'smtps'}
        assert is_tls_candidate(587, service_info) is True

    def test_tls_service_imaps(self):
        service_info = {'service': 'imaps'}
        assert is_tls_candidate(993, service_info) is True

    # ── Service info without TLS indicators ──
    def test_not_tls_service_http(self):
        service_info = {'service': 'http'}
        assert is_tls_candidate(80, service_info) is False

    def test_not_tls_service_ssh(self):
        service_info = {'service': 'ssh'}
        assert is_tls_candidate(22, service_info) is False

    def test_not_tls_service_mysql(self):
        service_info = {'service': 'mysql'}
        assert is_tls_candidate(3306, service_info) is False

    # ── No service info ──
    def test_no_service_info_returns_false(self):
        assert is_tls_candidate(443, None) is False

    def test_no_service_info_empty_dict(self):
        assert is_tls_candidate(443, {}) is False

    # ── Edge cases ──
    def test_service_info_empty_strings(self):
        service_info = {'service': '', 'product': ''}
        assert is_tls_candidate(80, service_info) is False

    def test_case_insensitive_service(self):
        service_info = {'service': 'HTTPS'}
        assert is_tls_candidate(80, service_info) is True

    def test_case_insensitive_product(self):
        service_info = {'product': 'Apache/SSL'}
        assert is_tls_candidate(443, service_info) is True

    def test_multiple_tls_indicators(self):
        service_info = {'service': 'secure-https-tls'}
        assert is_tls_candidate(8443, service_info) is True

    def test_port_takes_precedence_over_service(self):
        """Even if service says no TLS, known port = True."""
        service_info = {'service': 'http'}
        assert is_tls_candidate(443, service_info) is True


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
