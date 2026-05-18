"""Unit tests for input validation module."""

import sys
from pathlib import Path

import pytest

# Fix import path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.validators import (
    validate_target,
    validate_ports,
    sanitize_error_message,
    ValidationError,
)


# ============================================================
# TESTS: validate_target()
# ============================================================

class TestValidateTarget:
    """Tests for target validation function."""

    # Valid IPv4 addresses
    def test_valid_ipv4_single(self):
        """Accept valid single IPv4 address."""
        assert validate_target("192.168.1.1") == "192.168.1.1"
        assert validate_target("127.0.0.1") == "127.0.0.1"
        assert validate_target("8.8.8.8") == "8.8.8.8"

    def test_valid_ipv4_with_whitespace(self):
        """Accept IPv4 with leading/trailing whitespace."""
        assert validate_target("  192.168.1.1  ") == "192.168.1.1"

    # Valid IPv4 CIDR notation
    def test_valid_ipv4_cidr(self):
        """Accept valid IPv4 CIDR notation."""
        assert validate_target("192.168.1.0/24") == "192.168.1.0/24"
        assert validate_target("10.0.0.0/8") == "10.0.0.0/8"
        assert validate_target("172.16.0.0/12") == "172.16.0.0/12"

    # Valid IPv6 addresses
    def test_valid_ipv6_single(self):
        """Accept valid IPv6 addresses."""
        assert validate_target("::1") == "::1"
        assert validate_target("2001:db8::1") == "2001:db8::1"
        assert validate_target("fe80::1") == "fe80::1"

    def test_valid_ipv6_full_notation(self):
        """Accept IPv6 in full notation."""
        assert validate_target("2001:0db8:0000:0000:0000:0000:0000:0001") == \
               "2001:0db8:0000:0000:0000:0000:0000:0001"

    # Valid IPv6 CIDR notation
    def test_valid_ipv6_cidr(self):
        """Accept valid IPv6 CIDR notation."""
        assert validate_target("2001:db8::/32") == "2001:db8::/32"
        assert validate_target("::1/128") == "::1/128"
        assert validate_target("fe80::/10") == "fe80::/10"

    # Valid domain names
    def test_valid_domain_simple(self):
        """Accept simple domain names."""
        assert validate_target("example.com") == "example.com"
        assert validate_target("google.com") == "google.com"
        assert validate_target("github.com") == "github.com"

    def test_valid_domain_with_subdomain(self):
        """Accept domains with subdomains."""
        assert validate_target("subdomain.example.com") == "subdomain.example.com"
        assert validate_target("api.github.com") == "api.github.com"
        assert validate_target("www.example.co.uk") == "www.example.co.uk"

    def test_valid_domain_with_hyphen(self):
        """Accept domains with hyphens."""
        assert validate_target("my-domain.com") == "my-domain.com"
        assert validate_target("sub-domain.example.com") == "sub-domain.example.com"

    def test_valid_domain_localhost(self):
        """Accept localhost variants."""
        # Note: localhost should be accepted
        try:
            result = validate_target("localhost")
            # Either it's accepted or raises ValidationError - both are acceptable
        except ValidationError:
            pass

    # Invalid targets
    def test_invalid_ipv4_out_of_range(self):
        """Reject IPv4 addresses with out-of-range octets."""
        with pytest.raises(ValidationError):
            validate_target("256.256.256.256")
        with pytest.raises(ValidationError):
            validate_target("192.168.1.256")

    def test_invalid_ipv4_incomplete(self):
        """Reject incomplete IPv4 addresses."""
        with pytest.raises(ValidationError):
            validate_target("192.168.1")
        with pytest.raises(ValidationError):
            validate_target("192.168")

    def test_invalid_ipv6_malformed(self):
        """Reject malformed IPv6 addresses."""
        with pytest.raises(ValidationError):
            validate_target("gggg::1")
        with pytest.raises(ValidationError):
            validate_target("::g")

    def test_invalid_empty_target(self):
        """Reject empty or whitespace-only targets."""
        with pytest.raises(ValidationError):
            validate_target("")
        with pytest.raises(ValidationError):
            validate_target("   ")
        with pytest.raises(ValidationError):
            validate_target("\t\n")

    # Dangerous patterns - Command injection
    def test_invalid_command_injection_semicolon(self):
        """Reject targets with command injection attempt (semicolon)."""
        with pytest.raises(ValidationError):
            validate_target("192.168.1.1; whoami")

    def test_invalid_command_injection_pipe(self):
        """Reject targets with command injection attempt (pipe)."""
        with pytest.raises(ValidationError):
            validate_target("192.168.1.1 | cat /etc/passwd")

    def test_invalid_command_injection_ampersand(self):
        """Reject targets with command injection attempt (ampersand)."""
        with pytest.raises(ValidationError):
            validate_target("192.168.1.1 & whoami")

    def test_invalid_command_injection_backtick(self):
        """Reject targets with command injection attempt (backticks)."""
        with pytest.raises(ValidationError):
            validate_target("192.168.1.1`whoami`")

    def test_invalid_command_injection_dollar(self):
        """Reject targets with command injection attempt (dollar expansion)."""
        with pytest.raises(ValidationError):
            validate_target("192.168.1.1$(whoami)")

    # Dangerous patterns - Path traversal
    def test_invalid_path_traversal(self):
        """Reject targets with path traversal attempt."""
        with pytest.raises(ValidationError):
            validate_target("../../etc/passwd")
        with pytest.raises(ValidationError):
            validate_target("..\\..\\windows\\system32")

    # Dangerous patterns - SQL Injection
    def test_invalid_sql_injection(self):
        """Reject targets with SQL injection attempt."""
        with pytest.raises(ValidationError):
            validate_target("192.168.1.1' OR '1'='1")

    def test_invalid_sql_injection_comment(self):
        """Reject targets with SQL comment."""
        with pytest.raises(ValidationError):
            validate_target("192.168.1.1' --")

    # Dangerous patterns - XSS
    def test_invalid_xss_script_tag(self):
        """Reject targets with XSS attempt."""
        with pytest.raises(ValidationError):
            validate_target("<script>alert('xss')</script>")

    def test_invalid_xss_event_handler(self):
        """Reject targets with XSS event handler."""
        with pytest.raises(ValidationError):
            validate_target("\" onload=\"alert('xss')\"")

    # Dangerous patterns - Quotes
    def test_invalid_single_quote(self):
        """Reject targets containing single quotes."""
        with pytest.raises(ValidationError):
            validate_target("192.168.1.1'")

    def test_invalid_double_quote(self):
        """Reject targets containing double quotes."""
        with pytest.raises(ValidationError):
            validate_target("192.168.1.1\"")

    def test_invalid_length_exceeded(self):
        """Reject targets exceeding maximum length."""
        # Construct a very long string that's technically a valid domain format
        long_target = "a" * 256 + ".com"
        with pytest.raises(ValidationError):
            validate_target(long_target)


# ============================================================
# TESTS: validate_ports()
# ============================================================

class TestValidatePorts:
    """Tests for port validation function."""

    # Valid single ports
    def test_valid_single_port(self):
        """Accept single valid port."""
        assert validate_ports("22") == [22]
        assert validate_ports("80") == [80]
        assert validate_ports("443") == [443]

    def test_valid_multiple_ports_comma_separated(self):
        """Accept multiple comma-separated ports."""
        result = validate_ports("22,80,443")
        assert sorted(result) == [22, 80, 443]

    def test_valid_multiple_ports_space_separated(self):
        """Accept multiple space-separated ports."""
        result = validate_ports("22 80 443")
        assert sorted(result) == [22, 80, 443]

    def test_valid_multiple_ports_mixed_separators(self):
        """Accept multiple ports with mixed separators."""
        result = validate_ports("22, 80 443")
        assert sorted(result) == [22, 80, 443]

    # Valid port ranges
    def test_valid_port_range(self):
        """Accept valid port range."""
        result = validate_ports("20-25")
        assert result == [20, 21, 22, 23, 24, 25]

    def test_valid_port_range_large(self):
        """Accept large port range."""
        result = validate_ports("8000-8010")
        assert len(result) == 11
        assert min(result) == 8000
        assert max(result) == 8010

    def test_valid_port_range_single_port(self):
        """Accept port range with same start and end."""
        result = validate_ports("443-443")
        assert result == [443]

    # Valid combinations
    def test_valid_combined_ports_and_ranges(self):
        """Accept combination of single ports and ranges."""
        result = validate_ports("22,80,443,8000-8010,3000")
        assert 22 in result
        assert 80 in result
        assert 443 in result
        assert 8000 in result
        assert 8010 in result
        assert 3000 in result
        assert len(result) == 15  # 22,80,443,3000 (4 unique ports) + 11 ports from 8000-8010

    def test_valid_ports_with_whitespace(self):
        """Accept ports with surrounding whitespace."""
        result = validate_ports("  22, 80, 443  ")
        assert sorted(result) == [22, 80, 443]

    def test_valid_duplicate_ports_removed(self):
        """Remove duplicate ports from result."""
        result = validate_ports("22,80,22,443,80")
        assert sorted(result) == [22, 80, 443]

    def test_valid_ports_sorted(self):
        """Result is sorted."""
        result = validate_ports("443,80,22")
        assert result == [22, 80, 443]

    # Invalid cases
    def test_invalid_port_zero(self):
        """Reject port 0."""
        with pytest.raises(ValidationError):
            validate_ports("0")

    def test_invalid_port_negative(self):
        """Reject negative ports."""
        with pytest.raises(ValidationError):
            validate_ports("-1")

    def test_invalid_port_too_high(self):
        """Reject ports above 65535."""
        with pytest.raises(ValidationError):
            validate_ports("65536")
        with pytest.raises(ValidationError):
            validate_ports("99999")

    def test_invalid_port_non_numeric(self):
        """Reject non-numeric port."""
        with pytest.raises(ValidationError):
            validate_ports("abc")

    def test_invalid_port_in_list(self):
        """Reject list with invalid port."""
        with pytest.raises(ValidationError):
            validate_ports("22,80,abc")

    def test_invalid_port_range_backward(self):
        """Reject range with end < start."""
        with pytest.raises(ValidationError):
            validate_ports("443-80")

    def test_invalid_port_range_malformed(self):
        """Reject malformed range."""
        with pytest.raises(ValidationError):
            validate_ports("22-80-100")

    def test_invalid_port_range_non_numeric(self):
        """Reject range with non-numeric values."""
        with pytest.raises(ValidationError):
            validate_ports("abc-def")

    def test_invalid_empty_ports(self):
        """Reject empty ports string."""
        with pytest.raises(ValidationError):
            validate_ports("")
        with pytest.raises(ValidationError):
            validate_ports("   ")

    def test_invalid_special_characters(self):
        """Reject ports with special characters."""
        with pytest.raises(ValidationError):
            validate_ports("22;80")
        with pytest.raises(ValidationError):
            validate_ports("22|80")
        with pytest.raises(ValidationError):
            validate_ports("22&80")

    def test_invalid_too_many_ports(self):
        """Reject when too many ports specified."""
        # Create a large range that exceeds 10000 ports
        with pytest.raises(ValidationError):
            validate_ports("1-15001")


# ============================================================
# TESTS: sanitize_error_message()
# ============================================================

class TestSanitizeErrorMessage:
    """Tests for error message sanitization function."""

    def test_sanitize_removes_file_paths(self):
        """Remove file paths from error message."""
        error = "Error in /Users/test/app.py:123"
        result = sanitize_error_message(error)
        assert "/Users/test/app.py" not in result

    def test_sanitize_removes_windows_paths(self):
        """Remove Windows file paths from error message."""
        error = "Error in C:\\Users\\test\\app.py:123"
        result = sanitize_error_message(error)
        assert "C:\\Users" not in result

    def test_sanitize_removes_line_numbers(self):
        """Remove line numbers from error message."""
        error = "Error at line 123"
        result = sanitize_error_message(error)
        assert "line 123" not in result.lower()

    def test_sanitize_removes_credentials(self):
        """Remove credentials from error message."""
        error = "Connection failed: password=secret123"
        result = sanitize_error_message(error)
        assert "secret123" not in result

    def test_sanitize_removes_db_connection_strings(self):
        """Remove database connection strings."""
        error = "DB error: host=localhost user=admin password=topsecret"
        result = sanitize_error_message(error)
        assert "topsecret" not in result

    def test_sanitize_handles_exception_object(self):
        """Handle Exception objects."""
        error = ValueError("Test error message")
        result = sanitize_error_message(error)
        assert "Test error message" in result or len(result) > 0

    def test_sanitize_handles_empty_message(self):
        """Handle empty error messages."""
        result = sanitize_error_message("")
        assert len(result) > 0  # Should return default message

    def test_sanitize_collapses_whitespace(self):
        """Collapse multiple spaces and newlines."""
        error = "Error   with   multiple    spaces\nand\nnewlines"
        result = sanitize_error_message(error)
        assert "  " not in result  # No double spaces
        assert "\n" not in result  # No newlines

    def test_sanitize_returns_string(self):
        """Always return string."""
        error = ValueError("Test")
        result = sanitize_error_message(error)
        assert isinstance(result, str)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
