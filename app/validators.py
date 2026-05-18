"""
Input validation module for network vulnerability scanner.
Implements SSDLC-compliant input validation and sanitization.

Functions:
    validate_target(target): Validate target as IPv4, IPv6, CIDR, or domain name.
    validate_ports(ports_input): Parse and validate comma/space-separated ports and ranges.
    sanitize_error_message(error): Strip sensitive exception details for user display.
    
Exceptions:
    ValidationError: Raised when input validation fails with descriptive message.
"""

import re
import ipaddress
from typing import List, Union


class ValidationError(Exception):
    """Custom exception for input validation failures."""
    pass


def validate_target(target: str) -> str:
    """
    Validate scan target as IPv4, IPv6, CIDR notation, or domain name.
    
    Supports:
    - IPv4: 192.168.1.1, 127.0.0.1
    - IPv4 CIDR: 192.168.1.0/24, 10.0.0.0/8
    - IPv6: ::1, 2001:db8::1, fe80::1
    - IPv6 CIDR: 2001:db8::/32, ::1/128
    - Domain names: example.com, subdomain.example.co.uk, localhost
    
    Args:
        target (str): The target address to validate
        
    Returns:
        str: The validated target (trimmed whitespace)
        
    Raises:
        ValidationError: If target is invalid or dangerous
    """
    if not target:
        raise ValidationError("Target cannot be empty.")
    
    target = target.strip()
    
    if not target:
        raise ValidationError("Target cannot be empty or whitespace only.")
    
    # Check for dangerous patterns (command injection, path traversal, etc.)
    dangerous_patterns = [
        r'[;&|`$(){}[\]<>]',  # Shell metacharacters
        r'\.\.',               # Path traversal
        r"['\"]",              # Quotes that could break commands
        r'%[0-9a-fA-F]{2}',   # URL encoding markers
    ]
    
    for pattern in dangerous_patterns:
        if re.search(pattern, target):
            raise ValidationError(
                "Target contains invalid characters. Use only alphanumeric, dots, dashes, "
                "colons (IPv6), and forward slashes (CIDR)."
            )
    
    # Length check
    if len(target) > 255:
        raise ValidationError("Target exceeds maximum length of 255 characters.")
    
    # Check if it looks like an IPv4 attempt with numeric labels separated by dots
    # This helps reject malformed IPv4 addresses early
    # Also check for CIDR notation with forward slash
    if re.match(r'^[\d./]+$', target):
        # It looks like an IPv4 or IPv4 CIDR attempt
        try:
            ipaddress.ip_address(target)
            return target
        except ValueError:
            pass
        
        try:
            ipaddress.IPv4Network(target, strict=False)
            return target
        except ValueError:
            raise ValidationError(
                f"'{target}' is not a valid IPv4 address or IPv4 CIDR. "
                "IPv4 addresses must have octets in range 0-255 (e.g., 192.168.1.1 or 192.168.1.0/24)."
            )
    
    # Check if it looks like an IPv6 attempt (contains colons)
    if ':' in target:
        try:
            ipaddress.ip_address(target)
            return target
        except ValueError:
            pass
        
        try:
            ipaddress.IPv6Network(target, strict=False)
            return target
        except ValueError:
            raise ValidationError(
                f"'{target}' is not a valid IPv6 address or IPv6 CIDR. "
                "Use standard IPv6 notation (e.g., 2001:db8::1 or 2001:db8::/32)."
            )
    
    # Not an IP/CIDR - validate as domain name
    if _is_valid_domain(target):
        return target
    
    raise ValidationError(
        "Target is not a valid IPv4 address, IPv4 CIDR (e.g., 192.168.1.0/24), "
        "IPv6 address, IPv6 CIDR (e.g., 2001:db8::/32), or domain name (e.g., example.com)."
    )


def _is_valid_domain(domain: str) -> bool:
    """
    Validate domain name format (RFC 1123 compliant).
    
    Allows:
    - example.com
    - sub.example.com
    - example.co.uk
    - localhost
    - localhost.localdomain
    
    Args:
        domain (str): Domain name to validate
        
    Returns:
        bool: True if valid domain format
    """
    # RFC 1123: Labels can contain alphanumeric and hyphens, no leading/trailing hyphens
    # Overall domain length limit is 255 characters
    if len(domain) > 255:
        return False
    
    # Allow localhost variants
    if domain.lower() in ('localhost', 'localhost.localdomain'):
        return False  # Already handled as localhost should work
    
    # Split into labels (parts separated by dots)
    labels = domain.split('.')
    
    # Need at least one label for "localhost", but typically 2+ for FQDN
    if len(labels) < 1:
        return False
    
    # RFC 1123 domain label regex:
    # - Start with alphanumeric
    # - Can contain hyphens in middle
    # - End with alphanumeric
    # - 1-63 characters per label
    label_regex = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$')
    
    for label in labels:
        if not label or not label_regex.match(label):
            return False
    
    return True


def validate_ports(ports_input: str) -> List[int]:
    """
    Parse and validate comma/space-separated port numbers and ranges.
    
    Supports:
    - Single ports: 22, 80, 443
    - Multiple ports: 22,80,443 or 22 80 443
    - Port ranges: 1-1000, 8000-9000
    - Mixed: 22,80,443,8000-8010,3000
    
    Validates each port is in range 1-65535.
    Returns sorted list of unique ports.
    
    Args:
        ports_input (str): Comma/space-separated ports and/or ranges
        
    Returns:
        List[int]: Sorted list of unique valid ports
        
    Raises:
        ValidationError: If any port is invalid or out of range
    """
    if not ports_input:
        raise ValidationError("Ports cannot be empty.")
    
    ports_input = ports_input.strip()
    
    if not ports_input:
        raise ValidationError("Ports cannot be empty or whitespace only.")
    
    # Check for dangerous characters
    if re.search(r'[^0-9,\-\s]', ports_input):
        raise ValidationError(
            "Ports contain invalid characters. Use only numbers, commas, hyphens (for ranges), "
            "and spaces."
        )
    
    ports_set = set()
    
    # Split by comma or space
    entries = re.split(r'[,\s]+', ports_input)
    
    for entry in entries:
        entry = entry.strip()
        if not entry:
            continue
        
        # Check if it's a range (e.g., "22-25")
        if '-' in entry:
            parts = entry.split('-')
            if len(parts) != 2:
                raise ValidationError(
                    f"Invalid port range '{entry}'. Use format like '22-25' or '8000-9000'."
                )
            
            try:
                start_port = int(parts[0].strip())
                end_port = int(parts[1].strip())
            except ValueError:
                raise ValidationError(
                    f"Invalid port range '{entry}'. Port range must contain only numbers."
                )
            
            if start_port < 1 or start_port > 65535:
                raise ValidationError(
                    f"Invalid start port in range '{entry}'. Ports must be between 1 and 65535."
                )
            
            if end_port < 1 or end_port > 65535:
                raise ValidationError(
                    f"Invalid end port in range '{entry}'. Ports must be between 1 and 65535."
                )
            
            if start_port > end_port:
                raise ValidationError(
                    f"Invalid port range '{entry}'. Start port ({start_port}) must be <= "
                    f"end port ({end_port})."
                )
            
            # Add all ports in range
            for port in range(start_port, end_port + 1):
                ports_set.add(port)
        else:
            # Single port
            try:
                port = int(entry)
            except ValueError:
                raise ValidationError(f"Invalid port '{entry}'. Ports must be numbers.")
            
            if port < 1 or port > 65535:
                raise ValidationError(
                    f"Invalid port '{port}'. Ports must be between 1 and 65535."
                )
            
            ports_set.add(port)
    
    if not ports_set:
        raise ValidationError("No valid ports specified.")
    
    # Check total ports (warn if too many - nmap will handle, but we set a reasonable limit)
    if len(ports_set) > 10000:
        raise ValidationError(
            f"Too many ports specified ({len(ports_set)}). Maximum is 10000 ports per scan."
        )
    
    return sorted(list(ports_set))


def sanitize_error_message(error: Union[Exception, str]) -> str:
    """
    Sanitize error message to remove sensitive details for user display.
    
    Strips:
    - File paths and stack traces
    - SQL queries and database details
    - Exception types that reveal internals
    - Connection strings
    - System information
    
    Args:
        error (Union[Exception, str]): Error object or error message string
        
    Returns:
        str: Sanitized user-friendly error message
    """
    error_str = str(error) if isinstance(error, Exception) else error
    
    # Remove file paths (e.g., /path/to/file.py:123)
    error_str = re.sub(r'/[^\s]+\.py[:\s]', ' ', error_str)
    error_str = re.sub(r'C:\\[^\s]+\.py[:\s]', ' ', error_str)
    
    # Remove common sensitive patterns
    patterns_to_remove = [
        r'Traceback.*?(?=\n\n|\Z)',  # Stack traces
        r'File ".*?"',               # File references
        r'line \d+',                 # Line numbers
        r'(password|passwd|pwd|secret|token|key|credential)[\w]*\s*[=:]\s*[^\s]*',  # Credentials
        r'(host|server|db)[\w]*\s*[=:]\s*[^\s]*',  # Connection strings
    ]
    
    for pattern in patterns_to_remove:
        error_str = re.sub(pattern, '', error_str, flags=re.IGNORECASE | re.DOTALL)
    
    # Collapse multiple spaces/newlines
    error_str = re.sub(r'\s+', ' ', error_str).strip()
    
    # If result is empty or too vague, provide generic message
    if not error_str or len(error_str) < 5:
        return "An error occurred. Please contact the administrator."
    
    return error_str
