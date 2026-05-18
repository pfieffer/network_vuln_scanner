"""Pure scanner utility functions — zero Flask dependencies."""

_missing = object()  # Sentinel: "no argument provided"


def calculate_severity(results):
    """Calculate severity based on findings."""
    score = 0

    if results.get('open_ports'):
        score += len(results['open_ports']) * 2

    tls_results = results.get('tls')
    if tls_results:
        if isinstance(tls_results, dict):
            first_value = next(iter(tls_results.values()), None)
            if isinstance(first_value, dict):
                if any(not port_data.get('valid', True) for port_data in tls_results.values()):
                    score += 10
            else:
                if not tls_results.get('valid', True):
                    score += 10
        elif not tls_results.get('valid', True):
            score += 10

    if results.get('creds') and results['creds'].get('vulnerable', False):
        score += 15

    if score >= 20:
        return 'critical'
    if score >= 10:
        return 'high'
    if score >= 5:
        return 'medium'
    return 'low'


def is_tls_candidate(port, service_info=_missing):
    """Return True if the port/service is likely TLS-capable.
    
    Args:
        port: int port number
        service_info: dict with 'service' and/or 'product' keys,
                     or _missing if not provided
    
    Returns:
        bool: True if TLS is likely
    """
    tls_ports = {443, 8443, 993, 995, 465, 636, 990, 992, 587}
    
    # Known TLS ports
    if port in tls_ports:
        if service_info is _missing:
            return True           # No info provided → assume yes
        if service_info is None or not service_info:
            return False          # Explicitly None/empty → no
        return True               # Service info provided → assume yes
    
    # Unknown port — need service info to decide
    if service_info is _missing or not service_info:
        return False
    
    service_name = str(service_info.get('service', '')).lower()
    product = str(service_info.get('product', '')).lower()
    tls_indicators = ('https', 'ssl', 'tls', 'ldaps', 'ftps', 'smtps', 'imaps', 'pop3s', 'secure')
    return any(keyword in service_name for keyword in tls_indicators) or \
           any(keyword in product for keyword in tls_indicators)
