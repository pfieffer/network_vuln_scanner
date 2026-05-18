import ssl
import socket
from datetime import datetime

def check_tls(target, ports, timeout=3):
    """Check TLS certificate validity on candidate ports."""
    results = {}
    
    for port in ports:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((target, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    subject = dict(x[0] for x in cert.get('subject', []))
                    san = cert.get('subjectAltName', [])
                    serial_number = cert.get('serialNumber')
                    
                    expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    
                    cipher = ssock.cipher()
                    results[port] = {
                        'valid': True,
                        'issuer': issuer.get('CommonName', 'Unknown'),
                        'subject': subject.get('CommonName', 'Unknown'),
                        'expiry': expiry_date.strftime('%Y-%m-%d'),
                        'version': cert.get('version'),
                        'protocol': ssock.version(),
                        'cipher': cipher[0] if cipher else None,
                        'cipher_bits': cipher[2] if cipher else None,
                        'subject_alt_names': [name for name in san if isinstance(name, tuple)],
                        'serial_number': serial_number,
                    }
                    print(f"  ✅ TLS valid on port {port}: {issuer.get('CommonName', 'Unknown')}")
                    
        except ssl.SSLError as e:
            results[port] = {'valid': False, 'error': str(e)}
            print(f"  ⚠️ TLS error on port {port}: {e}")
        except socket.timeout:
            results[port] = {'valid': False, 'error': 'Connection timeout'}
            print(f"  ⚠️ Timeout on port {port}")
        except Exception as e:
            results[port] = {'valid': False, 'error': str(e)}
            print(f"  ⚠️ Error on port {port}: {e}")
    
    return results
