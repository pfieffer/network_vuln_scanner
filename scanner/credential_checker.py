import requests
from requests.auth import HTTPBasicAuth

DEFAULT_CREDS = [
    ('admin', 'admin'),
    ('admin', 'password'),
    ('admin', '1234'),
    ('root', 'root'),
    ('root', 'toor'),
    ('user', 'user'),
    ('test', 'test'),
]

def check_default_credentials(target, port=80, timeout=3):
    """Try default credentials on HTTP services."""
    findings = []
    protocol = 'http' if port == 80 else 'https'
    base_url = f"{protocol}://{target}:{port}"
    
    for username, password in DEFAULT_CREDS:
        try:
            url = f"{base_url}/"
            response = requests.get(
                url,
                auth=HTTPBasicAuth(username, password),
                timeout=timeout,
                verify=False
            )
            
            if response.status_code == 200:
                findings.append({
                    'username': username,
                    'password': password,
                    'url': url,
                    'status': response.status_code
                })
                
        except requests.exceptions.RequestException:
            continue
    
    return {
        'findings': findings,
        'total_checked': len(DEFAULT_CREDS),
        'vulnerable': len(findings) > 0
    }
