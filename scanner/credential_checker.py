import requests
from requests.auth import HTTPBasicAuth

ALLOWED_TARGETS = [
    "127.0.0.1",
    "localhost"
]

DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("root", "root")
]

def check_default_credentials(target: str, port: int):

    if target not in ALLOWED_TARGETS:
        return {
            "allowed": False,
            "message": "Credential checks not allowed on this target."
        }

    url = f"http://{target}:{port}"

    findings = []

    try:
        # First check whether auth is required
        initial_response = requests.get(url, timeout=3)

        auth_header = initial_response.headers.get("WWW-Authenticate")

        if initial_response.status_code != 401 or not auth_header:
            return {
                "allowed": True,
                "message": "No HTTP authentication detected.",
                "findings": []
            }

    except Exception as e:
        return {
            "allowed": True,
            "message": str(e),
            "findings": []
        }

    # Only attempt credentials if auth is actually required
    for username, password in DEFAULT_CREDS:

        try:
            response = requests.get(
                url,
                auth=HTTPBasicAuth(username, password),
                timeout=3
            )

            if response.status_code == 200:

                findings.append({
                    "username": username,
                    "password": password,
                    "success": True
                })

        except Exception:
            pass

    return {
        "allowed": True,
        "findings": findings
    }