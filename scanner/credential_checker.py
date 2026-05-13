import requests
from requests.auth import HTTPBasicAuth
from typing import List, Optional, Tuple

from .credential_store import load_default_credentials

ALLOWED_TARGETS = [
    "127.0.0.1",
    "localhost"
]


def check_default_credentials(target: str, port: int, credential_store_password: Optional[str] = None):
    if target not in ALLOWED_TARGETS:
        return {
            "allowed": False,
            "message": "Credential checks not allowed on this target.",
            "findings": []
        }

    if not credential_store_password:
        return {
            "allowed": False,
            "message": "Credential store password not provided.",
            "findings": []
        }

    try:
        default_creds: List[Tuple[str, str]] = load_default_credentials(credential_store_password)
    except Exception as exc:
        return {
            "allowed": False,
            "message": f"Could not decrypt credential store: {exc}",
            "findings": []
        }

    url = f"http://{target}:{port}"
    findings = []

    try:
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
            "allowed": False,
            "message": str(e),
            "findings": []
        }

    for username, password in default_creds:
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
        "message": "Credential check completed.",
        "findings": findings
    }
