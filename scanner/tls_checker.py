import ssl
import socket

def check_tls(host: str, port: int = 443):
    context = ssl.create_default_context()

    try:
        with socket.create_connection((host, port)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                return {
                    "valid": True,
                    "issuer": cert.get("issuer"),
                    "expiry": cert.get("notAfter"),
                }
    except ssl.SSLError:
        return {"valid": False, "error": "SSL Error"}
    except Exception as e:
        return {"valid": False, "error": str(e)}