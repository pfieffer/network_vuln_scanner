import ssl
import socket

def check_tls(host: str, port: int = 443):

    contexts = [
        ssl.create_default_context(),
        ssl._create_unverified_context()
    ]

    for context in contexts:

        try:
            with socket.create_connection((host, port)) as sock:

                with context.wrap_socket(sock, server_hostname=host) as ssock:

                    cert = ssock.getpeercert()

                    request = f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n"
                    ssock.send(request.encode())

                    response = ssock.recv(1024).decode(errors="ignore")

                    return {
                        "valid": True,
                        "issuer": cert.get("issuer"),
                        "expiry": cert.get("notAfter"),
                        "response": response.split("\r\n")[0]
                    }

        except Exception:
            continue

    return {
        "valid": False,
        "error": "TLS handshake failed"
    }