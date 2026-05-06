import socket

def identify_service(host: str, port: int) -> dict:
    result = {
        "service": "unknown",
        "banner": ""
    }

    try:
        with socket.socket() as s:
            s.settimeout(2)
            s.connect((host, port))

            # HTTP
            if port in [80, 8080]:
                request = f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n"
                s.send(request.encode())
                data = s.recv(1024).decode(errors="ignore")

                result["banner"] = data
                if "HTTP" in data:
                    result["service"] = "http"

            # HTTPS (handled separately usually)
            elif port == 443:
                result["service"] = "https"

            # SSH (auto banner)
            elif port == 22:
                data = s.recv(1024).decode(errors="ignore")
                result["banner"] = data
                if "SSH" in data:
                    result["service"] = "ssh"

            # FTP
            elif port == 21:
                data = s.recv(1024).decode(errors="ignore")
                result["banner"] = data
                if "FTP" in data:
                    result["service"] = "ftp"

    except Exception:
        pass

    return result