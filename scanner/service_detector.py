import socket

def grab_banner(host: str, port: int) -> str:
    try:
        with socket.socket() as s:
            s.settimeout(2)
            s.connect((host, port))

            # Send HTTP request if it's a web port
            if port in [80, 8080]:
                request = f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n"
                s.send(request.encode())

            data = s.recv(1024)
            return data.decode(errors="ignore")

    except Exception:
        return "Unknown"