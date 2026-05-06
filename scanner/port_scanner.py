import socket
from typing import List

DEFAULT_TIMEOUT = 2

def scan_port(host: str, port: int) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(DEFAULT_TIMEOUT)
            result = s.connect_ex((host, port))
            return result == 0
    except Exception:
        return False


def scan_ports(host: str, ports: List[int]) -> List[int]:
    open_ports = []
    for port in ports:
        if scan_port(host, port):
            open_ports.append(port)
    return open_ports