import sys

from scanner.port_scanner import scan_ports
from scanner.service_detector import grab_banner
from scanner.tls_checker import check_tls

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 run_scan.py <target>")
        return

    target = sys.argv[1]
    ports = [22, 80, 443]

    open_ports = scan_ports(target, ports)
    print(f"Open ports on {target}: {open_ports}")

    for port in open_ports:
        banner = grab_banner(target, port)
        print(f"[{port}] Banner: {banner}")

        if port == 443:
            tls = check_tls(target)
            print(f"[{port}] TLS Info: {tls}")

if __name__ == "__main__":
    main()