import sys

from scanner.port_scanner import scan_ports
from scanner.service_detector import identify_service
from scanner.tls_checker import check_tls
from scanner.credential_checker import check_default_credentials

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 run_scan.py <target>")
        return

    target = sys.argv[1]
    ports = [22, 80, 443, 4443, 8000, 8081]

    open_ports = scan_ports(target, ports)
    print(f"Open ports on {target}: {open_ports}")

    for port in open_ports:
        # HTTPS ports
        if port in [443, 4443]:
            print(f"[{port}] Service: https")
            tls = check_tls(target, port)
            print(f"[{port}] TLS Info: {tls}")

        else:
            service_info = identify_service(target, port)
            print(f"[{port}] Service: {service_info['service']}")
            print(f"[{port}] Banner: {service_info['banner']}")

            # Default credential detection

            if service_info["service"] == "http":
                creds = check_default_credentials(target, port)
                print(f"[{port}] Credential Check: {creds}")

if __name__ == "__main__":
    main()