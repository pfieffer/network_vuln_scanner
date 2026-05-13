import argparse
import getpass
import sys
from pathlib import Path

ROOT_PATH = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_PATH))

from scanner.port_scanner import scan_ports
from scanner.service_detector import identify_service
from scanner.tls_checker import check_tls
from scanner.credential_checker import check_default_credentials


def main():
    parser = argparse.ArgumentParser(description="Run the network vulnerability scanner.")
    parser.add_argument("target", help="Target hostname or IP address to scan.")
    parser.add_argument(
        "--cred-password",
        help="Password used to decrypt the encrypted default credential store.",
    )
    args = parser.parse_args()

    credential_password = args.cred_password
    if credential_password is None:
        credential_password = getpass.getpass(
            "Credential store password (leave blank to skip default credential checks): "
        )
        if credential_password == "":
            credential_password = None

    target = args.target
    ports = [22, 80, 443, 4443, 8000, 8081]

    open_ports = scan_ports(target, ports)
    print(f"Open ports on {target}: {open_ports}")

    for port in open_ports:
        if port in [443, 4443]:
            print(f"[{port}] Service: https")
            tls = check_tls(target, port)
            print(f"[{port}] TLS Info: {tls}")
        else:
            service_info = identify_service(target, port)
            print(f"[{port}] Service: {service_info['service']}")
            print(f"[{port}] Banner: {service_info['banner']}")

            if service_info["service"] == "http":
                creds = check_default_credentials(target, port, credential_password)
                print(f"[{port}] Credential Check: {creds}")


if __name__ == "__main__":
    main()
