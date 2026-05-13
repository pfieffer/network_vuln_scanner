import argparse
import base64
import getpass
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Tuple

ROOT_PATH = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_PATH))

from scanner.credential_store import load_default_credentials

DEFAULT_STORE_PATH = Path(__file__).resolve().parents[1] / "scanner" / "default_creds.enc"
DEFAULT_HOST = "localhost"
DEFAULT_PORT = 8081
USERNAME = None
PASSWORD = None


class AuthHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        auth_header = self.headers.get("Authorization")
        expected = "Basic " + base64.b64encode(
            f"{USERNAME}:{PASSWORD}".encode()
        ).decode()

        if auth_header == expected:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Authenticated!")
        else:
            self.send_response(401)
            self.send_header(
                "WWW-Authenticate",
                'Basic realm="Secure Area"'
            )
            self.end_headers()
            self.wfile.write(b"Authentication required")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Start a basic auth server using encrypted credentials.")
    parser.add_argument(
        "--cred-password",
        help="Password to decrypt the encrypted credential store.",
    )
    parser.add_argument(
        "--store",
        default=DEFAULT_STORE_PATH,
        help="Path to the encrypted credential store file.",
    )
    parser.add_argument(
        "--credential-index",
        type=int,
        default=0,
        help="Index of the credential pair to use from the decrypted store.",
    )
    parser.add_argument(
        "--host",
        default=DEFAULT_HOST,
        help="Host address to bind the server to.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help="Port to bind the server to.",
    )
    return parser.parse_args()


def load_credentials(store_path: Path, password: str, index: int) -> Tuple[str, str]:
    creds = load_default_credentials(password, store_path)
    if index < 0 or index >= len(creds):
        raise IndexError("Credential index is out of range.")
    return creds[index]


def main():
    global USERNAME, PASSWORD

    args = parse_args()
    credential_password = args.cred_password
    if credential_password is None:
        credential_password = getpass.getpass("Credential store password: ")

    store_path = Path(args.store)
    if not store_path.exists():
        raise FileNotFoundError(f"Encrypted credential store not found: {store_path}")

    USERNAME, PASSWORD = load_credentials(store_path, credential_password, args.credential_index)

    server = HTTPServer((args.host, args.port), AuthHandler)
    print(f"Basic Auth server running on http://{args.host}:{args.port}")
    print(f"Username: {USERNAME}")
    print(f"Password: {PASSWORD}")
    server.serve_forever()


if __name__ == "__main__":
    main()
