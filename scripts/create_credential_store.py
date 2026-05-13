import argparse
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

DEFAULT_CREDS = [
    ["admin", "admin"],
    ["admin", "password"],
    ["root", "root"],
]

SALT_SIZE = 16
NONCE_SIZE = 12
KDF_ITERATIONS = 200_000


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def create_credential_store(password: str, output_path: Path) -> None:
    if not password:
        raise ValueError("Password is required to create the credential store.")

    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)

    plaintext = json.dumps(DEFAULT_CREDS).encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    output_path.write_bytes(salt + nonce + ciphertext)
    print(f"Encrypted credential store created at {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Create an encrypted credential store for the scanner.")
    parser.add_argument(
        "--password",
        required=True,
        help="Password used to encrypt the credential store.",
    )
    parser.add_argument(
        "--output",
        default=Path(__file__).resolve().parents[1] / "scanner" / "default_creds.enc",
        help="Path to write the encrypted credential store.",
    )
    args = parser.parse_args()
    create_credential_store(args.password, Path(args.output))


if __name__ == "__main__":
    main()
