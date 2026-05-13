import json
import os
from pathlib import Path
from typing import List, Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

CREDENTIAL_STORE_PATH = Path(__file__).parent / "default_creds.enc"
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


def load_default_credentials(password: str, store_path: Optional[Path] = None) -> List[Tuple[str, str]]:
    if not password:
        raise ValueError("A password is required to decrypt the credential store.")

    credential_path = store_path or CREDENTIAL_STORE_PATH
    encrypted_data = credential_path.read_bytes()
    if len(encrypted_data) < SALT_SIZE + NONCE_SIZE:
        raise ValueError("Credential store file is invalid or incomplete.")

    salt = encrypted_data[:SALT_SIZE]
    nonce = encrypted_data[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ciphertext = encrypted_data[SALT_SIZE + NONCE_SIZE:]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except InvalidTag as exc:
        raise ValueError("Unable to decrypt credential store: invalid password or corrupted file.") from exc

    creds = json.loads(plaintext.decode("utf-8"))
    if not isinstance(creds, list) or not all(isinstance(item, list) and len(item) == 2 for item in creds):
        raise ValueError("Credential store format is not valid.")

    return [tuple(item) for item in creds]
