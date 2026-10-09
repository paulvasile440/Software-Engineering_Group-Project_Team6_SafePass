import base64
import hashlib
import hmac
import os
from cryptography.fernet import Fernet, InvalidToken

PBKDF2_ITERATIONS = 390_000


def generate_salt() -> bytes:
    return os.urandom(16)


def derive_key(master_password: str, salt: bytes) -> bytes:
    """Derive a Fernet-compatible key from the master password."""
    raw_key = hashlib.pbkdf2_hmac(
        "sha256",
        master_password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
        dklen=32,
    )
    return base64.urlsafe_b64encode(raw_key)


def create_verifier(master_password: str, salt: bytes) -> bytes:
    """Create a verifier without storing the master password."""
    return hashlib.pbkdf2_hmac(
        "sha256",
        master_password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
        dklen=32,
    )


def verify_master_password(master_password: str, salt: bytes, stored_verifier: bytes) -> bool:
    candidate = create_verifier(master_password, salt)
    return hmac.compare_digest(candidate, stored_verifier)


def encrypt_text(text: str, key: bytes) -> str:
    fernet = Fernet(key)
    return fernet.encrypt(text.encode("utf-8")).decode("utf-8")


def decrypt_text(token: str, key: bytes) -> str:
    fernet = Fernet(key)
    try:
        return fernet.decrypt(token.encode("utf-8")).decode("utf-8")
    except InvalidToken as exc:
        raise ValueError("Unable to decrypt stored data.") from exc
