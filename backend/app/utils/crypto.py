"""
app/utils/crypto.py

Cryptographic utilities for protecting sensitive credentials at rest.

Design decisions:
- Uses Fernet (symmetric authenticated encryption: AES-128-CBC + HMAC-SHA256).
- Derives a 32-byte URL-safe base64 key deterministically from settings.secret_key
  using SHA-256. This avoids needing separate key management configuration for MVP
  while guaranteeing a valid, cryptographically strong Fernet key.
- Guarantees confidentiality and integrity: tampered ciphertext will fail HMAC
  verification and raise an error rather than returning corrupt data.
"""

import base64
import hashlib
from typing import Optional
from cryptography.fernet import Fernet, InvalidToken
from app.config import settings


def _get_fernet() -> Fernet:
    """Derives a deterministic 32-byte base64 Fernet key from the application secret_key."""
    key_digest = hashlib.sha256(settings.secret_key.encode("utf-8")).digest()
    fernet_key = base64.urlsafe_b64encode(key_digest)
    return Fernet(fernet_key)


def encrypt_secret(plaintext: Optional[str]) -> Optional[str]:
    """
    Encrypts a plaintext secret into an authenticated ciphertext string.
    Returns None if input is None.
    """
    if plaintext is None:
        return None
    if not isinstance(plaintext, str):
        plaintext = str(plaintext)
    f = _get_fernet()
    encrypted_bytes = f.encrypt(plaintext.encode("utf-8"))
    return encrypted_bytes.decode("utf-8")


def decrypt_secret(ciphertext: Optional[str]) -> Optional[str]:
    """
    Decrypts an authenticated ciphertext string back into plaintext.
    Returns None if input is None.
    Raises ValueError if ciphertext was tampered with or key is invalid.
    """
    if ciphertext is None:
        return None
    f = _get_fernet()
    try:
        decrypted_bytes = f.decrypt(ciphertext.encode("utf-8"))
        return decrypted_bytes.decode("utf-8")
    except InvalidToken as exc:
        raise ValueError(
            "Decryption failed: Ciphertext is corrupted, tampered with, or encrypted with a different key."
        ) from exc
