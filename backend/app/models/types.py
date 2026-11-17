"""
app/models/types.py

Custom SQLAlchemy TypeDecorators.

EncryptedString:
Transparently encrypts string values when saving to the database (process_bind_param)
and decrypts them when reading from the database (process_result_value).
Guarantees encryption-at-rest for external API keys and authorization tokens.
"""

from sqlalchemy.types import TypeDecorator, Text
from app.utils.crypto import encrypt_secret, decrypt_secret


class EncryptedString(TypeDecorator):
    """
    SQLAlchemy TypeDecorator providing transparent authenticated encryption at rest.
    In the database: stored as Fernet ciphertext (Text).
    In Python memory: accessed as decrypted plaintext.
    """

    impl = Text
    cache_ok = True

    def process_bind_param(self, value, dialect):
        """Encrypts plaintext before storing in DB."""
        if value is not None:
            return encrypt_secret(value)
        return None

    def process_result_value(self, value, dialect):
        """Decrypts ciphertext upon retrieval from DB."""
        if value is not None:
            return decrypt_secret(value)
        return None
