"""
tests/test_encryption.py

Verification tests for credentials encryption at rest:
1. Fernet encryption and decryption round-trip.
2. Tamper resistance (HMAC integrity failure).
3. Raw database inspection: confirms ciphertext is stored on disk/database,
   and plaintext is never present in the raw database record.
4. Transparent ORM decryption: ensures the application gets plaintext when requested.
5. Data leak check: ensures secrets are omitted from model representation and schemas.
"""

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models.api_registry import APIRegistry
from app.schemas.api_registry import APIRegistryResponse
from app.utils.crypto import encrypt_secret, decrypt_secret


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        yield session
    finally:
        session.close()


class TestFernetCrypto:
    def test_encrypt_decrypt_roundtrip(self):
        plaintext = "sk_live_1234567890abcdef"
        ciphertext = encrypt_secret(plaintext)

        assert ciphertext is not None
        assert ciphertext != plaintext
        assert ciphertext.startswith("gAAAAA")  # Standard Fernet token prefix

        decrypted = decrypt_secret(ciphertext)
        assert decrypted == plaintext

    def test_handle_none_values(self):
        assert encrypt_secret(None) is None
        assert decrypt_secret(None) is None

    def test_tampered_ciphertext_fails(self):
        plaintext = "super_secret_token"
        ciphertext = encrypt_secret(plaintext)

        # Corrupt the ciphertext
        tampered = ciphertext[:-4] + "AAAA"

        with pytest.raises(ValueError, match="Decryption failed"):
            decrypt_secret(tampered)


class TestDatabaseEncryptionAtRest:
    def test_raw_db_stores_only_ciphertext(self, db_session):
        secret_token = "stripe_live_secret_key_998877"

        # 1. Save through SQLAlchemy ORM
        api = APIRegistry(
            name="Stripe Encrypted",
            base_url="https://api.stripe.com",
            auth_header_name="Authorization",
            auth_header_value=secret_token,
            endpoints=[],
        )
        db_session.add(api)
        db_session.commit()
        api_id = api.id

        # 2. Query RAW database table bypassing ORM TypeDecorator
        raw_result = db_session.execute(
            text("SELECT auth_header_value FROM api_registry WHERE id = :id"),
            {"id": api_id},
        ).fetchone()

        raw_stored_value = raw_result[0]

        # Security Assertions:
        # A. Plaintext must NOT exist anywhere in the raw database column
        assert secret_token not in raw_stored_value
        # B. Raw value must be an encrypted Fernet string
        assert raw_stored_value.startswith("gAAAAA")

        # 3. Query through ORM: transparent decryption
        db_session.expire_all()
        loaded_api = db_session.query(APIRegistry).filter_by(id=api_id).first()
        assert loaded_api.auth_header_value == secret_token

    def test_repr_and_schemas_do_not_leak_secret(self, db_session):
        secret_token = "sensitive_bearer_token_xyz"

        api = APIRegistry(
            name="GitHub API",
            base_url="https://api.github.com",
            auth_header_name="Authorization",
            auth_header_value=secret_token,
            endpoints=[],
        )
        db_session.add(api)
        db_session.commit()

        # Model __repr__ must not leak secret or ciphertext
        model_repr = repr(api)
        assert secret_token not in model_repr
        assert "gAAAAA" not in model_repr

        # Pydantic response schema must not leak secret
        resp = APIRegistryResponse.model_validate(api)
        dumped = resp.model_dump()

        assert "auth_header_value" not in dumped
        assert resp.has_auth is True
        assert secret_token not in str(dumped)
