"""Tests for cryptographic security and tenant credential encryption at rest."""
from __future__ import annotations

import pytest
from cryptography.fernet import InvalidToken
from sqlalchemy import select
from sqlalchemy.orm import Session

from saas.models.payments import TenantPaymentConfig
from saas.security.auth import (
    generate_secure_token,
    hash_password,
    hash_token,
    verify_password,
)
from saas.security.crypto import decrypt_secret, encrypt_secret


def test_symmetric_encryption_decryption():
    """Verify that plaintext strings encrypt and decrypt cleanly."""
    original_secret = "sandbox_secret_key_abcdef123456789"
    ciphertext = encrypt_secret(original_secret)

    assert ciphertext != original_secret
    assert len(ciphertext) > len(original_secret)

    decrypted = decrypt_secret(ciphertext)
    assert decrypted == original_secret


def test_encryption_ciphertext_is_non_deterministic():
    """Fernet includes a timestamp and random IV: two encryptions of same secret must yield different ciphertexts."""
    secret = "daraja_consumer_key_12345"
    c1 = encrypt_secret(secret)
    c2 = encrypt_secret(secret)

    assert c1 != c2
    assert decrypt_secret(c1) == secret
    assert decrypt_secret(c2) == secret


def test_tampered_ciphertext_fails():
    """Modifying ciphertext must raise ValueError from decrypt_secret."""
    secret = "daraja_passkey"
    ciphertext = encrypt_secret(secret)
    tampered = ciphertext[:-4] + "AAAA"

    with pytest.raises(ValueError):
        decrypt_secret(tampered)


def test_tenant_payment_config_encryption_at_rest(db_session: Session, seed_data: dict):
    """
    Ensure that sensitive M-Pesa and Paystack credentials set on TenantPaymentConfig
    are stored encrypted in DB columns and never as plaintext.
    """
    tenant_a = seed_data["tenant_a"]
    raw_key = "daraja_raw_consumer_key"
    raw_secret = "daraja_raw_consumer_secret"
    raw_passkey = "daraja_raw_passkey"

    config = TenantPaymentConfig(tenant_id=tenant_a.id)
    config.set_mpesa_credentials(
        consumer_key=raw_key,
        consumer_secret=raw_secret,
        passkey=raw_passkey,
    )
    db_session.add(config)
    db_session.commit()
    db_session.refresh(config)

    # Check raw DB columns: must NOT contain the plaintext values
    assert config.mpesa_consumer_key_encrypted is not None
    assert raw_key not in config.mpesa_consumer_key_encrypted
    assert raw_secret not in config.mpesa_consumer_secret_encrypted
    assert raw_passkey not in config.mpesa_passkey_encrypted

    # Helper method decrypts cleanly
    creds = config.get_mpesa_credentials()
    assert creds["consumer_key"] == raw_key
    assert creds["consumer_secret"] == raw_secret
    assert creds["passkey"] == raw_passkey


def test_password_hashing_and_verification():
    """Verify PBKDF2 password hashing and verification."""
    password = "CorrectHorseBatteryStaple!"
    hashed = hash_password(password)

    assert hashed != password
    assert verify_password(password, hashed) is True
    assert verify_password("WrongPassword!", hashed) is False


def test_token_generation_and_hashing():
    """Verify secure random token generation and SHA-256 token hashing."""
    token = generate_secure_token(32)
    assert len(token) >= 32

    token_hash_1 = hash_token(token)
    token_hash_2 = hash_token(token)

    assert len(token_hash_1) == 64  # SHA-256 hex string
    assert token_hash_1 == token_hash_2
