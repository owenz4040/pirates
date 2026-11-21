"""Symmetric encryption utilities for tenant API secrets at rest."""
from __future__ import annotations

import base64
import os
from cryptography.fernet import Fernet, InvalidToken

from saas.config import saas_settings


def _get_fernet(key: str | None = None) -> Fernet:
    k = key or saas_settings.encryption_master_key
    # Ensure key is 32 url-safe base64-encoded bytes
    if not k:
        raise ValueError("Encryption master key is not configured.")
    try:
        return Fernet(k.encode() if isinstance(k, str) else k)
    except Exception as e:
        # Fallback to hash-derived key if raw string was passed
        import hashlib
        derived = base64.urlsafe_b64encode(hashlib.sha256(k.encode()).digest())
        return Fernet(derived)


def encrypt_secret(plaintext: str | None, key: str | None = None) -> str:
    """Encrypt a sensitive credential string (e.g. Daraja Passkey, Paystack Secret Key)."""
    if not plaintext:
        return ""
    f = _get_fernet(key)
    return f.encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt_secret(ciphertext: str | None, key: str | None = None) -> str:
    """Decrypt an encrypted credential string. Returns empty string if ciphertext is empty."""
    if not ciphertext:
        return ""
    f = _get_fernet(key)
    try:
        return f.decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        raise ValueError("Invalid encryption key or corrupted ciphertext")
