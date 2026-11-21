"""Symmetric authenticated encryption utilities for tenant API secrets at rest.

Uses Fernet (AES-128-CBC with PKCS7 padding and HMAC-SHA256 authentication)
with MultiFernet support for zero-downtime key rotation.
"""
from __future__ import annotations

import base64
import hashlib
import os
from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from saas.config import saas_settings


def _build_single_fernet(k: str) -> Fernet:
    k = k.strip()
    try:
        return Fernet(k.encode() if isinstance(k, str) else k)
    except Exception:
        derived = base64.urlsafe_b64encode(hashlib.sha256(k.encode()).digest())
        return Fernet(derived)


def _get_fernet(key: str | None = None) -> Fernet | MultiFernet:
    raw = key or saas_settings.encryption_master_key
    if not raw:
        raise ValueError("Encryption master key is not configured.")

    # MultiFernet key rotation: support comma-separated keys (primary, fallback1, ...)
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    if len(parts) > 1:
        fernets = [_build_single_fernet(p) for p in parts]
        return MultiFernet(fernets)

    return _build_single_fernet(parts[0])


def encrypt_secret(plaintext: str | None, key: str | None = None) -> str:
    """Encrypt a sensitive credential string (e.g. Daraja Passkey, Paystack Secret Key).

    Always encrypts with the primary key.
    """
    if not plaintext:
        return ""
    f = _get_fernet(key)
    return f.encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt_secret(ciphertext: str | None, key: str | None = None) -> str:
    """Decrypt an encrypted credential string using primary or rotated fallback keys.

    Returns empty string if ciphertext is empty.
    """
    if not ciphertext:
        return ""
    f = _get_fernet(key)
    try:
        return f.decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        raise ValueError("Invalid encryption key or corrupted ciphertext")
