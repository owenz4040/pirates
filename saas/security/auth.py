"""Authentication, password hashing, and session verification."""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from typing import Tuple


def hash_password(password: str, salt: bytes | None = None) -> str:
    """Hash a password with PBKDF2-HMAC-SHA256 and a 16-byte random salt."""
    if salt is None:
        salt = secrets.token_bytes(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
    return f"{salt.hex()}:{key.hex()}"


def verify_password(plain_password: str, stored_hash: str) -> bool:
    """Verify a plain password against the stored salt:hash string."""
    try:
        salt_hex, key_hex = stored_hash.split(":")
        salt = bytes.fromhex(salt_hex)
        expected_key = bytes.fromhex(key_hex)
        computed_key = hashlib.pbkdf2_hmac("sha256", plain_password.encode("utf-8"), salt, 100_000)
        return hmac.compare_digest(expected_key, computed_key)
    except (ValueError, TypeError):
        return False


def generate_secure_token(nbytes: int = 32) -> str:
    """Generate a high-entropy URL-safe hex string."""
    return secrets.token_hex(nbytes)


def hash_token(token: str) -> str:
    """SHA-256 hash a router or API token before database storage."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
