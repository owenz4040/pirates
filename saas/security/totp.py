"""RFC 6238 Standard Time-Based One-Time Password (TOTP) Implementation."""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
import urllib.parse


def generate_totp_secret() -> str:
    """Generates a cryptographically random Base32 encoded 160-bit secret."""
    raw_bytes = secrets.token_bytes(20)
    return base64.b32encode(raw_bytes).decode("utf-8").replace("=", "")


def get_totp_code(secret: str, timestamp: float | None = None, interval: int = 30) -> str:
    """Computes the 6-digit TOTP code for a given timestamp according to RFC 6238."""
    if timestamp is None:
        timestamp = time.time()

    clean_secret = secret.replace(" ", "").upper()
    # Add padding if needed
    missing_padding = len(clean_secret) % 8
    if missing_padding:
        clean_secret += "=" * (8 - missing_padding)

    key = base64.b32decode(clean_secret)
    counter = int(timestamp // interval)
    msg = struct.pack(">Q", counter)

    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = (
        (digest[offset] & 0x7F) << 24
        | (digest[offset + 1] & 0xFF) << 16
        | (digest[offset + 2] & 0xFF) << 8
        | (digest[offset + 3] & 0xFF)
    )
    return f"{code_int % 1000000:06d}"


def verify_totp(secret: str, code: str, window: int = 1, interval: int = 30) -> bool:
    """
    Validates a 6-digit TOTP code against the secret.
    Allows clock drift within +/- window intervals (default +/- 30s).
    """
    clean_code = code.strip().replace(" ", "")
    if len(clean_code) != 6 or not clean_code.isdigit():
        return False

    now = time.time()
    for drift in range(-window, window + 1):
        candidate_time = now + (drift * interval)
        expected_code = get_totp_code(secret, timestamp=candidate_time, interval=interval)
        if hmac.compare_digest(expected_code, clean_code):
            return True
    return False


def get_totp_uri(secret: str, account_name: str, issuer: str = "COwen") -> str:
    """Constructs the standard otpauth:// URI for authenticator applications."""
    label = urllib.parse.quote(f"{issuer}:{account_name}")
    params = urllib.parse.urlencode({
        "secret": secret.replace(" ", "").upper(),
        "issuer": issuer,
        "algorithm": "SHA1",
        "digits": 6,
        "period": 30,
    })
    return f"otpauth://totp/{label}?{params}"
