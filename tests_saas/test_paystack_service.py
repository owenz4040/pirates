"""Unit tests for platform Paystack API client and signature verification."""
from __future__ import annotations

import hashlib
import hmac

import pytest

from saas.services.paystack import (
    PaystackPlatformError,
    _headers,
    verify_signature,
)


def test_verify_signature_standard_and_legacy():
    """Safeguard 1: Tests HMAC-SHA512 webhook signature verification with case variations and trimming."""
    secret_key = "sk_test_platform_secret_key_12345"
    raw_payload = b'{"event":"charge.success","data":{"reference":"sub_test_123"}}'
    
    # Calculate valid HMAC-SHA512
    valid_sig = hmac.new(secret_key.encode("utf-8"), raw_payload, hashlib.sha512).hexdigest()

    # 1. Lowercase standard
    assert verify_signature(raw_payload, valid_sig.lower(), secret_key=secret_key) is True

    # 2. Uppercase
    assert verify_signature(raw_payload, valid_sig.upper(), secret_key=secret_key) is True

    # 3. Whitespace around header
    assert verify_signature(raw_payload, f"  {valid_sig} \n", secret_key=secret_key) is True

    # 4. Tampered body
    tampered_body = b'{"event":"charge.success","data":{"reference":"sub_test_999"}}'
    assert verify_signature(tampered_body, valid_sig, secret_key=secret_key) is False

    # 5. Wrong key
    assert verify_signature(raw_payload, valid_sig, secret_key="sk_test_wrong_key") is False

    # 6. Empty / None signature
    assert verify_signature(raw_payload, "", secret_key=secret_key) is False
    assert verify_signature(raw_payload, None, secret_key=secret_key) is False


def test_headers_require_secret_key(monkeypatch):
    """Test that missing secret key raises PaystackPlatformError."""
    with pytest.raises(PaystackPlatformError):
        _headers(secret_key="")
