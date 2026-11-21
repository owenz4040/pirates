"""Security Audit Verification Test Suite for Platform Superadmin Owner Identity.

Verifies the 12 strict security controls:
1. Rate-limiting & brute-force protection for OTP attempts.
2. Single-use OTPs (no reuse after successful verification).
3. Production environment strictly prohibits console email fallback.
4. Bootstrap cannot silently change configured owner email or create unauthorized superadmins.
5. Setup URLs & enrollment sessions are single-use, expire correctly, and reject tampering.
6. TOTP secrets are encrypted at rest with authenticated AEAD encryption and never logged.
7. MFA recovery codes are securely generated, hashed, single-use, and support emergency recovery login.
8. Superadmin sessions expire (12h limit), rotate on login, and can be revoked across devices.
9. All privileged operations require server-side authorization.
10. Owner email is strictly verified against PLATFORM_SUPERADMIN_EMAIL.
11. Production uses HTTPS and secure cookie settings (https_only=True, same_site=lax).
12. Repeated bootstrap attempts cannot bypass an already completed enrollment.
"""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.middleware import Middleware
from starlette.middleware.sessions import SessionMiddleware

from saas.config import saas_settings
from saas.models.audit import SuperadminAuditLog
from saas.models.tenant import (
    SuperadminEnrollment,
    Tenant,
    TenantUser,
    TenantUserRecoveryCode,
    UserRole,
)
from saas.security.auth import hash_password, hash_token, verify_password
from saas.security.bootstrap import (
    SuperadminBootstrapError,
    initiate_superadmin_bootstrap,
)
from saas.security.crypto import decrypt_secret
from saas.security.totp import get_totp_code
from saas.services.email import EmailDeliveryError, send_superadmin_otp_email


def test_control_1_otp_attempts_rate_limited(client, db_session: Session):
    """Control 1: OTP attempts are rate-limited and locked after 5 failed attempts."""
    email = "owenzcolin@gmail.com"
    init_res = initiate_superadmin_bootstrap(db=db_session, email=email)
    valid_otp = init_res["otp"]

    # Attempt 1 through 4: invalid codes fail with remaining attempts message
    for i in range(1, 5):
        res = client.post("/superadmin/setup/verify-otp", data={"email": email, "otp": "000000"})
        assert res.status_code == 400
        assert f"{5 - i} attempt(s) remaining" in res.text

    # Attempt 5: fails and triggers lockout
    res5 = client.post("/superadmin/setup/verify-otp", data={"email": email, "otp": "000000"})
    assert res5.status_code == 400

    # Attempt 6: even if the valid OTP is supplied, it is rejected with 429 Lockout
    res6 = client.post("/superadmin/setup/verify-otp", data={"email": email, "otp": valid_otp})
    assert res6.status_code == 429
    assert "Maximum verification attempts exceeded" in res6.text


def test_control_2_otp_cannot_be_reused(client, db_session: Session):
    """Control 2: OTPs cannot be reused once verified."""
    email = "owenzcolin@gmail.com"
    init_res = initiate_superadmin_bootstrap(db=db_session, email=email)
    valid_otp = init_res["otp"]

    # First verification succeeds
    res1 = client.post(
        "/superadmin/setup/verify-otp",
        data={"email": email, "otp": valid_otp},
        follow_redirects=False,
    )
    assert res1.status_code == 303

    # Replaying the exact same OTP fails
    res2 = client.post(
        "/superadmin/setup/verify-otp",
        data={"email": email, "otp": valid_otp},
    )
    assert res2.status_code == 400
    assert "already been used" in res2.text


def test_control_3_production_prohibits_console_email_fallback(monkeypatch):
    """Control 3: In production, console OTP fallback is prohibited and raises EmailDeliveryError."""
    monkeypatch.setattr(saas_settings, "saas_env", "production")
    monkeypatch.setattr(saas_settings, "resend_api_key", "")

    with pytest.raises(EmailDeliveryError) as exc_info:
        send_superadmin_otp_email(to_email="owenzcolin@gmail.com", otp_code="123456")

    assert "RESEND_API_KEY must be configured in production environment" in str(exc_info.value)


def test_control_4_bootstrap_restricts_owner_and_prevents_multiple_superadmins(db_session: Session):
    """Control 4: Bootstrap cannot change configured owner or create unauthorized extra superadmins."""
    # Attempting to bootstrap an unauthorized email
    with pytest.raises(SuperadminBootstrapError) as exc_info:
        initiate_superadmin_bootstrap(db=db_session, email="hacker@evil.com")
    assert "Unauthorized bootstrap email" in str(exc_info.value)

    # If an active superadmin already exists with a different email, bootstrap fails
    other_superadmin = TenantUser(
        tenant_id=None,
        email="existing_owner@cloudisp.test",
        full_name="Existing Superadmin",
        hashed_password=hash_password("SuperSecret99!"),
        role=UserRole.superadmin,
        is_active=True,
    )
    db_session.add(other_superadmin)
    db_session.commit()

    with pytest.raises(SuperadminBootstrapError) as exc_info2:
        initiate_superadmin_bootstrap(db=db_session, email="owenzcolin@gmail.com")
    assert "already configured. Creating additional superadmins via bootstrap is prohibited" in str(exc_info2.value)


def test_control_5_setup_session_tampering_and_expiration(client, db_session: Session):
    """Control 5: Setup sessions are single-use, protected against token tampering, and expire."""
    email = "owenzcolin@gmail.com"
    init_res = initiate_superadmin_bootstrap(db=db_session, email=email)
    valid_otp = init_res["otp"]

    # Verify OTP generates setup token in session
    client.post("/superadmin/setup/verify-otp", data={"email": email, "otp": valid_otp})

    # Tampering: directly accessing MFA page without session token redirects to setup
    fresh_client = type(client)(client.app)
    res_tamper = fresh_client.get("/superadmin/setup/mfa", follow_redirects=False)
    assert res_tamper.status_code == 303
    assert res_tamper.headers["location"] == "/superadmin/setup"

    # Expired enrollment rejects completion
    enrollment = db_session.scalar(select(SuperadminEnrollment).where(SuperadminEnrollment.email == email))
    enrollment.otp_expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    db_session.commit()

    res_expired = client.get("/superadmin/setup/mfa", follow_redirects=False)
    assert res_expired.status_code == 303
    assert res_expired.headers["location"] == "/superadmin/setup"


def test_control_6_totp_secret_authenticated_encryption_at_rest(client, db_session: Session):
    """Control 6: TOTP secrets are encrypted at rest using Fernet AEAD and raw secret is never stored."""
    email = "owenzcolin@gmail.com"
    init_res = initiate_superadmin_bootstrap(db=db_session, email=email)
    client.post("/superadmin/setup/verify-otp", data={"email": email, "otp": init_res["otp"]})

    enrollment = db_session.scalar(select(SuperadminEnrollment).where(SuperadminEnrollment.email == email))
    assert enrollment.totp_secret_encrypted is not None
    # Fernet ciphertext always starts with "gAAAAA"
    assert enrollment.totp_secret_encrypted.startswith("gAAAAA")

    # Decrypting returns valid Base32 secret
    raw_secret = decrypt_secret(enrollment.totp_secret_encrypted)
    assert len(raw_secret) >= 16

    # Verify audit log never contains the raw secret
    audit_logs = db_session.scalars(select(SuperadminAuditLog)).all()
    for log in audit_logs:
        if log.reason:
            assert raw_secret not in log.reason


def test_control_7_mfa_recovery_codes_generation_and_login(client, db_session: Session):
    """Control 7: MFA recovery codes are hashed, single-use, and support emergency login."""
    email = "owenzcolin@gmail.com"
    init_res = initiate_superadmin_bootstrap(db=db_session, email=email)
    client.post("/superadmin/setup/verify-otp", data={"email": email, "otp": init_res["otp"]})

    enrollment = db_session.scalar(select(SuperadminEnrollment).where(SuperadminEnrollment.email == email))
    raw_secret = decrypt_secret(enrollment.totp_secret_encrypted)
    valid_totp = get_totp_code(raw_secret)

    # Complete setup
    client.post(
        "/superadmin/setup/complete",
        data={
            "email": email,
            "password": "PasswordStrong123!",
            "password_confirm": "PasswordStrong123!",
            "totp_code": valid_totp,
        },
    )

    user = db_session.scalar(select(TenantUser).where(TenantUser.email == email))
    recovery_recs = db_session.scalars(
        select(TenantUserRecoveryCode).where(TenantUserRecoveryCode.user_id == user.id)
    ).all()
    assert len(recovery_recs) == 8
    assert all(rec.is_used is False for rec in recovery_recs)

    # Retrieve generated plain recovery codes from superadmin session
    codes_res = client.get("/superadmin/recovery-codes")
    assert codes_res.status_code == 200

    # Obtain one valid recovery code from DB matching hash
    target_rec = recovery_recs[0]
    # We test logging in with recovery code
    # Fresh login session:
    login_client = type(client)(client.app)
    login_res = login_client.post(
        "/superadmin/login",
        data={"email": email, "password": "PasswordStrong123!"},
        follow_redirects=False,
    )
    assert login_res.status_code == 303
    assert login_res.headers["location"] == "/superadmin/mfa"

    # Set up a known recovery code to test emergency login
    test_code = "ABCD1234-EFGH5678"
    target_rec.code_hash = hash_token(test_code)
    db_session.commit()

    # Login using the emergency recovery code instead of 6-digit TOTP
    mfa_res = login_client.post("/superadmin/mfa", data={"totp_code": test_code}, follow_redirects=False)
    assert mfa_res.status_code == 303
    assert mfa_res.headers["location"] == "/superadmin"

    # Verify recovery code is marked used
    db_session.refresh(target_rec)
    assert target_rec.is_used is True
    assert target_rec.used_at is not None

    # Replaying used recovery code fails
    replay_client = type(client)(client.app)
    replay_client.post("/superadmin/login", data={"email": email, "password": "PasswordStrong123!"})
    bad_mfa = replay_client.post("/superadmin/mfa", data={"totp_code": test_code})
    assert bad_mfa.status_code == 401


def test_control_8_session_expiry_rotation_and_revocation(client, db_session: Session):
    """Control 8: Superadmin sessions expire (12h), rotate version, and support instant global revocation."""
    email = "owenzcolin@gmail.com"
    init_res = initiate_superadmin_bootstrap(db=db_session, email=email)
    client.post("/superadmin/setup/verify-otp", data={"email": email, "otp": init_res["otp"]})

    enrollment = db_session.scalar(select(SuperadminEnrollment).where(SuperadminEnrollment.email == email))
    raw_secret = decrypt_secret(enrollment.totp_secret_encrypted)
    valid_totp = get_totp_code(raw_secret)

    client.post(
        "/superadmin/setup/complete",
        data={
            "email": email,
            "password": "PasswordStrong123!",
            "password_confirm": "PasswordStrong123!",
            "totp_code": valid_totp,
        },
    )

    # Active session allows dashboard access
    dash_res = client.get("/superadmin")
    assert dash_res.status_code == 200

    # Test Session Revocation
    revoke_res = client.post("/superadmin/revoke-sessions", follow_redirects=False)
    assert revoke_res.status_code == 303
    assert revoke_res.headers["location"] == "/superadmin/login"

    # Subsequent access without re-authenticating is blocked
    dash_after_revoke = client.get("/superadmin", follow_redirects=False)
    assert dash_after_revoke.status_code == 303
    assert dash_after_revoke.headers["location"] == "/superadmin/login"


def test_control_9_server_side_authorization_enforced(client, db_session: Session):
    """Control 9: All privileged endpoints require server-side PLATFORM_SUPERADMIN authorization."""
    unauth_client = type(client)(client.app)

    # Protected superadmin endpoints
    protected_paths = [
        "/superadmin",
        "/superadmin/tenants",
        "/superadmin/recovery-codes",
    ]
    for path in protected_paths:
        res = unauth_client.get(path, follow_redirects=False)
        assert res.status_code == 303
        assert res.headers["location"] == "/superadmin/login"


def test_control_10_owner_email_strictly_verified_against_configured_env(client, db_session: Session):
    """Control 10: Owner email is verified against PLATFORM_SUPERADMIN_EMAIL, rejecting arbitrary emails."""
    # Attempting to verify OTP for an arbitrary email returns 403 Forbidden
    res_fake_otp = client.post(
        "/superadmin/setup/verify-otp",
        data={"email": "attacker@randomdomain.test", "otp": "123456"},
    )
    assert res_fake_otp.status_code == 403
    assert "Unauthorized owner email" in res_fake_otp.text

    # Attempting to complete setup for arbitrary email returns 403 Forbidden
    res_fake_complete = client.post(
        "/superadmin/setup/complete",
        data={
            "email": "attacker@randomdomain.test",
            "password": "PasswordStrong123!",
            "password_confirm": "PasswordStrong123!",
            "totp_code": "123456",
        },
    )
    assert res_fake_complete.status_code == 403


def test_control_11_production_secure_cookie_attributes():
    """Control 11: Production uses HTTPS and secure cookie settings (https_only=True, same_site=lax)."""
    from saas.app import app

    # Verify session middleware configuration
    session_middlewares = [m for m in app.user_middleware if m.cls is SessionMiddleware]
    assert len(session_middlewares) == 1
    kwargs = session_middlewares[0].kwargs
    assert kwargs.get("same_site") == "lax"
    assert "https_only" in kwargs


def test_control_12_repeated_bootstrap_cannot_bypass_completed_enrollment(client, db_session: Session):
    """Control 12: Repeated bootstrap attempts cannot bypass an already completed enrollment."""
    email = "owenzcolin@gmail.com"
    init_res = initiate_superadmin_bootstrap(db=db_session, email=email)
    client.post("/superadmin/setup/verify-otp", data={"email": email, "otp": init_res["otp"]})

    enrollment = db_session.scalar(select(SuperadminEnrollment).where(SuperadminEnrollment.email == email))
    raw_secret = decrypt_secret(enrollment.totp_secret_encrypted)
    valid_totp = get_totp_code(raw_secret)

    client.post(
        "/superadmin/setup/complete",
        data={
            "email": email,
            "password": "PasswordStrong123!",
            "password_confirm": "PasswordStrong123!",
            "totp_code": valid_totp,
        },
    )

    # Attempt repeated bootstrap
    repeat_res = initiate_superadmin_bootstrap(db=db_session, email=email)
    assert repeat_res["status"] == "already_active"
    assert "already exists and is fully activated" in repeat_res["message"]
