"""Tests for Platform Superadmin Owner Identity bootstrap, email OTP, and mandatory TOTP MFA."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from saas.models.audit import SuperadminAuditLog
from saas.models.tenant import SuperadminEnrollment, TenantUser, UserRole
from saas.security.auth import hash_token, verify_password
from saas.security.bootstrap import initiate_superadmin_bootstrap
from saas.security.crypto import decrypt_secret
from saas.security.totp import get_totp_code, verify_totp


def test_cli_bootstrap_initiates_enrollment(db_session: Session):
    """Test that CLI bootstrap creates pending enrollment, dispatches OTP, and records audit log."""
    email = "owenzcolin@gmail.com"
    result = initiate_superadmin_bootstrap(db=db_session, email=email)

    assert result["status"] == "otp_dispatched"
    assert result["email"] == email
    otp = result["otp"]
    assert len(otp) == 6
    assert otp.isdigit()

    # Verify enrollment in DB (OTP is hashed, not plaintext)
    enrollment = db_session.scalar(
        select(SuperadminEnrollment).where(SuperadminEnrollment.email == email)
    )
    assert enrollment is not None
    assert enrollment.is_email_verified is False
    assert enrollment.is_completed is False
    assert enrollment.otp_hash == hash_token(otp)
    assert otp not in enrollment.otp_hash

    # Verify audit log entry
    audit = db_session.scalar(
        select(SuperadminAuditLog).where(
            SuperadminAuditLog.action == "superadmin.bootstrap_initiated",
            SuperadminAuditLog.target_id == enrollment.id,
        )
    )
    assert audit is not None
    assert audit.actor_email == "system.cli"


def test_cli_bootstrap_idempotent_no_duplicates(db_session: Session):
    """Test that repeated bootstrap does not duplicate active superadmin accounts."""
    email = "owenzcolin@gmail.com"

    # Simulate already active superadmin
    user = TenantUser(
        tenant_id=None,
        email=email,
        full_name="Platform Owner",
        hashed_password="hashed_dummy_pass",
        role=UserRole.superadmin,
        mfa_enabled=True,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()

    # Re-run bootstrap
    result = initiate_superadmin_bootstrap(db=db_session, email=email)
    assert result["status"] == "already_active"
    assert "already exists" in result["message"]

    # Verify only ONE user exists
    users = db_session.scalars(select(TenantUser).where(TenantUser.email == email)).all()
    assert len(users) == 1


def test_setup_verify_otp_invalid_and_expired(client, db_session: Session):
    """Test that invalid or expired email OTP is rejected."""
    email = "owenzcolin@gmail.com"
    now = datetime.now(timezone.utc)

    # 1. Expired OTP
    enrollment_expired = SuperadminEnrollment(
        email=email,
        full_name="Platform Owner",
        otp_hash=hash_token("123456"),
        otp_expires_at=now - timedelta(minutes=1),
        is_email_verified=False,
    )
    db_session.add(enrollment_expired)
    db_session.commit()

    resp_expired = client.post(
        "/superadmin/setup/verify-otp",
        data={"email": email, "otp": "123456"},
    )
    assert resp_expired.status_code == 400
    assert "expired" in resp_expired.text

    # 2. Invalid OTP code
    enrollment_expired.otp_expires_at = now + timedelta(minutes=15)
    db_session.commit()

    resp_bad = client.post(
        "/superadmin/setup/verify-otp",
        data={"email": email, "otp": "999999"},
    )
    assert resp_bad.status_code == 400
    assert "Invalid verification code" in resp_bad.text


def test_complete_owner_superadmin_onboarding_with_totp_mfa(client, db_session: Session):
    """
    Test complete lifecycle:
    1. CLI Bootstrap -> OTP dispatched
    2. Step 1: Submit OTP -> Verified & stages TOTP secret
    3. Step 2: Submit password & valid authenticator TOTP code
    4. Account created, promoted to PLATFORM_SUPERADMIN, mfa_enabled=True, audit recorded.
    """
    email = "owenzcolin@gmail.com"

    # 1. CLI Bootstrap
    init_res = initiate_superadmin_bootstrap(db=db_session, email=email)
    otp = init_res["otp"]

    # 2. Step 1: Verify OTP
    res_otp = client.post(
        "/superadmin/setup/verify-otp",
        data={"email": email, "otp": otp},
        follow_redirects=False,
    )
    assert res_otp.status_code == 303
    assert res_otp.headers["location"] == "/superadmin/setup/mfa"

    # Verify enrollment state in DB
    enrollment = db_session.scalar(select(SuperadminEnrollment).where(SuperadminEnrollment.email == email))
    assert enrollment.is_email_verified is True
    assert enrollment.totp_secret_encrypted is not None

    raw_secret = decrypt_secret(enrollment.totp_secret_encrypted)
    assert len(raw_secret) >= 16

    # 3. Test Invalid TOTP code rejected
    bad_mfa_res = client.post(
        "/superadmin/setup/complete",
        data={
            "email": email,
            "password": "SuperOwnerPassword123!",
            "password_confirm": "SuperOwnerPassword123!",
            "totp_code": "000000",  # Wrong code
        },
    )
    assert bad_mfa_res.status_code == 400
    assert "Invalid 6-digit authenticator code" in bad_mfa_res.text

    # 4. Compute valid RFC 6238 TOTP code
    valid_totp = get_totp_code(raw_secret)
    assert len(valid_totp) == 6

    # 5. Submit valid password and valid TOTP code
    good_mfa_res = client.post(
        "/superadmin/setup/complete",
        data={
            "email": email,
            "password": "SuperOwnerPassword123!",
            "password_confirm": "SuperOwnerPassword123!",
            "totp_code": valid_totp,
        },
        follow_redirects=False,
    )
    assert good_mfa_res.status_code == 303
    assert good_mfa_res.headers["location"] == "/superadmin"

    # 6. Verify User activated as PLATFORM_SUPERADMIN in DB
    user = db_session.scalar(select(TenantUser).where(TenantUser.email == email))
    assert user is not None
    assert user.role == UserRole.superadmin
    assert user.tenant_id is None  # Independent of tenants
    assert user.mfa_enabled is True
    assert user.email_verified is True
    assert verify_password("SuperOwnerPassword123!", user.hashed_password) is True

    # 7. Verify Audit Log recorded
    audit = db_session.scalar(
        select(SuperadminAuditLog).where(
            SuperadminAuditLog.action == "superadmin.activated",
            SuperadminAuditLog.target_id == user.id,
        )
    )
    assert audit is not None
    assert audit.actor_email == email
    assert "MFA" in audit.reason


def test_superadmin_login_requires_mandatory_totp(client, db_session: Session):
    """Test that active superadmin login challenges for TOTP MFA."""
    email = "owenzcolin@gmail.com"

    # Initiate and complete onboarding
    init_res = initiate_superadmin_bootstrap(db=db_session, email=email)
    client.post("/superadmin/setup/verify-otp", data={"email": email, "otp": init_res["otp"]})

    enrollment = db_session.scalar(select(SuperadminEnrollment).where(SuperadminEnrollment.email == email))
    secret = decrypt_secret(enrollment.totp_secret_encrypted)
    totp_code = get_totp_code(secret)

    client.post(
        "/superadmin/setup/complete",
        data={
            "email": email,
            "password": "OwnerSecretPassword99!",
            "password_confirm": "OwnerSecretPassword99!",
            "totp_code": totp_code,
        },
    )

    # Now simulate a fresh login attempt
    # Step 1: Post password
    login_res = client.post(
        "/superadmin/login",
        data={"email": email, "password": "OwnerSecretPassword99!"},
        follow_redirects=False,
    )
    # Must redirect to MFA challenge
    assert login_res.status_code == 303
    assert login_res.headers["location"] == "/superadmin/mfa"

    # Step 2: Invalid MFA rejected
    mfa_bad = client.post("/superadmin/mfa", data={"totp_code": "000000"})
    assert mfa_bad.status_code == 401
    assert "Invalid authenticator code" in mfa_bad.text

    # Step 3: Valid MFA code authenticates
    fresh_totp = get_totp_code(secret)
    mfa_good = client.post("/superadmin/mfa", data={"totp_code": fresh_totp}, follow_redirects=False)
    assert mfa_good.status_code == 303
    assert mfa_good.headers["location"] == "/superadmin"
