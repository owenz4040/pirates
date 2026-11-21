"""Tests for administrator single-use invitation tokens and password setup."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from saas.models.tenant import Tenant, TenantInvitation, TenantStatus, TenantUser, UserRole
from saas.security.auth import generate_secure_token, hash_token, verify_password


def test_invitation_page_valid_token(client, db_session: Session):
    """Test GET /invite/{token} displays password setup form for unexpired unused token."""
    now = datetime.now(timezone.utc)
    raw_token = generate_secure_token(32)

    tenant = Tenant(
        name="Serengeti Broadband",
        slug="serengeti-bb",
        contact_email="info@serengeti.net",
        contact_phone="+254700000000",
        status=TenantStatus.active,
    )
    db_session.add(tenant)
    db_session.flush()

    invitation = TenantInvitation(
        tenant_id=tenant.id,
        email="admin@serengeti.net",
        full_name="Sarah Kiprono",
        role=UserRole.tenant_admin,
        token_hash=hash_token(raw_token),
        expires_at=now + timedelta(hours=72),
        is_used=False,
    )
    db_session.add(invitation)
    db_session.commit()

    response = client.get(f"/invite/{raw_token}")
    assert response.status_code == 200
    assert "Set Your Administrator Password" in response.text
    assert "Sarah Kiprono" in response.text
    assert "admin@serengeti.net" in response.text


def test_invitation_page_expired_or_invalid_token(client, db_session: Session):
    """Test that expired or invalid invitation tokens return 404."""
    now = datetime.now(timezone.utc)
    raw_token = generate_secure_token(32)

    tenant = Tenant(
        name="Expired ISP",
        slug="expired-isp",
        contact_email="expired@isp.net",
        contact_phone="+254700000000",
        status=TenantStatus.active,
    )
    db_session.add(tenant)
    db_session.flush()

    # Expired token
    invitation = TenantInvitation(
        tenant_id=tenant.id,
        email="old@isp.net",
        full_name="Old Admin",
        role=UserRole.tenant_admin,
        token_hash=hash_token(raw_token),
        expires_at=now - timedelta(hours=1),  # Already expired
        is_used=False,
    )
    db_session.add(invitation)
    db_session.commit()

    # Expired token request
    response_expired = client.get(f"/invite/{raw_token}")
    assert response_expired.status_code == 404

    # Non-existent token request
    response_fake = client.get(f"/invite/non_existent_token_12345")
    assert response_fake.status_code == 404


def test_invitation_acceptance_creates_user_and_marks_used(client, db_session: Session):
    """
    Test POST /invite/{token} sets password, creates active TenantUser,
    marks invitation as used, and rejects subsequent replay attempts.
    """
    now = datetime.now(timezone.utc)
    raw_token = generate_secure_token(32)

    tenant = Tenant(
        name="Equator Wireless",
        slug="equator-wifi",
        contact_email="info@equator.ke",
        contact_phone="+254700000000",
        status=TenantStatus.active,
    )
    db_session.add(tenant)
    db_session.flush()

    invitation = TenantInvitation(
        tenant_id=tenant.id,
        email="admin@equator.ke",
        full_name="Brian Ochieng",
        role=UserRole.tenant_admin,
        token_hash=hash_token(raw_token),
        expires_at=now + timedelta(hours=72),
        is_used=False,
    )
    db_session.add(invitation)
    db_session.commit()

    # 1. Accept invitation
    payload = {
        "password": "SecurePassword987!",
        "password_confirm": "SecurePassword987!",
    }
    response = client.post(f"/invite/{raw_token}", data=payload, follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/api/tenant/me"

    # 2. Verify User created in DB
    user = db_session.scalar(select(TenantUser).where(TenantUser.email == "admin@equator.ke"))
    assert user is not None
    assert user.tenant_id == tenant.id
    assert user.role == UserRole.tenant_admin
    assert verify_password("SecurePassword987!", user.hashed_password) is True

    # 3. Verify Invitation is now marked used
    db_session.refresh(invitation)
    assert invitation.is_used is True
    assert invitation.used_at is not None

    # 4. Replay attack: submitting again must fail
    response_replay = client.post(f"/invite/{raw_token}", data=payload)
    assert response_replay.status_code == 404
