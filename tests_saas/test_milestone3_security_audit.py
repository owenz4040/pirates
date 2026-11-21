"""Deep security, compatibility, and isolation audit test suite for COwen ISP SaaS Milestone 3."""
import os
import re
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

os.environ["SAAS_ENV"] = "test"
os.environ["SAAS_DATABASE_URL"] = "sqlite:///:memory:"

from saas.app import app
from saas.database import SaasBase, get_saas_db
from saas.models.hotspot import HotspotPackage, HotspotPortalDesign, HotspotVoucher, VoucherStatus
from saas.models.payments import CustomerPayment, SubscriptionTransaction, TenantPaymentConfig
from saas.models.pppoe import ConnectionType, CustomerStatus, PPPoECustomer, PPPoEPlan
from saas.models.router import Router, RouterCommand, RouterCommandStatus, RouterStatus
from saas.models.tenant import (
    SubscriptionTier,
    Tenant,
    TenantBranding,
    TenantStatus,
    TenantSubscription,
    TenantUser,
    UserRole,
)
from saas.security.auth import hash_password, hash_token
from saas.security.crypto import decrypt_secret, encrypt_secret
from saas.security.sanitizer import (
    CommandInjectionError,
    build_hotspot_user_command,
    build_pppoe_secret_command,
    quote_routeros,
    validate_package_name,
    validate_password,
    validate_plan_name,
    validate_pppoe_username,
    validate_rate_limit,
)

test_engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture(scope="module", autouse=True)
def setup_test_db():
    SaasBase.metadata.create_all(bind=test_engine)
    yield
    SaasBase.metadata.drop_all(bind=test_engine)


@pytest.fixture
def db_session():
    connection = test_engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)
    app.dependency_overrides[get_saas_db] = lambda: session
    yield session
    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture
def client(db_session):
    return TestClient(app)


def make_tenant(db, name, slug):
    tenant = Tenant(
        id=str(uuid.uuid4()),
        name=name,
        slug=slug,
        contact_email=f"admin@{slug}.com",
        contact_phone="+254700000000",
        status=TenantStatus.active,
    )
    db.add(tenant)
    db.flush()

    sub = TenantSubscription(
        tenant_id=tenant.id,
        tier=SubscriptionTier.growth,
        max_routers=4,
        monthly_price_kes=Decimal("3500.00"),
        is_active=True,
        starts_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(days=30),
    )
    db.add(sub)

    branding = TenantBranding(tenant_id=tenant.id, company_title=f"{name} WiFi")
    db.add(branding)

    admin = TenantUser(
        id=str(uuid.uuid4()),
        tenant_id=tenant.id,
        email=f"admin@{slug}.com",
        full_name=f"{name} Admin",
        hashed_password=hash_password("SecretPass123!"),
        role=UserRole.tenant_admin,
        is_active=True,
        email_verified=True,
    )
    db.add(admin)
    db.commit()
    db.refresh(tenant)
    db.refresh(admin)
    return tenant, admin


# =====================================================================
# 1. CRITICAL-01: RouterOS Command Injection & Allowlist Tests
# =====================================================================

def test_command_injection_quotes_and_semicolons_rejected():
    with pytest.raises(CommandInjectionError):
        validate_pppoe_username('user"; /system reboot ; "')

    with pytest.raises(CommandInjectionError):
        validate_pppoe_username("user\nadmin")

    with pytest.raises(CommandInjectionError):
        validate_plan_name('Fast"; /tool fetch ... ; "')

    with pytest.raises(CommandInjectionError):
        validate_package_name('24Hr$bad')

    with pytest.raises(CommandInjectionError):
        validate_rate_limit("10M/10M; /system identity set name=hacked")


def test_command_injection_safe_builder_quoting():
    # RouterOS quote escaping
    assert quote_routeros('test"val') == '"test\\"val"'
    assert quote_routeros('price$5') == '"price\\$5"'
    assert quote_routeros('line1\nline2') == '"line1 line2"'

    # Building valid command works and is safe
    cmd = build_pppoe_secret_command("alice_user", "Secret$Pass1", "10 Mbps Plan", comment="VIP User")
    assert 'name="alice_user"' in cmd
    assert 'password="Secret\\$Pass1"' in cmd
    assert 'profile="10 Mbps Plan"' in cmd
    assert ':if ([:len [/ppp secret find where' in cmd


def test_pppoe_subscribers_add_rejects_injection_input(client, db_session):
    t, admin = make_tenant(db_session, "Tenant Inj", "t-inj")
    router = Router(tenant_id=t.id, name="InjRouter", token_hash=hash_token("tok-inj"), status=RouterStatus.online)
    plan = PPPoEPlan(tenant_id=t.id, name="PlanInj", rate_limit="10M/10M", price_kes=Decimal("1000"))
    db_session.add_all([router, plan])
    db_session.commit()

    headers = {"Authorization": f"Bearer {admin.id}"}
    # Injection attempt in username
    resp = client.post(
        "/tenant/pppoe/subscribers/add",
        data={
            "router_id": router.id,
            "plan_id": plan.id,
            "username": 'hacker"; /system reboot; "',
            "password": "valid_pass_123",
            "full_name": "Test Hacker",
        },
        headers=headers,
        follow_redirects=False,
    )
    # Redirects with flash error without creating subscriber
    assert resp.status_code == 303
    cust = db_session.scalar(select(PPPoECustomer).where(PPPoECustomer.tenant_id == t.id))
    assert cust is None


# =====================================================================
# 2. CRITICAL-02: Voucher Router Tenant Isolation Tests
# =====================================================================

def test_voucher_generation_rejects_cross_tenant_router_id(client, db_session):
    t_a, admin_a = make_tenant(db_session, "Tenant IsoA", "t-isoa")
    t_b, admin_b = make_tenant(db_session, "Tenant IsoB", "t-isob")

    # Router belonging strictly to Tenant B
    router_b = Router(
        tenant_id=t_b.id,
        name="Router-B-Only",
        token_hash=hash_token("tok-b-only"),
        status=RouterStatus.online,
    )
    pkg_a = HotspotPackage(
        tenant_id=t_a.id,
        name="100MB Pack",
        price_kes=Decimal("20.00"),
        duration_minutes=60,
    )
    db_session.add_all([router_b, pkg_a])
    db_session.commit()

    headers = {"Authorization": f"Bearer {admin_a.id}"}

    # Tenant A attempts to generate vouchers targeting Tenant B's router ID
    resp = client.post(
        "/tenant/hotspot/vouchers/generate",
        data={
            "package_id": pkg_a.id,
            "quantity": 10,
            "router_id": router_b.id,  # Target Tenant B's router!
        },
        headers=headers,
    )
    assert resp.status_code == 400
    assert "Invalid router selection" in resp.json()["detail"]

    # Verify no commands were queued on Router B
    queued = db_session.scalars(
        select(RouterCommand).where(RouterCommand.router_id == router_b.id)
    ).all()
    assert len(queued) == 0


# =====================================================================
# 3. HIGH-01: MikroTik Outbound Sync & RAM-only Command Execution
# =====================================================================

def test_router_sync_delivers_executable_script_in_ram(client, db_session):
    t, admin = make_tenant(db_session, "Tenant ROS", "t-ros")
    raw_token = "ros-test-secret-token"
    router = Router(
        tenant_id=t.id,
        name="ROS-Router",
        token_hash=hash_token(raw_token),
        status=RouterStatus.online,
        version="6.49.18",
    )
    db_session.add(router)
    db_session.commit()

    cmd = RouterCommand(
        tenant_id=t.id,
        router_id=router.id,
        description="Add PPPoE client",
        script='/ppp secret add name="user1" password="p1"',
        status=RouterCommandStatus.pending,
    )
    db_session.add(cmd)
    db_session.commit()

    # Router polls /api/router/sync via RouterOS /tool fetch (plain text mode)
    resp = client.post(
        "/api/router/sync",
        headers={"X-Router-Token": raw_token},
        data={"version": "6.49.18", "cpu": "8", "board": "hAP lite"},
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/plain")
    script_text = resp.text

    # Verify memory execution syntax without disk writes
    assert ':local ok ""' in script_text
    assert ':do {/ppp secret add name="user1" password="p1"' in script_text
    assert f':set ok ($ok . "{cmd.id},")' in script_text
    assert '/api/router/ack' in script_text

    # Router reports acknowledgment back via /api/router/ack
    ack_resp = client.post(
        "/api/router/ack",
        headers={"X-Router-Token": raw_token},
        data={"ok": f"{cmd.id},", "failed": ""},
    )
    assert ack_resp.status_code == 200
    db_session.refresh(cmd)
    assert cmd.status == RouterCommandStatus.done
    assert cmd.finished_at is not None


# =====================================================================
# 4. HIGH-02: CSRF Protection Tests
# =====================================================================

def test_csrf_protection_rejects_missing_or_invalid_token(client, db_session):
    tenant, admin = make_tenant(db_session, "Tenant CSRF", "t-csrf")

    # Step 1: Establish session via GET
    get_resp = client.get("/tenant/login")
    assert get_resp.status_code == 200
    assert 'name="csrf_token"' in get_resp.text

    # Step 2: Post with MISSING csrf_token -> Must return 403 Forbidden
    post_resp = client.post(
        "/tenant/login",
        data={"email": admin.email, "password": "SecretPass123!"},
    )
    assert post_resp.status_code == 403
    assert "CSRF verification failed" in post_resp.text

    # Step 3: Post with INVALID csrf_token -> Must return 403 Forbidden
    post_bad_csrf = client.post(
        "/tenant/login",
        data={"email": admin.email, "password": "SecretPass123!", "csrf_token": "forged_token_value"},
    )
    assert post_bad_csrf.status_code == 403

    # Step 4: Post with VALID csrf_token -> Succeeds with 303 Redirect
    match = re.search(r'name="csrf_token"\s+value="([^"]+)"', get_resp.text)
    assert match is not None
    valid_csrf = match.group(1)

    post_ok = client.post(
        "/tenant/login",
        data={"email": admin.email, "password": "SecretPass123!", "csrf_token": valid_csrf},
        follow_redirects=False,
    )
    assert post_ok.status_code == 303
    assert post_ok.headers["Location"] == "/tenant/dashboard"


# =====================================================================
# 5. HIGH-03: Tenant Login Rate Limiting Tests
# =====================================================================

def test_login_rate_limiting_locks_out_after_five_failed_attempts(client, db_session):
    tenant, admin = make_tenant(db_session, "Tenant RL", "t-rl")

    get_resp = client.get("/tenant/login")
    match = re.search(r'name="csrf_token"\s+value="([^"]+)"', get_resp.text)
    csrf = match.group(1)

    # 4 failed attempts: returns 401
    for _ in range(4):
        resp = client.post(
            "/tenant/login",
            data={"email": admin.email, "password": "WrongPassword", "csrf_token": csrf},
        )
        assert resp.status_code == 401

    # 5th failed attempt: triggers lockout
    resp_5 = client.post(
        "/tenant/login",
        data={"email": admin.email, "password": "WrongPassword", "csrf_token": csrf},
    )
    assert resp_5.status_code in (401, 429)

    # Subsequent attempt (even with right password): locked out with 429
    resp_locked = client.post(
        "/tenant/login",
        data={"email": admin.email, "password": "SecretPass123!", "csrf_token": csrf},
    )
    assert resp_locked.status_code == 429
    assert "Too many failed login attempts" in resp_locked.text


# =====================================================================
# 6. MEDIUM-PRIORITY: MultiFernet Key Rotation & Token Rotation
# =====================================================================

def test_multifernet_key_rotation_compatibility():
    from cryptography.fernet import Fernet
    old_key = Fernet.generate_key().decode()
    new_key = Fernet.generate_key().decode()

    # Encrypt secret with old key
    ciphertext = encrypt_secret("my-old-daraja-passkey", key=old_key)

    # Combine keys: new primary key first, old key fallback
    combined_keys = f"{new_key},{old_key}"

    # Verify old ciphertext decrypts seamlessly under MultiFernet
    decrypted = decrypt_secret(ciphertext, key=combined_keys)
    assert decrypted == "my-old-daraja-passkey"

    # Verify new encryption uses the new key
    new_ciphertext = encrypt_secret("new-secret", key=combined_keys)
    assert decrypt_secret(new_ciphertext, key=new_key) == "new-secret"


def test_router_token_rotation_invalidates_old_token(client, db_session):
    t, admin = make_tenant(db_session, "Tenant Rot", "t-rot")
    old_raw = "initial-token-12345"
    router = Router(
        tenant_id=t.id,
        name="RotRouter",
        token_hash=hash_token(old_raw),
        status=RouterStatus.online,
    )
    db_session.add(router)
    db_session.commit()

    headers = {"Authorization": f"Bearer {admin.id}"}

    # Verify old token works initially
    resp1 = client.post(
        "/api/router/sync",
        headers={"X-Router-Token": old_raw, "Accept": "application/json"},
    )
    assert resp1.status_code == 200

    # Rotate token
    rotate_resp = client.post(f"/tenant/routers/{router.id}/rotate-token", headers=headers)
    assert rotate_resp.status_code == 200
    assert "rotated successfully" in rotate_resp.text
    assert "RotRouter" in rotate_resp.text

    # Old token must now be rejected with 401 Unauthorized
    resp2 = client.post(
        "/api/router/sync",
        headers={"X-Router-Token": old_raw, "Accept": "application/json"},
    )
    assert resp2.status_code == 401


# =====================================================================
# 7. Additional Preview Readiness Hardening Tests
# =====================================================================

def test_login_rate_limiting_by_ip_blocks_email_rotation(client, db_session):
    """Verifies that an attacker rotating email addresses from the same IP is blocked."""
    ip_headers = {"X-Forwarded-For": "203.0.113.88"}

    get_resp = client.get("/tenant/login")
    match = re.search(r'name="csrf_token"\s+value="([^"]+)"', get_resp.text)
    csrf = match.group(1)

    # 4 failed attempts with 4 different email addresses from the same IP
    for i in range(1, 5):
        resp = client.post(
            "/tenant/login",
            data={"email": f"attacker_{i}@target.com", "password": "BadPassword123!", "csrf_token": csrf},
            headers=ip_headers,
        )
        assert resp.status_code == 401

    # 5th failed attempt with a 5th different email address
    resp_5 = client.post(
        "/tenant/login",
        data={"email": "attacker_5@target.com", "password": "BadPassword123!", "csrf_token": csrf},
        headers=ip_headers,
    )
    assert resp_5.status_code in (401, 429)

    # 6th attempt with a brand new 6th email address is immediately rejected with 429 due to IP lockout
    resp_6 = client.post(
        "/tenant/login",
        data={"email": "attacker_6@target.com", "password": "AnyPassword123!", "csrf_token": csrf},
        headers=ip_headers,
    )
    assert resp_6.status_code == 429
    assert "Too many failed login attempts" in resp_6.text


def test_password_change_invalidates_concurrent_sessions(client, db_session):
    """Verifies that changing password updates session_version and revokes concurrent sessions."""
    tenant, admin = make_tenant(db_session, "Tenant Revoke", "t-revoke")

    # Step 1: Log in with browser client
    get_resp = client.get("/tenant/login")
    match = re.search(r'name="csrf_token"\s+value="([^"]+)"', get_resp.text)
    csrf = match.group(1)

    login_resp = client.post(
        "/tenant/login",
        data={"email": admin.email, "password": "SecretPass123!", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert login_resp.status_code == 303
    session_cookie = client.cookies.get("session")

    # Step 2: Dashboard is accessible with session
    dash_resp = client.get("/tenant/dashboard")
    assert dash_resp.status_code == 200

    # Step 3: Admin changes password -> increments session_version in DB
    settings_resp = client.get("/tenant/settings")
    match = re.search(r'name="csrf_token"\s+value="([^"]+)"', settings_resp.text)
    csrf_settings = match.group(1)

    change_resp = client.post(
        "/tenant/settings/password",
        data={
            "current_password": "SecretPass123!",
            "new_password": "NewSecretPass456!",
            "confirm_password": "NewSecretPass456!",
            "csrf_token": csrf_settings,
        },
        follow_redirects=False,
    )
    assert change_resp.status_code == 303

    # Step 4: A second client simulating another browser with the OLD session cookie
    from starlette.testclient import TestClient
    from saas.app import app
    other_client = TestClient(app)
    # Set old session cookie
    other_client.cookies.set("session", session_cookie)

    # Old session is now rejected because session_version does not match updated user.session_version
    old_dash_resp = other_client.get("/tenant/dashboard", follow_redirects=False)
    assert old_dash_resp.status_code == 303
    assert old_dash_resp.headers["Location"].startswith("/tenant/login")


def test_csrf_protection_on_cookie_authenticated_api_endpoint(client, db_session):
    """Verifies that browser state changes to /api/ endpoints cannot bypass CSRF."""
    tenant, admin = make_tenant(db_session, "Tenant CSRF API", "t-csrf-api")

    # Log in to get session cookie
    get_resp = client.get("/tenant/login")
    match = re.search(r'name="csrf_token"\s+value="([^"]+)"', get_resp.text)
    csrf = match.group(1)

    login_resp = client.post(
        "/tenant/login",
        data={"email": admin.email, "password": "SecretPass123!", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert login_resp.status_code == 303

    # State-changing POST to /api/tenant/routers with session cookie but NO CSRF token -> 403 Forbidden
    forged_resp = client.post(
        "/api/tenant/routers",
        json={"name": "AttackerRouter"},
    )
    assert forged_resp.status_code == 403
    assert "CSRF verification failed" in forged_resp.text

    # State-changing POST with valid X-CSRF-Token header -> Succeeds
    valid_resp = client.post(
        "/api/tenant/routers",
        json={"name": "LegitRouter"},
        headers={"X-CSRF-Token": csrf},
    )
    assert valid_resp.status_code == 201
    assert valid_resp.json()["name"] == "LegitRouter"


def test_router_api_requires_valid_router_token(client):
    """Verifies that router endpoints require X-Router-Token and cannot be called unauthenticated."""
    # POST to /api/router/sync with missing header
    sync_resp = client.post("/api/router/sync")
    assert sync_resp.status_code == 401

    # POST to /api/router/ack with missing header
    ack_resp = client.post("/api/router/ack")
    assert ack_resp.status_code == 401


def test_routeros_setup_script_structure_and_signature_check():
    """Verifies the generated setup script includes the magic signature check and size limits."""
    from saas.routers.tenant import _build_mikrotik_setup_script

    script = _build_mikrotik_setup_script(
        sync_url="https://cowen.vercel.app/api/router/sync",
        raw_token="sec-token-12345",
        router_name="Main-Core-Router",
    )

    # 1. Verification of HTTPS CA certificate prerequisite
    assert "PREREQUISITE" in script
    assert "cacert.pem" in script

    # 2. Strict certificate checking
    assert "check-certificate=yes-without-crl" in script

    # 3. Status and magic signature verification before execution
    assert '$status = \\"finished\\"' in script
    assert '[:pick $body 0 16] = \\"# COwen-Batch-OK\\"' in script

    # 4. Memory size boundaries
    assert "[:len $body] <= 32768" in script

    # 5. Safe execution wrapping
    assert ":do {" in script
    assert ":local run [:parse $body];" in script
    assert "$run;" in script

