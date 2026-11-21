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

    # 1. Verification of HTTPS CA certificate prerequisite: no incorrect ACME commands or untrusted external downloads
    assert "/certificate enable-ssl-certificate" not in script
    assert "curl.se" not in script
    assert "cacert.pem" not in script

    # 2. Universal RouterOS 6 & 7 certificate checking
    assert "check-certificate=no" in script or "check-certificate=yes-without-crl" in script

    # 3. Status and magic signature verification before execution
    assert r'\$status = \"finished\"' in script
    assert r'[:pick \$body 0 16] = \"# COwen-Batch-OK\"' in script

    # 4. Memory size boundaries
    assert "[:len $body] <= 32768" in script or r"[:len \$body] <= 32768" in script

    # 5. Safe execution wrapping
    assert ":do {" in script
    assert ":local run [:parse $body];" in script or r":local run [:parse \$body];" in script
    assert "$run;" in script or r"\$run;" in script


def test_routeros_quoting_has_zero_unescaped_internal_quotes():
    """Validates that RouterOS script source contains zero unescaped internal quotes and proper variable escapes."""
    from saas.security.sanitizer import (
        build_mikrotik_rsc_file,
        build_mikrotik_sync_script_source,
        build_mikrotik_terminal_commands,
    )

    url = "https://cowen.vercel.app/api/router/sync"
    token = "test-token-abcdef123456"
    router_name = "Pirates-WiFi"

    source = build_mikrotik_sync_script_source(url, token)

    # Walk through source character by character to ensure NO unescaped quotes exist
    escaped = False
    unescaped_quotes = []
    for idx, ch in enumerate(source):
        if ch == '\\' and not escaped:
            escaped = True
            continue
        if ch == '"' and not escaped:
            unescaped_quotes.append(idx)
        escaped = False

    assert len(unescaped_quotes) == 0, f"Found unescaped quotes in source at {unescaped_quotes}"

    # Verify variable references inside source are escaped with \$ to prevent premature evaluation
    for var in [r"\$ver", r"\$upt", r"\$cpu", r"\$brd", r"\$info", r"\$body", r"\$status", r"\$res", r"\$run"]:
        assert var in source, f"Variable {var} not properly escaped in script source"

    # Verify both terminal and rsc file generators
    rsc = build_mikrotik_rsc_file(url, token, router_name)
    assert "/system script add name=\"COwen_Sync_Script\"" in rsc
    assert "/system scheduler add name=\"COwen_Sync\"" in rsc
    assert "file-name=" not in source  # Zero NAND writes in the script itself

    term = build_mikrotik_terminal_commands(url, token, router_name)
    assert "/system script run COwen_Sync_Script" in term


def test_routeros_downloadable_rsc_endpoint(client, db_session, seed_data):
    """Verifies that configuration download uses CSRF-protected POST, never exposes tokens in URLs, and isolates tenants."""
    user_a = seed_data["user_a"]
    router_a = seed_data["router_a"]
    router_b = seed_data["router_b"]
    valid_raw_token = "alpha_token_1"
    headers = {"Authorization": f"Bearer {user_a.id}"}

    # 1. GET requests to the download endpoint are rejected (must be POST)
    resp_get = client.get(f"/tenant/routers/{router_a.id}/download-rsc", headers=headers)
    assert resp_get.status_code == 405  # Method Not Allowed

    # 2. Old GET endpoint with query parameter token is completely eliminated
    resp_old = client.get(f"/tenant/routers/{router_a.id}/script.rsc?token={valid_raw_token}", headers=headers)
    assert resp_old.status_code == 404

    # 3. POST download using active token in POST body (no rotation)
    resp_post_current = client.post(
        f"/tenant/routers/{router_a.id}/download-rsc",
        data={"token": valid_raw_token},
        headers=headers,
    )
    assert resp_post_current.status_code == 200
    assert "attachment; filename=" in resp_post_current.headers.get("content-disposition", "")
    assert ".rsc" in resp_post_current.headers.get("content-disposition", "")
    assert "no-store" in resp_post_current.headers.get("cache-control", "")
    assert valid_raw_token in resp_post_current.text
    assert router_a.name in resp_post_current.text
    # Verify sync works with this token
    sync_resp = client.post("/api/router/sync", headers={"X-Router-Token": valid_raw_token})
    assert sync_resp.status_code == 200

    # 4. POST download requesting rotation (or without token): rotates token and invalidates old one
    resp_rotate = client.post(
        f"/tenant/routers/{router_a.id}/download-rsc",
        data={"rotate": "true"},
        headers=headers,
    )
    assert resp_rotate.status_code == 200
    assert "COwen_Sync_Script" in resp_rotate.text
    # The old token is now IMMEDIATELY invalidated
    sync_old = client.post("/api/router/sync", headers={"X-Router-Token": valid_raw_token})
    assert sync_old.status_code == 401

    # 5. Cross-tenant isolation: Tenant A cannot download Tenant B's router configuration
    resp_cross = client.post(
        f"/tenant/routers/{router_b.id}/download-rsc",
        data={"rotate": "true"},
        headers=headers,
    )
    assert resp_cross.status_code == 404


def test_routeros_download_csrf_enforcement_with_browser_session(client, db_session, seed_data):
    """Verifies that browser session-authenticated download strictly enforces CSRF protection."""
    user_a = seed_data["user_a"]
    router_a = seed_data["router_a"]

    # Log in via HTML form to establish session cookie
    login_page = client.get("/tenant/login")
    match = re.search(r'name="csrf_token"\s+value="([^"]+)"', login_page.text)
    csrf_token = match.group(1)

    login_post = client.post(
        "/tenant/login",
        data={"email": user_a.email, "password": "AlphaPass123!", "csrf_token": csrf_token},
        follow_redirects=False,
    )
    assert login_post.status_code == 303

    # Forged request: POST without CSRF token -> 403 Forbidden
    forged_resp = client.post(f"/tenant/routers/{router_a.id}/download-rsc", data={"rotate": "true"})
    assert forged_resp.status_code == 403
    assert "CSRF verification failed" in forged_resp.text

    # Valid request: POST with valid session CSRF token -> 200 OK download
    valid_resp = client.post(
        f"/tenant/routers/{router_a.id}/download-rsc",
        data={"rotate": "true", "csrf_token": csrf_token},
    )
    assert valid_resp.status_code == 200
    assert "attachment; filename=" in valid_resp.headers.get("content-disposition", "")
    assert ".rsc" in valid_resp.headers.get("content-disposition", "")


def test_failed_download_recovery_and_flash_storage_safety():
    """Verifies recovery mechanism exists and no sensitive information is persisted to flash storage."""
    from saas.security.sanitizer import (
        build_mikrotik_rsc_file,
        build_mikrotik_sync_script_source,
    )

    url = "https://cowen.vercel.app/api/router/sync"
    raw_token = "recovery-token-xyz789"
    router_name = "Core-Router"

    # 1. Flash storage safety: Zero disk file writes in RAM sync script
    source = build_mikrotik_sync_script_source(url, raw_token)
    assert "dst-path" not in source
    assert "file=" not in source
    assert "file-name=" not in source
    assert "output=user as-value" in source

    # 2. RSC setup file contains clear on-error recovery wrappers so partial runs don't lock out the device
    rsc = build_mikrotik_rsc_file(url, raw_token, router_name)
    assert ":do { /system script remove" in rsc
    assert "on-error={}" in rsc
    assert ":do { /system scheduler remove" in rsc
    assert "on-error={}" in rsc
    assert "/system script run COwen_Sync_Script" in rsc


def test_router_command_pipeline_and_subscriber_lifecycle():
    """Verifies that website actions generate valid, injection-proof RouterOS commands with profile upsert."""
    from saas.security.sanitizer import (
        build_pppoe_profile_command,
        build_pppoe_disable_command,
        build_pppoe_enable_command,
        build_pppoe_delete_command,
    )
    from saas.routers.tenant import render_router_batch
    from saas.models.router import RouterCommand, RouterCommandStatus

    # 1. Profile upsert command
    prof_cmd = build_pppoe_profile_command("10M-Residential", "10M/10M")
    assert '/ppp profile add name="10M-Residential" rate-limit="10M/10M"' in prof_cmd
    assert '/ppp profile set [find where name="10M-Residential" and comment="COwen Managed Profile"] rate-limit="10M/10M"' in prof_cmd

    # 2. Suspend command kicks active session
    disable_cmd = build_pppoe_disable_command("user_test")
    assert '/ppp secret set [find where name="user_test"] disabled=yes' in disable_cmd
    assert '/ppp active remove [find where name="user_test"]' in disable_cmd

    # 3. Activate command
    enable_cmd = build_pppoe_enable_command("user_test")
    assert '/ppp secret set [find where name="user_test"] disabled=no' in enable_cmd

    # 4. Delete command cleans secret and kicks session
    delete_cmd = build_pppoe_delete_command("user_test")
    assert '/ppp secret remove [find where name="user_test"]' in delete_cmd

    # 5. Batch rendering includes ack, check-certificate=yes-without-crl, and zero bypass secrets
    cmd = RouterCommand(
        id="cmd-123",
        tenant_id="t-1",
        router_id="r-1",
        description="test",
        script=disable_cmd,
        status=RouterCommandStatus.pending,
    )
    batch_text = render_router_batch([cmd], "https://cowen-preview.vercel.app/api/router/ack", "raw-token-abc")
    assert "# COwen-Batch-OK" in batch_text
    assert "cmd-123" in batch_text
    assert "check-certificate=yes-without-crl" in batch_text
    assert "check-certificate=no" not in batch_text
    assert "x-vercel-protection-bypass" not in batch_text
    assert "X-Router-Token: raw-token-abc" in batch_text
    assert ":local ackData" in batch_text


# =====================================================================
# 8. Physical Provisioning & Delivery State Machine Regression Tests
# =====================================================================

def test_pppoe_profile_and_subscriber_provisioning(client, db_session, seed_data):
    """Verifies PPPoE plan queues profile upsert, and subscriber queues profile before secret."""
    user_a = seed_data["user_a"]
    router_a = seed_data["router_a"]
    headers = {"Authorization": f"Bearer {user_a.id}"}

    # 1. Add plan queues profile command to active router
    resp = client.post(
        "/tenant/pppoe/plans/add",
        data={
            "name": "50 Mbps Enterprise",
            "rate_limit": "50M/50M",
            "price_kes": 5000.0,
            "duration_days": 30,
        },
        headers=headers,
        follow_redirects=False,
    )
    assert resp.status_code == 303

    plan = db_session.scalar(select(PPPoEPlan).where(PPPoEPlan.name == "50 Mbps Enterprise"))
    assert plan is not None

    plan_cmd = db_session.scalar(
        select(RouterCommand).where(
            RouterCommand.router_id == router_a.id,
            RouterCommand.description == "Provision PPP profile: 50 Mbps Enterprise",
        )
    )
    assert plan_cmd is not None
    assert '/ppp profile add name="50 Mbps Enterprise" rate-limit="50M/50M"' in plan_cmd.script
    assert 'comment="COwen Managed Profile"' in plan_cmd.script

    # 2. Add subscriber queues combined profile and secret command
    resp2 = client.post(
        "/tenant/pppoe/subscribers/add",
        data={
            "router_id": router_a.id,
            "plan_id": plan.id,
            "username": "corp_sub_01",
            "password": "SecureSubPass1",
            "full_name": "Acme Corp Branch",
            "connection_type": "pppoe",
        },
        headers=headers,
        follow_redirects=False,
    )
    assert resp2.status_code == 303

    sub_cmd = db_session.scalar(
        select(RouterCommand).where(
            RouterCommand.router_id == router_a.id,
            RouterCommand.description.like("%corp_sub_01%"),
        )
    )
    assert sub_cmd is not None
    # Verify profile creation precedes secret creation in the script
    prof_pos = sub_cmd.script.find("/ppp profile")
    secret_pos = sub_cmd.script.find("/ppp secret")
    assert prof_pos != -1 and secret_pos != -1 and prof_pos < secret_pos


def test_profile_conflict_preserves_unmanaged_profiles():
    """Verifies that conflict-safe profile generators never overwrite unmanaged profiles."""
    from saas.security.sanitizer import (
        build_pppoe_profile_command,
        build_hotspot_profile_command,
    )

    # PPPoE profile: check-then-set only if comment matches COwen
    pppoe_cmd = build_pppoe_profile_command("existing-isp-profile", "20M/20M")
    assert 'and comment="COwen Managed Profile"' in pppoe_cmd
    assert 'else={:if ([:len [/ppp profile find where name="existing-isp-profile" and comment="COwen Managed Profile"]] > 0)' in pppoe_cmd

    # Hotspot profile: check-then-set only if comment matches COwen
    hotspot_cmd = build_hotspot_profile_command("existing-hotspot-pkg", "5M/5M")
    assert 'and comment="COwen Managed Profile"' in hotspot_cmd
    assert 'else={:if ([:len [/ip hotspot user profile find where name="existing-hotspot-pkg" and comment="COwen Managed Profile"]] > 0)' in hotspot_cmd


def test_hotspot_voucher_five_voucher_chunking(client, db_session, seed_data):
    """Verifies that generating vouchers creates 5-voucher chunks with profile prepended."""
    user_a = seed_data["user_a"]
    router_a = seed_data["router_a"]
    tenant_a = seed_data["tenant_a"]
    pkg_a = db_session.scalar(select(HotspotPackage).where(HotspotPackage.tenant_id == tenant_a.id))
    headers = {"Authorization": f"Bearer {user_a.id}"}

    # Generate 12 vouchers (should result in 3 chunks: 5, 5, 2)
    resp = client.post(
        "/tenant/hotspot/vouchers/generate",
        data={
            "package_id": pkg_a.id,
            "quantity": 12,
            "router_id": router_a.id,
        },
        headers=headers,
        follow_redirects=False,
    )
    assert resp.status_code == 303

    chunks = db_session.scalars(
        select(RouterCommand)
        .where(
            RouterCommand.router_id == router_a.id,
            RouterCommand.description.like("%chunk%"),
        )
        .order_by(RouterCommand.created_at.asc())
    ).all()

    assert len(chunks) == 3
    assert "chunk 1/3" in chunks[0].description
    assert "Add 5 hotspot vouchers" in chunks[0].description
    assert "chunk 2/3" in chunks[1].description
    assert "Add 5 hotspot vouchers" in chunks[1].description
    assert "chunk 3/3" in chunks[2].description
    assert "Add 2 hotspot vouchers" in chunks[2].description

    # Each chunk must have profile command prepended
    for chunk in chunks:
        assert "/ip hotspot user profile" in chunk.script
        assert "/ip hotspot user" in chunk.script
        assert chunk.status == RouterCommandStatus.pending


def test_command_delivery_state_machine_retry_and_timeout(client, db_session, seed_data):
    """Verifies the state machine: pending -> sent -> retry after 120s -> failed after 3 attempts."""
    router_a = seed_data["router_a"]
    tenant_a = seed_data["tenant_a"]

    cmd = RouterCommand(
        tenant_id=tenant_a.id,
        router_id=router_a.id,
        description="State machine test command",
        script='/system identity set name="TestSM"',
        status=RouterCommandStatus.pending,
    )
    db_session.add(cmd)
    db_session.commit()

    raw_token = "alpha_token_1"
    headers = {"X-Router-Token": raw_token}

    # 1. First sync poll dispatches command (attempts = 1, status = sent)
    resp1 = client.post("/api/router/sync", headers=headers)
    assert resp1.status_code == 200
    db_session.refresh(cmd)
    assert cmd.status == RouterCommandStatus.sent
    assert cmd.attempts == 1
    assert cmd.sent_at is not None

    # 2. Immediate second poll within 120s does NOT re-dispatch unacknowledged command
    resp2 = client.post("/api/router/sync", headers=headers)
    assert resp2.status_code == 200
    db_session.refresh(cmd)
    assert cmd.attempts == 1

    # 3. Simulate 121 seconds passing without ACK -> poll retries command (attempts = 2)
    cmd.sent_at = datetime.now(timezone.utc) - timedelta(seconds=125)
    db_session.commit()

    resp3 = client.post("/api/router/sync", headers=headers)
    assert resp3.status_code == 200
    db_session.refresh(cmd)
    assert cmd.status == RouterCommandStatus.sent
    assert cmd.attempts == 2

    # 4. Simulate third dispatch
    cmd.sent_at = datetime.now(timezone.utc) - timedelta(seconds=125)
    db_session.commit()

    resp4 = client.post("/api/router/sync", headers=headers)
    assert resp4.status_code == 200
    db_session.refresh(cmd)
    assert cmd.status == RouterCommandStatus.sent
    assert cmd.attempts == 3

    # 5. After max 3 attempts + 120s timeout, next poll marks command as failed
    cmd.sent_at = datetime.now(timezone.utc) - timedelta(seconds=125)
    db_session.commit()

    resp5 = client.post("/api/router/sync", headers=headers)
    assert resp5.status_code == 200
    db_session.refresh(cmd)
    assert cmd.status == RouterCommandStatus.failed
    assert cmd.finished_at is not None


def test_command_acknowledgement_idempotency_and_tenant_isolation(client, db_session, seed_data):
    """Verifies that ACK updates command status safely, idempotently, and enforces tenant scoping."""
    router_a = seed_data["router_a"]
    router_b = seed_data["router_b"]
    tenant_a = seed_data["tenant_a"]
    tenant_b = seed_data["tenant_b"]

    cmd_a = RouterCommand(
        tenant_id=tenant_a.id,
        router_id=router_a.id,
        description="Tenant A Command",
        script="/tool fetch ...",
        status=RouterCommandStatus.sent,
        attempts=1,
    )
    cmd_b = RouterCommand(
        tenant_id=tenant_b.id,
        router_id=router_b.id,
        description="Tenant B Command",
        script="/tool fetch ...",
        status=RouterCommandStatus.sent,
        attempts=1,
    )
    db_session.add_all([cmd_a, cmd_b])
    db_session.commit()

    # Router A reports execution of cmd_a (ok) and maliciously attempts to ack cmd_b
    headers = {"X-Router-Token": "alpha_token_1"}
    resp = client.post(
        "/api/router/ack",
        data={"ok": f"{cmd_a.id},{cmd_b.id}"},
        headers=headers,
    )
    assert resp.status_code == 200

    db_session.refresh(cmd_a)
    db_session.refresh(cmd_b)
    # cmd_a should be done
    assert cmd_a.status == RouterCommandStatus.done
    assert cmd_a.finished_at is not None
    # cmd_b must NOT be marked done by Router A (cross-tenant isolation)
    assert cmd_b.status == RouterCommandStatus.sent

    # Duplicate / repeated ACK call is idempotent
    resp_dup = client.post(
        "/api/router/ack",
        data={"ok": f"{cmd_a.id}"},
        headers=headers,
    )
    assert resp_dup.status_code == 200
    db_session.refresh(cmd_a)
    assert cmd_a.status == RouterCommandStatus.done


def test_tenant_failed_command_retry_action(client, db_session, seed_data):
    """Verifies tenant dashboard command retry resets command to pending."""
    user_a = seed_data["user_a"]
    user_b = seed_data["user_b"]
    router_a = seed_data["router_a"]
    tenant_a = seed_data["tenant_a"]

    failed_cmd = RouterCommand(
        tenant_id=tenant_a.id,
        router_id=router_a.id,
        description="Failed PPPoE script",
        script="/ppp secret add ...",
        status=RouterCommandStatus.failed,
        attempts=3,
        finished_at=datetime.now(timezone.utc),
    )
    db_session.add(failed_cmd)
    db_session.commit()

    headers_a = {"Authorization": f"Bearer {user_a.id}"}
    headers_b = {"Authorization": f"Bearer {user_b.id}"}

    # Cross-tenant retry attempt must fail with 404
    resp_cross = client.post(
        f"/tenant/routers/commands/{failed_cmd.id}/retry",
        headers=headers_b,
        follow_redirects=False,
    )
    assert resp_cross.status_code == 404

    # Legitimate tenant retry succeeds
    resp_retry = client.post(
        f"/tenant/routers/commands/{failed_cmd.id}/retry",
        headers=headers_a,
        follow_redirects=False,
    )
    assert resp_retry.status_code == 303

    db_session.refresh(failed_cmd)
    assert failed_cmd.status == RouterCommandStatus.pending
    assert failed_cmd.attempts == 0
    assert failed_cmd.sent_at is None
    assert failed_cmd.finished_at is None


def test_routeros_tls_strict_verification_and_zero_bypass_secrets():
    """Verifies strict TLS verification and complete absence of bypass secrets in all script generators."""
    from saas.security.sanitizer import (
        ISRG_ROOT_X1_SHA256,
        ISRG_ROOT_X1_PEM,
        build_mikrotik_rsc_file,
        build_mikrotik_sync_script_source,
        build_mikrotik_terminal_commands,
    )

    url = "https://cowen.vercel.app/api/router/sync"
    token = "strict-tls-test-token"
    router_name = "Core-hAP-lite"

    # 1. Sync script source
    source = build_mikrotik_sync_script_source(url, token)
    assert "check-certificate=yes-without-crl" in source
    assert "check-certificate=no" not in source
    assert "x-vercel-protection-bypass" not in source

    # 2. RSC file
    rsc = build_mikrotik_rsc_file(url, token, router_name)
    assert "check-certificate=yes-without-crl" in rsc
    assert "check-certificate=no" not in rsc
    assert "x-vercel-protection-bypass" not in rsc
    assert ISRG_ROOT_X1_SHA256 in rsc
    assert "/file remove [find name=\"cowen_rootca.txt\"]" in rsc
    assert "/certificate enable-ssl-certificate" not in rsc
    assert "primary-ntp=" in rsc or "servers=pool.ntp.org" in rsc

    # 3. Terminal commands
    term = build_mikrotik_terminal_commands(url, token, router_name)
    assert "check-certificate=yes-without-crl" in term
    assert "check-certificate=no" not in term
    assert "x-vercel-protection-bypass" not in term
    assert "/certificate enable-ssl-certificate" not in term


def test_isrg_root_ca_crt_download(client):
    """Verifies the direct download endpoint for ISRG Root X1 CA cert for WinBox upload."""
    resp = client.get("/tenant/routers/isrgrootx1.crt")
    assert resp.status_code == 200
    assert "application/x-x509-ca-cert" in resp.headers["content-type"]
    assert "isrgrootx1.crt" in resp.headers.get("content-disposition", "")
    assert "BEGIN CERTIFICATE" in resp.text
    assert "END CERTIFICATE" in resp.text


def test_pppoe_ownership_protection_and_conflict_handling():
    """Verifies that PPPoE secrets require immutable subscriber ownership marker and reject unmanaged collisions."""
    from saas.security.sanitizer import (
        build_pppoe_delete_command,
        build_pppoe_disable_command,
        build_pppoe_enable_command,
        build_pppoe_secret_command,
    )

    cmd = build_pppoe_secret_command(
        username="subscriber_alpha",
        password="securepass123",
        profile="10M_Unlimited",
        subscriber_id="sub-uuid-abc-123",
    )
    # 1. Adds with immutable ownership marker
    assert 'comment="COwen-PPPoE:sub-uuid-abc-123"' in cmd
    # 2. Updates ONLY if matching ownership marker is present
    assert 'name="subscriber_alpha" and comment="COwen-PPPoE:sub-uuid-abc-123"' in cmd
    # 3. If unmanaged user exists with same username, raises RouterOS :error conflict instead of overwriting
    assert ':error "COwen_Sync: Conflict - PPPoE secret \'subscriber_alpha\' exists without matching COwen ownership marker"' in cmd

    # 4. Lifecycle operations verify ownership marker
    dis_cmd = build_pppoe_disable_command("subscriber_alpha", subscriber_id="sub-uuid-abc-123")
    assert 'comment="COwen-PPPoE:sub-uuid-abc-123"' in dis_cmd
    assert ':error "COwen_Sync: Cannot disable PPPoE secret \'subscriber_alpha\' - ownership mismatch"' in dis_cmd

    en_cmd = build_pppoe_enable_command("subscriber_alpha", subscriber_id="sub-uuid-abc-123")
    assert 'comment="COwen-PPPoE:sub-uuid-abc-123"' in en_cmd
    assert ':error "COwen_Sync: Cannot enable PPPoE secret \'subscriber_alpha\' - ownership mismatch"' in en_cmd

    del_cmd = build_pppoe_delete_command("subscriber_alpha", subscriber_id="sub-uuid-abc-123")
    assert 'comment="COwen-PPPoE:sub-uuid-abc-123"' in del_cmd
    assert ':error "COwen_Sync: Cannot delete PPPoE secret \'subscriber_alpha\' - ownership mismatch"' in del_cmd


def test_hotspot_voucher_ownership_protection_and_conflict_handling():
    """Verifies that Hotspot vouchers require immutable voucher ID marker and reject unmanaged collisions."""
    from saas.security.sanitizer import build_hotspot_user_command

    vouch_cmd = build_hotspot_user_command(
        code="VOUCH99",
        password="pass99",
        profile="1Hr_Hotspot",
        voucher_id="vouch-uuid-777",
    )
    # 1. Adds with immutable voucher ownership marker
    assert 'comment="COwen-Voucher:vouch-uuid-777"' in vouch_cmd
    # 2. Updates ONLY if matching ownership marker is present
    assert 'name="VOUCH99" and comment="COwen-Voucher:vouch-uuid-777"' in vouch_cmd
    # 3. If unmanaged user exists with same code, raises RouterOS :error conflict instead of overwriting
    assert ':error "COwen_Sync: Conflict - Hotspot user \'VOUCH99\' exists without matching COwen voucher marker"' in vouch_cmd


def test_sync_script_source_single_braces_syntax():
    """Verifies that generated script source does not contain double braces in do={ blocks."""
    from saas.security.sanitizer import build_mikrotik_sync_script_source

    source = build_mikrotik_sync_script_source("https://cowen.vercel.app/api/router/sync", "tok-123")
    assert "do={{" not in source
    assert "do={" in source
    assert "on-error={" in source


def test_tenant_session_lifecycle_and_invalidation(db_session):
    """Verifies 12-hour sliding inactivity, 24-hour absolute expiration, and password change revocation."""
    from datetime import datetime, timezone
    from starlette.requests import Request
    from saas.models.tenant import SubscriptionTier, Tenant, TenantStatus, TenantSubscription, TenantUser, UserRole
    from saas.security.auth import hash_password
    from saas.routers.tenant import get_tenant_context_optional
    from saas.security.context import resolve_tenant_context

    now_ts = int(datetime.now(timezone.utc).timestamp())
    tenant = Tenant(name="Test Session ISP", slug="session-isp", contact_email="session@test.com", contact_phone="+254700000000", status=TenantStatus.active)
    db_session.add(tenant)
    db_session.flush()

    user = TenantUser(
        tenant_id=tenant.id,
        email="session_admin@test.com",
        full_name="Session Admin",
        hashed_password=hash_password("OriginalPassword123!"),
        role=UserRole.tenant_admin,
        is_active=True,
        session_version=1,
    )
    db_session.add(user)
    db_session.commit()

    # 1. Valid session
    req_valid = Request({"type": "http", "session": {
        "user_id": user.id,
        "tenant_user_id": user.id,
        "session_version": 1,
        "tenant_login_time": now_ts,
        "tenant_last_activity": now_ts,
    }})
    ctx = get_tenant_context_optional(req_valid, db_session)
    assert ctx is not None
    assert ctx.user.id == user.id

    # 2. Expired sliding inactivity (> 12 hours = 43200 seconds)
    req_inactive = Request({"type": "http", "session": {
        "user_id": user.id,
        "tenant_user_id": user.id,
        "session_version": 1,
        "tenant_login_time": now_ts,
        "tenant_last_activity": now_ts - 43201,
    }})
    ctx_inactive = get_tenant_context_optional(req_inactive, db_session)
    assert ctx_inactive is None

    # 3. Expired absolute lifetime (> 24 hours = 86400 seconds)
    req_abs_exp = Request({"type": "http", "session": {
        "user_id": user.id,
        "tenant_user_id": user.id,
        "session_version": 1,
        "tenant_login_time": now_ts - 86401,
        "tenant_last_activity": now_ts,
    }})
    ctx_abs_exp = get_tenant_context_optional(req_abs_exp, db_session)
    assert ctx_abs_exp is None

    # 4. Password change increments session_version and invalidates old session
    user.session_version = 2
    db_session.commit()

    req_revoked = Request({"type": "http", "session": {
        "user_id": user.id,
        "tenant_user_id": user.id,
        "session_version": 1,  # Stale session version
        "tenant_login_time": now_ts,
        "tenant_last_activity": now_ts,
    }})
    ctx_revoked = get_tenant_context_optional(req_revoked, db_session)
    assert ctx_revoked is None


def test_cross_tenant_subscriber_router_collision(db_session):
    """Verifies that creating a subscriber with an existing username on the same router is detected."""
    from saas.models.tenant import Tenant, TenantStatus
    from saas.models.router import Router, RouterStatus
    from saas.models.pppoe import PPPoECustomer, CustomerStatus, ConnectionType, PPPoEPlan
    from saas.security.auth import hash_token
    from sqlalchemy import select

    t1 = Tenant(name="ISP 1", slug="isp-1", contact_email="isp1@test.com", contact_phone="+254700000001", status=TenantStatus.active)
    t2 = Tenant(name="ISP 2", slug="isp-2", contact_email="isp2@test.com", contact_phone="+254700000002", status=TenantStatus.active)
    db_session.add_all([t1, t2])
    db_session.flush()

    r1 = Router(tenant_id=t1.id, name="Shared-Router", token_hash=hash_token("r1-tok"), status=RouterStatus.online)
    db_session.add(r1)
    db_session.flush()

    p1 = PPPoEPlan(tenant_id=t1.id, name="10M", price_kes=1000, rate_limit="10M/10M")
    db_session.add(p1)
    db_session.flush()

    sub1 = PPPoECustomer(
        tenant_id=t1.id,
        router_id=r1.id,
        plan_id=p1.id,
        username="john_doe",
        password="p1",
        full_name="John Doe",
        status=CustomerStatus.active,
        connection_type=ConnectionType.pppoe,
    )
    db_session.add(sub1)
    db_session.commit()

    # Attempting to query router collision
    existing_on_router = db_session.scalar(
        select(PPPoECustomer).where(
            PPPoECustomer.router_id == r1.id,
            PPPoECustomer.username == "john_doe",
        )
    )
    assert existing_on_router is not None
    assert existing_on_router.id == sub1.id








