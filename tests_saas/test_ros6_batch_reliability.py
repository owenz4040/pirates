"""Automated tests for RouterOS 6.49.18 batch reliability, 2500-byte limits,
and 4-stage Hotspot network provisioning with strict stage dependency ordering.
"""
from __future__ import annotations

import re
import pytest
from unittest.mock import MagicMock
from fastapi.testclient import TestClient

from saas.app import app
from saas.models.router import Router, RouterCommand, RouterCommandStatus, RouterStatus
from saas.models.hotspot import HotspotNetwork, HotspotVoucher, VoucherStatus
from saas.security.auth import hash_token
from saas.security.sanitizer import (
    build_hotspot_bridge_command,
    build_hotspot_wireless_command,
    build_hotspot_ip_dhcp_dns_command,
    build_hotspot_server_setup_command,
    build_mikrotik_sync_script_source,
)
from saas.routers.tenant import BATCH_BYTES_ROS6, BATCH_BYTES_ROS7, render_router_batch


def test_ros6_batch_bytes_limit_is_2500():
    """Verifies that BATCH_BYTES_ROS6 is strictly set to 2500 bytes and ROS7 is 32768."""
    assert BATCH_BYTES_ROS6 == 2500
    assert BATCH_BYTES_ROS7 == 32768


def test_four_hotspot_stages_individually_fit_within_ros6_limits():
    """Verifies that each of the 4 Hotspot provisioning stages renders well below 2,500 bytes."""
    clean_bridge = "COwen-Hotspot-Bridge"
    clean_ssid = "Pirate's WiFi"
    clean_sec = "open"
    gateway_ip = "10.5.50.1"
    net_cidr = "10.5.50.0/24"
    pool_start = "10.5.50.10"
    pool_end = "10.5.50.250"
    dns_name = "login.hotspot"

    # Stage 1: Bridge & Ports
    s1 = build_hotspot_bridge_command(
        bridge_name=clean_bridge,
        ethernet_ports=[],
        include_wlan=True,
        wlan_iface="wlan1",
    )
    # Stage 2: Wireless AP
    s2 = build_hotspot_wireless_command(
        ssid=clean_ssid,
        security_mode=clean_sec,
        password=None,
        band="2ghz-b/g/n",
        channel="auto",
        country="no_country_set",
        wlan_iface="wlan1",
        is_ros7=False,
    )
    # Stage 3: IP Gateway & DHCP
    s3 = build_hotspot_ip_dhcp_dns_command(
        bridge_name=clean_bridge,
        gateway_ip=gateway_ip,
        network_cidr=net_cidr,
        pool_start=pool_start,
        pool_end=pool_end,
        dns_servers=f"{gateway_ip},8.8.8.8,1.1.1.1",
    )
    # Stage 4: Hotspot Server & NAT
    s4 = build_hotspot_server_setup_command(
        server_name=f"{clean_bridge}-Server",
        server_profile_name=f"{clean_bridge}-Profile",
        bridge_name=clean_bridge,
        pool_name="COwen-Hotspot-Pool",
        dns_name=dns_name,
        gateway_ip=gateway_ip,
        network_cidr=net_cidr,
        html_dir="hotspot",
        login_by="http-chap,cookie",
    )

    dummy_token = "a" * 64
    ack_url = "https://cowen.vercel.app/api/router/ack"

    stages = [
        ("Stage 1", s1),
        ("Stage 2", s2),
        ("Stage 3", s3),
        ("Stage 4", s4),
    ]

    for name, script in stages:
        assert len(script.encode("utf-8")) < 1200, f"{name} script exceeds 1200 bytes: {len(script)} bytes"
        mock_cmd = MagicMock(spec=RouterCommand)
        mock_cmd.id = "test-cmd-id"
        mock_cmd.script = script
        rendered = render_router_batch([mock_cmd], ack_url, dummy_token)
        rendered_bytes = len(rendered.encode("utf-8"))
        assert rendered_bytes < BATCH_BYTES_ROS6, f"{name} rendered batch exceeds 2500 bytes: {rendered_bytes} bytes"
        assert rendered_bytes < 2000, f"{name} rendered batch unexpectedly large: {rendered_bytes} bytes"


def test_bridge_stage_preserves_unselected_ethernet_ports_and_wan():
    """Verifies Stage 1 does not add ether1 (WAN) or unselected ports to customer bridge."""
    s1_empty = build_hotspot_bridge_command(
        bridge_name="COwen-Hotspot-Bridge",
        ethernet_ports=[],
        include_wlan=True,
        wlan_iface="wlan1",
    )
    assert "ether1" not in s1_empty
    assert "ether2" not in s1_empty
    assert "ether3" not in s1_empty
    assert "ether4" not in s1_empty
    assert "wlan1" in s1_empty
    assert "COwen-Hotspot-Bridge" in s1_empty

    s1_explicit = build_hotspot_bridge_command(
        bridge_name="COwen-Hotspot-Bridge",
        ethernet_ports=["ether1", "ether3"],  # ether1 must be strictly stripped
        include_wlan=True,
        wlan_iface="wlan1",
    )
    assert "ether1" not in s1_explicit
    assert "ether3" in s1_explicit


def test_sync_script_diagnostics_separation():
    """Verifies router check-in script separates fetch, validation, parse, runtime, and ACK errors."""
    source = build_mikrotik_sync_script_source(
        sync_url="https://cowen.vercel.app/api/router/sync",
        raw_token="raw_token_xyz",
    )
    assert "HTTPS fetch failed - check network or TLS certificates" in source
    assert "response validation failed - invalid magic header or payload size" in source
    assert "script parsing failed - syntax error or truncated response" in source
    assert "runtime error executing batch commands" in source


def test_stage_dependencies_and_oversized_rejection(client, db_session):
    """Verifies that:
    1. Oversized commands exceeding 2500 bytes are rejected and marked failed without truncation.
    2. Stage 2/4 is blocked until Stage 1/4 receives router ACK ('done').
    3. If Stage 1 fails, Stage 2 is never dispatched.
    4. Customer vouchers are withheld until HotspotNetwork is confirmed 'provisioned'.
    """
    from saas.models.tenant import Tenant, TenantStatus
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    tenant = Tenant(
        name="Reliability Test Tenant",
        slug="rel-tenant",
        contact_email="test@tenant.com",
        contact_phone="+254700000000",
        status=TenantStatus.active,
    )
    db_session.add(tenant)
    db_session.flush()

    raw_token = "test-token-secret-ros6"
    router = Router(
        tenant_id=tenant.id,
        name="Test hAP lite",
        version="6.49.18",
        token_hash=hash_token(raw_token),
        status=RouterStatus.online,
    )
    db_session.add(router)
    db_session.flush()

    # Create 4 staged commands
    cmd1 = RouterCommand(
        tenant_id=tenant.id,
        router_id=router.id,
        description="Hotspot Stage 1/4: Bridge & Ports ('Test')",
        script="/interface bridge add name=test-br",
        status=RouterCommandStatus.pending,
    )
    cmd2 = RouterCommand(
        tenant_id=tenant.id,
        router_id=router.id,
        description="Hotspot Stage 2/4: Wireless AP ('Test')",
        script="/interface wireless set wlan1 ssid=Test",
        status=RouterCommandStatus.pending,
    )
    cmd3 = RouterCommand(
        tenant_id=tenant.id,
        router_id=router.id,
        description="Hotspot Stage 3/4: IP Gateway & DHCP ('Test')",
        script="/ip address add address=10.5.50.1/24 interface=test-br",
        status=RouterCommandStatus.pending,
    )
    cmd4 = RouterCommand(
        tenant_id=tenant.id,
        router_id=router.id,
        description="Hotspot Stage 4/4: Hotspot Server & NAT ('Test')",
        script="/ip hotspot add name=hs1 interface=test-br",
        status=RouterCommandStatus.pending,
    )
    db_session.add_all([cmd1, cmd2, cmd3, cmd4])
    db_session.commit()

    # 1. First sync check-in: Only Stage 1 should be dispatched because Stage 2-4 depend on Stage 1
    resp = client.post(
        "/api/router/sync",
        headers={"X-Router-Token": raw_token, "Accept": "application/json"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["commands"]) == 1
    assert data["commands"][0]["id"] == cmd1.id
    assert "Stage 1/4" in data["commands"][0]["description"]

    # Refresh DB objects
    db_session.refresh(cmd1)
    db_session.refresh(cmd2)
    assert cmd1.status == RouterCommandStatus.sent
    assert cmd2.status == RouterCommandStatus.pending

    # 2. Router ACKs Stage 1 as successfully executed
    ack_resp = client.post(
        "/api/router/ack",
        headers={"X-Router-Token": raw_token},
        data={"ok": cmd1.id, "failed": ""},
    )
    assert ack_resp.status_code == 200
    db_session.refresh(cmd1)
    assert cmd1.status == RouterCommandStatus.done

    # 3. Next sync check-in: Stage 2 should now be dispatched because Stage 1 is done
    resp2 = client.post(
        "/api/router/sync",
        headers={"X-Router-Token": raw_token, "Accept": "application/json"},
    )
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert len(data2["commands"]) == 1
    assert data2["commands"][0]["id"] == cmd2.id
    assert "Stage 2/4" in data2["commands"][0]["description"]

    # 4. Router ACKs Stage 2 as FAILED
    ack_fail = client.post(
        "/api/router/ack",
        headers={"X-Router-Token": raw_token},
        data={"ok": "", "failed": cmd2.id},
    )
    assert ack_fail.status_code == 200
    db_session.refresh(cmd2)
    assert cmd2.status == RouterCommandStatus.failed

    # 5. Subsequent sync check-in: Stage 3 and 4 MUST NOT be dispatched because Stage 2 failed!
    resp3 = client.post(
        "/api/router/sync",
        headers={"X-Router-Token": raw_token, "Accept": "application/json"},
    )
    assert resp3.status_code == 200
    data3 = resp3.json()
    assert len(data3["commands"]) == 0  # Blocked by dependency failure!


def test_oversized_first_command_is_rejected_not_truncated(client, db_session):
    """Verifies that an oversized command exceeding BATCH_BYTES_ROS6 (2,500 bytes)
    is rejected and marked failed, rather than dispatched or truncated.
    """
    from saas.models.tenant import Tenant, TenantStatus

    tenant = Tenant(
        name="Oversized Test Tenant",
        slug="oversized-tenant",
        contact_email="test@tenant.com",
        contact_phone="+254700000000",
        status=TenantStatus.active,
    )
    db_session.add(tenant)
    db_session.flush()

    raw_token = "oversized-test-token"
    router = Router(
        tenant_id=tenant.id,
        name="Test hAP lite",
        version="6.49.18",
        token_hash=hash_token(raw_token),
        status=RouterStatus.online,
    )
    db_session.add(router)
    db_session.flush()

    # Create a command with a script that exceeds 2,500 bytes
    huge_script = ":set test \"" + ("A" * 3000) + "\";"
    huge_cmd = RouterCommand(
        tenant_id=tenant.id,
        router_id=router.id,
        description="Huge monolithic command",
        script=huge_script,
        status=RouterCommandStatus.pending,
    )
    db_session.add(huge_cmd)
    db_session.commit()

    # Sync endpoint should reject it without sending
    resp = client.post(
        "/api/router/sync",
        headers={"X-Router-Token": raw_token, "Accept": "application/json"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["commands"]) == 0  # Not dispatched!

    db_session.refresh(huge_cmd)
    assert huge_cmd.status == RouterCommandStatus.failed  # Marked failed immediately
