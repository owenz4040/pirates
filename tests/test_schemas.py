from __future__ import annotations

import pytest

from billing.schemas import _normalize_kenyan_phone


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("0703551813", "+254703551813"),
        ("254703551813", "+254703551813"),
        ("+254703551813", "+254703551813"),
        (" 0703551813 ", "+254703551813"),
    ],
)
def test_normalize_kenyan_phone_accepts_common_formats(raw, expected):
    assert _normalize_kenyan_phone(raw) == expected


def test_normalize_kenyan_phone_rejects_garbage():
    with pytest.raises(ValueError):
        _normalize_kenyan_phone("not-a-phone-number")


def test_validate_ip():
    from billing.schemas import _validate_ip

    assert _validate_ip("192.168.88.50") == "192.168.88.50"
    assert _validate_ip("10.0.0.1/32") == "10.0.0.1"
    assert _validate_ip("192.168.88.48/29") == "192.168.88.48/29"
    assert _validate_ip("192.168.88.50/29") == "192.168.88.48/29"
    assert _validate_ip("10.10.10.0/24") == "10.10.10.0/24"
    assert _validate_ip(None) is None
    assert _validate_ip("") is None

    with pytest.raises(ValueError):
        _validate_ip("invalid-ip")

    with pytest.raises(ValueError):
        _validate_ip("999.999.999.999")

    with pytest.raises(ValueError):
        _validate_ip("192.168.88.50/99")


def test_customer_create_static():
    from billing.models import ConnectionType
    from billing.schemas import CustomerCreate

    payload = CustomerCreate(
        pppoe_username="static-alice",
        full_name="Alice Smith",
        phone_number="0712345678",
        plan_id=1,
        connection_type=ConnectionType.static,
        static_ip="192.168.1.100",
    )
    assert payload.connection_type == ConnectionType.static
    assert payload.static_ip == "192.168.1.100"
    assert payload.phone_number == "+254712345678"


def test_customer_create_static_repeater_pool():
    from billing.models import ConnectionType
    from billing.schemas import CustomerCreate

    payload = CustomerCreate(
        pppoe_username="repeater-bob",
        full_name="Bob Jones",
        phone_number="0722112233",
        plan_id=2,
        connection_type=ConnectionType.static,
        static_ip="192.168.88.48/29",
    )
    assert payload.connection_type == ConnectionType.static
    assert payload.static_ip == "192.168.88.48/29"
    assert payload.phone_number == "+254722112233"

