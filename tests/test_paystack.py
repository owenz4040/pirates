from __future__ import annotations

from billing.mpesa.paystack import parse_webhook_event


def test_parse_webhook_event_extracts_payer_phone():
    payload = {
        "event": "charge.success",
        "data": {
            "reference": "TestPay01-abc123",
            "status": "success",
            "amount": 100000,
            "id": 6428244558,
            "authorization": {"mobile_money_number": "254703551813"},
        },
    }
    result = parse_webhook_event(payload)
    assert result["payer_phone"] == "254703551813"
    assert result["amount_kes"] == 1000.0
    assert result["reference"] == "TestPay01-abc123"


def test_parse_webhook_event_missing_authorization():
    payload = {"event": "charge.failed", "data": {"reference": "x", "status": "failed"}}
    result = parse_webhook_event(payload)
    assert result["payer_phone"] is None
