from __future__ import annotations

from datetime import datetime
from decimal import Decimal

from pydantic import BaseModel, ConfigDict, field_validator

from billing.models import CustomerStatus, PaymentStatus


def _normalize_kenyan_phone(value: str) -> str:
    """
    Normalize to +254XXXXXXXXX so every downstream consumer (Paystack, the
    SMS client) can rely on a single consistent format instead of each
    defensively re-adding a '+' - we hit a real bug from exactly that gap.
    """
    digits = value.strip().replace(" ", "")
    if digits.startswith("+254"):
        return digits
    if digits.startswith("254"):
        return f"+{digits}"
    if digits.startswith("0"):
        return f"+254{digits[1:]}"
    raise ValueError(f"Expected a Kenyan number (07.../2547.../+2547...), got {value!r}")


class PlanCreate(BaseModel):
    name: str
    rate_limit: str
    price_kes: Decimal
    duration_days: int = 30


class PlanUpdate(BaseModel):
    rate_limit: str | None = None
    price_kes: Decimal | None = None
    duration_days: int | None = None


class PlanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    rate_limit: str
    price_kes: Decimal
    duration_days: int


class CustomerCreate(BaseModel):
    pppoe_username: str
    pppoe_password: str
    full_name: str
    phone_number: str
    email: str | None = None
    plan_id: int

    _normalize_phone = field_validator("phone_number")(_normalize_kenyan_phone)


class CustomerOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    pppoe_username: str
    full_name: str
    phone_number: str
    email: str | None
    plan_id: int
    status: CustomerStatus
    expires_at: datetime


class CustomerStatusOut(CustomerOut):
    online: bool


class CustomerCreateOut(CustomerOut):
    welcome_email_sent: bool
    welcome_email_error: str | None = None


class ChangePlan(BaseModel):
    plan_id: int


class CustomerUpdate(BaseModel):
    full_name: str | None = None
    phone_number: str | None = None
    email: str | None = None

    _normalize_phone = field_validator("phone_number")(
        lambda v: _normalize_kenyan_phone(v) if v is not None else v
    )


class PaymentCreate(BaseModel):
    """Manual payment entry (cash, adjustments) - M-Pesa payments go through the Paystack charge/webhook flow instead."""

    amount_kes: Decimal
    mpesa_receipt: str | None = None
    phone_number: str | None = None


class PaymentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    customer_id: int
    amount_kes: Decimal
    status: PaymentStatus
    mpesa_receipt: str | None
    created_at: datetime
    confirmed_at: datetime | None
