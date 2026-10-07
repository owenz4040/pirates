"""Business logic that ties the customers/plans/payments tables to the router.

Kept separate from the routers so the expiry worker (a standalone process,
not a FastAPI request) can call the same functions instead of duplicating them.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from billing.config import settings
from billing.email import client as email_client
from billing.email.layout import BRAND, Email
from billing.email.layout import render as render_email
from billing.models import ConnectionType, Customer, CustomerStatus, Payment, PaymentStatus, Plan
from billing.mpesa import paystack
from mikrotik.bandwidth import BandwidthProfileManager
from mikrotik.pppoe import PPPoEManager
from mikrotik.static_user import StaticUserManager

_EAT = timezone(timedelta(hours=3), "EAT")


def _fmt_eat(value: datetime) -> str:
    if value.tzinfo is None:  # stored as UTC
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(_EAT).strftime("%d %b %Y, %H:%M") + " EAT"


def create_customer(
    db: Session,
    ppp: PPPoEManager | None = None,
    *,
    pppoe_username: str,
    pppoe_password: str = "",
    full_name: str,
    phone_number: str,
    plan: Plan,
    connection_type: ConnectionType = ConnectionType.pppoe,
    static_ip: str | None = None,
    email: str | None = None,
    no_expiry: bool = False,
    static_mgr: StaticUserManager | None = None,
) -> Customer:
    """
    Create the PPPoE secret or Simple Queue on the router, then the billing record.

    New customers start already expired - they only become active through
    record_payment(), same path an existing customer's renewal takes.
    Unless no_expiry is True, in which case they are activated immediately.
    """
    if connection_type == ConnectionType.static:
        if not static_ip:
            raise ValueError("Static IP is required for static connection type")
        if static_mgr:
            static_mgr.create_or_update_queue(
                name=pppoe_username,
                target_ip=static_ip,
                rate_limit=plan.rate_limit,
                comment=full_name,
            )
            if no_expiry:
                static_mgr.restore_user(static_ip)
                status = CustomerStatus.active
                expires_at = None
            else:
                static_mgr.suspend_user(static_ip, comment=full_name)
                status = CustomerStatus.expired
                expires_at = datetime.now(timezone.utc)
        else:
            status = CustomerStatus.active if no_expiry else CustomerStatus.expired
            expires_at = None if no_expiry else datetime.now(timezone.utc)
    else:
        if ppp:
            ppp.create_secret(pppoe_username, pppoe_password, profile=plan.name, comment=full_name)
            if no_expiry:
                ppp.enable_user(pppoe_username)
                status = CustomerStatus.active
                expires_at = None
            else:
                ppp.disable_user(pppoe_username)
                status = CustomerStatus.expired
                expires_at = datetime.now(timezone.utc)
        else:
            status = CustomerStatus.active if no_expiry else CustomerStatus.expired
            expires_at = None if no_expiry else datetime.now(timezone.utc)

    customer = Customer(
        pppoe_username=pppoe_username,
        full_name=full_name,
        phone_number=phone_number,
        email=email,
        connection_type=connection_type,
        static_ip=static_ip,
        plan_id=plan.id,
        status=status,
        expires_at=expires_at,
    )
    db.add(customer)
    db.commit()
    db.refresh(customer)
    return customer


def _extend_subscription(customer: Customer) -> datetime:
    """
    Push expires_at out by one plan cycle from the later of now or the
    current expiry, so paying before the old period lapses doesn't forfeit
    the remaining paid days. Returns the "now" used, for confirmed_at.
    """
    now = datetime.now(timezone.utc)
    current_expires = customer.expires_at
    if current_expires is not None and current_expires.tzinfo is None:
        current_expires = current_expires.replace(tzinfo=timezone.utc)
    base = max(now, current_expires) if current_expires else now
    customer.expires_at = base + timedelta(days=customer.plan.duration_days)
    customer.status = CustomerStatus.active
    customer.reminder_2_days_sent = False
    customer.reminder_1_day_sent = False
    return now


def record_payment(
    db: Session,
    ppp: PPPoEManager | None = None,
    *,
    customer: Customer,
    amount_kes: Decimal,
    mpesa_receipt: str | None,
    phone_number: str | None,
    checkout_request_id: str | None = None,
    static_mgr: StaticUserManager | None = None,
) -> Payment:
    """Record and immediately confirm a payment - for manual/cash entry, not the M-Pesa callback path."""
    now = _extend_subscription(customer)
    db.add(customer)

    payment = Payment(
        customer_id=customer.id,
        amount_kes=amount_kes,
        status=PaymentStatus.confirmed,
        mpesa_receipt=mpesa_receipt,
        checkout_request_id=checkout_request_id,
        phone_number=phone_number or customer.phone_number,
        confirmed_at=now,
    )
    db.add(payment)
    _reactivate_on_router(customer, ppp, static_mgr)
    db.commit()
    db.refresh(customer)
    db.refresh(payment)
    return payment


def _reactivate_on_router(
    customer: Customer, ppp: PPPoEManager | None, static_mgr: StaticUserManager | None
) -> None:
    """
    Put a paid-up customer back on their plan's speed and let them online.
    Called before commit so queued router commands save in the same
    transaction as the payment.
    """
    if customer.connection_type == ConnectionType.static:
        if static_mgr:
            static_mgr.set_bandwidth(customer.pppoe_username, customer.plan.rate_limit)
            if customer.static_ip:
                static_mgr.restore_user(customer.static_ip)
    else:
        if ppp:
            ppp.set_profile(customer.pppoe_username, customer.plan.name)
            ppp.enable_user(customer.pppoe_username)


def create_pending_payment(
    db: Session,
    *,
    customer: Customer,
    amount_kes: Decimal,
    phone_number: str,
    checkout_request_id: str,
) -> Payment:
    """Record an STK push that's been sent but not yet answered by the customer."""
    payment = Payment(
        customer_id=customer.id,
        amount_kes=amount_kes,
        status=PaymentStatus.pending,
        phone_number=phone_number,
        checkout_request_id=checkout_request_id,
    )
    db.add(payment)
    db.commit()
    db.refresh(payment)
    return payment


def find_customer_by_phone(db: Session, phone_number: str) -> Customer | None:
    """Fallback match for walk-in paybill payments that didn't use the exact account code we generated."""
    return db.scalar(select(Customer).where(Customer.phone_number == phone_number))


def request_paybill_charge(db: Session, customer: Customer) -> dict[str, Any]:
    """
    Generate a one-time Paystack paybill code for a customer's plan price and
    record it as a pending payment. Shared by the manual "generate paybill
    code" action and the new-customer welcome message.
    """
    plan = customer.plan
    reference = f"{customer.pppoe_username}-{uuid.uuid4().hex[:12]}"
    data = paystack.initiate_paybill_charge(
        email=f"{customer.pppoe_username}@pirates.example.com",
        amount_kes=int(plan.price_kes),
        reference=reference,
    )
    create_pending_payment(
        db,
        customer=customer,
        amount_kes=plan.price_kes,
        phone_number=customer.phone_number or "",
        checkout_request_id=reference,
    )
    return {
        "reference": reference,
        "paybill": data.get("account_number"),
        "account_number": data.get("account_reference"),
        "amount_kes": int(plan.price_kes),
    }


def request_mpesa_charge(db: Session, customer: Customer) -> str:
    """
    Push an M-Pesa STK prompt to the customer's phone for their plan's price
    and record it as a pending payment. Shared by the admin-triggered "Send
    M-Pesa prompt" action and the public "Pay Now" email link. Returns the
    reference the webhook will echo back.
    """
    plan = customer.plan
    if not customer.phone_number:
        raise paystack.PaystackError(f"{customer.pppoe_username} has no phone number on file - add one first")
    reference = f"{customer.pppoe_username}-{uuid.uuid4().hex[:12]}"
    phone_number = customer.phone_number
    if not phone_number.startswith("+"):
        phone_number = f"+{phone_number}"

    paystack.initiate_mpesa_charge(
        email=f"{customer.pppoe_username}@pirates.example.com",
        phone_number=phone_number,
        amount_kes=int(plan.price_kes),
        reference=reference,
    )
    create_pending_payment(
        db,
        customer=customer,
        amount_kes=plan.price_kes,
        phone_number=customer.phone_number,
        checkout_request_id=reference,
    )
    return reference


def compose_welcome_message(customer: Customer, paybill_info: dict[str, Any]) -> str:
    return (
        f"Welcome to Pirates, {customer.full_name}! Your account ({customer.pppoe_username}) "
        f"is set up. To activate, pay KES {paybill_info['amount_kes']} via M-Pesa: "
        f"Paybill {paybill_info['paybill']}, Account {paybill_info['account_number']}. "
        "Your internet activates automatically once payment is confirmed."
    )


def _plan_speed_label(plan: Plan) -> str:
    """
    What customers are told the plan's speed is. Prefers plan.marketing_speed
    (set explicitly per plan, since the RouterOS rate-limit is often padded
    below the advertised number for overhead - e.g. "isp-9m" sold as
    "10mbps"). Falls back to pulling a "<number><unit>" out of the plan name
    itself (e.g. "isp-9m" -> "9mbps"), or the raw name if that doesn't match.
    """
    if plan.marketing_speed:
        return plan.marketing_speed
    plan_name = plan.name
    match = re.search(r"(\d+)\s*(mb?|kb?)\b", plan_name, re.IGNORECASE)
    if not match:
        return plan_name
    value, unit = match.group(1), match.group(2)[0].lower()
    return f"{value}{unit}bps"


def _pay_link(customer: Customer) -> str | None:
    if not settings.public_base_url:
        return None
    return f"{settings.public_base_url.rstrip('/')}/pay/{customer.pppoe_username}/{customer.pay_token}/mpesa"


def try_paybill_charge(db: Session, customer: Customer) -> tuple[dict[str, Any] | None, str | None]:
    """
    request_paybill_charge for emails: a Paystack failure (bad key, outage)
    must not stop the email going out, so return (None, reason) instead of
    raising. The email then shows the amount and the pay link without a code.
    """
    try:
        return request_paybill_charge(db, customer), None
    except Exception as exc:  # noqa: BLE001 - any Paystack failure degrades the email, never blocks it
        db.rollback()
        print(f"Paybill code for {customer.pppoe_username} failed: {exc}")
        return None, str(exc)


def _payment_details(customer: Customer, paybill_info: dict[str, Any] | None) -> list[tuple[str, str]]:
    if paybill_info is None:
        return [("Amount", f"KES {int(customer.plan.price_kes)}")]
    return [
        ("Amount", f"KES {paybill_info['amount_kes']}"),
        ("M-Pesa Paybill", str(paybill_info["paybill"])),
        ("Account number", str(paybill_info["account_number"])),
    ]


def _pay_button(customer: Customer, label: str) -> dict[str, Any]:
    url = _pay_link(customer)
    if not url:
        return {}
    return {
        "button": (label, url),
        "button_note": "This sends an M-Pesa payment request to your registered phone number for you to approve.",
    }


def compose_welcome_email(customer: Customer, paybill_info: dict[str, Any] | None) -> tuple[str, str, str]:
    """Returns (subject, html, text) for the new-account email."""
    return render_email(
        Email(
            subject=f"Your {BRAND} account is ready",
            greeting_name=customer.full_name,
            intro=(
                f"Your {_plan_speed_label(customer.plan)} internet account ({customer.pppoe_username}) has been set up. "
                "It will be activated as soon as your first payment is received."
            ),
            details=_payment_details(customer, paybill_info),
            **_pay_button(customer, "Pay with M-Pesa"),
            outro="Your connection switches on automatically once payment is confirmed, usually within a minute.",
            account=customer.pppoe_username,
        )
    )


def compose_receipt_email(customer: Customer, payment: Payment) -> tuple[str, str, str]:
    """Returns (subject, html, text) for the payment receipt."""
    expires = _fmt_eat(customer.expires_at) if customer.expires_at else "No expiry"
    return render_email(
        Email(
            subject=f"Payment received - {BRAND} receipt",
            greeting_name=customer.full_name,
            intro=f"Thank you. We have received your payment and your {_plan_speed_label(customer.plan)} connection is active.",
            details=[
                ("Amount paid", f"KES {payment.amount_kes}"),
                ("Receipt number", payment.mpesa_receipt or f"PW-{payment.id}"),
                ("Active until", expires),
            ],
            outro="Please keep this email as your receipt.",
            account=customer.pppoe_username,
        )
    )


def confirm_payment(
    db: Session,
    ppp: PPPoEManager | None,
    payment: Payment,
    *,
    mpesa_receipt: str,
    raw_callback: dict,
    static_mgr: StaticUserManager | None = None,
) -> Payment:
    """Called from the Paystack webhook on charge.success: finish a pending payment."""
    customer = payment.customer
    now = _extend_subscription(customer)
    db.add(customer)

    payment.status = PaymentStatus.confirmed
    payment.mpesa_receipt = mpesa_receipt
    payment.raw_callback = raw_callback
    payment.confirmed_at = now
    db.add(payment)
    _reactivate_on_router(customer, ppp, static_mgr)
    db.commit()
    db.refresh(customer)
    db.refresh(payment)
    return payment


def fail_payment(db: Session, payment: Payment, *, raw_callback: dict) -> Payment:
    """Called from the Paystack webhook for a non-success status (cancelled, failed, abandoned)."""
    payment.status = PaymentStatus.failed
    payment.raw_callback = raw_callback
    db.add(payment)
    db.commit()
    db.refresh(payment)
    return payment


def update_customer_details(
    db: Session,
    customer: Customer,
    *,
    full_name: str | None = None,
    phone_number: str | None = None,
    email: str | None = None,
    static_ip: str | None = None,
    static_mgr: StaticUserManager | None = None,
) -> Customer:
    """Edit contact details and static IP."""
    if full_name is not None:
        customer.full_name = full_name
    if phone_number is not None:
        customer.phone_number = phone_number
    if email is not None:
        customer.email = email
    if static_ip is not None and customer.connection_type == ConnectionType.static:
        old_ip = customer.static_ip
        customer.static_ip = static_ip
        if static_mgr:
            static_mgr.create_or_update_queue(
                name=customer.pppoe_username,
                target_ip=static_ip,
                rate_limit=customer.plan.rate_limit,
                comment=customer.full_name,
            )
            if customer.status in (CustomerStatus.suspended, CustomerStatus.expired):
                if old_ip:
                    static_mgr.restore_user(old_ip)
                static_mgr.suspend_user(static_ip, comment=customer.full_name)
    db.add(customer)
    db.commit()
    db.refresh(customer)
    return customer


def suspend_customer(
    db: Session,
    ppp: PPPoEManager | None,
    customer: Customer,
    static_mgr: StaticUserManager | None = None,
) -> Customer:
    """Manual suspend (support/abuse) - distinct from expiry, which the worker drives."""
    if customer.connection_type == ConnectionType.static:
        if static_mgr and customer.static_ip:
            static_mgr.suspend_user(customer.static_ip, comment=customer.full_name)
    else:
        if ppp:
            ppp.disable_user(customer.pppoe_username)
    customer.status = CustomerStatus.suspended
    db.add(customer)
    db.commit()
    db.refresh(customer)
    return customer


def delete_customer(
    db: Session,
    ppp: PPPoEManager | None,
    customer: Customer,
    static_mgr: StaticUserManager | None = None,
) -> None:
    """
    Permanently remove a customer: drops their PPPoE secret or simple queue from
    the router, then deletes their payment history and the customer row.
    """
    if customer.connection_type == ConnectionType.static:
        if static_mgr:
            static_mgr.delete_queue(customer.pppoe_username)
            if customer.static_ip:
                static_mgr.restore_user(customer.static_ip)
    else:
        if ppp:
            try:
                ppp.delete_secret(customer.pppoe_username)
            except LookupError:
                pass  # already gone from the router - fine, still remove the DB record
    db.query(Payment).filter(Payment.customer_id == customer.id).delete()
    db.delete(customer)
    db.commit()


def change_plan(
    db: Session,
    ppp: PPPoEManager | None,
    customer: Customer,
    new_plan: Plan,
    static_mgr: StaticUserManager | None = None,
) -> Customer:
    customer.plan_id = new_plan.id
    db.add(customer)
    if customer.status == CustomerStatus.active:
        if customer.connection_type == ConnectionType.static:
            if static_mgr:
                static_mgr.set_bandwidth(customer.pppoe_username, new_plan.rate_limit)
        else:
            if ppp:
                ppp.set_profile(customer.pppoe_username, new_plan.name)
    db.commit()
    db.refresh(customer)
    return customer


def set_expiry(
    db: Session,
    ppp: PPPoEManager | None,
    customer: Customer,
    expires_at: datetime | None,
    static_mgr: StaticUserManager | None = None,
) -> Customer:
    """
    Admin override of a customer's expiry, without recording a payment (e.g.
    compensation for an outage, a free trial, or fixing a mistake). None means
    no expiry. A future date (or none) reconnects the customer - even one who
    was manually suspended - and a past date cuts them off now rather than
    waiting for the next sweep.
    """
    now = datetime.now(timezone.utc)
    customer.expires_at = expires_at
    if expires_at is None or expires_at > now:
        if customer.status != CustomerStatus.active:
            _reactivate_on_router(customer, ppp, static_mgr)
        customer.status = CustomerStatus.active
        customer.reminder_2_days_sent = False
        customer.reminder_1_day_sent = False
    elif customer.status == CustomerStatus.active:
        if customer.connection_type == ConnectionType.static:
            if static_mgr and customer.static_ip:
                static_mgr.suspend_user(customer.static_ip, comment=customer.full_name)
        elif ppp:
            ppp.disable_user(customer.pppoe_username)
        customer.status = CustomerStatus.expired
    db.add(customer)
    db.commit()
    db.refresh(customer)
    return customer


@dataclass
class ImportRow:
    username: str
    full_name: str
    phone_number: str | None
    plan: Plan
    expires_at: datetime | None  # ignored for users disabled on the router
    disabled: bool


def import_router_users(db: Session, rows: list[ImportRow]) -> list[Customer]:
    """
    Create billing records for PPPoE users that already exist on the router.
    Nothing is queued for the router - the accounts are already there and set
    up, so importing never disconnects or changes anyone. Users disabled on
    the router come in as expired; the rest as active until expires_at (a
    past date is left to the expiry sweep, which also disables them on the
    router, so the two never disagree).
    """
    now = datetime.now(timezone.utc)
    created = []
    for row in rows:
        active = not row.disabled
        customer = Customer(
            pppoe_username=row.username,
            full_name=row.full_name,
            phone_number=row.phone_number,
            connection_type=ConnectionType.pppoe,
            plan_id=row.plan.id,
            status=CustomerStatus.active if active else CustomerStatus.expired,
            expires_at=row.expires_at if not row.disabled else now,
        )
        db.add(customer)
        created.append(customer)
    db.commit()
    return created


def create_plan(
    db: Session,
    bw: BandwidthProfileManager,
    *,
    name: str,
    rate_limit: str,
    price_kes: Decimal,
    duration_days: int,
    marketing_speed: str | None = None,
) -> Plan:
    """
    Create a plan and its matching RouterOS PPP profile in one step - no need
    to pre-create the profile on the router first, ensure_profile makes it
    (or fixes its rate-limit if a profile with that name already exists).
    """
    bw.ensure_profile(name, rate_limit)
    plan = Plan(
        name=name,
        rate_limit=rate_limit,
        marketing_speed=marketing_speed or None,
        price_kes=price_kes,
        duration_days=duration_days,
    )
    db.add(plan)
    db.commit()
    db.refresh(plan)
    return plan


def update_plan(
    db: Session,
    bw: BandwidthProfileManager,
    plan: Plan,
    *,
    name: str | None = None,
    rate_limit: str | None = None,
    price_kes: Decimal | None = None,
    duration_days: int | None = None,
    marketing_speed: str | None = None,
) -> Plan:
    """
    Edit a plan's name/price/speed/duration. price_kes and duration_days are
    DB-only (they only affect future billing); rate_limit and name also push
    to the matching RouterOS PPP profile (renaming it in place keeps every
    customer secret pointed at it - RouterOS resolves the reference by
    internal id, not the name string, verified live). Rate-limit changes
    apply to every customer on this plan on their next session (RouterOS
    applies rate-limit changes on reconnect, not mid-session - see
    PPPoEManager.set_profile). marketing_speed is DB-only - what customers
    are told the plan is, independent of the RouterOS rate-limit.
    """
    if name is not None and name != plan.name:
        bw.rename_profile(plan.name, name)
        plan.name = name
    if rate_limit is not None and rate_limit != plan.rate_limit:
        bw.set_rate_limit(plan.name, rate_limit)
        plan.rate_limit = rate_limit
    if price_kes is not None:
        plan.price_kes = price_kes
    if duration_days is not None:
        plan.duration_days = duration_days
    if marketing_speed is not None:
        plan.marketing_speed = marketing_speed or None
    db.add(plan)
    db.commit()
    db.refresh(plan)
    return plan


def expire_overdue_customers(
    db: Session,
    ppp: PPPoEManager | None = None,
    static_mgr: StaticUserManager | None = None,
) -> list[Customer]:
    """Suspend every active customer whose expires_at has passed. Used by the worker."""
    now = datetime.now(timezone.utc)
    overdue = (
        db.query(Customer)
        .filter(Customer.status == CustomerStatus.active, Customer.expires_at <= now)
        .all()
    )
    for customer in overdue:
        if customer.connection_type == ConnectionType.static:
            if static_mgr and customer.static_ip:
                static_mgr.suspend_user(customer.static_ip, comment=customer.full_name)
        else:
            if ppp:
                ppp.disable_user(customer.pppoe_username)
        customer.status = CustomerStatus.expired
        db.add(customer)
    db.commit()
    return overdue


def compose_reminder_email(customer: Customer, paybill_info: dict[str, Any] | None, days_left: int) -> tuple[str, str, str]:
    """Returns (subject, html, text) for the upcoming-expiry reminder."""
    when = "tomorrow" if days_left == 1 else f"in {days_left} days"
    expires = _fmt_eat(customer.expires_at) if customer.expires_at else ""
    return render_email(
        Email(
            subject=f"Your {BRAND} subscription ends {when}",
            greeting_name=customer.full_name,
            intro=f"Your internet subscription ends {when}{' (' + expires + ')' if expires else ''}. "
            "To stay connected without interruption, renew before then.",
            details=_payment_details(customer, paybill_info),
            **_pay_button(customer, "Renew with M-Pesa"),
            account=customer.pppoe_username,
        )
    )


def send_expiry_reminders(db: Session) -> tuple[int, int]:
    """
    Find customers who are 2 days or 1 day away from expiry and send them emails.
    Returns a tuple of (2_day_emails_sent, 1_day_emails_sent)
    """
    now = datetime.now(timezone.utc)
    two_days_from_now = now + timedelta(days=2)
    one_day_from_now = now + timedelta(days=1)
    
    # 2 days reminder
    customers_2_days = (
        db.query(Customer)
        .filter(
            Customer.status == CustomerStatus.active,
            Customer.expires_at <= two_days_from_now,
            Customer.expires_at > one_day_from_now,
            Customer.reminder_2_days_sent == False
        )
        .all()
    )
    
    count_2 = 0
    for customer in customers_2_days:
        if customer.email:
            paybill_info, _ = try_paybill_charge(db, customer)
            try:
                subject, html, text = compose_reminder_email(customer, paybill_info, 2)
                email_client.send_email(customer.email, subject, html, text)
            except Exception as exc:  # noqa: BLE001 - best effort, never blocks the sweep
                print(f"Reminder email to {customer.pppoe_username} failed: {exc}")
        customer.reminder_2_days_sent = True
        db.add(customer)
        count_2 += 1
        
    # 1 day reminder
    customers_1_day = (
        db.query(Customer)
        .filter(
            Customer.status == CustomerStatus.active,
            Customer.expires_at <= one_day_from_now,
            Customer.expires_at > now,
            Customer.reminder_1_day_sent == False
        )
        .all()
    )
    
    count_1 = 0
    for customer in customers_1_day:
        if customer.email:
            paybill_info, _ = try_paybill_charge(db, customer)
            try:
                subject, html, text = compose_reminder_email(customer, paybill_info, 1)
                email_client.send_email(customer.email, subject, html, text)
            except Exception as exc:  # noqa: BLE001 - best effort, never blocks the sweep
                print(f"Reminder email to {customer.pppoe_username} failed: {exc}")
        customer.reminder_1_day_sent = True
        db.add(customer)
        count_1 += 1
        
    db.commit()
    return count_2, count_1


@dataclass
class MonthIncome:
    year: int
    month: int
    label: str  # e.g. "Oct 2026"
    total_kes: Decimal
    payments: int


def monthly_income(db: Session, months: int = 12, now: datetime | None = None) -> list[MonthIncome]:
    """
    Confirmed payments summed per calendar month in Kenya time, oldest first,
    for the last `months` months including the current one (empty months are 0).
    """
    now_eat = (now or datetime.now(timezone.utc)).astimezone(_EAT)
    keys = []
    year, month = now_eat.year, now_eat.month
    for _ in range(months):
        keys.append((year, month))
        year, month = (year - 1, 12) if month == 1 else (year, month - 1)
    keys.reverse()

    start = datetime(keys[0][0], keys[0][1], 1, tzinfo=_EAT)
    totals = {key: [Decimal("0"), 0] for key in keys}
    rows = db.execute(
        select(Payment.amount_kes, Payment.confirmed_at).where(
            Payment.status == PaymentStatus.confirmed, Payment.confirmed_at >= start
        )
    )
    for amount, confirmed_at in rows:
        if confirmed_at.tzinfo is None:  # stored as UTC
            confirmed_at = confirmed_at.replace(tzinfo=timezone.utc)
        local = confirmed_at.astimezone(_EAT)
        bucket = totals.get((local.year, local.month))
        if bucket is not None:
            bucket[0] += amount
            bucket[1] += 1
    return [
        MonthIncome(y, m, datetime(y, m, 1).strftime("%b %Y"), totals[(y, m)][0], totals[(y, m)][1])
        for y, m in keys
    ]
