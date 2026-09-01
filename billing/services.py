"""Business logic that ties the customers/plans/payments tables to the router.

Kept separate from the routers so the expiry worker (a standalone process,
not a FastAPI request) can call the same functions instead of duplicating them.
"""

from __future__ import annotations

import html as html_module
import re
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from billing.config import settings
from billing.email import client as email_client
from billing.models import Customer, CustomerStatus, Payment, PaymentStatus, Plan
from billing.mpesa import paystack
from mikrotik.bandwidth import BandwidthProfileManager
from mikrotik.pppoe import PPPoEManager


def create_customer(
    db: Session,
    ppp: PPPoEManager,
    *,
    pppoe_username: str,
    pppoe_password: str,
    full_name: str,
    phone_number: str,
    plan: Plan,
    email: str | None = None,
    no_expiry: bool = False,
) -> Customer:
    """
    Create the PPPoE secret on the router, then the billing record.

    New customers start already expired - they only become active through
    record_payment(), same path an existing customer's renewal takes.
    Unless no_expiry is True, in which case they are activated immediately.
    """
    ppp.create_secret(pppoe_username, pppoe_password, profile=plan.name, comment=full_name)
    
    if no_expiry:
        ppp.enable_user(pppoe_username)
        status = CustomerStatus.active
        expires_at = None
    else:
        ppp.disable_user(pppoe_username)
        status = CustomerStatus.expired
        expires_at = datetime.now(timezone.utc)

    customer = Customer(
        pppoe_username=pppoe_username,
        full_name=full_name,
        phone_number=phone_number,
        email=email,
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
    base = max(now, customer.expires_at) if customer.expires_at else now
    customer.expires_at = base + timedelta(days=customer.plan.duration_days)
    customer.status = CustomerStatus.active
    customer.reminder_2_days_sent = False
    customer.reminder_1_day_sent = False
    return now


def record_payment(
    db: Session,
    ppp: PPPoEManager,
    *,
    customer: Customer,
    amount_kes: Decimal,
    mpesa_receipt: str | None,
    phone_number: str | None,
    checkout_request_id: str | None = None,
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
    db.commit()
    db.refresh(customer)
    db.refresh(payment)

    ppp.set_profile(customer.pppoe_username, customer.plan.name)
    ppp.enable_user(customer.pppoe_username)
    return payment


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
        phone_number=customer.phone_number,
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


def compose_welcome_email(customer: Customer, paybill_info: dict[str, Any]) -> tuple[str, str, str]:
    """
    Returns (subject, html, text) for the welcome email.
    Uses a plain, text-focused HTML design to avoid spam filters.
    """
    name = html_module.escape(customer.full_name)
    speed = html_module.escape(_plan_speed_label(customer.plan))
    subject = f"Welcome aboard, {customer.full_name}!"

    pay_button_html = ""
    if settings.public_base_url:
        pay_url = f"{settings.public_base_url}/pay/{customer.pppoe_username}/{customer.pay_token}/mpesa"
        pay_button_html = f"""\
            <table width="100%" border="0" cellspacing="0" cellpadding="0">
              <tr>
                <td align="center">
                  <a href="{pay_url}" style="display: inline-block; background-color: #d97706; color: #ffffff; text-decoration: none; padding: 14px 32px; border-radius: 6px; font-weight: bold; font-size: 16px; margin-bottom: 8px;">Tap to Pay with M-Pesa</a>
                  <p style="margin: 0; color: #94a3b8; font-size: 13px;">(Sends a PIN prompt straight to {customer.phone_number})</p>
                </td>
              </tr>
            </table>
"""

    html = f"""\
<div style="font-family: sans-serif; color: #333; max-width: 600px; line-height: 1.5;">
  <h2 style="color: #050810;">PIRATES WIFI</h2>
  <p>Ahoy, {name}.</p>
  <p>Your <strong>{speed}</strong> account has been prepared. Complete the payment below and set sail on the high seas of unlimited internet.</p>
  
  <div style="background-color: #f8f9fa; border: 1px solid #ddd; padding: 15px; margin: 20px 0;">
    <h3 style="margin-top: 0;">Amount Due: KES {paybill_info['amount_kes']}</h3>
    <p style="margin: 5px 0;"><strong>Paybill:</strong> {paybill_info['paybill']}</p>
    <p style="margin: 5px 0;"><strong>Account:</strong> {paybill_info['account_number']}</p>
  </div>

{pay_button_html}
  <p>Activates automatically the instant payment is confirmed - no need to contact us.</p>
  <hr style="border: 0; border-top: 1px solid #eee; margin: 20px 0;">
  <p style="font-size: 12px; color: #666;">PIRATES WIFI &middot; Smooth Sailing Ahead</p>
</div>
"""

    text_lines = [
        "PIRATES WIFI",
        "",
        f"Ahoy, {customer.full_name}.",
        "",
        f"Your {_plan_speed_label(customer.plan)} account has been prepared. Complete the payment "
        "below and set sail on the high seas of unlimited internet.",
        "",
        f"AMOUNT DUE: KES {paybill_info['amount_kes']}",
        f"Paybill: {paybill_info['paybill']}",
        f"Account: {paybill_info['account_number']}",
    ]
    if settings.public_base_url:
        pay_url = f"{settings.public_base_url}/pay/{customer.pppoe_username}/{customer.pay_token}/mpesa"
        text_lines += [
            "",
            f"Or pay instantly with M-Pesa: {pay_url}",
            f"(Sends a PIN prompt straight to {customer.phone_number})",
        ]
    text_lines += [
        "",
        "Activates automatically the instant payment is confirmed - no need to contact us.",
        "",
        "PIRATES WIFI - Smooth Sailing Ahead",
    ]
    text = "\n".join(text_lines)

    return subject, html, text


def compose_receipt_email(customer: Customer, payment: Payment) -> tuple[str, str, str]:
    """
    Returns (subject, html, text) for the payment-confirmation receipt.
    Uses a plain, text-focused HTML design to avoid spam filters.
    """
    name = html_module.escape(customer.full_name)
    speed = html_module.escape(_plan_speed_label(customer.plan))
    subject = "Payment received - you're all set"
    receipt_no = html_module.escape(payment.mpesa_receipt or f"PW-{payment.id}")
    expires = customer.expires_at.strftime("%d %b %Y, %H:%M UTC")

    html = f"""\
<div style="font-family: sans-serif; color: #333; max-width: 600px; line-height: 1.5;">
  <h2 style="color: #050810;">PIRATES WIFI - PAYMENT CONFIRMED</h2>
  <p>Ahoy, {name}.</p>
  <p>Your payment has cleared and your <strong>{speed}</strong> connection is active. Full speed ahead.</p>
  
  <div style="background-color: #f8f9fa; border: 1px solid #ddd; padding: 15px; margin: 20px 0;">
    <h3 style="margin-top: 0;">Amount Paid: KES {payment.amount_kes}</h3>
    <p style="margin: 5px 0;"><strong>Receipt No.:</strong> {receipt_no}</p>
    <p style="margin: 5px 0;"><strong>Active Until:</strong> {expires}</p>
  </div>

  <p>Keep this receipt for your records. Fair winds until your next renewal.</p>
  <hr style="border: 0; border-top: 1px solid #eee; margin: 20px 0;">
  <p style="font-size: 12px; color: #666;">PIRATES WIFI &middot; Smooth Sailing Ahead</p>
</div>
"""

    text = "\n".join(
        [
            "PIRATES WIFI - PAYMENT CONFIRMED",
            "",
            f"Ahoy, {customer.full_name}.",
            "",
            f"Your payment has cleared and your {_plan_speed_label(customer.plan)} connection is active. "
            "Full speed ahead.",
            "",
            f"AMOUNT PAID: KES {payment.amount_kes}",
            f"Receipt No.: {payment.mpesa_receipt or f'PW-{payment.id}'}",
            f"Active Until: {expires}",
            "",
            "Keep this receipt for your records. Fair winds until your next renewal.",
            "",
            "PIRATES WIFI - Smooth Sailing Ahead",
        ]
    )

    return subject, html, text


def confirm_payment(
    db: Session,
    ppp: PPPoEManager,
    payment: Payment,
    *,
    mpesa_receipt: str,
    raw_callback: dict,
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
    db.commit()
    db.refresh(customer)
    db.refresh(payment)

    ppp.set_profile(customer.pppoe_username, customer.plan.name)
    ppp.enable_user(customer.pppoe_username)
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
) -> Customer:
    """Edit contact details - DB-only, doesn't touch the router (name/phone/email aren't stored there)."""
    if full_name is not None:
        customer.full_name = full_name
    if phone_number is not None:
        customer.phone_number = phone_number
    if email is not None:
        customer.email = email
    db.add(customer)
    db.commit()
    db.refresh(customer)
    return customer


def suspend_customer(db: Session, ppp: PPPoEManager, customer: Customer) -> Customer:
    """Manual suspend (support/abuse) - distinct from expiry, which the worker drives."""
    ppp.disable_user(customer.pppoe_username)
    customer.status = CustomerStatus.suspended
    db.add(customer)
    db.commit()
    db.refresh(customer)
    return customer


def delete_customer(db: Session, ppp: PPPoEManager, customer: Customer) -> None:
    """
    Permanently remove a customer: drops their PPPoE secret (and any live
    session) from the router, then deletes their payment history and the
    customer row. Irreversible - use suspend_customer for anything that
    might need to be undone.
    """
    try:
        ppp.delete_secret(customer.pppoe_username)
    except LookupError:
        pass  # already gone from the router - fine, still remove the DB record
    db.query(Payment).filter(Payment.customer_id == customer.id).delete()
    db.delete(customer)
    db.commit()


def change_plan(
    db: Session,
    ppp: PPPoEManager,
    customer: Customer,
    new_plan: Plan,
) -> Customer:
    customer.plan_id = new_plan.id
    db.add(customer)
    db.commit()
    db.refresh(customer)
    if customer.status == CustomerStatus.active:
        ppp.set_profile(customer.pppoe_username, new_plan.name)
    return customer


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


def expire_overdue_customers(db: Session, ppp: PPPoEManager) -> list[Customer]:
    """Suspend every active customer whose expires_at has passed. Used by the worker."""
    now = datetime.now(timezone.utc)
    overdue = (
        db.query(Customer)
        .filter(Customer.status == CustomerStatus.active, Customer.expires_at <= now)
        .all()
    )
    for customer in overdue:
        ppp.disable_user(customer.pppoe_username)
        customer.status = CustomerStatus.expired
        db.add(customer)
    db.commit()
    return overdue


def compose_reminder_email(customer: Customer, paybill_info: dict[str, Any], days_left: int) -> tuple[str, str, str]:
    name = html_module.escape(customer.full_name)
    subject = f"Ahoy! Your Pirates WiFi expires in {days_left} {'day' if days_left == 1 else 'days'}"
    
    pay_button_html = ""
    if settings.public_base_url:
        pay_url = f"{settings.public_base_url}/pay/{customer.pppoe_username}/{customer.pay_token}/mpesa"
        pay_button_html = f"""\
            <table width="100%" border="0" cellspacing="0" cellpadding="0">
              <tr>
                <td align="center">
                  <a href="{pay_url}" style="display: inline-block; background-color: #d97706; color: #ffffff; text-decoration: none; padding: 14px 32px; border-radius: 6px; font-weight: bold; font-size: 16px; margin-bottom: 8px;">Tap to Renew with M-Pesa</a>
                  <p style="margin: 0; color: #94a3b8; font-size: 13px;">(Sends a PIN prompt straight to {customer.phone_number})</p>
                </td>
              </tr>
            </table>
"""

    html = f"""\
<div style="font-family: sans-serif; color: #333; max-width: 600px; line-height: 1.5;">
  <h2 style="color: #050810;">PIRATES WIFI - EXPIRY REMINDER</h2>
  <p>Ahoy, {name}.</p>
  <p>This is a quick reminder that your internet subscription will expire in <strong>{days_left} {'day' if days_left == 1 else 'days'}</strong>.</p>
  
  <div style="background-color: #f8f9fa; border: 1px solid #ddd; padding: 15px; margin: 20px 0;">
    <h3 style="margin-top: 0;">Amount Due: KES {paybill_info['amount_kes']}</h3>
    <p style="margin: 5px 0;"><strong>Paybill:</strong> {paybill_info['paybill']}</p>
    <p style="margin: 5px 0;"><strong>Account:</strong> {paybill_info['account_number']}</p>
  </div>

{pay_button_html}
  <hr style="border: 0; border-top: 1px solid #eee; margin: 20px 0;">
  <p style="font-size: 12px; color: #666;">PIRATES WIFI &middot; Smooth Sailing Ahead</p>
</div>
"""

    text_lines = [
        "PIRATES WIFI - EXPIRY REMINDER",
        "",
        f"Ahoy, {customer.full_name}.",
        "",
        f"This is a quick reminder that your internet subscription will expire in {days_left} {'day' if days_left == 1 else 'days'}.",
        "",
        f"AMOUNT DUE: KES {paybill_info['amount_kes']}",
        f"Paybill: {paybill_info['paybill']}",
        f"Account: {paybill_info['account_number']}",
    ]
    if settings.public_base_url:
        pay_url = f"{settings.public_base_url}/pay/{customer.pppoe_username}/{customer.pay_token}/mpesa"
        text_lines += [
            "",
            f"Or renew instantly with M-Pesa: {pay_url}",
            f"(Sends a PIN prompt straight to {customer.phone_number})",
        ]
    text_lines += [
        "",
        "PIRATES WIFI - Smooth Sailing Ahead",
    ]
    text = "\n".join(text_lines)

    return subject, html, text


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
            try:
                paybill_info = request_paybill_charge(db, customer)
                subject, html, text = compose_reminder_email(customer, paybill_info, 2)
                email_client.send_email(customer.email, subject, html, text)
            except Exception:
                pass # best effort
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
            try:
                paybill_info = request_paybill_charge(db, customer)
                subject, html, text = compose_reminder_email(customer, paybill_info, 1)
                email_client.send_email(customer.email, subject, html, text)
            except Exception:
                pass # best effort
        customer.reminder_1_day_sent = True
        db.add(customer)
        count_1 += 1
        
    db.commit()
    return count_2, count_1
