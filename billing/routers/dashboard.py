"""Server-rendered admin dashboard - HTML forms over the same services/mikrotik layer the JSON API uses."""

from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from billing import router_sync, services
from billing.auth import require_admin
from billing.db import get_db
from billing.email import client as email_client
from billing.router_sync import RouterGateway, get_router
from billing.config import settings
from billing.models import ConnectionType, Customer, Plan, RouterCommand, RouterCommandStatus
from billing.mpesa import paystack
from billing.mpesa.paystack import PaystackError
from billing.schemas import _normalize_kenyan_phone, _validate_ip

router = APIRouter(prefix="/dashboard", tags=["dashboard"], dependencies=[Depends(require_admin)])
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent.parent / "templates"))

# Admins enter and read times in Kenya time. Fixed offset: Kenya has no DST,
# and the serverless runtime may not ship a tz database.
EAT = timezone(timedelta(hours=3), "EAT")


def _to_eat(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:  # stored as UTC
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(EAT)


def _redirect(path: str, *, flash: str | None = None, flash_kind: str = "ok") -> RedirectResponse:
    query = {}
    if flash:
        query = {"flash": flash, "flash_kind": flash_kind}
    url = f"{path}?{urlencode(query)}" if query else path
    return RedirectResponse(url, status_code=303)


def _flash_context(request: Request) -> dict:
    return {
        "flash": request.query_params.get("flash"),
        "flash_kind": request.query_params.get("flash_kind", "ok"),
    }


def _get_customer_or_none(db: Session, username: str) -> Customer | None:
    return db.scalar(select(Customer).where(Customer.pppoe_username == username))


@router.get("")
def customers_page(
    request: Request,
    filter: str = "all",
    db: Session = Depends(get_db),
):
    # Sessions the router reported on its last sync (empty if it's gone quiet).
    active_usernames = router_sync.active_usernames(db)

    customers = db.scalars(select(Customer)).all()

    rows = []
    for c in customers:
        conn_val = getattr(c.connection_type, "value", str(c.connection_type))
        if conn_val == "static":
            # Static users have no session to report - treat "not suspended" as online.
            online = bool(c.static_ip) and getattr(c.status, "value", str(c.status)) == "active"
        else:
            u_clean = c.pppoe_username.strip().lower() if c.pppoe_username else ""
            online = u_clean in active_usernames
        rows.append({"customer": c, "online": online})
    
    stats = {
        "total": len(customers),
        "active": sum(1 for c in customers if getattr(c.status, "value", str(c.status)) == "active"),
        "suspended": sum(1 for c in customers if getattr(c.status, "value", str(c.status)) in ("suspended", "expired")),
        "online": sum(1 for row in rows if row["online"]),
    }
    
    if filter == "active":
        rows = [r for r in rows if getattr(r["customer"].status, "value", str(r["customer"].status)) == "active"]
    elif filter == "expired":
        rows = [r for r in rows if getattr(r["customer"].status, "value", str(r["customer"].status)) == "expired"]
    elif filter == "online":
        rows = [r for r in rows if r["online"]]
    elif filter == "offline":
        rows = [r for r in rows if not r["online"]]
    elif filter == "pppoe":
        rows = [r for r in rows if getattr(r["customer"].connection_type, "value", str(r["customer"].connection_type)) == "pppoe"]
    elif filter == "static":
        rows = [r for r in rows if getattr(r["customer"].connection_type, "value", str(r["customer"].connection_type)) == "static"]

    plans = db.scalars(select(Plan)).all()
    return templates.TemplateResponse(
        request,
        "customers.html",
        {"customers": rows, "plans": plans, "stats": stats, "filter_type": filter, **_flash_context(request)},
    )


@router.get("/customers/new")
def new_customer_page(
    request: Request,
    db: Session = Depends(get_db),
):
    plans = db.scalars(select(Plan)).all()
    return templates.TemplateResponse(
        request,
        "add_customer.html",
        {"plans": plans, **_flash_context(request)},
    )


@router.post("/customers")
def create_customer(
    pppoe_username: str = Form(...),
    pppoe_password: str = Form(""),
    full_name: str = Form(...),
    phone_number: str = Form(...),
    email: str = Form(""),
    plan_id: int = Form(...),
    connection_type: str = Form("pppoe"),
    static_ip: str = Form(""),
    no_expiry: bool = Form(False),
    db: Session = Depends(get_db),
    gw: RouterGateway = Depends(get_router),
):
    plan = db.get(Plan, plan_id)
    if plan is None:
        return _redirect("/dashboard/customers/new", flash=f"No plan with id {plan_id}", flash_kind="error")
    if _get_customer_or_none(db, pppoe_username) is not None:
        return _redirect("/dashboard/customers/new", flash=f"{pppoe_username} already exists", flash_kind="error")
    try:
        phone_number = _normalize_kenyan_phone(phone_number)
    except ValueError as exc:
        return _redirect("/dashboard/customers/new", flash=str(exc), flash_kind="error")

    conn_type = ConnectionType.static if connection_type == "static" else ConnectionType.pppoe
    clean_static_ip = None
    if conn_type == ConnectionType.static:
        if not static_ip:
            return _redirect("/dashboard/customers/new", flash="Static IP is required for static users", flash_kind="error")
        try:
            clean_static_ip = _validate_ip(static_ip)
        except ValueError as exc:
            return _redirect("/dashboard/customers/new", flash=str(exc), flash_kind="error")
    else:
        if not pppoe_password:
            return _redirect("/dashboard/customers/new", flash="Password is required for PPPoE users", flash_kind="error")

    ppp = gw.ppp
    static_mgr = gw.static
    customer = services.create_customer(
        db,
        ppp,
        pppoe_username=pppoe_username,
        pppoe_password=pppoe_password,
        full_name=full_name,
        phone_number=phone_number,
        email=email or None,
        plan=plan,
        connection_type=conn_type,
        static_ip=clean_static_ip,
        no_expiry=no_expiry,
        static_mgr=static_mgr,
    )

    if not customer.email:
        return _redirect(f"/dashboard/customers/{pppoe_username}", flash=f"Created {pppoe_username}")
    try:
        paybill_info = services.request_paybill_charge(db, customer)
        subject, html, text = services.compose_welcome_email(customer, paybill_info)
        email_client.send_email(customer.email, subject, html, text)
        flash, flash_kind = f"Created {pppoe_username} and sent welcome email", "ok"
    except Exception as exc:  # noqa: BLE001 - the welcome email is best-effort, never fatal to signup
        flash, flash_kind = f"Created {pppoe_username}, but welcome email failed: {exc}", "error"
    return _redirect(f"/dashboard/customers/{pppoe_username}", flash=flash, flash_kind=flash_kind)


@router.get("/customers/{username}")
def customer_page(
    username: str,
    request: Request,
    db: Session = Depends(get_db),
):
    customer = _get_customer_or_none(db, username)
    if customer is None:
        return _redirect("/dashboard", flash=f"No customer {username!r}", flash_kind="error")
    if customer.connection_type.value == "static":
        online = bool(customer.static_ip) and customer.status.value == "active"
    else:
        online = username.strip().lower() in router_sync.active_usernames(db)

    plans = db.scalars(select(Plan)).all()
    payments = sorted(customer.payments, key=lambda p: p.created_at, reverse=True)
    return templates.TemplateResponse(
        request,
        "customer_detail.html",
        {
            "customer": customer,
            "online": online,
            "plans": plans,
            "payments": payments,
            "expires_local": _to_eat(customer.expires_at),
            **_flash_context(request),
        },
    )


@router.post("/customers/{username}/suspend")
def suspend(username: str, db: Session = Depends(get_db), gw: RouterGateway = Depends(get_router)):
    customer = _get_customer_or_none(db, username)
    if customer is None:
        return _redirect("/dashboard", flash=f"No customer {username!r}", flash_kind="error")
    ppp = gw.ppp
    static_mgr = gw.static
    services.suspend_customer(db, ppp, customer, static_mgr=static_mgr)
    return _redirect(f"/dashboard/customers/{username}", flash=f"Suspended {username}")


@router.post("/customers/{username}/delete")
def delete_customer(username: str, db: Session = Depends(get_db), gw: RouterGateway = Depends(get_router)):
    customer = _get_customer_or_none(db, username)
    if customer is None:
        return _redirect("/dashboard", flash=f"No customer {username!r}", flash_kind="error")
    ppp = gw.ppp
    static_mgr = gw.static
    try:
        services.delete_customer(db, ppp, customer, static_mgr=static_mgr)
    except Exception as exc:  # noqa: BLE001 - surface router errors (e.g. unreachable) to the admin
        return _redirect(f"/dashboard/customers/{username}", flash=f"Couldn't delete {username}: {exc}", flash_kind="error")
    return _redirect("/dashboard", flash=f"Deleted {username}")


@router.post("/customers/{username}/details")
def update_details(
    username: str,
    full_name: str = Form(...),
    phone_number: str = Form(...),
    email: str = Form(""),
    static_ip: str = Form(""),
    db: Session = Depends(get_db),
    gw: RouterGateway = Depends(get_router),
):
    customer = _get_customer_or_none(db, username)
    if customer is None:
        return _redirect("/dashboard", flash=f"No customer {username!r}", flash_kind="error")
    try:
        phone_number = _normalize_kenyan_phone(phone_number)
    except ValueError as exc:
        return _redirect(f"/dashboard/customers/{username}", flash=str(exc), flash_kind="error")

    clean_static_ip = None
    if customer.connection_type.value == "static" and static_ip:
        try:
            clean_static_ip = _validate_ip(static_ip)
        except ValueError as exc:
            return _redirect(f"/dashboard/customers/{username}", flash=str(exc), flash_kind="error")

    static_mgr = gw.static
    try:
        services.update_customer_details(
            db,
            customer,
            full_name=full_name,
            phone_number=phone_number,
            email=email or None,
            static_ip=clean_static_ip,
            static_mgr=static_mgr,
        )
    except IntegrityError:
        db.rollback()
        return _redirect(
            f"/dashboard/customers/{username}",
            flash=f"Phone number {phone_number!r} is already in use by another customer",
            flash_kind="error",
        )
    return _redirect(f"/dashboard/customers/{username}", flash="Details updated")


@router.post("/customers/{username}/expiry")
def set_expiry(
    username: str,
    mode: str = Form(...),
    expires_at: str = Form(""),
    days: int = Form(0),
    db: Session = Depends(get_db),
    gw: RouterGateway = Depends(get_router),
):
    """mode: "set" to an exact date, "add" days, or "none" for no expiry."""
    customer = _get_customer_or_none(db, username)
    if customer is None:
        return _redirect("/dashboard", flash=f"No customer {username!r}", flash_kind="error")
    page = f"/dashboard/customers/{username}"

    if mode == "none":
        new_expiry = None
    elif mode == "add":
        if days == 0:
            return _redirect(page, flash="Enter a number of days", flash_kind="error")
        now = datetime.now(timezone.utc)
        current = customer.expires_at
        if current is not None and current.tzinfo is None:
            current = current.replace(tzinfo=timezone.utc)
        # Adding days stacks on remaining time, like a payment; removing days counts from the current expiry.
        base = current if current is not None and (current > now or days < 0) else now
        new_expiry = base + timedelta(days=days)
    elif mode == "set":
        try:
            new_expiry = datetime.strptime(expires_at, "%Y-%m-%dT%H:%M").replace(tzinfo=EAT).astimezone(timezone.utc)
        except ValueError:
            return _redirect(page, flash="Pick a valid date and time", flash_kind="error")
    else:
        return _redirect(page, flash="Unknown expiry action", flash_kind="error")

    services.set_expiry(db, gw.ppp, customer, new_expiry, static_mgr=gw.static)
    if new_expiry is None:
        flash = f"{username} now has no expiry"
    else:
        flash = f"{username} now expires {new_expiry.astimezone(EAT).strftime('%d %b %Y, %H:%M')} EAT"
        if customer.status.value == "expired":
            flash += " (in the past - disconnected)"
    return _redirect(page, flash=flash)


@router.post("/customers/{username}/plan")
def change_plan(
    username: str,
    plan_id: int = Form(...),
    db: Session = Depends(get_db),
    gw: RouterGateway = Depends(get_router),
):
    customer = _get_customer_or_none(db, username)
    new_plan = db.get(Plan, plan_id)
    if customer is None or new_plan is None:
        return _redirect("/dashboard", flash="Customer or plan not found", flash_kind="error")
    ppp = gw.ppp
    static_mgr = gw.static
    services.change_plan(db, ppp, customer, new_plan, static_mgr=static_mgr)
    return _redirect(f"/dashboard/customers/{username}", flash=f"Moved {username} to {new_plan.name}")


@router.post("/customers/{username}/payments")
def record_payment(
    username: str,
    amount_kes: Decimal = Form(...),
    mpesa_receipt: str = Form(""),
    db: Session = Depends(get_db),
    gw: RouterGateway = Depends(get_router),
):
    customer = _get_customer_or_none(db, username)
    if customer is None:
        return _redirect("/dashboard", flash=f"No customer {username!r}", flash_kind="error")
    ppp = gw.ppp
    static_mgr = gw.static
    payment = services.record_payment(
        db,
        ppp,
        customer=customer,
        amount_kes=amount_kes,
        mpesa_receipt=mpesa_receipt or None,
        phone_number=None,
        static_mgr=static_mgr,
    )
    if customer.email:
        try:
            subject, html, text = services.compose_receipt_email(customer, payment)
            email_client.send_email(customer.email, subject, html, text)
        except Exception:  # noqa: BLE001 - the receipt is best-effort, never fatal to recording the payment
            pass
    return _redirect(f"/dashboard/customers/{username}", flash=f"Recorded KES {amount_kes} for {username}")


@router.post("/customers/{username}/mpesa/charge")
def mpesa_charge(username: str, db: Session = Depends(get_db)):
    customer = _get_customer_or_none(db, username)
    if customer is None:
        return _redirect("/dashboard", flash=f"No customer {username!r}", flash_kind="error")
    plan = customer.plan

    phone_number = customer.phone_number
    if not phone_number.startswith("+"):
        phone_number = f"+{phone_number}"
    reference = f"{customer.pppoe_username}-{uuid.uuid4().hex[:12]}"

    try:
        paystack.initiate_mpesa_charge(
            email=f"{customer.pppoe_username}@pirates.example.com",
            phone_number=phone_number,
            amount_kes=int(plan.price_kes),
            reference=reference,
        )
    except PaystackError as exc:
        return _redirect(f"/dashboard/customers/{username}", flash=str(exc), flash_kind="error")

    services.create_pending_payment(
        db, customer=customer, amount_kes=plan.price_kes, phone_number=customer.phone_number, checkout_request_id=reference
    )
    return _redirect(f"/dashboard/customers/{username}", flash=f"M-Pesa prompt sent to {customer.phone_number}")


@router.post("/customers/{username}/mpesa/paybill")
def mpesa_paybill(username: str, db: Session = Depends(get_db)):
    customer = _get_customer_or_none(db, username)
    if customer is None:
        return _redirect("/dashboard", flash=f"No customer {username!r}", flash_kind="error")

    try:
        info = services.request_paybill_charge(db, customer)
    except PaystackError as exc:
        return _redirect(f"/dashboard/customers/{username}", flash=str(exc), flash_kind="error")

    message = f"Paybill {info['paybill']}, account {info['account_number']}, amount KES {info['amount_kes']}"
    return _redirect(f"/dashboard/customers/{username}", flash=message)


@router.get("/plans")
def plans_page(request: Request, db: Session = Depends(get_db)):
    plans = db.scalars(select(Plan)).all()
    return templates.TemplateResponse(request, "plans.html", {"plans": plans, **_flash_context(request)})


@router.post("/plans")
def create_plan(
    name: str = Form(...),
    rate_limit: str = Form(...),
    price_kes: Decimal = Form(...),
    duration_days: int = Form(30),
    marketing_speed: str = Form(""),
    db: Session = Depends(get_db),
    gw: RouterGateway = Depends(get_router),
):
    if db.scalar(select(Plan).where(Plan.name == name)):
        return _redirect("/dashboard/plans", flash=f"Plan {name!r} already exists", flash_kind="error")
    bw = gw.bw
    try:
        services.create_plan(
            db,
            bw,
            name=name,
            rate_limit=rate_limit,
            price_kes=price_kes,
            duration_days=duration_days,
            marketing_speed=marketing_speed,
        )
    except Exception as exc:  # noqa: BLE001 - surface router errors (e.g. unreachable) to the admin
        return _redirect("/dashboard/plans", flash=f"Couldn't create plan: {exc}", flash_kind="error")
    return _redirect(
        "/dashboard/plans", flash=f"Created plan {name} and its {rate_limit} RouterOS profile"
    )


@router.post("/plans/{plan_id}")
def update_plan(
    plan_id: int,
    name: str = Form(...),
    rate_limit: str = Form(...),
    price_kes: Decimal = Form(...),
    duration_days: int = Form(...),
    marketing_speed: str = Form(""),
    db: Session = Depends(get_db),
    gw: RouterGateway = Depends(get_router),
):
    plan = db.get(Plan, plan_id)
    if plan is None:
        return _redirect("/dashboard/plans", flash=f"No plan with id {plan_id}", flash_kind="error")
    if name != plan.name and db.scalar(select(Plan).where(Plan.name == name)):
        return _redirect("/dashboard/plans", flash=f"Plan {name!r} already exists", flash_kind="error")
    old_name = plan.name
    bw = gw.bw
    try:
        services.update_plan(
            db,
            bw,
            plan,
            name=name,
            rate_limit=rate_limit,
            price_kes=price_kes,
            duration_days=duration_days,
            marketing_speed=marketing_speed,
        )
    except Exception as exc:  # noqa: BLE001 - surface router errors (e.g. unreachable) to the admin
        return _redirect("/dashboard/plans", flash=f"Couldn't update plan: {exc}", flash_kind="error")
    flash = f"Updated {old_name}" if name == old_name else f"Renamed {old_name} to {name} and updated it"
    return _redirect("/dashboard/plans", flash=flash)


@router.get("/router")
def router_page(request: Request, db: Session = Depends(get_db)):
    device = router_sync.get_or_create_device(db)
    base_url = settings.public_base_url or str(request.base_url)
    commands = db.scalars(select(RouterCommand).order_by(RouterCommand.id.desc()).limit(50)).all()
    counts = {
        status.value: db.scalar(select(func.count()).select_from(RouterCommand).where(RouterCommand.status == status))
        for status in RouterCommandStatus
    }
    return templates.TemplateResponse(
        request,
        "router.html",
        {
            "device": device,
            "online": router_sync.is_online(device),
            "setup_script": router_sync.setup_script(base_url, device.token),
            "commands": commands,
            "counts": counts,
            **_flash_context(request),
        },
    )


@router.post("/router/resync")
def router_resync(db: Session = Depends(get_db)):
    queued = router_sync.enqueue_full_resync(db)
    return _redirect("/dashboard/router", flash=f"Queued {queued} commands to bring the router in line with billing")


@router.post("/router/retry")
def router_retry(db: Session = Depends(get_db)):
    retried = router_sync.retry_failed(db)
    return _redirect("/dashboard/router", flash=f"Re-queued {retried} failed commands")


@router.post("/router/token")
def router_rotate_token(db: Session = Depends(get_db)):
    device = router_sync.get_or_create_device(db)
    device.token = secrets.token_hex(24)
    db.add(device)
    db.commit()
    return _redirect(
        "/dashboard/router",
        flash="New token generated - paste the updated setup script into the router, the old one no longer works",
    )
