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
from billing.models import ConnectionType, Customer, Plan, RouterCommand, RouterCommandStatus, RouterDevice
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
    income = services.monthly_income(db)
    return templates.TemplateResponse(
        request,
        "customers.html",
        {
            "customers": rows,
            "plans": plans,
            "stats": stats,
            "filter_type": filter,
            "unimported": _unimported_count(db, {c.pppoe_username.lower() for c in customers}),
            "income": income,
            "income_chart": _income_chart(income),
            **_flash_context(request),
        },
    )


def _nice_step(raw: float) -> float:
    """Round a gridline step up to 1, 2, 2.5 or 5 x 10^n."""
    import math

    magnitude = 10 ** math.floor(math.log10(raw))
    for factor in (1, 2, 2.5, 5, 10):
        if raw <= factor * magnitude:
            return factor * magnitude
    return 10 * magnitude


def _income_chart(months: list[services.MonthIncome]) -> dict:
    """SVG geometry for the monthly income column chart (viewBox 720 x 240)."""
    width, height = 720, 240
    left, right, top, bottom = 64, 8, 16, 28
    plot_w, plot_h = width - left - right, height - top - bottom
    peak = max((float(m.total_kes) for m in months), default=0)
    step = _nice_step(peak / 4) if peak > 0 else 1
    axis_max = step * max(1, -(-peak // step))  # ceil to a whole number of steps
    slot = plot_w / len(months)
    bar_w = min(24, slot * 0.6)
    bars = []
    for i, m in enumerate(months):
        value = float(m.total_kes)
        h = plot_h * value / axis_max
        x = left + slot * i + (slot - bar_w) / 2
        y = top + plot_h - h
        r = min(4, h, bar_w / 2)
        # Rounded top corners, square at the baseline.
        path = (
            f"M{x:.1f},{top + plot_h:.1f} V{y + r:.1f} Q{x:.1f},{y:.1f} {x + r:.1f},{y:.1f} "
            f"H{x + bar_w - r:.1f} Q{x + bar_w:.1f},{y:.1f} {x + bar_w:.1f},{y + r:.1f} V{top + plot_h:.1f} Z"
        ) if h > 0 else ""
        bars.append({
            "month": m, "path": path, "cx": x + bar_w / 2, "y": y,
            "slot_x": left + slot * i, "slot_w": slot, "short": m.label[:3],
        })
    ticks = [{"value": step * k, "y": top + plot_h - plot_h * step * k / axis_max} for k in range(int(axis_max / step) + 1)]
    return {
        "width": width, "height": height, "left": left, "right": width - right, "top": top,
        "baseline": top + plot_h, "bars": bars, "ticks": ticks, "empty": peak == 0,
    }


def _unimported_count(db: Session, existing: set[str]) -> int | None:
    """PPPoE users in the router's last export that aren't billing customers yet (None if never exported)."""
    device = db.scalar(select(RouterDevice).order_by(RouterDevice.id))
    if device is None or device.router_secrets is None:
        return None
    return sum(
        1
        for s in device.router_secrets
        if s.get("service", "") in IMPORTABLE_SERVICES and s["name"].lower() not in existing
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
    owner = db.scalar(select(Customer).where(Customer.phone_number == phone_number))
    if owner is not None:
        return _redirect(
            "/dashboard/customers/new",
            flash=f"Phone {phone_number} already belongs to {owner.pppoe_username} ({owner.full_name})",
            flash_kind="error",
        )

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

    try:
        customer = services.create_customer(
            db,
            gw.ppp,
            pppoe_username=pppoe_username,
            pppoe_password=pppoe_password,
            full_name=full_name,
            phone_number=phone_number,
            email=email or None,
            plan=plan,
            connection_type=conn_type,
            static_ip=clean_static_ip,
            no_expiry=no_expiry,
            static_mgr=gw.static,
        )
    except IntegrityError:
        # A race with another signup, or a clash the checks above missed - nothing was saved or queued.
        db.rollback()
        return _redirect(
            "/dashboard/customers/new",
            flash=f"Couldn't create {pppoe_username}: the username or phone number is already in use",
            flash_kind="error",
        )

    if not customer.email:
        return _redirect(f"/dashboard/customers/{pppoe_username}", flash=f"Created {pppoe_username}")
    paybill_info, paybill_error = services.try_paybill_charge(db, customer)
    try:
        subject, html, text = services.compose_welcome_email(customer, paybill_info)
        email_client.send_email(customer.email, subject, html, text)
        flash, flash_kind = f"Created {pppoe_username} and sent welcome email", "ok"
        if paybill_error:
            flash += f" without a paybill code (Paystack: {paybill_error})"
            flash_kind = "error"
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


@router.post("/customers/{username}/welcome")
def resend_welcome(username: str, db: Session = Depends(get_db)):
    customer = _get_customer_or_none(db, username)
    if customer is None:
        return _redirect("/dashboard", flash=f"No customer {username!r}", flash_kind="error")
    page = f"/dashboard/customers/{username}"
    if not customer.email:
        return _redirect(page, flash="Add an email address first", flash_kind="error")
    paybill_info, paybill_error = services.try_paybill_charge(db, customer)
    try:
        subject, html, text = services.compose_welcome_email(customer, paybill_info)
        email_client.send_email(customer.email, subject, html, text)
    except Exception as exc:  # noqa: BLE001 - surface the provider's reason to the admin
        return _redirect(page, flash=f"Welcome email failed: {exc}", flash_kind="error")
    if paybill_error:
        return _redirect(page, flash=f"Sent to {customer.email} without a paybill code (Paystack: {paybill_error})", flash_kind="error")
    return _redirect(page, flash=f"Welcome email sent to {customer.email}")


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
    phone_number: str = Form(""),
    email: str = Form(""),
    static_ip: str = Form(""),
    db: Session = Depends(get_db),
    gw: RouterGateway = Depends(get_router),
):
    customer = _get_customer_or_none(db, username)
    if customer is None:
        return _redirect("/dashboard", flash=f"No customer {username!r}", flash_kind="error")
    try:
        phone_number = _normalize_kenyan_phone(phone_number) if phone_number.strip() else None
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
    if not customer.phone_number:
        return _redirect(f"/dashboard/customers/{username}", flash="Add a phone number first", flash_kind="error")

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
def router_page(request: Request, setup: bool = False, db: Session = Depends(get_db)):
    device = router_sync.get_or_create_device(db)
    online = router_sync.is_online(device)
    # Once connected, the script (which carries the router's secret token) isn't
    # rendered at all unless asked for, e.g. to reinstall or replace the router.
    show_setup = setup or not online
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
            "online": online,
            "show_setup": show_setup,
            "setup_script": router_sync.setup_script(base_url, device.token) if show_setup else "",
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


# --- import existing PPPoE users from the router ---------------------------------

IMPORTABLE_SERVICES = {"pppoe", "any", ""}


def _import_state(db: Session) -> dict:
    device = router_sync.get_or_create_device(db)
    requested = device.secrets_requested_at
    reported = device.secrets_reported_at
    waiting = requested is not None and (reported is None or _to_eat(reported) < _to_eat(requested))

    existing = {u.lower() for u in db.scalars(select(Customer.pppoe_username))}
    plans = db.scalars(select(Plan).order_by(Plan.price_kes)).all()
    plans_by_name = {p.name: p for p in plans}
    profiles = {p["name"]: p.get("rate_limit", "") for p in (device.router_profiles or [])}

    candidates, skipped_existing = [], 0
    for secret in device.router_secrets or []:
        if secret.get("service", "") not in IMPORTABLE_SERVICES:
            continue
        if secret["name"].lower() in existing:
            skipped_existing += 1
            continue
        plan = plans_by_name.get(secret["profile"])
        candidates.append({**secret, "plan_id": plan.id if plan else None})

    missing_profiles = sorted(
        {c["profile"] for c in candidates if c["plan_id"] is None and c["profile"] not in router_sync.BUILTIN_PROFILES}
    )
    return {
        "device": device,
        "waiting": waiting,
        "reported_local": _to_eat(reported),
        "candidates": candidates,
        "skipped_existing": skipped_existing,
        "plans": plans,
        "missing_profiles": [{"name": n, "rate_limit": profiles.get(n, "")} for n in missing_profiles],
        "default_expiry": (datetime.now(EAT) + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M"),
    }


@router.get("/router/import")
def import_page(request: Request, db: Session = Depends(get_db)):
    return templates.TemplateResponse(
        request, "router_import.html", {**_import_state(db), "errors": {}, "values": {}, **_flash_context(request)}
    )


@router.post("/router/import/request")
def import_request(request: Request, db: Session = Depends(get_db)):
    router_sync.request_secrets_export(db, settings.public_base_url or str(request.base_url))
    return _redirect("/dashboard/router/import", flash="Asked the router for its user list - this takes about a minute")


@router.post("/router/import/plans")
def import_create_plans(db: Session = Depends(get_db)):
    """Create a plan per unmatched router profile. No router command - the profile already exists there."""
    state = _import_state(db)
    for profile in state["missing_profiles"]:
        db.add(Plan(name=profile["name"], rate_limit=profile["rate_limit"] or "", price_kes=Decimal("0"), duration_days=30))
    db.commit()
    names = ", ".join(p["name"] for p in state["missing_profiles"])
    return _redirect(
        "/dashboard/router/import",
        flash=f"Created plans: {names}. Set their prices under Plans - they start at KES 0.",
    )


@router.post("/router/import")
async def import_users(request: Request, db: Session = Depends(get_db)):
    form = await request.form()
    state = _import_state(db)
    by_name = {c["name"]: c for c in state["candidates"]}
    plans = {p.id: p for p in state["plans"]}
    taken_phones = {p for p in db.scalars(select(Customer.phone_number)) if p}

    rows, errors, values = [], {}, {}
    for username in form.getlist("pick"):
        secret = by_name.get(username)
        if secret is None:
            continue  # already imported or no longer on the router
        full_name = (form.get(f"name::{username}") or "").strip() or username
        phone_raw = (form.get(f"phone::{username}") or "").strip()
        plan_raw = form.get(f"plan::{username}") or ""
        expires_raw = (form.get(f"expires::{username}") or "").strip()
        values[username] = {"name": full_name, "phone": phone_raw, "plan": plan_raw, "expires": expires_raw}

        phone = None
        if phone_raw:
            try:
                phone = _normalize_kenyan_phone(phone_raw)
            except ValueError as exc:
                errors[username] = str(exc)
                continue
            if phone in taken_phones:
                errors[username] = f"Phone {phone} is already used by another customer"
                continue
            taken_phones.add(phone)
        plan = plans.get(int(plan_raw)) if plan_raw.isdigit() else None
        if plan is None:
            errors[username] = "Choose a plan"
            continue
        expires = None
        if expires_raw:
            try:
                expires = datetime.strptime(expires_raw, "%Y-%m-%dT%H:%M").replace(tzinfo=EAT).astimezone(timezone.utc)
            except ValueError:
                errors[username] = "Invalid expiry date"
                continue
        rows.append(services.ImportRow(username, full_name, phone, plan, expires, bool(secret.get("disabled"))))

    if errors:
        return templates.TemplateResponse(
            request,
            "router_import.html",
            {
                **state, "errors": errors, "values": values, "picked": set(form.getlist("pick")),
                "flash": f"Nothing imported - fix the {len(errors)} highlighted row(s)", "flash_kind": "error",
            },
            status_code=400,
        )
    if not rows:
        return _redirect("/dashboard/router/import", flash="Tick at least one user to import", flash_kind="error")
    services.import_router_users(db, rows)
    return _redirect("/dashboard", flash=f"Imported {len(rows)} customers from the router")
