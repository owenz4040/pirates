"""Server-rendered admin dashboard - HTML forms over the same services/mikrotik layer the JSON API uses."""

from __future__ import annotations

import uuid
from decimal import Decimal
from pathlib import Path
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from librouteros.api import Api
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from billing import services
from billing.auth import require_admin
from billing.db import get_db
from billing.email import client as email_client
from billing.mikrotik_dep import get_router_api
from billing.models import ConnectionType, Customer, Plan
from billing.mpesa import paystack
from billing.mpesa.paystack import PaystackError
from billing.schemas import _normalize_kenyan_phone, _validate_ip
from mikrotik.bandwidth import BandwidthProfileManager
from mikrotik.pppoe import PPPoEManager
from mikrotik.static_user import StaticUserManager, _clean_address

router = APIRouter(prefix="/dashboard", tags=["dashboard"], dependencies=[Depends(require_admin)])
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent.parent / "templates"))


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
    api: Api | None = Depends(get_router_api),
):
    ppp = PPPoEManager(api) if api else None
    static_mgr = StaticUserManager(api) if api else None

    # Fetch router state once in bulk instead of querying for each customer in a loop
    active_usernames = set()
    if ppp:
        try:
            active_usernames = {
                row.get("name", "").strip().lower()
                for row in ppp.list_active_sessions()
                if row.get("name")
            }
        except Exception:
            pass

    suspended_ips = set()
    if static_mgr:
        try:
            suspended_ips = static_mgr.list_suspended_ips()
        except Exception:
            pass

    customers = db.scalars(select(Customer)).all()

    rows = []
    for c in customers:
        conn_val = getattr(c.connection_type, "value", str(c.connection_type))
        if conn_val == "static":
            addr = _clean_address(c.static_ip) if c.static_ip else None
            online = (addr is not None and addr not in suspended_ips) if static_mgr else False
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
    api: Api | None = Depends(get_router_api),
):
    plan = db.get(Plan, plan_id)
    if plan is None:
        return _redirect("/dashboard/customers/new", flash=f"No plan with id {plan_id}", flash_kind="error")
    if _get_customer_or_none(db, pppoe_username) is not None:
        return _redirect("/dashboard/customers/new", flash=f"{pppoe_username} already exists", flash_kind="error")
    if not api:
        return _redirect("/dashboard/customers/new", flash="Router is offline - cannot create customer", flash_kind="error")
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

    ppp = PPPoEManager(api)
    static_mgr = StaticUserManager(api)
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
    api: Api | None = Depends(get_router_api),
):
    customer = _get_customer_or_none(db, username)
    if customer is None:
        return _redirect("/dashboard", flash=f"No customer {username!r}", flash_kind="error")
    ppp = PPPoEManager(api) if api else None
    static_mgr = StaticUserManager(api) if api else None
    if customer.connection_type.value == "static":
        online = not static_mgr.is_suspended(customer.static_ip) if (static_mgr and customer.static_ip) else False
    else:
        online = ppp.is_online(username) if ppp else False

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
            **_flash_context(request),
        },
    )


@router.post("/customers/{username}/suspend")
def suspend(username: str, db: Session = Depends(get_db), api: Api | None = Depends(get_router_api)):
    customer = _get_customer_or_none(db, username)
    if customer is None:
        return _redirect("/dashboard", flash=f"No customer {username!r}", flash_kind="error")
    if not api:
        return _redirect(f"/dashboard/customers/{username}", flash="Router is offline", flash_kind="error")
    ppp = PPPoEManager(api)
    static_mgr = StaticUserManager(api)
    services.suspend_customer(db, ppp, customer, static_mgr=static_mgr)
    return _redirect(f"/dashboard/customers/{username}", flash=f"Suspended {username}")


@router.post("/customers/{username}/delete")
def delete_customer(username: str, db: Session = Depends(get_db), api: Api | None = Depends(get_router_api)):
    customer = _get_customer_or_none(db, username)
    if customer is None:
        return _redirect("/dashboard", flash=f"No customer {username!r}", flash_kind="error")
    if not api:
        return _redirect(f"/dashboard/customers/{username}", flash="Router is offline", flash_kind="error")
    ppp = PPPoEManager(api)
    static_mgr = StaticUserManager(api)
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
    api: Api | None = Depends(get_router_api),
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

    static_mgr = StaticUserManager(api) if api else None
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


@router.post("/customers/{username}/plan")
def change_plan(
    username: str,
    plan_id: int = Form(...),
    db: Session = Depends(get_db),
    api: Api | None = Depends(get_router_api),
):
    customer = _get_customer_or_none(db, username)
    new_plan = db.get(Plan, plan_id)
    if customer is None or new_plan is None:
        return _redirect("/dashboard", flash="Customer or plan not found", flash_kind="error")
    if not api:
        return _redirect(f"/dashboard/customers/{username}", flash="Router is offline", flash_kind="error")
    ppp = PPPoEManager(api)
    static_mgr = StaticUserManager(api)
    services.change_plan(db, ppp, customer, new_plan, static_mgr=static_mgr)
    return _redirect(f"/dashboard/customers/{username}", flash=f"Moved {username} to {new_plan.name}")


@router.post("/customers/{username}/payments")
def record_payment(
    username: str,
    amount_kes: Decimal = Form(...),
    mpesa_receipt: str = Form(""),
    db: Session = Depends(get_db),
    api: Api | None = Depends(get_router_api),
):
    customer = _get_customer_or_none(db, username)
    if customer is None:
        return _redirect("/dashboard", flash=f"No customer {username!r}", flash_kind="error")
    if not api:
        return _redirect(f"/dashboard/customers/{username}", flash="Router is offline", flash_kind="error")
    ppp = PPPoEManager(api)
    static_mgr = StaticUserManager(api)
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
    api: Api | None = Depends(get_router_api),
):
    if db.scalar(select(Plan).where(Plan.name == name)):
        return _redirect("/dashboard/plans", flash=f"Plan {name!r} already exists", flash_kind="error")
    if not api:
        return _redirect("/dashboard/plans", flash="Router is offline - cannot create plan", flash_kind="error")
    bw = BandwidthProfileManager(api)
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
    api: Api | None = Depends(get_router_api),
):
    plan = db.get(Plan, plan_id)
    if plan is None:
        return _redirect("/dashboard/plans", flash=f"No plan with id {plan_id}", flash_kind="error")
    if name != plan.name and db.scalar(select(Plan).where(Plan.name == name)):
        return _redirect("/dashboard/plans", flash=f"Plan {name!r} already exists", flash_kind="error")
    if not api:
        return _redirect("/dashboard/plans", flash="Router is offline - cannot update plan", flash_kind="error")
    old_name = plan.name
    bw = BandwidthProfileManager(api)
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
