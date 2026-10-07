"""Login/logout for the admin dashboard's session cookie."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from sqlalchemy.orm import Session

from billing.auth import clear_failures, client_ip, lockout_remaining, record_failure, verify_credentials
from billing.db import get_db

router = APIRouter(tags=["auth"])
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent.parent / "templates"))


def _safe_next(next_path: str | None) -> str:
    # Only allow same-site relative paths - never redirect off the dashboard.
    if not next_path or not next_path.startswith("/") or next_path.startswith("//"):
        return "/dashboard"
    return next_path


@router.get("/login")
def login_page(request: Request, next: str = "/dashboard", error: str = ""):
    if request.session.get("admin_user"):
        return RedirectResponse(_safe_next(next), status_code=303)
    return templates.TemplateResponse(
        request, "login.html", {"next": _safe_next(next), "error": error}
    )


@router.post("/login")
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    next: str = Form("/dashboard"),
    db: Session = Depends(get_db),
):
    ip = client_ip(request)
    if lockout_remaining(db, ip) is not None:
        # Checked before the password, so a locked-out guesser learns nothing.
        query = urlencode({"error": "locked", "next": _safe_next(next)})
        return RedirectResponse(f"/login?{query}", status_code=303)
    if not verify_credentials(username, password):
        record_failure(db, ip, username)
        query = urlencode({"error": "1", "next": _safe_next(next)})
        return RedirectResponse(f"/login?{query}", status_code=303)
    clear_failures(db, ip)
    request.session.clear()
    request.session["admin_user"] = username
    return RedirectResponse(_safe_next(next), status_code=303)


@router.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)
