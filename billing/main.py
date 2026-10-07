from __future__ import annotations

import os

from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI, Request  # noqa: E402
from fastapi.responses import RedirectResponse  # noqa: E402
from starlette.middleware.sessions import SessionMiddleware  # noqa: E402

from billing.auth import NotAuthenticated  # noqa: E402
from billing.config import settings  # noqa: E402
from billing.routers import auth, customers, dashboard, mpesa, payments, plans, router_api  # noqa: E402

# No background worker here: on Vercel, expiries run on each router sync and
# reminders on the daily cron (see billing/worker.py).
app = FastAPI(title="Pirates Billing API")
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.session_secret_key,
    session_cookie="pirates_admin_session",
    max_age=14 * 24 * 60 * 60,
    same_site="lax",
    https_only=bool(os.environ.get("VERCEL")),  # Vercel is always https; local dev is plain http
)


@app.exception_handler(NotAuthenticated)
def _redirect_to_login(request: Request, exc: NotAuthenticated) -> RedirectResponse:
    return RedirectResponse(f"/login?next={exc.next_path}", status_code=303)


app.include_router(auth.router)
app.include_router(plans.router)
app.include_router(customers.router)
app.include_router(payments.router)
app.include_router(mpesa.router)
app.include_router(dashboard.router)
app.include_router(router_api.router)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/")
def read_root():
    return RedirectResponse("/dashboard", status_code=303)
