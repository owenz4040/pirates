from __future__ import annotations

import os
from urllib.parse import urlsplit

from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI, Request  # noqa: E402
from fastapi.responses import PlainTextResponse, RedirectResponse  # noqa: E402
from starlette.middleware.sessions import SessionMiddleware  # noqa: E402

from billing.auth import NotAuthenticated  # noqa: E402
from billing.config import settings  # noqa: E402
from billing.routers import auth, customers, dashboard, mpesa, payments, plans, router_api  # noqa: E402

# No background worker here: on Vercel, expiries run on each router sync and
# reminders on the daily cron (see billing/worker.py).
# Interactive API docs are off: they'd publish a map of every endpoint.
app = FastAPI(title="Pirates Billing API", docs_url=None, redoc_url=None, openapi_url=None)

CSP = "; ".join([
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline'",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src https://fonts.gstatic.com",
    "img-src 'self' data:",
    "connect-src 'self'",
    "frame-ancestors 'none'",
    "form-action 'self'",
    "base-uri 'self'",
])
SECURITY_HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
}
# Called by machines, not browsers: they authenticate with tokens/signatures and send no Origin.
CSRF_EXEMPT_PREFIXES = ("/api/", "/paystack/webhook")


@app.middleware("http")
async def security(request: Request, call_next):
    if request.method not in {"GET", "HEAD", "OPTIONS"} and not request.url.path.startswith(CSRF_EXEMPT_PREFIXES):
        # Cross-site request forgery guard: a browser always says where a
        # form post came from, and it must be this site.
        source = request.headers.get("origin") or request.headers.get("referer")
        if source and urlsplit(source).netloc != request.url.netloc:
            return PlainTextResponse("Cross-site request blocked", status_code=403)
    response = await call_next(request)
    for name, value in SECURITY_HEADERS.items():
        response.headers.setdefault(name, value)
    if request.url.path.startswith(("/dashboard", "/login")):
        response.headers["Cache-Control"] = "no-store"  # don't leave customer data in shared caches
    return response


app.add_middleware(
    SessionMiddleware,
    secret_key=settings.session_secret_key,
    session_cookie="pirates_admin_session",
    max_age=7 * 24 * 60 * 60,
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
