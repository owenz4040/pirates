"""Machine-to-machine endpoints: the MikroTik's sync/ack calls and the Vercel cron."""

from __future__ import annotations

import secrets
from urllib.parse import parse_qs

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from billing import router_sync
from billing.config import settings
from billing.db import get_db
from billing.models import RouterDevice
from billing.worker import expire_sweep, run_daily

router = APIRouter(prefix="/api", tags=["router"])


async def _form(request: Request) -> dict[str, str]:
    # Parsed by hand: RouterOS's /tool fetch doesn't always send a form Content-Type.
    raw = (await request.body()).decode("utf-8", errors="replace")
    return {key: values[-1] for key, values in parse_qs(raw, keep_blank_values=True).items()}


def _device(request: Request, db: Session) -> RouterDevice:
    device = router_sync.authenticate(db, request.headers.get("x-pirates-token", ""))
    if device is None:
        raise HTTPException(401, "Unknown router token")
    return device


def _base_url(request: Request) -> str:
    return settings.public_base_url or str(request.base_url)


@router.post("/router/sync", response_class=PlainTextResponse)
async def sync(request: Request, db: Session = Depends(get_db)) -> str:
    """Router check-in: records its status, runs the expiry sweep, returns the next command batch as a script."""
    device = _device(request, db)
    router_sync.record_checkin(db, device, await _form(request), request.client.host if request.client else None)
    db.commit()
    # The router calls every minute, which makes it a free scheduler for expiries.
    expire_sweep(db)
    batch = router_sync.next_batch(db, device)
    return router_sync.render_batch(batch, f"{_base_url(request).rstrip('/')}/api/router/ack", device.token)


@router.post("/router/ack")
async def ack(request: Request, db: Session = Depends(get_db)) -> dict[str, int]:
    _device(request, db)
    form = await _form(request)
    done, failed = router_sync.acknowledge(db, form.get("ok", ""), form.get("failed", ""))
    return {"done": done, "failed": failed}


@router.get("/cron/daily")
def cron_daily(request: Request, db: Session = Depends(get_db)) -> dict[str, object]:
    """Called by Vercel Cron (see vercel.json), which sends `Authorization: Bearer $CRON_SECRET`."""
    expected = f"Bearer {settings.cron_secret}"
    if not settings.cron_secret or not secrets.compare_digest(request.headers.get("authorization", ""), expected):
        raise HTTPException(401, "Unauthorized")
    return run_daily(db)


@router.post("/router/secrets")
async def router_secrets(request: Request, db: Session = Depends(get_db)) -> dict[str, str]:
    """Receives the router's PPP secret/profile export (see router_sync.export_script) for importing users."""
    device = _device(request, db)
    body = (await request.body()).decode("utf-8", errors="replace")
    router_sync.ingest_secrets(db, device, body)
    return {"status": "ok"}
