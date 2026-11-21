"""Public marketing website router."""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

_TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

marketing_router = APIRouter(tags=["marketing"])


@marketing_router.get("/", response_class=HTMLResponse)
def index(request: Request):
    """Renders the public landing page."""
    return templates.TemplateResponse(request=request, name="marketing.html", context={})


@marketing_router.get("/pricing", response_class=HTMLResponse)
def pricing_redirect():
    """Redirects to the pricing section on the landing page."""
    return RedirectResponse(url="/#pricing", status_code=302)
