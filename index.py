"""Vercel entrypoint - Vercel looks for a FastAPI `app` in a root index.py."""

from billing.main import app  # noqa: F401
