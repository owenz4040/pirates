"""Vercel entrypoint - Vercel looks for a FastAPI `app` in a root index.py."""
import os

if os.environ.get("DEPLOY_TARGET") == "saas" or os.environ.get("COWEN_APP") == "true":
    from saas.app import app  # noqa: F401
else:
    from billing.main import app  # noqa: F401
