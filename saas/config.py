"""SaaS Platform Settings and Configuration."""
from __future__ import annotations

import os
from pydantic_settings import BaseSettings, SettingsConfigDict


class SaasSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env.saas",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    platform_name: str = "COwen ISP Billing"

    # Database: defaults to dedicated saas.db for zero-cost local dev,
    # or a dedicated Neon Postgres connection string in production
    saas_database_url: str = "sqlite:///./saas.db"

    # Master encryption key for tenant API keys at rest (Fernet / AES-256-GCM, 32 urlsafe base64 bytes)
    encryption_master_key: str = "4v9zG8XW2qZb7Yn1Km5Rt0Pu3Sw6Vx9Ay2Cd5Fh8Jk0="

    # Secret key for signing SaaS admin & tenant session cookies
    saas_session_secret: str = "saas-insecure-dev-session-secret-change-in-prod-32bytes"

    # Platform Owner Paystack credentials (FOR SAAS SUBSCRIPTIONS ONLY)
    platform_paystack_secret_key: str = ""
    platform_paystack_public_key: str = ""
    platform_paystack_callback_url: str = "http://localhost:8001/checkout/callback"

    # Resend email credentials for invitations & receipts
    resend_api_key: str = ""
    resend_from_address: str = "COwen ISP Billing <onboarding@cowen.app>"

    # Public SaaS domain
    saas_public_base_url: str = "http://localhost:8001"

    # Environment
    saas_env: str = "development"

    # Initial Superadmin Bootstrap (Configured via PLATFORM_SUPERADMIN_EMAIL)
    platform_superadmin_email: str = "owenzcolin@gmail.com"
    superadmin_email: str = "owenzcolin@gmail.com"
    superadmin_password: str = ""

    @property
    def effective_database_url(self) -> str:
        # Exclusively reads SAAS_DATABASE_URL with NO fallback to DATABASE_URL
        url = (os.environ.get("SAAS_DATABASE_URL") or self.saas_database_url).strip()
        if url.startswith("sqlite:///./") and os.environ.get("VERCEL"):
            url = "sqlite:////tmp/saas.db"
        return url

    @property
    def effective_public_base_url(self) -> str:
        url = os.environ.get("SAAS_PUBLIC_BASE_URL") or os.environ.get("PUBLIC_BASE_URL")
        if not url and os.environ.get("VERCEL"):
            return "https://cowen.vercel.app"
        return url or self.saas_public_base_url

    @property
    def effective_resend_api_key(self) -> str:
        return self.resend_api_key or os.environ.get("RESEND_API_KEY") or ""

    @property
    def effective_resend_from_address(self) -> str:
        return os.environ.get("RESEND_FROM_ADDRESS") or self.resend_from_address

    @property
    def effective_paystack_secret_key(self) -> str:
        key = self.platform_paystack_secret_key or os.environ.get("PAYSTACK_SECRET_KEY") or ""
        return key.strip()

    @property
    def effective_paystack_public_key(self) -> str:
        key = self.platform_paystack_public_key or os.environ.get("PAYSTACK_PUBLIC_KEY") or ""
        return key.strip()


saas_settings = SaasSettings()
