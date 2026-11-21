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


saas_settings = SaasSettings()
