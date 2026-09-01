"""Billing backend settings, loaded from environment / .env."""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql+psycopg://pirates:pirates-dev-password@localhost:5432/pirates"

    # Paystack - M-Pesa charges go through Paystack's Charge API rather than
    # Safaricom Daraja directly. Use the "test" secret key for sandbox.
    paystack_secret_key: str = ""

    # Login for the admin dashboard - it can suspend customers and trigger
    # real M-Pesa charges, so it doesn't stay open by default.
    admin_username: str = "admin"
    admin_password: str = ""

    # Signs the admin dashboard's session cookie. Set a fixed random value in
    # .env so logins survive server restarts - if left blank, a new one is
    # generated at startup and every admin gets logged out on restart.
    session_secret_key: str = ""

    # Africa's Talking - welcome SMS on signup. Use username="sandbox" with a
    # sandbox API key to test without spending real credit (only reaches
    # numbers registered as test numbers in the AT dashboard).
    africastalking_username: str = ""
    africastalking_api_key: str = ""
    africastalking_sender_id: str = ""

    # Resend - welcome email on signup. Until a domain is verified at
    # resend.com/domains, this can only send to the account's own email and
    # must send from the "resend.dev" testing address below.
    resend_api_key: str = ""
    resend_from_address: str = "Pirates <onboarding@resend.dev>"

    # Public URL this server is reachable at (the cloudflared tunnel URL for
    # now) - needed to build absolute links in emails, like the "Pay Now"
    # button, since email clients can't resolve localhost.
    public_base_url: str = ""


settings = Settings()

if not settings.session_secret_key:
    import secrets

    settings.session_secret_key = secrets.token_hex(32)
