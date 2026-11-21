"""Email notification service for tenant administrator invitations and receipts."""
from __future__ import annotations

import logging
from typing import Any

from saas.config import saas_settings

logger = logging.getLogger("saas.email")


class EmailDeliveryError(RuntimeError):
    """Raised when an email fails to deliver."""
    pass


def send_invitation_email(
    *,
    to_email: str,
    admin_name: str,
    company_name: str,
    invitation_url: str,
) -> bool:
    """
    Safeguard 5: Sends an administrator onboarding invitation containing the single-use setup link.
    Decoupled from database provisioning: returns True if sent, False if Resend is unconfigured,
    and logs cleanly without exposing credentials or throwing unhandled errors.
    """
    if not saas_settings.resend_api_key:
        logger.warning(
            "RESEND_API_KEY is not configured. Simulating invitation delivery for %s: %s",
            to_email,
            invitation_url,
        )
        return False

    subject = f"Welcome to {company_name} on COwen ISP Billing - Set Up Your Admin Account"
    html_content = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Welcome to COwen</title>
</head>
<body style="margin:0;padding:24px;background:#090a0f;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#f0f2f5;">
  <div style="max-width:540px;margin:0 auto;background:#121621;border:1px solid rgba(223,183,88,0.3);border-radius:12px;padding:36px;box-shadow:0 8px 30px rgba(0,0,0,0.5);">
    <div style="color:#dfb758;font-size:12px;font-weight:700;letter-spacing:0.15em;text-transform:uppercase;margin-bottom:12px;">COwen ISP Billing</div>
    <h1 style="margin:0 0 16px;color:#f0f2f5;font-size:22px;font-weight:600;">Welcome, {admin_name}!</h1>
    <p style="color:#949eb5;font-size:15px;line-height:1.6;margin:0 0 24px;">
      Your company account for <strong style="color:#f0f2f5;">{company_name}</strong> has been provisioned successfully.
      To activate your administrator dashboard and configure your MikroTik routers, click the button below to set your password.
    </p>
    <div style="text-align:center;margin:32px 0;">
      <a href="{invitation_url}" style="background:#dfb758;color:#090a0f;padding:14px 28px;text-decoration:none;border-radius:8px;font-weight:700;font-size:15px;display:inline-block;">
        Set Administrator Password &rarr;
      </a>
    </div>
    <p style="color:#949eb5;font-size:13px;line-height:1.5;margin:0 0 12px;">
      This single-use invitation link expires in 72 hours.
    </p>
    <p style="color:#64748b;font-size:12px;line-height:1.4;margin:24px 0 0;border-top:1px solid rgba(255,255,255,0.08);padding-top:16px;">
      If you did not request this account, please ignore this email.
    </p>
  </div>
</body>
</html>"""

    text_content = f"""Welcome, {admin_name}!

Your company account for {company_name} has been provisioned successfully on COwen ISP Billing.
To activate your administrator dashboard and configure your MikroTik routers, open the following link to set your password:

{invitation_url}

This single-use invitation link expires in 72 hours.
"""

    try:
        import resend
        resend.api_key = saas_settings.resend_api_key
        payload = {
            "from": saas_settings.resend_from_address,
            "to": [to_email],
            "subject": subject,
            "html": html_content,
            "text": text_content,
        }
        res = resend.Emails.send(payload)
        logger.info("Invitation email dispatched to %s (id: %s)", to_email, res.get("id"))
        return True
    except Exception as exc:
        logger.error("Failed to deliver invitation email to %s: %s", to_email, exc)
        return False


def send_superadmin_otp_email(
    *,
    to_email: str,
    otp_code: str,
) -> bool:
    """
    Sends the single-use 6-digit email verification code for Superadmin owner identity setup.
    Safeguard 3: In production, console fallback is strictly prohibited.
    """
    if not saas_settings.resend_api_key:
        if saas_settings.saas_env == "production":
            logger.error("Attempted Superadmin OTP email in production without RESEND_API_KEY.")
            raise EmailDeliveryError("RESEND_API_KEY must be configured in production environment.")
        
        logger.warning(
            "RESEND_API_KEY is not configured. Simulating Superadmin verification OTP for %s: [ %s ]",
            to_email,
            otp_code,
        )
        return False

    subject = "COwen Platform Owner Identity Verification — OTP Code"
    html_content = f"""<!doctype html>
<html>
<body style="margin:0;padding:24px;background:#090a0f;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;color:#f0f2f5;">
  <div style="max-width:520px;margin:0 auto;background:#121621;border:1px solid rgba(223,183,88,0.4);border-radius:12px;padding:36px;text-align:center;">
    <div style="color:#dfb758;font-size:12px;font-weight:700;letter-spacing:0.15em;text-transform:uppercase;margin-bottom:12px;">COwen Superadmin Onboarding</div>
    <h1 style="margin:0 0 16px;color:#fff;font-size:22px;">Verify Owner Identity</h1>
    <p style="color:#949eb5;font-size:14px;line-height:1.6;margin:0 0 24px;">
      Use the following single-use verification code to activate the Platform Superadmin account for <strong style="color:#fff;">{to_email}</strong>.
    </p>
    <div style="background:#090a0f;border:1px solid rgba(223,183,88,0.3);border-radius:8px;padding:18px;margin:24px 0;display:inline-block;letter-spacing:0.3em;font-size:32px;font-weight:800;color:#dfb758;font-family:monospace;">
      {otp_code}
    </div>
    <p style="color:#949eb5;font-size:13px;line-height:1.5;">
      This verification code is valid for 15 minutes.
    </p>
  </div>
</body>
</html>"""

    text_content = f"""COwen Platform Owner Identity Verification

Your single-use 6-digit verification code is: {otp_code}

This code is valid for 15 minutes.
"""

    try:
        import resend
        resend.api_key = saas_settings.resend_api_key
        payload = {
            "from": saas_settings.resend_from_address,
            "to": [to_email],
            "subject": subject,
            "html": html_content,
            "text": text_content,
        }
        resend.Emails.send(payload)
        logger.info("Superadmin OTP dispatched to %s", to_email)
        return True
    except Exception as exc:
        logger.error("Failed to deliver Superadmin OTP to %s: %s", to_email, exc)
        return False

