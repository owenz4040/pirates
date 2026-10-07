"""
One layout for every customer email, written to look like what it is - a
transactional account notice - so spam filters treat it that way:

- a complete HTML document (doctype, lang, title) with a matching plain-text part
- plain, factual wording; no hype words, exclamation marks or "PIN" phrasing,
  which are what M-Pesa phishing emails look like
- links only to our own domain, shown as text as well as a button
- a footer saying who sent it and why the customer is getting it
"""

from __future__ import annotations

import html
from dataclasses import dataclass, field

BRAND = "Pirates Wifi"


@dataclass
class Email:
    subject: str
    greeting_name: str
    intro: str
    details: list[tuple[str, str]] = field(default_factory=list)
    button: tuple[str, str] | None = None  # (label, url)
    button_note: str | None = None
    outro: str | None = None
    account: str = ""


def render(email: Email) -> tuple[str, str, str]:
    """Returns (subject, html, text)."""
    esc = html.escape

    detail_rows = "".join(
        f'<tr><td style="padding:6px 0;color:#555555;">{esc(label)}</td>'
        f'<td style="padding:6px 0;text-align:right;font-weight:600;color:#111111;">{esc(value)}</td></tr>'
        for label, value in email.details
    )
    details_html = (
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
        f'style="border-top:1px solid #e5e5e5;border-bottom:1px solid #e5e5e5;margin:20px 0;font-size:15px;">'
        f"{detail_rows}</table>"
        if email.details
        else ""
    )

    button_html = ""
    if email.button:
        label, url = email.button
        note = f'<p style="margin:8px 0 0;color:#555555;font-size:13px;">{esc(email.button_note)}</p>' if email.button_note else ""
        button_html = (
            f'<p style="margin:24px 0 0;"><a href="{esc(url)}" '
            f'style="display:inline-block;background:#1a56db;color:#ffffff;text-decoration:none;'
            f'padding:12px 24px;border-radius:6px;font-weight:600;font-size:15px;">{esc(label)}</a></p>'
            f"{note}"
            f'<p style="margin:12px 0 0;color:#555555;font-size:13px;">Or open this link: '
            f'<a href="{esc(url)}" style="color:#1a56db;">{esc(url)}</a></p>'
        )

    outro_html = f'<p style="margin:20px 0 0;">{esc(email.outro)}</p>' if email.outro else ""
    account_line = f" for account {esc(email.account)}" if email.account else ""

    body = f"""\
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(email.subject)}</title>
</head>
<body style="margin:0;padding:0;background:#f4f4f5;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f5;">
<tr><td align="center" style="padding:24px 12px;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:560px;background:#ffffff;border-radius:8px;">
<tr><td style="padding:28px 28px 8px;font-family:Arial,Helvetica,sans-serif;font-size:18px;font-weight:700;color:#111111;">{BRAND}</td></tr>
<tr><td style="padding:8px 28px 28px;font-family:Arial,Helvetica,sans-serif;font-size:15px;line-height:1.6;color:#222222;">
<p style="margin:0 0 12px;">Hello {esc(email.greeting_name)},</p>
<p style="margin:0;">{esc(email.intro)}</p>
{details_html}{button_html}{outro_html}
</td></tr>
</table>
<p style="max-width:560px;margin:16px auto 0;font-family:Arial,Helvetica,sans-serif;font-size:12px;line-height:1.5;color:#777777;">
You are receiving this because you have an internet account with {BRAND}{account_line}. This is a service message about your account.
</p>
</td></tr>
</table>
</body>
</html>
"""

    text_lines = [BRAND, "", f"Hello {email.greeting_name},", "", email.intro]
    if email.details:
        text_lines.append("")
        text_lines += [f"{label}: {value}" for label, value in email.details]
    if email.button:
        label, url = email.button
        text_lines += ["", f"{label}: {url}"]
        if email.button_note:
            text_lines.append(email.button_note)
    if email.outro:
        text_lines += ["", email.outro]
    text_lines += [
        "",
        "--",
        f"You are receiving this because you have an internet account with {BRAND}"
        f"{' for account ' + email.account if email.account else ''}. This is a service message about your account.",
    ]
    return email.subject, body, "\n".join(text_lines)
