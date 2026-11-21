"""RouterOS parameter validation and escaping utilities.

Prevents command injection when generating RouterOS scripts from tenant input.
Strict allowlists are enforced; invalid characters are rejected rather than sanitized.
"""
from __future__ import annotations

import re

# Strict validation regexes
# Alphanumeric with safe punctuation: dot, underscore, hyphen, @
_USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_\-\.@]{2,64}$")
# Plan/Package names: alphanumeric, spaces, hyphens, parentheses (e.g. "10 Mbps (Home)")
_NAME_REGEX = re.compile(r"^[a-zA-Z0-9\s_\-\.()]{2,64}$")
# Rate limits: e.g. "10M/10M", "512k/2M", "5M/10M 10M/20M"
_RATE_LIMIT_REGEX = re.compile(r"^[0-9]+[kKmMgG]/[0-9]+[kKmMgG](\s+[0-9]+[kKmMgG]/[0-9]+[kKmMgG])?$")
# Hotspot voucher codes: uppercase alphanumeric, 3 to 32 chars
_VOUCHER_CODE_REGEX = re.compile(r"^[a-zA-Z0-9_\-]{3,32}$")
# Control characters (ASCII 0-31 and 127)
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


class CommandInjectionError(ValueError):
    """Raised when user input violates RouterOS parameter safety rules."""
    pass


def quote_routeros(value: str) -> str:
    """Quote a value as a RouterOS string literal.

    Escapes backslashes, double quotes, and dollar signs ($ expands as a variable in RouterOS).
    Replaces any control characters or newlines with a safe space.
    """
    text = _CONTROL_CHARS.sub(" ", str(value))
    text = text.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$")
    return f'"{text}"'


def validate_pppoe_username(username: str) -> str:
    """Validate PPPoE username against strict allowlist."""
    username = username.strip()
    if not _USERNAME_REGEX.match(username):
        raise CommandInjectionError(
            f"Invalid PPPoE username '{username}'. Only letters, numbers, hyphens, dots, underscores, and @ are allowed (2-64 characters)."
        )
    return username


def validate_password(password: str) -> str:
    """Validate subscriber password: must not contain newlines or control characters."""
    if not password:
        raise CommandInjectionError("Password cannot be empty.")
    if _CONTROL_CHARS.search(password):
        raise CommandInjectionError("Password contains forbidden control characters.")
    if len(password) > 128:
        raise CommandInjectionError("Password is too long (max 128 characters).")
    return password


def validate_plan_name(name: str) -> str:
    """Validate bandwidth speed plan name."""
    name = name.strip()
    if not _NAME_REGEX.match(name):
        raise CommandInjectionError(
            f"Invalid plan name '{name}'. Only letters, numbers, spaces, dots, hyphens, and parentheses are allowed (2-64 characters)."
        )
    return name


def validate_rate_limit(rate_limit: str) -> str:
    """Validate MikroTik rate limit syntax (e.g. '10M/10M')."""
    rate_limit = rate_limit.strip()
    if not _RATE_LIMIT_REGEX.match(rate_limit):
        raise CommandInjectionError(
            f"Invalid rate limit '{rate_limit}'. Format must be Rx/Tx (e.g., '10M/10M' or '512k/2M')."
        )
    return rate_limit


def validate_package_name(name: str) -> str:
    """Validate Hotspot package name."""
    name = name.strip()
    if not _NAME_REGEX.match(name):
        raise CommandInjectionError(
            f"Invalid package name '{name}'. Only letters, numbers, spaces, dots, hyphens, and parentheses are allowed (2-64 characters)."
        )
    return name


def validate_voucher_code(code: str) -> str:
    """Validate Hotspot voucher code."""
    code = code.strip()
    if not _VOUCHER_CODE_REGEX.match(code):
        raise CommandInjectionError(
            f"Invalid voucher code '{code}'. Only alphanumeric characters, hyphens, and underscores are allowed (3-32 characters)."
        )
    return code


def validate_comment(comment: str | None) -> str:
    """Sanitize comment string for RouterOS: removes control characters and caps length."""
    if not comment:
        return ""
    cleaned = _CONTROL_CHARS.sub(" ", comment.strip())
    # Truncate to 128 characters max
    return cleaned[:128]


def build_pppoe_secret_command(
    username: str,
    password: str,
    profile: str,
    service: str = "pppoe",
    comment: str | None = None,
) -> str:
    """Build a safe, idempotent RouterOS command to create or update a PPPoE secret."""
    v_user = validate_pppoe_username(username)
    v_pass = validate_password(password)
    v_prof = validate_plan_name(profile)
    v_comm = validate_comment(comment)

    match = f"name={quote_routeros(v_user)}"
    add_args = f"password={quote_routeros(v_pass)} profile={quote_routeros(v_prof)} service={quote_routeros(service)}"
    set_args = f"password={quote_routeros(v_pass)} profile={quote_routeros(v_prof)}"
    if v_comm:
        add_args += f" comment={quote_routeros(v_comm)}"
        set_args += f" comment={quote_routeros(v_comm)}"

    return (
        f":if ([:len [/ppp secret find where {match}]] = 0) "
        f"do={{/ppp secret add {match} {add_args}}} "
        f"else={{/ppp secret set [find where {match}] {set_args}}}"
    )


def build_hotspot_user_command(
    code: str,
    password: str,
    profile: str,
    comment: str | None = None,
) -> str:
    """Build a safe, idempotent RouterOS command to create or update a Hotspot user."""
    v_code = validate_voucher_code(code)
    v_pass = validate_password(password)
    v_prof = validate_package_name(profile)
    v_comm = validate_comment(comment)

    match = f"name={quote_routeros(v_code)}"
    add_args = f"password={quote_routeros(v_pass)} profile={quote_routeros(v_prof)}"
    set_args = f"password={quote_routeros(v_pass)} profile={quote_routeros(v_prof)}"
    if v_comm:
        add_args += f" comment={quote_routeros(v_comm)}"
        set_args += f" comment={quote_routeros(v_comm)}"

    return (
        f":if ([:len [/ip hotspot user find where {match}]] = 0) "
        f"do={{/ip hotspot user add {match} {add_args}}} "
        f"else={{/ip hotspot user set [find where {match}] {set_args}}}"
    )


def build_mikrotik_sync_script_source(
    sync_url: str,
    raw_token: str,
    bypass_secret: str | None = None,
) -> str:
    """Builds the in-memory RouterOS script source for periodic cloud synchronization.

    Compatible with RouterOS 6.49+ and RouterOS 7.x.
    All internal string quotes are escaped as \\\" and variable references as \\$
    to guarantee safe parsing into the RouterOS script repository with zero quote collisions
    or premature variable expansions in the terminal.
    Uses check-certificate=no to guarantee native, out-of-the-box HTTPS polling on both
    RouterOS 6 (which lacks preinstalled root CAs) and RouterOS 7, while maintaining
    TLS transport encryption and cryptographic token authentication.
    Zero files are written to NAND storage.
    """
    clean_url = sync_url.strip().replace('"', '').replace('\\', '').replace('$', '')
    clean_token = raw_token.strip().replace('"', '').replace('\\', '').replace('$', '')
    header_val = f"Content-Type: application/x-www-form-urlencoded,X-Router-Token: {clean_token}"
    if bypass_secret:
        clean_bypass = bypass_secret.strip().replace('"', '').replace('\\', '').replace('$', '')
        if clean_bypass:
            header_val += f",x-vercel-protection-bypass: {clean_bypass}"

    source_statements = [
        ":local ver [/system resource get version];",
        ":local upt [/system resource get uptime];",
        ":local cpu [/system resource get cpu-load];",
        ":local brd [/system resource get board-name];",
        ':local info (\\"version=\\" . \\$ver . \\"&uptime=\\" . \\$upt . \\"&cpu=\\" . \\$cpu . \\"&board=\\" . \\$brd);',
        ':local body \\"\\";',
        ':local status \\"\\";',
        f':do {{ :local res [/tool fetch url=\\"{clean_url}\\" http-method=post http-header-field=\\"{header_val}\\" http-data=\\$info check-certificate=no output=user as-value]; :set status (\\$res->\\"status\\"); :set body (\\$res->\\"data\\"); :log info \\"COwen_Sync: Check-in successful\\"; }} on-error={{ :log warning \\"COwen_Sync: HTTPS fetch failed - check network or TLS certificates\\" }};',
        ':if (\\$status = \\"finished\\" and [:len \\$body] >= 16 and [:len \\$body] <= 32768 and [:pick \\$body 0 16] = \\"# COwen-Batch-OK\\") do={{ :do {{ :local run [:parse \\$body]; \\$run; }} on-error={{ :log warning \\"COwen_Sync: batch command execution error\\" }}; }};'
    ]
    return " ".join(source_statements)


def build_mikrotik_rsc_file(
    sync_url: str,
    raw_token: str,
    router_name: str,
    bypass_secret: str | None = None,
) -> str:
    """Generates a downloadable, self-contained RouterOS .rsc configuration script.

    Compatible with RouterOS 7.x (including 7.25.1) and RouterOS 6.49+.
    Can be imported safely using: /import file-name=cowen_setup.rsc
    Avoids multiline terminal paste and CRLF buffer truncation issues.
    """
    clean_name = validate_plan_name(router_name)
    script_source = build_mikrotik_sync_script_source(sync_url, raw_token, bypass_secret=bypass_secret)

    return (
        f"# =====================================================================\n"
        f"# COwen ISP SaaS — MikroTik RouterOS Setup Configuration\n"
        f"# Target Router: {clean_name}\n"
        f"# Cloud Endpoint: {sync_url}\n"
        f"# Architecture: Outbound HTTPS Polling (Port 443 in RAM)\n"
        f"# Compatibility: RouterOS 6.49+ & RouterOS 7.x\n"
        f"# =====================================================================\n\n"
        f"# Step 1: Enable native SSL/TLS root certificates on RouterOS 7 (if supported)\n"
        f":do {{ /certificate enable-ssl-certificate }} on-error={{\n"
        f"    :log info \"COwen_Sync: enable-ssl-certificate not supported on RouterOS 6 (native HTTPS active)\"\n"
        f"}}\n\n"
        f"# Step 2: Remove any previous synchronization script and scheduler safely\n"
        f":do {{ /system script remove [find name=\"COwen_Sync_Script\"] }} on-error={{}}\n"
        f":do {{ /system scheduler remove [find name=\"COwen_Sync\"] }} on-error={{}}\n\n"
        f"# Step 3: Add synchronization script to RAM script repository\n"
        f"/system script add name=\"COwen_Sync_Script\" comment=\"COwen ISP SaaS Cloud Sync\" source=\"{script_source}\"\n\n"
        f"# Step 4: Schedule synchronization every 60 seconds\n"
        f"/system scheduler add name=\"COwen_Sync\" interval=60s on-event=\"COwen_Sync_Script\" start-time=startup comment=\"COwen ISP SaaS Cloud Poller\"\n\n"
        f"# Step 5: Execute initial synchronization immediately\n"
        f"/system script run COwen_Sync_Script\n"
        f":log info \"COwen_Sync: Setup successfully imported and initialized.\"\n"
    )


def build_mikrotik_terminal_commands(
    sync_url: str,
    raw_token: str,
    router_name: str,
    bypass_secret: str | None = None,
) -> str:
    """Generates terminal paste commands with single-line script source to avoid CRLF line continuation bugs."""
    clean_name = validate_plan_name(router_name)
    script_source = build_mikrotik_sync_script_source(sync_url, raw_token, bypass_secret=bypass_secret)

    return (
        f"# MikroTik RouterOS Outbound HTTPS Synchronization Setup\n"
        f"# Device: {clean_name}\n"
        f":do {{ /certificate enable-ssl-certificate }} on-error={{}}\n"
        f":do {{ /system script remove [find name=\"COwen_Sync_Script\"] }} on-error={{}}\n"
        f":do {{ /system scheduler remove [find name=\"COwen_Sync\"] }} on-error={{}}\n"
        f"/system script add name=\"COwen_Sync_Script\" comment=\"COwen ISP SaaS Cloud Sync\" source=\"{script_source}\"\n"
        f"/system scheduler add name=\"COwen_Sync\" interval=60s on-event=\"COwen_Sync_Script\" start-time=startup\n"
        f"/system script run COwen_Sync_Script\n"
    )

