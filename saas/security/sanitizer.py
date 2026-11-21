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


# Verified Let's Encrypt ISRG Root X1 Certificate and SHA-256 Fingerprint
ISRG_ROOT_X1_SHA256 = "96bcec06264976f37460779acf28c5a7cfe8a3c0aae11a8ffcee05c0bddf08c6"
ISRG_ROOT_X1_PEM = (
    "-----BEGIN CERTIFICATE-----\\r\\n"
    "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\\r\\n"
    "-----END CERTIFICATE-----\\r\\n"
)


def build_pppoe_profile_command(
    name: str,
    rate_limit: str,
    comment: str = "COwen Managed Profile",
) -> str:
    """Build a safe, conflict-safe idempotent RouterOS command to create or update a PPP profile.

    Ensures the profile has the exact rate-limit without overwriting existing unmanaged profiles.
    """
    v_name = validate_plan_name(name)
    v_rate = validate_rate_limit(rate_limit)
    v_comm = validate_comment(comment)

    q_name = quote_routeros(v_name)
    q_rate = quote_routeros(v_rate)
    q_comm = quote_routeros(v_comm)

    return (
        f":if ([:len [/ppp profile find where name={q_name}]] = 0) do={{"
        f"/ppp profile add name={q_name} rate-limit={q_rate} comment={q_comm}"
        f"}} else={{"
        f":if ([:len [/ppp profile find where name={q_name} and comment={q_comm}]] > 0) do={{"
        f"/ppp profile set [find where name={q_name} and comment={q_comm}] rate-limit={q_rate}"
        f"}}"
        f"}}"
    )


def build_hotspot_profile_command(
    name: str,
    rate_limit: str,
    shared_users: int = 1,
    comment: str = "COwen Managed Profile",
) -> str:
    """Build a safe, conflict-safe idempotent RouterOS command to create or update a Hotspot user profile.

    Ensures the user profile has the exact rate-limit and shared-users settings without overwriting unmanaged profiles.
    """
    v_name = validate_package_name(name)
    v_rate = validate_rate_limit(rate_limit)
    v_comm = validate_comment(comment)

    q_name = quote_routeros(v_name)
    q_rate = quote_routeros(v_rate)
    q_comm = quote_routeros(v_comm)

    return (
        f":if ([:len [/ip hotspot user profile find where name={q_name}]] = 0) do={{"
        f"/ip hotspot user profile add name={q_name} rate-limit={q_rate} shared-users={shared_users} comment={q_comm}"
        f"}} else={{"
        f":if ([:len [/ip hotspot user profile find where name={q_name} and comment={q_comm}]] > 0) do={{"
        f"/ip hotspot user profile set [find where name={q_name} and comment={q_comm}] rate-limit={q_rate} shared-users={shared_users}"
        f"}}"
        f"}}"
    )


def build_pppoe_disable_command(username: str, subscriber_id: str | None = None) -> str:
    """Build a safe command to disable a PPPoE secret and kick active sessions immediately, verifying ownership."""
    v_user = validate_pppoe_username(username)
    q_user = quote_routeros(v_user)
    if subscriber_id:
        q_marker = quote_routeros(f"COwen-PPPoE:{subscriber_id}")
        return (
            f":if ([:len [/ppp secret find where name={q_user} and comment={q_marker}]] > 0) do={{"
            f"/ppp secret set [find where name={q_user} and comment={q_marker}] disabled=yes; "
            f":do {{/ppp active remove [find where name={q_user}]}} on-error={{}}"
            f"}} else={{"
            f':error "COwen_Sync: Cannot disable PPPoE secret \'{v_user}\' - ownership mismatch"'
            f"}}"
        )
    return f"/ppp secret set [find where name={q_user}] disabled=yes; :do {{/ppp active remove [find where name={q_user}]}} on-error={{}}"


def build_pppoe_enable_command(username: str, subscriber_id: str | None = None) -> str:
    """Build a safe command to enable a PPPoE secret, verifying ownership."""
    v_user = validate_pppoe_username(username)
    q_user = quote_routeros(v_user)
    if subscriber_id:
        q_marker = quote_routeros(f"COwen-PPPoE:{subscriber_id}")
        return (
            f":if ([:len [/ppp secret find where name={q_user} and comment={q_marker}]] > 0) do={{"
            f"/ppp secret set [find where name={q_user} and comment={q_marker}] disabled=no"
            f"}} else={{"
            f':error "COwen_Sync: Cannot enable PPPoE secret \'{v_user}\' - ownership mismatch"'
            f"}}"
        )
    return f"/ppp secret set [find where name={q_user}] disabled=no"


def build_pppoe_delete_command(username: str, subscriber_id: str | None = None) -> str:
    """Build a safe command to remove a PPPoE secret and kick active sessions, verifying ownership."""
    v_user = validate_pppoe_username(username)
    q_user = quote_routeros(v_user)
    if subscriber_id:
        q_marker = quote_routeros(f"COwen-PPPoE:{subscriber_id}")
        return (
            f":if ([:len [/ppp secret find where name={q_user} and comment={q_marker}]] > 0) do={{"
            f":do {{/ppp secret remove [find where name={q_user} and comment={q_marker}]}} on-error={{}}; "
            f":do {{/ppp active remove [find where name={q_user}]}} on-error={{}}"
            f"}} else={{"
            f':error "COwen_Sync: Cannot delete PPPoE secret \'{v_user}\' - ownership mismatch"'
            f"}}"
        )
    return f":do {{/ppp secret remove [find where name={q_user}]}} on-error={{}}; :do {{/ppp active remove [find where name={q_user}]}} on-error={{}}"


def build_pppoe_secret_command(
    username: str,
    password: str,
    profile: str,
    service: str = "pppoe",
    comment: str | None = None,
    subscriber_id: str | None = None,
) -> str:
    """Build a safe, idempotent RouterOS command to create or update a PPPoE secret with immutable ownership marker.

    Guarantees:
    - Every COwen-managed PPPoE secret carries an immutable ownership marker (COwen-PPPoE:<subscriber_id>).
    - Updates an existing secret only if its ownership marker matches.
    - If an existing secret has no COwen marker or belongs to another subscriber, raises a conflict (:error).
    - Never changes an unmanaged customer's password, profile, service or comment.
    - Completely idempotent on retries.
    """
    v_user = validate_pppoe_username(username)
    v_pass = validate_password(password)
    v_prof = validate_plan_name(profile)

    if subscriber_id:
        v_marker = f"COwen-PPPoE:{subscriber_id}"
    elif comment and "COwen-PPPoE:" in comment:
        v_marker = comment
    else:
        v_marker = f"COwen-PPPoE:{v_user}"

    q_user = quote_routeros(v_user)
    q_pass = quote_routeros(v_pass)
    q_prof = quote_routeros(v_prof)
    q_marker = quote_routeros(v_marker)
    q_serv = quote_routeros(service)

    return (
        f":if ([:len [/ppp secret find where name={q_user}]] = 0) do={{"
        f"/ppp secret add name={q_user} password={q_pass} profile={q_prof} service={q_serv} comment={q_marker}"
        f"}} else={{"
        f":if ([:len [/ppp secret find where name={q_user} and comment={q_marker}]] > 0) do={{"
        f"/ppp secret set [find where name={q_user} and comment={q_marker}] password={q_pass} profile={q_prof}"
        f"}} else={{"
        f':error "COwen_Sync: Conflict - PPPoE secret \'{v_user}\' exists without matching COwen ownership marker"'
        f"}}"
        f"}}"
    )


def build_hotspot_user_command(
    code: str,
    password: str,
    profile: str,
    comment: str | None = None,
    voucher_id: str | None = None,
) -> str:
    """Build a safe, idempotent RouterOS command to create or update a Hotspot user with immutable ownership marker.

    Guarantees:
    - Every COwen-managed voucher carries an immutable ownership marker (COwen-Voucher:<voucher_id>).
    - Updates an existing voucher only if its ownership marker matches.
    - Detects username collisions with unmanaged Hotspot users and raises a conflict (:error).
    - Never overwrites unrelated Hotspot users.
    - Completely idempotent on retries.
    """
    v_code = validate_voucher_code(code)
    v_pass = validate_password(password)
    v_prof = validate_package_name(profile)

    if voucher_id:
        v_marker = f"COwen-Voucher:{voucher_id}"
    elif comment and "COwen-Voucher:" in comment:
        v_marker = comment
    elif comment:
        v_marker = f"COwen-Voucher:{v_code} | {validate_comment(comment)}"
    else:
        v_marker = f"COwen-Voucher:{v_code}"

    q_code = quote_routeros(v_code)
    q_pass = quote_routeros(v_pass)
    q_prof = quote_routeros(v_prof)
    q_marker = quote_routeros(v_marker)

    return (
        f":if ([:len [/ip hotspot user find where name={q_code}]] = 0) do={{"
        f"/ip hotspot user add name={q_code} password={q_pass} profile={q_prof} comment={q_marker}"
        f"}} else={{"
        f":if ([:len [/ip hotspot user find where name={q_code} and comment={q_marker}]] > 0) do={{"
        f"/ip hotspot user set [find where name={q_code} and comment={q_marker}] password={q_pass} profile={q_prof}"
        f"}} else={{"
        f':error "COwen_Sync: Conflict - Hotspot user \'{v_code}\' exists without matching COwen voucher marker"'
        f"}}"
        f"}}"
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
    Uses strict TLS certificate verification (check-certificate=yes-without-crl)
    and per-router cryptographic token authentication (X-Router-Token).
    Zero deployment-wide bypass secrets are embedded.
    Zero files are written to NAND storage during polling.
    """
    clean_url = sync_url.strip().replace('"', '').replace('\\', '').replace('$', '')
    clean_token = raw_token.strip().replace('"', '').replace('\\', '').replace('$', '')
    header_val = f"Content-Type: application/x-www-form-urlencoded,X-Router-Token: {clean_token}"

    source_statements = [
        ":local ver [/system resource get version];",
        ":local upt [/system resource get uptime];",
        ":local cpu [/system resource get cpu-load];",
        ":local brd [/system resource get board-name];",
        ':local info (\\"version=\\" . \\$ver . \\"&uptime=\\" . \\$upt . \\"&cpu=\\" . \\$cpu . \\"&board=\\" . \\$brd);',
        ':local body \\"\\";',
        ':local status \\"\\";',
        f':do {{ :local res [/tool fetch url=\\"{clean_url}\\" http-method=post http-header-field=\\"{header_val}\\" http-data=\\$info check-certificate=yes-without-crl output=user as-value]; :set status (\\$res->\\"status\\"); :set body (\\$res->\\"data\\"); :log info \\"COwen_Sync: Check-in successful\\"; }} on-error={{ :log warning \\"COwen_Sync: HTTPS fetch failed - check network or TLS certificates\\" }};',
        ':if (\\$status = \\"finished\\" and [:len \\$body] >= 16 and [:len \\$body] <= 32768 and [:pick \\$body 0 16] = \\"# COwen-Batch-OK\\") do={ :do { :local run [:parse \\$body]; \\$run; } on-error={ :log warning \\"COwen_Sync: batch command execution error\\" }; };'
    ]
    return " ".join(source_statements)


def build_mikrotik_rsc_file(
    sync_url: str,
    raw_token: str,
    router_name: str,
    bypass_secret: str | None = None,
) -> str:
    """Generates a downloadable, self-contained RouterOS .rsc configuration script.

    Universal compatibility for RouterOS 6.49+ and RouterOS 7.x (including SMIPS architecture).
    Enforces strict TLS verification via check-certificate=yes-without-crl.
    Ensures network time synchronization (SNTP) is enabled so TLS cert validity checks succeed.
    Verifies that the official Let's Encrypt ISRG Root X1 CA is installed and trusted.
    Can be imported safely using: /import file-name=cowen_setup.rsc
    """
    clean_name = validate_plan_name(router_name)
    script_source = build_mikrotik_sync_script_source(sync_url, raw_token)

    return (
        f"# =====================================================================\n"
        f"# COwen ISP SaaS — MikroTik RouterOS Setup Configuration\n"
        f"# Target Router: {clean_name}\n"
        f"# Cloud Endpoint: {sync_url}\n"
        f"# Architecture: Outbound HTTPS Polling (Strict TLS Port 443 in RAM)\n"
        f"# Compatibility: RouterOS 6.49+ & RouterOS 7.x (SMIPS, MIPSBE, ARM, x86)\n"
        f"# =====================================================================\n\n"
        f"# Step 1: Ensure router clock is synchronized via SNTP / NTP\n"
        f"# TLS certificate verification requires an accurate system clock.\n"
        f":do {{\n"
        f"    /system ntp client set enabled=yes primary-ntp=129.6.15.28 secondary-ntp=132.163.96.1\n"
        f"}} on-error={{\n"
        f"    :do {{ /system ntp client set enabled=yes servers=pool.ntp.org }} on-error={{\n"
        f"        :log warning \"COwen_Sync: NTP client configuration skipped\"\n"
        f"    }}\n"
        f"}}\n\n"
        f"# Step 2: Ensure official ISRG Root X1 CA is installed and trusted for TLS verification\n"
        f":if ([:len [/certificate find where fingerprint=\"{ISRG_ROOT_X1_SHA256}\"]] = 0) do={{\n"
        f"    :do {{\n"
        f"        /file print file=\"cowen_rootca\"\n"
        f"        :delay 2s\n"
        f"        /file set cowen_rootca.txt contents=\"{ISRG_ROOT_X1_PEM}\"\n"
        f"        /certificate import file-name=cowen_rootca.txt passphrase=\"\"\n"
        f"        /file remove [find name=\"cowen_rootca.txt\"]\n"
        f"        /certificate set [find where fingerprint=\"{ISRG_ROOT_X1_SHA256}\"] trusted=yes\n"
        f"        :log info \"COwen_Sync: ISRG Root X1 certificate imported and trusted\"\n"
        f"    }} on-error={{\n"
        f"        :log warning \"COwen_Sync: Root CA inline import skipped (upload isrgrootx1.crt if not present)\"\n"
        f"    }}\n"
        f"}} else={{\n"
        f"    /certificate set [find where fingerprint=\"{ISRG_ROOT_X1_SHA256}\"] trusted=yes\n"
        f"}}\n\n"
        f"# Step 3: Remove any previous synchronization script and scheduler safely\n"
        f":do {{ /system script remove [find name=\"COwen_Sync_Script\"] }} on-error={{}}\n"
        f":do {{ /system scheduler remove [find name=\"COwen_Sync\"] }} on-error={{}}\n\n"
        f"# Step 4: Add synchronization script to RAM script repository\n"
        f"/system script add name=\"COwen_Sync_Script\" comment=\"COwen ISP SaaS Cloud Sync\" source=\"{script_source}\"\n\n"
        f"# Step 5: Schedule synchronization every 60 seconds\n"
        f"/system scheduler add name=\"COwen_Sync\" interval=60s on-event=\"COwen_Sync_Script\" start-time=startup comment=\"COwen ISP SaaS Cloud Poller\"\n\n"
        f"# Step 6: Execute initial synchronization immediately\n"
        f"/system script run COwen_Sync_Script\n"
        f":log info \"COwen_Sync: Setup successfully imported and initialized.\"\n"
    )


def build_mikrotik_terminal_commands(
    sync_url: str,
    raw_token: str,
    router_name: str,
    bypass_secret: str | None = None,
) -> str:
    """Generates terminal paste commands with single-line script source and strict TLS validation."""
    clean_name = validate_plan_name(router_name)
    script_source = build_mikrotik_sync_script_source(sync_url, raw_token)

    return (
        f"# MikroTik RouterOS Outbound HTTPS Synchronization Setup\n"
        f"# Device: {clean_name}\n"
        f":do {{ /system script remove [find name=\"COwen_Sync_Script\"] }} on-error={{}}\n"
        f":do {{ /system scheduler remove [find name=\"COwen_Sync\"] }} on-error={{}}\n"
        f"/system script add name=\"COwen_Sync_Script\" comment=\"COwen ISP SaaS Cloud Sync\" source=\"{script_source}\"\n"
        f"/system scheduler add name=\"COwen_Sync\" interval=60s on-event=\"COwen_Sync_Script\" start-time=startup\n"
        f"/system script run COwen_Sync_Script\n"
    )

