"""
Pull-based router control.

The app (on Vercel) never connects to the MikroTik. Billing actions queue
RouterOS script lines in `router_commands`; once a minute the router POSTs to
/api/router/sync, gets the next batch back as a script, runs it, and reports
which commands succeeded via /api/router/ack.

Ordering matters (enable-then-disable must not run as disable-then-enable),
so a new batch is only handed out once the previous one is acknowledged or
has timed out - and a timed-out batch is re-sent ahead of anything newer.
"""

from __future__ import annotations

import secrets
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from fastapi import Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from billing.db import get_db
from billing.models import (
    ConnectionType,
    Customer,
    CustomerStatus,
    Plan,
    RouterCommand,
    RouterCommandStatus,
    RouterDevice,
)
from mikrotik.script import ScriptBandwidthProfileManager, ScriptPPPoEManager, ScriptStaticUserManager, quote

# A sent batch with no acknowledgement after this long is assumed lost and re-sent.
ACK_TIMEOUT = timedelta(minutes=3)
# Give up on a command after this many unacknowledged sends.
MAX_ATTEMPTS = 5
# RouterOS 6 caps `/tool fetch output=user` at 4 KB, RouterOS 7 at 64 KB.
BATCH_BYTES_ROS6 = 3500
BATCH_BYTES_ROS7 = 48000
# A router that hasn't synced for this long is shown as offline.
OFFLINE_AFTER = timedelta(minutes=3)


class CommandSink:
    """Adds commands to the session without committing - they land in the caller's transaction."""

    def __init__(self, db: Session) -> None:
        self._db = db
        self.count = 0

    def add(self, description: str, script: str) -> None:
        self._db.add(RouterCommand(description=description[:255], script=script))
        self.count += 1


@dataclass
class RouterGateway:
    sink: CommandSink
    ppp: ScriptPPPoEManager
    static: ScriptStaticUserManager
    bw: ScriptBandwidthProfileManager


def gateway(db: Session) -> RouterGateway:
    sink = CommandSink(db)
    return RouterGateway(
        sink=sink,
        ppp=ScriptPPPoEManager(sink),
        static=ScriptStaticUserManager(sink),
        bw=ScriptBandwidthProfileManager(sink),
    )


def get_router(db: Session = Depends(get_db)) -> Iterator[RouterGateway]:
    """FastAPI dependency - shares the request's DB session so commands commit with the billing change."""
    yield gateway(db)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: datetime | None) -> datetime | None:
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


# --- the router device -----------------------------------------------------


def get_or_create_device(db: Session) -> RouterDevice:
    device = db.scalar(select(RouterDevice).order_by(RouterDevice.id))
    if device is None:
        device = RouterDevice()
        db.add(device)
        db.commit()
        db.refresh(device)
    return device


def authenticate(db: Session, token: str) -> RouterDevice | None:
    if not token:
        return None
    for device in db.scalars(select(RouterDevice)):
        if secrets.compare_digest(device.token, token):
            return device
    return None


def is_online(device: RouterDevice | None) -> bool:
    last_seen = _aware(device.last_seen_at) if device else None
    return last_seen is not None and _now() - last_seen < OFFLINE_AFTER


def active_usernames(db: Session) -> set[str]:
    """Lower-cased PPPoE usernames the router last reported as connected (empty if the router is offline)."""
    device = db.scalar(select(RouterDevice).order_by(RouterDevice.id))
    if not is_online(device) or not device.active_usernames:
        return set()
    return {name.strip().lower() for name in device.active_usernames}


def record_checkin(db: Session, device: RouterDevice, form: dict[str, str], client_ip: str | None) -> None:
    device.last_seen_at = _now()
    device.last_ip = client_ip
    device.version = (form.get("version") or device.version or "")[:64] or None
    device.board = (form.get("board") or device.board or "")[:64] or None
    device.uptime = (form.get("uptime") or device.uptime or "")[:32] or None
    cpu = form.get("cpu", "")
    device.cpu_load = int(cpu) if cpu.isdigit() else device.cpu_load
    if "active" in form:
        device.active_usernames = [name for name in form["active"].split(",") if name]
    db.add(device)


# --- batching ----------------------------------------------------------------


def _batch_limit(device: RouterDevice) -> int:
    return BATCH_BYTES_ROS7 if (device.version or "").startswith("7") else BATCH_BYTES_ROS6


def next_batch(db: Session, device: RouterDevice) -> list[RouterCommand]:
    """
    Claim the next commands to send, oldest first. Returns nothing while a
    previous batch is still awaiting its acknowledgement, so commands never
    run out of order.
    """
    now = _now()
    stale_before = now - ACK_TIMEOUT
    in_flight = db.scalars(
        select(RouterCommand).where(RouterCommand.status == RouterCommandStatus.sent)
    ).all()
    if any(_aware(cmd.sent_at) > stale_before for cmd in in_flight):
        return []

    for cmd in in_flight:  # all timed out
        if cmd.attempts >= MAX_ATTEMPTS:
            cmd.status = RouterCommandStatus.failed
            cmd.finished_at = now
            db.add(cmd)
    db.flush()

    candidates = db.scalars(
        select(RouterCommand)
        .where(RouterCommand.status.in_([RouterCommandStatus.pending, RouterCommandStatus.sent]))
        .order_by(RouterCommand.id)
        .limit(500)
        .with_for_update(skip_locked=True)
    ).all()

    limit = _batch_limit(device)
    batch: list[RouterCommand] = []
    size = 0
    for cmd in candidates:
        cost = len(cmd.script) + 120  # + the :do/on-error wrapper
        if batch and size + cost > limit:
            break
        batch.append(cmd)
        size += cost

    for cmd in batch:
        cmd.status = RouterCommandStatus.sent
        cmd.sent_at = now
        cmd.attempts += 1
        db.add(cmd)
    db.commit()
    return batch


def render_batch(batch: list[RouterCommand], ack_url: str, token: str) -> str:
    """
    The script the router runs. Each command is wrapped so one failure doesn't
    stop the rest, and the script ends by reporting which ids succeeded.
    """
    if not batch:
        return ""
    lines = [':local ok ""', ':local failed ""']
    for cmd in batch:
        lines.append(
            f":do {{{cmd.script}; :set ok ($ok . \"{cmd.id},\")}} "
            f"on-error={{:set failed ($failed . \"{cmd.id},\"); :log warning \"pirates: command {cmd.id} failed\"}}"
        )
    lines.append(
        f":do {{/tool fetch url={quote(ack_url)} http-method=post "
        f"http-header-field={quote('X-Pirates-Token: ' + token)} "
        f'http-data=("ok=" . $ok . "&failed=" . $failed) output=none}} '
        f'on-error={{:log warning "pirates: could not report results"}}'
    )
    return "\n".join(lines) + "\n"


def _parse_ids(value: str) -> list[int]:
    return [int(part) for part in value.split(",") if part.strip().isdigit()]


def acknowledge(db: Session, ok: str, failed: str) -> tuple[int, int]:
    now = _now()
    results = [(i, RouterCommandStatus.done) for i in _parse_ids(ok)]
    results += [(i, RouterCommandStatus.failed) for i in _parse_ids(failed)]
    for command_id, status in results:
        cmd = db.get(RouterCommand, command_id)
        if cmd is None or cmd.status != RouterCommandStatus.sent:
            continue
        cmd.status = status
        cmd.finished_at = now
        db.add(cmd)
    db.commit()
    return sum(s == RouterCommandStatus.done for _, s in results), sum(
        s == RouterCommandStatus.failed for _, s in results
    )


def retry_failed(db: Session) -> int:
    failed = db.scalars(select(RouterCommand).where(RouterCommand.status == RouterCommandStatus.failed)).all()
    for cmd in failed:
        cmd.status = RouterCommandStatus.pending
        cmd.attempts = 0
        cmd.sent_at = None
        cmd.finished_at = None
        db.add(cmd)
    db.commit()
    return len(failed)


def enqueue_full_resync(db: Session) -> int:
    """
    Re-push every plan profile and every customer's on/off state, to repair
    drift (e.g. someone changed a user by hand in Winbox, or the router was
    reset). PPPoE passwords aren't stored here, so missing secrets can't be
    recreated - existing ones are corrected in place.
    """
    gw = gateway(db)
    for plan in db.scalars(select(Plan)):
        gw.bw.ensure_profile(plan.name, plan.rate_limit)
    for customer in db.scalars(select(Customer)):
        active = customer.status == CustomerStatus.active
        if customer.connection_type == ConnectionType.static:
            if not customer.static_ip:
                continue
            gw.static.create_or_update_queue(
                customer.pppoe_username, customer.static_ip, customer.plan.rate_limit, comment=customer.full_name
            )
            if active:
                gw.static.restore_user(customer.static_ip)
            else:
                gw.static.suspend_user(customer.static_ip, comment=customer.full_name)
        else:
            gw.ppp.set_profile(customer.pppoe_username, customer.plan.name, force_reconnect=False)
            if active:
                gw.ppp.enable_user(customer.pppoe_username)
            else:
                gw.ppp.disable_user(customer.pppoe_username)
    db.commit()
    return gw.sink.count


# --- one-time router setup ---------------------------------------------------


def setup_script(base_url: str, token: str) -> str:
    """
    Pasted once into the MikroTik terminal. Installs a script that syncs with
    this app and a scheduler that runs it every minute. Each run loops up to
    five times so a backlog drains quickly.
    """
    base = base_url.rstrip("/")
    sync_url = quote(f"{base}/api/router/sync")
    header = quote(f"X-Pirates-Token: {token}")
    return f"""\
/system script remove [find where name="pirates-sync"]
/system scheduler remove [find where name="pirates-sync"]
/system script add name="pirates-sync" policy=ftp,read,write,policy,test source={{
:local rounds 0
:local more true
:while ($more && $rounds < 5) do={{
  :set rounds ($rounds + 1)
  :local active ""
  :foreach i in=[/ppp active find] do={{ :set active ($active . [/ppp active get $i name] . ",") }}
  :local info ("version=" . [/system resource get version] . "&board=" . [/system resource get board-name] . "&uptime=" . [/system resource get uptime] . "&cpu=" . [/system resource get cpu-load] . "&active=" . $active)
  :local body ""
  :do {{
    :local res [/tool fetch url={sync_url} http-method=post http-header-field={header} http-data=$info output=user as-value]
    :set body ($res->"data")
  }} on-error={{ :log warning "pirates: sync failed"; :set more false }}
  :if ([:len $body] = 0) do={{ :set more false }} else={{
    :local run [:parse $body]
    $run
  }}
}}
}}
/system scheduler add name="pirates-sync" interval=1m start-time=startup policy=ftp,read,write,policy,test on-event="/system script run pirates-sync"
/system script run pirates-sync
"""
