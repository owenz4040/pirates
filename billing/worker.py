"""
Expiry sweep and reminders.

On Vercel this runs two ways: the expiry sweep piggybacks on every router
sync (so it runs once a minute for free), and the daily Vercel cron calls
run_daily() for reminders plus a backup sweep. Router changes are queued,
not applied here - the router picks them up on its next sync.

Usage (manual run against the configured database):
    python -m billing.worker
"""

from __future__ import annotations

from dotenv import load_dotenv

load_dotenv()

from sqlalchemy.orm import Session  # noqa: E402

from billing.db import SessionLocal  # noqa: E402
from billing.router_sync import gateway  # noqa: E402
from billing.services import expire_overdue_customers, send_expiry_reminders  # noqa: E402


def expire_sweep(db: Session) -> list[str]:
    gw = gateway(db)
    expired = expire_overdue_customers(db, ppp=gw.ppp, static_mgr=gw.static)
    return [customer.pppoe_username for customer in expired]


def run_daily(db: Session) -> dict[str, object]:
    count_2, count_1 = send_expiry_reminders(db)
    expired = expire_sweep(db)
    return {"reminders_2_day": count_2, "reminders_1_day": count_1, "expired": expired}


def main() -> None:
    db = SessionLocal()
    try:
        result = run_daily(db)
        print(f"Sent {result['reminders_2_day']}x 2-day and {result['reminders_1_day']}x 1-day reminders.")
        for username in result["expired"]:
            print(f"Expired {username} (queued for the router)")
        if not result["expired"]:
            print("No overdue customers.")
    finally:
        db.close()


if __name__ == "__main__":
    main()
