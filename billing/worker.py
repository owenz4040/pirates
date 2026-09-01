"""
Expiry sweep: suspends every active customer whose expires_at has passed.

One-shot by design - run it on a schedule (Windows Task Scheduler, cron,
systemd timer) rather than as a long-lived daemon. Nothing here needs to run
more than once every few minutes; a monthly cutoff doesn't need per-second
precision.

Usage:
    python -m billing.worker
"""

from __future__ import annotations

from dotenv import load_dotenv

load_dotenv()

from billing.db import SessionLocal  # noqa: E402
from billing.services import expire_overdue_customers  # noqa: E402
from mikrotik.client import router_connection  # noqa: E402
from mikrotik.pppoe import PPPoEManager  # noqa: E402


def main() -> None:
    db = SessionLocal()
    try:
        from billing.services import send_expiry_reminders
        count_2, count_1 = send_expiry_reminders(db)
        if count_2 or count_1:
            print(f"Sent {count_2}x 2-day reminders and {count_1}x 1-day reminders.")

        with router_connection() as api:
            ppp = PPPoEManager(api)
            expired = expire_overdue_customers(db, ppp)
        for customer in expired:
            print(f"Expired {customer.pppoe_username} (was due {customer.expires_at.isoformat()})")
        if not expired:
            print("No overdue customers.")
    finally:
        db.close()


if __name__ == "__main__":
    main()
