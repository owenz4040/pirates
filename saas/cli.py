"""Command Line Interface for SaaS administrative and bootstrap tasks."""
from __future__ import annotations

import argparse
import sys

from sqlalchemy.orm import Session

from saas.config import saas_settings
from saas.database import SaasBase, saas_engine
from saas.security.bootstrap import initiate_superadmin_bootstrap


def main():
    parser = argparse.ArgumentParser(description="COwen ISP Billing SaaS Administrative CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # bootstrap-superadmin
    bootstrap_parser = subparsers.add_parser(
        "bootstrap-superadmin",
        help="Securely initiate the Platform Superadmin owner identity bootstrap with mandatory email OTP and MFA.",
    )
    bootstrap_parser.add_argument(
        "--email",
        default=saas_settings.platform_superadmin_email or "owenzcolin@gmail.com",
        help="Owner email address to bootstrap (defaults to PLATFORM_SUPERADMIN_EMAIL or owenzcolin@gmail.com)",
    )

    args = parser.parse_args()

    # Ensure tables exist
    SaasBase.metadata.create_all(bind=saas_engine)

    if args.command == "bootstrap-superadmin":
        with Session(saas_engine) as session:
            result = initiate_superadmin_bootstrap(db=session, email=args.email)
            if result["status"] == "already_active":
                print(f"[!] {result['message']} (email: {result['email']})")
                sys.exit(0)
            elif result["status"] == "otp_dispatched":
                print("=================================================================")
                print("  CLOUD-ISP PLATFORM SUPERADMIN OWNER BOOTSTRAP")
                print("=================================================================")
                print(f"Target Owner Email : {result['email']}")
                print(f"Verification OTP   : {result['otp']}")
                print(f"OTP Validity       : {result['expires_in_minutes']} minutes")
                print(f"Setup URL          : {result['setup_url']}")
                print("=================================================================")
                print("[+] Complete verification, password setup, and TOTP MFA at the Setup URL.")
                sys.exit(0)
            else:
                print(f"[-] Bootstrap error: {result}")
                sys.exit(1)


if __name__ == "__main__":
    main()
