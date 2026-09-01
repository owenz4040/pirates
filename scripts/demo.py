"""
Manual smoke test against a real router. Requires the MIKROTIK_* env vars
from .env.example to be set (or a .env file if you use python-dotenv).

Usage:
    python -m scripts.demo list-secrets
    python -m scripts.demo list-profiles
    python -m scripts.demo suspend <username>
    python -m scripts.demo restore <username>
    python -m scripts.demo set-bandwidth <username> <profile-name>
    python -m scripts.demo ensure-profile <profile-name> <rate-limit>   # e.g. 10M/10M
"""

from __future__ import annotations

import sys

from dotenv import load_dotenv

from mikrotik.bandwidth import BandwidthProfileManager
from mikrotik.client import RouterConfig, router_connection
from mikrotik.pppoe import PPPoEManager


def main() -> None:
    if len(sys.argv) < 2:
        print(__doc__)
        raise SystemExit(1)

    load_dotenv()
    command, *args = sys.argv[1:]
    config = RouterConfig.from_env()

    with router_connection(config) as api:
        ppp = PPPoEManager(api)
        bw = BandwidthProfileManager(api)

        if command == "list-secrets":
            for secret in ppp.list_secrets():
                status = "disabled" if secret.disabled else "enabled"
                online = "online" if ppp.is_online(secret.name) else "offline"
                print(f"{secret.name:20} profile={secret.profile:15} {status:9} {online}")
        elif command == "list-profiles":
            for profile in bw.list_profiles():
                print(f"{profile.name:20} rate-limit={profile.rate_limit}")
        elif command == "suspend":
            ppp.disable_user(args[0])
            print(f"Suspended {args[0]}")
        elif command == "restore":
            ppp.enable_user(args[0])
            print(f"Restored {args[0]}")
        elif command == "set-bandwidth":
            username, profile = args
            ppp.set_profile(username, profile)
            print(f"Moved {username} to profile {profile}")
        elif command == "ensure-profile":
            name, rate_limit = args
            profile = bw.ensure_profile(name, rate_limit)
            print(f"Profile {profile.name} rate-limit={profile.rate_limit}")
        else:
            print(__doc__)
            raise SystemExit(1)


if __name__ == "__main__":
    main()
