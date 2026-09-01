"""Connection handling for the MikroTik RouterOS API."""

from __future__ import annotations

import os
import ssl
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator

from librouteros import connect
from librouteros.api import Api


@dataclass(frozen=True)
class RouterConfig:
    """Connection settings for a single RouterOS device (e.g. the hAP lite)."""

    host: str
    username: str
    password: str
    port: int = 8729
    use_ssl: bool = True
    verify_ssl: bool = False

    @classmethod
    def from_env(cls) -> "RouterConfig":
        """Build config from MIKROTIK_* environment variables (see .env.example)."""
        return cls(
            host=_require_env("MIKROTIK_HOST"),
            username=_require_env("MIKROTIK_USER"),
            password=_require_env("MIKROTIK_PASSWORD"),
            port=int(os.environ.get("MIKROTIK_PORT", "8729")),
            use_ssl=os.environ.get("MIKROTIK_USE_SSL", "true").lower() != "false",
            verify_ssl=os.environ.get("MIKROTIK_VERIFY_SSL", "false").lower() == "true",
        )


def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


@contextmanager
def router_connection(config: RouterConfig | None = None) -> Iterator[Api]:
    """
    Open a connection to the router and close it on exit.

    Uses api-ssl (port 8729) by default since the router is reachable over the
    public internet. RouterOS's default cert is self-signed, so hostname/CA
    verification is off by default; set MIKROTIK_VERIFY_SSL=true once you've
    installed a real certificate (see README).
    """
    config = config or RouterConfig.from_env()

    ssl_wrapper = None
    if config.use_ssl:
        ctx = ssl.create_default_context()
        if not config.verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        ssl_wrapper = ctx.wrap_socket

    api = connect(
        host=config.host,
        username=config.username,
        password=config.password,
        port=config.port,
        ssl_wrapper=ssl_wrapper,
    )
    try:
        yield api
    finally:
        api.close()
