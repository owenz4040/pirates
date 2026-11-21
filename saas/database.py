"""Database connection and session factory for the SaaS platform."""
from __future__ import annotations

import os
from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import NullPool

from saas.config import saas_settings


class SaasBase(DeclarativeBase):
    pass


# Connect arguments: SQLite requires check_same_thread=False for multithreading
connect_args = {}
if saas_settings.saas_database_url.startswith("sqlite"):
    connect_args = {"check_same_thread": False}
    saas_engine = create_engine(saas_settings.saas_database_url, connect_args=connect_args)
elif os.environ.get("VERCEL"):
    saas_engine = create_engine(saas_settings.saas_database_url, poolclass=NullPool)
else:
    saas_engine = create_engine(saas_settings.saas_database_url, pool_pre_ping=True)

SaasSessionLocal = sessionmaker(bind=saas_engine, autoflush=False, expire_on_commit=False)


def get_saas_db() -> Iterator[Session]:
    db = SaasSessionLocal()
    try:
        yield db
    finally:
        db.close()
