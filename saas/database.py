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


db_url = getattr(saas_settings, "effective_database_url", saas_settings.saas_database_url).strip().strip("'\"")
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql+psycopg://", 1)
elif db_url.startswith("postgresql://") and not db_url.startswith("postgresql+"):
    db_url = db_url.replace("postgresql://", "postgresql+psycopg://", 1)

# Connect arguments: SQLite requires check_same_thread=False for multithreading
connect_args = {}
if db_url.startswith("sqlite"):
    connect_args = {"check_same_thread": False}
    saas_engine = create_engine(db_url, connect_args=connect_args)
elif os.environ.get("VERCEL"):
    saas_engine = create_engine(db_url, poolclass=NullPool)
else:
    saas_engine = create_engine(db_url, pool_pre_ping=True)

SaasSessionLocal = sessionmaker(bind=saas_engine, autoflush=False, expire_on_commit=False)


def get_saas_db() -> Iterator[Session]:
    db = SaasSessionLocal()
    try:
        yield db
    finally:
        db.close()
