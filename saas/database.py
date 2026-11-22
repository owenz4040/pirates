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


_schema_synced = False


def ensure_schema_synced(engine=None) -> None:
    """
    Guarantees all tables and columns defined in SaasBase metadata exist in the database.
    Performs non-destructive, additive column synchronization across SQLite and PostgreSQL.
    """
    import logging
    from sqlalchemy import inspect, text
    import saas.models  # noqa: F401

    _logger = logging.getLogger("saas.database")
    target_engine = engine or saas_engine

    try:
        SaasBase.metadata.create_all(bind=target_engine)
    except Exception as e:
        _logger.warning("create_all warning during schema sync: %s", e)

    try:
        inspector = inspect(target_engine)
        dialect_name = target_engine.dialect.name
        with target_engine.begin() as conn:
            for table_name, table in SaasBase.metadata.tables.items():
                if not inspector.has_table(table_name):
                    continue
                db_cols = {c["name"] for c in inspector.get_columns(table_name)}
                for col in table.columns:
                    if col.name not in db_cols:
                        col_type = col.type.compile(target_engine.dialect)
                        if dialect_name == "postgresql":
                            sql = f"ALTER TABLE {table_name} ADD COLUMN IF NOT EXISTS {col.name} {col_type}"
                        else:
                            sql = f"ALTER TABLE {table_name} ADD COLUMN {col.name} {col_type}"
                        _logger.info("Auto-migrating missing column: %s", sql)
                        conn.execute(text(sql))
    except Exception as e:
        _logger.error("Schema synchronization error: %s", e, exc_info=True)


def ensure_schema_synced_once(engine=None) -> None:
    """Invokes ensure_schema_synced once per container/process lifecycle."""
    global _schema_synced
    if _schema_synced:
        return
    import os
    if os.environ.get("PYTEST_CURRENT_TEST") or os.environ.get("TESTING") == "true":
        return
    ensure_schema_synced(engine)
    _schema_synced = True


def get_saas_db() -> Iterator[Session]:
    ensure_schema_synced_once()
    db = SaasSessionLocal()
    try:
        yield db
    finally:
        db.close()
