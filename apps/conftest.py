import pathlib

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from testcontainers.postgres import PostgresContainer


def _async_postgres_url(sync_url: str) -> str:
    if "+asyncpg" in sync_url:
        return sync_url
    if "postgresql+psycopg2://" in sync_url:
        return sync_url.replace("postgresql+psycopg2://", "postgresql+asyncpg://", 1)
    if "psycopg2" in sync_url:
        return sync_url.replace("psycopg2", "asyncpg")
    if sync_url.startswith("postgresql://"):
        return sync_url.replace("postgresql://", "postgresql+asyncpg://", 1)
    return sync_url


def _apply_base_schema_sql_statements():
    """DDL statements from all migration files (split for async execution)."""
    root = pathlib.Path(__file__).resolve().parent.parent
    migrations_dir = root / "db" / "migrations"
    
    # Dynamically load and sort all .sql files
    sql_files = sorted(migrations_dir.glob("*.sql"))
    
    for sql_path in sql_files:
        yield sql_path.read_text()


@pytest.fixture(scope="session")
def postgres_container():
    """Spins up a single Postgres container for the entire test session."""
    with PostgresContainer("postgres:15-alpine", dbname="hr_directory") as postgres:
        yield _async_postgres_url(postgres.get_connection_url())


@pytest_asyncio.fixture(scope="session")
async def db_engine(postgres_container):
    engine = create_async_engine(postgres_container, echo=False, pool_pre_ping=True)
    async with engine.begin() as conn:
        # Get raw asyncpg connection to execute multiple statements in a single call
        raw_conn = await conn.get_raw_connection()
        for script in _apply_base_schema_sql_statements():
            await raw_conn.driver_connection.execute(script)
    try:
        yield engine
    finally:
        await engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def db_session(db_engine):
    """Provides a transactional db session that rolls back after each test."""
    connection = await db_engine.connect()
    transaction = await connection.begin()

    async_session_factory = async_sessionmaker(
        bind=connection,
        expire_on_commit=False,
        join_transaction_mode="create_savepoint",
    )

    session = async_session_factory()
    try:
        yield session
    finally:
        await session.close()
        await transaction.rollback()
        await connection.close()
