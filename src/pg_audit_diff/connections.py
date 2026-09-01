"""PostgreSQL connection helpers and credential redaction."""

from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager
from typing import Any

import psycopg
from psycopg import sql
from psycopg.rows import dict_row


@contextmanager
def connect_readonly(
    dsn: str,
    *,
    role: str | None = None,
) -> Generator[psycopg.Connection[Any], None, None]:
    """Open a read-only PostgreSQL connection configured with safety timeouts and optional role."""
    conn = psycopg.connect(dsn, row_factory=dict_row, autocommit=True)
    try:
        conn.execute("SET application_name = 'pg-audit-diff'")
        conn.execute("SET statement_timeout = 30000")
        conn.execute("SET lock_timeout = 5000")
        conn.execute("SET default_transaction_read_only = ON")
        conn.execute("SET default_transaction_isolation = 'repeatable read'")
        if role:
            conn.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(role)))
        yield conn
    finally:
        conn.close()


def verify_connection(dsn: str, *, role: str | None = None) -> bool:
    """Verify that a read-only database connection can be established."""
    try:
        with connect_readonly(dsn, role=role) as conn:
            row = conn.execute("SELECT 1 AS ok").fetchone()
            return row is not None and row.get("ok") == 1
    except Exception:
        return False
